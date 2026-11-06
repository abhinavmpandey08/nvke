// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicoingest ingests a site's machines into an installed NICo: it
// gives NICo the site-wide BMC credentials and each machine of the NICo
// settings as an expected machine through NICo's admin CLI, approves measured
// boot when the site attests, and waits until NICo's REST API reports every
// machine Ready.
package nicoingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

const defaultTimeout = 4 * time.Hour

// pcrRegisters are the measured-boot PCRs whose values NICo trusts on first boot.
const pcrRegisters = "0,3,5,6"

// hostInbandSegment is NICo's NetworkSegmentType number for the host in-band network.
const hostInbandSegment = 3

// CommandRunner runs kubectl.
type CommandRunner interface {
	// Run executes name with args and returns its combined output, which is
	// populated on error too.
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Config is the NICo Run ingests into and what it ingests.
type Config struct {
	// Kubeconfig is the cluster NICo runs in.
	Kubeconfig string
	// Settings name the machines and hold the site config.
	Settings *nicosettings.Settings
	// Secrets hold the site-wide BMC root password, the DPU BMC factory login
	// and each machine's BMC factory login.
	Secrets nicosettings.Secrets
	// REST is NICo's REST API, which the machines are read back from.
	REST *nicorest.Client
	// Runner runs kubectl. Nil means os/exec.
	Runner CommandRunner
	// Kube reads NICo's pods and the admin CLI certificate.
	Kube kubernetes.Interface
	// Timeout bounds the wait for every machine to become Ready. Zero means four hours.
	Timeout time.Duration
	// Logger receives progress. Nil means slog.Default().
	Logger *slog.Logger
}

// Run gives NICo the site-wide BMC root password, the DPU BMC factory login
// for each of Settings.DPUFactoryModels when one is set, and every machine of
// the settings as an expected machine; approves measured boot for every
// machine when the site config turns attestation on; and waits until NICo's
// REST API reports each machine Ready or in use. The UEFI passwords are not
// set here. Every step can be run again. When the wait times out, its error
// names the machines NICo has not discovered and those in Error.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Settings == nil || cfg.REST == nil || cfg.Kube == nil {
		return errors.New("nicoingest: Settings, REST and Kube are required")
	}
	if cfg.Secrets.SiteWideBMCRootPassword == "" {
		return fmt.Errorf("nicoingest: the site-wide BMC root password (%s) is required", nicosettings.SiteWideBMCRootPasswordEnv)
	}
	if cfg.Runner == nil {
		cfg.Runner = execRunner{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "nicoingest")

	cli, err := openAdminCLI(ctx, cfg, log)
	if err != nil {
		return err
	}
	err = register(ctx, cfg, cli, log)
	cli.close(ctx)
	if err != nil {
		return err
	}
	return waitReady(ctx, cfg, log)
}

// register gives NICo the credentials and expected machines, and approves measured boot.
func register(ctx context.Context, cfg Config, cli *adminCLI, log *slog.Logger) error {
	s := cfg.Secrets
	if _, err := cli.run(ctx, "setting the site-wide BMC root password",
		"credential", "add-bmc", "--kind=site-wide-root", "--password="+s.SiteWideBMCRootPassword); err != nil {
		return err
	}
	if s.DPUBMCFactoryUsername != "" {
		models := cfg.Settings.DPUFactoryModels
		if len(models) == 0 {
			// NICo's catch-all, used for every model without its own login.
			models = []string{"unknown"}
		}
		for _, model := range models {
			if _, err := cli.run(ctx, "setting the DPU BMC factory login for model "+model, "credential", "add-dpu-factory-default",
				"--model="+model, "--username="+s.DPUBMCFactoryUsername, "--password="+s.DPUBMCFactoryPassword); err != nil {
				return err
			}
		}
	}
	log.Info("NICo has the site-wide BMC credentials")

	for _, m := range cfg.Settings.Machines {
		login, ok := s.BMCLogins[m.BMCLogin]
		if !ok {
			return fmt.Errorf("nicoingest: machine %s has no BMC login: set %s_USERNAME and %s_PASSWORD", m.Name, m.BMCLogin, m.BMCLogin)
		}
		out, err := cli.run(ctx, "adding expected machine "+m.Name, expectedMachineArgs(m, login)...)
		switch {
		case err != nil && strings.Contains(strings.ToLower(out), "duplicate mac address"):
			log.Info("NICo already expects the machine", "machine", m.Name)
		case err != nil:
			return err
		default:
			log.Info("NICo expects the machine", "machine", m.Name)
		}
	}

	if cfg.Settings.SiteConfig.AttestationEnabled {
		out, err := cli.run(ctx, "approving measured boot for every machine",
			"attestation", "measured-boot", "site", "trusted-machine", "approve", "*", "persist", "--pcr-registers="+pcrRegisters)
		if err != nil && !strings.Contains(strings.ToLower(out), "duplicate key value") {
			return err
		}
		log.Info("NICo trusts every machine's measured boot", "pcrRegisters", pcrRegisters)
	}
	return nil
}

// expectedInterface is an entry of `expected-machine add --interfaces`.
type expectedInterface struct {
	MACAddress         string `json:"mac_address"`
	Role               string `json:"role"`
	FixedIP            string `json:"fixed_ip,omitempty"`
	Primary            bool   `json:"primary,omitempty"`
	NetworkSegmentType int    `json:"network_segment_type,omitempty"`
}

// expectedMachineArgs builds the admin CLI's `expected-machine add` for m,
// which NICo logs in to first with login. Values are passed as --flag=value so
// one starting with a dash is not read as a flag.
func expectedMachineArgs(m nicosettings.Machine, login nicosettings.Login) []string {
	args := []string{
		"expected-machine", "add",
		"--bmc-mac-address=" + m.BMCMAC,
		"--bmc-username=" + login.Username,
		"--bmc-password=" + login.Password,
		"--chassis-serial-number=" + m.Serial,
		"--meta-name=" + m.Name,
	}
	if m.RetainBMCPassword {
		args = append(args, "--bmc-retain-credentials=true")
	}
	if m.DPUPolicy != "" {
		args = append(args, "--dpu-policy="+m.DPUPolicy)
	}
	if m.BMCIP != "" {
		args = append(args, "--bmc-ip-address="+m.BMCIP)
	}
	var ifaces []expectedInterface
	if m.BootNICMAC != "" {
		ifaces = append(ifaces, expectedInterface{
			MACAddress: m.BootNICMAC, Role: "host", FixedIP: m.BootNICIP, Primary: true, NetworkSegmentType: hostInbandSegment,
		})
	}
	for _, d := range m.DPUs {
		if d.Serial != "" {
			args = append(args, "--fallback-dpu-serial-number="+d.Serial)
		}
		if d.BMCMAC != "" {
			ifaces = append(ifaces, expectedInterface{MACAddress: d.BMCMAC, Role: "dpu_bmc", FixedIP: d.BMCIP})
		}
		if d.OSMAC != "" {
			ifaces = append(ifaces, expectedInterface{MACAddress: d.OSMAC, Role: "dpu_os", FixedIP: d.OSIP})
		}
	}
	if len(ifaces) > 0 {
		b, _ := json.Marshal(ifaces) // plain strings, bools and ints always marshal
		args = append(args, "--interfaces="+string(b))
	}
	return args
}
