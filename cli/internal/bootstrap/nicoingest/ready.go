// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// pollInterval is how often the wait reads the machines.
var pollInterval = 30 * time.Second

// pageSize is the largest page NICo's REST API returns.
const pageSize = 100

// machine is the part of a NICo REST machine the wait reads.
type machine struct {
	SerialNumber string `json:"serialNumber"`
	Status       string `json:"status"`
	Metadata     struct {
		BMCInfo struct {
			MAC string `json:"mac"`
		} `json:"bmcInfo"`
		DMIData struct {
			ProductSerial string `json:"productSerial"`
			ChassisSerial string `json:"chassisSerial"`
		} `json:"dmiData"`
	} `json:"metadata"`
}

// waitReady polls NICo's REST API until every machine of the settings is Ready or in use.
func waitReady(ctx context.Context, cfg Config, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	hosts := cfg.Settings.Machines
	last := ""
	for {
		var state string
		machines, err := listMachines(ctx, cfg.REST)
		if err != nil {
			state = "listing NICo's machines: " + err.Error()
			if ctx.Err() != nil && last != "" {
				state = last // the deadline cut this request off, so the timeout reports what the last poll read
			}
			if state != last {
				log.Warn("listing NICo's machines failed; retrying", "err", err)
			}
		} else {
			p := evaluate(hosts, machines)
			if p.done() {
				log.Info("every machine is Ready in NICo", "machines", len(hosts))
				return nil
			}
			state = p.String()
			if state != last {
				log.Info("waiting for the machines to become Ready in NICo", "ready", p.ready, "machines", len(hosts), "pending", state)
			}
		}
		last = state
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("timed out after %s waiting for the machines to become Ready in NICo: %s", cfg.Timeout, last)
			}
			return fmt.Errorf("waiting for the machines to become Ready in NICo: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// listMachines reads every machine NICo's REST API shows the caller, with its BMC and DMI data.
func listMachines(ctx context.Context, rest *nicorest.Client) ([]machine, error) {
	var all []machine
	for page := 1; ; page++ {
		var ms []machine
		path := fmt.Sprintf("machine?includeMetadata=true&pageSize=%d&pageNumber=%d", pageSize, page)
		if err := rest.Do(ctx, http.MethodGet, path, nil, &ms); err != nil {
			return nil, err
		}
		all = append(all, ms...)
		if len(ms) < pageSize {
			return all, nil
		}
	}
}

// progress is how far NICo has come with the settings' machines.
type progress struct {
	ready int
	// missing are the machines NICo has not discovered, errored those in
	// Error, and waiting the others not Ready yet, each with its status.
	missing, errored, waiting []string
}

func (p progress) done() bool {
	return len(p.missing)+len(p.errored)+len(p.waiting) == 0
}

func (p progress) String() string {
	var parts []string
	if len(p.errored) > 0 {
		parts = append(parts, "in Error: "+strings.Join(p.errored, ", "))
	}
	if len(p.missing) > 0 {
		parts = append(parts, "not discovered: "+strings.Join(p.missing, ", "))
	}
	if len(p.waiting) > 0 {
		parts = append(parts, "not Ready: "+strings.Join(p.waiting, ", "))
	}
	return strings.Join(parts, "; ")
}

// evaluate says where each of hosts is among machines. A machine in use is
// done too: it was Ready before an earlier run allocated it.
func evaluate(hosts []nicosettings.Machine, machines []machine) progress {
	var p progress
	for _, h := range hosts {
		m, ok := find(h, machines)
		switch {
		case !ok:
			p.missing = append(p.missing, h.Name)
		case m.Status == "Ready" || m.Status == "InUse":
			p.ready++
		case m.Status == "Error":
			p.errored = append(p.errored, h.Name)
		default:
			p.waiting = append(p.waiting, fmt.Sprintf("%s (%s)", h.Name, m.Status))
		}
	}
	return p
}

// find returns the machine whose BMC is h's, or, failing that, whose serial is h's.
func find(h nicosettings.Machine, machines []machine) (machine, bool) {
	mac := normalMAC(h.BMCMAC)
	for _, m := range machines {
		if m.Metadata.BMCInfo.MAC != "" && normalMAC(m.Metadata.BMCInfo.MAC) == mac {
			return m, true
		}
	}
	for _, m := range machines {
		for _, s := range []string{m.SerialNumber, m.Metadata.DMIData.ChassisSerial, m.Metadata.DMIData.ProductSerial} {
			if s != "" && strings.EqualFold(strings.TrimSpace(s), h.Serial) {
				return m, true
			}
		}
	}
	return machine{}, false
}

func normalMAC(s string) string {
	if hw, err := net.ParseMAC(strings.TrimSpace(s)); err == nil {
		return hw.String()
	}
	return strings.ToLower(strings.TrimSpace(s))
}
