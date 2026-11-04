// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicosettings

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// siteConfigTOML is the part of nico-api's site config the bootstrap reads.
// Booleans are pointers so an omitted key can take the chart base config's value.
type siteConfigTOML struct {
	SiteName           string             `toml:"sitename"`
	InitialDomainName  string             `toml:"initial_domain_name"`
	AttestationEnabled *bool              `toml:"attestation_enabled"`
	DHCPServers        []string           `toml:"dhcp_servers"`
	NTPServers         []string           `toml:"ntp_servers"`
	SiteFabricPrefixes []string           `toml:"site_fabric_prefixes"`
	DenyPrefixes       []string           `toml:"deny_prefixes"`
	Networks           map[string]Network `toml:"networks"`
	Pools              map[string]Pool    `toml:"pools"`
	SiteExplorer       struct {
		DPUPolicy string `toml:"dpu_policy"`
		DPUMode   string `toml:"dpu_mode"`
	} `toml:"site_explorer"`
	MachineValidation struct {
		Enabled *bool `toml:"enabled"`
	} `toml:"machine_validation_config"`
	FirmwareGlobal struct {
		Autoupdate *bool `toml:"autoupdate"`
	} `toml:"firmware_global"`
	DPF struct {
		Enabled bool `toml:"enabled"`
	} `toml:"dpf"`
}

// dpuPolicies maps every spelling nico-api accepts for a DPU policy to the
// policy: the canonical names and the legacy dpu_mode values.
var dpuPolicies = map[string]string{
	"manage": DPUPolicyManage, "dpu_mode": DPUPolicyManage,
	"nic": DPUPolicyNIC, "use_as_nic": DPUPolicyNIC, "nic_mode": DPUPolicyNIC,
	"ignore": DPUPolicyIgnore, "no_dpu": DPUPolicyIgnore,
}

// ParseSiteConfig reads the site config from a NICo Core values file: the TOML
// string at nico-api.siteConfig.nicoApiSiteConfig, and the DNS and NTP servers
// at nico-dhcp.config.kea.hookParameters. A key the TOML omits takes
// nico-api's base config value, which turns attestation, machine validation and
// firmware autoupdate on. It checks only that the config can be read; Load
// validates what it says.
func ParseSiteConfig(coreValues []byte) (SiteConfig, error) {
	var values struct {
		NicoAPI struct {
			SiteConfig struct {
				Enabled           *bool  `yaml:"enabled"`
				NicoAPISiteConfig string `yaml:"nicoApiSiteConfig"`
			} `yaml:"siteConfig"`
		} `yaml:"nico-api"`
		NicoDHCP struct {
			Config struct {
				Kea struct {
					HookParameters struct {
						Nameservers string `yaml:"nameservers"`
						NTPServer   string `yaml:"ntpServer"`
					} `yaml:"hookParameters"`
				} `yaml:"kea"`
			} `yaml:"config"`
		} `yaml:"nico-dhcp"`
	}
	if err := yaml.Unmarshal(coreValues, &values); err != nil {
		return SiteConfig{}, fmt.Errorf("parsing the values: %w", err)
	}
	sc := values.NicoAPI.SiteConfig
	if sc.Enabled != nil && !*sc.Enabled {
		return SiteConfig{}, errors.New("nico-api.siteConfig.enabled is false, so nico-api would run without the site config")
	}
	if sc.NicoAPISiteConfig == "" {
		return SiteConfig{}, errors.New("nico-api.siteConfig.nicoApiSiteConfig is not set: it is the site config")
	}
	var t siteConfigTOML
	if err := toml.Unmarshal([]byte(sc.NicoAPISiteConfig), &t); err != nil {
		return SiteConfig{}, fmt.Errorf("parsing nico-api.siteConfig.nicoApiSiteConfig: %w", err)
	}
	if t.DPF.Enabled {
		return SiteConfig{}, errors.New("nico-api.siteConfig.nicoApiSiteConfig: [dpf] enabled = true is not supported: nvkectl does not install DPF")
	}
	// nico-api reads dpu_mode only when dpu_policy is unset.
	raw := t.SiteExplorer.DPUPolicy
	if raw == "" {
		raw = t.SiteExplorer.DPUMode
	}
	policy := DPUPolicyManage
	if raw != "" {
		var ok bool
		if policy, ok = dpuPolicies[raw]; !ok {
			return SiteConfig{}, fmt.Errorf("nico-api.siteConfig.nicoApiSiteConfig: [site_explorer] dpu_policy %q is not one of manage, nic, ignore", raw)
		}
	}
	hook := values.NicoDHCP.Config.Kea.HookParameters
	return SiteConfig{
		SiteName:           t.SiteName,
		DNSDomain:          t.InitialDomainName,
		DefaultDPUPolicy:   policy,
		AttestationEnabled: orTrue(t.AttestationEnabled),
		MachineValidation:  orTrue(t.MachineValidation.Enabled),
		FirmwareAutoupdate: orTrue(t.FirmwareGlobal.Autoupdate),
		SiteFabricPrefixes: t.SiteFabricPrefixes,
		DenyPrefixes:       t.DenyPrefixes,
		DHCPServers:        t.DHCPServers,
		NTPServers:         t.NTPServers,
		DHCPNameservers:    strings.TrimSpace(hook.Nameservers),
		DHCPNTPServer:      strings.TrimSpace(hook.NTPServer),
		Networks:           t.Networks,
		Pools:              t.Pools,
	}, nil
}

// orTrue returns *b, or true when b is nil.
func orTrue(b *bool) bool {
	return b == nil || *b
}
