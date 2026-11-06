// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

func testSettings() *nicosettings.Settings {
	return &nicosettings.Settings{File: nicosettings.File{
		APIHostname: "api.site.example.com",
		Images: nicosettings.Images{
			Registry:             "nvcr.io/nico",
			CoreTag:              "v2.2.2",
			RestTag:              "v2.2.2",
			BootArtifactsX86:     "nvcr.io/nico/boot-artifacts-x86_64:v2.2.2",
			BootArtifactsAarch64: "nvcr.io/nico/boot-artifacts-aarch64:v2.2.2",
			Unbound:              "nvcr.io/nico/unbound:1.20",
			UnboundExporter:      "nvcr.io/nico/unbound_exporter:0.4",
		},
		Addresses: nicosettings.Addresses{
			DHCP: "10.0.0.67", PXE: "10.0.0.80", API: "10.0.0.43", REST: "10.0.0.88", Keycloak: "10.0.0.82",
			DNS: "10.0.0.53", NTP: []string{"10.0.0.123", "10.0.0.124"},
		},
		UpstreamDNS: []string{"1.1.1.1", "8.8.8.8"},
		UpstreamNTP: []string{"ntp.example.com"},
	}}
}

// at walks values along path, returning nil when a key is missing.
func at(values map[string]any, path ...string) any {
	var v any = values
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func TestCoreOverrides(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		edit    func(*nicosettings.Settings)
		check   func(t *testing.T, v map[string]any)
	}{
		{
			name:    "seed keeps every service inside the cluster",
			profile: ProfileSeed,
			check: func(t *testing.T, v map[string]any) {
				for _, chart := range []string{"nico-api", "nico-dhcp", "nico-pxe", "nico-ssh-console-rs", "nico-ntp", "unbound"} {
					assert.Equal(t, false, at(v, chart, "externalService", "enabled"), chart)
				}
				for _, chart := range []string{"nico-api", "nico-pxe"} {
					assert.Equal(t, false, at(v, chart, "legacyAlias", "enabled"), chart)
				}
			},
		},
		{
			name:    "site leaves publishing to nvkectl",
			profile: ProfileSite,
			check: func(t *testing.T, v map[string]any) {
				for _, chart := range []string{"nico-api", "nico-dhcp", "nico-pxe", "nico-ssh-console-rs", "nico-ntp", "unbound"} {
					assert.Equal(t, false, at(v, chart, "externalService", "enabled"), chart)
				}
			},
		},
		{
			name:    "API identity, images and the reduced service set",
			profile: ProfileSeed,
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, "nvcr.io/nico/nvmetal-carbide", at(v, "global", "image", "repository"))
				assert.Equal(t, "v2.2.2", at(v, "global", "image", "tag"))
				assert.Equal(t, "api.site.example.com", at(v, "nico-api", "hostname"))
				assert.Equal(t, []string{"site-root"}, at(v, "nico-api", "auth", "additionalIssuerCns"))
				assert.Subset(t, at(v, "nico-api", "certificate", "extraDnsNames"),
					[]string{"api.site.example.com", "carbide-api.forge", "nico-api.forge"})
				assert.Equal(t, []string{"10.0.0.43"}, at(v, "nico-api", "certificate", "ipAddresses"))
				for _, off := range [][]string{
					{"nico-api", "componentManager", "enabled"},
					{"nico-api", "rms", "enabled"},
					{"nico-api", "dpf", "rbacCreate"},
					{"nico-dns", "enabled"},
					{"nico-flow", "enabled"},
					{"nico-dsx-exchange-consumer", "enabled"},
					{"nico-machine-a-tron", "enabled"},
				} {
					assert.Equal(t, false, at(v, off...), "%v", off)
				}
			},
		},
		{
			name:    "DHCP hands out NICo's addresses",
			profile: ProfileSeed,
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, "10.0.0.67", at(v, "nico-dhcp", "config", "kea", "serverIdentifier"))
				hook := at(v, "nico-dhcp", "config", "kea", "hookParameters")
				assert.Equal(t, map[string]any{"provisioningServer": "10.0.0.80", "nameservers": "10.0.0.53", "ntpServer": "10.0.0.123,10.0.0.124"}, hook)
			},
		},
		{
			name:    "boot artifacts go to PXE and the API",
			profile: ProfileSeed,
			edit: func(s *nicosettings.Settings) {
				s.Images.MachineValidation = "nvcr.io/nico/machine-validation-config:v2.2.2"
			},
			check: func(t *testing.T, v map[string]any) {
				for _, chart := range []string{"nico-pxe", "nico-api"} {
					boot, ok := at(v, chart, "bootArtifactContainers").([]map[string]any)
					require.True(t, ok, chart)
					require.Len(t, boot, 3, chart)
					assert.Equal(t, "nvcr.io/nico/boot-artifacts-x86_64:v2.2.2", boot[0]["image"])
					assert.Equal(t, []string{"sh", "-c", "cp -r /aarch64 /apt /forge-boot-artifacts/blobs/internal"}, boot[1]["command"])
					assert.Equal(t, "machine-validation-config", boot[2]["name"])
				}
			},
		},
		{
			name:    "no machine-validation image, no machine-validation container",
			profile: ProfileSeed,
			check: func(t *testing.T, v map[string]any) {
				assert.Len(t, at(v, "nico-pxe", "bootArtifactContainers"), 2)
			},
		},
		{
			name:    "NICo's resolver and NTP when their addresses are set",
			profile: ProfileSeed,
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, true, at(v, "unbound", "enabled"))
				assert.Equal(t, "nvcr.io/nico/unbound", at(v, "unbound", "image", "repository"))
				assert.Equal(t, "1.20", at(v, "unbound", "image", "tag"))
				assert.Equal(t, "0.4", at(v, "unbound", "exporterImage", "tag"))
				assert.Equal(t, "forward-zone:\n    name: \".\"\n    forward-addr: 1.1.1.1\n    forward-addr: 8.8.8.8\n",
					at(v, "unbound", "localConfig", "forwarders.conf"))
				records, ok := at(v, "unbound", "localData").([]map[string]any)
				require.True(t, ok)
				names := map[string]any{}
				for _, r := range records {
					names[r["name"].(string)] = r["addresses"]
				}
				assert.Equal(t, []string{"10.0.0.43"}, names["carbide-api.forge"])
				assert.Equal(t, []string{"10.0.0.80"}, names["carbide-static-pxe.forge"])
				assert.Equal(t, []string{"10.0.0.123", "10.0.0.124"}, names["carbide-ntp.forge"])
				assert.Equal(t, []string{"10.0.0.53"}, names["unbound.forge"])
				assert.Equal(t, true, at(v, "nico-ntp", "enabled"))
				assert.Equal(t, 2, at(v, "nico-ntp", "replicas"))
				assert.Equal(t, []string{"ntp.example.com"}, at(v, "nico-ntp", "ntp", "upstreamServers"))
			},
		},
		{
			name:    "the site's DNS and NTP leave unbound and nico-ntp off",
			profile: ProfileSite,
			edit: func(s *nicosettings.Settings) {
				s.Addresses.DNS, s.Addresses.NTP = "", nil
				s.SiteConfig.NTPServers = []string{"10.1.0.1", "ntp.site.example.com"}
			},
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, map[string]any{"enabled": false}, v["unbound"])
				assert.Equal(t, map[string]any{"enabled": false}, v["nico-ntp"])
				hook := at(v, "nico-dhcp", "config", "kea", "hookParameters")
				assert.Equal(t, map[string]any{"provisioningServer": "10.0.0.80", "ntpServer": "10.1.0.1"}, hook,
					"the site config's NTP addresses, and the operator's resolver")
			},
		},
		{
			name:    "no exporter image turns the exporter off",
			profile: ProfileSeed,
			edit:    func(s *nicosettings.Settings) { s.Images.UnboundExporter = "" },
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, false, at(v, "unbound", "exporter", "enabled"))
				assert.Nil(t, at(v, "unbound", "exporterImage"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testSettings()
			if tt.edit != nil {
				tt.edit(s)
			}
			cfg := NewConfig(s, nicosettings.Secrets{}, tt.profile, "standard")
			tt.check(t, coreOverrides(cfg))
		})
	}
}

func TestSplitImage(t *testing.T) {
	tests := []struct {
		ref, repo, tag string
	}{
		{"nvcr.io/nico/unbound:1.20", "nvcr.io/nico/unbound", "1.20"},
		{"registry:5000/unbound", "registry:5000/unbound", "latest"},
		{"registry:5000/unbound:1.20", "registry:5000/unbound", "1.20"},
		{"nvcr.io/nico/unbound@sha256:abc", "nvcr.io/nico/unbound@sha256", "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			repo, tag := splitImage(tt.ref)
			assert.Equal(t, tt.repo, repo)
			assert.Equal(t, tt.tag, tag)
			if tag != "latest" {
				assert.Equal(t, tt.ref, repo+":"+tag, "the chart joins them back to the reference")
			}
		})
	}
}
