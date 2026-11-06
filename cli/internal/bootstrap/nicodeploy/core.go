// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// lbIPsAnnotation pins a LoadBalancer Service to an address MetalLB holds.
const lbIPsAnnotation = "metallb.universe.tf/loadBalancerIPs"

// bootArtifactsDir is where the Core charts mount the boot-artifact volume in
// the init containers that fill it.
const bootArtifactsDir = "/forge-boot-artifacts/blobs/internal"

func (e *Engine) installCore(ctx context.Context, kubeconfig, root, tmp string, cfg Config) error {
	if cfg.Settings == nil {
		return errors.New("nicodeploy: Settings is required to install NICo Core")
	}
	// Core's migration hook pulls its image before the chart's own objects exist.
	if cfg.RegistryPassword != "" {
		if err := e.applySecret(ctx, pullSecretFor(nicoNamespace, cfg)); err != nil {
			return err
		}
	}
	coreValues := filepath.Join(tmp, "core-values.yaml")
	if err := writeValues(coreValues, cfg.CoreValues); err != nil {
		return err
	}
	values := filepath.Join(tmp, "nico-core.yaml")
	if err := writeValues(values, coreOverrides(cfg)); err != nil {
		return err
	}
	// The operator's values are NICo's own site configuration; the overrides come last so they win.
	return e.helm(ctx, kubeconfig, "nico", nicoNamespace, []string{filepath.Join(root, "helm")},
		[]string{filepath.Join(root, "helm-prereqs", "values", "nico-core.yaml"), coreValues, values}, cfg.Timeout)
}

// coreOverrides is what NICo Core takes beyond NICo's values and the
// operator's site configuration: the images, the API's host name and the
// service addresses from the settings, the reduced set of services nvkectl
// runs, and how each service is published for cfg's profile.
func coreOverrides(cfg Config) map[string]any {
	s := cfg.Settings
	a := s.Addresses
	site := cfg.Profile == ProfileSite
	ntp := ntpAddresses(s)
	boot := bootArtifactContainers(s.Images)

	hook := map[string]any{"provisioningServer": a.PXE}
	if a.DNS != "" {
		hook["nameservers"] = a.DNS
	}
	if len(ntp) > 0 {
		hook["ntpServer"] = strings.Join(ntp, ",")
	}

	overrides := map[string]any{
		"global": map[string]any{"image": map[string]any{
			"repository": cfg.ImageRegistry + "/nvmetal-carbide",
			"tag":        cfg.CoreImageTag,
		}},
		"nico-api": map[string]any{
			"hostname": s.APIHostname,
			// The admin CLI's certificates are issued under the site root.
			"auth": map[string]any{"additionalIssuerCns": []string{"site-root"}},
			"certificate": map[string]any{
				// DPU agents dial the API by its .forge names.
				"extraDnsNames": []string{s.APIHostname, "carbide-api.forge", "nico-api.forge", "carbide-api.forge-system.svc.cluster.local"},
				"ipAddresses":   []string{a.API},
			},
			"bootArtifactContainers": boot,
			// No RMS or DPF runs beside this NICo.
			"componentManager": map[string]any{"enabled": false},
			"rms":              map[string]any{"enabled": false},
			"dpf":              map[string]any{"rbacCreate": false},
			"externalService":  externalService(site, a.API, true),
		},
		"nico-dhcp": map[string]any{
			"config": map[string]any{"kea": map[string]any{
				// The chart derives option 54 only from the LoadBalancer annotation, which the seed does not set.
				"serverIdentifier": a.DHCP,
				"hookParameters":   hook,
			}},
			"externalService": externalService(site, a.DHCP, false),
		},
		"nico-pxe": map[string]any{
			"bootArtifactContainers": boot,
			"externalService":        externalService(site, a.PXE, true),
		},
		"nico-ssh-console-rs":        map[string]any{"externalService": map[string]any{"enabled": false}},
		"nico-dns":                   map[string]any{"enabled": false},
		"nico-flow":                  map[string]any{"enabled": false},
		"nico-dsx-exchange-consumer": map[string]any{"enabled": false},
		"nico-machine-a-tron":        map[string]any{"enabled": false},
		"nico-ntp":                   map[string]any{"enabled": false},
		"unbound":                    map[string]any{"enabled": false},
	}

	if len(a.NTP) > 0 {
		ntpValues := map[string]any{"enabled": true, "replicas": len(a.NTP)}
		if len(s.UpstreamNTP) > 0 {
			ntpValues["ntp"] = map[string]any{"upstreamServers": s.UpstreamNTP}
		}
		if site {
			perPod := make([]map[string]any, len(a.NTP))
			for i, ip := range a.NTP {
				perPod[i] = map[string]any{lbIPsAnnotation: ip}
			}
			ntpValues["externalService"] = map[string]any{"enabled": true, "perPodAnnotations": perPod}
		} else {
			ntpValues["externalService"] = map[string]any{"enabled": false}
		}
		overrides["nico-ntp"] = ntpValues
	}

	if a.DNS != "" {
		repo, tag := splitImage(s.Images.Unbound)
		unbound := map[string]any{
			"enabled":         true,
			"image":           map[string]any{"repository": repo, "tag": tag},
			"localConfig":     map[string]any{"forwarders.conf": forwarders(s.UpstreamDNS)},
			"localData":       forgeRecords(a, ntp),
			"externalService": externalService(site, a.DNS, true),
		}
		if s.Images.UnboundExporter != "" {
			repo, tag := splitImage(s.Images.UnboundExporter)
			unbound["exporterImage"] = map[string]any{"repository": repo, "tag": tag}
		} else {
			unbound["exporter"] = map[string]any{"enabled": false}
		}
		overrides["unbound"] = unbound
	}
	return overrides
}

// externalService is a Core chart's externalService values: on the site, a
// LoadBalancer pinned to address, with externalTrafficPolicy Local where the
// chart takes it; on the seed, or without an address, none.
func externalService(site bool, address string, localPolicy bool) map[string]any {
	if !site || address == "" {
		return map[string]any{"enabled": false}
	}
	values := map[string]any{"enabled": true, "annotations": map[string]any{lbIPsAnnotation: address}}
	if localPolicy {
		values["externalTrafficPolicy"] = "Local"
	}
	return values
}

// bootArtifactContainers are the init containers that copy the boot artifacts
// NICo's PXE and API serve out of their images, as NICo's chart values list them.
func bootArtifactContainers(images nicosettings.Images) []map[string]any {
	container := func(name, image string, dirs ...string) map[string]any {
		return map[string]any{
			"name":    name,
			"image":   image,
			"command": []string{"sh", "-c", "cp -r " + strings.Join(dirs, " ") + " " + bootArtifactsDir},
		}
	}
	containers := []map[string]any{
		container("boot-artifacts-x86-64", images.BootArtifactsX86, "/x86_64"),
		// The aarch64 image has no /firmware; copying a missing directory crash-loops the init container.
		container("boot-artifacts-aarch64", images.BootArtifactsAarch64, "/aarch64", "/apt"),
	}
	if images.MachineValidation != "" {
		containers = append(containers, container("machine-validation-config", images.MachineValidation, "/machine-validation"))
	}
	return containers
}

// ntpAddresses are the NTP servers DHCP hands out: NICo's, or the IP
// addresses among the site config's ntp_servers when NICo runs none.
func ntpAddresses(s *nicosettings.Settings) []string {
	if len(s.Addresses.NTP) > 0 {
		return s.Addresses.NTP
	}
	var ips []string
	for _, server := range s.SiteConfig.NTPServers {
		if net.ParseIP(server) != nil {
			ips = append(ips, server)
		}
	}
	return ips
}

// forgeRecords are the .forge names DPU agents and host loaders look up, each
// with the address of the service it names.
func forgeRecords(a nicosettings.Addresses, ntp []string) []map[string]any {
	var records []map[string]any
	add := func(addresses []string, names ...string) {
		if len(addresses) == 0 {
			return
		}
		for _, name := range names {
			records = append(records, map[string]any{"name": name, "addresses": addresses})
		}
	}
	add([]string{a.API}, "carbide-api.forge", "nico-api.forge")
	add([]string{a.PXE}, "carbide-pxe.forge", "nico-pxe.forge", "carbide-static-pxe.forge")
	add(ntp, "carbide-ntp.forge", "nico-ntp.forge")
	add([]string{a.DNS}, "unbound.forge")
	return records
}

// forwarders is unbound's forwarders.conf, sending every other name to upstream.
func forwarders(upstream []string) string {
	var b strings.Builder
	b.WriteString("forward-zone:\n    name: \".\"\n")
	for _, server := range upstream {
		fmt.Fprintf(&b, "    forward-addr: %s\n", server)
	}
	return b.String()
}

// splitImage splits an image reference into the repository and tag the
// unbound chart joins with a colon. A digest reference splits at its
// algorithm's colon, which joins back to the same reference.
func splitImage(ref string) (repository, tag string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ref, "latest"
	}
	return ref[:i], ref[i+1:]
}
