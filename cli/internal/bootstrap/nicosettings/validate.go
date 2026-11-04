// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicosettings

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	dnsLabelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	hostnameRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	envPrefixRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// chassisSerialRE is the chassis serial NICo accepts for an expected machine.
	chassisSerialRE = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
)

// requiredPools are the resource pools nico-api refuses to start without.
var requiredPools = []string{"lo-ip", "vlan-id", "vni", "vpc-vni"}

// dpuFactoryModels are the DPU models the admin CLI sets a factory login for.
var dpuFactoryModels = map[string]bool{"bf2": true, "bf3": true, "bf4": true, "unknown": true}

// maxNTPAddresses is how many NICo NTP addresses the bootstrap cluster has node ports for.
const maxNTPAddresses = 3

// Prefix-length bounds NICo REST accepts for a subnet.
const (
	minSubnetPrefixLength = 8
	maxSubnetPrefixLength = 30
)

// validate adds every problem with s to p. siteConfigRead says whether
// s.SiteConfig was read, so its checks are skipped rather than repeated as
// noise when it could not be.
func (s *Settings) validate(p *problems, siteConfigRead bool) {
	for _, f := range []struct{ name, value string }{
		{"apiHostname", s.APIHostname},
		{"coreValues", s.CoreValues},
		{"machines", s.Machines},
		{"images.registry", s.Images.Registry},
		{"images.coreTag", s.Images.CoreTag},
		{"images.restTag", s.Images.RestTag},
		{"images.bootArtifactsX86_64", s.Images.BootArtifactsX86},
		{"images.bootArtifactsAarch64", s.Images.BootArtifactsAarch64},
		{"addresses.dhcp", s.Addresses.DHCP},
		{"addresses.pxe", s.Addresses.PXE},
		{"addresses.api", s.Addresses.API},
		{"addresses.rest", s.Addresses.REST},
		{"site.storageClass", s.Site.StorageClass},
		{"allocation.vpcType", s.Allocation.VPCType},
		{"allocation.sshPublicKey", s.Allocation.SSHPublicKey},
		{"handoverDir", s.HandoverDir},
	} {
		if f.value == "" {
			p.addf("%s is required", f.name)
		}
	}
	if h := s.APIHostname; h != "" && (len(h) > 253 || !hostnameRE.MatchString(h)) {
		p.addf("apiHostname %q must be a lowercase DNS name", h)
	}
	if s.Site.Replicas < 0 {
		p.addf("site.replicas must not be negative")
	}
	if s.HandoverDir != "" {
		if _, err := os.Stat(filepath.Join(s.HandoverDir, HandoverVaultKeysFile)); err == nil {
			p.addf("handoverDir %s already holds a handover bundle: move it away or name another directory", s.HandoverDir)
		}
	}
	for _, m := range s.DPUFactoryModels {
		if !dpuFactoryModels[m] {
			p.addf("dpuFactoryModels: %q is not one of bf2, bf3, bf4, unknown", m)
		}
	}
	s.validateIdentity(p)
	s.validateAddresses(p)
	s.validateImages(p)
	s.validateMachines(p)
	if siteConfigRead {
		s.validateSiteConfig(p)
	}
	s.validateAllocation(p)
}

// validateIdentity checks the external identity provider, when one is set.
func (s *Settings) validateIdentity(p *problems) {
	ext := s.Identity.External
	if ext == nil {
		return
	}
	if s.OrgID == "" {
		p.addf("orgID is required with identity.external: the org is %q only in the bundled Keycloak", DefaultOrgID)
	}
	for _, u := range []struct{ name, value string }{
		{"identity.external.issuer", ext.Issuer},
		{"identity.external.jwksURL", ext.JWKSURL},
		{"identity.external.tokenURL", ext.TokenURL},
	} {
		if parsed, err := url.Parse(u.value); err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			p.addf("%s %q must be an http or https URL", u.name, u.value)
		}
	}
	if ext.ClientID == "" {
		p.addf("identity.external.clientID is required")
	}
}

// validateAddresses checks the service addresses: each a valid address, IPv4
// where NICo hands it out over DHCPv4, and no two services on one address.
func (s *Settings) validateAddresses(p *problems) {
	a := s.Addresses
	if s.Identity.External == nil && a.Keycloak == "" {
		p.addf("addresses.keycloak is required with the bundled Keycloak: it is the token endpoint")
	}
	if s.Identity.External != nil && a.Keycloak != "" {
		p.addf("addresses.keycloak must be unset with identity.external: no Keycloak is installed")
	}
	if len(a.NTP) > maxNTPAddresses {
		p.addf("addresses.ntp lists %d addresses; at most %d are supported", len(a.NTP), maxNTPAddresses)
	}
	if a.DNS != "" && len(s.UpstreamDNS) == 0 {
		p.addf("upstreamDNS is required with addresses.dns: NICo's resolver forwards other names there")
	}
	for i, ip := range s.UpstreamDNS {
		if _, err := netip.ParseAddr(ip); err != nil {
			p.addf("upstreamDNS[%d] %q is not an IP address", i, ip)
		}
	}
	for i, server := range s.UpstreamNTP {
		if strings.TrimSpace(server) == "" {
			p.addf("upstreamNTP[%d] is empty", i)
		}
	}

	type service struct {
		name, value string
		ipv4        bool
	}
	services := []service{
		{"addresses.dhcp", a.DHCP, true},
		{"addresses.pxe", a.PXE, true},
		{"addresses.api", a.API, false},
		{"addresses.rest", a.REST, false},
		{"addresses.keycloak", a.Keycloak, false},
		{"addresses.dns", a.DNS, true},
		{"addresses.sshConsole", a.SSHConsole, false},
	}
	for i, ntp := range a.NTP {
		services = append(services, service{fmt.Sprintf("addresses.ntp[%d]", i), ntp, true})
	}
	owner := map[netip.Addr]string{}
	for _, svc := range services {
		if svc.value == "" {
			continue
		}
		addr, err := netip.ParseAddr(svc.value)
		switch {
		case err != nil:
			p.addf("%s %q is not an IP address", svc.name, svc.value)
			continue
		case svc.ipv4 && !addr.Is4():
			p.addf("%s %q must be an IPv4 address: NICo hands it out over DHCPv4", svc.name, svc.value)
		}
		if other, taken := owner[addr]; taken {
			p.addf("%s and %s are both %s: each service needs its own address", other, svc.name, addr)
			continue
		}
		owner[addr] = svc.name
	}
}

// validateImages checks the images the settings turn on.
func (s *Settings) validateImages(p *problems) {
	img := s.Images
	if s.Addresses.DNS != "" {
		for _, ref := range []struct{ name, value string }{
			{"images.unbound", img.Unbound},
			{"images.unboundExporter", img.UnboundExporter},
		} {
			switch {
			case ref.value == "" && ref.name == "images.unbound":
				p.addf("%s is required with addresses.dns", ref.name)
			case ref.value == "":
				// nicodeploy turns the exporter sidecar off without an image.
			case !strings.Contains(ref.value[strings.LastIndex(ref.value, "/")+1:], ":"):
				// The chart takes the image as a repository and a tag.
				p.addf("%s %q must carry a tag, as repository:tag", ref.name, ref.value)
			}
		}
	}
}

// validateMachines checks the machines file: every host named, its BMC MAC,
// serial and login set, and no name, MAC, serial or IP address used twice.
func (s *Settings) validateMachines(p *problems) {
	if s.Machines != "" && len(s.MachineList) == 0 {
		p.addf("machines %s lists no machine", s.Machines)
	}
	names, macs, serials, ips := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	// unique records value under kind for the machine at; the first holder keeps it.
	unique := func(seen map[string]string, kind, value, at string) {
		if other, taken := seen[value]; taken {
			p.addf("%s: %s %s is also %s's", at, kind, value, other)
			return
		}
		seen[value] = at
	}
	mac := func(at, field, value string, required bool) {
		if value == "" {
			if required {
				p.addf("%s: %s is required", at, field)
			}
			return
		}
		hw, err := net.ParseMAC(value)
		if err != nil || len(hw) != 6 {
			p.addf("%s: %s %q is not a MAC address", at, field, value)
			return
		}
		unique(macs, field, hw.String(), at)
	}
	ip := func(at, field, value string) {
		if value == "" {
			return
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			p.addf("%s: %s %q is not an IP address", at, field, value)
			return
		}
		unique(ips, field, addr.String(), at)
	}
	for i, m := range s.MachineList {
		at := fmt.Sprintf("machines[%d]", i)
		if m.Name == "" {
			p.addf("%s: name is required", at)
		} else {
			at = fmt.Sprintf("machines[%d] (%s)", i, m.Name)
			unique(names, "name", m.Name, at)
		}
		mac(at, "bmcMAC", m.BMCMAC, true)
		switch {
		case m.Serial == "":
			p.addf("%s: serial is required", at)
		case !chassisSerialRE.MatchString(m.Serial):
			p.addf("%s: serial %q must be 4 to 64 letters, digits, dashes or underscores: NICo refuses any other chassis serial", at, m.Serial)
		default:
			unique(serials, "serial", m.Serial, at)
		}
		switch {
		case m.BMCLogin == "":
			p.addf("%s: bmcLogin is required: it names the variables <bmcLogin>_USERNAME and <bmcLogin>_PASSWORD", at)
		case !envPrefixRE.MatchString(m.BMCLogin):
			p.addf("%s: bmcLogin %q must be an environment variable name prefix (letters, digits, underscores)", at, m.BMCLogin)
		}
		if m.DPUPolicy != "" && m.DPUPolicy != DPUPolicyManage && m.DPUPolicy != DPUPolicyNIC && m.DPUPolicy != DPUPolicyIgnore {
			p.addf("%s: dpuPolicy %q is not one of %s, %s, %s", at, m.DPUPolicy, DPUPolicyManage, DPUPolicyNIC, DPUPolicyIgnore)
		}
		if policy := s.dpuPolicy(m); (policy == DPUPolicyNIC || policy == DPUPolicyIgnore) && m.BootNICMAC == "" {
			p.addf("%s: bootNICMAC is required with DPU policy %s", at, policy)
		}
		if m.BootNICIP != "" && m.BootNICMAC == "" {
			p.addf("%s: bootNICIP needs bootNICMAC", at)
		}
		ip(at, "bmcIP", m.BMCIP)
		mac(at, "bootNICMAC", m.BootNICMAC, false)
		ip(at, "bootNICIP", m.BootNICIP)
		for j, d := range m.DPUs {
			dpu := fmt.Sprintf("dpus[%d].", j)
			if d.Serial != "" {
				unique(serials, dpu+"serial", d.Serial, at)
			}
			mac(at, dpu+"bmcMAC", d.BMCMAC, false)
			ip(at, dpu+"bmcIP", d.BMCIP)
			mac(at, dpu+"osMAC", d.OSMAC, false)
			ip(at, dpu+"osIP", d.OSIP)
		}
	}
}

// dpuPolicy returns the DPU policy NICo applies to m: its own nic or ignore,
// else the site config's default.
func (s *Settings) dpuPolicy(m Machine) string {
	if m.DPUPolicy == DPUPolicyNIC || m.DPUPolicy == DPUPolicyIgnore {
		return m.DPUPolicy
	}
	if s.SiteConfig.DefaultDPUPolicy == "" {
		return DPUPolicyManage
	}
	return s.SiteConfig.DefaultDPUPolicy
}

// validateSiteConfig checks the Core values' site config against what the
// bootstrap and NICo need of it.
func (s *Settings) validateSiteConfig(p *problems) {
	const at = "coreValues site config"
	sc := s.SiteConfig
	if name := sc.SiteName; len(name) > 63 || !dnsLabelRE.MatchString(name) {
		p.addf("%s: sitename %q must be a lowercase DNS label", at, name)
	}
	if sc.DNSDomain == "" {
		p.addf("%s: initial_domain_name is required: without it nico-api creates no network segment", at)
	}
	if sc.MachineValidation && s.Images.MachineValidation == "" {
		p.addf("images.machineValidation is required: the site config turns machine validation on")
	}
	for _, name := range requiredPools {
		pool, ok := sc.Pools[name]
		switch {
		case !ok:
			p.addf("%s: [pools.%s] is required", at, name)
		case len(pool.Ranges) == 0 && pool.Prefix == "":
			p.addf("%s: [pools.%s] must set ranges or a prefix", at, name)
		}
	}

	types := map[string]bool{}
	for name, n := range sc.Networks {
		switch n.Type {
		case "admin", "underlay", "hostinband":
			types[n.Type] = true
		default:
			p.addf("%s: [networks.%s] type %q is not one of admin, underlay, hostinband", at, name, n.Type)
		}
		if _, err := parsePrefix(n.Prefix); err != nil {
			p.addf("%s: [networks.%s] prefix %q is not a CIDR", at, name, n.Prefix)
		}
		if _, err := netip.ParseAddr(n.Gateway); err != nil {
			p.addf("%s: [networks.%s] gateway %q is not an IP address", at, name, n.Gateway)
		}
		if n.MTU == nil {
			p.addf("%s: [networks.%s] mtu is required: nico-api refuses a segment without it", at, name)
		}
		if n.ReserveFirst == nil {
			p.addf("%s: [networks.%s] reserve_first is required: nico-api refuses a segment without it", at, name)
		}
	}
	var managed, nicOrIgnore bool
	for _, m := range s.MachineList {
		if s.dpuPolicy(m) == DPUPolicyManage {
			managed = true
		} else {
			nicOrIgnore = true
		}
	}
	if managed && !types["admin"] {
		p.addf("%s: an admin network segment is required: hosts with DPU policy manage are ingested on it", at)
	}
	if nicOrIgnore && !types["hostinband"] {
		p.addf("%s: a hostinband network segment is required: hosts with DPU policy nic or ignore boot on it", at)
	}

	if len(sc.SiteFabricPrefixes) == 0 {
		p.addf("%s: site_fabric_prefixes is required: the control-plane machines' addresses are allocated from it", at)
	}
	fabric := s.prefixes(p, "site_fabric_prefixes", sc.SiteFabricPrefixes)
	deny := s.prefixes(p, "deny_prefixes", sc.DenyPrefixes)
	for _, d := range deny {
		for _, f := range fabric {
			if d.Overlaps(f) {
				p.addf("%s: deny_prefixes %s overlaps site_fabric_prefixes %s", at, d, f)
			}
		}
	}

	dhcpListed := false
	for _, server := range sc.DHCPServers {
		addr, err := netip.ParseAddr(server)
		if err != nil || !addr.Is4() {
			p.addf("%s: dhcp_servers entry %q is not an IPv4 address", at, server)
			continue
		}
		if dhcp, err := netip.ParseAddr(s.Addresses.DHCP); err == nil && addr == dhcp {
			dhcpListed = true
		}
	}
	if s.Addresses.DHCP != "" && !dhcpListed {
		p.addf("%s: dhcp_servers must list addresses.dhcp %s: DPUs relay DHCP to it", at, s.Addresses.DHCP)
	}
	for _, server := range sc.NTPServers {
		if addr, err := netip.ParseAddr(server); err != nil || !addr.Is4() {
			p.addf("%s: ntp_servers entry %q is not an IPv4 address", at, server)
		}
	}
	// NICo's DHCP hands these to hosts and DPUs, which need the .forge names and a clock to be ingested.
	if s.Addresses.DNS == "" && sc.DHCPNameservers == "" {
		p.addf("addresses.dns, or nico-dhcp.config.kea.hookParameters.nameservers in the Core values, is required: " +
			"DHCP hands hosts and DPUs the resolver of the .forge names")
	}
	if len(s.Addresses.NTP) == 0 && len(sc.NTPServers) == 0 && sc.DHCPNTPServer == "" {
		p.addf("addresses.ntp, the site config's ntp_servers, or nico-dhcp.config.kea.hookParameters.ntpServer in the Core values " +
			"is required: DHCP hands hosts and DPUs their NTP servers")
	}
}

// prefixes parses the site config's list key, adding a problem for each entry that is not a prefix.
func (s *Settings) prefixes(p *problems, key string, list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range list {
		prefix, err := parsePrefix(v)
		if err != nil {
			p.addf("coreValues site config: %s entry %q is not a CIDR", key, v)
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// parsePrefix parses a CIDR the way nico-api does: a bare address is a host prefix.
func parsePrefix(v string) (netip.Prefix, error) {
	if !strings.Contains(v, "/") {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.ParsePrefix(v)
}

// validateAllocation checks the VPC type and the prefix lengths: the tenant
// block must fit in a site fabric prefix and hold the control-plane subnet.
func (s *Settings) validateAllocation(p *problems) {
	al := s.Allocation
	switch al.VPCType {
	case "", VPCTypeEthernetVirtualizer:
	case VPCTypeFNN:
		p.addf("allocation.vpcType %s is not supported yet: NICo makes an FNN VPC external unless the tenant has a routing profile, "+
			"which the bootstrap does not set; use %s", VPCTypeFNN, VPCTypeEthernetVirtualizer)
	default:
		p.addf("allocation.vpcType %q is not one of %s, %s", al.VPCType, VPCTypeEthernetVirtualizer, VPCTypeFNN)
	}
	if al.SubnetPrefixLength < minSubnetPrefixLength || al.SubnetPrefixLength > maxSubnetPrefixLength {
		p.addf("allocation.subnetPrefixLength %d must be from %d to %d", al.SubnetPrefixLength, minSubnetPrefixLength, maxSubnetPrefixLength)
	}
	if al.TenantBlockPrefixLength < 1 || al.TenantBlockPrefixLength >= al.SubnetPrefixLength {
		p.addf("allocation.tenantBlockPrefixLength %d must be at least 1 and shorter than subnetPrefixLength %d",
			al.TenantBlockPrefixLength, al.SubnetPrefixLength)
	}
	// The tenant block is IPv4, cut from the largest IPv4 fabric prefix it fits in.
	shortest := -1
	for _, v := range s.SiteConfig.SiteFabricPrefixes {
		if prefix, err := parsePrefix(v); err == nil && prefix.Addr().Is4() && (shortest < 0 || prefix.Bits() < shortest) {
			shortest = prefix.Bits()
		}
	}
	switch {
	case len(s.SiteConfig.SiteFabricPrefixes) == 0:
		// Reported with the site config.
	case shortest < 0:
		p.addf("coreValues site config: site_fabric_prefixes must hold an IPv4 prefix: the tenant block is IPv4")
	case al.TenantBlockPrefixLength > 0 && al.TenantBlockPrefixLength < shortest:
		p.addf("allocation.tenantBlockPrefixLength %d is shorter than the largest site fabric prefix, /%d, so no fabric prefix holds the tenant block",
			al.TenantBlockPrefixLength, shortest)
	}
}
