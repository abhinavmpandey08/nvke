// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicosettings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleKey is the fixture's SSH public key.
const exampleKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFaUvKa5gh7fX1JoWzi2kpa8cZBzIOdt36jSRbxyzYyG example@nvke"

// fixture writes testdata/nico.yaml, with each edit applied, into a temporary
// directory and returns its path.
func fixture(t *testing.T, edits ...func(string) string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "nico.yaml"))
	require.NoError(t, err)
	content := string(data)
	for _, edit := range edits {
		content = edit(content)
	}
	path := filepath.Join(t.TempDir(), "nico.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// replace returns an edit that replaces from with to, failing when from is absent.
func replace(t *testing.T, from, to string) func(string) string {
	return func(s string) string {
		require.Contains(t, s, from)
		return strings.Replace(s, from, to, 1)
	}
}

func TestLoad_ReadsEverything(t *testing.T) {
	path := fixture(t)
	handover := filepath.Join(t.TempDir(), "site-a-nico-handover")

	s, err := Load(path, handover)
	require.NoError(t, err)

	assert.Equal(t, path, s.Path)
	assert.Equal(t, handover, s.HandoverDir)
	assert.Equal(t, exampleKey, s.Allocation.SSHPublicKey)
	assert.Equal(t, DefaultOrgID, s.EffectiveOrgID())
	require.Len(t, s.Machines, 2)
	assert.Equal(t, DPUPolicyNIC, s.Machines[1].DPUPolicy)
	assert.Equal(t, "10.2.0.20", s.Machines[1].DPUs[0].BMCIP)
	assert.Equal(t, BGPSpeaker{ASN: 65010, Peers: []BGPPeer{{Address: "10.0.0.1", ASN: 65000}}}, s.BGP.Seed)
	assert.Equal(t, "192.0.2.13:8388", s.Addresses.RESTEndpoint().String())
	assert.Equal(t, "192.0.2.14:8082", s.Addresses.KeycloakEndpoint().String())
	assert.Equal(t, "api.site-a.example.com", s.CoreValues["nico-api"].(map[string]any)["hostname"])

	sc := s.SiteConfig
	assert.Equal(t, "site-a", sc.SiteName)
	assert.Equal(t, "site-a.example.com", sc.DNSDomain)
	assert.Equal(t, DPUPolicyManage, sc.DefaultDPUPolicy)
	assert.False(t, sc.AttestationEnabled)
	assert.True(t, sc.MachineValidation)
	assert.False(t, sc.FirmwareAutoupdate)
	assert.Equal(t, []string{"10.100.0.0/16"}, sc.SiteFabricPrefixes)
	assert.Equal(t, []string{"192.0.2.10"}, sc.DHCPServers)
	mtu, reserve := 9000, 5
	assert.Equal(t, Network{Type: "admin", Prefix: "10.1.0.0/24", Gateway: "10.1.0.1", MTU: &mtu, ReserveFirst: &reserve}, sc.Networks["admin"])
	assert.Equal(t, []PoolRange{{Start: "100", End: "501"}}, sc.Pools["vlan-id"].Ranges)
}

func TestLoad_TrimsABlockScalarKey(t *testing.T) {
	path := fixture(t, replace(t, "  sshPublicKey: "+exampleKey, "  sshPublicKey: |\n    "+exampleKey))

	s, err := Load(path, "")
	require.NoError(t, err)
	assert.Equal(t, exampleKey, s.Allocation.SSHPublicKey)
}

func TestLoad_Refuses(t *testing.T) {
	for _, tt := range []struct {
		name    string
		edit    func(string) string
		wantErr []string
	}{
		{
			name:    "an unknown field in the settings",
			edit:    func(s string) string { return s + "apiHostnmae: typo\n" },
			wantErr: []string{"apiHostnmae"},
		},
		{
			name:    "an unknown field in a machine",
			edit:    replace(t, "    serial: SN-A\n", "    serial: SN-A\n    sereal: typo\n"),
			wantErr: []string{"sereal"},
		},
		{
			name:    "an unknown field in bgp",
			edit:    replace(t, "  seed:\n    asn: 65010\n", "  seed:\n    asn: 65010\n    holdTime: 90\n"),
			wantErr: []string{"holdTime"},
		},
		{
			name:    "the removed bgp.site",
			edit:    replace(t, "bgp:\n", "bgp:\n  site:\n    asn: 65020\n"),
			wantErr: []string{"field site not found"},
		},
		{
			name:    "the removed handoverDir",
			edit:    replace(t, "apiHostname: api.site-a.example.com\n", "apiHostname: api.site-a.example.com\nhandoverDir: handover\n"),
			wantErr: []string{"handoverDir"},
		},
		{
			name:    "an empty settings file",
			edit:    func(string) string { return "" },
			wantErr: []string{"the file is empty"},
		},
		{
			name: "no machines, Core values or SSH public key",
			edit: func(s string) string {
				s = s[:strings.Index(s, "machines:\n")]
				return strings.Replace(s, "  sshPublicKey: "+exampleKey+"\n", "", 1)
			},
			wantErr: []string{"allocation.sshPublicKey is required", "coreValues is required", "machines is required"},
		},
		{
			name:    "an SSH public key that is a path",
			edit:    replace(t, "sshPublicKey: "+exampleKey, "sshPublicKey: id.pub"),
			wantErr: []string{"allocation.sshPublicKey must be one OpenSSH public key"},
		},
		{
			name:    "an SSH public key whose type is not its key's",
			edit:    replace(t, "sshPublicKey: ssh-ed25519 ", "sshPublicKey: ssh-rsa "),
			wantErr: []string{"allocation.sshPublicKey must be one OpenSSH public key"},
		},
		{
			name:    "a site name that is not a DNS label",
			edit:    replace(t, `sitename = "site-a"`, `sitename = "Site_A"`),
			wantErr: []string{`sitename "Site_A" must be a lowercase DNS label`},
		},
		{
			name: "several problems at once",
			edit: func(s string) string {
				return strings.NewReplacer("apiHostname: api.site-a.example.com\n", "", "  pxe: 192.0.2.11\n", "").Replace(s)
			},
			wantErr: []string{"apiHostname is required\naddresses.pxe is required"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Load(fixture(t, tt.edit), "")
			require.Error(t, err)
			assert.Nil(t, s)
			for _, want := range tt.wantErr {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	handedOver := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(handedOver, HandoverVaultKeysFile), nil, 0o600))
	for _, tt := range []struct {
		name    string
		mutate  func(s *Settings)
		wantErr string
	}{
		{name: "the fixture is valid", mutate: func(*Settings) {}},
		{
			name:    "a missing site name",
			mutate:  func(s *Settings) { s.SiteConfig.SiteName = "" },
			wantErr: `sitename "" must be a lowercase DNS label`,
		},
		{
			name:    "an API hostname that is not a DNS name",
			mutate:  func(s *Settings) { s.APIHostname = "api_site" },
			wantErr: `apiHostname "api_site" must be a lowercase DNS name`,
		},
		{
			name:    "a missing image",
			mutate:  func(s *Settings) { s.Images.BootArtifactsAarch64 = "" },
			wantErr: "images.bootArtifactsAarch64 is required",
		},
		{
			name:    "an address that is not an IP",
			mutate:  func(s *Settings) { s.Addresses.API = "api.example.com" },
			wantErr: `addresses.api "api.example.com" is not an IP address`,
		},
		{
			name:    "a DHCP address that is IPv6",
			mutate:  func(s *Settings) { s.Addresses.DHCP = "2001:db8::10" },
			wantErr: "addresses.dhcp \"2001:db8::10\" must be an IPv4 address",
		},
		{
			name:    "two services on one address",
			mutate:  func(s *Settings) { s.Addresses.REST = s.Addresses.API },
			wantErr: "addresses.api and addresses.rest are both 192.0.2.12",
		},
		{
			name: "REST and Keycloak on one address and their own ports",
			mutate: func(s *Settings) {
				s.Addresses.REST, s.Addresses.Keycloak = "10.180.126.250:30388", "10.180.126.250:30082"
			},
			wantErr: "",
		},
		{
			name:    "REST and Keycloak on one address and port",
			mutate:  func(s *Settings) { s.Addresses.REST, s.Addresses.Keycloak = "192.0.2.13:8082", "192.0.2.13" },
			wantErr: "addresses.rest and addresses.keycloak are both 192.0.2.13:8082: services that share an address need different ports",
		},
		{
			name:    "Keycloak on another service's address, on another port",
			mutate:  func(s *Settings) { s.Addresses.Keycloak = "192.0.2.12:30082" },
			wantErr: "addresses.api and addresses.keycloak are both 192.0.2.12: each service needs its own address",
		},
		{
			name:    "an IPv6 REST address with a port",
			mutate:  func(s *Settings) { s.Addresses.REST = "[2001:db8::13]:30388" },
			wantErr: "",
		},
		{
			name:    "a REST port that is not a port",
			mutate:  func(s *Settings) { s.Addresses.REST = "192.0.2.13:http" },
			wantErr: `addresses.rest "192.0.2.13:http" is not an IP address or IP:port`,
		},
		{
			name:    "a Keycloak port of 0",
			mutate:  func(s *Settings) { s.Addresses.Keycloak = "192.0.2.14:0" },
			wantErr: `addresses.keycloak "192.0.2.14:0" has port 0`,
		},
		{
			name:    "an NTP address shared with DNS",
			mutate:  func(s *Settings) { s.Addresses.NTP[2] = s.Addresses.DNS },
			wantErr: "addresses.dns and addresses.ntp[2] are both 192.0.2.15",
		},
		{
			name:    "too many NTP addresses",
			mutate:  func(s *Settings) { s.Addresses.NTP = append(s.Addresses.NTP, "192.0.2.19") },
			wantErr: "addresses.ntp lists 4 addresses; at most 3",
		},
		{
			name:    "no Keycloak address",
			mutate:  func(s *Settings) { s.Addresses.Keycloak = "" },
			wantErr: "addresses.keycloak is required",
		},
		{
			name:    "NICo DNS without an upstream",
			mutate:  func(s *Settings) { s.UpstreamDNS = nil },
			wantErr: "upstreamDNS is required with addresses.dns",
		},
		{
			name:    "NICo DNS without unbound images",
			mutate:  func(s *Settings) { s.Images.Unbound = "" },
			wantErr: "images.unbound is required with addresses.dns",
		},
		{
			name:    "NICo DNS without the unbound exporter image",
			mutate:  func(s *Settings) { s.Images.UnboundExporter = "" },
			wantErr: "",
		},
		{
			name:    "an unbound image without a tag",
			mutate:  func(s *Settings) { s.Images.UnboundExporter = "registry.example.com:5000/unbound_exporter" },
			wantErr: "images.unboundExporter \"registry.example.com:5000/unbound_exporter\" must carry a tag",
		},
		{
			name: "the site's DNS needs no unbound images",
			mutate: func(s *Settings) {
				s.Addresses.DNS = ""
				s.UpstreamDNS = nil
				s.Images.Unbound = ""
				s.Images.UnboundExporter = ""
				s.SiteConfig.DHCPNameservers = "198.51.100.53"
			},
			wantErr: "",
		},
		{
			name:    "no DNS server for DHCP to hand out",
			mutate:  func(s *Settings) { s.Addresses.DNS = "" },
			wantErr: "addresses.dns, or nico-dhcp.config.kea.hookParameters.nameservers in the Core values, is required",
		},
		{
			name:    "no NTP server for DHCP to hand out",
			mutate:  func(s *Settings) { s.Addresses.NTP = nil; s.SiteConfig.NTPServers = nil },
			wantErr: "addresses.ntp, the site config's ntp_servers, or nico-dhcp.config.kea.hookParameters.ntpServer",
		},
		{
			name: "the site's NTP given in the Core values",
			mutate: func(s *Settings) {
				s.Addresses.NTP = nil
				s.SiteConfig.NTPServers = nil
				s.SiteConfig.DHCPNTPServer = "198.51.100.123"
			},
			wantErr: "",
		},
		{
			name:    "a handover directory that holds a bundle",
			mutate:  func(s *Settings) { s.HandoverDir = handedOver },
			wantErr: "already holds a handover bundle",
		},
		{
			name:    "machine validation without its image",
			mutate:  func(s *Settings) { s.Images.MachineValidation = "" },
			wantErr: "images.machineValidation is required",
		},
		{
			name:    "machine validation off needs no image",
			mutate:  func(s *Settings) { s.Images.MachineValidation = ""; s.SiteConfig.MachineValidation = false },
			wantErr: "",
		},
		{
			name:    "no BGP",
			mutate:  func(s *Settings) { s.BGP = BGP{} },
			wantErr: "bgp.seed.asn is required: an ASN from 1 to 4294967295\nbgp.seed.peers must list at least one router",
		},
		{
			name:    "a BGP peer without an address or ASN",
			mutate:  func(s *Settings) { s.BGP.Seed.Peers = append(s.BGP.Seed.Peers, BGPPeer{}) },
			wantErr: "bgp.seed.peers[1].address is required\nbgp.seed.peers[1].asn is required",
		},
		{
			name:    "a BGP peer address that is not an IP",
			mutate:  func(s *Settings) { s.BGP.Seed.Peers[0].Address = "router.example.com" },
			wantErr: `bgp.seed.peers[0].address "router.example.com" is not an IP address`,
		},
		{
			name: "a BGP peer listed twice",
			mutate: func(s *Settings) {
				s.BGP.Seed.Peers = append(s.BGP.Seed.Peers, BGPPeer{Address: "10.0.0.1", ASN: 65001})
			},
			wantErr: "bgp.seed.peers[1].address 10.0.0.1 is also bgp.seed.peers[0]'s",
		},
		{
			name:    "an iBGP IPv6 peer",
			mutate:  func(s *Settings) { s.BGP.Seed.Peers[0] = BGPPeer{Address: "2001:db8::1", ASN: s.BGP.Seed.ASN} },
			wantErr: "",
		},
		{
			name:    "two SSH public keys",
			mutate:  func(s *Settings) { s.Allocation.SSHPublicKey += "\n" + exampleKey },
			wantErr: "allocation.sshPublicKey must be one OpenSSH public key",
		},
		{
			name:    "an SSH public key without a comment",
			mutate:  func(s *Settings) { s.Allocation.SSHPublicKey = strings.TrimSuffix(exampleKey, " example@nvke") },
			wantErr: "",
		},
		{
			name:    "an unknown DPU factory model",
			mutate:  func(s *Settings) { s.DPUFactoryModels = []string{"bf3", "bf9"} },
			wantErr: `dpuFactoryModels: "bf9" is not one of`,
		},
		{
			name:    "no machines",
			mutate:  func(s *Settings) { s.Machines = nil },
			wantErr: "machines is required",
		},
		{
			name: "a machine without a name, serial or login",
			mutate: func(s *Settings) {
				s.Machines[0].Name = ""
				s.Machines[0].Serial = ""
				s.Machines[0].BMCLogin = ""
			},
			wantErr: "machines[0]: name is required\nmachines[0]: serial is required\nmachines[0]: bmcLogin is required",
		},
		{
			name:    "a login prefix that is not a variable name",
			mutate:  func(s *Settings) { s.Machines[0].BMCLogin = "NICO-BMC" },
			wantErr: `machines[0] (host-a): bmcLogin "NICO-BMC" must be an environment variable name prefix`,
		},
		{
			name:    "a serial NICo refuses",
			mutate:  func(s *Settings) { s.Machines[0].Serial = "SN.A" },
			wantErr: `machines[0] (host-a): serial "SN.A" must be 4 to 64 letters, digits, dashes or underscores`,
		},
		{
			name:    "a duplicate name",
			mutate:  func(s *Settings) { s.Machines[1].Name = "host-a" },
			wantErr: "machines[1] (host-a): name host-a is also machines[0] (host-a)'s",
		},
		{
			name:    "a duplicate MAC in another spelling",
			mutate:  func(s *Settings) { s.Machines[1].BootNICMAC = "02-00-00-00-00-01" },
			wantErr: "machines[1] (host-b): bootNICMAC 02:00:00:00:00:01 is also machines[0] (host-a)'s",
		},
		{
			name:    "a duplicate serial",
			mutate:  func(s *Settings) { s.Machines[0].Serial = "DPU-SN-B" },
			wantErr: "machines[1] (host-b): dpus[0].serial DPU-SN-B is also machines[0] (host-a)'s",
		},
		{
			name:    "a duplicate IP",
			mutate:  func(s *Settings) { s.Machines[0].BMCIP = "10.2.0.20" },
			wantErr: "machines[1] (host-b): dpus[0].bmcIP 10.2.0.20 is also machines[0] (host-a)'s",
		},
		{
			name:    "a malformed MAC",
			mutate:  func(s *Settings) { s.Machines[0].BMCMAC = "02:00:00:00:00" },
			wantErr: `machines[0] (host-a): bmcMAC "02:00:00:00:00" is not a MAC address`,
		},
		{
			name:    "an unknown DPU policy",
			mutate:  func(s *Settings) { s.Machines[0].DPUPolicy = "nic_mode" },
			wantErr: `machines[0] (host-a): dpuPolicy "nic_mode" is not one of manage, nic, ignore`,
		},
		{
			name:    "a NIC-policy host without a boot NIC",
			mutate:  func(s *Settings) { s.Machines[1].BootNICMAC = "" },
			wantErr: "machines[1] (host-b): bootNICMAC is required with DPU policy nic",
		},
		{
			name:    "the site's default policy needs a boot NIC too",
			mutate:  func(s *Settings) { s.SiteConfig.DefaultDPUPolicy = DPUPolicyIgnore },
			wantErr: "machines[0] (host-a): bootNICMAC is required with DPU policy ignore",
		},
		{
			name:    "no DNS domain",
			mutate:  func(s *Settings) { s.SiteConfig.DNSDomain = "" },
			wantErr: "initial_domain_name is required",
		},
		{
			name:    "a missing pool",
			mutate:  func(s *Settings) { delete(s.SiteConfig.Pools, "vpc-vni") },
			wantErr: "[pools.vpc-vni] is required",
		},
		{
			name:    "a pool with no ranges",
			mutate:  func(s *Settings) { s.SiteConfig.Pools["vni"] = Pool{Type: "integer"} },
			wantErr: "[pools.vni] must set ranges or a prefix",
		},
		{
			name:    "a pool given by prefix",
			mutate:  func(s *Settings) { s.SiteConfig.Pools["lo-ip"] = Pool{Type: "ipv4", Prefix: "10.200.0.0/24"} },
			wantErr: "",
		},
		{
			name:    "managed DPUs without an admin segment",
			mutate:  func(s *Settings) { delete(s.SiteConfig.Networks, "admin") },
			wantErr: "an admin network segment is required",
		},
		{
			name:    "NIC-mode hosts without a host in-band segment",
			mutate:  func(s *Settings) { delete(s.SiteConfig.Networks, "inband") },
			wantErr: "a hostinband network segment is required",
		},
		{
			name:    "a segment without a gateway",
			mutate:  func(s *Settings) { s.SiteConfig.Networks["oob"] = Network{Type: "underlay", Prefix: "10.2.0.0/24"} },
			wantErr: `[networks.oob] gateway "" is not an IP address`,
		},
		{
			name: "a segment without its MTU or reserved addresses",
			mutate: func(s *Settings) {
				n := s.SiteConfig.Networks["oob"]
				n.MTU, n.ReserveFirst = nil, nil
				s.SiteConfig.Networks["oob"] = n
			},
			wantErr: "[networks.oob] mtu is required: nico-api refuses a segment without it\n" +
				"coreValues site config: [networks.oob] reserve_first is required",
		},
		{
			name: "an unknown segment type",
			mutate: func(s *Settings) {
				s.SiteConfig.Networks["oob"] = Network{Type: "tenant", Prefix: "10.2.0.0/24", Gateway: "10.2.0.1"}
			},
			wantErr: `[networks.oob] type "tenant" is not one of admin, underlay, hostinband`,
		},
		{
			name:    "no fabric prefix",
			mutate:  func(s *Settings) { s.SiteConfig.SiteFabricPrefixes = nil },
			wantErr: "site_fabric_prefixes is required",
		},
		{
			name:    "a denied prefix inside the fabric",
			mutate:  func(s *Settings) { s.SiteConfig.DenyPrefixes = []string{"10.100.4.0/24"} },
			wantErr: "deny_prefixes 10.100.4.0/24 overlaps site_fabric_prefixes 10.100.0.0/16",
		},
		{
			name:    "a bare address is a host prefix",
			mutate:  func(s *Settings) { s.SiteConfig.DenyPrefixes = []string{"10.100.0.9"} },
			wantErr: "deny_prefixes 10.100.0.9/32 overlaps",
		},
		{
			name:    "DHCP servers without NICo's",
			mutate:  func(s *Settings) { s.SiteConfig.DHCPServers = []string{"192.0.2.99"} },
			wantErr: "dhcp_servers must list addresses.dhcp 192.0.2.10",
		},
		{
			name:    "an unknown VPC type",
			mutate:  func(s *Settings) { s.Allocation.VPCType = "flat" },
			wantErr: `allocation.vpcType "flat" is not one of ethernetVirtualizer, fnn`,
		},
		{
			name:    "a subnet longer than REST takes",
			mutate:  func(s *Settings) { s.Allocation.SubnetPrefixLength = 31 },
			wantErr: "allocation.subnetPrefixLength 31 must be from 8 to 30",
		},
		{
			name:    "an FNN VPC, until the bootstrap sets the tenant's routing profile",
			mutate:  func(s *Settings) { s.Allocation.VPCType = VPCTypeFNN },
			wantErr: "allocation.vpcType fnn is not supported yet",
		},
		{
			name:    "a tenant block no larger than the subnet",
			mutate:  func(s *Settings) { s.Allocation.TenantBlockPrefixLength = 26 },
			wantErr: "allocation.tenantBlockPrefixLength 26 must be at least 1 and shorter than subnetPrefixLength 26",
		},
		{
			name:    "a tenant block larger than the fabric",
			mutate:  func(s *Settings) { s.Allocation.TenantBlockPrefixLength = 12 },
			wantErr: "allocation.tenantBlockPrefixLength 12 is shorter than the largest site fabric prefix, /16",
		},
		{
			name:    "a tenant block the size of the fabric",
			mutate:  func(s *Settings) { s.Allocation.TenantBlockPrefixLength = 16 },
			wantErr: "",
		},
		{
			name:    "only IPv6 fabric",
			mutate:  func(s *Settings) { s.SiteConfig.SiteFabricPrefixes = []string{"2001:db8::/48"} },
			wantErr: "site_fabric_prefixes must hold an IPv4 prefix",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Load(fixture(t), "")
			require.NoError(t, err)
			tt.mutate(s)
			var p problems
			s.validate(&p, true)
			if tt.wantErr == "" {
				assert.NoError(t, p.err())
				return
			}
			require.Error(t, p.err())
			assert.Contains(t, p.err().Error(), tt.wantErr)
		})
	}
}

func TestParseSiteConfig(t *testing.T) {
	values := func(toml string) []byte {
		return []byte("nico-api:\n  siteConfig:\n    nicoApiSiteConfig: |\n      " + strings.ReplaceAll(toml, "\n", "\n      ") + "\n")
	}
	for _, tt := range []struct {
		name    string
		values  []byte
		want    SiteConfig
		wantErr string
	}{
		{
			name:   "omitted switches take the chart's base config",
			values: values(`sitename = "site-a"`),
			want:   SiteConfig{SiteName: "site-a", DefaultDPUPolicy: DPUPolicyManage, AttestationEnabled: true, MachineValidation: true, FirmwareAutoupdate: true},
		},
		{
			name: "switches set off",
			values: values("attestation_enabled = false\n[machine_validation_config]\nenabled = false\n" +
				"[firmware_global]\nautoupdate = false\n[site_explorer]\ndpu_policy = \"ignore\""),
			want: SiteConfig{DefaultDPUPolicy: DPUPolicyIgnore},
		},
		{
			name:   "the legacy dpu_mode key",
			values: values("[site_explorer]\ndpu_mode = \"nic_mode\""),
			want:   SiteConfig{DefaultDPUPolicy: DPUPolicyNIC, AttestationEnabled: true, MachineValidation: true, FirmwareAutoupdate: true},
		},
		{
			name:   "dpu_policy wins over dpu_mode",
			values: values("[site_explorer]\ndpu_policy = \"use_as_nic\"\ndpu_mode = \"no_dpu\""),
			want:   SiteConfig{DefaultDPUPolicy: DPUPolicyNIC, AttestationEnabled: true, MachineValidation: true, FirmwareAutoupdate: true},
		},
		{
			name: "the DNS and NTP servers DHCP hands out",
			values: append(values(`sitename = "site-a"`),
				"nico-dhcp:\n  config:\n    kea:\n      hookParameters:\n        nameservers: \"198.51.100.53\"\n        ntpServer: \" 198.51.100.123 \"\n"...),
			want: SiteConfig{
				SiteName: "site-a", DefaultDPUPolicy: DPUPolicyManage, AttestationEnabled: true, MachineValidation: true, FirmwareAutoupdate: true,
				DHCPNameservers: "198.51.100.53", DHCPNTPServer: "198.51.100.123",
			},
		},
		{
			name:    "an unknown DPU policy",
			values:  values("[site_explorer]\ndpu_policy = \"offload\""),
			wantErr: `dpu_policy "offload" is not one of manage, nic, ignore`,
		},
		{
			name:    "DPF turned on",
			values:  values("[dpf]\nenabled = true"),
			wantErr: "[dpf] enabled = true is not supported",
		},
		{
			name:    "no site config",
			values:  []byte("nico-api:\n  hostname: api.example.com\n"),
			wantErr: "nico-api.siteConfig.nicoApiSiteConfig is not set",
		},
		{
			name:    "the site config turned off",
			values:  []byte("nico-api:\n  siteConfig:\n    enabled: false\n    nicoApiSiteConfig: 'sitename = \"a\"'\n"),
			wantErr: "nico-api.siteConfig.enabled is false",
		},
		{
			name:    "TOML that does not parse",
			values:  values("sitename = "),
			wantErr: "parsing nico-api.siteConfig.nicoApiSiteConfig",
		},
		{
			name:    "a pool range nico-api would refuse",
			values:  values("[pools.vni]\ntype = \"integer\"\nranges = [{ start = 1, end = 2 }]"),
			wantErr: "parsing nico-api.siteConfig.nicoApiSiteConfig",
		},
		{
			name:    "YAML that does not parse",
			values:  []byte("nico-api: [\n"),
			wantErr: "parsing the values",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSiteConfig(tt.values)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretsFromEnv(t *testing.T) {
	const (
		rootPassword = "example-root-password"
		bmcPassword  = "example-bmc-password"
	)
	setAll := func(t *testing.T) {
		for env, v := range map[string]string{
			SiteWideBMCRootPasswordEnv: rootPassword, HostUEFIPasswordEnv: "example-host-uefi", DPUUEFIPasswordEnv: "example-dpu-uefi",
			DPUBMCFactoryUsernameEnv: "", DPUBMCFactoryPasswordEnv: "", RegistryUsernameEnv: "", RegistryPasswordEnv: "",
			BGPPasswordEnv: "", "NICO_BMC_EXAMPLE_USERNAME": "root", "NICO_BMC_EXAMPLE_PASSWORD": bmcPassword,
		} {
			t.Setenv(env, v)
		}
	}
	for _, tt := range []struct {
		name     string
		env      map[string]string
		settings func(s *Settings)
		wantErr  []string
	}{
		{name: "every required secret set"},
		{
			name:    "the site-wide secrets missing",
			env:     map[string]string{SiteWideBMCRootPasswordEnv: "", HostUEFIPasswordEnv: "", DPUUEFIPasswordEnv: ""},
			wantErr: []string{SiteWideBMCRootPasswordEnv + " is not set", HostUEFIPasswordEnv + " is not set", DPUUEFIPasswordEnv + " is not set"},
		},
		{
			name:    "a machine's BMC login missing",
			env:     map[string]string{"NICO_BMC_EXAMPLE_PASSWORD": ""},
			wantErr: []string{"NICO_BMC_EXAMPLE_PASSWORD is not set: it is the BMC factory login of machine host-a"},
		},
		{
			name:    "half a DPU factory login",
			env:     map[string]string{DPUBMCFactoryUsernameEnv: "root"},
			wantErr: []string{DPUBMCFactoryUsernameEnv + " and " + DPUBMCFactoryPasswordEnv + " must be set together"},
		},
		{
			name:     "DPU factory models without the login",
			settings: func(s *Settings) { s.DPUFactoryModels = []string{"bf3"} },
			wantErr:  []string{"dpuFactoryModels names the DPU models"},
		},
		{
			name: "the BGP password",
			env:  map[string]string{BGPPasswordEnv: "example-bgp-password"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Load(fixture(t), "")
			require.NoError(t, err)
			if tt.settings != nil {
				tt.settings(s)
			}
			setAll(t)
			for env, v := range tt.env {
				t.Setenv(env, v)
			}
			got, err := SecretsFromEnv(s)
			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				for _, want := range tt.wantErr {
					assert.Contains(t, err.Error(), want)
				}
				assert.NotContains(t, err.Error(), rootPassword)
				assert.NotContains(t, err.Error(), bmcPassword)
				assert.Equal(t, Secrets{}, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, rootPassword, got.SiteWideBMCRootPassword)
			assert.Equal(t, map[string]Login{"NICO_BMC_EXAMPLE": {Username: "root", Password: bmcPassword}}, got.BMCLogins)
			assert.Equal(t, tt.env[BGPPasswordEnv], got.BGPPassword)
		})
	}
}
