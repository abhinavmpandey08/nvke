// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicosettings reads the NICo settings file: everything
// `nvkectl bootstrap site` needs to install NICo, ingest the site's machines
// and hand NICo over, kept out of the site spec. infra.nico.managed.settings
// names it. Secrets are not in it; they come from the environment.
package nicosettings

// Environment variables the secrets are read from.
const (
	// SiteWideBMCRootPasswordEnv holds the password NICo sets on every BMC it ingests.
	SiteWideBMCRootPasswordEnv = "NVKECTL_NICO_BMC_ROOT_PASSWORD"
	// HostUEFIPasswordEnv and DPUUEFIPasswordEnv hold the UEFI passwords NICo sets.
	HostUEFIPasswordEnv = "NVKECTL_NICO_HOST_UEFI_PASSWORD"
	DPUUEFIPasswordEnv  = "NVKECTL_NICO_DPU_UEFI_PASSWORD"
	// DPUBMCFactoryUsernameEnv and DPUBMCFactoryPasswordEnv hold the DPU BMC
	// factory login, when it is not the vendor default. Optional.
	DPUBMCFactoryUsernameEnv = "NVKECTL_NICO_DPU_BMC_FACTORY_USERNAME"
	DPUBMCFactoryPasswordEnv = "NVKECTL_NICO_DPU_BMC_FACTORY_PASSWORD"
	// RegistryUsernameEnv and RegistryPasswordEnv log in to Images.Registry.
	// Optional: without a password the images are pulled anonymously.
	RegistryUsernameEnv = "NVKECTL_NICO_REGISTRY_USERNAME"
	RegistryPasswordEnv = "NVKECTL_NICO_REGISTRY_PASSWORD"
	// ClientSecretEnv holds Identity.External's client secret.
	ClientSecretEnv = "NVKECTL_NICO_CLIENT_SECRET"
)

// Values Allocation.VPCType takes.
const (
	VPCTypeEthernetVirtualizer = "ethernetVirtualizer"
	VPCTypeFNN                 = "fnn"
)

// DPU policies a machine takes.
const (
	DPUPolicyManage = "manage"
	DPUPolicyNIC    = "nic"
	DPUPolicyIgnore = "ignore"
)

// DefaultOrgID is the org NICo's bundled Keycloak realm defines.
const DefaultOrgID = "ncx"

// DefaultSiteReplicas is how many replicas NICo's stateful services run on the site cluster.
const DefaultSiteReplicas = 3

// HandoverVaultKeysFile is the handover bundle's file of Vault's unseal keys
// and root token. A handover directory that holds it already holds a bundle.
const HandoverVaultKeysFile = "vault-keys.json"

// File is the NICo settings file. Relative paths in it resolve from the file's
// own directory.
type File struct {
	// OrgID is the NICo org the site's objects are created in. Optional with the
	// bundled Keycloak, where it defaults to DefaultOrgID.
	OrgID string `yaml:"orgID,omitempty"`
	// APIHostname is the NICo API's host name, put on its certificate. Required.
	APIHostname string `yaml:"apiHostname"`
	// CoreValues is a NICo Core values file in the format of NICo's
	// helm-prereqs/values/nico-core.yaml. Its nico-api.siteConfig.nicoApiSiteConfig
	// TOML is the site config: the site's name in NICo, DNS domain, network segments, resource pools,
	// tenant address space, blocked ranges, DHCP and NTP servers, default DPU
	// policy, attestation and validation settings. Required.
	CoreValues string `yaml:"coreValues"`
	// Machines is the machines file. Required.
	Machines string `yaml:"machines"`
	// Images are NICo's images.
	Images Images `yaml:"images"`
	// Addresses are the fixed addresses NICo's services are published on, the
	// same on the bootstrap and the site cluster.
	Addresses Addresses `yaml:"addresses"`
	// UpstreamDNS is where NICo's .forge resolver forwards other names.
	// Required when Addresses.DNS is set.
	UpstreamDNS []string `yaml:"upstreamDNS,omitempty"`
	// UpstreamNTP is where NICo's NTP servers sync from. Optional.
	UpstreamNTP []string `yaml:"upstreamNTP,omitempty"`
	// Site is how NICo runs on the site cluster.
	Site SiteProfile `yaml:"site"`
	// Allocation is what the control-plane machines are allocated with.
	Allocation Allocation `yaml:"allocation"`
	// Identity is the identity provider NICo's REST API trusts.
	Identity Identity `yaml:"identity,omitempty"`
	// DPUFactoryModels are the DPU models the DPU BMC factory login is set for,
	// when DPUBMCFactoryUsernameEnv is set.
	DPUFactoryModels []string `yaml:"dpuFactoryModels,omitempty"`
	// HandoverDir is the directory the handover bundle is written to. Required,
	// and must not hold a bundle already.
	HandoverDir string `yaml:"handoverDir"`
}

// Images are NICo's images. Their tags must be builds of the NICo release
// nvkectl pins.
type Images struct {
	// Registry is where Core and REST images are pulled from. Required.
	Registry string `yaml:"registry"`
	// CoreTag and RestTag are the Core and REST image tags. Required.
	CoreTag string `yaml:"coreTag"`
	RestTag string `yaml:"restTag"`
	// BootArtifactsX86 and BootArtifactsAarch64 are the boot-artifact images
	// NICo's PXE and API serve hosts and DPUs from. Required.
	BootArtifactsX86     string `yaml:"bootArtifactsX86_64"`
	BootArtifactsAarch64 string `yaml:"bootArtifactsAarch64"`
	// MachineValidation is the machine-validation image. Required when the site
	// config turns machine validation on.
	MachineValidation string `yaml:"machineValidation,omitempty"`
	// Unbound and UnboundExporter are the .forge resolver's images. Required
	// when Addresses.DNS is set.
	Unbound         string `yaml:"unbound,omitempty"`
	UnboundExporter string `yaml:"unboundExporter,omitempty"`
}

// Addresses are the fixed IP addresses NICo's services are published on.
type Addresses struct {
	// DHCP (udp/67), PXE (tcp/80, 8080), API (tcp/443) and REST (tcp/8388) are required.
	DHCP string `yaml:"dhcp"`
	PXE  string `yaml:"pxe"`
	API  string `yaml:"api"`
	REST string `yaml:"rest"`
	// Keycloak is the token endpoint (tcp/8082). Required with the bundled Keycloak.
	Keycloak string `yaml:"keycloak,omitempty"`
	// DNS is NICo's .forge resolver (udp and tcp/53). Empty when the site's DNS
	// serves the .forge names.
	DNS string `yaml:"dns,omitempty"`
	// NTP are NICo's NTP servers (udp/123), one per replica. Empty when the
	// site's NTP is used.
	NTP []string `yaml:"ntp,omitempty"`
	// SSHConsole is NICo's SSH console (tcp/22). Optional; published on the site cluster only.
	SSHConsole string `yaml:"sshConsole,omitempty"`
}

// SiteProfile is how NICo runs on the site cluster.
type SiteProfile struct {
	// StorageClass is the StorageClass of Vault's and Postgres's volumes. Required.
	StorageClass string `yaml:"storageClass"`
	// Replicas is how many Vault and Postgres instances run. DefaultSiteReplicas when unset.
	Replicas int `yaml:"replicas,omitempty"`
}

// Allocation is what the bootstrap creates in NICo for the control plane.
type Allocation struct {
	// VPCType is VPCTypeEthernetVirtualizer, a VPC with a subnet. Required.
	// VPCTypeFNN, a VPC with a VPC prefix, is refused until the bootstrap sets
	// the tenant's routing profile, without which NICo makes the VPC external.
	VPCType string `yaml:"vpcType"`
	// TenantBlockPrefixLength is the prefix length of the tenant IP block
	// allocated from the tenant address space. Required.
	TenantBlockPrefixLength int `yaml:"tenantBlockPrefixLength"`
	// SubnetPrefixLength is the prefix length of the control-plane subnet or
	// VPC prefix cut from the tenant block. Required.
	SubnetPrefixLength int `yaml:"subnetPrefixLength"`
	// SSHPublicKey is a file holding the SSH public key put on the control-plane machines. Required.
	SSHPublicKey string `yaml:"sshPublicKey"`
}

// Identity is the identity provider NICo's REST API trusts. Without External
// the bootstrap installs NICo's bundled Keycloak.
type Identity struct {
	External *ExternalIdentity `yaml:"external,omitempty"`
}

// ExternalIdentity is an OIDC provider outside NICo. Its client secret comes
// from ClientSecretEnv.
type ExternalIdentity struct {
	Issuer   string `yaml:"issuer"`
	JWKSURL  string `yaml:"jwksURL"`
	TokenURL string `yaml:"tokenURL"`
	ClientID string `yaml:"clientID"`
}

// Machine is one host in the machines file.
type Machine struct {
	// Name is how the bootstrap refers to the host. Required, unique.
	Name string `yaml:"name"`
	// BMCMAC is the host BMC's MAC address. Required.
	BMCMAC string `yaml:"bmcMAC"`
	// Serial is the serial the BMC reports. Required.
	Serial string `yaml:"serial"`
	// BMCLogin is the prefix of the environment variables <BMCLogin>_USERNAME
	// and <BMCLogin>_PASSWORD holding the BMC's factory login. Required.
	BMCLogin string `yaml:"bmcLogin"`
	// RetainBMCPassword keeps the factory BMC password instead of rotating it
	// to the site-wide root.
	RetainBMCPassword bool `yaml:"retainBMCPassword,omitempty"`
	// DPUPolicy overrides the site config's default DPU policy.
	DPUPolicy string `yaml:"dpuPolicy,omitempty"`
	// BMCIP is the BMC's fixed address, when NICo's DHCP does not address it.
	BMCIP string `yaml:"bmcIP,omitempty"`
	// BootNICMAC and BootNICIP are the host's boot NIC: required with DPU policy
	// nic or ignore, or when the host boots from an onboard NIC. BootNICIP is optional.
	BootNICMAC string `yaml:"bootNICMAC,omitempty"`
	BootNICIP  string `yaml:"bootNICIP,omitempty"`
	// DPUs are fixed addresses, or serials the host does not report, of the host's DPUs.
	DPUs []DPU `yaml:"dpus,omitempty"`
	// SKU is the host's SKU, with strict BOM validation.
	SKU string `yaml:"sku,omitempty"`
}

// DPU is what the machines file may say about one of a host's DPUs. Every field is optional.
type DPU struct {
	Serial string `yaml:"serial,omitempty"`
	BMCMAC string `yaml:"bmcMAC,omitempty"`
	BMCIP  string `yaml:"bmcIP,omitempty"`
	OSMAC  string `yaml:"osMAC,omitempty"`
	OSIP   string `yaml:"osIP,omitempty"`
}

// Secrets are the secrets read from the environment.
type Secrets struct {
	SiteWideBMCRootPassword string
	HostUEFIPassword        string
	DPUUEFIPassword         string
	DPUBMCFactoryUsername   string
	DPUBMCFactoryPassword   string
	RegistryUsername        string
	RegistryPassword        string
	ClientSecret            string
	// BMCLogins maps each machine's BMCLogin prefix to its username and password.
	BMCLogins map[string]Login
}

// Login is a username and password.
type Login struct {
	Username string
	Password string
}

// SiteConfig is what the bootstrap reads from the Core values' site config TOML.
type SiteConfig struct {
	// SiteName is the site's name in NICo.
	SiteName  string
	DNSDomain string
	// DefaultDPUPolicy is one of the DPU policies, DPUPolicyManage when the site config sets none.
	DefaultDPUPolicy string
	// AttestationEnabled, MachineValidation and FirmwareAutoupdate are true
	// when the site config omits them, as in the chart's base config.
	AttestationEnabled bool
	MachineValidation  bool
	FirmwareAutoupdate bool
	SiteFabricPrefixes []string
	DenyPrefixes       []string
	DHCPServers        []string
	NTPServers         []string
	// DHCPNameservers and DHCPNTPServer are the Core values'
	// nico-dhcp.config.kea.hookParameters nameservers and ntpServer: the DNS
	// and NTP servers DHCP hands out when NICo runs none of its own.
	DHCPNameservers string
	DHCPNTPServer   string
	// Networks are the [networks.<name>] segments, by name.
	Networks map[string]Network
	// Pools are the [pools.<name>] resource pools, by name.
	Pools map[string]Pool
}

// Network is one network segment of the site config. MTU and ReserveFirst
// are pointers so an omitted key, which nico-api refuses, can be told apart.
type Network struct {
	Type         string `toml:"type"`
	Prefix       string `toml:"prefix"`
	Gateway      string `toml:"gateway"`
	MTU          *int   `toml:"mtu"`
	ReserveFirst *int   `toml:"reserve_first"`
}

// Pool is one resource pool of the site config: a list of ranges, or a prefix.
type Pool struct {
	Type   string      `toml:"type"`
	Prefix string      `toml:"prefix"`
	Ranges []PoolRange `toml:"ranges"`
}

// PoolRange is one range of a Pool.
type PoolRange struct {
	Start string `toml:"start"`
	End   string `toml:"end"`
}

// Settings is a loaded, validated settings file with its paths resolved.
type Settings struct {
	File
	// Path is the settings file's own path.
	Path string
	// Machines are the machines file's hosts.
	MachineList []Machine
	// SiteConfig is read from CoreValues.
	SiteConfig SiteConfig
	// SSHPublicKeyData is the content of Allocation.SSHPublicKey.
	SSHPublicKeyData string
}

// EffectiveOrgID returns OrgID, or DefaultOrgID when it is unset.
func (s *Settings) EffectiveOrgID() string {
	if s.OrgID != "" {
		return s.OrgID
	}
	return DefaultOrgID
}

// EffectiveSiteReplicas returns Site.Replicas, or DefaultSiteReplicas when it is unset.
func (s *Settings) EffectiveSiteReplicas() int {
	if s.Site.Replicas > 0 {
		return s.Site.Replicas
	}
	return DefaultSiteReplicas
}
