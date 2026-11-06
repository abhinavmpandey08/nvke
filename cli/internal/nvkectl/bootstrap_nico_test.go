// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nvkectl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicoalloc"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicodeploy"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/seedbgp"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/sitecluster"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/sitespec"
	"github.com/dsx-ai-factory/nvke/cli/internal/redact"
	api "github.com/dsx-ai-factory/nvke/controller/api"
)

// ipRunner answers `ip -o addr show` with addrs, refuses changes with refuse
// when it is set, and records every other ip command.
type ipRunner struct {
	addrs  string
	refuse string
	calls  []string
}

func (r *ipRunner) Run(_ context.Context, _ map[string]string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if cmd == "ip -o addr show" {
		return r.addrs, nil
	}
	r.calls = append(r.calls, cmd)
	if r.refuse != "" {
		return r.refuse, errors.New("exit status 2")
	}
	return "", nil
}

const ipAddrShow = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet 192.0.2.10/32 scope global lo\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
`

// TestEnsureHostAddresses: a service address missing from the bootstrap host is
// put on lo as a host route; one already on lo is left alone; one on another
// interface, which the move could not take off, is refused.
func TestEnsureHostAddresses(t *testing.T) {
	for name, tt := range map[string]struct {
		addrs     []string
		refuse    string
		wantCalls []string
		wantErr   []string
	}{
		"missing IPv4 address added": {
			addrs:     []string{"192.0.2.10", "192.0.2.11"},
			wantCalls: []string{"ip addr add 192.0.2.11/32 dev lo"},
		},
		"missing IPv6 address added": {
			addrs:     []string{"2001:db8::13"},
			wantCalls: []string{"ip addr add 2001:db8::13/128 dev lo"},
		},
		"address already on lo": {addrs: []string{"192.0.2.10"}},
		"address on another interface": {
			addrs:   []string{"10.0.0.5"},
			wantErr: []string{"10.0.0.5 is on interface eth0", "remove it from eth0"},
		},
		"refused without privileges": {
			addrs:     []string{"192.0.2.11"},
			refuse:    "RTNETLINK answers: Operation not permitted\n",
			wantCalls: []string{"ip addr add 192.0.2.11/32 dev lo"},
			wantErr:   []string{"192.0.2.11", "Operation not permitted", "root or CAP_NET_ADMIN"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &ipRunner{addrs: ipAddrShow, refuse: tt.refuse}
			err := ensureHostAddresses(context.Background(), runner, tt.addrs, slog.New(slog.DiscardHandler))
			assert.Equal(t, tt.wantCalls, runner.calls)
			if len(tt.wantErr) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, want := range tt.wantErr {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

// TestRemoveHostAddresses: only addresses on lo are removed, with the prefix
// they are listed with.
func TestRemoveHostAddresses(t *testing.T) {
	runner := &ipRunner{addrs: ipAddrShow + "1: lo    inet 192.0.2.12/24 scope global lo\\ \n"}
	err := removeHostAddresses(context.Background(), runner, []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "10.0.0.5"},
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.Equal(t, []string{"ip addr del 192.0.2.10/32 dev lo", "ip addr del 192.0.2.12/24 dev lo"}, runner.calls)
}

// TestPointAtNico: the IDs of the NICo the bootstrap installed reach the
// create request, with the subnet or the VPC prefix the VPC type made.
func TestPointAtNico(t *testing.T) {
	ids := map[string]string{}
	for _, name := range []string{"site", "vpc", "type", "group", "net"} {
		ids[name] = uuid.NewString()
	}
	inst := &nicodeploy.Installed{SiteID: ids["site"], RESTEndpoint: "http://192.0.2.13:8388", OrgID: "ncx", APIName: "nico"}
	for name, tt := range map[string]struct {
		res        nicoalloc.Result
		wantSubnet bool
	}{
		"ethernet virtualizer": {
			res:        nicoalloc.Result{InstanceTypeID: ids["type"], VPCID: ids["vpc"], SubnetID: ids["net"], SSHKeyGroupID: ids["group"]},
			wantSubnet: true,
		},
		"FNN": {
			res: nicoalloc.Result{InstanceTypeID: ids["type"], VPCID: ids["vpc"], VPCPrefixID: ids["net"], SSHKeyGroupID: ids["group"]},
		},
	} {
		t.Run(name, func(t *testing.T) {
			inv := &sitespec.SiteSpec{ClusterName: "site-a", Infra: sitespec.Infra{Provider: sitespec.ProviderNico, Nico: &sitespec.NicoInfra{
				Managed:      &sitespec.NicoManaged{Settings: "nico.yaml"},
				ControlPlane: sitespec.NicoControlPlane{Count: 1},
			}}}
			inv.Infra.Nico.ControlPlane.Release = "r"
			require.NoError(t, pointAtNico(inv, inst, &tt.res))

			req, err := sitecluster.ClusterRequest(inv)
			require.NoError(t, err)
			require.NotNil(t, req.Nico)
			assert.Equal(t, "ncx", req.Nico.OrgID)
			assert.Equal(t, ids["site"], req.Nico.SiteID.String())
			assert.Equal(t, ids["vpc"], req.Nico.VpcID.String())
			cp := req.ControlPlaneConfig.Nico
			assert.Equal(t, []uuid.UUID{uuid.MustParse(ids["type"])}, cp.InstanceTypePreference)
			assert.Equal(t, []uuid.UUID{uuid.MustParse(ids["group"])}, cp.SSHKeyGroupIDs)
			network := []uuid.UUID{uuid.MustParse(ids["net"])}
			if tt.wantSubnet {
				assert.Equal(t, network, cp.SubnetIDs)
				assert.Empty(t, cp.VpcPrefixIDs)
			} else {
				assert.Equal(t, network, cp.VpcPrefixIDs)
				assert.Empty(t, cp.SubnetIDs)
			}
			assert.Equal(t, "nico", inv.Infra.Nico.Remote.APIName)
		})
	}
	t.Run("an ID that is not a UUID", func(t *testing.T) {
		inv := &sitespec.SiteSpec{Infra: sitespec.Infra{Provider: sitespec.ProviderNico, Nico: &sitespec.NicoInfra{}}}
		err := pointAtNico(inv, inst, &nicoalloc.Result{InstanceTypeID: "it-1", VPCID: ids["vpc"], SubnetID: ids["net"], SSHKeyGroupID: ids["group"]})
		require.ErrorContains(t, err, `instance type ID "it-1"`)
		assert.Nil(t, inv.Infra.Nico.Remote, "the site spec is left as it was")
	})
}

// managedNicoSiteSpec writes the nico example as a managed NICo whose settings
// are the nicosettings test fixture, with count control-plane machines and
// every secret the settings need set.
func managedNicoSiteSpec(t *testing.T, count int) string {
	t.Helper()
	path := nicoSiteSpecFile(t)
	dir := filepath.Dir(path)
	data, err := os.ReadFile(filepath.Join("../bootstrap/nicosettings/testdata", "nico.yaml"))
	require.NoError(t, err)
	// The site cluster's nodes are its control plane, each running one Vault replica.
	data = []byte(strings.Replace(string(data), "  storageClass: example-storage\n",
		"  storageClass: example-storage\n  replicas: "+strconv.Itoa(count)+"\n", 1))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nico.yaml"), data, 0o600))
	example, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(example)
	remote := "    remote:\n      endpoint: \"https://nico.example\"\n      siteID: \"00000000-0000-0000-0000-000000000001\"\n" +
		"      vpcID: \"00000000-0000-0000-0000-000000000002\"\n"
	require.Contains(t, text, remote, "the example's remote block changed; update this test")
	text = strings.Replace(text, remote, "    managed:\n      settings: nico.yaml\n", 1)
	require.Contains(t, text, "      count: 3\n", "the example's control-plane count changed; update this test")
	text = strings.Replace(text, "      count: 3\n", "      count: "+strconv.Itoa(count)+"\n", 1)
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))

	t.Setenv(sitespec.NicoCredentialsEnv, "")
	t.Setenv(sitespec.NicoInsecureEndpointEnv, "1")
	t.Setenv(nicosettings.SiteWideBMCRootPasswordEnv, "example-root-password")
	t.Setenv(nicosettings.HostUEFIPasswordEnv, "example-host-uefi")
	t.Setenv(nicosettings.DPUUEFIPasswordEnv, "example-dpu-uefi")
	t.Setenv("NICO_BMC_EXAMPLE_USERNAME", "example-user")
	t.Setenv("NICO_BMC_EXAMPLE_PASSWORD", "example-bmc-password")
	return path
}

// TestRunBootstrapSiteDryRunLoadsManagedNico: the dry run loads the NICo
// settings and their secrets, and refuses a control plane larger than the
// machines file and more Vault replicas than the control plane has nodes.
func TestRunBootstrapSiteDryRunLoadsManagedNico(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		err := runBootstrapSite(context.Background(), io.Discard, &bootstrapSiteOptions{siteSpec: managedNicoSiteSpec(t, 1), dryRun: true})
		require.NoError(t, err)
		assert.NotEqual(t, "example-bmc-password", redact.Text("example-bmc-password"), "a BMC password is redacted")
	})
	t.Run("more control-plane machines than the machines file lists", func(t *testing.T) {
		err := runBootstrapSite(context.Background(), io.Discard, &bootstrapSiteOptions{siteSpec: managedNicoSiteSpec(t, 3), dryRun: true})
		require.ErrorContains(t, err, "machines lists 2 hosts, fewer than the 3")
	})
	t.Run("more Vault replicas than the site cluster has nodes", func(t *testing.T) {
		path := managedNicoSiteSpec(t, 1)
		settings := filepath.Join(filepath.Dir(path), "nico.yaml")
		data, err := os.ReadFile(settings)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(settings, []byte(strings.Replace(string(data), "  replicas: 1\n", "  replicas: 3\n", 1)), 0o600))
		err = runBootstrapSite(context.Background(), io.Discard, &bootstrapSiteOptions{siteSpec: path, dryRun: true})
		require.ErrorContains(t, err, "site.replicas is 3, more than the site cluster's 1 nodes")
	})
	t.Run("a secret missing", func(t *testing.T) {
		path := managedNicoSiteSpec(t, 1)
		t.Setenv(nicosettings.HostUEFIPasswordEnv, "")
		err := runBootstrapSite(context.Background(), io.Discard, &bootstrapSiteOptions{siteSpec: path, dryRun: true})
		require.ErrorContains(t, err, nicosettings.HostUEFIPasswordEnv)
	})
}

// TestManagedNicoAddresses: the addresses put on the bootstrap host are those
// the seed's port mappings listen on, each once.
func TestManagedNicoAddresses(t *testing.T) {
	n := &managedNico{settings: &nicosettings.Settings{File: nicosettings.File{Addresses: nicosettings.Addresses{
		DHCP: "192.0.2.10", PXE: "192.0.2.11", API: "192.0.2.12", REST: "192.0.2.13", Keycloak: "192.0.2.14",
		NTP: []string{"192.0.2.16", "192.0.2.17"},
	}}}}
	assert.ElementsMatch(t, []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.16", "192.0.2.17"}, n.addresses())
}

// seedHost is the bootstrap host: `ip -o addr show` prints addrs, `ip route
// get` names src 10.0.0.5, a speaker's container runs, with another
// configuration than a test writes, and an Established session, and every
// change is recorded.
type seedHost struct {
	addrs string
	calls []string
}

func (h *seedHost) Run(_ context.Context, _ map[string]string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch {
	case cmd == "ip -o addr show":
		return h.addrs, nil
	case strings.HasPrefix(cmd, "ip -o route get"):
		return args[3] + " dev eth0 src 10.0.0.5 uid 0", nil
	case strings.HasPrefix(cmd, "nerdctl inspect"):
		return "true", nil
	case strings.HasSuffix(cmd, "show bgp neighbors json"):
		return `{"10.0.0.1":{"bgpState":"Established"}}`, nil
	}
	h.calls = append(h.calls, cmd)
	return "", nil
}

// kubeRunner records the commands controllerdeploy runs.
type kubeRunner struct{ calls []string }

func (r *kubeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return "", nil
}

func vipNico(t *testing.T, rest, keycloak string, withdrawn ...string) *managedNico {
	n := &managedNico{
		settings: &nicosettings.Settings{File: nicosettings.File{
			Addresses: nicosettings.Addresses{DHCP: "192.0.2.10", PXE: "192.0.2.11", API: "192.0.2.12", REST: rest, Keycloak: keycloak},
			BGP:       nicosettings.BGP{Seed: nicosettings.BGPSpeaker{ASN: 65001, Peers: []nicosettings.BGPPeer{{Address: "10.0.0.1", ASN: 65000}}}},
		}},
		vip:      netip.MustParseAddr("192.0.2.250"),
		bgpDir:   filepath.Join(t.TempDir(), "bgp"),
		seedKube: fake.NewClientset(),
	}
	if len(withdrawn) > 0 {
		_, err := n.seedKube.CoreV1().ConfigMaps(withdrawnNamespace).Create(context.Background(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: withdrawnNamespace, Name: withdrawnConfigMap},
			Data:       map[string]string{withdrawnKey: strings.Join(withdrawn, "\n")},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	return n
}

func recordedWithdrawn(t *testing.T, n *managedNico) []string {
	cm, err := n.seedKube.CoreV1().ConfigMaps(withdrawnNamespace).Get(context.Background(), withdrawnConfigMap, metav1.GetOptions{})
	require.NoError(t, err)
	return strings.Fields(cm.Data[withdrawnKey])
}

// TestManagedNicoAnnounce: a new run announces every service address; a
// resumed run announces only those an earlier run did not withdraw, takes the
// withdrawn ones off the host and puts the others back.
func TestManagedNicoAnnounce(t *testing.T) {
	const onLo = "1: lo    inet 192.0.2.250/32 scope global lo\n"
	for name, tt := range map[string]struct {
		adopted   bool
		withdrawn []string
		wantConf  []string
		notConf   []string
		wantCalls []string
	}{
		"a new run": {
			wantConf:  []string{"network 192.0.2.10/32", "network 192.0.2.250/32", "bgp router-id 10.0.0.5"},
			wantCalls: []string{"nerdctl rm -f nvkectl-bootstrap-nico-bgp", "nerdctl run"},
		},
		"resumed after the VIP was withdrawn": {
			adopted: true, withdrawn: []string{"192.0.2.250"},
			wantConf: []string{"network 192.0.2.10/32"}, notConf: []string{"192.0.2.250"},
			wantCalls: []string{"ip addr del 192.0.2.250/32 dev lo", "ip addr add 192.0.2.10/32 dev lo", "nerdctl rm -f nvkectl-bootstrap-nico-bgp", "nerdctl run"},
		},
		"resumed after every address was withdrawn": {
			adopted: true, withdrawn: []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.250"},
			wantCalls: []string{"ip addr del 192.0.2.250/32 dev lo"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := vipNico(t, "192.0.2.250:30388", "192.0.2.250:30082", tt.withdrawn...)
			host := &seedHost{addrs: onLo}
			require.NoError(t, n.announce(context.Background(), tt.adopted, "nvkectl-bootstrap", "", host, slog.New(slog.DiscardHandler)))
			var got []string
			for _, c := range host.calls {
				if strings.HasPrefix(c, "nerdctl run") {
					c = "nerdctl run"
					assert.Contains(t, strings.Join(host.calls, " "), "--name nvkectl-bootstrap-nico-bgp")
				}
				if strings.HasPrefix(c, "ip addr add") && !strings.Contains(c, "192.0.2.10/") {
					continue
				}
				got = append(got, c)
			}
			assert.Equal(t, tt.wantCalls, got)
			conf, _ := os.ReadFile(filepath.Join(n.bgpDir, "frr.conf"))
			for _, w := range tt.wantConf {
				assert.Contains(t, string(conf), w)
			}
			for _, w := range tt.notConf {
				assert.NotContains(t, string(conf), w)
			}
		})
	}
}

// TestManagedNicoWithdrawVIP: once the site cluster request is accepted, a
// REST or Keycloak on the control-plane VIP moves CAPNICo to NICo's in-cluster
// endpoints, and the VIP leaves the bootstrap host: recorded first, then its
// route, then the address. Without one on the VIP nothing changes.
func TestManagedNicoWithdrawVIP(t *testing.T) {
	const patch = "kubectl --kubeconfig /seed -n capnico-system patch secret nico-credentials --type merge -p " +
		`{"stringData":{"endpoint":"` + nicodeploy.InClusterRESTEndpoint + `","tokenURL":"` + nicodeploy.InClusterTokenURL + `"}}`
	withdraw := "nerdctl exec nvkectl-bootstrap-nico-bgp vtysh -c configure terminal -c router bgp 65001 " +
		"-c address-family ipv4 unicast -c no network 192.0.2.250/32"
	for name, tt := range map[string]struct {
		rest, keycloak string
		withdrawn      []string
		wantKube       []string
		wantHost       []string
		wantRecorded   []string
	}{
		"REST and Keycloak on the VIP": {
			rest: "192.0.2.250:30388", keycloak: "192.0.2.250:30082",
			wantKube: []string{patch}, wantHost: []string{withdraw, "ip addr del 192.0.2.250/32 dev lo"},
			wantRecorded: []string{"192.0.2.250"},
		},
		"only Keycloak on the VIP": {
			rest: "192.0.2.13", keycloak: "192.0.2.250:30082",
			wantKube: []string{patch}, wantHost: []string{withdraw, "ip addr del 192.0.2.250/32 dev lo"},
			wantRecorded: []string{"192.0.2.250"},
		},
		"resumed after the VIP was withdrawn": {
			rest: "192.0.2.250:30388", keycloak: "192.0.2.250:30082", withdrawn: []string{"192.0.2.250"},
			wantKube: []string{patch}, wantRecorded: []string{"192.0.2.250"},
		},
		"neither on the VIP": {rest: "192.0.2.13", keycloak: "192.0.2.14"},
	} {
		t.Run(name, func(t *testing.T) {
			n := vipNico(t, tt.rest, tt.keycloak, tt.withdrawn...)
			n.withdrawn = tt.withdrawn
			n.speaker = &seedbgp.Speaker{Runner: &seedHost{}, Logger: slog.New(slog.DiscardHandler)}
			n.bgp = seedbgp.Config{Name: "nvkectl-bootstrap-nico-bgp", Dir: n.bgpDir, Image: "frr@sha256:abc", BGP: n.settings.BGP.Seed}
			host := &seedHost{addrs: "1: lo    inet 192.0.2.250/32 scope global lo\n"}
			n.speaker.Runner = host
			kube := &kubeRunner{}
			require.NoError(t, n.withdrawVIP(context.Background(), "/seed", kube, host, slog.New(slog.DiscardHandler)))
			assert.Equal(t, tt.wantKube, kube.calls)
			assert.Equal(t, tt.wantHost, host.calls)
			if tt.wantRecorded == nil {
				return
			}
			assert.Equal(t, tt.wantRecorded, recordedWithdrawn(t, n))
			if tt.withdrawn == nil {
				conf, err := os.ReadFile(filepath.Join(n.bgpDir, "frr.conf"))
				require.NoError(t, err)
				assert.NotContains(t, string(conf), "192.0.2.250", "the speaker's configuration still announces the VIP")
				assert.Contains(t, string(conf), "network 192.0.2.10/32")
			}
		})
	}
}

// TestManagedNicoWithdrawAll: the move records every address withdrawn, stops
// the speaker and takes the addresses off the host.
func TestManagedNicoWithdrawAll(t *testing.T) {
	n := vipNico(t, "192.0.2.13", "192.0.2.14")
	host := &seedHost{addrs: "1: lo    inet 192.0.2.10/32 scope global lo\n"}
	n.speaker = &seedbgp.Speaker{Runner: host, Logger: slog.New(slog.DiscardHandler)}
	n.bgp = seedbgp.Config{Name: "nvkectl-bootstrap-nico-bgp", Dir: n.bgpDir}
	require.NoError(t, n.withdrawAll(context.Background(), host, slog.New(slog.DiscardHandler)))
	assert.Equal(t, []string{"nerdctl rm -f nvkectl-bootstrap-nico-bgp", "ip addr del 192.0.2.10/32 dev lo"}, host.calls)
	assert.ElementsMatch(t, n.addresses(), recordedWithdrawn(t, n))
}

// acceptingAPI is a controller that accepts every create request.
type acceptingAPI struct{ sitecluster.ClusterAPI }

func (acceptingAPI) CreateCluster(context.Context, api.CreateClusterJSONRequestBody) (*api.Cluster, error) {
	return &api.Cluster{ID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Name: "nvke-site"}, nil
}

// TestCreateSiteClusterCallsAccepted: the hook runs as soon as the create is
// accepted, and its failure keeps the bootstrap cluster.
func TestCreateSiteClusterCallsAccepted(t *testing.T) {
	inv, err := sitespec.Load(nicoSiteSpecFile(t))
	require.NoError(t, err)
	called := false
	_, kept, err := createSiteCluster(context.Background(), nil, inv, &bootstrapSiteOptions{}, acceptingAPI{},
		func(context.Context) error { called = true; return errors.New("withdrawing the VIP") }, slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "withdrawing the VIP")
	assert.True(t, called)
	assert.True(t, kept, "a failure after the create is accepted keeps the bootstrap cluster")
}
