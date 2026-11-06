// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nvkectl

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/controllerdeploy"
	bootstrapengine "github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/engine"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicoalloc"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicodeploy"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicoingest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicomove"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/seedbgp"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/sitespec"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/untaint"
	"github.com/dsx-ai-factory/nvke/cli/internal/redact"
)

// bootstrapStorageClass is the StorageClass Kind gives every cluster it creates.
const bootstrapStorageClass = "standard"

// hostLoopback is the bootstrap host's interface the service addresses are put on.
const hostLoopback = "lo"

// nicoFetchTimeout bounds the download of the NICo source release.
const nicoFetchTimeout = 10 * time.Minute

// withdrawnNamespace and withdrawnConfigMap are where the bootstrap cluster
// records the service addresses already taken off the bootstrap host, so a
// resumed run does not announce them again.
const (
	withdrawnNamespace = "kube-system"
	withdrawnConfigMap = "nvkectl-nico-withdrawn"
	withdrawnKey       = "addresses"
)

// managedNico is the NICo infra.nico.managed has the bootstrap install: its
// settings and secrets, loaded before anything is built, and what the install
// on the bootstrap cluster leaves for the move onto the site cluster.
type managedNico struct {
	settings *nicosettings.Settings
	secrets  nicosettings.Secrets

	// dir holds the NICo source release, root its extracted charts. They are
	// kept until the move, which installs the same charts on the site.
	dir, root string
	// seed is the bootstrap cluster's install and inst the NICo it installed.
	seed nicodeploy.Config
	inst *nicodeploy.Installed

	// vip is the site's control-plane VIP, which REST and Keycloak may share.
	vip netip.Addr
	// dial reaches REST and Keycloak through the bootstrap cluster when they
	// share vip; nil otherwise. See nicodeploy.SeedLoopback.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// bgpDir holds the bootstrap host's BGP speaker's configuration.
	bgpDir string
	// speaker announces the service addresses from the bootstrap host, with bgp its configuration.
	speaker *seedbgp.Speaker
	bgp     seedbgp.Config
	// seedKube is a client of the bootstrap cluster, which records withdrawn.
	seedKube kubernetes.Interface
	// withdrawn are the service addresses already taken off the bootstrap host.
	withdrawn []string
}

// loadManagedNico loads the NICo settings infra.nico.managed names and the
// secrets they need from the environment. It returns nil without a managed
// NICo. Every secret it reads is registered for redaction, so none reaches a
// log or an error printed later.
func loadManagedNico(inv *sitespec.SiteSpec) (*managedNico, error) {
	if !inv.IsManagedNico() {
		return nil, nil
	}
	path := inv.NicoSettingsPath()
	settings, err := nicosettings.Load(path, inv.NicoHandoverDir())
	if err != nil {
		return nil, fmt.Errorf("NICo settings %s: %w", path, err)
	}
	secrets, err := nicosettings.SecretsFromEnv(settings)
	if err != nil {
		return nil, fmt.Errorf("NICo settings %s: %w", path, err)
	}
	for _, s := range []string{
		secrets.SiteWideBMCRootPassword, secrets.HostUEFIPassword, secrets.DPUUEFIPassword,
		secrets.DPUBMCFactoryPassword, secrets.RegistryPassword, secrets.BGPPassword,
	} {
		redact.RegisterSecret(s)
	}
	for _, login := range secrets.BMCLogins {
		redact.RegisterSecret(login.Password)
	}
	if have, want := len(settings.Machines), inv.ControlPlaneCount(); have < want {
		return nil, fmt.Errorf("NICo settings %s: machines lists %d hosts, fewer than the %d infra.nico.controlPlane.count asks for",
			path, have, want)
	}
	// Vault's chart runs one replica per node, and the site cluster's nodes are its control plane.
	if replicas, nodes := settings.EffectiveSiteReplicas(), inv.ControlPlaneCount(); replicas > nodes {
		return nil, fmt.Errorf("NICo settings %s: site.replicas is %d, more than the site cluster's %d nodes (infra.nico.controlPlane.count); "+
			"set site.replicas to at most %d", path, replicas, nodes, nodes)
	}
	vip, _ := netip.ParseAddr(inv.Cluster.ControlPlaneVIP)
	return &managedNico{settings: settings, secrets: secrets, vip: vip, bgpDir: inv.ResolvePath(inv.ClusterName + "-nico-bgp")}, nil
}

// portMappings returns the Kind port mappings that publish NICo on the
// bootstrap host, and those through which nvkectl reaches REST and Keycloak
// when they share the control-plane VIP.
func (n *managedNico) portMappings() []bootstrapengine.PortMapping {
	loopback, dial := nicodeploy.SeedLoopback(n.settings.Addresses, n.vip)
	n.dial = dial
	return append(nicodeploy.SeedPortMappings(n.settings.Addresses), loopback...)
}

// sharesVIP reports whether REST or Keycloak is on the control-plane VIP.
func (n *managedNico) sharesVIP() bool {
	a := n.settings.Addresses
	return n.vip.IsValid() && (a.RESTEndpoint().Addr() == n.vip || a.KeycloakEndpoint().Addr() == n.vip)
}

// announced returns the service addresses the bootstrap host still holds.
func (n *managedNico) announced() []string {
	return slices.DeleteFunc(n.addresses(), func(a string) bool { return slices.Contains(n.withdrawn, a) })
}

// bgpConfig returns the speaker's configuration, announcing what announced returns.
func (n *managedNico) bgpConfig() seedbgp.Config {
	c := n.bgp
	c.Addresses = nil
	for _, a := range n.announced() {
		c.Addresses = append(c.Addresses, netip.MustParseAddr(a))
	}
	return c
}

// announce announces the service addresses from the bootstrap host over BGP
// and waits for a session with a router to come up. A resumed run first
// reads which addresses an earlier run withdrew, takes them off the host, and
// puts back the others, which the host may have lost.
func (n *managedNico) announce(
	ctx context.Context,
	adopted bool,
	bootstrapCluster, kubeconfig string,
	hostRunner bootstrapengine.CommandRunner,
	logger *slog.Logger,
) error {
	if n.seedKube == nil {
		kube, err := untaint.NewClient(kubeconfig)
		if err != nil {
			return err
		}
		n.seedKube = kube
	}
	if adopted {
		cm, err := n.seedKube.CoreV1().ConfigMaps(withdrawnNamespace).Get(ctx, withdrawnConfigMap, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
		case err != nil:
			return fmt.Errorf("reading which NICo service addresses an earlier run withdrew: %w", err)
		default:
			n.withdrawn = strings.Fields(cm.Data[withdrawnKey])
		}
		if err := removeHostAddresses(ctx, hostRunner, n.withdrawn, logger); err != nil {
			return err
		}
		if err := ensureHostAddresses(ctx, hostRunner, n.announced(), logger); err != nil {
			return err
		}
	}
	image, err := manifest.Load().Components[manifest.ComponentFRR].Images[manifest.ImageFRR].Pinned()
	if err != nil {
		return err
	}
	routerID, err := seedbgp.RouterID(ctx, hostRunner, n.settings.BGP.Seed.Peers)
	if err != nil {
		return err
	}
	n.speaker = &seedbgp.Speaker{Runner: hostRunner, Logger: logger}
	n.bgp = seedbgp.Config{
		Name: bootstrapCluster + "-nico-bgp", Dir: n.bgpDir, Image: image,
		BGP: n.settings.BGP.Seed, Password: n.secrets.BGPPassword, RouterID: routerID,
	}
	if len(n.announced()) == 0 {
		logger.Info("NICo's service addresses were withdrawn from the bootstrap host by an earlier run; not announcing them")
		return nil
	}
	return n.speaker.Start(ctx, n.bgpConfig())
}

// recordWithdrawn adds addrs to the addresses the bootstrap cluster records as
// withdrawn, before they are taken off the host, so a run that stops part of
// the way leaves a resumed run to finish.
func (n *managedNico) recordWithdrawn(ctx context.Context, addrs []string) error {
	for _, a := range addrs {
		if !slices.Contains(n.withdrawn, a) {
			n.withdrawn = append(n.withdrawn, a)
		}
	}
	cms := n.seedKube.CoreV1().ConfigMaps(withdrawnNamespace)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: withdrawnNamespace, Name: withdrawnConfigMap},
		Data:       map[string]string{withdrawnKey: strings.Join(n.withdrawn, "\n")},
	}
	_, err := cms.Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("recording the NICo service addresses withdrawn from the bootstrap host: %w", err)
	}
	return nil
}

// withdrawVIP runs once the controller accepts the site cluster request, when
// REST or Keycloak shares the control-plane VIP, which the site's kube-vip
// announces next. It points CAPNICo on the bootstrap cluster at NICo's
// in-cluster REST and token endpoints, then withdraws the VIP from the
// bootstrap host: its route from the BGP speaker, which keeps announcing the
// other addresses, and the address from the host's loopback interface.
func (n *managedNico) withdrawVIP(
	ctx context.Context,
	seedKubeconfig string,
	runner controllerdeploy.CommandRunner,
	hostRunner bootstrapengine.CommandRunner,
	logger *slog.Logger,
) error {
	if !n.sharesVIP() {
		return nil
	}
	if err := controllerdeploy.New(runner, logger).
		SetCAPNICoEndpoints(ctx, seedKubeconfig, nicodeploy.InClusterRESTEndpoint, nicodeploy.InClusterTokenURL); err != nil {
		return err
	}
	vip := n.vip.String()
	if slices.Contains(n.withdrawn, vip) {
		return nil
	}
	logger.Info("withdrawing the control-plane VIP from the bootstrap host before the site cluster announces it", "vip", vip)
	if err := n.recordWithdrawn(ctx, []string{vip}); err != nil {
		return err
	}
	if err := n.speaker.Withdraw(ctx, n.bgpConfig(), []netip.Addr{n.vip}); err != nil {
		return err
	}
	return removeHostAddresses(ctx, hostRunner, []string{vip}, logger)
}

// withdrawAll withdraws every service address from the bootstrap host, so
// the site cluster can announce them: it stops the BGP speaker and takes the
// addresses off the host's loopback interface.
func (n *managedNico) withdrawAll(ctx context.Context, hostRunner bootstrapengine.CommandRunner, logger *slog.Logger) error {
	if err := n.recordWithdrawn(ctx, n.addresses()); err != nil {
		return err
	}
	if n.speaker != nil {
		if err := n.speaker.Stop(ctx, n.bgp); err != nil {
			return err
		}
	}
	return removeHostAddresses(ctx, hostRunner, n.addresses(), logger)
}

// addresses returns the service addresses published on the bootstrap host, in
// the order SeedPortMappings lists them.
func (n *managedNico) addresses() []string {
	var addrs []string
	for _, m := range nicodeploy.SeedPortMappings(n.settings.Addresses) {
		if !slices.Contains(addrs, m.ListenAddress) {
			addrs = append(addrs, m.ListenAddress)
		}
	}
	return addrs
}

// removeSource deletes the NICo source release.
func (n *managedNico) removeSource() {
	if n.dir != "" {
		_ = os.RemoveAll(n.dir)
	}
}

// install installs NICo in the bootstrap cluster from the release the
// bootstrap manifest pins, and sets NICo's client credentials on cweCfg, so the
// NVKE stack installs CAPNICo with them.
func (n *managedNico) install(
	ctx context.Context,
	kubeconfig string,
	cweCfg *controllerdeploy.Config,
	runner controllerdeploy.CommandRunner,
	logger *slog.Logger,
) error {
	dir, err := os.MkdirTemp("", "nvkectl-nico-source-")
	if err != nil {
		return err
	}
	n.dir = dir
	client := &http.Client{Timeout: nicoFetchTimeout}
	if n.root, err = nicodeploy.Fetch(ctx, client, *manifest.Load().Components[manifest.ComponentNico].Source, dir); err != nil {
		return err
	}
	kube, err := untaint.NewClient(kubeconfig)
	if err != nil {
		return err
	}
	n.seed = nicodeploy.NewConfig(n.settings, n.secrets, nicodeploy.ProfileSeed, bootstrapStorageClass)
	n.seed.Dial = n.dial
	if n.inst, err = nicodeploy.New(runner, kube, logger).Install(ctx, kubeconfig, n.root, n.seed); err != nil {
		return fmt.Errorf("installing NICo: %w", err)
	}
	cweCfg.CAPNICo = controllerdeploy.CAPNICoAccess{
		Endpoint:     n.inst.RESTEndpoint,
		OrgID:        n.inst.OrgID,
		APIName:      n.inst.APIName,
		TokenURL:     n.inst.Credentials.TokenURL,
		ClientID:     n.inst.Credentials.ClientID,
		ClientSecret: n.inst.Credentials.ClientSecret,
	}
	return nil
}

// configure ingests the site's machines into the installed NICo, creates the
// objects CAPNICo allocates the control plane with, and points the site spec
// at them, so the create request carries their IDs.
func (n *managedNico) configure(
	ctx context.Context,
	inv *sitespec.SiteSpec,
	kubeconfig string,
	runner controllerdeploy.CommandRunner,
	logger *slog.Logger,
) error {
	// The stack install just applied CAPNICo's published endpoints again; a run
	// resumed after the VIP was withdrawn points it back at the in-cluster ones.
	if n.vip.IsValid() && slices.Contains(n.withdrawn, n.vip.String()) {
		if err := controllerdeploy.New(runner, logger).
			SetCAPNICoEndpoints(ctx, kubeconfig, nicodeploy.InClusterRESTEndpoint, nicodeploy.InClusterTokenURL); err != nil {
			return err
		}
	}
	kube, err := untaint.NewClient(kubeconfig)
	if err != nil {
		return err
	}
	rest := n.inst.REST()
	if err := nicoingest.Run(ctx, nicoingest.Config{
		Kubeconfig: kubeconfig,
		Settings:   n.settings,
		Secrets:    n.secrets,
		REST:       rest,
		Runner:     runner,
		Kube:       kube,
		Logger:     logger,
	}); err != nil {
		return fmt.Errorf("ingesting the site's machines into NICo: %w", err)
	}
	serials := make([]string, 0, len(n.settings.Machines))
	for _, m := range n.settings.Machines {
		serials = append(serials, m.Serial)
	}
	res, err := nicoalloc.Ensure(ctx, nicoalloc.Config{
		REST:              rest,
		SiteID:            n.inst.SiteID,
		Name:              inv.ClusterName,
		Serials:           serials,
		ControlPlaneCount: inv.ControlPlaneCount(),
		Allocation:        n.settings.Allocation,
		SSHPublicKey:      n.settings.Allocation.SSHPublicKey,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("creating the control plane's NICo objects: %w", err)
	}
	if err := pointAtNico(inv, n.inst, res); err != nil {
		return err
	}
	logger.Info("NICo is ready in the bootstrap cluster", "site", n.inst.SiteID, "endpoint", n.inst.RESTEndpoint)
	return nil
}

// pointAtNico makes the site spec name the NICo the bootstrap installed and
// the objects nicoalloc created in it: infra.nico.remote, the org, and the
// control plane's instance type, subnet or VPC prefix, and SSH key group.
func pointAtNico(inv *sitespec.SiteSpec, inst *nicodeploy.Installed, res *nicoalloc.Result) error {
	network, networkID := "subnet", res.SubnetID
	if res.VPCPrefixID != "" {
		network, networkID = "VPC prefix", res.VPCPrefixID
	}
	fields := []struct{ what, id string }{
		{"site", inst.SiteID},
		{"VPC", res.VPCID},
		{"instance type", res.InstanceTypeID},
		{"SSH key group", res.SSHKeyGroupID},
		{network, networkID},
	}
	ids := make([]uuid.UUID, len(fields))
	for i, f := range fields {
		id, err := uuid.Parse(f.id)
		if err != nil {
			return fmt.Errorf("NICo returned %s ID %q, which is not a UUID: %w", f.what, f.id, err)
		}
		ids[i] = id
	}
	n := inv.Infra.Nico
	n.OrgID = inst.OrgID
	n.Remote = &sitespec.NicoRemote{Endpoint: inst.RESTEndpoint, SiteID: ids[0], VpcID: ids[1], APIName: inst.APIName}
	cp := &n.ControlPlane.NicoControlPlaneProviderCreate
	cp.InstanceTypePreference = []uuid.UUID{ids[2]}
	cp.SSHKeyGroupIDs = []uuid.UUID{ids[3]}
	cp.SubnetIDs, cp.VpcPrefixIDs = nil, nil
	if res.VPCPrefixID != "" {
		cp.VpcPrefixIDs = []uuid.UUID{ids[4]}
	} else {
		cp.SubnetIDs = []uuid.UUID{ids[4]}
	}
	return nil
}

// move moves NICo from the bootstrap cluster onto the site cluster and writes
// its handover bundle. It withdraws the service addresses from the bootstrap
// host once the site is ready to hold them.
func (n *managedNico) move(
	ctx context.Context,
	seedKubeconfig, siteKubeconfig string,
	runner controllerdeploy.CommandRunner,
	hostRunner bootstrapengine.CommandRunner,
	logger *slog.Logger,
) error {
	seedKube, err := untaint.NewClient(seedKubeconfig)
	if err != nil {
		return err
	}
	siteKube, err := untaint.NewClient(siteKubeconfig)
	if err != nil {
		return err
	}
	logger.Info("moving NICo onto the site cluster", "site", n.inst.SiteID)
	site := nicodeploy.NewConfig(n.settings, n.secrets, nicodeploy.ProfileSite, bootstrapStorageClass)
	if n.vip.IsValid() {
		site.ControlPlaneVIP = n.vip.String()
	}
	_, err = nicomove.Run(ctx, nicomove.Config{
		SeedKubeconfig: seedKubeconfig,
		SiteKubeconfig: siteKubeconfig,
		Root:           n.root,
		Seed:           n.seed,
		Site:           site,
		SiteID:         n.inst.SiteID,
		Runner:         runner,
		SeedKube:       seedKube,
		SiteKube:       siteKube,
		RemoveHostAddresses: func(ctx context.Context) error {
			return n.withdrawAll(ctx, hostRunner, logger)
		},
		Logger: logger,
	})
	return err
}

// nicoMoveFailedError wraps err, from moving NICo onto the site cluster. The
// bootstrap cluster may still hold NICo's only databases and Vault, so the
// advice is to keep it. The move may also have left CAPNICo on the site stopped.
func nicoMoveFailedError(err error, cluster *bootstrapengine.Cluster) error {
	return &recoveryError{fmt.Errorf("moving NICo onto the site cluster: %w; bootstrap cluster %q may hold NICo's only copy of "+
		"its databases and Vault, so it was retained and is not to be deleted (kubeconfig: %s); CAPNICo on the site cluster "+
		"(capnico-system/controller-manager) may be left scaled to 0", err, cluster.Name, cluster.KubeconfigPath)}
}

// hostAddress is one address on the bootstrap host: the interface it is on
// and the prefix it was added with.
type hostAddress struct {
	dev    string
	prefix string
}

// listHostAddresses returns the bootstrap host's addresses, from `ip -o addr show`.
func listHostAddresses(ctx context.Context, runner bootstrapengine.CommandRunner) (map[netip.Addr]hostAddress, error) {
	out, err := runner.Run(ctx, nil, "ip", "-o", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("listing the bootstrap host's addresses with `ip -o addr show`: %w: %s", err, strings.TrimSpace(out))
	}
	have := map[netip.Addr]hostAddress{}
	// Each line is "<index>: <dev> inet|inet6 <address>/<length> ...".
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || (f[2] != "inet" && f[2] != "inet6") {
			continue
		}
		if p, err := netip.ParsePrefix(f[3]); err == nil {
			have[p.Addr()] = hostAddress{dev: f[1], prefix: f[3]}
		}
	}
	return have, nil
}

// ensureHostAddresses puts each address in addrs on the bootstrap host's
// loopback interface, unless it is there already, so Kind can publish NICo's
// services on it. An address on any other interface is refused: the move takes
// the addresses off this host and onto the site cluster, and only removes them
// from the loopback interface.
func ensureHostAddresses(ctx context.Context, runner bootstrapengine.CommandRunner, addrs []string, logger *slog.Logger) error {
	have, err := listHostAddresses(ctx, runner)
	if err != nil {
		return err
	}
	for _, s := range addrs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("NICo service address %q: %w", s, err)
		}
		if a, ok := have[ip]; ok {
			if a.dev != hostLoopback {
				return fmt.Errorf("NICo service address %s is on interface %s of the bootstrap host; the bootstrap puts the service "+
					"addresses on %s and moves them to the site cluster at the end, so remove it from %s and re-run", s, a.dev, hostLoopback, a.dev)
			}
			continue
		}
		prefix := netip.PrefixFrom(ip, ip.BitLen()).String()
		if out, err := runner.Run(ctx, nil, "ip", "addr", "add", prefix, "dev", hostLoopback); err != nil {
			hint := ""
			if strings.Contains(out, "not permitted") {
				hint = "; adding an address needs root or CAP_NET_ADMIN: run nvkectl as root, or add it yourself with `ip addr add " +
					prefix + " dev " + hostLoopback + "`"
			}
			return fmt.Errorf("adding NICo service address %s to the bootstrap host: %w: %s%s", s, err, strings.TrimSpace(out), hint)
		}
		logger.Info("added a NICo service address to the bootstrap host", "address", s, "dev", hostLoopback)
	}
	return nil
}

// removeHostAddresses takes each address in addrs off the bootstrap host's
// loopback interface, whoever put it there: the site cluster announces the
// addresses next, and an address left on the host would answer for them too.
func removeHostAddresses(ctx context.Context, runner bootstrapengine.CommandRunner, addrs []string, logger *slog.Logger) error {
	have, err := listHostAddresses(ctx, runner)
	if err != nil {
		return err
	}
	for _, s := range addrs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("NICo service address %q: %w", s, err)
		}
		a, ok := have[ip]
		if !ok || a.dev != hostLoopback {
			continue
		}
		if out, err := runner.Run(ctx, nil, "ip", "addr", "del", a.prefix, "dev", hostLoopback); err != nil {
			return fmt.Errorf("removing NICo service address %s from the bootstrap host: %w: %s", s, err, strings.TrimSpace(out))
		}
		logger.Info("removed a NICo service address from the bootstrap host", "address", s)
	}
	return nil
}
