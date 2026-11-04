// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// What moving NICo to the site cluster touches beyond its install.
const (
	siteRootSecret = "site-root"

	metallbRelease   = "metallb"
	metallbNamespace = "metallb-system"
	// metallbPool holds NICo's service addresses and nothing else.
	metallbPool = "nico-services"

	restAPIDeployment     = "nico-rest-api"
	cloudWorkerDeployment = "nico-rest-cloud-worker"

	// Paths in the Vault and Postgres pods that files pass through.
	podVaultSnapshot = "/tmp/nvkectl-vault.snap"
)

// Databases are NICo's databases in its Postgres that move with it: Core's,
// REST's (which the site agent shares) and Keycloak's. Temporal's do not move.
var Databases = []string{"nico_system_nico", "nico_rest", "keycloak"}

// cronWorkflows are the IDs of NICo REST's cron workflows in the cloud
// namespace. Each site agent's crons are inventory-<site ID> workflows.
var cronWorkflows = []string{"site-monitor-health-all", "monitor-site-temporal-namespaces", "rotate-certs-and-otps"}

var (
	databaseName          = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	temporalNamespaceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	workflowIDField       = regexp.MustCompile(`"workflow_?[Ii]d"\s*:\s*"([^"]*)"`)
)

// Carried is the state the site cluster's NICo starts from that neither its
// databases nor its Vault hold.
type Carried struct {
	// SiteRoot is the site root CA NICo's PKI chains to (cert-manager/site-root).
	SiteRoot *corev1.Secret
	// RESTCA is the CA NICo REST's and Temporal's certificates chain to
	// (nico-rest/ca-signing-secret).
	RESTCA *corev1.Secret
	// SSHHostKey is the SSH console's host key (nico-system/ssh-host-key), nil
	// when there is none.
	SSHHostKey *corev1.Secret
	// KeycloakLogin is the bundled Keycloak's admin password and client secrets
	// (nico-rest/keycloak-login), which its database already holds. Nil with an
	// external identity provider.
	KeycloakLogin *corev1.Secret
}

// ReadCarried reads the Carried state of the installed NICo.
func (e *Engine) ReadCarried(ctx context.Context) (Carried, error) {
	var c Carried
	for _, s := range []struct {
		dst             **corev1.Secret
		namespace, name string
		optional        bool
	}{
		{&c.SiteRoot, certManagerNS, siteRootSecret, false},
		{&c.RESTCA, restNamespace, restCASecret, false},
		{&c.SSHHostKey, nicoNamespace, sshHostKeySecret, true},
		{&c.KeycloakLogin, restNamespace, keycloakLoginSecret, true},
	} {
		secret, err := e.kube.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err) && s.optional:
			continue
		case err != nil:
			return Carried{}, fmt.Errorf("reading Secret %s/%s: %w", s.namespace, s.name, err)
		}
		*s.dst = secret
	}
	return c, nil
}

// PrepareSite readies the site cluster for the bootstrap cluster's NICo, as
// cfg describes it with ProfileSite: MetalLB holding every service address,
// the carried Secrets, the prerequisites on the carried site root CA, and
// Temporal with the cloud, site and siteID namespaces. It starts nothing that
// writes NICo's databases. root is the NICo source Fetch extracted. The
// cluster must already run cert-manager.
func (e *Engine) PrepareSite(ctx context.Context, kubeconfig, root string, cfg Config, carried Carried, siteID string) error {
	if cfg.Settings == nil {
		return errors.New("nicodeploy: Settings is required to prepare the site")
	}
	if carried.SiteRoot == nil || carried.RESTCA == nil {
		return errors.New("nicodeploy: the site root CA and the REST CA must be carried to the site")
	}
	if _, err := uuid.Parse(siteID); err != nil {
		return fmt.Errorf("nicodeploy: the NICo site ID %q is not a UUID", siteID)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	cfg.siteRootCarried = true
	tmp, err := os.MkdirTemp("", "nvkectl-nico-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := e.installMetalLB(ctx, kubeconfig, tmp, cfg); err != nil {
		return err
	}
	if err := e.applyCarried(ctx, carried); err != nil {
		return err
	}
	if err := e.InstallPrerequisites(ctx, kubeconfig, root, cfg); err != nil {
		return err
	}
	if err := e.ensureRESTCA(ctx, kubeconfig, root); err != nil {
		return err
	}
	if err := e.installTemporal(ctx, kubeconfig, root, tmp, cfg.Timeout); err != nil {
		return err
	}
	if err := e.ensureTemporalNamespace(ctx, kubeconfig, siteID, cfg.Timeout); err != nil {
		return err
	}
	e.log.Info("the site cluster is ready for NICo", "site", cfg.SiteName)
	return nil
}

// installMetalLB installs MetalLB with a pool of NICo's service addresses,
// announced on the site's layer 2 network. The pool assigns an address only
// to a Service that names it.
func (e *Engine) installMetalLB(ctx context.Context, kubeconfig, tmp string, cfg Config) error {
	values := filepath.Join(tmp, "metallb.yaml")
	if err := writeValues(values, map[string]any{"speaker": map[string]any{
		// kubeadm marks control-plane nodes excluded from load balancers, and the site's nodes may all be control planes.
		"ignoreExcludeLB": true,
		"frr":             map[string]any{"enabled": false},
	}}); err != nil {
		return err
	}
	if err := e.helm(ctx, kubeconfig, metallbRelease, metallbNamespace, chartRef(manifest.Load(), manifest.ComponentMetalLB),
		[]string{values}, cfg.Timeout); err != nil {
		return err
	}
	pool, err := metalLBPool(cfg.Settings.Addresses)
	if err != nil {
		return err
	}
	path := filepath.Join(tmp, "metallb-pool.yaml")
	if err := os.WriteFile(path, pool, 0o600); err != nil {
		return err
	}
	// MetalLB's webhook refuses the pool until its certificate is in place.
	return e.until(ctx, cfg.Timeout, "MetalLB to take NICo's address pool", func(ctx context.Context) (bool, error) {
		_, err := e.kubectl(ctx, kubeconfig, "apply", "-f", path)
		if err != nil {
			e.log.Warn("applying MetalLB's address pool failed; retrying", "err", err)
		}
		return err == nil, nil
	})
}

// metalLBPool is the IPAddressPool of every address in a and the
// L2Advertisement that announces it.
func metalLBPool(a nicosettings.Addresses) ([]byte, error) {
	var cidrs []string
	for _, address := range serviceAddresses(a) {
		ip := net.ParseIP(address)
		if ip == nil {
			return nil, fmt.Errorf("nicodeploy: the service address %q is not an IP address", address)
		}
		bits := "/128"
		if ip.To4() != nil {
			bits = "/32"
		}
		cidrs = append(cidrs, ip.String()+bits)
	}
	meta := map[string]any{"name": metallbPool, "namespace": metallbNamespace}
	var docs []string
	for _, obj := range []map[string]any{
		{
			"apiVersion": "metallb.io/v1beta1", "kind": "IPAddressPool", "metadata": meta,
			"spec": map[string]any{"addresses": cidrs, "autoAssign": false},
		},
		{
			"apiVersion": "metallb.io/v1beta1", "kind": "L2Advertisement", "metadata": meta,
			"spec": map[string]any{"ipAddressPools": []string{metallbPool}},
		},
	} {
		b, err := sigsyaml.Marshal(obj)
		if err != nil {
			return nil, err
		}
		docs = append(docs, string(b))
	}
	return []byte(strings.Join(docs, "---\n")), nil
}

// serviceAddresses lists each address NICo's services are published on once.
func serviceAddresses(a nicosettings.Addresses) []string {
	var out []string
	for _, address := range append([]string{a.DHCP, a.PXE, a.API, a.REST, a.Keycloak, a.DNS, a.SSHConsole}, a.NTP...) {
		if address != "" && !slices.Contains(out, address) {
			out = append(out, address)
		}
	}
	return out
}

// applyCarried writes the carried Secrets where the site's NICo reads them.
// nico-prereqs adopts the SSH host key, and keeps the key it finds.
func (e *Engine) applyCarried(ctx context.Context, c Carried) error {
	helmLabels, helmAnnotations := prereqsOwned()
	secrets := []*corev1.Secret{
		carry(c.SiteRoot, certManagerNS, nil, nil),
		// REST's ClusterIssuer reads the CA from cert-manager's namespace.
		carry(c.RESTCA, restNamespace, nil, nil),
		carry(c.RESTCA, certManagerNS, nil, nil),
	}
	if c.SSHHostKey != nil {
		if err := e.ensureNamespace(ctx, nicoNamespace, helmLabels, helmAnnotations); err != nil {
			return err
		}
		secrets = append(secrets, carry(c.SSHHostKey, nicoNamespace, helmLabels, helmAnnotations))
	}
	if c.KeycloakLogin != nil {
		secrets = append(secrets, carry(c.KeycloakLogin, restNamespace, nil, nil))
	}
	for _, ns := range []string{certManagerNS, restNamespace} {
		if err := e.ensureNamespace(ctx, ns, nil, nil); err != nil {
			return err
		}
	}
	for _, s := range secrets {
		if err := e.applySecret(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// carry is a copy of s in namespace, with only its type and data.
func carry(s *corev1.Secret, namespace string, labels, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: s.Name, Labels: labels, Annotations: annotations},
		Type:       s.Type,
		Data:       s.Data,
	}
}

// ScaleRESTAPI sets NICo REST's API to replicas and, for zero, waits for its
// pods to go, so it serves no request after it returns.
func (e *Engine) ScaleRESTAPI(ctx context.Context, replicas int) error {
	selector, err := e.scaleDeployment(ctx, restNamespace, restAPIDeployment, replicas)
	if err != nil {
		return err
	}
	if replicas > 0 {
		return nil
	}
	return e.waitPodsGone(ctx, restNamespace, selector)
}

// StopNICo stops every Deployment and StatefulSet of NICo Core, REST, its
// site agent and Keycloak, and waits for their pods to go. Postgres, Vault
// and Temporal keep running.
func (e *Engine) StopNICo(ctx context.Context) error {
	type workload struct{ namespace, selector string }
	var stopped []workload
	for _, ns := range []string{restNamespace, nicoNamespace} {
		deployments, err := e.kube.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing Deployments in %s: %w", ns, err)
		}
		for _, d := range deployments.Items {
			selector, err := e.scaleDeployment(ctx, ns, d.Name, 0)
			if err != nil {
				return err
			}
			stopped = append(stopped, workload{ns, selector})
		}
		statefulSets, err := e.kube.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing StatefulSets in %s: %w", ns, err)
		}
		for _, s := range statefulSets.Items {
			if err := e.patchReplicas(ctx, "statefulset", ns, s.Name, 0); err != nil {
				return err
			}
			stopped = append(stopped, workload{ns, metav1.FormatLabelSelector(s.Spec.Selector)})
		}
	}
	for _, w := range stopped {
		if err := e.waitPodsGone(ctx, w.namespace, w.selector); err != nil {
			return err
		}
	}
	e.log.Info("NICo is stopped", "workloads", len(stopped))
	return nil
}

// scaleDeployment sets the Deployment's replicas and returns its pod selector.
func (e *Engine) scaleDeployment(ctx context.Context, namespace, name string, replicas int) (string, error) {
	d, err := e.kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading Deployment %s/%s: %w", namespace, name, err)
	}
	if err := e.patchReplicas(ctx, "deployment", namespace, name, replicas); err != nil {
		return "", err
	}
	return metav1.FormatLabelSelector(d.Spec.Selector), nil
}

func (e *Engine) patchReplicas(ctx context.Context, kind, namespace, name string, replicas int) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))
	var err error
	if kind == "statefulset" {
		_, err = e.kube.AppsV1().StatefulSets(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	} else {
		_, err = e.kube.AppsV1().Deployments(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	}
	if err != nil {
		return fmt.Errorf("scaling %s %s/%s to %d: %w", kind, namespace, name, replicas, err)
	}
	return nil
}

// waitPodsGone waits until no running pod in namespace matches selector.
func (e *Engine) waitPodsGone(ctx context.Context, namespace, selector string) error {
	return e.until(ctx, defaultTimeout, "the pods "+selector+" in "+namespace+" to stop", func(ctx context.Context) (bool, error) {
		pods, err := e.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return false, nil
		}
		// A finished Job's pod, such as nico-api's migration, can share a Deployment's labels and never goes away.
		return !slices.ContainsFunc(pods.Items, func(p corev1.Pod) bool {
			return p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed
		}), nil
	})
}

// RunningWorkflows returns the IDs of the workflows running in the Temporal
// namespace of NICo's Temporal, leaving out the periodic ones: NICo REST's
// crons, the site agent's inventory crons and the inventory reports they send,
// which the site agent sends again wherever it runs.
func (e *Engine) RunningWorkflows(ctx context.Context, kubeconfig, namespace string) ([]string, error) {
	if !temporalNamespaceName.MatchString(namespace) {
		return nil, fmt.Errorf("nicodeploy: %q is not a Temporal namespace name", namespace)
	}
	list := fmt.Sprintf("temporal workflow list -n %s --query %s --address %s:7233 %s -o json",
		namespace, shellQuote("ExecutionStatus='Running'"), temporalHost, temporalTLS)
	out, err := e.kubectl(ctx, kubeconfig, "-n", temporalNamespace, "exec", "deploy/temporal-admintools", "--", "sh", "-c", list)
	if err != nil {
		return nil, err
	}
	return busyWorkflows(out), nil
}

// busyWorkflows returns the IDs in a Temporal CLI JSON listing that are not periodic.
func busyWorkflows(listing string) []string {
	var ids []string
	for _, m := range workflowIDField.FindAllStringSubmatch(listing, -1) {
		id := m[1]
		periodic := strings.HasPrefix(id, "inventory-") || slices.Contains(cronWorkflows, id) ||
			(strings.HasPrefix(id, "update-") && strings.Contains(id, "-inventory-"))
		if !periodic && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// DumpDatabase writes a custom-format pg_dump of database in NICo's Postgres
// to path, private to its owner. It gives up after 15 minutes.
func (e *Engine) DumpDatabase(ctx context.Context, kubeconfig, database, path string) (err error) {
	if !databaseName.MatchString(database) {
		return fmt.Errorf("nicodeploy: %q is not a database name", database)
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	defer func() { err = timedOut(ctx, err, "dumping "+database) }()
	pod, err := e.postgresPrimary(ctx)
	if err != nil {
		return err
	}
	remote := "/tmp/nvkectl-" + database + ".dump"
	defer e.removeInPod(ctx, kubeconfig, postgresNamespace, pod, "postgres", remote)
	if _, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "exec", pod, "-c", "postgres", "--",
		"su", "postgres", "-c", "pg_dump -Fc -d "+database+" -f "+remote); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "cp", "-c", "postgres", pod+":"+remote, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	e.log.Info("dumped NICo's database", "database", database)
	return nil
}

// RestoreDatabase restores the dump at path into database in NICo's
// Postgres, replacing the objects the dump holds and keeping their owners,
// whose roles NICo's Postgres creates with the same names on every cluster.
// It gives up after 15 minutes.
func (e *Engine) RestoreDatabase(ctx context.Context, kubeconfig, database, path string) (err error) {
	if !databaseName.MatchString(database) {
		return fmt.Errorf("nicodeploy: %q is not a database name", database)
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	defer func() { err = timedOut(ctx, err, "restoring "+database) }()
	pod, err := e.postgresPrimary(ctx)
	if err != nil {
		return err
	}
	remote := "/tmp/nvkectl-" + database + ".dump"
	if _, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "cp", "-c", "postgres", path, pod+":"+remote); err != nil {
		return err
	}
	defer e.removeInPod(ctx, kubeconfig, postgresNamespace, pod, "postgres", remote)
	// kubectl cp writes the file as root, private as it was here.
	restore := "chown postgres " + remote + " && su postgres -c " +
		shellQuote("pg_restore --clean --if-exists --single-transaction -d "+database+" "+remote)
	if _, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "exec", pod, "-c", "postgres", "--", "sh", "-c", restore); err != nil {
		return err
	}
	e.log.Info("restored NICo's database", "database", database)
	return nil
}

// timedOut names what timed out when ctx's deadline ended the step that returned err.
func timedOut(ctx context.Context, err error, what string) error {
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timed out %s: %w", what, err)
	}
	return err
}

// SnapshotVault writes a raft snapshot of the installed Vault to path,
// private to its owner. It gives up after 15 minutes.
func (e *Engine) SnapshotVault(ctx context.Context, kubeconfig, path string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	defer func() { err = timedOut(ctx, err, "taking a snapshot of Vault") }()
	keys, err := e.VaultKeys(ctx)
	if err != nil {
		return err
	}
	pod, err := e.activeVaultPod(ctx)
	if err != nil {
		return err
	}
	defer e.removeInPod(ctx, kubeconfig, vaultNamespace, pod, "vault", podVaultSnapshot)
	if err := e.vaultCommand(ctx, kubeconfig, pod, keys.RootToken, "vault operator raft snapshot save -tls-skip-verify "+podVaultSnapshot); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", vaultNamespace, "cp", "-c", "vault", pod+":"+podVaultSnapshot, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	e.log.Info("took a snapshot of NICo's Vault")
	return nil
}

// RestoreVault replaces the installed Vault's data with the snapshot at
// snapshot, taken from the Vault whose keys are keys, and opens it with those
// keys: it stores them in place of the installed Vault's, restarts and
// unseals every Vault pod, and upgrades nico-prereqs with their root token,
// which points Vault's Kubernetes auth at this cluster and issues NICo a new
// AppRole secret. The prerequisites must be installed from a carried site
// root CA, as PrepareSite installs them.
func (e *Engine) RestoreVault(ctx context.Context, kubeconfig, root string, cfg Config, snapshot string, keys VaultKeys) error {
	if !keys.complete() {
		return errors.New("nicodeploy: the unseal keys and root token of the snapshot's Vault are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	cfg.siteRootCarried = true
	current, err := e.VaultKeys(ctx)
	if err != nil {
		return err
	}
	pod, err := e.activeVaultPod(ctx)
	if err != nil {
		return err
	}
	step, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if _, err := e.kubectl(step, kubeconfig, "-n", vaultNamespace, "cp", "-c", "vault", snapshot, pod+":"+podVaultSnapshot); err != nil {
		return timedOut(step, err, "copying the snapshot into Vault")
	}
	defer e.removeInPod(ctx, kubeconfig, vaultNamespace, pod, "vault", podVaultSnapshot)
	restoreErr := timedOut(step, e.vaultCommand(step, kubeconfig, pod, current.RootToken,
		"vault operator raft snapshot restore -force -tls-skip-verify "+podVaultSnapshot), "restoring Vault's snapshot")
	if restoreErr != nil {
		// Vault seals itself once its data holds another Vault's keyring, which can fail the request that restored it.
		if s, err := e.vaultStatus(ctx, kubeconfig, pod); err != nil || !s.Sealed {
			return restoreErr
		}
	}
	e.log.Info("restored NICo's Vault from the snapshot")

	body, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	stored := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultKeysSecret},
		Data:       map[string][]byte{vaultKeysKey: body},
	}
	// Vault now opens with these keys only, so the write is retried.
	if err := e.until(ctx, cfg.Timeout, "Vault's keys to be stored", func(ctx context.Context) (bool, error) {
		err := e.applySecret(ctx, stored)
		if err != nil {
			e.log.Warn("storing Vault's keys failed; retrying", "err", err)
		}
		return err == nil, nil
	}); err != nil {
		return err
	}
	if err := e.restartVault(ctx, cfg); err != nil {
		return err
	}
	// Unseals the restarted pods with the stored keys and reruns nico-prereqs' Vault configuration.
	if err := e.InstallPrerequisites(ctx, kubeconfig, root, cfg); err != nil {
		return err
	}
	return e.grantTemporalCreateDB(ctx, kubeconfig, cfg.Timeout)
}

// restartVault deletes every Vault pod and waits for its replacement to run.
func (e *Engine) restartVault(ctx context.Context, cfg Config) error {
	pods := e.kube.CoreV1().Pods(vaultNamespace)
	old := map[string]types.UID{}
	for i := range cfg.Replicas {
		name := fmt.Sprintf("vault-%d", i)
		p, err := pods.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("reading pod %s/%s: %w", vaultNamespace, name, err)
		}
		old[name] = p.UID
		if err := pods.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("restarting pod %s/%s: %w", vaultNamespace, name, err)
		}
	}
	return e.until(ctx, cfg.Timeout, "Vault's pods to restart", func(ctx context.Context) (bool, error) {
		for name, uid := range old {
			p, err := pods.Get(ctx, name, metav1.GetOptions{})
			if err != nil || p.UID == uid || p.Status.Phase != corev1.PodRunning {
				return false, nil
			}
		}
		return true, nil
	})
}

// vaultCommand runs command in the Vault pod with token, as vaultScript runs a script.
func (e *Engine) vaultCommand(ctx context.Context, kubeconfig, pod, token, command string) error {
	return e.vaultScript(ctx, kubeconfig, pod, command, "export VAULT_TOKEN="+shellQuote(token)+"\nexec "+command+"\n")
}

// SiteState is what NICo REST's database records about a site.
type SiteState struct {
	// InventoryReceived is when the site agent's inventory last reached REST,
	// to the second; zero before the first.
	InventoryReceived time.Time
	// Machines maps the ID of each of the site's machines to its status.
	Machines map[string]string
}

// SiteState reads the state of the site siteID from NICo REST's database.
func (e *Engine) SiteState(ctx context.Context, kubeconfig, siteID string) (SiteState, error) {
	if _, err := uuid.Parse(siteID); err != nil {
		return SiteState{}, fmt.Errorf("nicodeploy: the NICo site ID %q is not a UUID", siteID)
	}
	out, err := e.restSQL(ctx, kubeconfig, fmt.Sprintf(`SELECT 'inventory ' || COALESCE(floor(EXTRACT(EPOCH FROM inventory_received))::bigint, 0)
  FROM site WHERE id='%[1]s'
UNION ALL SELECT 'machine ' || id || ' ' || status FROM machine WHERE site_id='%[1]s' AND deleted IS NULL;`, siteID))
	if err != nil {
		return SiteState{}, err
	}
	return parseSiteState(out, siteID)
}

func parseSiteState(out, siteID string) (SiteState, error) {
	state := SiteState{Machines: map[string]string{}}
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "inventory":
			seconds, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return SiteState{}, fmt.Errorf("reading the site's inventory time %q: %w", fields[1], err)
			}
			if seconds > 0 {
				state.InventoryReceived = time.Unix(seconds, 0)
			}
			found = true
		case len(fields) == 3 && fields[0] == "machine":
			state.Machines[fields[1]] = fields[2]
		}
	}
	if !found {
		return SiteState{}, fmt.Errorf("NICo REST has no site %s", siteID)
	}
	return state, nil
}

// StartSite starts the moved NICo on the site cluster as cfg describes it
// with ProfileSite, after PrepareSite, the database restores and
// RestoreVault: Keycloak, NICo Core, REST and the site agent of siteID, each
// on its LoadBalancer address. It restarts REST's cloud worker once, which
// starts REST's crons in the site's Temporal, verifies NICo answers on its
// addresses, and returns how it is reached.
func (e *Engine) StartSite(ctx context.Context, kubeconfig, root string, cfg Config, siteID string) (*Installed, error) {
	if cfg.Settings == nil || cfg.ImageRegistry == "" || cfg.CoreImageTag == "" || cfg.RestImageTag == "" || cfg.CoreValues == "" {
		return nil, errors.New("nicodeploy: Settings, ImageRegistry, CoreImageTag, RestImageTag and CoreValues are required")
	}
	if _, err := uuid.Parse(siteID); err != nil {
		return nil, fmt.Errorf("nicodeploy: the NICo site ID %q is not a UUID", siteID)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	tmp, err := os.MkdirTemp("", "nvkectl-nico-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	// The site agent dials Core once at start, so Core comes first.
	if err := e.installCore(ctx, kubeconfig, root, tmp, cfg); err != nil {
		return nil, err
	}
	creds, err := e.installREST(ctx, kubeconfig, root, tmp, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := e.RegisterSite(ctx, kubeconfig, root, tmp, cfg, siteID); err != nil {
		return nil, err
	}
	// The cloud worker starts REST's crons only when it shuts down.
	deployment := "deployment/" + cloudWorkerDeployment
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "rollout", "restart", deployment); err != nil {
		return nil, err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "rollout", "status", deployment, "--timeout="+cfg.Timeout.String()); err != nil {
		return nil, err
	}
	inst := &Installed{
		SiteID:       siteID,
		RESTEndpoint: restEndpoint(cfg.Settings),
		OrgID:        cfg.Settings.EffectiveOrgID(),
		APIName:      nicorest.DefaultAPIName,
		Credentials:  creds,
	}
	if err := e.verify(ctx, cfg, inst); err != nil {
		return nil, err
	}
	e.log.Info("NICo runs on the site cluster", "site", cfg.SiteName, "siteID", siteID)
	return inst, nil
}

// WriteHelmValues writes the values each of NICo's Helm releases runs with to
// dir, one <release>.yaml each, private to their owner. They hold secrets.
func (e *Engine) WriteHelmValues(ctx context.Context, kubeconfig, dir string) error {
	for _, r := range [][2]string{
		{metallbRelease, metallbNamespace},
		{"postgres-operator", postgresNamespace},
		{"vault", vaultNamespace},
		{"external-secrets", esoNamespace},
		{prereqsRelease, nicoNamespace},
		{"nico", nicoNamespace},
		{"temporal", temporalNamespace},
		{"nico-rest", restNamespace},
		{siteAgentRelease, restNamespace},
	} {
		// The values hold secrets, so the output is never put in an error.
		out, err := e.runner.Run(ctx, "helm", "get", "values", r[0], "--namespace", r[1], "--kubeconfig", kubeconfig, "--output", "yaml")
		if err != nil {
			return fmt.Errorf("reading the values of the release %s in %s: %w", r[0], r[1], err)
		}
		path := filepath.Join(dir, r[0]+".yaml")
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}
