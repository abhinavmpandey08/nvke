// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicodeploy installs NICo, the controller that ingests and provisions
// a site's hosts, on a Kubernetes cluster from the charts in its source
// release. It installs the reduced NICo `nvkectl bootstrap site` runs for
// infra.nico.managed: no DPF, RMS, Flow, MetalLB or observability.
package nicodeploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
	"github.com/dsx-ai-factory/nvke/cli/internal/redact"
)

// Where NICo's installer puts each prerequisite. NICo's charts name these
// namespaces and objects, so they are not configurable here.
const (
	nicoNamespace     = "nico-system"
	vaultNamespace    = "vault"
	postgresNamespace = "postgres"
	certManagerNS     = "cert-manager"
	esoNamespace      = "external-secrets"
	prereqsRelease    = "nico-prereqs"
	pgCluster         = "nico-pg-cluster"

	vaultKeysSecret   = "vault-cluster-keys"
	vaultKeysKey      = "cluster-keys.json"
	vaultUnsealSecret = "vaultunsealkeys"
	vaultRootSecret   = "vaultroottoken"
	nicoVaultToken    = "nico-vault-token"
	sshHostKeySecret  = "ssh-host-key"
	// vaultKeyShares and vaultKeyThreshold are NICo's own, so a Vault this
	// installs unseals the way NICo's runbooks say.
	vaultKeyShares    = 5
	vaultKeyThreshold = 3

	// The Vault paths NICo reads the site's UEFI passwords from.
	dpuUEFIPath  = "machines/all_dpus/site_default/uefi-metadata-items/auth"
	hostUEFIPath = "machines/all_hosts/site_default/uefi-metadata-items/auth"
	// dpuFactoryBMCPath is the Vault path of a DPU model's BMC factory login, before its model's segment.
	dpuFactoryBMCPath = "machines/all_dpus/factory_default/bmc-metadata-items/"

	defaultTimeout = 15 * time.Minute
	pollInterval   = 5 * time.Second

	// podVaultScript is where vaultScript puts its script in a Vault pod.
	podVaultScript = "/tmp/nvkectl-vault.sh"
)

// vaultServerPod matches the names of the Vault chart's server pods.
var vaultServerPod = regexp.MustCompile(`^vault-\d+$`)

// CommandRunner runs helm and kubectl.
type CommandRunner interface {
	// Run executes name with args and returns its combined output, which is
	// populated on error too.
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Engine installs NICo.
type Engine struct {
	runner CommandRunner
	kube   kubernetes.Interface
	log    *slog.Logger
	poll   time.Duration
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// New returns an Engine that runs helm and kubectl through runner, or os/exec
// when it is nil, and reads and writes Secrets through kube.
func New(runner CommandRunner, kube kubernetes.Interface, log *slog.Logger) *Engine {
	if runner == nil {
		runner = execRunner{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Engine{runner: runner, kube: kube, log: log.With("component", "nicodeploy"), poll: pollInterval}
}

// InstallPrerequisites installs what NICo Core and REST run on: the Zalando
// Postgres operator, Vault (initialized and unsealed), External Secrets, and
// NICo's nico-prereqs chart, which creates NICo's Postgres cluster, PKI and
// synced credentials. root is the NICo source Fetch extracted. The cluster must
// already run cert-manager. Every step is an upgrade or a check, so it can be
// run again.
func (e *Engine) InstallPrerequisites(ctx context.Context, kubeconfig, root string, cfg Config) error {
	if cfg.SiteName == "" || cfg.Replicas < 1 || cfg.StorageClass == "" {
		return errors.New("nicodeploy: SiteName, Replicas and StorageClass are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	tmp, err := os.MkdirTemp("", "nvkectl-nico-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	prereqs := filepath.Join(root, "helm-prereqs")
	m := manifest.Load()
	seeds, kvMount, err := kvSeeds(filepath.Join(prereqs, "values.yaml"), cfg)
	if err != nil {
		return err
	}

	e.log.Info("installing NICo's prerequisites", "site", cfg.SiteName, "replicas", cfg.Replicas)
	// NICo's helmfile also applies operators/crds, the Prometheus Operator CRDs. Nothing this install renders uses
	// them, and on the site cluster they would overwrite NKTP's newer copies, so they are left out.
	if err := e.helm(ctx, kubeconfig, "postgres-operator", postgresNamespace, chartRef(m, manifest.ComponentPostgresOperator),
		[]string{filepath.Join(prereqs, "operators", "values", "postgres-operator.yaml")}, cfg.Timeout); err != nil {
		return err
	}

	prereqValues := filepath.Join(tmp, "nico-prereqs.yaml")
	if err := writeValues(prereqValues, prereqsValues(cfg, "", seeds)); err != nil {
		return err
	}
	if err := e.issueVaultTLS(ctx, kubeconfig, prereqs, prereqValues, !cfg.siteRootCarried, cfg.Timeout); err != nil {
		return err
	}
	vaultValues := filepath.Join(tmp, "vault.yaml")
	if err := writeValues(vaultValues, vaultOverrides(cfg)); err != nil {
		return err
	}
	// Vault is not Ready until it is unsealed, so its install is not waited on.
	if err := e.helm(ctx, kubeconfig, "vault", vaultNamespace, chartRef(m, manifest.ComponentVault),
		[]string{filepath.Join(prereqs, "operators", "values", "vault.yaml"), vaultValues}, 0); err != nil {
		return err
	}
	token, err := e.unsealVault(ctx, kubeconfig, cfg)
	if err != nil {
		return err
	}
	if err := e.helm(ctx, kubeconfig, "external-secrets", esoNamespace, chartRef(m, manifest.ComponentExternalSecrets),
		[]string{filepath.Join(prereqs, "operators", "values", "external-secrets.yaml")}, cfg.Timeout); err != nil {
		return err
	}

	// The values carry Vault's root token, so the file is private and removed with tmp.
	if err := writeValues(prereqValues, prereqsValues(cfg, token, seeds)); err != nil {
		return err
	}
	if err := e.ensureSSHHostKey(ctx); err != nil {
		return err
	}
	if err := e.helm(ctx, kubeconfig, prereqsRelease, nicoNamespace, []string{prereqs},
		[]string{filepath.Join(prereqs, "values.yaml"), prereqValues}, cfg.Timeout); err != nil {
		return err
	}
	if err := e.seedUEFIPasswords(ctx, kubeconfig, token, kvMount, cfg.Secrets); err != nil {
		return err
	}
	return e.waitPrerequisites(ctx, kubeconfig, cfg.Timeout)
}

// installCertManager installs the cert-manager the bootstrap manifest pins, with
// its CRDs. A later `clusterctl init` finds it working and keeps it.
func (e *Engine) installCertManager(ctx context.Context, kubeconfig, tmp string, timeout time.Duration) error {
	values := filepath.Join(tmp, "cert-manager.yaml")
	if err := writeValues(values, map[string]any{"crds": map[string]any{"enabled": true}}); err != nil {
		return err
	}
	return e.helm(ctx, kubeconfig, "cert-manager", certManagerNS, chartRef(manifest.Load(), manifest.ComponentCertManager),
		[]string{values}, timeout)
}

// prereqsOwned returns the Helm ownership labels and annotations of an object
// nico-prereqs adopts.
func prereqsOwned() (labels, annotations map[string]string) {
	return map[string]string{"app.kubernetes.io/managed-by": "Helm"},
		map[string]string{"meta.helm.sh/release-name": prereqsRelease, "meta.helm.sh/release-namespace": nicoNamespace}
}

// seedUEFIPasswords writes the site's UEFI passwords where NICo reads them in
// Vault's KV mount. They reach Vault through vaultScript, never a command line
// or the Job nico-prereqs renders its own seeds into.
func (e *Engine) seedUEFIPasswords(ctx context.Context, kubeconfig, token, kvMount string, s nicosettings.Secrets) error {
	pod, err := e.activeVaultPod(ctx)
	if err != nil {
		return err
	}
	for _, seed := range [][2]string{{dpuUEFIPath, s.DPUUEFIPassword}, {hostUEFIPath, s.HostUEFIPassword}} {
		body, err := json.Marshal(map[string]any{"UsernamePassword": map[string]string{"username": "", "password": seed[1]}})
		if err != nil {
			return err
		}
		command := "vault kv put -tls-skip-verify " + kvMount + "/" + seed[0] + " -"
		if err := e.vaultScript(ctx, kubeconfig, pod, command,
			"export VAULT_TOKEN="+shellQuote(token)+"\nexec "+command+heredoc(string(body))); err != nil {
			return err
		}
	}
	e.log.Info("Vault holds the site's UEFI passwords")
	return nil
}

// ensureSSHHostKey creates the SSH console's host key Secret, in OpenSSH
// format, when it does not exist. nico-prereqs adopts the Secret and keeps the
// key it finds; the key the chart generates itself is PKCS8, which
// ssh-console-rs refuses at startup.
func (e *Engine) ensureSSHHostKey(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating the SSH console's host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("encoding the SSH console's host key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding the SSH console's host key: %w", err)
	}
	helmLabels, helmAnnotations := prereqsOwned()
	if err := e.ensureNamespace(ctx, nicoNamespace, helmLabels, helmAnnotations); err != nil {
		return err
	}
	_, err = e.kube.CoreV1().Secrets(nicoNamespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: nicoNamespace, Name: sshHostKeySecret, Labels: helmLabels, Annotations: helmAnnotations},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ssh_host_ed25519_key":     pem.EncodeToMemory(block),
			"ssh_host_ed25519_key_pub": ssh.MarshalAuthorizedKey(sshPub),
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating Secret %s/%s: %w", nicoNamespace, sshHostKeySecret, err)
	}
	return nil
}

// issueVaultTLS issues the certificates Vault's pods mount before they start,
// and the site root CA they chain to when siteRoot is set.
func (e *Engine) issueVaultTLS(ctx context.Context, kubeconfig, prereqs, values string, siteRoot bool, timeout time.Duration) error {
	if err := e.ensureNamespace(ctx, vaultNamespace, nil, nil); err != nil {
		return err
	}
	args := []string{"template", prereqsRelease, prereqs, "--namespace", nicoNamespace, "--values", values}
	certificates := [][2]string{{vaultNamespace, "nicoca-vault-client"}, {vaultNamespace, "vault-raft-tls"}}
	if siteRoot {
		args = append(args, "--show-only", "templates/site-root-certificate.yaml")
		certificates = append([][2]string{{certManagerNS, "site-root"}}, certificates...)
	}
	rendered, err := e.runner.Run(ctx, "helm", append(args, "--show-only", "templates/vault-tls-certs.yaml")...)
	if err != nil {
		return fmt.Errorf("rendering NICo's Vault certificates: %w\n%s", err, rendered)
	}
	path := filepath.Join(filepath.Dir(values), "vault-tls.yaml")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "apply", "--server-side", "--field-manager=helm", "-f", path); err != nil {
		return err
	}
	for _, c := range certificates {
		if _, err := e.kubectl(ctx, kubeconfig, "wait", "--for=condition=Ready", "certificate/"+c[1], "-n", c[0],
			"--timeout="+timeout.String()); err != nil {
			return err
		}
	}
	return nil
}

type vaultStatus struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

// VaultKeys are what Vault's initialization returns once: the unseal keys and
// the root token, in the JSON `vault operator init -format=json` prints.
type VaultKeys struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

// unsealVault initializes Vault once, keeping its keys in a Secret, unseals
// every pod, and publishes the root token where nico-prereqs reads it. It
// returns the root token.
func (e *Engine) unsealVault(ctx context.Context, kubeconfig string, cfg Config) (string, error) {
	pods := make([]string, cfg.Replicas)
	for i := range pods {
		pods[i] = fmt.Sprintf("vault-%d", i)
	}
	var status vaultStatus
	if err := e.until(ctx, cfg.Timeout, "Vault to answer", func(ctx context.Context) (bool, error) {
		s, err := e.vaultStatus(ctx, kubeconfig, pods[0])
		status = s
		return err == nil, nil
	}); err != nil {
		return "", err
	}
	if !status.Initialized {
		e.log.Info("initializing Vault")
		if err := e.initVault(ctx, kubeconfig, pods[0], cfg); err != nil {
			return "", err
		}
	}
	keys, err := e.VaultKeys(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: Vault is initialized, so only its stored keys open it; restore them into %s/%s, "+
			"or reinstall Vault with its volumes deleted", err, vaultNamespace, vaultKeysSecret)
	}
	for _, pod := range pods {
		opened, err := e.unsealPod(ctx, kubeconfig, pod, keys, cfg.RestoredVaultKeys, cfg.Timeout)
		if err != nil {
			return "", err
		}
		if opened.RootToken != keys.RootToken {
			e.log.Info("Vault opened with the keys of the Vault a move restored into it; storing them", "pod", pod)
			if err := e.storeVaultKeys(ctx, opened, cfg.Timeout); err != nil {
				return "", err
			}
			keys = opened
		}
	}

	unseal := map[string][]byte{}
	for i, k := range keys.UnsealKeysB64 {
		unseal[fmt.Sprint(i)] = []byte(k)
	}
	token := map[string][]byte{"token": []byte(keys.RootToken)}
	// nico-prereqs adopts the namespace and the token Secret, so they carry its Helm ownership.
	helmLabels, helmAnnotations := prereqsOwned()
	for _, s := range []*corev1.Secret{
		{ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultUnsealSecret}, Data: unseal},
		{ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultRootSecret}, Data: token},
		{ObjectMeta: metav1.ObjectMeta{Namespace: nicoNamespace, Name: nicoVaultToken, Labels: helmLabels, Annotations: helmAnnotations}, Data: token},
	} {
		if s.Namespace == nicoNamespace {
			if err := e.ensureNamespace(ctx, nicoNamespace, helmLabels, helmAnnotations); err != nil {
				return "", err
			}
		}
		if err := e.applySecret(ctx, s); err != nil {
			return "", err
		}
	}
	e.log.Info("Vault is initialized and unsealed", "pods", len(pods))
	return keys.RootToken, nil
}

// initVault initializes Vault and stores what it returns, which Vault gives
// out only once, in a Secret. Until the Secret holds them, the keys are also in
// a private file, which the error names if they cannot be stored.
func (e *Engine) initVault(ctx context.Context, kubeconfig, pod string, cfg Config) error {
	run, cancel := context.WithTimeout(ctx, cfg.Timeout)
	// The output holds the root token and unseal keys, so it is never put in an error or log.
	// The chart's cert-reload sidecar sends SIGHUP to every process named vault,
	// which would kill this client after the server has initialized.
	out, err := e.runner.Run(run, "kubectl", "--kubeconfig", kubeconfig, "-n", vaultNamespace, "exec", pod, "-c", "vault", "--",
		"sh", "-c", fmt.Sprintf("trap '' HUP; exec vault operator init -tls-skip-verify -key-shares=%d -key-threshold=%d -format=json",
			vaultKeyShares, vaultKeyThreshold))
	cancel()
	if err != nil {
		return fmt.Errorf("initializing Vault in %s/%s: %w; if Vault reports itself initialized from now on, its keys were lost "+
			"and Vault must be reinstalled with its volumes deleted", vaultNamespace, pod, err)
	}
	body := jsonObject(out)
	var keys VaultKeys
	if err := json.Unmarshal(body, &keys); err != nil || keys.RootToken == "" {
		return fmt.Errorf("initializing Vault in %s/%s: its answer does not hold the root token", vaultNamespace, pod)
	}
	keys.redact()
	saved, err := saveVaultInit(cfg, body)
	if err != nil {
		e.log.Warn("keeping a copy of Vault's keys on disk failed; storing them in the cluster only", "err", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultKeysSecret},
		Data:       map[string][]byte{vaultKeysKey: body},
	}
	// Losing the keys means reinstalling Vault, so the write is retried.
	if err := e.until(ctx, cfg.Timeout, "Vault's keys to be stored", func(ctx context.Context) (bool, error) {
		err := e.applySecret(ctx, secret)
		if err != nil {
			e.log.Warn("storing Vault's keys failed; retrying", "err", err)
		}
		return err == nil, nil
	}); err != nil {
		if saved == "" {
			return err
		}
		return fmt.Errorf("%w; Vault's unseal keys and root token are only in %s: store them in %s/%s under %s, "+
			"or Vault must be reinstalled with its volumes deleted", err, saved, vaultNamespace, vaultKeysSecret, vaultKeysKey)
	}
	if saved != "" {
		_ = os.Remove(saved)
	}
	return nil
}

// saveVaultInit writes Vault's init answer to a file private to its owner, in
// the settings' handover directory, or the temporary directory without one,
// and returns its path.
func saveVaultInit(cfg Config, body []byte) (string, error) {
	dir := os.TempDir()
	if cfg.Settings != nil && cfg.Settings.HandoverDir != "" {
		dir = cfg.Settings.HandoverDir
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	f, err := os.CreateTemp(dir, "vault-init-*.json")
	if err != nil {
		return "", err
	}
	_, err = f.Write(body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// unsealPod unseals pod with the threshold of keys and returns the keys that
// opened it: keys when it was not sealed. With restored, the keys of a
// snapshot a move may have restored into Vault, attempts alternate between
// the two. The keys reach the pod in vaultScript's script and Vault reads
// each from stdin, so none is on a command line.
func (e *Engine) unsealPod(ctx context.Context, kubeconfig, pod string, keys VaultKeys, restored *VaultKeys, timeout time.Duration) (VaultKeys, error) {
	sets := []VaultKeys{keys}
	if restored != nil && restored.complete() && restored.RootToken != keys.RootToken {
		sets = append(sets, *restored)
	}
	opened, attempt := keys, 0
	err := e.until(ctx, timeout, pod+" to be unsealed", func(ctx context.Context) (bool, error) {
		s, err := e.vaultStatus(ctx, kubeconfig, pod)
		if err != nil {
			return false, nil
		}
		if !s.Sealed {
			return true, nil
		}
		opened = sets[attempt%len(sets)]
		attempt++
		script := "set -e\n"
		for _, key := range opened.UnsealKeysB64[:vaultKeyThreshold] {
			script += "vault write -tls-skip-verify sys/unseal key=-" + heredoc(key)
		}
		if err := e.vaultScript(ctx, kubeconfig, pod, "vault write sys/unseal", script); err != nil {
			e.log.Warn("unsealing Vault failed; retrying", "pod", pod, "err", err)
		}
		return false, nil
	})
	return opened, err
}

// redact registers k's keys and token, so no log or printed error shows them.
func (k VaultKeys) redact() {
	redact.RegisterSecret(k.RootToken)
	for _, key := range k.UnsealKeysB64 {
		redact.RegisterSecret(key)
	}
}

// VaultKeys returns the unseal keys and root token of the installed Vault.
func (e *Engine) VaultKeys(ctx context.Context) (VaultKeys, error) {
	secret, err := e.kube.CoreV1().Secrets(vaultNamespace).Get(ctx, vaultKeysSecret, metav1.GetOptions{})
	if err != nil {
		return VaultKeys{}, fmt.Errorf("reading Vault's keys from %s/%s: %w", vaultNamespace, vaultKeysSecret, err)
	}
	var keys VaultKeys
	if err := json.Unmarshal(secret.Data[vaultKeysKey], &keys); err != nil || !keys.complete() {
		return VaultKeys{}, fmt.Errorf("%s/%s does not hold Vault's unseal keys and root token", vaultNamespace, vaultKeysSecret)
	}
	keys.redact()
	return keys, nil
}

// storeVaultKeys stores keys in place of the installed Vault's. Vault opens
// with them only, so the write is retried until timeout.
func (e *Engine) storeVaultKeys(ctx context.Context, keys VaultKeys, timeout time.Duration) error {
	body, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	stored := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultKeysSecret},
		Data:       map[string][]byte{vaultKeysKey: body},
	}
	return e.until(ctx, timeout, "Vault's keys to be stored", func(ctx context.Context) (bool, error) {
		err := e.applySecret(ctx, stored)
		if err != nil {
			e.log.Warn("storing Vault's keys failed; retrying", "err", err)
		}
		return err == nil, nil
	})
}

func (k VaultKeys) complete() bool {
	return len(k.UnsealKeysB64) >= vaultKeyThreshold && k.RootToken != ""
}

// vaultStatus reads pod's Vault status. `vault status` exits non-zero while
// Vault is sealed, so its answer is read whenever it prints one.
func (e *Engine) vaultStatus(ctx context.Context, kubeconfig, pod string) (vaultStatus, error) {
	out, runErr := e.runner.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", vaultNamespace, "exec", pod, "-c", "vault", "--",
		"vault", "status", "-tls-skip-verify", "-format=json")
	var s vaultStatus
	if err := json.Unmarshal(jsonObject(out), &s); err != nil {
		return s, fmt.Errorf("reading Vault's status in %s/%s: %w\n%s", vaultNamespace, pod, errors.Join(runErr, err), out)
	}
	return s, nil
}

func (e *Engine) postgresPrimary(ctx context.Context) (string, error) {
	pods, err := e.kube.CoreV1().Pods(postgresNamespace).List(ctx, metav1.ListOptions{LabelSelector: "application=spilo,spilo-role=master"})
	if err != nil {
		return "", fmt.Errorf("finding the Postgres primary: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no Postgres primary in %s", postgresNamespace)
	}
	return pods.Items[0].Name, nil
}

// removeInPod deletes path in the pod, even once ctx is canceled, giving up after a minute.
func (e *Engine) removeInPod(ctx context.Context, kubeconfig, namespace, pod, container, path string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if _, err := e.runner.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace,
		"exec", pod, "-c", container, "--", "rm", "-f", path); err != nil {
		e.log.Warn("removing a file from a pod failed", "pod", namespace+"/"+pod, "path", path, "err", err)
	}
}

// activeVaultPod returns the Vault pod that serves writes: the one Vault
// labels active, or the only one.
func (e *Engine) activeVaultPod(ctx context.Context) (string, error) {
	var pod string
	err := e.until(ctx, defaultTimeout, "an active Vault pod", func(ctx context.Context) (bool, error) {
		pods, err := e.kube.CoreV1().Pods(vaultNamespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, nil
		}
		var servers []string
		for _, p := range pods.Items {
			if !vaultServerPod.MatchString(p.Name) {
				continue
			}
			if p.Labels["vault-active"] == "true" {
				pod = p.Name
				return true, nil
			}
			servers = append(servers, p.Name)
		}
		if len(servers) == 1 {
			pod = servers[0]
		}
		return pod != "", nil
	})
	return pod, err
}

// heredoc feeds input, one line, to the command it follows on stdin. One line
// cannot hold the delimiter line, so input ends where it does.
func heredoc(input string) string {
	return " <<'NVKECTL_INPUT'\n" + input + "\nNVKECTL_INPUT\n"
}

// vaultScript runs script with sh in the Vault pod. What script holds, such as
// a token, reaches the pod through kubectl cp's stream, never on a command
// line; the script removes itself before the rest of it runs. Errors name the
// script by what, and never hold Vault's answer.
func (e *Engine) vaultScript(ctx context.Context, kubeconfig, pod, what, script string) error {
	f, err := os.CreateTemp("", "nvkectl-vault-*.sh")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, err = f.WriteString("rm -f -- \"$0\"\n" + script)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if _, err := e.runner.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", vaultNamespace, "cp", "-c", "vault",
		f.Name(), pod+":"+podVaultScript); err != nil {
		return fmt.Errorf("copying a script into %s/%s: %w", vaultNamespace, pod, err)
	}
	// Removed here too in case the script never ran.
	defer e.removeInPod(ctx, kubeconfig, vaultNamespace, pod, "vault", podVaultScript)
	if _, err := e.runner.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", vaultNamespace, "exec", pod, "-c", "vault", "--",
		"sh", podVaultScript); err != nil {
		return fmt.Errorf("running %q in %s/%s: %w", what, vaultNamespace, pod, err)
	}
	return nil
}

// waitPrerequisites waits for what NICo Core reads at start: its Postgres
// cluster, the pg_trgm extension NICo REST's migrations need, and the
// credentials External Secrets syncs from Vault.
func (e *Engine) waitPrerequisites(ctx context.Context, kubeconfig string, timeout time.Duration) error {
	if err := e.patchNamespaceLabels(ctx, nicoNamespace, map[string]string{"nico.nvidia.com/managed": "true"}); err != nil {
		return err
	}
	if err := e.until(ctx, timeout, pgCluster+" to run", func(ctx context.Context) (bool, error) {
		out, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "get", "postgresql", pgCluster,
			"-o", "jsonpath={.status.PostgresClusterStatus}")
		return err == nil && strings.TrimSpace(out) == "Running", nil
	}); err != nil {
		return err
	}
	if err := e.until(ctx, timeout, "the pg_trgm extension in nico_rest", func(ctx context.Context) (bool, error) {
		pod, err := e.postgresPrimary(ctx)
		if err != nil {
			return false, nil
		}
		_, err = e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "exec", pod, "--",
			"su", "postgres", "-c", "psql -d nico_rest -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'")
		return err == nil, nil
	}); err != nil {
		return err
	}
	for _, s := range []struct {
		name string
		keys []string
	}{
		{"nico-roots", nil},
		{"nico-system.nico.nico-pg-cluster.credentials", nil},
		{"nico-vault-approle-tokens", []string{"VAULT_ROLE_ID", "VAULT_SECRET_ID"}},
	} {
		if err := e.until(ctx, timeout, "Secret "+nicoNamespace+"/"+s.name, func(ctx context.Context) (bool, error) {
			secret, err := e.kube.CoreV1().Secrets(nicoNamespace).Get(ctx, s.name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			for _, k := range s.keys {
				if len(secret.Data[k]) == 0 {
					return false, nil
				}
			}
			return true, nil
		}); err != nil {
			return err
		}
	}
	e.log.Info("NICo's prerequisites are ready")
	return nil
}

// prereqsValues is what the nico-prereqs chart takes beyond its own values.yaml,
// with seeds as its Vault KV seeds. rootToken is empty until Vault is
// initialized; the Vault certificates render without it.
func prereqsValues(cfg Config, rootToken string, seeds []map[string]any) map[string]any {
	pg := map[string]any{
		"instances":       cfg.Replicas,
		"synchronousMode": cfg.Replicas > 1,
		"storageClass":    cfg.StorageClass,
	}
	if cfg.Replicas == 1 {
		pg["resources"] = map[string]any{"requests": map[string]any{"cpu": "250m", "memory": "512Mi"}}
	}
	values := map[string]any{
		"siteName":   cfg.SiteName,
		"vault":      map[string]any{"token": rootToken, "kvSeeds": seeds},
		"postgresql": pg,
		"rms":        map[string]any{"enabled": false},
		"flow":       map[string]any{"enabled": false},
		// Temporal and Keycloak keep their databases in NICo's Postgres, so all of NICo's state is in one place.
		"temporal": map[string]any{"useHaPostgres": true},
		"keycloak": map[string]any{"useHaPostgres": true},
	}
	if cfg.siteRootCarried {
		// The CA is another cluster's, copied in; the chart must not issue a new one over it.
		values["certManager"] = map[string]any{"siteRoot": map[string]any{"create": false}}
	}
	return values
}

// kvSeeds returns the vault.kvSeeds of nico-prereqs' values.yaml at path, and
// its vault.kvMount. The chart writes its seeds on every install and upgrade,
// so the rows nvkectl writes elsewhere are left out: the site_default UEFI
// rows, which seedUEFIPasswords writes, and, when cfg has a DPU BMC factory
// login, the factory rows of its models, which nicoingest writes.
func kvSeeds(path string, cfg Config) ([]map[string]any, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading nico-prereqs' values: %w", err)
	}
	var values struct {
		Vault struct {
			KVMount string           `yaml:"kvMount"`
			KVSeeds []map[string]any `yaml:"kvSeeds"`
		} `yaml:"vault"`
	}
	if err := yaml.Unmarshal(b, &values); err != nil {
		return nil, "", fmt.Errorf("reading nico-prereqs' values %s: %w", path, err)
	}
	if values.Vault.KVMount == "" {
		return nil, "", fmt.Errorf("nico-prereqs' values %s set no vault.kvMount", path)
	}
	drop := map[string]bool{dpuUEFIPath: true, hostUEFIPath: true}
	if cfg.Secrets.DPUBMCFactoryUsername != "" {
		models := []string{"unknown"}
		if cfg.Settings != nil && len(cfg.Settings.DPUFactoryModels) > 0 {
			models = cfg.Settings.DPUFactoryModels
		}
		for _, model := range models {
			if model == "unknown" {
				model = "root" // NICo's Vault segment for a DPU of unknown model
			}
			drop[dpuFactoryBMCPath+model] = true
		}
	}
	var seeds []map[string]any
	for _, seed := range values.Vault.KVSeeds {
		if p, _ := seed["path"].(string); !drop[p] {
			seeds = append(seeds, seed)
		}
	}
	return seeds, values.Vault.KVMount, nil
}

// vaultOverrides sizes NICo's Vault values for cfg. A single replica runs on
// the bootstrap host, so it asks for a fraction of NICo's production requests.
func vaultOverrides(cfg Config) map[string]any {
	server := map[string]any{
		"ha":           map[string]any{"replicas": cfg.Replicas},
		"dataStorage":  map[string]any{"storageClass": cfg.StorageClass},
		"auditStorage": map[string]any{"storageClass": cfg.StorageClass},
	}
	if cfg.Replicas == 1 {
		server["resources"] = map[string]any{"requests": map[string]any{"cpu": "250m", "memory": "256Mi"}}
	}
	return map[string]any{"server": server}
}

func writeValues(path string, values map[string]any) error {
	b, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// chartRef is the chart half of a helm install for an upstream chart the manifest pins.
func chartRef(m *manifest.Manifest, component string) []string {
	c := m.Components[component].Chart
	return []string{c.Name, "--repo", c.Repo, "--version", c.Version}
}

// helm installs or upgrades release from chart, waiting up to wait when it is non-zero.
func (e *Engine) helm(ctx context.Context, kubeconfig, release, namespace string, chart, values []string, wait time.Duration) error {
	args := append([]string{"upgrade", "--install", release}, chart...)
	args = append(args, "--namespace", namespace, "--create-namespace", "--kubeconfig", kubeconfig)
	for _, v := range values {
		args = append(args, "--values", v)
	}
	if wait > 0 {
		args = append(args, "--wait", "--timeout", wait.String())
	}
	e.log.Info("installing", "release", release, "namespace", namespace)
	if out, err := e.runner.Run(ctx, "helm", args...); err != nil {
		return fmt.Errorf("installing %s in %s: %w\n%s", release, namespace, err, out)
	}
	return nil
}

func (e *Engine) kubectl(ctx context.Context, kubeconfig string, args ...string) (string, error) {
	out, err := e.runner.Run(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

func (e *Engine) ensureNamespace(ctx context.Context, name string, labels, annotations map[string]string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels, Annotations: annotations}}
	_, err := e.kube.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if len(labels) == 0 && len(annotations) == 0 {
			return nil
		}
		existing, err := e.kube.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("reading namespace %s: %w", name, err)
		}
		existing.Labels = merge(existing.Labels, labels)
		existing.Annotations = merge(existing.Annotations, annotations)
		_, err = e.kube.CoreV1().Namespaces().Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating namespace %s: %w", name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating namespace %s: %w", name, err)
	}
	return nil
}

func (e *Engine) patchNamespaceLabels(ctx context.Context, name string, labels map[string]string) error {
	return e.ensureNamespace(ctx, name, labels, nil)
}

// applySecret creates s, or replaces the data and metadata of the Secret of its name.
func (e *Engine) applySecret(ctx context.Context, s *corev1.Secret) error {
	secrets := e.kube.CoreV1().Secrets(s.Namespace)
	_, err := secrets.Create(ctx, s, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		if err != nil {
			return fmt.Errorf("creating Secret %s/%s: %w", s.Namespace, s.Name, err)
		}
		return nil
	}
	existing, err := secrets.Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading Secret %s/%s: %w", s.Namespace, s.Name, err)
	}
	existing.Data = s.Data
	existing.Labels = merge(existing.Labels, s.Labels)
	existing.Annotations = merge(existing.Annotations, s.Annotations)
	if _, err := secrets.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating Secret %s/%s: %w", s.Namespace, s.Name, err)
	}
	return nil
}

func merge(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// until calls done every poll interval until it reports true, returns an error, or timeout passes.
func (e *Engine) until(ctx context.Context, timeout time.Duration, what string, done func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		ok, err := done(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out after %s waiting for %s", timeout, what)
		case <-time.After(e.poll):
		}
	}
}

// jsonObject returns the JSON object in out, dropping anything kubectl or the
// command printed around it.
func jsonObject(out string) []byte {
	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	if start < 0 || end < start {
		return []byte(out)
	}
	return []byte(out[start : end+1])
}
