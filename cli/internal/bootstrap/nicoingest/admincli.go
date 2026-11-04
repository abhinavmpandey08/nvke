// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// Where NICo Core runs its admin CLI. NICo's charts and image fix these.
const (
	nicoNamespace = "nico-system"
	apiContainer  = "nico-api"
	// apiSelector picks nico-api's Deployment pods, not its migration Job's.
	apiSelector  = "app.kubernetes.io/name=nico-api,app.kubernetes.io/component=api,app!=nico-api-migrate"
	adminCLIPath = "/opt/carbide/nico-admin-cli"
	adminCLIAPI  = "https://nico-api.nico-system.svc.cluster.local:1079"
	// apiRootCA is the CA nico-api's own certificate chains to, mounted in its pod.
	apiRootCA = "/var/run/secrets/spiffe.io/ca.crt"

	adminCertName = "nvkectl-admin-cli"
	certTimeout   = 5 * time.Minute
	cleanupWait   = time.Minute
)

// adminCertManifest requests the admin CLI's client certificate from
// vault-nico-issuer, which signs with the site root CA. nico-api takes a
// certificate whose issuer is listed in auth.additionalIssuerCns as an admin.
// Vault's role takes only P-256 keys.
const adminCertManifest = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ` + adminCertName + `
  namespace: ` + nicoNamespace + `
spec:
  secretName: ` + adminCertName + `
  commonName: nvkectl-admin
  duration: 1h
  renewBefore: 20m
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: vault-nico-issuer
`

// adminCLI runs NICo's admin CLI in a nico-api pod with a short-lived admin
// certificate copied into it.
type adminCLI struct {
	runner     CommandRunner
	kube       kubernetes.Interface
	kubeconfig string
	log        *slog.Logger
	// pod is the nico-api pod the CLI runs in.
	pod string
	// local is a private directory on this host, remote its counterpart in the pod.
	local, remote string
	// secrets are redacted from the CLI's output.
	secrets []string
	n       int
}

// openAdminCLI issues the admin certificate and copies it into a ready nico-api pod.
func openAdminCLI(ctx context.Context, cfg Config, log *slog.Logger) (_ *adminCLI, err error) {
	local, err := os.MkdirTemp("", "nvkectl-nico-admin-")
	if err != nil {
		return nil, err
	}
	a := &adminCLI{
		runner: cfg.Runner, kube: cfg.Kube, kubeconfig: cfg.Kubeconfig, log: log,
		local: local, remote: "/tmp/" + filepath.Base(local), secrets: secretValues(cfg.Secrets),
	}
	defer func() {
		if err != nil {
			a.close(ctx)
		}
	}()

	// A certificate left by an interrupted run may have expired, so it is issued afresh.
	a.deleteCert(ctx)
	manifest := filepath.Join(local, "certificate.yaml")
	if err := os.WriteFile(manifest, []byte(adminCertManifest), 0o600); err != nil {
		return nil, err
	}
	if _, err := a.kubectl(ctx, "apply", "-f", manifest); err != nil {
		return nil, fmt.Errorf("requesting NICo's admin CLI certificate: %w", err)
	}
	if _, err := a.kubectl(ctx, "-n", nicoNamespace, "wait", "--for=condition=Ready",
		"certificate.cert-manager.io/"+adminCertName, "--timeout="+certTimeout.String()); err != nil {
		return nil, fmt.Errorf("waiting for NICo's admin CLI certificate: %w", err)
	}
	secret, err := a.kube.CoreV1().Secrets(nicoNamespace).Get(ctx, adminCertName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("reading NICo's admin CLI certificate %s/%s: %w", nicoNamespace, adminCertName, err)
	}
	if a.pod, err = apiPod(ctx, a.kube); err != nil {
		return nil, err
	}
	if _, err := a.exec(ctx, "mkdir", "-p", "-m", "700", a.remote); err != nil {
		return nil, err
	}
	for _, key := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey} {
		if len(secret.Data[key]) == 0 {
			return nil, fmt.Errorf("NICo's admin CLI certificate %s/%s has no %s", nicoNamespace, adminCertName, key)
		}
		if err := a.copy(ctx, key, secret.Data[key]); err != nil {
			return nil, err
		}
	}
	log.Info("issued NICo's admin CLI certificate", "pod", a.pod)
	return a, nil
}

// apiPod returns a ready nico-api pod.
func apiPod(ctx context.Context, kube kubernetes.Interface) (string, error) {
	pods, err := kube.CoreV1().Pods(nicoNamespace).List(ctx, metav1.ListOptions{LabelSelector: apiSelector})
	if err != nil {
		return "", fmt.Errorf("listing nico-api pods: %w", err)
	}
	for _, p := range pods.Items {
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				return p.Name, nil
			}
		}
	}
	return "", errors.New("no nico-api pod in nico-system is ready")
}

// run runs the admin CLI with args and returns its output, with every secret
// redacted. what names the step in the error.
func (a *adminCLI) run(ctx context.Context, what string, args ...string) (string, error) {
	cmd := append([]string{
		adminCLIPath, "--api-url=" + adminCLIAPI, "--root-ca-path=" + apiRootCA,
		"--client-cert-path=" + a.remote + "/" + corev1.TLSCertKey, "--client-key-path=" + a.remote + "/" + corev1.TLSPrivateKeyKey,
	}, args...)
	// args carry passwords, so they reach the pod in a script copied through
	// kubectl cp's stream, never on kubectl's command line. The script removes
	// itself before the CLI starts.
	a.n++
	name := fmt.Sprintf("cmd-%d", a.n)
	if err := a.copy(ctx, name, []byte("rm -f -- \"$0\"\nexec "+shellJoin(cmd)+"\n")); err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	out, err := a.runner.Run(ctx, "kubectl", "--kubeconfig", a.kubeconfig, "-n", nicoNamespace,
		"exec", a.pod, "-c", apiContainer, "--", "sh", a.remote+"/"+name)
	out = a.redact(out)
	if err != nil {
		return out, fmt.Errorf("%s: nico-admin-cli: %w: %s", what, err, strings.TrimSpace(out))
	}
	return out, nil
}

// close removes the admin certificate from the pod, the cluster and this host.
func (a *adminCLI) close(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	if a.pod != "" {
		if _, err := a.exec(ctx, "rm", "-rf", a.remote); err != nil {
			a.log.Warn("removing NICo's admin CLI certificate from the nico-api pod failed", "pod", a.pod, "err", err)
		}
	}
	a.deleteCert(ctx)
	_ = os.RemoveAll(a.local)
}

// deleteCert deletes the admin certificate's Certificate and Secret.
func (a *adminCLI) deleteCert(ctx context.Context) {
	if _, err := a.kubectl(ctx, "-n", nicoNamespace, "delete", "certificate.cert-manager.io", adminCertName, "--ignore-not-found"); err != nil {
		a.log.Warn("deleting NICo's admin CLI Certificate failed", "err", err)
	}
	if err := a.kube.CoreV1().Secrets(nicoNamespace).Delete(ctx, adminCertName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		a.log.Warn("deleting NICo's admin CLI certificate Secret failed", "err", err)
	}
}

// copy writes data to name in the pod's private directory, through a private file on this host.
func (a *adminCLI) copy(ctx context.Context, name string, data []byte) error {
	path := filepath.Join(a.local, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	_, err := a.kubectl(ctx, "cp", path, nicoNamespace+"/"+a.pod+":"+a.remote+"/"+name, "-c", apiContainer)
	return err
}

func (a *adminCLI) exec(ctx context.Context, args ...string) (string, error) {
	return a.kubectl(ctx, append([]string{"-n", nicoNamespace, "exec", a.pod, "-c", apiContainer, "--"}, args...)...)
}

// kubectl runs kubectl with args, which never carry a secret.
func (a *adminCLI) kubectl(ctx context.Context, args ...string) (string, error) {
	out, err := a.runner.Run(ctx, "kubectl", append([]string{"--kubeconfig", a.kubeconfig}, args...)...)
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(a.redact(out)))
	}
	return out, nil
}

func (a *adminCLI) redact(out string) string {
	for _, s := range a.secrets {
		out = strings.ReplaceAll(out, s, "<redacted>")
	}
	return out
}

// secretValues lists the passwords the admin CLI is given.
func secretValues(s nicosettings.Secrets) []string {
	var out []string
	for _, v := range []string{s.SiteWideBMCRootPassword, s.DPUBMCFactoryPassword} {
		if v != "" {
			out = append(out, v)
		}
	}
	for _, l := range s.BMCLogins {
		if l.Password != "" {
			out = append(out, l.Password)
		}
	}
	return out
}

// shellJoin quotes args for sh.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, s := range args {
		quoted[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}
