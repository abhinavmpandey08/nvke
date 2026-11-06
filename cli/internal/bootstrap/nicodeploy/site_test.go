// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// index returns the position of the first call containing want, or -1.
func (r *recordingRunner) index(want string) int {
	for i, c := range r.calls {
		if strings.Contains(c, want) {
			return i
		}
	}
	return -1
}

func TestBusyWorkflows(t *testing.T) {
	tests := []struct {
		name    string
		listing string
		want    []string
	}{
		{name: "nothing runs", listing: "[]", want: nil},
		{
			name: "crons and inventory reports are left out",
			listing: `[{"execution":{"workflowId":"site-monitor-health-all","runId":"r1"}},
{"execution":{"workflowId":"inventory-machine-6f1c","runId":"r2"}},
{"execution":{"workflowId":"update-machine-inventory-6f1c-2","runId":"r3"}},
{"execution":{"workflowId":"rotate-certs-and-otps","runId":"r4"}}]`,
			want: nil,
		},
		{
			name: "one-shot workflows are listed once, sorted",
			listing: `{"execution":{"workflowId":"create-instance-b","runId":"r1"},"parentExecution":{"workflowId":"create-instance-a"}}
{"execution":{"workflow_id":"create-instance-a","run_id":"r2"}}
{"execution":{"workflowId":"monitor-site-temporal-namespaces","runId":"r3"}}`,
			want: []string{"create-instance-a", "create-instance-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, busyWorkflows(tt.listing))
		})
	}
}

func TestRunningWorkflowsRefusesUnsafeNamespaces(t *testing.T) {
	e := New(&recordingRunner{}, fake.NewClientset(), discardLog())
	_, err := e.RunningWorkflows(context.Background(), "kubeconfig", "cloud; rm -rf /")
	assert.Error(t, err)
}

func TestParseSiteState(t *testing.T) {
	const site = "6f1c2a52-3c0e-4b4e-9b4f-0d3c9b8d6a11"
	tests := []struct {
		name    string
		out     string
		want    SiteState
		wantErr bool
	}{
		{
			name: "inventory and machines",
			out:  "inventory 1767225600\nmachine fm100ht1 Ready\nmachine fm100ht2 InUse\n",
			want: SiteState{InventoryReceived: time.Unix(1767225600, 0), Machines: map[string]string{"fm100ht1": "Ready", "fm100ht2": "InUse"}},
		},
		{name: "no inventory yet", out: "inventory 0\n", want: SiteState{Machines: map[string]string{}}},
		{name: "no site row", out: "machine fm100ht1 Ready\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSiteState(tt.out, site)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, tt.want.InventoryReceived.Equal(got.InventoryReceived))
			assert.Equal(t, tt.want.Machines, got.Machines)
		})
	}
}

func TestReadCarriedThenApply(t *testing.T) {
	ctx := context.Background()
	secret := func(ns, name string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns, Name: name, UID: "seed-uid", ResourceVersion: "42",
				Annotations: map[string]string{"cert-manager.io/certificate-name": name},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{"tls.crt": []byte(name + "-crt"), "tls.key": []byte(name + "-key")},
		}
	}
	tests := []struct {
		name    string
		seed    []runtime.Object
		wantSSH bool
		wantErr bool
	}{
		{
			name: "every Secret is carried",
			seed: []runtime.Object{
				secret(certManagerNS, siteRootSecret), secret(restNamespace, restCASecret),
				secret(nicoNamespace, sshHostKeySecret), secret(restNamespace, keycloakLoginSecret),
			},
			wantSSH: true,
		},
		{
			name: "the SSH host key is optional",
			seed: []runtime.Object{secret(certManagerNS, siteRootSecret), secret(restNamespace, restCASecret), secret(restNamespace, keycloakLoginSecret)},
		},
		{
			name:    "the Keycloak login is required",
			seed:    []runtime.Object{secret(certManagerNS, siteRootSecret), secret(restNamespace, restCASecret)},
			wantErr: true,
		},
		{name: "the site root CA is required", seed: []runtime.Object{secret(restNamespace, restCASecret)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carried, err := New(nil, fake.NewClientset(tt.seed...), discardLog()).ReadCarried(ctx)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSSH, carried.SSHHostKey != nil)

			site := fake.NewClientset()
			require.NoError(t, New(nil, site, discardLog()).applyCarried(ctx, carried))
			want := [][2]string{{certManagerNS, siteRootSecret}, {restNamespace, restCASecret}, {certManagerNS, restCASecret}, {restNamespace, keycloakLoginSecret}}
			if tt.wantSSH {
				want = append(want, [2]string{nicoNamespace, sshHostKeySecret})
			}
			for _, w := range want {
				got, err := site.CoreV1().Secrets(w[0]).Get(ctx, w[1], metav1.GetOptions{})
				require.NoError(t, err, "Secret %s/%s", w[0], w[1])
				assert.Equal(t, corev1.SecretTypeTLS, got.Type)
				assert.NotEmpty(t, got.Data["tls.key"])
				assert.NotEqual(t, types.UID("seed-uid"), got.UID, "the seed's object metadata is not copied")
				if w[1] == sshHostKeySecret {
					assert.Equal(t, prereqsRelease, got.Annotations["meta.helm.sh/release-name"], "nico-prereqs adopts the host key")
				} else {
					assert.Empty(t, got.Annotations, "cert-manager's annotations stay behind")
				}
			}
		})
	}
}

func TestPrereqsValuesCarriedSiteRoot(t *testing.T) {
	cfg := restTestConfig()
	assert.Nil(t, valueAt(prereqsValues(cfg, "token", nil), "certManager"), "the chart issues the site root CA by default")
	cfg.siteRootCarried = true
	assert.Equal(t, false, valueAt(prereqsValues(cfg, "token", nil), "certManager", "siteRoot", "create"))
}

func TestIssueVaultTLSWithCarriedSiteRoot(t *testing.T) {
	for _, siteRoot := range []bool{true, false} {
		runner := &recordingRunner{}
		e := New(runner, fake.NewClientset(), discardLog())
		require.NoError(t, e.issueVaultTLS(context.Background(), "kubeconfig", "/src/helm-prereqs", filepath.Join(t.TempDir(), "values.yaml"), siteRoot, time.Second))
		assert.Equal(t, siteRoot, runner.index("templates/site-root-certificate.yaml") >= 0, "site root rendered: %v", siteRoot)
		assert.Equal(t, siteRoot, runner.index("certificate/site-root") >= 0, "site root waited on: %v", siteRoot)
		assert.GreaterOrEqual(t, runner.index("certificate/vault-raft-tls"), 0)
	}
}

func TestEnsureRESTCACopiesAMissedCopy(t *testing.T) {
	ctx := context.Background()
	ca := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: restCASecret},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: []byte("example-crt"), corev1.TLSPrivateKeyKey: []byte("example-key")},
	}
	kube := fake.NewClientset(ca)
	require.NoError(t, New(&recordingRunner{}, kube, discardLog()).ensureRESTCA(ctx, "kubeconfig", "/src"))
	copied, err := kube.CoreV1().Secrets(certManagerNS).Get(ctx, restCASecret, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, ca.Data, copied.Data, "cert-manager gets the CA REST already has, not a new one")
}

func TestStopNICo(t *testing.T) {
	ctx := context.Background()
	replicas := int32(2)
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
	kube := fake.NewClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: "nico-rest-api"},
			Spec:       appsv1.DeploymentSpec{Replicas: &replicas, Selector: selector},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: nicoNamespace, Name: "nico-api"},
			Spec:       appsv1.DeploymentSpec{Replicas: &replicas, Selector: selector},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: siteAgentRelease},
			Spec:       appsv1.StatefulSetSpec{Replicas: &replicas, Selector: selector},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: temporalNamespace, Name: "temporal-frontend"},
			Spec:       appsv1.DeploymentSpec{Replicas: &replicas, Selector: selector},
		},
		// A finished migration Job's pod carries nico-api's labels; it must not hold the stop up.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: nicoNamespace, Name: "nico-api-migrate-x", Labels: map[string]string{"app": "x"}},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
	)
	e := New(nil, kube, discardLog())
	e.poll = time.Millisecond

	done := make(chan error, 1)
	go func() { done <- e.StopNICo(ctx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("StopNICo waited on a pod that already finished")
	}
	for _, d := range [][2]string{{restNamespace, "nico-rest-api"}, {nicoNamespace, "nico-api"}} {
		got, err := kube.AppsV1().Deployments(d[0]).Get(ctx, d[1], metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, int32(0), *got.Spec.Replicas, "%s/%s", d[0], d[1])
	}
	agent, err := kube.AppsV1().StatefulSets(restNamespace).Get(ctx, siteAgentRelease, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), *agent.Spec.Replicas)
	temporal, err := kube.AppsV1().Deployments(temporalNamespace).Get(ctx, "temporal-frontend", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), *temporal.Spec.Replicas, "Temporal keeps running")
}

func TestVaultCommandKeepsTheTokenOffCommandLines(t *testing.T) {
	const token = "hvs.example-token"
	var script string
	runner := &recordingRunner{answer: func(args []string) (string, error) {
		for i, a := range args {
			if a == "cp" {
				b, err := os.ReadFile(args[i+3])
				script = string(b)
				return "", err
			}
		}
		return "", nil
	}}
	e := New(runner, fake.NewClientset(), discardLog())

	require.NoError(t, e.vaultCommand(context.Background(), "kubeconfig", "vault-0", token, "vault operator raft snapshot save /tmp/s"))
	for _, c := range runner.calls {
		assert.NotContains(t, c, token)
	}
	assert.Contains(t, script, "export VAULT_TOKEN='"+token+"'")
	assert.True(t, strings.HasPrefix(script, `rm -f -- "$0"`), "the script removes itself before it runs")
	assert.GreaterOrEqual(t, runner.index("exec vault-0 -c vault -- sh "+podVaultScript), 0)
	assert.GreaterOrEqual(t, runner.index("rm -f "+podVaultScript), 0, "removed even if it never ran")
}

func TestVaultKeys(t *testing.T) {
	keys := VaultKeys{UnsealKeysB64: []string{"k0", "k1", "k2", "k3", "k4"}, RootToken: "root-token"}
	body, err := json.Marshal(keys)
	require.NoError(t, err)
	stored := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: vaultKeysSecret}, Data: map[string][]byte{vaultKeysKey: body}}
	got, err := New(nil, fake.NewClientset(stored), discardLog()).VaultKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, keys, got)

	stored.Data[vaultKeysKey] = []byte(`{"unseal_keys_b64":["k0"],"root_token":"root-token"}`)
	_, err = New(nil, fake.NewClientset(stored), discardLog()).VaultKeys(context.Background())
	assert.Error(t, err, "fewer keys than the threshold")
}

func TestRestartVault(t *testing.T) {
	ctx := context.Background()
	var pods []runtime.Object
	for _, name := range []string{"vault-0", "vault-1", "vault-2"} {
		pods = append(pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: name, UID: "old"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		})
	}
	kube := fake.NewClientset(pods...)
	// The StatefulSet controller replaces each deleted pod.
	kube.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		name := action.(k8stesting.DeleteAction).GetName()
		replaced := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: name, UID: "new"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		return true, nil, kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), replaced, vaultNamespace)
	})
	e := New(nil, kube, discardLog())
	e.poll = time.Millisecond

	require.NoError(t, e.restartVault(ctx, Config{Replicas: 3, Timeout: time.Second}))
	for _, name := range []string{"vault-0", "vault-1", "vault-2"} {
		p, err := kube.CoreV1().Pods(vaultNamespace).Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, types.UID("new"), p.UID)
	}
}

func TestDumpAndRestoreDatabase(t *testing.T) {
	ctx := context.Background()
	primary := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: postgresNamespace, Name: "nico-pg-cluster-0",
		Labels: map[string]string{"application": "spilo", "spilo-role": "master"},
	}}
	runner := &recordingRunner{answer: func(args []string) (string, error) {
		// kubectl cp from the pod writes the local file.
		if strings.Contains(strings.Join(args, " "), " cp ") && strings.Contains(args[len(args)-2], ":") {
			return "", os.WriteFile(args[len(args)-1], []byte("PGDMP"), 0o644)
		}
		return "", nil
	}}
	e := New(runner, fake.NewClientset(primary), discardLog())
	path := filepath.Join(t.TempDir(), "nico_rest.dump")

	require.NoError(t, e.DumpDatabase(ctx, "seed", "nico_rest", path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the dump is private")
	assert.GreaterOrEqual(t, runner.index("su postgres -c pg_dump -Fc -d nico_rest -f /tmp/nvkectl-nico_rest.dump"), 0)

	require.NoError(t, e.RestoreDatabase(ctx, "site", "nico_rest", path))
	restore := runner.index("pg_restore --clean --if-exists --single-transaction -d nico_rest /tmp/nvkectl-nico_rest.dump")
	require.GreaterOrEqual(t, restore, 0)
	assert.NotContains(t, runner.calls[restore], "--no-owner", "owners are kept")
	assert.Greater(t, runner.index("site -n postgres exec nico-pg-cluster-0 -c postgres -- rm -f /tmp/nvkectl-nico_rest.dump"), restore,
		"the copy in the pod is removed")

	assert.Error(t, e.DumpDatabase(ctx, "seed", "nico_rest; drop", path))
}
