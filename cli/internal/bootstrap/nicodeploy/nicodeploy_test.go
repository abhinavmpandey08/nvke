// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// fakeVault answers the vault commands the install runs through kubectl exec,
// for one pod per replica, and records every command line. A pod unseals after
// vaultKeyThreshold unseal writes, which reach it in a copied script.
type fakeVault struct {
	initialized bool
	unseals     map[string]int
	inits       int
	lines       []string
}

func (v *fakeVault) Run(_ context.Context, _ string, args ...string) (string, error) {
	line := strings.Join(args, " ")
	v.lines = append(v.lines, line)
	pod := ""
	for i, a := range args {
		switch {
		case a == "exec" && i+1 < len(args):
			pod = args[i+1]
		case a == "cp" && i+4 < len(args):
			// kubectl cp -c vault <script> <pod>:<path>
			script, err := os.ReadFile(args[i+3])
			if err != nil {
				return "", err
			}
			pod, _, _ = strings.Cut(args[i+4], ":")
			v.unseals[pod] += strings.Count(string(script), "vault write -tls-skip-verify sys/unseal key=-")
			return "", nil
		}
	}
	switch {
	case strings.Contains(line, "vault status"):
		sealed := v.unseals[pod] < vaultKeyThreshold
		b, _ := json.Marshal(vaultStatus{Initialized: v.initialized, Sealed: sealed})
		if sealed {
			// vault status exits 2 while sealed, still printing its answer.
			return "Defaulted container\n" + string(b), errors.New("exit status 2")
		}
		return string(b), nil
	case strings.Contains(line, "operator init"):
		if !strings.Contains(line, "trap '' HUP; exec vault operator init") {
			return "", errors.New("exit status 129: vault operator init runs without SIGHUP ignored")
		}
		v.inits++
		v.initialized = true
		b, _ := json.Marshal(VaultKeys{UnsealKeysB64: []string{"k0", "k1", "k2", "k3", "k4"}, RootToken: "root-token"})
		return string(b), nil
	}
	return "", nil
}

func TestUnsealVault(t *testing.T) {
	tests := []struct {
		name      string
		replicas  int
		firstRun  bool
		wantInits int
	}{
		{name: "initializes once and unseals the single seed pod", replicas: 1, firstRun: true, wantInits: 1},
		{name: "unseals every replica", replicas: 3, firstRun: true, wantInits: 1},
		{name: "a second run reuses the stored keys", replicas: 1, firstRun: false, wantInits: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			kube := fake.NewClientset()
			vault := &fakeVault{unseals: map[string]int{}}
			e := New(vault, kube, slog.New(slog.NewTextHandler(io.Discard, nil)))
			e.poll = time.Millisecond
			cfg := Config{SiteName: "site", Replicas: tt.replicas, StorageClass: "standard", Timeout: time.Second}

			token, err := e.unsealVault(context.Background(), "kubeconfig", cfg)
			require.NoError(t, err)
			if !tt.firstRun {
				vault.unseals = map[string]int{} // the pods restarted sealed
				token, err = e.unsealVault(context.Background(), "kubeconfig", cfg)
				require.NoError(t, err)
			}

			assert.Equal(t, "root-token", token)
			assert.Equal(t, tt.wantInits, vault.inits)
			assert.Len(t, vault.unseals, tt.replicas)
			for pod, n := range vault.unseals {
				assert.Equal(t, vaultKeyThreshold, n, "%s unsealed with the threshold of keys", pod)
			}
			for _, line := range vault.lines {
				assert.NotRegexp(t, `\bk[0-4]\b|root-token`, line, "no key or token on a command line")
			}
			saved, err := filepath.Glob(filepath.Join(tmp, "vault-init-*.json"))
			require.NoError(t, err)
			assert.Empty(t, saved, "the keys' copy on disk is removed once they are stored")
			for _, s := range [][2]string{{vaultNamespace, vaultKeysSecret}, {vaultNamespace, vaultRootSecret}, {vaultNamespace, vaultUnsealSecret}, {nicoNamespace, nicoVaultToken}} {
				_, err := kube.CoreV1().Secrets(s[0]).Get(context.Background(), s[1], metav1.GetOptions{})
				assert.NoError(t, err, "Secret %s/%s", s[0], s[1])
			}
			ns, err := kube.CoreV1().Namespaces().Get(context.Background(), nicoNamespace, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, prereqsRelease, ns.Annotations["meta.helm.sh/release-name"], "nico-prereqs can adopt its namespace")
		})
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// restTestConfig is a seed Config for the site site-a.
func restTestConfig() Config {
	s := &nicosettings.Settings{File: nicosettings.File{
		Addresses: nicosettings.Addresses{REST: "10.0.0.88", Keycloak: "10.0.0.82"},
	}}
	return Config{
		SiteName: "site-a", Replicas: 1, Timeout: time.Second, ImageRegistry: "nvcr.io/example", RestImageTag: "v2.2.2",
		Settings: s, Secrets: nicosettings.Secrets{HostUEFIPassword: "host-uefi", DPUUEFIPassword: "dpu-uefi"},
	}
}

// valueAt returns the value at path in nested Helm values.
func valueAt(values map[string]any, path ...string) any {
	var v any = values
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func TestInitVaultKeepsTheKeysWhenTheyCannotBeStored(t *testing.T) {
	kube := fake.NewClientset()
	kube.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("the API server is down")
	})
	e := New(&fakeVault{unseals: map[string]int{}}, kube, discardLog())
	e.poll = time.Millisecond
	dir := filepath.Join(t.TempDir(), "handover")
	cfg := Config{Timeout: 20 * time.Millisecond, Settings: &nicosettings.Settings{HandoverDir: dir}}

	err := e.initVault(context.Background(), "kubeconfig", "vault-0", cfg)
	require.Error(t, err)
	saved, globErr := filepath.Glob(filepath.Join(dir, "vault-init-*.json"))
	require.NoError(t, globErr)
	require.Len(t, saved, 1)
	assert.Contains(t, err.Error(), "only in "+saved[0])
	body, readErr := os.ReadFile(saved[0])
	require.NoError(t, readErr)
	assert.Contains(t, string(body), "root-token")
	info, statErr := os.Stat(saved[0])
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestKVSeeds(t *testing.T) {
	// The rows of nico-prereqs' values.yaml, with example passwords.
	const chart = `vault:
  kvMount: "secrets"
  kvSeeds:
    - path: "machines/all_dpus/factory_default/bmc-metadata-items/root"
      data: {UsernamePassword: {username: "root", password: "example-factory"}}
    - path: "machines/all_dpus/factory_default/uefi-metadata-items/auth"
      data: {UsernamePassword: {username: "", password: "example-uefi"}}
    - path: "machines/all_dpus/site_default/uefi-metadata-items/auth"
      data: {UsernamePassword: {username: "", password: ""}}
    - path: "machines/all_hosts/site_default/uefi-metadata-items/auth"
      data: {UsernamePassword: {username: "", password: ""}}
`
	path := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(path, []byte(chart), 0o600))
	tests := []struct {
		name      string
		factory   string
		models    []string
		wantPaths []string
	}{
		{
			name: "the chart's rows but the UEFI passwords nvkectl writes itself",
			wantPaths: []string{
				"machines/all_dpus/factory_default/bmc-metadata-items/root",
				"machines/all_dpus/factory_default/uefi-metadata-items/auth",
			},
		},
		{
			name:      "an operator's factory login replaces the catch-all row",
			factory:   "example-user",
			wantPaths: []string{"machines/all_dpus/factory_default/uefi-metadata-items/auth"},
		},
		{
			name:    "an operator's factory login for other models keeps the catch-all row",
			factory: "example-user",
			models:  []string{"bf3"},
			wantPaths: []string{
				"machines/all_dpus/factory_default/bmc-metadata-items/root",
				"machines/all_dpus/factory_default/uefi-metadata-items/auth",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := restTestConfig()
			cfg.Secrets.DPUBMCFactoryUsername = tt.factory
			cfg.Settings.DPUFactoryModels = tt.models
			seeds, mount, err := kvSeeds(path, cfg)
			require.NoError(t, err)
			assert.Equal(t, "secrets", mount)
			var paths []string
			for _, s := range seeds {
				paths = append(paths, s["path"].(string))
			}
			assert.Equal(t, tt.wantPaths, paths)
			values := prereqsValues(cfg, "root-token", seeds)
			assert.Equal(t, seeds, valueAt(values, "vault", "kvSeeds"))
			assert.Equal(t, "root-token", valueAt(values, "vault", "token"))
		})
	}

	require.NoError(t, os.WriteFile(path, []byte("vault:\n  kvSeeds: []\n"), 0o600))
	_, _, err := kvSeeds(path, restTestConfig())
	assert.ErrorContains(t, err, "vault.kvMount")
}

func TestSeedUEFIPasswords(t *testing.T) {
	var scripts []string
	runner := &recordingRunner{answer: func(args []string) (string, error) {
		for i, a := range args {
			if a == "cp" {
				b, err := os.ReadFile(args[i+3])
				scripts = append(scripts, string(b))
				return "", err
			}
		}
		return "", nil
	}}
	vault := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: vaultNamespace, Name: "vault-0"}}
	e := New(runner, fake.NewClientset(vault), discardLog())
	secrets := nicosettings.Secrets{HostUEFIPassword: "example-host-uefi", DPUUEFIPassword: "example-dpu-uefi"}

	require.NoError(t, e.seedUEFIPasswords(context.Background(), "kubeconfig", "root-token", "secrets", secrets))
	for _, c := range runner.calls {
		assert.NotContains(t, c, "example-")
		assert.NotContains(t, c, "root-token")
	}
	require.Len(t, scripts, 2)
	assert.Contains(t, scripts[0], "exec vault kv put -tls-skip-verify secrets/"+dpuUEFIPath+" - <<'NVKECTL_INPUT'\n"+
		`{"UsernamePassword":{"password":"example-dpu-uefi","username":""}}`+"\nNVKECTL_INPUT\n")
	assert.Contains(t, scripts[1], "secrets/"+hostUEFIPath)
	assert.Contains(t, scripts[1], `"password":"example-host-uefi"`)
}

func TestRestOverrides(t *testing.T) {
	login := &keycloakLogin{AdminPassword: "a", ServiceSecret: "s", RESTSecret: "r"}
	tests := []struct {
		name  string
		login *keycloakLogin
		check func(t *testing.T, v map[string]any)
	}{
		{
			name:  "bundled Keycloak issues tokens at its published address",
			login: login,
			check: func(t *testing.T, v map[string]any) {
				assert.Equal(t, map[string]any{"enabled": true, "externalBaseURL": "http://10.0.0.82:8082", "serviceAccount": true},
					valueAt(v, "nico-rest-api", "config", "keycloak"))
				assert.Nil(t, valueAt(v, "nico-rest-api", "config", "issuers"))
				assert.Equal(t, "r", valueAt(v, "nico-rest-common", "secrets", "keycloakClientSecret", "value"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := restOverrides(restTestConfig(), "nico-rest.nico", "db-password", tt.login)
			assert.Equal(t, map[string]any{"enabled": false}, valueAt(v, "nico-rest-api", "nodePort"), "Kind maps nvkectl's node port, not the chart's")
			assert.Equal(t, temporalHost, valueAt(v, "nico-rest-api", "config", "temporal", "host"))
			assert.Equal(t, "db-password", valueAt(v, "nico-rest-common", "secrets", "dbCreds", "password"))
			assert.Nil(t, valueAt(v, "nico-rest-common", "secrets", "imagePullSecret"), "no registry login, no pull secret")
			tt.check(t, v)
		})
	}
}

func TestClientCredentials(t *testing.T) {
	login := &keycloakLogin{ServiceSecret: "service-secret"}
	assert.Equal(t, nicorest.ClientCredentials{
		TokenURL: "http://10.0.0.82:8082/realms/nico/protocol/openid-connect/token", ClientID: "ncx-service", ClientSecret: "service-secret",
	}, clientCredentials(restTestConfig(), login))
	assert.Equal(t, "http://10.0.0.88:8388", restEndpoint(restTestConfig().Settings))

	cfg := restTestConfig()
	cfg.Settings.Addresses.REST, cfg.Settings.Addresses.Keycloak = "10.0.0.250:30388", "[fd00::82]:30082"
	assert.Equal(t, "http://10.0.0.250:30388", restEndpoint(cfg.Settings))
	assert.Equal(t, "http://[fd00::82]:30082/realms/nico/protocol/openid-connect/token", clientCredentials(cfg, login).TokenURL)
}

func TestSiteAgentValues(t *testing.T) {
	v := siteAgentValues(restTestConfig(), "0b4f6d3c-1111-4222-8333-444455556666")
	assert.Equal(t, map[string]any{
		"CLUSTER_ID":                   "0b4f6d3c-1111-4222-8333-444455556666",
		"TEMPORAL_SUBSCRIBE_NAMESPACE": "0b4f6d3c-1111-4222-8333-444455556666",
		"TEMPORAL_SUBSCRIBE_QUEUE":     "site",
		"TEMPORAL_HOST":                "temporal-frontend.nico-temporal",
		"FLOW_GRPC_ENABLED":            "false",
	}, v["envConfig"])
	assert.Equal(t, 1, v["replicaCount"])
	assert.Equal(t, "v2.2.2", valueAt(v, "global", "image", "tag"))
}

// sqlRunner answers the psql the site lookup runs with row, or fails it the first fails times.
type sqlRunner struct {
	row   string
	fails int
	calls []string
}

func (r *sqlRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	line := strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if r.fails > 0 {
		r.fails--
		return "connection refused", errors.New("exit status 2")
	}
	if strings.Contains(line, "SELECT id FROM site") {
		return r.row + "\n", nil
	}
	return "", nil
}

func TestResolveSiteID(t *testing.T) {
	const given, prior, row = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	tests := []struct {
		name         string
		given, prior string
		row          string
		fails        int
		want         string
		wantLookup   bool
		wantErr      bool
	}{
		{name: "a given ID wins", given: given, prior: prior, row: row, want: given},
		{name: "the previous install's ID is kept", prior: prior, row: row, want: prior},
		{name: "REST's site of the same name and org is adopted", row: row, want: row, wantLookup: true},
		{name: "a failed lookup is retried, not taken as no site", row: row, fails: 2, want: row, wantLookup: true},
		{name: "a new ID is minted when there is no site", wantLookup: true},
		{name: "an ID that is not a UUID is refused", given: "not-a-uuid", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kube := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: postgresNamespace, Name: "nico-pg-cluster-0",
				Labels: map[string]string{"application": "spilo", "spilo-role": "master"},
			}})
			runner := &sqlRunner{row: tt.row, fails: tt.fails}
			e := New(runner, kube, discardLog())
			e.poll = time.Millisecond

			id, err := e.resolveSiteID(context.Background(), "kubeconfig", restTestConfig(), tt.given, tt.prior)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.want != "" {
				assert.Equal(t, tt.want, id)
			} else {
				_, err := uuid.Parse(id)
				assert.NoError(t, err, "a minted ID is a UUID")
			}
			assert.Equal(t, tt.wantLookup, len(runner.calls) > 0)
			for _, c := range runner.calls {
				assert.Contains(t, c, "-tAc "+shellQuote("SELECT id FROM site WHERE name='site-a' AND org='ncx' AND deleted IS NULL LIMIT 1;"))
			}
		})
	}
}

func TestRegisterSiteRefusesNamesUnsafeInSQL(t *testing.T) {
	cfg := restTestConfig()
	cfg.SiteName = "site'; DROP TABLE site; --"
	e := New(&sqlRunner{}, fake.NewClientset(), discardLog())
	_, err := e.RegisterSite(context.Background(), "kubeconfig", "root", t.TempDir(), cfg, "")
	require.Error(t, err)
}

func TestShellQuote(t *testing.T) {
	assert.Equal(t, `'SELECT '\''a'\'''`, shellQuote(`SELECT 'a'`))
}

const testRealmConfigMap = `apiVersion: v1
kind: ConfigMap
metadata:
  name: keycloak-realm
data:
  nico-realm.json: |
    {
      "realm": "nico",
      "roles": {"realm": [{"name": "ncx:NICO_PROVIDER_ADMIN"}, {"name": "ncx:NICO_TENANT_ADMIN"}]},
      "clients": [
        {"clientId": "nico-rest", "secret": "nico-local-secret"},
        {"clientId": "ncx-service", "secret": "nico-local-secret"}
      ],
      "users": [{"username": "service-account-ncx-service", "realmRoles": ["ncx:NICO_PROVIDER_ADMIN", "ncx:NICO_TENANT_ADMIN"]}]
    }
`

func TestKeycloakRealmJSON(t *testing.T) {
	login := &keycloakLogin{ServiceSecret: "service-secret", RESTSecret: "rest-secret"}
	tests := []struct {
		name      string
		configMap string
		org       string
		wantRoles []any
		wantErr   bool
	}{
		{
			name: "the default org keeps NICo's roles", configMap: testRealmConfigMap, org: "ncx",
			wantRoles: []any{"ncx:NICO_PROVIDER_ADMIN", "ncx:NICO_TENANT_ADMIN"},
		},
		{
			name: "another org gets the service account's roles", configMap: testRealmConfigMap, org: "acme",
			wantRoles: []any{"acme:NICO_PROVIDER_ADMIN", "acme:NICO_TENANT_ADMIN"},
		},
		{
			name: "a realm without the clients is refused", org: "ncx", wantErr: true,
			configMap: strings.ReplaceAll(testRealmConfigMap, `"clientId": "ncx-service"`, `"clientId": "other"`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := keycloakRealmJSON([]byte(tt.configMap), login, tt.org, "http://10.0.0.5:30082")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotContains(t, string(b), "nico-local-secret")
			var realm struct {
				Clients []struct{ ClientID, Secret string } `json:"clients"`
				Users   []struct {
					RealmRoles []any `json:"realmRoles"`
				} `json:"users"`
				Attributes map[string]any `json:"attributes"`
			}
			require.NoError(t, json.Unmarshal(b, &realm))
			secrets := map[string]string{}
			for _, c := range realm.Clients {
				secrets[c.ClientID] = c.Secret
			}
			assert.Equal(t, map[string]string{"nico-rest": "rest-secret", "ncx-service": "service-secret"}, secrets)
			assert.Equal(t, tt.wantRoles, realm.Users[0].RealmRoles)
			assert.Equal(t, "http://10.0.0.5:30082", realm.Attributes["frontendUrl"])
		})
	}
}

const testKeycloakDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  selector:
    matchLabels: {app: keycloak}
  template:
    metadata:
      labels: {app: keycloak}
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:24.0
          env:
            - name: KEYCLOAK_ADMIN
              value: "admin"
            - name: KEYCLOAK_ADMIN_PASSWORD
              value: "admin"
            - name: KC_DB_URL
              value: "jdbc:postgresql://${KEYCLOAK_DB_HOST}:5432/${KEYCLOAK_DB_NAME}?sslmode=${KEYCLOAK_DB_SSLMODE}"
            - name: KC_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: "${KEYCLOAK_DB_PASSWORD_SECRET_NAME}"
                  key: "${KEYCLOAK_DB_PASSWORD_SECRET_KEY}"
      volumes:
        - name: realm-config
          configMap:
            name: keycloak-realm
`

func TestKeycloakDeployment(t *testing.T) {
	b, err := keycloakDeployment([]byte(testKeycloakDeployment))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "${")
	var d appsv1.Deployment
	require.NoError(t, sigsyaml.Unmarshal(b, &d))
	env := map[string]corev1.EnvVar{}
	for _, e := range d.Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e
	}
	password := env["KEYCLOAK_ADMIN_PASSWORD"]
	assert.Empty(t, password.Value)
	require.NotNil(t, password.ValueFrom)
	assert.Equal(t, corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: keycloakLoginSecret}, Key: "admin-password"},
		*password.ValueFrom.SecretKeyRef)
	assert.Equal(t, "jdbc:postgresql://"+pgHost+":5432/keycloak?sslmode=require", env["KC_DB_URL"].Value)
	assert.Equal(t, keycloakCreds, env["KC_DB_PASSWORD"].ValueFrom.SecretKeyRef.Name)
	vol := d.Spec.Template.Spec.Volumes[0]
	assert.Nil(t, vol.ConfigMap)
	require.NotNil(t, vol.Secret)
	assert.Equal(t, keycloakRealmSecret, vol.Secret.SecretName)

	_, err = keycloakDeployment([]byte(strings.ReplaceAll(testKeycloakDeployment, "KEYCLOAK_ADMIN_PASSWORD", "OTHER")))
	assert.Error(t, err, "a Deployment that no longer takes the password the same way is refused")
}

func TestEnsureKeycloakLogin(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: keycloakLoginSecret},
		Data:       map[string][]byte{"admin-password": []byte("kept")},
	})
	e := New(&sqlRunner{}, kube, discardLog())

	first, err := e.ensureKeycloakLogin(ctx)
	require.NoError(t, err)
	assert.Equal(t, "kept", first.AdminPassword, "a stored secret is never replaced")
	assert.Len(t, first.ServiceSecret, 32)
	assert.Len(t, first.RESTSecret, 32)
	assert.NotEqual(t, first.ServiceSecret, first.RESTSecret)

	second, err := e.ensureKeycloakLogin(ctx)
	require.NoError(t, err)
	assert.Equal(t, first, second, "a rerun reuses the generated secrets")
}

func TestEnsureSSHHostKey(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	e := New(&sqlRunner{}, kube, discardLog())

	require.NoError(t, e.ensureSSHHostKey(ctx))
	got, err := kube.CoreV1().Secrets(nicoNamespace).Get(ctx, sshHostKeySecret, metav1.GetOptions{})
	require.NoError(t, err)
	key := got.Data["ssh_host_ed25519_key"]
	assert.True(t, strings.HasPrefix(string(key), "-----BEGIN OPENSSH PRIVATE KEY-----"), "ssh-console-rs reads only the OpenSSH format")
	signer, err := ssh.ParsePrivateKey(key)
	require.NoError(t, err)
	assert.Equal(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())), string(got.Data["ssh_host_ed25519_key_pub"]))
	assert.Equal(t, prereqsRelease, got.Annotations["meta.helm.sh/release-name"], "nico-prereqs can adopt the Secret")

	require.NoError(t, e.ensureSSHHostKey(ctx))
	again, err := kube.CoreV1().Secrets(nicoNamespace).Get(ctx, sshHostKeySecret, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, key, again.Data["ssh_host_ed25519_key"], "an existing key, such as one carried from the seed, is kept")
}

// agentRunner answers kubectl logs for the site agent's pods: they log the
// connection only after connectAfterRestart restarts.
type agentRunner struct {
	mu                  sync.Mutex
	connectAfterRestart int
	restarts            int
}

func (r *agentRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.Join(args, " ")
	switch {
	case strings.Contains(line, "rollout restart"):
		r.restarts++
	case strings.Contains(line, " logs "):
		if r.restarts >= r.connectAfterRestart {
			return `{"level":"info","message":"CoreGrpcClient: Successfully connected to server"}`, nil
		}
		return `{"level":"error","message":"CoreGrpcClient: Failed to get version from server"}`, nil
	}
	return "", nil
}

func TestWaitSiteAgentConnected(t *testing.T) {
	tests := []struct {
		name                string
		connectAfterRestart int
		wantRestarts        int
		wantErr             bool
	}{
		{name: "a connected agent is left running", connectAfterRestart: 0, wantRestarts: 0},
		{name: "an agent that did not connect is restarted once", connectAfterRestart: 1, wantRestarts: 1},
		{name: "an agent that never connects fails after one restart", connectAfterRestart: 2, wantRestarts: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kube := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: restNamespace, Name: "nico-rest-site-agent-0",
				Labels: map[string]string{"app.kubernetes.io/name": siteAgentRelease},
			}})
			runner := &agentRunner{connectAfterRestart: tt.connectAfterRestart}
			e := New(runner, kube, discardLog())
			e.poll = time.Millisecond

			err := e.waitSiteAgentConnected(context.Background(), "kubeconfig", 20*time.Millisecond)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantRestarts, runner.restarts)
		})
	}
}

// recordingRunner records each command and answers it with answer, when set.
type recordingRunner struct {
	mu     sync.Mutex
	calls  []string
	answer func(args []string) (string, error)
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.mu.Unlock()
	if r.answer != nil {
		return r.answer(args)
	}
	return "", nil
}
