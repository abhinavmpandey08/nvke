// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicomove

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicodeploy"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

const siteID = "6f1c2a52-3c0e-4b4e-9b4f-0d3c9b8d6a11"

// fakeEngine records what Run does to one cluster, in one log shared by both.
type fakeEngine struct {
	name  string
	log   *[]string
	fail  string
	busy  int // RunningWorkflows answers busy for this many calls
	state []nicodeploy.SiteState
	reads int
	// stopped is what Stopped answers; rootToken is the token VaultKeys
	// returns, "example-token" when empty.
	stopped   bool
	rootToken string
	// prepared is the Config PrepareSite was given.
	prepared nicodeploy.Config
}

func (f *fakeEngine) record(call string) error {
	*f.log = append(*f.log, f.name+" "+call)
	if call == f.fail {
		return errors.New(call + " failed")
	}
	return nil
}

func (f *fakeEngine) ReadCarried(context.Context) (nicodeploy.Carried, error) {
	tls := func(name string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Data:       map[string][]byte{corev1.TLSCertKey: []byte(name + "-crt"), corev1.TLSPrivateKeyKey: []byte(name + "-key")},
		}
	}
	return nicodeploy.Carried{
		SiteRoot: tls("site-root"), RESTCA: tls("ca-signing-secret"),
		KeycloakLogin: &corev1.Secret{Data: map[string][]byte{"admin-password": []byte("example-password")}},
	}, f.record("ReadCarried")
}

func (f *fakeEngine) VaultKeys(context.Context) (nicodeploy.VaultKeys, error) {
	token := f.rootToken
	if token == "" {
		token = "example-token"
	}
	return nicodeploy.VaultKeys{UnsealKeysB64: []string{"k0", "k1", "k2"}, RootToken: token}, f.record("VaultKeys")
}

func (f *fakeEngine) PrepareSite(_ context.Context, _, _ string, cfg nicodeploy.Config, _ nicodeploy.Carried, _ string) error {
	f.prepared = cfg
	return f.record("PrepareSite")
}

func (f *fakeEngine) ScaleRESTAPI(_ context.Context, replicas int) error {
	return f.record("ScaleRESTAPI " + map[bool]string{true: "0", false: "up"}[replicas == 0])
}

func (f *fakeEngine) RunningWorkflows(_ context.Context, _, namespace string) ([]string, error) {
	if namespace != "cloud" {
		return nil, nil
	}
	if f.busy > 0 {
		f.busy--
		return []string{"create-instance"}, nil
	}
	return nil, f.record("RunningWorkflows idle")
}

func (f *fakeEngine) StopNICo(context.Context) error { return f.record("StopNICo") }

func (f *fakeEngine) Stopped(context.Context) (bool, error) { return f.stopped, nil }

func (f *fakeEngine) DumpDatabase(_ context.Context, _, database, path string) error {
	if err := os.WriteFile(path, []byte("PGDMP"), 0o600); err != nil {
		return err
	}
	return f.record("DumpDatabase " + database)
}

func (f *fakeEngine) RestoreDatabase(_ context.Context, _, database, _ string) error {
	return f.record("RestoreDatabase " + database)
}

func (f *fakeEngine) SnapshotVault(_ context.Context, _, path string) error {
	if err := os.WriteFile(path, []byte("snapshot"), 0o600); err != nil {
		return err
	}
	return f.record("SnapshotVault")
}

func (f *fakeEngine) RestoreVault(context.Context, string, string, nicodeploy.Config, string, nicodeploy.VaultKeys) error {
	return f.record("RestoreVault")
}

func (f *fakeEngine) SiteState(context.Context, string, string) (nicodeploy.SiteState, error) {
	s := f.state[min(f.reads, len(f.state)-1)]
	f.reads++
	return s, nil
}

func (f *fakeEngine) PublishSite(context.Context, nicodeploy.Config) error {
	return f.record("PublishSite")
}

func (f *fakeEngine) StartSite(context.Context, string, string, nicodeploy.Config, string) (*nicodeploy.Installed, error) {
	return &nicodeploy.Installed{SiteID: siteID, RESTEndpoint: "http://10.0.0.88:8388"}, f.record("StartSite")
}

func (f *fakeEngine) WriteHelmValues(_ context.Context, _, dir string) error {
	return os.WriteFile(filepath.Join(dir, "nico.yaml"), []byte("global: {}\n"), 0o600)
}

func testMover(t *testing.T, failOn string, before, after nicodeploy.SiteState) (*mover, *[]string) {
	t.Helper()
	inputs := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(inputs, name)
		require.NoError(t, os.WriteFile(p, []byte(name), 0o644))
		return p
	}
	settings := &nicosettings.Settings{Path: write("nico.yaml"), HandoverDir: filepath.Join(t.TempDir(), "handover")}
	two := int32(2)
	siteKube := fake.NewClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: capnicoNamespace, Name: capnicoDeployment},
		Spec:       appsv1.DeploymentSpec{Replicas: &two},
		Status:     appsv1.DeploymentStatus{AvailableReplicas: 1},
	})
	log := &[]string{}
	cfg := Config{
		SeedKubeconfig: "seed", SiteKubeconfig: "site", Root: "/src", SiteID: siteID,
		Site:     nicodeploy.Config{Settings: settings, CoreImageTag: "v2.2.2", RestImageTag: "v2.2.2"},
		SeedKube: fake.NewClientset(), SiteKube: siteKube,
		RemoveHostAddresses: func(context.Context) error { *log = append(*log, "host RemoveHostAddresses"); return nil },
	}
	seed := &fakeEngine{name: "seed", log: log, fail: failOn, busy: 2}
	site := &fakeEngine{name: "site", log: log, fail: failOn, state: []nicodeploy.SiteState{before, before, after}, rootToken: "site-token"}
	return &mover{
		cfg: cfg, seed: seed, site: site, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		poll: time.Millisecond, timeout: 200 * time.Millisecond,
		now: func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC) },
	}, log
}

func states() (before, after nicodeploy.SiteState) {
	before = nicodeploy.SiteState{InventoryReceived: time.Unix(100, 0), Machines: map[string]string{"m1": "InUse", "m2": "Ready", "m3": "Error"}}
	after = nicodeploy.SiteState{InventoryReceived: time.Unix(200, 0), Machines: map[string]string{"m1": "InUse", "m2": "Ready", "m3": "Error"}}
	return before, after
}

func TestRunOrder(t *testing.T) {
	before, after := states()
	m, log := testMover(t, "", before, after)
	inst, err := m.run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, siteID, inst.SiteID)

	assert.Equal(t, []string{
		"seed ReadCarried",
		"seed VaultKeys",
		"site PrepareSite",
		"seed ScaleRESTAPI 0",
		"seed RunningWorkflows idle",
		"seed StopNICo",
		"seed DumpDatabase nico_system_nico",
		"site RestoreDatabase nico_system_nico",
		"seed DumpDatabase nico_rest",
		"site RestoreDatabase nico_rest",
		"seed DumpDatabase keycloak",
		"site RestoreDatabase keycloak",
		"seed SnapshotVault",
		"site RestoreVault",
		"host RemoveHostAddresses",
		"site PublishSite",
		"site StartSite",
	}, *log)

	ctx := context.Background()
	restored := m.site.(*fakeEngine).prepared.RestoredVaultKeys
	require.NotNil(t, restored, "the site may open its Vault with the bootstrap cluster's keys")
	assert.Equal(t, "example-token", restored.RootToken)
	_, err = m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(ctx, stateMovedConfigMap, metav1.GetOptions{})
	require.NoError(t, err, "the site records that the databases and Vault moved")
	capnico, err := m.cfg.SiteKube.AppsV1().Deployments(capnicoNamespace).Get(ctx, capnicoDeployment, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), *capnico.Spec.Replicas, "CAPNICo runs again, with the replicas it had")

	dir := m.cfg.Site.Settings.HandoverDir
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	for _, f := range []string{
		"databases/nico_system_nico.dump", "databases/nico_rest.dump", "databases/keycloak.dump", "vault.snap",
		"inputs/settings.yaml", "helm-values/nico.yaml",
		"versions.yaml", "vault-keys.json", "site-root.crt", "site-root.key", "rest-ca.crt", "rest-ca.key", "keycloak-admin.yaml",
	} {
		info, err := os.Stat(filepath.Join(dir, f))
		require.NoError(t, err, f)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), f)
	}
	settings, err := os.ReadFile(filepath.Join(dir, "inputs", "settings.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "nico.yaml", string(settings))
	versions, err := os.ReadFile(filepath.Join(dir, "versions.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(versions), "version: v2.2.2")
	assert.Contains(t, string(versions), "postgres-operator")

	cm, err := m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(ctx, handoverConfigMap, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "v2.2.2", cm.Data["nicoVersion"])
	assert.Equal(t, "2026-11-03T00:00:00Z", cm.Data["handedOverAt"])
}

func TestRunKeepsAnEarlierBundle(t *testing.T) {
	before, after := states()
	m, _ := testMover(t, "", before, after)
	dir := m.cfg.Site.Settings.HandoverDir
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, nicosettings.HandoverVaultKeysFile), []byte("earlier"), 0o600))

	_, err := m.run(context.Background())
	require.ErrorIs(t, err, os.ErrExist)
	keys, err := os.ReadFile(filepath.Join(dir, nicosettings.HandoverVaultKeysFile))
	require.NoError(t, err)
	assert.Equal(t, "earlier", string(keys), "an earlier bundle's Vault keys are never overwritten")
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "a directory that existed keeps its mode")
}

func TestRunStopsAtTheFirstFailure(t *testing.T) {
	before, after := states()
	m, log := testMover(t, "RestoreVault", before, after)
	_, err := m.run(context.Background())
	require.ErrorContains(t, err, "RestoreVault failed")
	assert.Equal(t, "site RestoreVault", (*log)[len(*log)-1], "nothing after the failed step runs")
	assert.NotContains(t, *log, "host RemoveHostAddresses", "the addresses stay with the bootstrap cluster")

	capnico, err := m.cfg.SiteKube.AppsV1().Deployments(capnicoNamespace).Get(context.Background(), capnicoDeployment, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, int32(0), *capnico.Spec.Replicas, "CAPNICo starts no work against a NICo that is not moved")
	_, err = m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(context.Background(), handoverConfigMap, metav1.GetOptions{})
	assert.Error(t, err, "the site is not marked handed over")
	_, err = m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(context.Background(), stateMovedConfigMap, metav1.GetOptions{})
	assert.Error(t, err, "a Vault restore that failed is not recorded as moved")
}

func TestVerify(t *testing.T) {
	before, after := states()
	tests := []struct {
		name    string
		after   nicodeploy.SiteState
		wantErr string
	}{
		{name: "inventory moved forward and machines kept their status", after: after},
		{
			name:    "no inventory since the move",
			after:   nicodeploy.SiteState{InventoryReceived: before.InventoryReceived, Machines: after.Machines},
			wantErr: "inventory",
		},
		{
			name: "a machine that was usable is not",
			after: nicodeploy.SiteState{
				InventoryReceived: after.InventoryReceived,
				Machines:          map[string]string{"m1": "InUse", "m2": "Error"},
			},
			wantErr: "m2 (Error)",
		},
		{
			name:    "a machine that was usable is gone",
			after:   nicodeploy.SiteState{InventoryReceived: after.InventoryReceived, Machines: map[string]string{"m2": "Ready"}},
			wantErr: "m1 (missing)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := testMover(t, "", before, tt.after)
			m.site.(*fakeEngine).state = []nicodeploy.SiteState{tt.after}
			err := m.verify(context.Background(), before)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestDrainNamesWhatStillRuns(t *testing.T) {
	before, after := states()
	m, _ := testMover(t, "", before, after)
	m.seed.(*fakeEngine).busy = 1 << 30
	err := m.drain(context.Background())
	assert.ErrorContains(t, err, "cloud/create-instance")
}

func TestRunValidatesConfig(t *testing.T) {
	_, err := Run(context.Background(), Config{SeedKubeconfig: "seed"})
	assert.Error(t, err)
}

func TestRunResumes(t *testing.T) {
	before, after := states()
	moveState := []string{
		"seed DumpDatabase nico_system_nico", "site RestoreDatabase nico_system_nico",
		"seed DumpDatabase nico_rest", "site RestoreDatabase nico_rest",
		"seed DumpDatabase keycloak", "site RestoreDatabase keycloak",
		"seed SnapshotVault", "site RestoreVault",
	}
	stop := []string{"seed ScaleRESTAPI 0", "seed RunningWorkflows idle", "seed StopNICo"}
	tests := []struct {
		name string
		// prepare sets up what an earlier run left.
		prepare  func(t *testing.T, m *mover)
		wantNone bool
		skipped  []string
		ran      []string
	}{
		{
			name: "the site is already handed over",
			prepare: func(t *testing.T, m *mover) {
				_, err := m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Create(context.Background(),
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: handoverNamespace, Name: handoverConfigMap}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			wantNone: true,
		},
		{
			name:    "the bootstrap cluster's NICo is already stopped",
			prepare: func(_ *testing.T, m *mover) { m.seed.(*fakeEngine).stopped = true },
			skipped: stop,
			ran:     append([]string{"site PrepareSite"}, moveState...),
		},
		{
			name: "the databases and Vault are already moved",
			prepare: func(t *testing.T, m *mover) {
				m.seed.(*fakeEngine).stopped = true
				_, err := m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Create(context.Background(),
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: handoverNamespace, Name: stateMovedConfigMap}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			skipped: append(slices.Clone(stop), moveState...),
			ran:     []string{"site PrepareSite", "host RemoveHostAddresses", "site PublishSite", "site StartSite"},
		},
		{
			// The site's Vault holds the bootstrap cluster's keys, but the restore stopped before restarting Vault.
			name: "the Vault restore stopped after storing the keys",
			prepare: func(_ *testing.T, m *mover) {
				m.seed.(*fakeEngine).stopped = true
				m.site.(*fakeEngine).rootToken = "example-token"
			},
			skipped: stop,
			ran:     append([]string{"site PrepareSite"}, moveState...),
		},
		{
			name: "the handover bundle was partly written",
			prepare: func(t *testing.T, m *mover) {
				m.cfg.Resume = true
				dir := m.cfg.Site.Settings.HandoverDir
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "inputs"), 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(dir, nicosettings.HandoverVaultKeysFile), []byte("cut sh"), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "inputs", "settings.yaml"), []byte("cut"), 0o600))
			},
			ran: append(append([]string{"site PrepareSite"}, stop...), moveState...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, log := testMover(t, "", before, after)
			tt.prepare(t, m)
			_, err := m.run(context.Background())
			require.NoError(t, err)
			if tt.wantNone {
				assert.Empty(t, *log, "a handed-over NICo is left as it is")
				return
			}
			for _, call := range tt.skipped {
				assert.NotContains(t, *log, call)
			}
			for _, call := range tt.ran {
				assert.Contains(t, *log, call)
			}
			dir := m.cfg.Site.Settings.HandoverDir
			keys, err := os.ReadFile(filepath.Join(dir, nicosettings.HandoverVaultKeysFile))
			require.NoError(t, err)
			assert.Contains(t, string(keys), "example-token", "the bundle holds the bootstrap cluster's Vault keys")
			_, err = m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(context.Background(), handoverConfigMap, metav1.GetOptions{})
			assert.NoError(t, err, "the site is marked handed over")
		})
	}
}
