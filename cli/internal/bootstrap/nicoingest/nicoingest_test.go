// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

func TestExpectedMachineArgs(t *testing.T) {
	login := nicosettings.Login{Username: "root", Password: "-pa ss'word"}
	tests := []struct {
		name    string
		machine nicosettings.Machine
		want    []string
	}{
		{
			name:    "required fields only",
			machine: nicosettings.Machine{Name: "h1", BMCMAC: "aa:bb:cc:dd:ee:01", Serial: "S1", BMCLogin: "H1"},
			want: []string{
				"expected-machine", "add", "--bmc-mac-address=aa:bb:cc:dd:ee:01", "--bmc-username=root",
				"--bmc-password=-pa ss'word", "--chassis-serial-number=S1", "--meta-name=h1",
			},
		},
		{
			name: "every optional field",
			machine: nicosettings.Machine{
				Name: "h2", BMCMAC: "aa:bb:cc:dd:ee:02", Serial: "S2", BMCLogin: "H2",
				RetainBMCPassword: true, DPUPolicy: nicosettings.DPUPolicyNIC, BMCIP: "10.0.0.2",
				BootNICMAC: "aa:bb:cc:00:00:02", BootNICIP: "10.1.0.2",
				DPUs: []nicosettings.DPU{
					{Serial: "D1", BMCMAC: "aa:bb:cc:00:01:01", BMCIP: "10.2.0.1", OSMAC: "aa:bb:cc:00:02:01", OSIP: "10.3.0.1"},
					{Serial: "D2"},
				},
			},
			want: []string{
				"expected-machine", "add", "--bmc-mac-address=aa:bb:cc:dd:ee:02", "--bmc-username=root",
				"--bmc-password=-pa ss'word", "--chassis-serial-number=S2", "--meta-name=h2",
				"--bmc-retain-credentials=true", "--dpu-policy=nic", "--bmc-ip-address=10.0.0.2",
				"--fallback-dpu-serial-number=D1", "--fallback-dpu-serial-number=D2",
				`--interfaces=[{"mac_address":"aa:bb:cc:00:00:02","role":"host","fixed_ip":"10.1.0.2","primary":true,"network_segment_type":3},` +
					`{"mac_address":"aa:bb:cc:00:01:01","role":"dpu_bmc","fixed_ip":"10.2.0.1"},` +
					`{"mac_address":"aa:bb:cc:00:02:01","role":"dpu_os","fixed_ip":"10.3.0.1"}]`,
			},
		},
		{
			name:    "boot NIC without a fixed address",
			machine: nicosettings.Machine{Name: "h3", BMCMAC: "aa:bb:cc:dd:ee:03", Serial: "S3", BootNICMAC: "aa:bb:cc:00:00:03"},
			want: []string{
				"expected-machine", "add", "--bmc-mac-address=aa:bb:cc:dd:ee:03", "--bmc-username=root",
				"--bmc-password=-pa ss'word", "--chassis-serial-number=S3", "--meta-name=h3",
				`--interfaces=[{"mac_address":"aa:bb:cc:00:00:03","role":"host","primary":true,"network_segment_type":3}]`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, expectedMachineArgs(tt.machine, login))
		})
	}
}

func TestEvaluate(t *testing.T) {
	hosts := []nicosettings.Machine{
		{Name: "h1", BMCMAC: "AA:BB:CC:DD:EE:01", Serial: "S1"},
		{Name: "h2", BMCMAC: "aa:bb:cc:dd:ee:02", Serial: "S2"},
	}
	withBMC := func(mac, status string) machine {
		var m machine
		m.Metadata.BMCInfo.MAC, m.Status = mac, status
		return m
	}
	withChassis := func(serial, status string) machine {
		var m machine
		m.Metadata.DMIData.ChassisSerial, m.Status = serial, status
		return m
	}
	tests := []struct {
		name     string
		machines []machine
		want     progress
	}{
		{
			name:     "both Ready, matched by BMC MAC in any format",
			machines: []machine{withBMC("aa-bb-cc-dd-ee-01", "Ready"), withBMC("AA:BB:CC:DD:EE:02", "Ready")},
			want:     progress{ready: 2},
		},
		{
			name:     "a machine in use counts as done",
			machines: []machine{withBMC("aa:bb:cc:dd:ee:01", "InUse"), withBMC("aa:bb:cc:dd:ee:02", "Ready")},
			want:     progress{ready: 2},
		},
		{
			name:     "matched by serial when NICo reports no BMC",
			machines: []machine{{SerialNumber: "s1", Status: "Ready"}, withChassis("S2", "Ready")},
			want:     progress{ready: 2},
		},
		{
			name:     "one in Error, one not discovered",
			machines: []machine{withBMC("aa:bb:cc:dd:ee:01", "Error"), withBMC("aa:bb:cc:dd:ee:09", "Ready")},
			want:     progress{errored: []string{"h1"}, missing: []string{"h2"}},
		},
		{
			name:     "still initializing",
			machines: []machine{withBMC("aa:bb:cc:dd:ee:01", "Initializing"), withBMC("aa:bb:cc:dd:ee:02", "Ready")},
			want:     progress{ready: 1, waiting: []string{"h1 (Initializing)"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(hosts, tt.machines)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, len(tt.want.missing)+len(tt.want.errored)+len(tt.want.waiting) == 0, got.done())
		})
	}
}

const (
	rootPassword    = "root-secret"
	factoryPassword = "factory-secret"
	h1Password      = "h1-secret"
	h2Password      = "h2-secret"
)

// fakeKubectl plays kubectl against a nico-api pod: it keeps what is copied
// into the pod, runs copied scripts by answering from their content, and
// creates the certificate Secret when the Certificate is waited on.
type fakeKubectl struct {
	kube   kubernetes.Interface
	answer func(script string) (string, error)

	mu      sync.Mutex
	calls   []string
	files   map[string]string
	scripts []string
}

func (f *fakeKubectl) Run(ctx context.Context, _ string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	switch {
	case contains(args, "wait"):
		_, err := f.kube.CoreV1().Secrets(nicoNamespace).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: nicoNamespace, Name: adminCertName},
			Data:       map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY")},
		}, metav1.CreateOptions{})
		return "", err
	case contains(args, "cp"):
		src, dst := args[3], args[4]
		b, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		f.files[dst[strings.Index(dst, ":")+1:]] = string(b)
	case contains(args, "sh"):
		script := f.files[args[len(args)-1]]
		f.scripts = append(f.scripts, script)
		if f.answer != nil {
			return f.answer(script)
		}
	}
	return "", nil
}

func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func readyPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nicoNamespace,
			Name:      "nico-api-0",
			Labels:    map[string]string{"app.kubernetes.io/name": "nico-api", "app.kubernetes.io/component": "api"},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

// restServer serves a token and the machines list, answering each list with machines().
func restServer(t *testing.T, machines func() []map[string]any) *nicorest.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
		case "/v2/org/ncx/nico/machine":
			if r.Header.Get("Authorization") != "Bearer t" || r.URL.Query().Get("includeMetadata") != "true" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(machines())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return nicorest.New(srv.URL, "ncx", "nico", nicorest.ClientCredentials{TokenURL: srv.URL + "/token", ClientID: "c", ClientSecret: "s"})
}

func bmcMachine(mac, status string) map[string]any {
	return map[string]any{"status": status, "metadata": map[string]any{"bmcInfo": map[string]any{"mac": mac}}}
}

func testConfig(t *testing.T, kube kubernetes.Interface, runner CommandRunner, rest *nicorest.Client) Config {
	t.Helper()
	settings := &nicosettings.Settings{
		File: nicosettings.File{DPUFactoryModels: []string{"bf3"}, Machines: []nicosettings.Machine{
			{Name: "h1", BMCMAC: "aa:bb:cc:dd:ee:01", Serial: "S1", BMCLogin: "H1"},
			{Name: "h2", BMCMAC: "aa:bb:cc:dd:ee:02", Serial: "S2", BMCLogin: "H2"},
		}},
		SiteConfig: nicosettings.SiteConfig{AttestationEnabled: true},
	}
	return Config{
		Kubeconfig: "/kubeconfig",
		Settings:   settings,
		Secrets: nicosettings.Secrets{
			SiteWideBMCRootPassword: rootPassword,
			DPUBMCFactoryUsername:   "root",
			DPUBMCFactoryPassword:   factoryPassword,
			BMCLogins:               map[string]nicosettings.Login{"H1": {Username: "admin", Password: h1Password}, "H2": {Username: "admin", Password: h2Password}},
		},
		REST:    rest,
		Runner:  runner,
		Kube:    kube,
		Timeout: 5 * time.Second,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestRun(t *testing.T) {
	pollInterval = 10 * time.Millisecond
	kube := fake.NewClientset(readyPod())
	runner := &fakeKubectl{kube: kube, files: map[string]string{}, answer: func(script string) (string, error) {
		switch {
		case strings.Contains(script, "'--meta-name=h2'"):
			// A rerun: NICo already has h2.
			return "Error: duplicate MAC address for expected host BMC interface: aa:bb:cc:dd:ee:02", errors.New("exit status 1")
		case strings.Contains(script, "trusted-machine"):
			return "duplicate key value violates unique constraint", errors.New("exit status 1")
		}
		return "", nil
	}}
	polls := 0
	rest := restServer(t, func() []map[string]any {
		polls++
		if polls == 1 {
			return []map[string]any{bmcMachine("aa:bb:cc:dd:ee:01", "Initializing")}
		}
		return []map[string]any{bmcMachine("aa:bb:cc:dd:ee:01", "Ready"), bmcMachine("aa:bb:cc:dd:ee:02", "Ready")}
	})

	require.NoError(t, Run(context.Background(), testConfig(t, kube, runner, rest)))

	require.Len(t, runner.scripts, 5)
	for i, want := range []string{
		"'credential' 'add-bmc' '--kind=site-wide-root' '--password=" + rootPassword + "'",
		"'credential' 'add-dpu-factory-default' '--model=bf3' '--username=root' '--password=" + factoryPassword + "'",
		"'expected-machine' 'add' '--bmc-mac-address=aa:bb:cc:dd:ee:01'",
		"'expected-machine' 'add' '--bmc-mac-address=aa:bb:cc:dd:ee:02'",
		"'attestation' 'measured-boot' 'site' 'trusted-machine' 'approve' '*' 'persist' '--pcr-registers=0,3,5,6'",
	} {
		assert.Contains(t, runner.scripts[i], want)
		assert.True(t, strings.HasPrefix(runner.scripts[i], "rm -f -- \"$0\"\nexec '/opt/carbide/nico-admin-cli' '--api-url="+adminCLIAPI+"'"))
	}
	for _, call := range runner.calls {
		for _, secret := range []string{rootPassword, factoryPassword, h1Password, h2Password} {
			assert.NotContains(t, call, secret, "a secret reached kubectl's command line")
		}
	}
	last := runner.calls[len(runner.calls)-2:]
	assert.Contains(t, last[0], "exec nico-api-0 -c nico-api -- rm -rf /tmp/nvkectl-nico-admin-")
	assert.Contains(t, last[1], "delete certificate.cert-manager.io "+adminCertName)
	_, err := kube.CoreV1().Secrets(nicoNamespace).Get(context.Background(), adminCertName, metav1.GetOptions{})
	assert.True(t, err != nil, "the admin certificate Secret is deleted")
}

func TestRunRedactsSecrets(t *testing.T) {
	kube := fake.NewClientset(readyPod())
	runner := &fakeKubectl{kube: kube, files: map[string]string{}, answer: func(script string) (string, error) {
		if strings.Contains(script, "'--meta-name=h1'") {
			return "Error: login admin/" + h1Password + " rejected", errors.New("exit status 1")
		}
		return "", nil
	}}
	rest := restServer(t, func() []map[string]any { return nil })

	err := Run(context.Background(), testConfig(t, kube, runner, rest))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "adding expected machine h1")
	assert.Contains(t, err.Error(), "<redacted>")
	assert.NotContains(t, err.Error(), h1Password)
	assert.Contains(t, runner.calls[len(runner.calls)-1], "delete certificate.cert-manager.io", "the certificate is removed after a failure")
}

func TestRunTimesOutNamingMachines(t *testing.T) {
	pollInterval = 10 * time.Millisecond
	kube := fake.NewClientset(readyPod())
	runner := &fakeKubectl{kube: kube, files: map[string]string{}}
	rest := restServer(t, func() []map[string]any {
		return []map[string]any{bmcMachine("aa:bb:cc:dd:ee:01", "Error")}
	})
	cfg := testConfig(t, kube, runner, rest)
	cfg.Timeout = 100 * time.Millisecond

	err := Run(context.Background(), cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Contains(t, err.Error(), "in Error: h1")
	assert.Contains(t, err.Error(), "not discovered: h2")
}

func TestRunWithoutReadyPod(t *testing.T) {
	kube := fake.NewClientset()
	runner := &fakeKubectl{kube: kube, files: map[string]string{}}
	rest := restServer(t, func() []map[string]any { return nil })

	err := Run(context.Background(), testConfig(t, kube, runner, rest))

	require.ErrorContains(t, err, "no nico-api pod")
	assert.Empty(t, runner.scripts)
}
