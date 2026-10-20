// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pivot

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/spirehandover"
	api "github.com/dsx-ai-factory/nvke/controller/api"
)

const vip = "192.0.2.10"

// fakeRunner answers kubectl and clusterctl calls by the first rule whose
// substring the command line contains, and records every call.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	rules []rule
}

type rule struct {
	match string
	out   func() (string, error)
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, line)
	rules := r.rules
	r.mu.Unlock()
	for _, rl := range rules {
		if strings.Contains(line, rl.match) {
			return rl.out()
		}
	}
	return "", nil
}

func (r *fakeRunner) on(match, out string) {
	r.rules = append(r.rules, rule{match, func() (string, error) { return out, nil }})
}

// index returns the position of the first call containing match, or -1.
func (r *fakeRunner) index(match string) int {
	for i, c := range r.calls {
		if strings.Contains(c, match) {
			return i
		}
	}
	return -1
}

func deployment(ns, name, image string, annotations map[string]string) *appsv1.Deployment {
	one := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: image}}}},
		},
	}
}

func clusterObjects(extra ...runtime.Object) []runtime.Object {
	return append([]runtime.Object{
		deployment(controllerNamespace, controllerName, "controller:1", nil),
		deployment("capi-system", "capi-controller-manager", "capi:1", nil),
		deployment("capnico-system", "controller-manager", "capnico:1", nil),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: postgresNamespace, Name: "postgres-0",
				Labels: map[string]string{"app.kubernetes.io/name": "postgresql"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: spireNamespace, Name: spireExternalSvc},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{NodePort: 30440}}},
		},
	}, extra...)
}

type fixture struct {
	p      *pivot
	runner *fakeRunner
	seed   *fake.Clientset
	site   *fake.Clientset
	// handedOver records the SPIRE handover's config.
	handedOver *spirehandover.Config
}

func newFixture(t *testing.T, seedObjs, siteObjs []runtime.Object) *fixture {
	t.Helper()
	f := &fixture{runner: &fakeRunner{}, seed: fake.NewClientset(seedObjs...), site: fake.NewClientset(siteObjs...)}
	f.p = newPivot(Config{
		ClusterName: "site", SiteSpireAddress: vip, PollInterval: time.Millisecond,
		Runner: f.runner, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	},
		&cluster{name: "seed", kubeconfig: "seed.kubeconfig", kube: f.seed},
		&cluster{name: "site", kubeconfig: "site.kubeconfig", kube: f.site})
	f.p.handover = func(_ context.Context, cfg spirehandover.Config) error {
		f.handedOver = &cfg
		return nil
	}
	return f
}

// happyPath makes every check answer as on a cluster ready to pivot.
func (f *fixture) happyPath() {
	moved := false
	f.runner.rules = append(f.runner.rules,
		rule{"workflow_outbox", func() (string, error) { return "0", nil }},
		rule{"temporal workflow count", func() (string, error) { return "Total: 0", nil }},
		rule{"clusterctl move", func() (string, error) { moved = true; return "", nil }},
		rule{"seed.kubeconfig -n nvke-system get clusters.cluster.x-k8s.io --ignore-not-found", func() (string, error) {
			if moved {
				return "", nil
			}
			return "cluster.cluster.x-k8s.io/site", nil
		}},
		rule{"get machines.cluster.x-k8s.io", func() (string, error) { return "site-cp-a=site-cp-a\n", nil }},
		rule{"ControlPlaneInitialized", func() (string, error) { return "True", nil }},
		rule{"get crd", func() (string, error) {
			return "customresourcedefinition.apiextensions.k8s.io/nicomachines.infrastructure.cluster.x-k8s.io\n" +
				"customresourcedefinition.apiextensions.k8s.io/machines.cluster.x-k8s.io", nil
		}},
	)
	restored := false
	f.runner.rules = append(f.runner.rules,
		rule{"pg_restore", func() (string, error) { restored = true; return "", nil }},
		rule{"seed.kubeconfig -n postgres exec postgres-0 -- psql", func() (string, error) { return "cluster a\nnode b", nil }},
		rule{"site.kubeconfig -n postgres exec postgres-0 -- psql", func() (string, error) {
			if restored {
				return "cluster a\nnode b", nil
			}
			return "", nil
		}},
		rule{"get --raw", func() (string, error) {
			addr := vip
			b, _ := json.Marshal(api.ClusterSpireServerStatus{Nodes: []api.NodeSpireAgentStatus{
				{Name: "n1", Reachable: true, HasValidSVID: true, ServerAddress: &addr},
			}})
			return string(b), nil
		}},
	)
}

func TestRunPivotsInOrder(t *testing.T) {
	etcdKey := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: controllerNamespace, Name: etcdKeyPrefix + "x"},
		Data:       map[string][]byte{"active": []byte("k")},
	}
	f := newFixture(t, clusterObjects(etcdKey), clusterObjects())
	f.happyPath()

	require.NoError(t, f.p.run(context.Background()))

	require.NotNil(t, f.handedOver)
	require.Equal(t, vip, f.handedOver.SiteSpireAddress)
	require.Equal(t, 30440, f.handedOver.SiteSpirePort)

	order := []string{
		"site.kubeconfig -n nke-controller scale deployment nke-controller --replicas=0",
		"seed.kubeconfig -n nke-controller scale deployment nke-controller --replicas=0",
		"label customresourcedefinition.apiextensions.k8s.io/nicomachines.infrastructure.cluster.x-k8s.io",
		"clusterctl move --kubeconfig seed.kubeconfig --to-kubeconfig site.kubeconfig --namespace nvke-system",
		"pg_dump",
		"pg_restore",
		"site.kubeconfig -n nke-controller scale deployment nke-controller --replicas=1",
		"get --raw",
	}
	last := -1
	for _, call := range order {
		i := f.runner.index(call)
		require.Greater(t, i, last, "%q out of order in %v", call, f.runner.calls)
		last = i
	}
	require.Equal(t, -1, f.runner.index("label customresourcedefinition.apiextensions.k8s.io/machines.cluster"),
		"only infrastructure CRDs are labelled")

	copied, err := f.site.CoreV1().Secrets(controllerNamespace).Get(context.Background(), etcdKeyPrefix+"x", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []byte("k"), copied.Data["active"])
}

func TestQuiesceSeedFailsWhenWorkArrivesWhileStopping(t *testing.T) {
	f := newFixture(t, clusterObjects(), clusterObjects())
	stopped := false
	f.runner.rules = append(f.runner.rules,
		rule{"scale deployment nke-controller --replicas=0", func() (string, error) { stopped = true; return "", nil }},
		rule{"workflow_outbox", func() (string, error) {
			if stopped {
				return "1", nil
			}
			return "0", nil
		}},
		rule{"temporal workflow count", func() (string, error) { return "Total: 0", nil }},
	)
	require.ErrorContains(t, f.p.quiesceSeed(context.Background()), "took on work while stopping (1 queued, 0 running)")
}

func TestMoveCAPI(t *testing.T) {
	t.Run("skips when the site already holds the cluster", func(t *testing.T) {
		f := newFixture(t, clusterObjects(), clusterObjects())
		f.runner.on("site.kubeconfig -n nvke-system get clusters.cluster.x-k8s.io --ignore-not-found", "cluster.cluster.x-k8s.io/site")
		require.NoError(t, f.p.moveCAPI(context.Background()))
		require.Equal(t, -1, f.runner.index("clusterctl move"))
	})
	t.Run("waits until every Machine has a node", func(t *testing.T) {
		f := newFixture(t, clusterObjects(), clusterObjects())
		f.runner.on("seed.kubeconfig -n nvke-system get clusters.cluster.x-k8s.io --ignore-not-found", "cluster.cluster.x-k8s.io/site")
		polls := 0
		f.runner.rules = append(f.runner.rules,
			rule{"get machines.cluster.x-k8s.io", func() (string, error) {
				polls++
				if polls < 3 {
					return "site-cp-a=site-cp-a\nsite-cp-b=\n", nil
				}
				return "site-cp-a=site-cp-a\nsite-cp-b=site-cp-b\n", nil
			}},
			rule{"ControlPlaneInitialized", func() (string, error) { return "True", nil }},
		)
		require.NoError(t, f.p.moveCAPI(context.Background()))
		require.Equal(t, 3, polls)
		require.NotEqual(t, -1, f.runner.index("clusterctl move"))
	})
	t.Run("does not move before the control plane is initialized", func(t *testing.T) {
		f := newFixture(t, clusterObjects(), clusterObjects())
		f.p.cfg.PollInterval = time.Millisecond
		f.runner.on("seed.kubeconfig -n nvke-system get clusters.cluster.x-k8s.io --ignore-not-found", "cluster.cluster.x-k8s.io/site")
		f.runner.on("get machines.cluster.x-k8s.io", "site-cp-a=site-cp-a\n")
		f.runner.on("ControlPlaneInitialized", "False")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		require.ErrorContains(t, f.p.moveCAPI(ctx), "control plane")
		require.Equal(t, -1, f.runner.index("clusterctl move"))
	})
	t.Run("refuses different provider versions", func(t *testing.T) {
		f := newFixture(t, clusterObjects(),
			[]runtime.Object{
				deployment("capi-system", "capi-controller-manager", "capi:1", nil),
				deployment("capnico-system", "controller-manager", "capnico:2", nil),
			})
		f.runner.on("seed.kubeconfig -n nvke-system get clusters.cluster.x-k8s.io --ignore-not-found", "cluster.cluster.x-k8s.io/site")
		require.ErrorContains(t, f.p.moveCAPI(context.Background()), "capnico:1 on the seed but capnico:2 on the site")
		require.Equal(t, -1, f.runner.index("clusterctl move"))
	})
}

func TestMoveDatabase(t *testing.T) {
	t.Run("skips when the site holds the seed's records", func(t *testing.T) {
		f := newFixture(t, clusterObjects(), clusterObjects())
		f.runner.on("psql", "cluster a")
		require.NoError(t, f.p.moveDatabase(context.Background()))
		require.Equal(t, -1, f.runner.index("pg_dump"))
	})
	t.Run("fails when the restore does not match", func(t *testing.T) {
		f := newFixture(t, clusterObjects(), clusterObjects())
		f.runner.on("seed.kubeconfig -n postgres exec postgres-0 -- psql", "cluster a")
		f.runner.on("site.kubeconfig -n postgres exec postgres-0 -- psql", "")
		require.ErrorContains(t, f.p.moveDatabase(context.Background()), "after the restore")
		require.NotEqual(t, -1, f.runner.index("rm -f "+dumpPath), "the dumps are removed")
	})
}

func TestSpireHandoverSkipsOnceTheSeedIsQuiesced(t *testing.T) {
	stopped := deployment(controllerNamespace, controllerName, "controller:1", nil)
	zero := int32(0)
	stopped.Spec.Replicas = &zero
	f := newFixture(t, []runtime.Object{stopped}, clusterObjects())
	require.NoError(t, f.p.spireHandover(context.Background()))
	require.Nil(t, f.handedOver)
}

func TestActivateSiteRestoresRecordedReplicas(t *testing.T) {
	site := deployment(controllerNamespace, controllerName, "controller:1", map[string]string{replicasAnnotation: "3"})
	f := newFixture(t, clusterObjects(), []runtime.Object{site})
	require.NoError(t, f.p.activateSite(context.Background()))
	require.NotEqual(t, -1, f.runner.index("scale deployment nke-controller --replicas=3"))
}

func TestVerifyListsNodesNotOnTheSite(t *testing.T) {
	f := newFixture(t, clusterObjects(), clusterObjects())
	other := "198.51.100.1"
	b, err := json.Marshal(api.ClusterSpireServerStatus{Nodes: []api.NodeSpireAgentStatus{
		{Name: "n1", Reachable: true, HasValidSVID: true, ServerAddress: &other},
	}})
	require.NoError(t, err)
	f.runner.on("get --raw", string(b))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorContains(t, f.p.verify(ctx), "n1")
}
