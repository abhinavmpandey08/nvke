// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pivot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/spirehandover"
	api "github.com/dsx-ai-factory/nvke/controller/api"
)

// Where the NVKE stack runs, on the seed as controllerdeploy installs it and
// on the site, which is installed the same way.
const (
	controllerNamespace = "nke-controller"
	controllerName      = "nke-controller"
	postgresNamespace   = "postgres"
	postgresSelector    = "app.kubernetes.io/name=postgresql"
	databaseName        = "nke-controller"
	temporalNamespace   = "temporal"
	temporalNSName      = "cloud-workflow-engine"
	spireNamespace      = "spire-server"
	spireExternalSvc    = "spire-server-external"
	managementNamespace = "nvke-system"
	etcdKeyPrefix       = "etcd-encryption-key-"
	clusterNameLabel    = "cluster.x-k8s.io/cluster-name"
	clusterctlLabel     = "clusterctl.cluster.x-k8s.io"
	infraCRDSuffix      = ".infrastructure.cluster.x-k8s.io"
	dumpPath            = "/tmp/nvke-pivot.dump"
	// replicasAnnotation records the site controller's replicas while the pivot holds it at zero.
	replicasAnnotation = "nvke.nvidia.com/pivot-replicas"
)

// providerDeployments must run the same image on both clusters for clusterctl move.
var providerDeployments = [][2]string{
	{"capi-system", "capi-controller-manager"},
	{"capnico-system", "controller-manager"},
}

// stopSiteController holds the site controller at zero replicas until activateSite,
// so it acts on nothing before its database is restored.
func (p *pivot) stopSiteController(ctx context.Context) error {
	deploys := p.site.kube.AppsV1().Deployments(controllerNamespace)
	d, err := deploys.Get(ctx, controllerName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if _, ok := d.Annotations[replicasAnnotation]; !ok {
		replicas := int32(1)
		if d.Spec.Replicas != nil && *d.Spec.Replicas > 0 {
			replicas = *d.Spec.Replicas
		}
		patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, replicasAnnotation, strconv.Itoa(int(replicas)))
		if _, err := p.kubectl(ctx, p.site, "-n", controllerNamespace, "patch", "deployment", controllerName,
			"--type=merge", "-p", patch); err != nil {
			return err
		}
	}
	return p.stopController(ctx, p.site)
}

// stopController scales c's NVKE controller to zero and waits for its pods to go.
func (p *pivot) stopController(ctx context.Context, c *cluster) error {
	if _, err := p.kubectl(ctx, c, "-n", controllerNamespace, "scale", "deployment", controllerName, "--replicas=0"); err != nil {
		return err
	}
	return p.poll(ctx, c.name+" controller pods to stop", defaultQuiesceTimeout, func(ctx context.Context) (bool, error) {
		d, err := c.kube.AppsV1().Deployments(controllerNamespace).Get(ctx, controllerName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return d.Status.Replicas == 0, nil
	})
}

// spireHandover hands node identity to the site SPIRE server and repoints every node at it.
func (p *pivot) spireHandover(ctx context.Context) error {
	// quiesceSeed stops the seed controller only after the handover is done,
	// and the handover's repoint needs that controller.
	d, err := p.seed.kube.AppsV1().Deployments(controllerNamespace).Get(ctx, controllerName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if d.Spec.Replicas != nil && *d.Spec.Replicas == 0 {
		p.log.Info("the seed controller is already stopped, so the SPIRE handover is done")
		return nil
	}
	svc, err := p.site.kube.CoreV1().Services(spireNamespace).Get(ctx, spireExternalSvc, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if len(svc.Spec.Ports) == 0 || svc.Spec.Ports[0].NodePort == 0 {
		return fmt.Errorf("site service %s/%s has no node port", spireNamespace, spireExternalSvc)
	}
	return p.handover(ctx, spirehandover.Config{
		SeedKubeconfig:   p.seed.kubeconfig,
		SiteKubeconfig:   p.site.kubeconfig,
		Controller:       p.cfg.Controller,
		ClusterID:        p.cfg.ClusterID,
		SiteSpireAddress: p.cfg.SiteSpireAddress,
		SiteSpirePort:    int(svc.Spec.Ports[0].NodePort),
		PollInterval:     p.cfg.PollInterval,
		Runner:           p.runner,
		Logger:           p.log,
	})
}

// quiesceSeed waits until the seed controller has no queued or running
// workflow, then stops it. Temporal's history stays on the seed, so nothing
// may be in flight when the database moves.
func (p *pivot) quiesceSeed(ctx context.Context) error {
	var busy string
	if err := p.poll(ctx, "the seed controller to finish its workflows", defaultQuiesceTimeout, func(ctx context.Context) (bool, error) {
		var err error
		busy, err = p.seedBusy(ctx)
		if err != nil {
			return false, err
		}
		if busy != "" {
			p.log.Info("waiting for the seed controller to go idle", "busy", busy)
		}
		return busy == "", nil
	}); err != nil {
		return fmt.Errorf("%w: %s", err, busy)
	}
	if err := p.stopController(ctx, p.seed); err != nil {
		return err
	}
	// Work queued between the check and the stop would be stranded on the seed.
	busy, err := p.seedBusy(ctx)
	if err != nil {
		return err
	}
	if busy != "" {
		return fmt.Errorf("the seed controller took on work while stopping (%s); scale %s/%s on the seed back up, "+
			"let it finish, and re-run", busy, controllerNamespace, controllerName)
	}
	return nil
}

// seedBusy describes the seed controller's queued and running workflows, or returns "" when it has none.
func (p *pivot) seedBusy(ctx context.Context) (string, error) {
	queued, err := p.psql(ctx, p.seed, "SELECT count(*) FROM workflow_outbox WHERE processed_at IS NULL")
	if err != nil {
		return "", err
	}
	out, err := p.kubectl(ctx, p.seed, "-n", temporalNamespace, "exec", "deploy/temporal-admintools", "--",
		"temporal", "workflow", "count", "-n", temporalNSName, "--query", `ExecutionStatus="Running"`)
	if err != nil {
		return "", err
	}
	running := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "Total:"))
	if queued == "0" && running == "0" {
		return "", nil
	}
	return fmt.Sprintf("%s queued, %s running", queued, running), nil
}

// moveCAPI moves the cluster's Cluster API objects to the site with clusterctl move.
func (p *pivot) moveCAPI(ctx context.Context) error {
	onSeed, err := p.hasCAPICluster(ctx, p.seed)
	if err != nil {
		return err
	}
	if !onSeed {
		onSite, err := p.hasCAPICluster(ctx, p.site)
		if err != nil {
			return err
		}
		if !onSite {
			return fmt.Errorf("cluster %s/%s is on neither the seed nor the site", managementNamespace, p.cfg.ClusterName)
		}
		p.log.Info("the Cluster API objects are already on the site")
		return nil
	}
	for _, d := range providerDeployments {
		seedImage, err := p.image(ctx, p.seed, d[0], d[1])
		if err != nil {
			return err
		}
		siteImage, err := p.image(ctx, p.site, d[0], d[1])
		if err != nil {
			return err
		}
		if seedImage != siteImage {
			return fmt.Errorf("%s/%s runs %s on the seed but %s on the site; clusterctl move needs the same version",
				d[0], d[1], seedImage, siteImage)
		}
	}
	// clusterctl move only moves kinds whose CRD carries its label, and
	// the CAPNICo manifest does not set it.
	out, err := p.kubectl(ctx, p.seed, "get", "crd", "-o", "name")
	if err != nil {
		return err
	}
	for _, crd := range strings.Fields(out) {
		if strings.HasSuffix(crd, infraCRDSuffix) {
			if _, err := p.kubectl(ctx, p.seed, "label", crd, clusterctlLabel+"=", "--overwrite"); err != nil {
				return err
			}
		}
	}
	move := []string{"move", "--kubeconfig", p.seed.kubeconfig, "--to-kubeconfig", p.site.kubeconfig, "--namespace", managementNamespace}
	// Cluster API links a Machine to its Node only on a later resync, up to
	// ten minutes after the build, and clusterctl refuses to move before then.
	var waiting string
	if err := p.poll(ctx, "Cluster API to link every Machine to its node", moveReadyTimeout, func(ctx context.Context) (bool, error) {
		was := waiting
		var err error
		waiting, err = p.capiNotReady(ctx)
		if err != nil {
			return false, err
		}
		if waiting != "" && waiting != was {
			p.log.Info("waiting for Cluster API to link every Machine to its node", "waiting", waiting)
		}
		return waiting == "", nil
	}); err != nil {
		return fmt.Errorf("%w: %s", err, waiting)
	}
	if out, err := p.runner.Run(ctx, "clusterctl", move...); err != nil {
		return fmt.Errorf("clusterctl move: %w\n%s", err, out)
	}
	p.log.Info("moved the Cluster API objects to the site", "cluster", p.cfg.ClusterName)
	return nil
}

// capiNotReady names what clusterctl move would refuse on the seed: Machines
// without a node, or a control plane not yet initialized. It returns "" when there is none.
func (p *pivot) capiNotReady(ctx context.Context) (string, error) {
	out, err := p.kubectl(ctx, p.seed, "-n", managementNamespace, "get", "machines.cluster.x-k8s.io",
		"-l", clusterNameLabel+"="+p.cfg.ClusterName, "-o", `jsonpath={range .items[*]}{.metadata.name}={.status.nodeRef.name}{"\n"}{end}`)
	if err != nil {
		return "", err
	}
	var waiting []string
	for _, line := range strings.Fields(out) {
		if strings.HasSuffix(line, "=") {
			waiting = append(waiting, strings.TrimSuffix(line, "="))
		}
	}
	initialized, err := p.kubectl(ctx, p.seed, "-n", managementNamespace, "get", "clusters.cluster.x-k8s.io", p.cfg.ClusterName,
		"-o", `jsonpath={.status.conditions[?(@.type=="ControlPlaneInitialized")].status}`)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(initialized) != "True" {
		waiting = append(waiting, "control plane")
	}
	return strings.Join(waiting, ", "), nil
}

func (p *pivot) hasCAPICluster(ctx context.Context, c *cluster) (bool, error) {
	out, err := p.kubectl(ctx, c, "-n", managementNamespace, "get", "clusters.cluster.x-k8s.io",
		"--ignore-not-found", "-o", "name", p.cfg.ClusterName)
	return strings.TrimSpace(out) != "", err
}

func (p *pivot) image(ctx context.Context, c *cluster, namespace, name string) (string, error) {
	d, err := c.kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("%s: %w", c.name, err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		return "", fmt.Errorf("%s: deployment %s/%s has no containers", c.name, namespace, name)
	}
	return d.Spec.Template.Spec.Containers[0].Image, nil
}

// moveDatabase restores a dump of the seed controller's database on the site,
// then checks that both hold the same cluster and node records.
func (p *pivot) moveDatabase(ctx context.Context) error {
	seedRecords, err := p.records(ctx, p.seed)
	if err != nil {
		return err
	}
	siteRecords, err := p.records(ctx, p.site)
	if err != nil {
		return err
	}
	if siteRecords == seedRecords {
		p.log.Info("the site database already holds the seed's records")
		return nil
	}

	seedPod, err := p.postgresPod(ctx, p.seed)
	if err != nil {
		return err
	}
	sitePod, err := p.postgresPod(ctx, p.site)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "nvke-pivot-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	local := filepath.Join(tmp, "db.dump")

	if _, err := p.kubectl(ctx, p.seed, "-n", postgresNamespace, "exec", seedPod, "--",
		"pg_dump", "-U", "postgres", "-Fc", "-f", dumpPath, databaseName); err != nil {
		return err
	}
	defer p.removeDump(ctx, p.seed, seedPod)
	if _, err := p.kubectl(ctx, p.seed, "-n", postgresNamespace, "cp", seedPod+":"+dumpPath, local); err != nil {
		return err
	}
	if _, err := p.kubectl(ctx, p.site, "-n", postgresNamespace, "cp", local, sitePod+":"+dumpPath); err != nil {
		return err
	}
	defer p.removeDump(ctx, p.site, sitePod)
	if _, err := p.kubectl(ctx, p.site, "-n", postgresNamespace, "exec", sitePod, "--",
		"pg_restore", "-U", "postgres", "--clean", "--if-exists", "--no-owner", "--single-transaction",
		"-d", databaseName, dumpPath); err != nil {
		return err
	}

	siteRecords, err = p.records(ctx, p.site)
	if err != nil {
		return err
	}
	if siteRecords != seedRecords {
		return fmt.Errorf("after the restore the site database holds %q, the seed %q", siteRecords, seedRecords)
	}
	p.log.Info("moved the controller database to the site")
	return nil
}

// records lists the IDs of the cluster and node records in c's controller database.
func (p *pivot) records(ctx context.Context, c *cluster) (string, error) {
	return p.psql(ctx, c, "SELECT 'cluster ' || id FROM clusters UNION ALL SELECT 'node ' || id FROM nodes ORDER BY 1")
}

func (p *pivot) psql(ctx context.Context, c *cluster, query string) (string, error) {
	pod, err := p.postgresPod(ctx, c)
	if err != nil {
		return "", err
	}
	out, err := p.kubectl(ctx, c, "-n", postgresNamespace, "exec", pod, "--",
		"psql", "-U", "postgres", "-d", databaseName, "-v", "ON_ERROR_STOP=1", "-tAc", query)
	return strings.TrimSpace(out), err
}

func (p *pivot) postgresPod(ctx context.Context, c *cluster) (string, error) {
	pods, err := c.kube.CoreV1().Pods(postgresNamespace).List(ctx, metav1.ListOptions{LabelSelector: postgresSelector})
	if err != nil {
		return "", fmt.Errorf("%s: %w", c.name, err)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			return pod.Name, nil
		}
	}
	return "", fmt.Errorf("%s: no running Postgres pod in %s", c.name, postgresNamespace)
}

func (p *pivot) removeDump(ctx context.Context, c *cluster, pod string) {
	if _, err := p.kubectl(context.WithoutCancel(ctx), c, "-n", postgresNamespace, "exec", pod, "--", "rm", "-f", dumpPath); err != nil {
		p.log.Warn("removing the database dump", "cluster", c.name, "err", err)
	}
}

// copySecrets copies the Secrets clusterctl move does not carry: the
// cluster's etcd encryption keys and any of its Secrets left in the
// management namespace.
func (p *pivot) copySecrets(ctx context.Context) error {
	keys, err := p.seed.kube.CoreV1().Secrets(controllerNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	for i := range keys.Items {
		if strings.HasPrefix(keys.Items[i].Name, etcdKeyPrefix) {
			if err := p.copySecret(ctx, &keys.Items[i]); err != nil {
				return err
			}
		}
	}
	owned, err := p.seed.kube.CoreV1().Secrets(managementNamespace).List(ctx,
		metav1.ListOptions{LabelSelector: clusterNameLabel + "=" + p.cfg.ClusterName})
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	for i := range owned.Items {
		if err := p.copySecret(ctx, &owned.Items[i]); err != nil {
			return err
		}
	}
	return nil
}

// copySecret creates src on the site unless a Secret of that name is already there.
func (p *pivot) copySecret(ctx context.Context, src *corev1.Secret) error {
	dst := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: src.Name, Namespace: src.Namespace, Labels: src.Labels, Annotations: src.Annotations,
		},
		Type: src.Type,
		Data: src.Data,
	}
	_, err := p.site.kube.CoreV1().Secrets(src.Namespace).Create(ctx, dst, metav1.CreateOptions{})
	switch {
	case apierrors.IsAlreadyExists(err):
		return nil
	case apierrors.IsNotFound(err):
		// The namespace is missing.
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: src.Namespace}}
		if _, err := p.site.kube.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("site: %w", err)
		}
		return p.copySecret(ctx, src)
	case err != nil:
		return fmt.Errorf("site: copying Secret %s/%s: %w", src.Namespace, src.Name, err)
	}
	p.log.Info("copied a Secret to the site", "secret", src.Namespace+"/"+src.Name)
	return nil
}

// activateSite scales the site controller back to the replicas recorded by stopSiteController.
func (p *pivot) activateSite(ctx context.Context) error {
	d, err := p.site.kube.AppsV1().Deployments(controllerNamespace).Get(ctx, controllerName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	replicas := d.Annotations[replicasAnnotation]
	if replicas == "" {
		replicas = "1"
	}
	if _, err := p.kubectl(ctx, p.site, "-n", controllerNamespace, "scale", "deployment", controllerName,
		"--replicas="+replicas); err != nil {
		return err
	}
	_, err = p.kubectl(ctx, p.site, "-n", controllerNamespace, "rollout", "status", "deployment/"+controllerName,
		"--timeout="+defaultQuiesceTimeout.String())
	return err
}

// verify waits until the site controller reaches every node's agent and sees
// it holding an SVID from the site SPIRE server.
func (p *pivot) verify(ctx context.Context) error {
	path := fmt.Sprintf("/api/v1/namespaces/%s/services/%s:http/proxy/api/clusters/%s/spire-server",
		controllerNamespace, controllerName, p.cfg.ClusterID)
	var pending []string
	err := p.poll(ctx, "the site controller to reach every node", defaultVerifyTimeout, func(ctx context.Context) (bool, error) {
		out, err := p.kubectl(ctx, p.site, "get", "--raw", path)
		if err != nil {
			pending = []string{err.Error()}
			return false, nil
		}
		var status api.ClusterSpireServerStatus
		if err := json.Unmarshal([]byte(out), &status); err != nil {
			return false, fmt.Errorf("decoding the site controller's SPIRE status: %w", err)
		}
		pending = pending[:0]
		for _, n := range status.Nodes {
			if !n.Reachable || !n.HasValidSVID || n.ServerAddress == nil || *n.ServerAddress != p.cfg.SiteSpireAddress {
				pending = append(pending, n.Name)
			}
		}
		return len(status.Nodes) > 0 && len(pending) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.Join(pending, "; "))
	}
	p.log.Info("the site controller reaches every node")
	return nil
}
