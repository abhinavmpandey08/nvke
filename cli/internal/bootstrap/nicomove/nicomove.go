// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicomove moves the NICo `nvkectl bootstrap site` installed on the
// bootstrap cluster to the site cluster after the pivot, keeping its site,
// machines, credentials and addresses, and hands it over: it writes the
// handover bundle and marks the site's NICo as handed over.
package nicomove

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicodeploy"
)

// CAPNICo's controller on the site cluster, which starts NICo work.
const (
	capnicoNamespace  = "capnico-system"
	capnicoDeployment = "controller-manager"
)

const (
	defaultTimeout = 30 * time.Minute
	pollInterval   = 5 * time.Second
)

// The Temporal namespaces NICo REST's workers use; the site agent's is the site ID.
var restTemporalNamespaces = []string{"cloud", "site"}

// Config is what Run moves NICo with.
type Config struct {
	// SeedKubeconfig and SiteKubeconfig reach the bootstrap and the site cluster.
	SeedKubeconfig, SiteKubeconfig string
	// Root is the NICo source nicodeploy.Fetch extracted.
	Root string
	// Seed and Site are the Configs NICo was installed with on the bootstrap
	// cluster and is to run with on the site cluster. Site.Settings is required.
	Seed, Site nicodeploy.Config
	// SiteID is the NICo site's ID, which stays the same.
	SiteID string
	// Runner runs helm and kubectl; os/exec when nil.
	Runner nicodeploy.CommandRunner
	// SeedKube and SiteKube are clients of the bootstrap and the site cluster.
	SeedKube, SiteKube kubernetes.Interface
	// RemoveHostAddresses withdraws NICo's service addresses from the
	// bootstrap host, so the site cluster can announce them. Optional.
	RemoveHostAddresses func(context.Context) error
	// Logger receives progress; slog.Default when nil.
	Logger *slog.Logger
	// Resume continues a move an earlier run of the same bootstrap started: the
	// files it wrote to the handover directory are replaced instead of refused.
	Resume bool
}

// engine is what Run does on one cluster's NICo. *nicodeploy.Engine is one.
type engine interface {
	ReadCarried(ctx context.Context) (nicodeploy.Carried, error)
	VaultKeys(ctx context.Context) (nicodeploy.VaultKeys, error)
	PrepareSite(ctx context.Context, kubeconfig, root string, cfg nicodeploy.Config, carried nicodeploy.Carried, siteID string) error
	ScaleRESTAPI(ctx context.Context, replicas int) error
	RunningWorkflows(ctx context.Context, kubeconfig, namespace string) ([]string, error)
	StopNICo(ctx context.Context) error
	Stopped(ctx context.Context) (bool, error)
	DumpDatabase(ctx context.Context, kubeconfig, database, path string) error
	RestoreDatabase(ctx context.Context, kubeconfig, database, path string) error
	SnapshotVault(ctx context.Context, kubeconfig, path string) error
	RestoreVault(ctx context.Context, kubeconfig, root string, cfg nicodeploy.Config, snapshot string, keys nicodeploy.VaultKeys) error
	SiteState(ctx context.Context, kubeconfig, siteID string) (nicodeploy.SiteState, error)
	PublishSite(ctx context.Context, cfg nicodeploy.Config) error
	StartSite(ctx context.Context, kubeconfig, root string, cfg nicodeploy.Config, siteID string) (*nicodeploy.Installed, error)
	WriteHelmValues(ctx context.Context, kubeconfig, dir string) error
}

var _ engine = (*nicodeploy.Engine)(nil)

// Run moves NICo from the bootstrap cluster to the site cluster and returns
// how the site's NICo is reached. It prepares the site, stops new NICo work
// (CAPNICo on the site, REST on the bootstrap cluster), waits for the
// workflows already running to finish, stops the bootstrap cluster's NICo,
// moves its databases and Vault, withdraws the service addresses from the
// bootstrap host, publishes them on the site cluster, starts NICo on the site
// with the same site ID, restarts CAPNICo, and checks that the site agent
// reports and the machines kept their status. It then writes the handover bundle to Site.Settings.HandoverDir and
// the ConfigMap nico-system/nvkectl-handover. The bootstrap cluster's NICo is
// left stopped, with its state, so a failed move can be recovered from it.
//
// Run can be run again after a move that stopped part of the way. It returns
// nil without doing anything when the site cluster already holds
// nvkectl-handover. It does not stop the bootstrap cluster's NICo again once
// it is stopped, and does not move the databases and Vault again once the
// site cluster holds the ConfigMap nico-system/nvkectl-nico-state-moved,
// written when their move finished: from then on the site's copies are the
// ones NICo may have written to. Until then the site's NICo has not started,
// so the move is redone. Every other step is an upgrade or a check.
func Run(ctx context.Context, cfg Config) (*nicodeploy.Installed, error) {
	if cfg.SeedKubeconfig == "" || cfg.SiteKubeconfig == "" || cfg.Root == "" || cfg.SiteID == "" {
		return nil, errors.New("nicomove: SeedKubeconfig, SiteKubeconfig, Root and SiteID are required")
	}
	if cfg.Site.Settings == nil || cfg.Site.Settings.HandoverDir == "" {
		return nil, errors.New("nicomove: Site.Settings with a HandoverDir is required")
	}
	if cfg.SeedKube == nil || cfg.SiteKube == nil {
		return nil, errors.New("nicomove: SeedKube and SiteKube are required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	timeout := cfg.Site.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	m := &mover{
		cfg:     cfg,
		seed:    nicodeploy.New(cfg.Runner, cfg.SeedKube, log),
		site:    nicodeploy.New(cfg.Runner, cfg.SiteKube, log),
		log:     log.With("component", "nicomove"),
		poll:    pollInterval,
		timeout: timeout,
		now:     time.Now,
	}
	return m.run(ctx)
}

type mover struct {
	cfg        Config
	seed, site engine
	log        *slog.Logger
	poll       time.Duration
	timeout    time.Duration
	now        func() time.Time
}

func (m *mover) run(ctx context.Context) (*nicodeploy.Installed, error) {
	c := m.cfg
	if done, err := m.handedOver(ctx); err != nil || done {
		return nil, err
	}
	dir := c.Site.Settings.HandoverDir
	dumps := filepath.Join(dir, "databases")
	for _, d := range []string{dir, dumps} {
		if err := privateDir(d); err != nil {
			return nil, err
		}
	}
	carried, err := m.seed.ReadCarried(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := m.seed.VaultKeys(ctx)
	if err != nil {
		return nil, err
	}

	m.log.Info("preparing the site cluster for NICo")
	// An earlier run may have restored the bootstrap cluster's Vault on the site and stopped before storing its keys.
	site := c.Site
	site.RestoredVaultKeys = &keys
	if err := m.site.PrepareSite(ctx, c.SiteKubeconfig, c.Root, site, carried, c.SiteID); err != nil {
		return nil, err
	}
	// CAPNICo and REST's API start every NICo workflow.
	m.log.Info("stopping new NICo work")
	capnicoReplicas, err := m.capnicoReplicas(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.scaleCAPNICo(ctx, 0); err != nil {
		return nil, err
	}
	stopped, err := m.seed.Stopped(ctx)
	if err != nil {
		return nil, err
	}
	if stopped {
		m.log.Info("the bootstrap cluster's NICo is already stopped")
	} else {
		if err := m.seed.ScaleRESTAPI(ctx, 0); err != nil {
			return nil, err
		}
		if err := m.drain(ctx); err != nil {
			return nil, err
		}
		if err := m.seed.StopNICo(ctx); err != nil {
			return nil, err
		}
	}

	if err := m.moveState(ctx, dir, dumps, keys); err != nil {
		return nil, err
	}
	before, err := m.site.SiteState(ctx, c.SiteKubeconfig, c.SiteID)
	if err != nil {
		return nil, err
	}

	if c.RemoveHostAddresses != nil {
		m.log.Info("withdrawing NICo's service addresses from the bootstrap host")
		if err := c.RemoveHostAddresses(ctx); err != nil {
			return nil, fmt.Errorf("withdrawing NICo's service addresses from the bootstrap host: %w", err)
		}
	}
	if err := m.publishSite(ctx); err != nil {
		return nil, err
	}
	m.log.Info("starting NICo on the site cluster")
	inst, err := m.site.StartSite(ctx, c.SiteKubeconfig, c.Root, c.Site, c.SiteID)
	if err != nil {
		return nil, err
	}
	if err := m.scaleCAPNICo(ctx, capnicoReplicas); err != nil {
		return nil, err
	}
	if err := m.verify(ctx, before); err != nil {
		return nil, err
	}

	if err := m.writeHandover(ctx, dir, carried, keys); err != nil {
		return nil, err
	}
	if err := m.markHandover(ctx); err != nil {
		return nil, err
	}
	m.log.Info("NICo is moved to the site cluster and handed over", "siteID", c.SiteID, "handover", dir)
	return inst, nil
}

// handedOver reports whether the site cluster holds the marker of a NICo
// already handed over.
func (m *mover) handedOver(ctx context.Context) (bool, error) {
	_, err := m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace).Get(ctx, handoverConfigMap, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reading ConfigMap %s/%s: %w", handoverNamespace, handoverConfigMap, err)
	}
	m.log.Info("NICo on the site cluster is already handed over", "configMap", handoverNamespace+"/"+handoverConfigMap)
	return true, nil
}

// moveState moves NICo's databases and Vault from the stopped bootstrap
// cluster's NICo to the site cluster and records that on the site cluster,
// unless it is recorded already: the site's NICo may have written to them since.
func (m *mover) moveState(ctx context.Context, dir, dumps string, keys nicodeploy.VaultKeys) error {
	c := m.cfg
	configMaps := c.SiteKube.CoreV1().ConfigMaps(handoverNamespace)
	_, err := configMaps.Get(ctx, stateMovedConfigMap, metav1.GetOptions{})
	switch {
	case err == nil:
		m.log.Info("NICo's databases and Vault are already on the site cluster")
		return nil
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("reading ConfigMap %s/%s: %w", handoverNamespace, stateMovedConfigMap, err)
	}
	m.log.Info("moving NICo's databases and Vault to the site cluster")
	for _, db := range nicodeploy.Databases {
		path := filepath.Join(dumps, db+".dump")
		if err := m.seed.DumpDatabase(ctx, c.SeedKubeconfig, db, path); err != nil {
			return err
		}
		if err := m.site.RestoreDatabase(ctx, c.SiteKubeconfig, db, path); err != nil {
			return err
		}
	}
	snapshot := filepath.Join(dir, "vault.snap")
	if err := m.seed.SnapshotVault(ctx, c.SeedKubeconfig, snapshot); err != nil {
		return err
	}
	if err := m.site.RestoreVault(ctx, c.SiteKubeconfig, c.Root, c.Site, snapshot, keys); err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: handoverNamespace, Name: stateMovedConfigMap}}
	if _, err := configMaps.Create(ctx, cm, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("writing ConfigMap %s/%s: %w", handoverNamespace, stateMovedConfigMap, err)
	}
	return nil
}

// publishSite publishes NICo's service addresses on the site cluster. It runs
// only once the bootstrap host has withdrawn them, so no address is announced
// from both.
func (m *mover) publishSite(ctx context.Context) error {
	m.log.Info("publishing NICo's service addresses on the site cluster")
	return m.site.PublishSite(ctx, m.cfg.Site)
}

// drain waits until no workflow but the periodic ones runs in the bootstrap
// cluster's Temporal namespaces of NICo REST and the site agent.
func (m *mover) drain(ctx context.Context) error {
	var busy []string
	var last error
	logged := ""
	err := m.until(ctx, "NICo's running workflows to finish", func(ctx context.Context) (bool, error) {
		busy, last = nil, nil
		for _, ns := range append(slices.Clone(restTemporalNamespaces), m.cfg.SiteID) {
			ids, err := m.seed.RunningWorkflows(ctx, m.cfg.SeedKubeconfig, ns)
			if err != nil {
				last = err
				return false, nil
			}
			for _, id := range ids {
				busy = append(busy, ns+"/"+id)
			}
		}
		if now := strings.Join(busy, ", "); now != "" && now != logged {
			m.log.Info("waiting for NICo's workflows to finish", "running", now)
			logged = now
		}
		return len(busy) == 0, nil
	})
	switch {
	case err == nil:
		return nil
	case last != nil:
		return fmt.Errorf("%w: %w", err, last)
	case len(busy) > 0:
		return fmt.Errorf("%w: still running: %s", err, strings.Join(busy, ", "))
	}
	return err
}

// capnicoReplicas returns the replicas CAPNICo's controller on the site
// cluster runs, at least one: a count of zero is a failed move's, which the
// move must not keep.
func (m *mover) capnicoReplicas(ctx context.Context) (int, error) {
	d, err := m.cfg.SiteKube.AppsV1().Deployments(capnicoNamespace).Get(ctx, capnicoDeployment, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("reading %s/%s: %w", capnicoNamespace, capnicoDeployment, err)
	}
	if d.Spec.Replicas == nil {
		return 1, nil
	}
	return max(int(*d.Spec.Replicas), 1), nil
}

// scaleCAPNICo sets CAPNICo's controller on the site cluster to replicas.
func (m *mover) scaleCAPNICo(ctx context.Context, replicas int) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))
	if _, err := m.cfg.SiteKube.AppsV1().Deployments(capnicoNamespace).Patch(ctx, capnicoDeployment, types.MergePatchType, patch,
		metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("scaling %s/%s to %d: %w", capnicoNamespace, capnicoDeployment, replicas, err)
	}
	return nil
}

// verify checks the moved NICo: the site agent's inventory reaches REST
// after the move, every machine that was Ready or InUse before it is again,
// and CAPNICo runs.
func (m *mover) verify(ctx context.Context, before nicodeploy.SiteState) error {
	c := m.cfg
	if err := m.until(ctx, "the site agent's inventory to reach NICo REST on the site cluster", func(ctx context.Context) (bool, error) {
		now, err := m.site.SiteState(ctx, c.SiteKubeconfig, c.SiteID)
		return err == nil && now.InventoryReceived.After(before.InventoryReceived), nil
	}); err != nil {
		return err
	}
	var want []string
	for id, status := range before.Machines {
		if usable(status) {
			want = append(want, id)
		}
	}
	slices.Sort(want)
	var lost []string
	if err := m.until(ctx, "the site's machines to be Ready or InUse again", func(ctx context.Context) (bool, error) {
		now, err := m.site.SiteState(ctx, c.SiteKubeconfig, c.SiteID)
		if err != nil {
			return false, nil
		}
		lost = nil
		for _, id := range want {
			if status := now.Machines[id]; !usable(status) {
				lost = append(lost, fmt.Sprintf("%s (%s)", id, or(status, "missing")))
			}
		}
		return len(lost) == 0, nil
	}); err != nil {
		return fmt.Errorf("%w: %s", err, strings.Join(lost, ", "))
	}
	return m.until(ctx, "CAPNICo to run on the site cluster", func(ctx context.Context) (bool, error) {
		d, err := c.SiteKube.AppsV1().Deployments(capnicoNamespace).Get(ctx, capnicoDeployment, metav1.GetOptions{})
		return err == nil && d.Status.AvailableReplicas > 0, nil
	})
}

// usable reports whether a machine in status is ingested and healthy.
func usable(status string) bool {
	return status == "Ready" || status == "InUse"
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// until calls done every poll interval until it reports true, returns an error, or the timeout passes.
func (m *mover) until(ctx context.Context, what string, done func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
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
			return fmt.Errorf("timed out after %s waiting for %s", m.timeout, what)
		case <-time.After(m.poll):
		}
	}
}
