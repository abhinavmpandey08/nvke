// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The site agent's chart release and the objects of it nvkectl reads.
const (
	siteAgentRelease     = "nico-rest-site-agent"
	siteAgentConfigMap   = siteAgentRelease + "-config"
	siteAgentCertificate = "core-grpc-client-site-agent-certs"
	siteRegistration     = "site-registration"
	// siteAgentConnected is what the site agent logs once it reaches NICo Core.
	// It dials Core once at start and never again, so without it the agent is useless.
	siteAgentConnected = "CoreGrpcClient: Successfully connected to server"
	// siteAgentConnectWait is how long the agent gets to connect before it is restarted.
	siteAgentConnectWait = 2 * time.Minute
)

// sqlSafeName is what a site name or org must look like to be put in SQL.
var sqlSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// RegisterSite registers the NICo site cfg.SiteName in cfg.Settings' org and
// runs its site agent, connected to NICo Core, and returns the site's ID.
// siteID is reused when it is set; when it is empty, the ID is the previous
// install's, else the ID of REST's site of that name and org, else a new one.
// NICo REST must already run. tmp is a private directory for rendered values.
func (e *Engine) RegisterSite(ctx context.Context, kubeconfig, root, tmp string, cfg Config, siteID string) (string, error) {
	org := cfg.Settings.EffectiveOrgID()
	if !sqlSafeName.MatchString(cfg.SiteName) || !sqlSafeName.MatchString(org) {
		return "", fmt.Errorf("nicodeploy: the site name %q and org %q must match %s", cfg.SiteName, org, sqlSafeName)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	prior, err := e.priorSiteID(ctx)
	if err != nil {
		return "", err
	}
	siteID, err = e.resolveSiteID(ctx, kubeconfig, cfg, siteID, prior)
	if err != nil {
		return "", err
	}
	if err := e.seedSite(ctx, kubeconfig, cfg, siteID); err != nil {
		return "", err
	}
	// The bootstrap Job keeps an existing registration, so one for another site is dropped.
	if prior != "" && prior != siteID {
		err := e.kube.CoreV1().Secrets(restNamespace).Delete(ctx, siteRegistration, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return "", fmt.Errorf("deleting Secret %s/%s: %w", restNamespace, siteRegistration, err)
		}
	}

	chart := filepath.Join(root, "helm", "rest", siteAgentRelease)
	values := filepath.Join(tmp, "nico-rest-site-agent.yaml")
	if err := writeValues(values, siteAgentValues(cfg, siteID)); err != nil {
		return "", err
	}
	valueFiles := []string{filepath.Join(root, "helm-prereqs", "values", "nico-site-agent.yaml"), values}
	if err := e.issueSiteAgentCert(ctx, kubeconfig, chart, valueFiles, cfg.Timeout); err != nil {
		return "", err
	}
	// The agent fails at start without its Temporal namespace.
	if err := e.ensureTemporalNamespace(ctx, kubeconfig, siteID, cfg.Timeout); err != nil {
		return "", err
	}
	if err := e.helm(ctx, kubeconfig, siteAgentRelease, restNamespace, []string{chart}, valueFiles, cfg.Timeout); err != nil {
		return "", err
	}
	if err := e.waitSiteAgentConnected(ctx, kubeconfig, cfg.Timeout); err != nil {
		return "", err
	}
	e.log.Info("the NICo site is registered", "site", cfg.SiteName, "siteID", siteID)
	return siteID, nil
}

// priorSiteID returns the site ID the installed site agent runs with, or "".
func (e *Engine) priorSiteID(ctx context.Context) (string, error) {
	cm, err := e.kube.CoreV1().ConfigMaps(restNamespace).Get(ctx, siteAgentConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading ConfigMap %s/%s: %w", restNamespace, siteAgentConfigMap, err)
	}
	return cm.Data["CLUSTER_ID"], nil
}

// resolveSiteID returns given, else prior, else the ID of REST's site named
// cfg.SiteName in the org, else a new ID.
func (e *Engine) resolveSiteID(ctx context.Context, kubeconfig string, cfg Config, given, prior string) (string, error) {
	id := given
	if id == "" {
		id = prior
	}
	if id == "" {
		// A failed lookup is retried, never read as "no site": that would register the site twice.
		if err := e.until(ctx, cfg.Timeout, "REST's site table", func(ctx context.Context) (bool, error) {
			out, err := e.restSQL(ctx, kubeconfig, fmt.Sprintf(
				"SELECT id FROM site WHERE name='%s' AND org='%s' AND deleted IS NULL LIMIT 1;", cfg.SiteName, cfg.Settings.EffectiveOrgID(),
			))
			id = strings.TrimSpace(out)
			return err == nil, nil
		}); err != nil {
			return "", err
		}
	}
	if id == "" {
		return uuid.NewString(), nil
	}
	if _, err := uuid.Parse(id); err != nil {
		return "", fmt.Errorf("nicodeploy: the NICo site ID %q is not a UUID", id)
	}
	return id, nil
}

// seedSite creates, unless they exist, the org's default infrastructure
// provider and a Pending site row with siteID in REST's database, as NICo's
// setup.sh does. The site agent's inventory is dropped for a site without a
// row. Flow is off, as nvkectl does not run it.
func (e *Engine) seedSite(ctx context.Context, kubeconfig string, cfg Config, siteID string) error {
	org, name := cfg.Settings.EffectiveOrgID(), cfg.SiteName
	sql := fmt.Sprintf(`INSERT INTO infrastructure_provider (id, name, display_name, org, created, updated, created_by)
  SELECT gen_random_uuid(), 'default', 'default', '%[1]s', now(), now(), '%[2]s'
  WHERE NOT EXISTS (SELECT 1 FROM infrastructure_provider WHERE org='%[1]s' AND name='default' AND deleted IS NULL);
INSERT INTO site (id, name, display_name, org, infrastructure_provider_id, registration_token,
    registration_token_expiration, is_infinity_enabled, is_serial_console_enabled, status, created, updated, created_by, config)
  SELECT '%[2]s', '%[3]s', '%[3]s', '%[1]s',
    (SELECT id FROM infrastructure_provider WHERE org='%[1]s' AND name='default' AND deleted IS NULL LIMIT 1),
    gen_random_uuid(), now() + interval '7 days', false, false, 'Pending', now(), now(), '%[2]s',
    '{"native_networking": true, "network_security_group": true, "flow": false}'
  WHERE NOT EXISTS (SELECT 1 FROM site WHERE id='%[2]s');
INSERT INTO status_detail (id, entity_id, status, message, count, created, updated)
  SELECT gen_random_uuid(), '%[2]s', 'Pending', 'received site creation request, pending pairing', 1, now(), now()
  WHERE NOT EXISTS (SELECT 1 FROM status_detail WHERE entity_id='%[2]s');`, org, siteID, name)
	// Retried until REST's migrations have made the tables.
	return e.until(ctx, cfg.Timeout, "the NICo site row", func(ctx context.Context) (bool, error) {
		_, err := e.restSQL(ctx, kubeconfig, sql)
		if err != nil {
			e.log.Warn("seeding the NICo site row failed; retrying", "err", err)
		}
		return err == nil, nil
	})
}

// restSQL runs sql on REST's database on the Postgres primary and returns its unaligned rows.
func (e *Engine) restSQL(ctx context.Context, kubeconfig, sql string) (string, error) {
	pod, err := e.postgresPrimary(ctx)
	if err != nil {
		return "", err
	}
	return e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "exec", pod, "-c", "postgres", "--",
		"su", "postgres", "-c", "psql -d nico_rest -v ON_ERROR_STOP=1 -tAc "+shellQuote(sql))
}

// shellQuote quotes s as one word for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// siteAgentValues is what the site agent takes beyond NICo's values: its image,
// its site, and Temporal in its own namespace. Flow does not run.
func siteAgentValues(cfg Config, siteID string) map[string]any {
	return map[string]any{
		"global":       map[string]any{"image": map[string]any{"repository": cfg.ImageRegistry, "tag": cfg.RestImageTag}},
		"replicaCount": cfg.Replicas,
		"envConfig": map[string]any{
			"CLUSTER_ID":                   siteID,
			"TEMPORAL_SUBSCRIBE_NAMESPACE": siteID,
			"TEMPORAL_SUBSCRIBE_QUEUE":     "site",
			"TEMPORAL_HOST":                temporalHost,
			"FLOW_GRPC_ENABLED":            "false",
		},
	}
}

// issueSiteAgentCert issues the site agent's NICo Core client certificate
// before its pods start, which read it once at start. The chart adopts it.
func (e *Engine) issueSiteAgentCert(ctx context.Context, kubeconfig, chart string, values []string, timeout time.Duration) error {
	args := []string{"template", siteAgentRelease, chart, "--namespace", restNamespace}
	for _, v := range values {
		args = append(args, "--values", v)
	}
	rendered, err := e.runner.Run(ctx, "helm", append(args, "--show-only", "templates/certificate.yaml")...)
	if err != nil {
		return fmt.Errorf("rendering the site agent's certificate: %w\n%s", err, rendered)
	}
	path := filepath.Join(filepath.Dir(values[len(values)-1]), "site-agent-certificate.yaml")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "apply", "-f", path); err != nil {
		return err
	}
	cert := "certificate/" + siteAgentCertificate
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "annotate", cert, "--overwrite",
		"meta.helm.sh/release-name="+siteAgentRelease, "meta.helm.sh/release-namespace="+restNamespace); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "label", cert, "--overwrite", "app.kubernetes.io/managed-by=Helm"); err != nil {
		return err
	}
	_, err = e.kubectl(ctx, kubeconfig, "wait", "--for=condition=Ready", cert, "-n", restNamespace, "--timeout="+timeout.String())
	return err
}

// waitSiteAgentConnected waits for every site agent pod to log that it reached
// NICo Core, restarting the agent once when it does not.
func (e *Engine) waitSiteAgentConnected(ctx context.Context, kubeconfig string, timeout time.Duration) error {
	connected := func(ctx context.Context) (bool, error) {
		pods, err := e.kube.CoreV1().Pods(restNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + siteAgentRelease})
		if err != nil || len(pods.Items) == 0 {
			return false, nil
		}
		for _, p := range pods.Items {
			// The line is logged at start; the first bytes hold it however long the pod has run.
			out, err := e.runner.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", restNamespace, "logs", p.Name, "--limit-bytes=8388608")
			if err != nil || !strings.Contains(out, siteAgentConnected) {
				return false, nil
			}
		}
		return true, nil
	}
	if e.until(ctx, min(siteAgentConnectWait, timeout), "the site agent to connect to NICo Core", connected) == nil {
		return nil
	}
	e.log.Warn("the site agent did not connect to NICo Core; restarting it")
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "rollout", "restart", "statefulset/"+siteAgentRelease); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "rollout", "status", "statefulset/"+siteAgentRelease,
		"--timeout="+timeout.String()); err != nil {
		return err
	}
	return e.until(ctx, timeout, "the site agent to connect to NICo Core", connected)
}
