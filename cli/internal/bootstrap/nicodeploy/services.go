// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
	"github.com/dsx-ai-factory/nvke/cli/internal/redact"
)

// Where NICo's services run. Temporal runs in a namespace of its own: the NVKE
// stack runs a Temporal release in "temporal" in the same bootstrap cluster.
const (
	restNamespace     = "nico-rest"
	temporalNamespace = "nico-temporal"
	temporalHost      = "temporal-frontend." + temporalNamespace
	pgHost            = pgCluster + "." + postgresNamespace + ".svc.cluster.local"
	pullSecret        = "imagepullsecret"
	restCASecret      = "ca-signing-secret"
	temporalCreds     = "nico-temporal-pg-creds"
	keycloakCreds     = "nico-keycloak-pg-creds"
	restDBCreds       = "nico-rest-pg-creds"

	// The bundled Keycloak: its realm, the clients whose secrets nvkectl
	// generates, and the Secrets holding them.
	keycloakRealm       = "nico"
	keycloakRealmFile   = "nico-realm.json"
	serviceClientID     = "ncx-service"
	restClientID        = "nico-rest"
	keycloakLoginSecret = "keycloak-login"
	keycloakRealmSecret = "keycloak-realm"
)

// temporalTLS is how the Temporal CLI in NICo's admintools reaches its frontend.
const temporalTLS = "--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt " +
	"--tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key " +
	"--tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt " +
	"--tls-server-name interservice.server.temporal.local"

// The Temporal namespaces NICo REST's workers use.
var temporalNamespaces = []string{"cloud", "site"}

// Install installs NICo on the cluster as cfg.Settings describes and returns
// how it is reached: its prerequisites, with the UEFI passwords, NICo Core, the
// REST CA, NICo's bundled Keycloak, Temporal, NICo REST, and the site agent of a
// registered site. With ProfileSeed it publishes every service on its fixed
// node port once NICo Core is installed. It verifies NICo answers on the
// settings' addresses before it returns. root is the NICo source Fetch
// extracted. With ProfileSeed it first installs cert-manager; otherwise the
// cluster must already run it. Every step is an upgrade or a check, so it can be run again.
func (e *Engine) Install(ctx context.Context, kubeconfig, root string, cfg Config) (*Installed, error) {
	if cfg.Settings == nil || cfg.ImageRegistry == "" || cfg.CoreImageTag == "" || cfg.RestImageTag == "" || len(cfg.CoreValues) == 0 {
		return nil, errors.New("nicodeploy: Settings, ImageRegistry, CoreImageTag, RestImageTag and CoreValues are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	tmp, err := os.MkdirTemp("", "nvkectl-nico-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if cfg.Profile == ProfileSeed {
		if err := e.installCertManager(ctx, kubeconfig, tmp, cfg.Timeout); err != nil {
			return nil, err
		}
	}
	if err := e.InstallPrerequisites(ctx, kubeconfig, root, cfg); err != nil {
		return nil, err
	}
	if err := e.installCore(ctx, kubeconfig, root, tmp, cfg); err != nil {
		return nil, err
	}
	// Published before REST so the bundled Keycloak's token URL is reachable from
	// the host, and the fixed node ports are claimed before any chart takes one at random.
	if cfg.Profile == ProfileSeed {
		if err := e.publishSeed(ctx, cfg); err != nil {
			return nil, err
		}
	}
	creds, err := e.installREST(ctx, kubeconfig, root, tmp, cfg)
	if err != nil {
		return nil, err
	}
	siteID, err := e.RegisterSite(ctx, kubeconfig, root, tmp, cfg, "")
	if err != nil {
		return nil, err
	}
	inst := &Installed{
		SiteID:       siteID,
		RESTEndpoint: restEndpoint(cfg.Settings),
		OrgID:        cfg.Settings.EffectiveOrgID(),
		APIName:      nicorest.DefaultAPIName,
		Credentials:  creds,
		Dial:         cfg.Dial,
	}
	if err := e.verify(ctx, cfg, inst); err != nil {
		return nil, err
	}
	e.log.Info("NICo is installed", "site", cfg.SiteName, "siteID", siteID, "core", cfg.CoreImageTag, "rest", cfg.RestImageTag)
	return inst, nil
}

// installREST installs NICo REST with what it runs on: its CA and issuer, the
// identity provider and Temporal. It returns the OAuth2 client nvkectl and
// CAPNICo fetch tokens with.
func (e *Engine) installREST(ctx context.Context, kubeconfig, root, tmp string, cfg Config) (nicorest.ClientCredentials, error) {
	if err := e.ensureNamespace(ctx, restNamespace, nil, nil); err != nil {
		return nicorest.ClientCredentials{}, err
	}
	if err := e.ensureRESTCA(ctx, kubeconfig, root); err != nil {
		return nicorest.ClientCredentials{}, err
	}
	login, err := e.installKeycloak(ctx, kubeconfig, root, tmp, cfg)
	if err != nil {
		return nicorest.ClientCredentials{}, err
	}
	if err := e.installTemporal(ctx, kubeconfig, root, tmp, cfg.Timeout); err != nil {
		return nicorest.ClientCredentials{}, err
	}
	if err := e.installRESTChart(ctx, kubeconfig, root, tmp, cfg, login); err != nil {
		return nicorest.ClientCredentials{}, err
	}
	return clientCredentials(cfg, login), nil
}

// installRESTChart installs the nico-rest chart. login is the bundled Keycloak's.
func (e *Engine) installRESTChart(ctx context.Context, kubeconfig, root, tmp string, cfg Config, login *keycloakLogin) error {
	creds, err := e.waitSecret(ctx, restNamespace, restDBCreds, cfg.Timeout)
	if err != nil {
		return err
	}
	redact.RegisterSecret(string(creds.Data["password"]))
	// The values carry the database password and client secret, so the file is private and removed with tmp.
	values := filepath.Join(tmp, "nico-rest.yaml")
	if err := writeValues(values, restOverrides(cfg, string(creds.Data["username"]), string(creds.Data["password"]), login)); err != nil {
		return err
	}
	if err := e.helm(ctx, kubeconfig, "nico-rest", restNamespace, []string{filepath.Join(root, "helm", "rest", "nico-rest")},
		[]string{filepath.Join(root, "helm-prereqs", "values", "nico-rest.yaml"), values}, cfg.Timeout); err != nil {
		return err
	}
	if cfg.Profile == ProfileSite {
		return e.applyLoadBalancer(ctx, restNamespace, "nico-rest-api", cfg.Settings.Addresses.RESTEndpoint().Addr().String(), 8388)
	}
	return nil
}

// restOverrides is what NICo REST takes beyond NICo's values: the images and
// their pull credentials, the database login, the replicas, Temporal's address
// in its own namespace, and the bundled Keycloak whose tokens it accepts, with
// login its secrets.
func restOverrides(cfg Config, dbUser, dbPassword string, login *keycloakLogin) map[string]any {
	secrets := map[string]any{"dbCreds": map[string]any{"username": dbUser, "password": dbPassword}}
	if cfg.RegistryPassword != "" {
		secrets["imagePullSecret"] = map[string]any{"dockerconfigjson": base64.StdEncoding.EncodeToString(dockerConfig(cfg))}
	}
	temporal := map[string]any{"host": temporalHost}
	apiConfig := map[string]any{"temporal": temporal}
	// Tokens carry the issuer they were fetched from, which is the published address, not the in-cluster one.
	apiConfig["keycloak"] = map[string]any{"enabled": true, "externalBaseURL": keycloakBaseURL(cfg.Settings), "serviceAccount": true}
	secrets["keycloakClientSecret"] = map[string]any{"value": login.RESTSecret}
	return map[string]any{
		"global":           map[string]any{"image": map[string]any{"repository": cfg.ImageRegistry, "tag": cfg.RestImageTag}},
		"nico-rest-common": map[string]any{"secrets": secrets},
		// The chart's own node port is not one Kind maps; nvkectl publishes REST itself.
		"nico-rest-api":          map[string]any{"replicaCount": cfg.Replicas, "nodePort": map[string]any{"enabled": false}, "config": apiConfig},
		"nico-rest-cert-manager": map[string]any{"replicaCount": cfg.Replicas},
		"nico-rest-site-manager": map[string]any{"replicaCount": cfg.Replicas},
		"nico-rest-workflow": map[string]any{
			"secrets":     map[string]any{"dbCreds": "db-creds"},
			"config":      map[string]any{"db": map[string]any{"host": pgHost, "name": "nico_rest", "user": "nico-rest.nico"}, "temporal": temporal},
			"cloudWorker": map[string]any{"replicaCount": cfg.Replicas},
			"siteWorker":  map[string]any{"replicaCount": cfg.Replicas},
		},
	}
}

// InClusterRESTEndpoint is NICo REST's base URL inside the cluster NICo runs on.
const InClusterRESTEndpoint = "http://nico-rest-api." + restNamespace + ".svc:8388"

// InClusterTokenURL is the bundled Keycloak's token endpoint inside the cluster NICo runs on.
const InClusterTokenURL = "http://keycloak." + restNamespace + ".svc:8082/realms/" + keycloakRealm + "/protocol/openid-connect/token"

// restEndpoint is NICo REST's base URL at its published address.
func restEndpoint(s *nicosettings.Settings) string {
	return "http://" + s.Addresses.RESTEndpoint().String()
}

// keycloakBaseURL is the bundled Keycloak's base URL at its published address.
func keycloakBaseURL(s *nicosettings.Settings) string {
	return "http://" + s.Addresses.KeycloakEndpoint().String()
}

// clientCredentials is the OAuth2 client nvkectl and CAPNICo fetch tokens
// with: the bundled realm's service account.
func clientCredentials(cfg Config, login *keycloakLogin) nicorest.ClientCredentials {
	return nicorest.ClientCredentials{
		TokenURL:     keycloakBaseURL(cfg.Settings) + "/realms/" + keycloakRealm + "/protocol/openid-connect/token",
		ClientID:     serviceClientID,
		ClientSecret: login.ServiceSecret,
	}
}

// applyLoadBalancer publishes port of the chart Service name on ip: a
// LoadBalancer Service <name>-external with the same selector, which MetalLB
// gives that address.
func (e *Engine) applyLoadBalancer(ctx context.Context, namespace, name, ip string, port int32) error {
	services := e.kube.CoreV1().Services(namespace)
	src, err := services.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading Service %s/%s: %w", namespace, name, err)
	}
	var ports []corev1.ServicePort
	for _, p := range src.Spec.Ports {
		if p.Port == port {
			p.NodePort = 0
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return fmt.Errorf("the Service %s/%s has no port %d", namespace, name, port)
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name + "-external",
			Annotations: map[string]string{lbIPsAnnotation: ip},
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: src.Spec.Selector, Ports: ports},
	}
	_, err = services.Create(ctx, svc, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		if err != nil {
			return fmt.Errorf("creating Service %s/%s: %w", namespace, svc.Name, err)
		}
		return nil
	}
	existing, err := services.Get(ctx, svc.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading Service %s/%s: %w", namespace, svc.Name, err)
	}
	existing.Annotations = merge(existing.Annotations, svc.Annotations)
	existing.Spec.Type, existing.Spec.Selector, existing.Spec.Ports = svc.Spec.Type, svc.Spec.Selector, svc.Spec.Ports
	if _, err := services.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating Service %s/%s: %w", namespace, svc.Name, err)
	}
	return nil
}

// ensureRESTCA creates the CA NICo REST's ClusterIssuer signs with, once, and
// the issuer. The CA is kept in REST's namespace and copied to cert-manager's
// on every run, so a copy a failed run missed is made.
func (e *Engine) ensureRESTCA(ctx context.Context, kubeconfig, root string) error {
	existing, err := e.kube.CoreV1().Secrets(restNamespace).Get(ctx, restCASecret, metav1.GetOptions{})
	var data map[string][]byte
	switch {
	case apierrors.IsNotFound(err):
		certPEM, keyPEM, err := newCA()
		if err != nil {
			return err
		}
		data = map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM}
	case err != nil:
		return fmt.Errorf("reading Secret %s/%s: %w", restNamespace, restCASecret, err)
	default:
		data = existing.Data
	}
	for _, ns := range []string{restNamespace, certManagerNS} {
		if err := e.applySecret(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: restCASecret},
			Type:       corev1.SecretTypeTLS,
			Data:       data,
		}); err != nil {
			return err
		}
	}
	_, err = e.kubectl(ctx, kubeconfig, "apply", "-f",
		filepath.Join(root, "rest-api", "deploy", "kustomize", "base", "cert-manager-io", "cluster-issuer.yaml"))
	return err
}

// newCA returns a self-signed CA certificate and key in PEM, as NICo REST's gen-site-ca.sh makes them.
func newCA() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "NICo Local Dev CA", Organization: []string{"NVIDIA"}, Country: []string{"US"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}

// keycloakLogin is the bundled Keycloak's secrets, generated once and kept in
// the Secret keycloakLoginSecret, which replace NICo's development defaults.
type keycloakLogin struct {
	// AdminPassword is the master realm's admin password.
	AdminPassword string
	// ServiceSecret and RESTSecret are the client secrets of ncx-service, the
	// service account nvkectl and CAPNICo use, and of nico-rest, REST's own client.
	ServiceSecret string
	RESTSecret    string
}

// installKeycloak runs NICo's development Keycloak against its database in
// NICo's Postgres, with generated secrets in place of its defaults, and
// returns them.
func (e *Engine) installKeycloak(ctx context.Context, kubeconfig, root, tmp string, cfg Config) (*keycloakLogin, error) {
	login, err := e.ensureKeycloakLogin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := e.waitSecret(ctx, restNamespace, keycloakCreds, cfg.Timeout); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "helm-prereqs", "keycloak")
	realmFile, err := os.ReadFile(filepath.Join(dir, "realm-configmap.yaml"))
	if err != nil {
		return nil, err
	}
	realm, err := keycloakRealmJSON(realmFile, login, cfg.Settings.EffectiveOrgID(), keycloakBaseURL(cfg.Settings))
	if err != nil {
		return nil, err
	}
	// The realm holds the client secrets, so Keycloak imports it from a Secret instead of NICo's ConfigMap.
	if err := e.applySecret(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: keycloakRealmSecret},
		Data:       map[string][]byte{keycloakRealmFile: realm},
	}); err != nil {
		return nil, err
	}
	deploymentFile, err := os.ReadFile(filepath.Join(dir, "deployment.yaml"))
	if err != nil {
		return nil, err
	}
	deployment, err := keycloakDeployment(deploymentFile)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(tmp, "keycloak.yaml")
	if err := os.WriteFile(path, deployment, 0o600); err != nil {
		return nil, err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "apply", "-n", restNamespace, "-f", filepath.Join(dir, "service.yaml"), "-f", path); err != nil {
		return nil, err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "-n", restNamespace, "rollout", "status", "deployment/keycloak",
		"--timeout="+cfg.Timeout.String()); err != nil {
		return nil, err
	}
	if cfg.Profile == ProfileSite {
		if err := e.applyLoadBalancer(ctx, restNamespace, "keycloak", cfg.Settings.Addresses.KeycloakEndpoint().Addr().String(), 8082); err != nil {
			return nil, err
		}
	}
	return login, nil
}

// ensureKeycloakLogin reads the bundled Keycloak's secrets, generating the
// ones the Secret does not hold yet. Keycloak keeps the first ones it starts
// with in its database, so they are never replaced.
func (e *Engine) ensureKeycloakLogin(ctx context.Context) (*keycloakLogin, error) {
	data := map[string][]byte{}
	existing, err := e.kube.CoreV1().Secrets(restNamespace).Get(ctx, keycloakLoginSecret, metav1.GetOptions{})
	switch {
	case err == nil:
		data = existing.Data
	case !apierrors.IsNotFound(err):
		return nil, fmt.Errorf("reading Secret %s/%s: %w", restNamespace, keycloakLoginSecret, err)
	}
	changed := false
	for _, key := range []string{"admin-password", "ncx-service-secret", "nico-rest-secret"} {
		if len(data[key]) > 0 {
			continue
		}
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if data == nil {
			data = map[string][]byte{}
		}
		data[key] = []byte(base64.RawURLEncoding.EncodeToString(b))
		changed = true
	}
	if changed {
		if err := e.applySecret(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: restNamespace, Name: keycloakLoginSecret},
			Data:       data,
		}); err != nil {
			return nil, err
		}
	}
	login := &keycloakLogin{
		AdminPassword: string(data["admin-password"]),
		ServiceSecret: string(data["ncx-service-secret"]),
		RESTSecret:    string(data["nico-rest-secret"]),
	}
	for _, secret := range []string{login.AdminPassword, login.ServiceSecret, login.RESTSecret} {
		redact.RegisterSecret(secret)
	}
	return login, nil
}

// keycloakRealmJSON returns the realm NICo's realm ConfigMap defines, with
// login's client secrets, its roles in org instead of NICo's default org, and
// frontendURL as the realm's frontend URL.
func keycloakRealmJSON(configMap []byte, login *keycloakLogin, org, frontendURL string) ([]byte, error) {
	var cm corev1.ConfigMap
	if err := sigsyaml.Unmarshal(configMap, &cm); err != nil {
		return nil, fmt.Errorf("reading NICo's Keycloak realm: %w", err)
	}
	raw, ok := cm.Data[keycloakRealmFile]
	if !ok {
		return nil, fmt.Errorf("NICo's Keycloak realm ConfigMap has no %s", keycloakRealmFile)
	}
	// Realm roles are named <org>:<role>; REST reads the org from the name.
	raw = strings.ReplaceAll(raw, `"`+nicosettings.DefaultOrgID+`:`, `"`+org+`:`)
	var realm map[string]any
	if err := json.Unmarshal([]byte(raw), &realm); err != nil {
		return nil, fmt.Errorf("reading NICo's Keycloak realm: %w", err)
	}
	secrets := map[string]string{serviceClientID: login.ServiceSecret, restClientID: login.RESTSecret}
	clients, _ := realm["clients"].([]any)
	for _, c := range clients {
		client, _ := c.(map[string]any)
		id, _ := client["clientId"].(string)
		if secret, ok := secrets[id]; ok {
			client["secret"] = secret
			delete(secrets, id)
		}
	}
	if len(secrets) > 0 {
		return nil, fmt.Errorf("NICo's Keycloak realm does not define the clients %s and %s", serviceClientID, restClientID)
	}
	// REST accepts only tokens issued by the published address, so a token
	// fetched in-cluster must carry that issuer too.
	attributes, _ := realm["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["frontendUrl"] = frontendURL
	realm["attributes"] = attributes
	return json.Marshal(realm)
}

// keycloakDeployment returns NICo's Keycloak Deployment for its database in
// NICo's Postgres, with the admin password and the realm read from Secrets.
func keycloakDeployment(manifest []byte) ([]byte, error) {
	// The variables keycloak/setup.sh fills in with envsubst, for a database on NICo's Postgres.
	filled := strings.NewReplacer(
		"${KEYCLOAK_DB_HOST}", pgHost,
		"${KEYCLOAK_DB_NAME}", "keycloak",
		"${KEYCLOAK_DB_USER}", "keycloak.nico",
		"${KEYCLOAK_DB_SSLMODE}", "require",
		"${KEYCLOAK_DB_PASSWORD_SECRET_NAME}", keycloakCreds,
		"${KEYCLOAK_DB_PASSWORD_SECRET_KEY}", "password",
	).Replace(string(manifest))
	var d appsv1.Deployment
	if err := sigsyaml.Unmarshal([]byte(filled), &d); err != nil {
		return nil, fmt.Errorf("reading NICo's Keycloak Deployment: %w", err)
	}
	password, realm := false, false
	pod := &d.Spec.Template.Spec
	for i := range pod.Containers {
		for j, env := range pod.Containers[i].Env {
			if env.Name == "KEYCLOAK_ADMIN_PASSWORD" {
				pod.Containers[i].Env[j] = corev1.EnvVar{Name: env.Name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: keycloakLoginSecret}, Key: "admin-password",
				}}}
				password = true
			}
		}
	}
	for i, v := range pod.Volumes {
		if v.Name == "realm-config" {
			pod.Volumes[i].VolumeSource = corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: keycloakRealmSecret}}
			realm = true
		}
	}
	if !password || !realm {
		return nil, errors.New("NICo's Keycloak Deployment has no KEYCLOAK_ADMIN_PASSWORD or realm-config volume to replace")
	}
	return sigsyaml.Marshal(&d)
}

// installTemporal installs NICo's Temporal in its own namespace, on NICo's
// Postgres, and creates the Temporal namespaces NICo REST uses.
func (e *Engine) installTemporal(ctx context.Context, kubeconfig, root, tmp string, timeout time.Duration) error {
	if err := e.ensureNamespace(ctx, temporalNamespace, nil, nil); err != nil {
		return err
	}
	if err := e.grantTemporalCreateDB(ctx, kubeconfig, timeout); err != nil {
		return err
	}
	// nico-prereqs syncs these credentials only into a namespace named
	// temporal, so they are copied from the Postgres operator's Secret.
	// shortcut: a one-time copy, not refreshed; replace with an ExternalSecret if the operator starts rotating passwords.
	src, err := e.waitSecret(ctx, postgresNamespace, "temporal.nico."+pgCluster+".credentials.postgresql.acid.zalan.do", timeout)
	if err != nil {
		return err
	}
	if err := e.applySecret(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: temporalNamespace, Name: temporalCreds},
		Data:       src.Data,
	}); err != nil {
		return err
	}

	certs, err := os.ReadFile(filepath.Join(root, "rest-api", "deploy", "kustomize", "base", "temporal-helm", "certificates.yaml"))
	if err != nil {
		return err
	}
	path := filepath.Join(tmp, "temporal-certificates.yaml")
	moved := strings.ReplaceAll(string(certs), "namespace: temporal\n", "namespace: "+temporalNamespace+"\n")
	if err := os.WriteFile(path, []byte(moved), 0o600); err != nil {
		return err
	}
	if _, err := e.kubectl(ctx, kubeconfig, "apply", "-f", path); err != nil {
		return err
	}
	for _, c := range []string{"server-interservice-cert", "server-cloud-cert", "server-site-cert"} {
		if _, err := e.kubectl(ctx, kubeconfig, "wait", "--for=condition=Ready", "certificate/"+c, "-n", temporalNamespace,
			"--timeout="+timeout.String()); err != nil {
			return err
		}
	}

	sql := func(database string) map[string]any {
		return map[string]any{"sql": map[string]any{
			"host": pgHost, "database": database, "user": "temporal.nico", "existingSecret": temporalCreds,
			"tls": map[string]any{"enabled": true},
		}}
	}
	values := filepath.Join(tmp, "temporal.yaml")
	if err := writeValues(values, map[string]any{"server": map[string]any{"config": map[string]any{"persistence": map[string]any{
		"secretName": temporalCreds, "default": sql("temporal"), "visibility": sql("temporal_visibility"),
	}}}}); err != nil {
		return err
	}
	chart := filepath.Join(root, "rest-api", "temporal-helm", "temporal")
	if err := e.helm(ctx, kubeconfig, "temporal", temporalNamespace, []string{chart},
		[]string{filepath.Join(chart, "values-kind.yaml"), values}, timeout); err != nil {
		return err
	}
	for _, ns := range temporalNamespaces {
		if err := e.ensureTemporalNamespace(ctx, kubeconfig, ns, timeout); err != nil {
			return err
		}
	}
	return nil
}

// grantTemporalCreateDB gives temporal.nico the createdb flag and waits for
// Postgres to apply it. The Temporal chart's schema job runs CREATE DATABASE,
// which Postgres refuses without it even when the database exists.
// shortcut: NICo grants this itself from v2.4 (infra-controller#7122); drop this once the pinned release does. nico-prereqs
// resets the flag on every upgrade, so it is applied after each one.
func (e *Engine) grantTemporalCreateDB(ctx context.Context, kubeconfig string, timeout time.Duration) error {
	if _, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "patch", "postgresql", pgCluster, "--type=merge",
		"-p", `{"spec":{"users":{"temporal.nico":["createdb"]}}}`); err != nil {
		return err
	}
	return e.until(ctx, timeout, "temporal.nico to be granted createdb", func(ctx context.Context) (bool, error) {
		pod, err := e.postgresPrimary(ctx)
		if err != nil {
			return false, nil
		}
		out, err := e.kubectl(ctx, kubeconfig, "-n", postgresNamespace, "exec", pod, "-c", "postgres", "--",
			"su", "postgres", "-c", `psql -tAc "SELECT rolcreatedb FROM pg_roles WHERE rolname = 'temporal.nico'"`)
		return err == nil && strings.TrimSpace(out) == "t", nil
	})
}

// ensureTemporalNamespace creates the Temporal namespace name unless it exists.
func (e *Engine) ensureTemporalNamespace(ctx context.Context, kubeconfig, name string, timeout time.Duration) error {
	operator := func(args string) string {
		return fmt.Sprintf("temporal operator namespace %s --address %s:7233 %s", args, temporalHost, temporalTLS)
	}
	return e.until(ctx, timeout, "Temporal namespace "+name, func(ctx context.Context) (bool, error) {
		if _, err := e.kubectl(ctx, kubeconfig, "-n", temporalNamespace, "exec", "deploy/temporal-admintools", "--",
			"sh", "-c", operator("describe -n "+name)); err == nil {
			return true, nil
		}
		out, err := e.kubectl(ctx, kubeconfig, "-n", temporalNamespace, "exec", "deploy/temporal-admintools", "--",
			"sh", "-c", operator("create -n "+name+" --retention 72h"))
		return err == nil || strings.Contains(strings.ToLower(out), "already exists"), nil
	})
}

// waitSecret waits for the Secret External Secrets or the Postgres operator creates.
func (e *Engine) waitSecret(ctx context.Context, namespace, name string, timeout time.Duration) (*corev1.Secret, error) {
	var secret *corev1.Secret
	err := e.until(ctx, timeout, "Secret "+namespace+"/"+name, func(ctx context.Context) (bool, error) {
		s, err := e.kube.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		secret = s
		return err == nil, nil
	})
	return secret, err
}

// pullSecretFor is the pull Secret NICo Core's pods name, for cfg's registry.
func pullSecretFor(namespace string, cfg Config) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: pullSecret},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: dockerConfig(cfg)},
	}
}

// dockerConfig is a docker config JSON holding cfg's registry credentials.
func dockerConfig(cfg Config) []byte {
	user := cfg.RegistryUsername
	if user == "" {
		user = "$oauthtoken"
	}
	host, _, _ := strings.Cut(cfg.ImageRegistry, "/")
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{"username": user, "password": cfg.RegistryPassword}}})
	return b
}
