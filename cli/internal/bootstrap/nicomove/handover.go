// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicomove

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicodeploy"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// The marker the site's NICo carries once it is handed over.
const (
	handoverNamespace = "nico-system"
	handoverConfigMap = "nvkectl-handover"
	// stateMovedConfigMap records that NICo's databases and Vault are moved.
	stateMovedConfigMap = "nvkectl-nico-state-moved"
)

// writeHandover writes what whoever runs the site's NICo needs beside the
// database dumps and Vault snapshot the move already put in dir: the inputs,
// the Helm values and chart versions NICo runs with, Vault's keys, the CAs
// and the bundled Keycloak's admin login. Every file is private to its owner.
// A file that exists is refused, or replaced with Config.Resume.
func (m *mover) writeHandover(ctx context.Context, dir string, carried nicodeploy.Carried, keys nicodeploy.VaultKeys) error {
	s := m.cfg.Site.Settings
	inputs := filepath.Join(dir, "inputs")
	values := filepath.Join(dir, "helm-values")
	for _, d := range []string{inputs, values} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	settings, err := os.ReadFile(s.Path)
	if err != nil {
		return fmt.Errorf("copying %s into the handover bundle: %w", s.Path, err)
	}
	if err := writePrivate(filepath.Join(inputs, "settings.yaml"), settings, m.cfg.Resume); err != nil {
		return err
	}
	if err := m.site.WriteHelmValues(ctx, m.cfg.SiteKubeconfig, values); err != nil {
		return err
	}
	versions, err := yaml.Marshal(chartVersions(m.cfg.Site))
	if err != nil {
		return err
	}
	vaultKeys, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"versions.yaml":                    versions,
		nicosettings.HandoverVaultKeysFile: vaultKeys,
		"site-root.crt":                    carried.SiteRoot.Data[corev1.TLSCertKey],
		"site-root.key":                    carried.SiteRoot.Data[corev1.TLSPrivateKeyKey],
		"rest-ca.crt":                      carried.RESTCA.Data[corev1.TLSCertKey],
		"rest-ca.key":                      carried.RESTCA.Data[corev1.TLSPrivateKeyKey],
	}
	login, err := yaml.Marshal(map[string]string{"username": "admin", "password": string(carried.KeycloakLogin.Data["admin-password"])})
	if err != nil {
		return err
	}
	files["keycloak-admin.yaml"] = login
	for name, b := range files {
		if err := writePrivate(filepath.Join(dir, name), b, m.cfg.Resume); err != nil {
			return err
		}
	}
	m.log.Info("wrote the NICo handover bundle", "dir", dir)
	return nil
}

// chartVersions is the NICo release and the upstream charts nvkectl installs
// it from, as its manifest pins them, and the images NICo runs.
func chartVersions(cfg nicodeploy.Config) map[string]any {
	man := manifest.Load()
	charts := map[string]any{}
	for _, c := range []string{manifest.ComponentPostgresOperator, manifest.ComponentVault, manifest.ComponentExternalSecrets} {
		if chart := man.Components[c].Chart; chart != nil {
			charts[c] = chart
		}
	}
	nico := map[string]any{}
	if src := man.Components[manifest.ComponentNico].Source; src != nil {
		nico = map[string]any{"version": nicoVersion(src.URL), "source": src.URL, "sha256": src.SHA256}
	}
	return map[string]any{
		"nico":   nico,
		"images": map[string]string{"registry": cfg.ImageRegistry, "coreTag": cfg.CoreImageTag, "restTag": cfg.RestImageTag},
		"charts": charts,
	}
}

// nicoVersion is the release tag a NICo source archive URL names.
func nicoVersion(url string) string {
	return strings.TrimSuffix(path.Base(url), ".tar.gz")
}

// markHandover writes the ConfigMap that marks the site's NICo as handed over.
func (m *mover) markHandover(ctx context.Context) error {
	data := map[string]string{
		"coreImageTag": m.cfg.Site.CoreImageTag,
		"restImageTag": m.cfg.Site.RestImageTag,
		"handedOverAt": m.now().UTC().Format(time.RFC3339),
	}
	if src := manifest.Load().Components[manifest.ComponentNico].Source; src != nil {
		data["nicoVersion"] = nicoVersion(src.URL)
		data["nicoSource"] = src.URL
	}
	configMaps := m.cfg.SiteKube.CoreV1().ConfigMaps(handoverNamespace)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: handoverNamespace, Name: handoverConfigMap}, Data: data}
	_, err := configMaps.Create(ctx, cm, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := configMaps.Get(ctx, handoverConfigMap, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("reading ConfigMap %s/%s: %w", handoverNamespace, handoverConfigMap, getErr)
		}
		existing.Data = data
		_, err = configMaps.Update(ctx, existing, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("writing ConfigMap %s/%s: %w", handoverNamespace, handoverConfigMap, err)
	}
	return nil
}

// privateDir creates dir private to its owner. A directory that exists is
// left as it is: it may be the operator's, such as /tmp.
func privateDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

// writePrivate writes b to a new file at path, private to its owner. Unless
// replace is set it never overwrites a file, which may be an earlier bundle's
// only copy; replace is for a file this bootstrap wrote itself, which may
// have been cut short.
func writePrivate(path string, b []byte, replace bool) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if replace {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
