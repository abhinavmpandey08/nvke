// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package manifest holds the bootstrap manifest: the charts
// `nvkectl bootstrap site` fetches and installs with Helm, and the images the
// bootstrap runs. nvkectl pins each chart's version. The digests are recorded
// for mirroring; the bootstrap does not verify them.
package manifest

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Component keys, as the manifest names them.
const (
	ComponentPostgres    = "postgresql"
	ComponentTemporal    = "temporal"
	ComponentSPIRECRDs   = "spire-crds"
	ComponentSPIRE       = "spire"
	ComponentController  = "controller"
	ComponentProvisioned = "cluster-api-provider-provisioned"
	ComponentCAPNICo     = "cluster-api-provider-nico"

	// The NICo the bootstrap installs for infra.nico.managed, and the upstream
	// charts its install pulls.
	ComponentNico             = "nico"
	ComponentPostgresOperator = "postgres-operator"
	ComponentVault            = "vault"
	ComponentExternalSecrets  = "external-secrets"
	ComponentCertManager      = "cert-manager"
	// ComponentMetalLB publishes NICo's services on the site cluster.
	ComponentMetalLB = "metallb"
	// ComponentFRR is the BGP speaker that announces NICo's service addresses
	// from the bootstrap host, and ImageFRR its image's key.
	ComponentFRR = "frr"
	ImageFRR     = "speaker"

	// Image keys under the two components this repository builds.
	ImageController = "controller"
	ImageManager    = "manager"

	// ImageCAPNICo is the key of the CAPNICo controller image.
	ImageCAPNICo = "controller"
)

// manifestYAML is the embedded manifest. `nvkectl get bootstrap-manifest` prints it.
//
//go:embed bootstrap-manifest.yaml
var manifestYAML []byte

// Manifest lists the charts `bootstrap site` fetches and the images it runs,
// with the version and digest of each.
type Manifest struct {
	Components map[string]Component `yaml:"components"`
}

// Component is one deployed piece: its chart, if pulled, and its images.
type Component struct {
	Chart  *Chart           `yaml:"chart,omitempty"`
	Images map[string]Image `yaml:"images,omitempty"`
	// Source is a source archive the component's charts are taken from, for a
	// component that publishes none.
	Source *Source `yaml:"source,omitempty"`
}

// Source is a source archive, which the bootstrap checks against SHA256
// before it uses it.
type Source struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
}

// Chart names a Helm chart by repository, name and version.
type Chart struct {
	Repo    string `yaml:"repo,omitempty"`
	Name    string `yaml:"name,omitempty"`
	Version string `yaml:"version,omitempty"`
	// SHA256 is the digest of the chart archive.
	SHA256 string `yaml:"sha256,omitempty"`
}

// Image is a container image the component runs.
type Image struct {
	Ref string `yaml:"ref"`
	// Digest is the image digest. Empty for the images the operator builds.
	Digest string `yaml:"digest,omitempty"`
}

// Pinned returns the image as repository@Digest, without its tag, which a
// registry can move. It fails when Digest is not a sha256 digest.
func (i Image) Pinned() (string, error) {
	if !strings.HasPrefix(i.Digest, "sha256:") {
		return "", fmt.Errorf("bootstrap-manifest.yaml lists no sha256 digest for the image %q", i.Ref)
	}
	repo := i.Ref
	if at := strings.IndexByte(repo, '@'); at >= 0 {
		repo = repo[:at]
	}
	if colon := strings.LastIndexByte(repo, ':'); colon > strings.LastIndexByte(repo, '/') {
		repo = repo[:colon]
	}
	return repo + "@" + i.Digest, nil
}

// Load parses the embedded manifest. It panics if the document does not
// parse; that is a build defect.
func Load() *Manifest {
	decoder := yaml.NewDecoder(bytes.NewReader(manifestYAML))
	decoder.KnownFields(true)
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		panic("manifest: embedded bootstrap-manifest.yaml does not parse: " + err.Error())
	}
	return &m
}

// Bytes returns the embedded manifest as shipped, comments included.
func Bytes() []byte {
	return bytes.Clone(manifestYAML)
}
