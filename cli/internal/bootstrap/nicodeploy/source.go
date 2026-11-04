// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
)

// sourceDirs are the parts of the NICo source archive the install reads.
var sourceDirs = []string{"helm-prereqs/", "helm/", "rest-api/temporal-helm/", "rest-api/deploy/kustomize/base/"}

// Fetch downloads the NICo source archive src names into dir, checks it
// against src.SHA256, and extracts the chart directories the install reads. It
// returns the extracted source root. Nothing is extracted from an archive whose
// digest does not match.
func Fetch(ctx context.Context, client *http.Client, src manifest.Source, dir string) (string, error) {
	archive := filepath.Join(dir, "nico-source.tar.gz")
	if err := download(ctx, client, src, archive); err != nil {
		return "", err
	}
	root := filepath.Join(dir, "nico")
	if err := extract(archive, root); err != nil {
		return "", fmt.Errorf("extracting %s: %w", src.URL, err)
	}
	return root, nil
}

func download(ctx context.Context, client *http.Client, src manifest.Source, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", src.URL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", src.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: %s", src.URL, resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, sum), resp.Body); err != nil {
		return fmt.Errorf("fetching %s: %w", src.URL, err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != src.SHA256 {
		return fmt.Errorf("%s has sha256 %s, want %s", src.URL, got, src.SHA256)
	}
	return f.Close()
}

// extract writes the archive's sourceDirs under root, dropping the archive's
// top-level directory.
func extract(archive, root string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, name, ok := strings.Cut(hdr.Name, "/")
		if !ok || !wanted(name) {
			continue
		}
		path := filepath.Join(root, name)
		if !strings.HasPrefix(path, root+string(filepath.Separator)) {
			return fmt.Errorf("archive entry %q escapes the extraction directory", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFile(path, tr, hdr.FileInfo().Mode().Perm()); err != nil {
				return err
			}
		}
		// Links and other entries are not needed by the charts and are skipped.
	}
}

func wanted(name string) bool {
	for _, dir := range sourceDirs {
		if strings.HasPrefix(name, dir) {
			return true
		}
	}
	return false
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
