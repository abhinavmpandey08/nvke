// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/manifest"
)

// sourceArchive builds a release archive whose entries sit under one top-level
// directory, as GitHub's are.
func sourceArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "infra-controller-2.2.2/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func serve(t *testing.T, body []byte) manifest.Source {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	return manifest.Source{URL: srv.URL + "/v2.2.2.tar.gz", SHA256: hex.EncodeToString(sum[:])}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		tamper  bool
		want    map[string]string
		absent  []string
		wantErr string
	}{
		{
			name: "extracts only the chart directories",
			files: map[string]string{
				"helm-prereqs/Chart.yaml":                    "name: nico-prereqs",
				"helm/Chart.yaml":                            "name: nico",
				"rest-api/temporal-helm/temporal/Chart.yaml": "name: temporal",
				"crates/api/src/main.rs":                     "fn main() {}",
				"rest-api/cmd/main.go":                       "package main",
			},
			want: map[string]string{
				"helm-prereqs/Chart.yaml":                    "name: nico-prereqs",
				"helm/Chart.yaml":                            "name: nico",
				"rest-api/temporal-helm/temporal/Chart.yaml": "name: temporal",
			},
			absent: []string{"crates", "rest-api/cmd"},
		},
		{
			name:    "refuses an archive whose digest does not match",
			files:   map[string]string{"helm/Chart.yaml": "name: nico"},
			tamper:  true,
			wantErr: "has sha256",
		},
		{
			name:    "refuses an entry that escapes the extraction directory",
			files:   map[string]string{"helm/../../escape": "x"},
			wantErr: "escapes the extraction directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := serve(t, sourceArchive(t, tt.files))
			if tt.tamper {
				src.SHA256 = "0000"
			}
			dir := t.TempDir()
			root, err := Fetch(context.Background(), http.DefaultClient, src, dir)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.NoDirExists(t, filepath.Join(dir, "nico", "helm"), "nothing is extracted from a refused archive")
				return
			}
			require.NoError(t, err)
			for name, body := range tt.want {
				got, err := os.ReadFile(filepath.Join(root, name))
				require.NoError(t, err)
				assert.Equal(t, body, string(got))
			}
			for _, name := range tt.absent {
				assert.NoDirExists(t, filepath.Join(root, name))
			}
		})
	}
}
