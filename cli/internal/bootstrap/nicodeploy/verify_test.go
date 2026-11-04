// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckCertificate(t *testing.T) {
	// httptest's certificate names example.com and 127.0.0.1.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	tests := []struct {
		name, hostname string
		wantErr        bool
	}{
		{name: "the certificate names the host", hostname: "example.com"},
		{name: "the certificate names another host", hostname: "api.site.example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCertificate(context.Background(), addr, tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestCheckHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tests := []struct {
		name, path string
		wantErr    bool
	}{
		{name: "answers 200", path: "/metrics"},
		{name: "answers 404", path: "/missing", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkHTTP(context.Background(), srv.URL+tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
