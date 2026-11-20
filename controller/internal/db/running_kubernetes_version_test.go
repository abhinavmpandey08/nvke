// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dsx-ai-factory/nvke/controller/internal/db"
)

func TestRunningKubernetesVersion(t *testing.T) {
	tests := []struct {
		name  string
		nodes []db.Node
		want  string
	}{
		{name: "no observed versions fall back to the desired one", nodes: []db.Node{{}, {}}, want: "1.36.6"},
		{name: "oldest observed version wins mid-upgrade", nodes: []db.Node{{KubeletVersion: "1.36.6"}, {KubeletVersion: "1.36.4"}, {}}, want: "1.36.4"},
		{name: "minor versions compare numerically", nodes: []db.Node{{KubeletVersion: "1.9.0"}, {KubeletVersion: "1.10.0"}}, want: "1.9.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, db.RunningKubernetesVersion(tc.nodes, "1.36.6"))
		})
	}
}
