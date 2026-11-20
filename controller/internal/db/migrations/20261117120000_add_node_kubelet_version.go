// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// nodes.kubelet_version records the kubelet version the node's Kubernetes Node
// reports, without a leading "v". Until now the controller inferred a node's
// version from its pinned control-plane configuration, which does not change
// when a control plane is upgraded outside NVKE.
// Empty means not yet observed.
//
//nolint:gochecknoinits // Bun registers migrations at package initialization.
func init() {
	migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		if _, err := db.ExecContext(ctx, `
			ALTER TABLE nodes
				ADD COLUMN IF NOT EXISTS kubelet_version text NOT NULL DEFAULT ''
		`); err != nil {
			return fmt.Errorf("add nodes.kubelet_version: %w", err)
		}
		return nil
	}, func(context.Context, *bun.DB) error {
		return fmt.Errorf("down migration not supported")
	})
}
