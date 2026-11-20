// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activities

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	nvkeproto "github.com/dsx-ai-factory/nvke/agent/pkg/agent/proto"

	"github.com/dsx-ai-factory/nvke/controller/internal/agent/agenttest"
	"github.com/dsx-ai-factory/nvke/controller/internal/db"
	"github.com/dsx-ai-factory/nvke/controller/internal/testutil"
)

// joinStringAgent fails for the named nodes and records the order it was asked in.
type joinStringAgent struct {
	*agenttest.FakeClient
	failing map[string]bool
	asked   []string
}

func (f *joinStringAgent) UpdateAndFetchKubeAdmJoinStrings(_ context.Context, node db.Node, _ *nvkeproto.KubeadmJoinStringRequest) (*nvkeproto.KubeadmJoinStringResponse, error) {
	f.asked = append(f.asked, node.Name)
	if f.failing[node.Name] {
		return nil, errors.New("agent unreachable")
	}
	return &nvkeproto.KubeadmJoinStringResponse{ControlplaneJoinString: "cp " + node.Name, WorkerJoinString: "worker " + node.Name}, nil
}

func TestJoinStringsFromControlPlane(t *testing.T) {
	cpNode := func(name string, agentReady bool) db.Node {
		n := db.Node{ID: uuid.New(), Name: name, IP: "10.0.0.1", ControlPlane: true}
		n.Conditions.Joined = db.NewCondition(true, "Joined")
		n.Conditions.KubernetesReady = db.NewCondition(true, "Ready")
		n.Conditions.NodeAgentReady = db.NewCondition(agentReady, "agent")
		return n
	}
	deleting := cpNode("cp-0-deleting", true)
	deleting.Conditions.Deleting = db.NewCondition(true, "Deleting")
	notJoined := cpNode("cp-0-pending", true)
	notJoined.Conditions.Joined = db.NewCondition(false, "Pending")

	tests := []struct {
		name      string
		nodes     []db.Node
		failing   map[string]bool
		wantAsked []string
		wantFrom  string
		wantErr   string
	}{
		{
			name:      "agent-ready node is asked before one whose agent has not answered",
			nodes:     []db.Node{cpNode("cp-a", false), cpNode("cp-b", true), deleting, notJoined},
			wantAsked: []string{"cp-b"},
			wantFrom:  "cp-b",
		},
		{
			name:      "a failing node is skipped for the next",
			nodes:     []db.Node{cpNode("cp-a", true), cpNode("cp-b", true)},
			failing:   map[string]bool{"cp-a": true},
			wantAsked: []string{"cp-a", "cp-b"},
			wantFrom:  "cp-b",
		},
		{
			name:      "every node failing reports each",
			nodes:     []db.Node{cpNode("cp-a", true), cpNode("cp-b", false)},
			failing:   map[string]bool{"cp-a": true, "cp-b": true},
			wantAsked: []string{"cp-a", "cp-b"},
			wantErr:   "node cp-b: agent unreachable",
		},
		{name: "no joined node", nodes: []db.Node{deleting, notJoined}, wantErr: "no joined control-plane node"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clusterID := uuid.New()
			for i := range tc.nodes {
				tc.nodes[i].ClusterID = clusterID
			}
			store := &testutil.MockDB{}
			store.On("ListNodes", mock.Anything, mock.Anything).Return(tc.nodes, nil)
			agentClient := &joinStringAgent{FakeClient: &agenttest.FakeClient{}, failing: tc.failing}
			a := &Activities{db: store, nodeAgentClient: agentClient}

			joinStrings, err := a.joinStringsFromControlPlane(context.Background(), clusterID)

			assert.Equal(t, tc.wantAsked, agentClient.asked)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "worker "+tc.wantFrom, joinStrings.GetWorkerJoinString())
		})
	}
}

func TestJoinKubernetesVersion(t *testing.T) {
	cluster := db.Cluster{KubernetesVersion: "1.36.4"}
	tests := []struct {
		name    string
		nodeSet db.NodeSet
		want    string
	}{
		{name: "worker uses its node set's version", nodeSet: db.NodeSet{KubernetesVersion: "1.37.1"}, want: "1.37.1"},
		{name: "control-plane node has no node set", want: "1.36.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, joinKubernetesVersion(cluster, tc.nodeSet))
		})
	}
}
