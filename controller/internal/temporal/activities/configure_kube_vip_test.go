// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activities

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/testsuite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvkeproto "github.com/dsx-ai-factory/nvke/agent/pkg/agent/proto"

	"github.com/dsx-ai-factory/nvke/controller/internal/agent/agenttest"
	"github.com/dsx-ai-factory/nvke/controller/internal/config"
	"github.com/dsx-ai-factory/nvke/controller/internal/db"
	"github.com/dsx-ai-factory/nvke/controller/internal/testutil"
)

func TestConfigureKubeVip_BGPPEERASNFromProvider(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cluster    db.Cluster
		nodePool   db.NodePool
		cfg        config.Config
		wantSource nvkeproto.ReconcileKubeVipRequest_BGPPeerASNSource
		wantASN    uint32
		wantFMDS   string
	}{
		"CAPI pool without Nico payload uses default ASN": {
			cluster: db.Cluster{
				ProviderType:    db.ProviderTypeCAPI,
				ControlPlaneVIP: "10.0.0.10",
			},
			nodePool: db.NodePool{
				ControlPlane: true,
				Capi:         &db.CAPINodePoolProvider{},
			},
			wantSource: nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_STATIC,
			wantASN:    4294967000,
		},
		"CAPI pool with site FMDS endpoint uses FMDS ASN": {
			cluster: db.Cluster{
				ProviderType:    db.ProviderTypeCAPI,
				ControlPlaneVIP: "10.0.0.10",
			},
			nodePool: db.NodePool{
				ControlPlane: true,
				Capi:         &db.CAPINodePoolProvider{},
			},
			cfg: config.Config{
				KubeVipFMDSEndpoint: "http://169.254.169.254/latest/meta-data/asn",
			},
			wantSource: nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_FMDS,
			wantASN:    0,
			wantFMDS:   "http://169.254.169.254/latest/meta-data/asn",
		},
		"Nico pool with VPC prefix uses FMDS ASN": {
			cluster: db.Cluster{
				ProviderType:    db.ProviderTypeNico,
				ControlPlaneVIP: "10.0.0.10",
			},
			nodePool: db.NodePool{
				ControlPlane: true,
				Nico: &db.NicoNodePoolProvider{
					VpcPrefixIDs: []uuid.UUID{uuid.New()},
				},
			},
			wantSource: nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_FMDS,
			wantASN:    0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nodeID := uuid.New()
			nodeSetID := uuid.New()
			nodePoolID := uuid.New()
			clusterID := uuid.New()
			node := db.Node{
				ID:           nodeID,
				ClusterID:    clusterID,
				NodeSetID:    nodeSetID,
				NodePoolID:   nodePoolID,
				ControlPlane: true,
				IP:           "10.0.0.20",
			}

			tt.cluster.ID = clusterID
			tt.nodePool.ID = nodePoolID
			mockDB := &testutil.MockDB{}
			mockDB.On("GetNode", mock.Anything, nodeID).Return(node, nil).Twice()
			mockDB.On("GetNodeSet", mock.Anything, nodeSetID).Return(db.NodeSet{ID: nodeSetID, NodePoolID: nodePoolID}, nil)
			mockDB.On("GetNodePool", mock.Anything, nodePoolID).Return(tt.nodePool, nil)
			mockDB.On("GetCluster", mock.Anything, clusterID).Return(tt.cluster, nil).Once()

			fakeAgent := &agenttest.FakeClient{
				ReconcileKubeVipResponse: &nvkeproto.ReconcileKubeVipResponse{
					Outcome:           nvkeproto.ReconcileKubeVipResponse_OUTCOME_UNCHANGED,
					ManifestPath:      "/etc/kubernetes/manifests/kube-vip.yaml",
					BgpInterface:      "eth0",
					BgpPeerAddress:    "10.0.0.1",
					BgpPeerAsn:        tt.wantASN,
					KubeconfigPath:    "/etc/kubernetes/kube-vip.conf",
					KubeconfigChanged: false,
				},
			}

			a := &Activities{cfg: tt.cfg, db: mockDB, nodeAgentClient: fakeAgent}
			testSuite := &testsuite.WorkflowTestSuite{}
			env := testSuite.NewTestActivityEnvironment()
			env.RegisterActivity(a.configureKubeVip)
			value, err := env.ExecuteActivity(a.configureKubeVip, ConfigureKubeVipInput{
				NodeID:              nodeID,
				ConfigureSuperAdmin: true,
			})
			require.NoError(t, err)
			var result ConfigureKubeVipResult
			require.NoError(t, value.Get(&result))
			require.Nil(t, result.ConfigureSuperAdminOutput)
			require.Contains(t, result.ConfigureKubeVipOutput, "OUTCOME_UNCHANGED")
			require.Len(t, fakeAgent.ReconcileKubeVipRequests, 1)
			request := fakeAgent.ReconcileKubeVipRequests[0]
			require.Equal(t, "10.0.0.10", request.GetVipAddress())
			require.Equal(t, "10.0.0.20", request.GetNodeIp())
			require.Equal(t, uint32(65100), request.GetBgpAsn())
			require.Equal(t, tt.wantSource, request.GetBgpPeerAsnSource())
			require.Equal(t, tt.wantASN, request.GetBgpPeerAsn())
			require.Equal(t, tt.wantFMDS, request.GetFmdsEndpoint())
			require.Empty(t, request.GetServiceAccountToken())
			mockDB.AssertExpectations(t)
		})
	}
}

func TestConfigureKubeVip_RPCFallbackBoundary(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		rpcError            error
		configureSuperAdmin bool
		fmdsEndpoint        string
		wantRunbooks        []string
		wantError           string
	}{
		"unimplemented uses kube-vip runbook": {
			rpcError:     status.Error(codes.Unimplemented, "unknown method ReconcileKubeVip"),
			wantRunbooks: []string{configureKubeVipRunbookName},
		},
		"wrapped unimplemented preserves legacy super-admin ordering": {
			rpcError:            fmt.Errorf("reconcile call: %w", status.Error(codes.Unimplemented, "unknown method ReconcileKubeVip")),
			configureSuperAdmin: true,
			wantRunbooks:        []string{"configure-super-admin", configureKubeVipRunbookName},
		},
		"unimplemented passes FMDS endpoint to legacy runbook": {
			rpcError:     status.Error(codes.Unimplemented, "unknown method ReconcileKubeVip"),
			fmdsEndpoint: "http://169.254.169.254/latest/meta-data/asn",
			wantRunbooks: []string{configureKubeVipRunbookName},
		},
		"operational RPC error is propagated": {
			rpcError:  status.Error(codes.Internal, "manifest write failed"),
			wantError: "manifest write failed",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nodeID := uuid.New()
			nodeSetID := uuid.New()
			nodePoolID := uuid.New()
			clusterID := uuid.New()
			node := db.Node{
				ID:           nodeID,
				Name:         "cp-0",
				ClusterID:    clusterID,
				NodeSetID:    nodeSetID,
				NodePoolID:   nodePoolID,
				ControlPlane: true,
				IP:           "10.0.0.20",
			}
			cluster := db.Cluster{ID: clusterID, ProviderType: db.ProviderTypeCAPI, ControlPlaneVIP: "10.0.0.10"}
			nodePool := db.NodePool{ID: nodePoolID, ControlPlane: true, Capi: &db.CAPINodePoolProvider{}}
			mockDB := &testutil.MockDB{}
			mockDB.On("GetNode", mock.Anything, nodeID).Return(node, nil).Times(2 + len(tt.wantRunbooks))
			mockDB.On("GetNodeSet", mock.Anything, nodeSetID).Return(db.NodeSet{ID: nodeSetID, NodePoolID: nodePoolID}, nil)
			mockDB.On("GetNodePool", mock.Anything, nodePoolID).Return(nodePool, nil)
			mockDB.On("GetCluster", mock.Anything, clusterID).Return(cluster, nil).Times(1 + len(tt.wantRunbooks))

			fakeAgent := &agenttest.FakeClient{ReconcileKubeVipError: tt.rpcError}
			fakeAgent.ExecuteScriptHook = func(_ db.Node, runbookName, script string) (*nvkeproto.ExecuteScriptResponse, error) {
				if runbookName == configureKubeVipRunbookName {
					wantPeerAS := "4294967000"
					if tt.fmdsEndpoint != "" {
						wantPeerAS = "FROM_FMDS"
					}
					require.Contains(t, script, "export VIP_ADDRESS='10.0.0.10'")
					require.Contains(t, script, "export BGP_AS='65100'")
					require.Contains(t, script, "export BGP_PEER_AS='"+wantPeerAS+"'")
					require.Contains(t, script, "export FMDS_ENDPOINT='"+tt.fmdsEndpoint+"'")
					require.Contains(t, script, "export NODE_IP='10.0.0.20'")
				}
				return &nvkeproto.ExecuteScriptResponse{ExitCode: 0, Output: runbookName + " output"}, nil
			}

			a := &Activities{
				cfg: config.Config{
					KubeVipFMDSEndpoint: tt.fmdsEndpoint,
				},
				db:              mockDB,
				nodeAgentClient: fakeAgent,
			}
			testSuite := &testsuite.WorkflowTestSuite{}
			env := testSuite.NewTestActivityEnvironment()
			env.RegisterActivity(a.configureKubeVip)
			value, err := env.ExecuteActivity(a.configureKubeVip, ConfigureKubeVipInput{
				NodeID:              nodeID,
				ConfigureSuperAdmin: tt.configureSuperAdmin,
			})
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				require.Empty(t, fakeAgent.ExecuteScriptNames)
			} else {
				require.NoError(t, err)
				var result ConfigureKubeVipResult
				require.NoError(t, value.Get(&result))
				require.Equal(t, tt.wantRunbooks, fakeAgent.ExecuteScriptNames)
				require.Equal(t, configureKubeVipRunbookName+" output", result.ConfigureKubeVipOutput)
				if tt.configureSuperAdmin {
					require.NotNil(t, result.ConfigureSuperAdminOutput)
					require.Equal(t, "configure-super-admin output", *result.ConfigureSuperAdminOutput)
				} else {
					require.Nil(t, result.ConfigureSuperAdminOutput)
				}
			}
			require.Len(t, fakeAgent.ReconcileKubeVipRequests, 1)
			require.Equal(t, tt.fmdsEndpoint, fakeAgent.ReconcileKubeVipRequests[0].GetFmdsEndpoint())
			mockDB.AssertExpectations(t)
		})
	}
}

func TestConfigureKubeVip_ServiceAccountToken(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		withToken   bool
		providerErr error
		wantToken   string
		wantError   string
	}{
		"without the flag the tenant API is not touched": {
			providerErr: context.DeadlineExceeded,
		},
		"with the flag the token is created and passed": {
			withToken: true,
			wantToken: "example-token",
		},
		"an unreachable tenant API fails before the agent call": {
			withToken:   true,
			providerErr: context.DeadlineExceeded,
			wantError:   context.DeadlineExceeded.Error(),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nodeID, nodeSetID, nodePoolID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			node := db.Node{
				ID: nodeID, Name: "cp-0", ClusterID: clusterID, NodeSetID: nodeSetID, NodePoolID: nodePoolID,
				ControlPlane: true, IP: "10.0.0.20",
			}
			mockDB := &testutil.MockDB{}
			mockDB.On("GetNode", mock.Anything, nodeID).Return(node, nil).Twice()
			mockDB.On("GetNodeSet", mock.Anything, nodeSetID).Return(db.NodeSet{ID: nodeSetID, NodePoolID: nodePoolID}, nil)
			mockDB.On("GetNodePool", mock.Anything, nodePoolID).
				Return(db.NodePool{ID: nodePoolID, ControlPlane: true, Capi: &db.CAPINodePoolProvider{}}, nil)
			mockDB.On("GetCluster", mock.Anything, clusterID).
				Return(db.Cluster{ID: clusterID, ProviderType: db.ProviderTypeCAPI, ControlPlaneVIP: "10.0.0.10"}, nil).Once()

			tenantClient := newKubeVipTenantClient(t)
			fakeAgent := &agenttest.FakeClient{
				ReconcileKubeVipResponse: &nvkeproto.ReconcileKubeVipResponse{Outcome: nvkeproto.ReconcileKubeVipResponse_OUTCOME_UPDATED},
			}
			a := &Activities{
				db:                   mockDB,
				nodeAgentClient:      fakeAgent,
				tenantClientProvider: &fakeTenantClientProvider{tenantClient: tenantClient, err: tt.providerErr},
			}
			testSuite := &testsuite.WorkflowTestSuite{}
			env := testSuite.NewTestActivityEnvironment()
			env.RegisterActivity(a.configureKubeVip)
			_, err := env.ExecuteActivity(a.configureKubeVip, ConfigureKubeVipInput{
				NodeID:                  nodeID,
				WithServiceAccountToken: tt.withToken,
			})
			mockDB.AssertExpectations(t)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				require.Empty(t, fakeAgent.ReconcileKubeVipRequests)
				return
			}
			require.NoError(t, err)
			require.Len(t, fakeAgent.ReconcileKubeVipRequests, 1)
			require.Equal(t, tt.wantToken, fakeAgent.ReconcileKubeVipRequests[0].GetServiceAccountToken())
		})
	}
}

func TestEnsureKubeVipServiceAccountToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenantClient := newKubeVipTenantClient(t)
	// A drifted role is put back to the rules kube-vip needs.
	require.NoError(t, tenantClient.Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: kubeVipRBACName},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}))

	for range 2 {
		token, err := ensureKubeVipServiceAccountToken(ctx, tenantClient)
		require.NoError(t, err)
		require.Equal(t, "example-token", token)
	}

	require.NoError(t, tenantClient.Get(ctx, types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: kubeVipServiceAccountName}, &corev1.ServiceAccount{}))
	var role rbacv1.ClusterRole
	require.NoError(t, tenantClient.Get(ctx, types.NamespacedName{Name: kubeVipRBACName}, &role))
	require.Equal(t, kubeVipRBACRules(), role.Rules)
	var binding rbacv1.ClusterRoleBinding
	require.NoError(t, tenantClient.Get(ctx, types.NamespacedName{Name: kubeVipRBACName}, &binding))
	require.Equal(t, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: kubeVipRBACName}, binding.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: kubeVipServiceAccountName, Namespace: metav1.NamespaceSystem}}, binding.Subjects)
	var secret corev1.Secret
	require.NoError(t, tenantClient.Get(ctx, types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: kubeVipTokenSecretName}, &secret))
	require.Equal(t, corev1.SecretTypeServiceAccountToken, secret.Type)
	require.Equal(t, kubeVipServiceAccountName, secret.Annotations[corev1.ServiceAccountNameKey])
}

// newKubeVipTenantClient seeds the token Secret with data, standing in for
// kube-controller-manager's token controller, which the fake client lacks.
func newKubeVipTenantClient(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, rbacv1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceSystem, Name: kubeVipTokenSecretName},
		Type:       corev1.SecretTypeServiceAccountToken,
		Data:       map[string][]byte{corev1.ServiceAccountTokenKey: []byte("example-token")},
	}).Build()
}
