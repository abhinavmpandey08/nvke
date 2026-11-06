// SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activities

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvkeproto "github.com/dsx-ai-factory/nvke/agent/pkg/agent/proto"

	"github.com/dsx-ai-factory/nvke/controller/internal/clients"
	"github.com/dsx-ai-factory/nvke/controller/internal/nodes"
)

const (
	configureKubeVipRunbookName = "configure-kube-vip"
	fmdsBGPPeerAS               = "FROM_FMDS"

	kubeVipServiceAccountName = "kube-vip"
	kubeVipTokenSecretName    = "kube-vip-token" //nolint:gosec // Secret name, not a credential.
	kubeVipRBACName           = "nvke:kube-vip"
	// kubeVipTokenWait bounds the wait for kube-controller-manager's token
	// controller to fill the token Secret within one activity attempt.
	kubeVipTokenWait = 30 * time.Second
)

// kubeVipRBACRules is what kube-vip's service mode needs to serve
// LoadBalancer Services of its class with externalTrafficPolicy Local.
func kubeVipRBACRules() []rbacv1.PolicyRule {
	const update = "update"
	read := []string{"get", "list", "watch"}
	return []rbacv1.PolicyRule{
		// kube-vip writes its vipHost annotation with an update before it sets the status.
		{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "list", "watch", update}},
		{APIGroups: []string{""}, Resources: []string{"services/status"}, Verbs: []string{update, "patch"}},
		{APIGroups: []string{""}, Resources: []string{"endpoints"}, Verbs: read},
		{APIGroups: []string{discoveryv1.GroupName}, Resources: []string{"endpointslices"}, Verbs: read},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: read},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create", update}},
	}
}

type ConfigureKubeVipInput struct {
	NodeID    uuid.UUID
	ClusterID uuid.UUID
	// ConfigureSuperAdmin is used only by the mixed-fleet legacy fallback.
	// Typed reconciliation never creates an elevated kubeconfig.
	ConfigureSuperAdmin bool
	// WithServiceAccountToken says the cluster's API server is reachable, so
	// kube-vip's service account and its token are created there and the token
	// is passed to the node agent, which turns on kube-vip's service mode.
	WithServiceAccountToken bool

	NodeProvisioningConditionMessage    string
	ClusterProvisioningConditionMessage string
}

type ConfigureKubeVipResult struct {
	// ConfigureSuperAdminOutput is populated only by the legacy fallback.
	ConfigureSuperAdminOutput *string
	ConfigureKubeVipOutput    string
}

func (a *Activities) ConfigureKubeVip(ctx context.Context, input ConfigureKubeVipInput) (ConfigureKubeVipResult, error) {
	var conditionMessage string
	var updateCondition func(ctx context.Context, message string) error

	if input.NodeProvisioningConditionMessage != "" {
		conditionMessage = input.NodeProvisioningConditionMessage
		updateCondition = a.nodeProvisioningConditionMessageUpdater(input.NodeID)
	} else if input.ClusterProvisioningConditionMessage != "" {
		conditionMessage = input.ClusterProvisioningConditionMessage
		updateCondition = a.clusterProvisioningConditionMessageUpdater(input.ClusterID)
	}

	conditionUpdateWrapper := ActivityStatusConditionUpdateWrapper[ConfigureKubeVipResult]{
		Message:         conditionMessage,
		UpdateCondition: updateCondition,
		RenderError:     messageForTemporalError,
		ActivityBody: func() (ConfigureKubeVipResult, error) {
			return a.configureKubeVip(ctx, input)
		},
	}

	return conditionUpdateWrapper.Run(ctx)
}

func (a *Activities) configureKubeVip(ctx context.Context, input ConfigureKubeVipInput) (ConfigureKubeVipResult, error) {
	logger := activity.GetLogger(ctx)

	node, err := a.db.GetNode(ctx, input.NodeID)
	if err != nil {
		return ConfigureKubeVipResult{}, fmt.Errorf("failed to get node: %w", err)
	}

	_, nodePool, err := nodes.GetNodeContext(ctx, a.db, node)
	if err != nil {
		return ConfigureKubeVipResult{}, fmt.Errorf("failed to get node context: %w", err)
	}

	cluster, err := a.GetClusterForNode(ctx, node.ID)
	if err != nil {
		return ConfigureKubeVipResult{}, fmt.Errorf("failed to get cluster: %w", err)
	}

	if !nodePool.ControlPlane {
		// Not a control plane node, so we don't need to configure KubeVip
		return ConfigureKubeVipResult{}, nil
	}

	if cluster.ControlPlaneVIP == "" {
		// No control plane VIP, so we don't need to configure KubeVip
		return ConfigureKubeVipResult{}, nil
	}

	const kubeVipASN = 65100

	// Native-networking sites learn the per-node DPU ASN from FMDS. The
	// site-scoped endpoint supports every infrastructure provider; VPC prefixes
	// remain a compatibility signal for existing NICo deployments.
	const defaultBGPPeerASN uint32 = 4294967000
	bgpPeerAS := "4294967000"
	bgpPeerASN := defaultBGPPeerASN
	bgpPeerASNSource := nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_STATIC
	fmdsEndpoint := a.cfg.KubeVipFMDSEndpoint
	if fmdsEndpoint != "" {
		bgpPeerAS = fmdsBGPPeerAS
		bgpPeerASN = 0
		bgpPeerASNSource = nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_FMDS
	} else {
		provider, err := clients.GetProviderClient(cluster)
		if err != nil {
			return ConfigureKubeVipResult{}, err
		}
		useFMDS, err := provider.KubeVIPConfig().UsesFMDSBGPPeerASN(nodePool)
		if err != nil {
			return ConfigureKubeVipResult{}, err
		}
		if useFMDS {
			bgpPeerAS = fmdsBGPPeerAS
			bgpPeerASN = 0
			bgpPeerASNSource = nvkeproto.ReconcileKubeVipRequest_BGP_PEER_ASN_SOURCE_FMDS
		}
	}

	logger.Info("Configuring kube-vip on control plane node",
		"clusterID", cluster.ID,
		"controlPlaneVIP", cluster.ControlPlaneVIP,
		"nodeID", node.ID,
		"nodeIP", node.IP,
		"kubeVipASN", kubeVipASN,
		"bgpPeerAS", bgpPeerAS,
		"withServiceAccountToken", input.WithServiceAccountToken,
	)

	// Assume host ID is the same as node ID by convention
	hostID := node.ID
	heartbeatCancel := startActivityHeartbeat(ctx)
	defer heartbeatCancel()
	var serviceAccountToken string
	if input.WithServiceAccountToken {
		tenantClient, err := a.tenantClientForCluster(ctx, cluster)
		if err != nil {
			return ConfigureKubeVipResult{}, err
		}
		if serviceAccountToken, err = ensureKubeVipServiceAccountToken(ctx, tenantClient); err != nil {
			return ConfigureKubeVipResult{}, err
		}
	}
	reconcileResponse, err := a.nodeAgentClient.ReconcileKubeVip(ctx, node, &nvkeproto.ReconcileKubeVipRequest{
		VipAddress:          cluster.ControlPlaneVIP,
		BgpAsn:              kubeVipASN,
		NodeIp:              node.IP,
		BgpPeerAsnSource:    bgpPeerASNSource,
		BgpPeerAsn:          bgpPeerASN,
		FmdsEndpoint:        fmdsEndpoint,
		ServiceAccountToken: serviceAccountToken,
	})
	if err == nil {
		if reconcileResponse == nil {
			return ConfigureKubeVipResult{}, fmt.Errorf("node agent returned an empty kube-vip reconciliation response")
		}
		switch reconcileResponse.GetOutcome() {
		case nvkeproto.ReconcileKubeVipResponse_OUTCOME_UNSPECIFIED:
			return ConfigureKubeVipResult{}, fmt.Errorf("node agent returned an unspecified kube-vip reconciliation outcome")
		case nvkeproto.ReconcileKubeVipResponse_OUTCOME_CREATED,
			nvkeproto.ReconcileKubeVipResponse_OUTCOME_UPDATED,
			nvkeproto.ReconcileKubeVipResponse_OUTCOME_UNCHANGED:
			return ConfigureKubeVipResult{
				ConfigureKubeVipOutput: fmt.Sprintf(
					"kube-vip %s: manifest=%s interface=%s peer=%s peerASN=%d kubeconfig=%s kubeconfigChanged=%t cleanedInterfaces=%v",
					reconcileResponse.GetOutcome(),
					reconcileResponse.GetManifestPath(),
					reconcileResponse.GetBgpInterface(),
					reconcileResponse.GetBgpPeerAddress(),
					reconcileResponse.GetBgpPeerAsn(),
					reconcileResponse.GetKubeconfigPath(),
					reconcileResponse.GetKubeconfigChanged(),
					reconcileResponse.GetCleanedInterfaces(),
				),
			}, nil
		default:
			return ConfigureKubeVipResult{}, fmt.Errorf("node agent returned invalid kube-vip reconciliation outcome %s", reconcileResponse.GetOutcome())
		}
	}
	if status.Code(err) != codes.Unimplemented {
		return ConfigureKubeVipResult{}, fmt.Errorf("failed to reconcile kube-vip on node %s: %w", node.Name, err)
	}
	logger.Info("ReconcileKubeVip is unavailable; falling back to legacy kube-vip runbooks",
		"nodeID", node.ID,
		"nodeName", node.Name,
	)

	// Keep elevated kubeconfig generation below the Unimplemented gate. The
	// typed path is deliberately credential-less; super-admin exists only to
	// support agents that still require the legacy runbook.
	var configureSuperAdminOutput *string
	if input.ConfigureSuperAdmin {
		configureSuperAdminResult, err := a.ExecuteHostRunbook(ctx, ExecuteHostRunbookInput{
			HostID:      hostID,
			RunbookName: "configure-super-admin",
			RunbookEnv:  map[string]string{},
		})
		if err != nil {
			return ConfigureKubeVipResult{}, fmt.Errorf("failed to configure super-admin kubeconfig: %w", err)
		}
		configureSuperAdminOutput = &configureSuperAdminResult.Output
	}

	configureKubeVipResult, err := a.ExecuteHostRunbook(ctx, ExecuteHostRunbookInput{
		HostID:      hostID,
		RunbookName: configureKubeVipRunbookName,
		RunbookEnv: map[string]string{
			"VIP_ADDRESS":   cluster.ControlPlaneVIP,
			"BGP_AS":        fmt.Sprintf("%d", kubeVipASN),
			"BGP_PEER_AS":   bgpPeerAS,
			"FMDS_ENDPOINT": fmdsEndpoint,
			"NODE_IP":       node.IP,
		},
	})
	if err != nil {
		return ConfigureKubeVipResult{}, fmt.Errorf("failed to configure kube-vip: %w", err)
	}

	return ConfigureKubeVipResult{
		ConfigureSuperAdminOutput: configureSuperAdminOutput,
		ConfigureKubeVipOutput:    configureKubeVipResult.Output,
	}, nil
}

// ensureKubeVipServiceAccountToken creates or updates kube-system/kube-vip,
// its RBAC and its token Secret in the workload cluster, then returns the
// token. The token is a credential: callers must never log it.
func ensureKubeVipServiceAccountToken(ctx context.Context, tenantClient ctrlclient.Client) (string, error) {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: kubeVipServiceAccountName, Namespace: metav1.NamespaceSystem},
	}
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kubeVipRBACName}}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: kubeVipRBACName}}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: kubeVipTokenSecretName, Namespace: metav1.NamespaceSystem},
	}
	objects := []struct {
		object ctrlclient.Object
		mutate func()
	}{
		{serviceAccount, func() {}},
		{role, func() { role.Rules = kubeVipRBACRules() }},
		{binding, func() {
			binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: kubeVipRBACName}
			binding.Subjects = []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      kubeVipServiceAccountName,
				Namespace: metav1.NamespaceSystem,
			}}
		}},
		{secret, func() {
			secret.Type = corev1.SecretTypeServiceAccountToken
			metav1.SetMetaDataAnnotation(&secret.ObjectMeta, corev1.ServiceAccountNameKey, kubeVipServiceAccountName)
		}},
	}
	for _, current := range objects {
		if _, err := controllerutil.CreateOrUpdate(ctx, tenantClient, current.object, func() error {
			current.mutate()
			return nil
		}); err != nil {
			return "", fmt.Errorf("applying kube-vip %T %s: %w", current.object, current.object.GetName(), err)
		}
	}

	// kube-controller-manager's token controller fills the Secret asynchronously.
	key := ctrlclient.ObjectKeyFromObject(secret)
	if err := wait.PollUntilContextTimeout(ctx, time.Second, kubeVipTokenWait, true, func(ctx context.Context) (bool, error) {
		if err := tenantClient.Get(ctx, key, secret); err != nil {
			return false, err
		}
		return len(secret.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}); err != nil {
		return "", fmt.Errorf("waiting for the token in Secret %s: %w", key, err)
	}
	return string(secret.Data[corev1.ServiceAccountTokenKey]), nil
}
