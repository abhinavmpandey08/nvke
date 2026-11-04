// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/engine"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

func TestSeedPortMappings(t *testing.T) {
	base := []engine.PortMapping{
		{ContainerPort: 31067, HostPort: 67, Protocol: "UDP", ListenAddress: "10.0.0.67"},
		{ContainerPort: 31080, HostPort: 80, Protocol: "TCP", ListenAddress: "10.0.0.80"},
		{ContainerPort: 31880, HostPort: 8080, Protocol: "TCP", ListenAddress: "10.0.0.80"},
		{ContainerPort: 31443, HostPort: 443, Protocol: "TCP", ListenAddress: "10.0.0.43"},
		{ContainerPort: 31388, HostPort: 8388, Protocol: "TCP", ListenAddress: "10.0.0.88"},
	}
	keycloak := engine.PortMapping{ContainerPort: 31082, HostPort: 8082, Protocol: "TCP", ListenAddress: "10.0.0.82"}
	tests := []struct {
		name string
		edit func(*nicosettings.Addresses)
		want []engine.PortMapping
	}{
		{
			name: "every service NICo serves",
			want: append(append([]engine.PortMapping{}, base...), keycloak,
				engine.PortMapping{ContainerPort: 31053, HostPort: 53, Protocol: "UDP", ListenAddress: "10.0.0.53"},
				engine.PortMapping{ContainerPort: 31053, HostPort: 53, Protocol: "TCP", ListenAddress: "10.0.0.53"},
				engine.PortMapping{ContainerPort: 31123, HostPort: 123, Protocol: "UDP", ListenAddress: "10.0.0.123"},
				engine.PortMapping{ContainerPort: 31124, HostPort: 123, Protocol: "UDP", ListenAddress: "10.0.0.124"},
			),
		},
		{
			name: "the site's DNS and NTP, an external identity provider, and no SSH console on the seed",
			edit: func(a *nicosettings.Addresses) { a.DNS, a.NTP, a.Keycloak = "", nil, "" },
			want: base,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testSettings().Addresses
			if tt.edit != nil {
				tt.edit(&a)
			}
			assert.Equal(t, tt.want, SeedPortMappings(a))
		})
	}
}

func TestPublishSeed(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	e := New(nil, kube, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cfg := NewConfig(testSettings(), nicosettings.Secrets{}, ProfileSeed, "standard")

	require.NoError(t, e.publishSeed(ctx, cfg))
	require.NoError(t, e.publishSeed(ctx, cfg), "a rerun updates the Services")

	tests := []struct {
		namespace, name string
		selector        map[string]string
		ports           []corev1.ServicePort
	}{
		{
			namespace: nicoNamespace, name: "nvkectl-nico-pxe",
			selector: map[string]string{"app.kubernetes.io/name": "nico-pxe", "app.kubernetes.io/component": "pxe"},
			ports: []corev1.ServicePort{
				{Name: "tcp-80", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(8080), NodePort: 31080},
				{Name: "tcp-8080", Protocol: corev1.ProtocolTCP, Port: 8080, TargetPort: intstr.FromInt32(8080), NodePort: 31880},
			},
		},
		{
			namespace: nicoNamespace, name: "nvkectl-nico-api",
			selector: map[string]string{"app.kubernetes.io/name": "nico-api", "app.kubernetes.io/component": "api"},
			ports:    []corev1.ServicePort{{Name: "tcp-443", Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromInt32(1079), NodePort: 31443}},
		},
		{
			namespace: restNamespace, name: "nvkectl-keycloak",
			selector: map[string]string{"app": "keycloak"},
			ports:    []corev1.ServicePort{{Name: "tcp-8082", Protocol: corev1.ProtocolTCP, Port: 8082, TargetPort: intstr.FromInt32(8080), NodePort: 31082}},
		},
		{
			namespace: nicoNamespace, name: "nvkectl-unbound",
			selector: map[string]string{
				"app.kubernetes.io/component": "recursive-dns", "app.kubernetes.io/instance": "nico-unbound",
				"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/name": "unbound",
			},
			ports: []corev1.ServicePort{
				{Name: "udp-53", Protocol: corev1.ProtocolUDP, Port: 53, TargetPort: intstr.FromString("dns-udp"), NodePort: 31053},
				{Name: "tcp-53", Protocol: corev1.ProtocolTCP, Port: 53, TargetPort: intstr.FromString("dns-tcp"), NodePort: 31053},
			},
		},
		{
			namespace: nicoNamespace, name: "nvkectl-nico-ntp-1",
			selector: map[string]string{"app.kubernetes.io/name": "nico-ntp", "statefulset.kubernetes.io/pod-name": "nico-ntp-1"},
			ports:    []corev1.ServicePort{{Name: "udp-123", Protocol: corev1.ProtocolUDP, Port: 123, TargetPort: intstr.FromInt32(123), NodePort: 31124}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := kube.CoreV1().Services(tt.namespace).Get(ctx, tt.name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, corev1.ServiceTypeNodePort, s.Spec.Type)
			assert.Equal(t, tt.selector, s.Spec.Selector)
			assert.Equal(t, tt.ports, s.Spec.Ports)
		})
	}

	t.Run("an external identity provider publishes no Keycloak", func(t *testing.T) {
		kube := fake.NewClientset()
		e := New(nil, kube, slog.New(slog.NewTextHandler(io.Discard, nil)))
		settings := testSettings()
		settings.Identity.External = &nicosettings.ExternalIdentity{Issuer: "https://idp.example.com"}
		require.NoError(t, e.publishSeed(ctx, NewConfig(settings, nicosettings.Secrets{}, ProfileSeed, "standard")))
		_, err := kube.CoreV1().Services(restNamespace).Get(ctx, "nvkectl-keycloak", metav1.GetOptions{})
		assert.Error(t, err)
	})
}
