// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/engine"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// Node ports NICo's services are published on in the bootstrap cluster. The
// NVKE stack holds ports in the 30000 range.
const (
	dhcpNodePort     = 31067
	pxeNodePort      = 31080
	pxeAltNodePort   = 31880
	apiNodePort      = 31443
	restNodePort     = 31388
	keycloakNodePort = 31082
	dnsNodePort      = 31053
	// ntpNodePort is the first NTP address's; each further address takes the next port.
	ntpNodePort = 31123
)

// seedPort is one service port published on the bootstrap host: Kind maps
// address:port to nodePort, where the NodePort Service service forwards it to
// the pods selector picks.
type seedPort struct {
	namespace, service string
	selector           map[string]string
	port, nodePort     int32
	target             intstr.IntOrString
	protocol           corev1.Protocol
	address            string
}

// seedPorts lists the ports published for addresses a, from the selectors and
// target ports of the charts' own external Services.
func seedPorts(a nicosettings.Addresses) []seedPort {
	dhcp := map[string]string{"app.kubernetes.io/name": "nico-dhcp", "app.kubernetes.io/component": "dhcp"}
	pxe := map[string]string{"app.kubernetes.io/name": "nico-pxe", "app.kubernetes.io/component": "pxe"}
	api := map[string]string{"app.kubernetes.io/name": "nico-api", "app.kubernetes.io/component": "api"}
	rest := map[string]string{"app": "nico-rest-api", "app.kubernetes.io/name": "nico-rest-api", "app.kubernetes.io/component": "api"}
	keycloak := map[string]string{"app": "keycloak"}
	rp, kp := a.RESTEndpoint(), a.KeycloakEndpoint()
	ports := []seedPort{
		{nicoNamespace, "nvkectl-nico-dhcp", dhcp, 67, dhcpNodePort, intstr.FromInt32(67), corev1.ProtocolUDP, a.DHCP},
		{nicoNamespace, "nvkectl-nico-pxe", pxe, 80, pxeNodePort, intstr.FromInt32(8080), corev1.ProtocolTCP, a.PXE},
		{nicoNamespace, "nvkectl-nico-pxe", pxe, 8080, pxeAltNodePort, intstr.FromInt32(8080), corev1.ProtocolTCP, a.PXE},
		{nicoNamespace, "nvkectl-nico-api", api, 443, apiNodePort, intstr.FromInt32(1079), corev1.ProtocolTCP, a.API},
		{restNamespace, "nvkectl-nico-rest-api", rest, int32(rp.Port()), restNodePort, intstr.FromInt32(8388), corev1.ProtocolTCP, rp.Addr().String()},
		{restNamespace, "nvkectl-keycloak", keycloak, int32(kp.Port()), keycloakNodePort, intstr.FromInt32(8080), corev1.ProtocolTCP, kp.Addr().String()},
	}
	if a.DNS != "" {
		unbound := map[string]string{
			"app.kubernetes.io/component":  "recursive-dns",
			"app.kubernetes.io/instance":   "nico-unbound",
			"app.kubernetes.io/managed-by": "Helm",
			"app.kubernetes.io/name":       "unbound",
		}
		ports = append(ports,
			seedPort{nicoNamespace, "nvkectl-unbound", unbound, 53, dnsNodePort, intstr.FromString("dns-udp"), corev1.ProtocolUDP, a.DNS},
			seedPort{nicoNamespace, "nvkectl-unbound", unbound, 53, dnsNodePort, intstr.FromString("dns-tcp"), corev1.ProtocolTCP, a.DNS})
	}
	// Each NTP address is one nico-ntp replica's.
	for i, ip := range a.NTP {
		pod := map[string]string{"app.kubernetes.io/name": "nico-ntp", "statefulset.kubernetes.io/pod-name": fmt.Sprintf("nico-ntp-%d", i)}
		ports = append(ports, seedPort{
			nicoNamespace, fmt.Sprintf("nvkectl-nico-ntp-%d", i), pod,
			123, ntpNodePort + int32(i), intstr.FromInt32(123), corev1.ProtocolUDP, ip,
		})
	}
	return ports
}

// SeedPortMappings returns the Kind port mappings that publish NICo's services
// on their addresses on the bootstrap host, each to the node port the
// bootstrap cluster's NICo listens on.
func SeedPortMappings(a nicosettings.Addresses) []engine.PortMapping {
	var mappings []engine.PortMapping
	for _, p := range seedPorts(a) {
		mappings = append(mappings, engine.PortMapping{
			ContainerPort: p.nodePort,
			HostPort:      p.port,
			Protocol:      string(p.protocol),
			ListenAddress: p.address,
		})
	}
	return mappings
}

// SeedLoopback returns, for each of REST and Keycloak whose address is vip, a
// Kind port mapping of its node port on the bootstrap host's 127.0.0.1, and a
// dialer that connects to its published address and port through that
// mapping, so nvkectl reaches it through the bootstrap cluster once the site's
// kube-vip holds vip. Requests keep the published address as their host, so
// Keycloak's tokens keep the issuer REST accepts. It returns no mappings and a
// nil dialer when neither is on vip.
func SeedLoopback(a nicosettings.Addresses, vip netip.Addr) ([]engine.PortMapping, func(ctx context.Context, network, addr string) (net.Conn, error)) {
	var mappings []engine.PortMapping
	via := map[string]string{}
	for _, s := range []struct {
		published netip.AddrPort
		nodePort  int32
	}{{a.RESTEndpoint(), restNodePort}, {a.KeycloakEndpoint(), keycloakNodePort}} {
		if !vip.IsValid() || s.published.Addr() != vip {
			continue
		}
		mappings = append(mappings, engine.PortMapping{ContainerPort: s.nodePort, HostPort: s.nodePort, ListenAddress: "127.0.0.1"})
		via[s.published.String()] = net.JoinHostPort("127.0.0.1", fmt.Sprint(s.nodePort))
	}
	if len(mappings) == 0 {
		return nil, nil
	}
	var d net.Dialer
	return mappings, func(ctx context.Context, network, addr string) (net.Conn, error) {
		if local, ok := via[addr]; ok {
			addr = local
		}
		return d.DialContext(ctx, network, addr)
	}
}

// The class of the LoadBalancer Services the site's kube-vip handles, and the
// annotation naming the address it announces for one.
const (
	kubeVIPClass         = "kube-vip.io/kube-vip-class"
	kubeVIPIPsAnnotation = "kube-vip.io/loadbalancerIPs"
)

// publishSeed creates the NodePort Services the seed's port mappings reach,
// and their namespaces when they do not exist yet, so it can run before the
// services it publishes are installed.
func (e *Engine) publishSeed(ctx context.Context, cfg Config) error {
	if cfg.Settings == nil {
		return errors.New("nicodeploy: Settings is required to publish NICo")
	}
	services := seedServices(cfg.Settings.Addresses)
	if err := e.applyServices(ctx, services); err != nil {
		return err
	}
	e.log.Info("NICo's services are published on the bootstrap host", "services", len(services))
	return nil
}

// PublishSite publishes NICo's services on their addresses on the site
// cluster, as cfg describes it with ProfileSite: each is a LoadBalancer
// Service of kube-vip's class, pinned to its address, with
// externalTrafficPolicy Local. REST or Keycloak on cfg.ControlPlaneVIP is
// instead a NodePort Service on its own port, reached on the VIP kube-vip
// already announces. It creates the namespaces that do not exist yet and can
// be run again. The bootstrap host must have withdrawn the addresses first.
func (e *Engine) PublishSite(ctx context.Context, cfg Config) error {
	if cfg.Settings == nil {
		return errors.New("nicodeploy: Settings is required to publish NICo")
	}
	services := siteServices(cfg.Settings.Addresses, cfg.ControlPlaneVIP)
	if err := e.applyServices(ctx, services); err != nil {
		return err
	}
	e.log.Info("NICo's services are published on the site cluster", "services", len(services))
	return nil
}

// seedServices are the NodePort Services that publish seedPorts on the
// bootstrap host.
func seedServices(a nicosettings.Addresses) []*corev1.Service {
	var services []*corev1.Service
	byName := map[string]*corev1.Service{}
	for _, p := range seedPorts(a) {
		s := byName[p.namespace+"/"+p.service]
		if s == nil {
			s = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: p.namespace, Name: p.service},
				Spec: corev1.ServiceSpec{
					Type:     corev1.ServiceTypeNodePort,
					Selector: p.selector,
					// Kind runs one node, so every endpoint is local and the client's address is kept.
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				},
			}
			byName[p.namespace+"/"+p.service] = s
			services = append(services, s)
		}
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
			Name:       fmt.Sprintf("%s-%d", strings.ToLower(string(p.protocol)), p.port),
			Protocol:   p.protocol,
			Port:       p.port,
			TargetPort: p.target,
			NodePort:   p.nodePort,
		})
	}
	return services
}

// siteServices are the Services that publish the same ports on the site
// cluster: LoadBalancer Services of kube-vip's class pinned to their
// addresses, except a NodePort Service on its own ports for an address that is
// controlPlaneVIP.
func siteServices(a nicosettings.Addresses, controlPlaneVIP string) []*corev1.Service {
	vip, _ := netip.ParseAddr(controlPlaneVIP)
	address := map[string]string{}
	for _, p := range seedPorts(a) {
		address[p.namespace+"/"+p.service] = p.address
	}
	services := seedServices(a)
	for _, s := range services {
		ip := address[s.Namespace+"/"+s.Name]
		if addr, err := netip.ParseAddr(ip); err == nil && addr == vip {
			// Every control-plane node announces the VIP over BGP, and need not run the service's pods.
			s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
			for i := range s.Spec.Ports {
				s.Spec.Ports[i].NodePort = s.Spec.Ports[i].Port
			}
			continue
		}
		class := kubeVIPClass
		s.Annotations = map[string]string{kubeVIPIPsAnnotation: ip}
		s.Spec.Type = corev1.ServiceTypeLoadBalancer
		s.Spec.LoadBalancerClass = &class
		for i := range s.Spec.Ports {
			s.Spec.Ports[i].NodePort = 0
		}
	}
	return services
}

// applyServices applies each of services, creating its namespace when it does not exist yet.
func (e *Engine) applyServices(ctx context.Context, services []*corev1.Service) error {
	for _, s := range services {
		if err := e.ensureNamespace(ctx, s.Namespace, nil, nil); err != nil {
			return err
		}
		if err := e.applyService(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// applyService creates s, or replaces the spec of the Service of its name
// while keeping its cluster IP, and adds s's annotations to it.
func (e *Engine) applyService(ctx context.Context, s *corev1.Service) error {
	services := e.kube.CoreV1().Services(s.Namespace)
	_, err := services.Create(ctx, s, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := services.Get(ctx, s.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("reading Service %s/%s: %w", s.Namespace, s.Name, getErr)
		}
		existing.Spec.Type = s.Spec.Type
		existing.Spec.Selector = s.Spec.Selector
		existing.Spec.Ports = s.Spec.Ports
		existing.Spec.ExternalTrafficPolicy = s.Spec.ExternalTrafficPolicy
		existing.Spec.LoadBalancerClass = s.Spec.LoadBalancerClass
		existing.Annotations = merge(existing.Annotations, s.Annotations)
		_, err = services.Update(ctx, existing, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("publishing Service %s/%s%s: %w", s.Namespace, s.Name, e.nodePortHolders(ctx, s), err)
	}
	return nil
}

// nodePortHolders names the other Services that hold one of s's node ports,
// the usual reason a fixed node port is refused.
func (e *Engine) nodePortHolders(ctx context.Context, s *corev1.Service) string {
	want := map[int32]bool{}
	for _, p := range s.Spec.Ports {
		want[p.NodePort] = true
	}
	all, err := e.kube.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}
	var holders []string
	for _, other := range all.Items {
		if other.Namespace == s.Namespace && other.Name == s.Name {
			continue
		}
		taken := want[other.Spec.HealthCheckNodePort]
		for _, p := range other.Spec.Ports {
			taken = taken || want[p.NodePort]
		}
		if taken {
			holders = append(holders, other.Namespace+"/"+other.Name)
		}
	}
	if len(holders) == 0 {
		return ""
	}
	return " (its node ports are held by Service " + strings.Join(holders, ", ") + ")"
}
