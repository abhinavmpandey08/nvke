// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package seedbgp runs the bootstrap host's BGP speaker: FRR in a
// host-network container that announces NICo's service addresses as host
// routes, next hop itself, to the routers bgp.seed names, and accepts no
// routes from them.
package seedbgp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/engine"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

const (
	// DefaultTimeout bounds the wait for a session to come up.
	DefaultTimeout = 3 * time.Minute
	pollInterval   = 5 * time.Second
	// maxPasswordLength is the longest TCP MD5 key Linux takes.
	maxPasswordLength = 80
	// acceptNone is the route map every session takes routes in through.
	acceptNone = "nvkectl-accept-none"
)

// The files the speaker's directory holds, mounted read-only at /etc/frr.
const (
	configFile  = "frr.conf"
	daemonsFile = "daemons"
	vtyshFile   = "vtysh.conf"
)

// daemons starts bgpd, which the image leaves off, beside the daemons FRR always runs.
const daemons = `bgpd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
`

// vtyshConf makes vtysh read frr.conf as the one configuration of every daemon.
const vtyshConf = "service integrated-vtysh-config\n"

// Config is the speaker's container and what it announces.
type Config struct {
	// Name is the container's name. Required.
	Name string
	// Dir holds the speaker's configuration, mounted read-only at /etc/frr.
	// It holds the BGP password, so it is private to the user nvkectl runs as. Required.
	Dir string
	// Image is the FRR image. Required.
	Image string
	// BGP is the speaker's ASN and the routers it peers with.
	BGP nicosettings.BGPSpeaker
	// Password is the TCP MD5 password of every session; empty for none.
	Password string
	// RouterID is the speaker's BGP router ID. Optional: FRR picks one when it is not an IPv4 address.
	RouterID netip.Addr
	// Addresses are announced, each as a /32 or /128 route.
	Addresses []netip.Addr
}

// Render returns the FRR configuration of c: one session per router, routes
// for Addresses with this host as next hop, and a route map that accepts no
// route from any router.
func Render(c Config) (string, error) {
	if c.BGP.ASN == 0 || len(c.BGP.Peers) == 0 {
		return "", errors.New("seedbgp: an ASN and at least one router are required")
	}
	if len(c.Password) > maxPasswordLength || strings.ContainsFunc(c.Password, unicode.IsSpace) {
		return "", fmt.Errorf("seedbgp: the BGP password must be at most %d characters with no spaces", maxPasswordLength)
	}
	peers := make([]netip.Addr, len(c.BGP.Peers))
	for i, p := range c.BGP.Peers {
		addr, err := netip.ParseAddr(p.Address)
		if err != nil || p.ASN == 0 {
			return "", fmt.Errorf("seedbgp: router %q needs an IP address and an ASN", p.Address)
		}
		peers[i] = addr
	}
	var b strings.Builder
	fmt.Fprintf(&b, "frr defaults traditional\nhostname %s\nlog stdout informational\n!\n", c.Name)
	fmt.Fprintf(&b, "route-map %s deny 10\nexit\n!\n", acceptNone)
	fmt.Fprintf(&b, "router bgp %d\n", c.BGP.ASN)
	if c.RouterID.Is4() {
		fmt.Fprintf(&b, " bgp router-id %s\n", c.RouterID)
	}
	// The routes are this speaker's own, so eBGP sends them without an outbound policy;
	// and they are announced whether or not the address is on this host.
	b.WriteString(" no bgp ebgp-requires-policy\n no bgp default ipv4-unicast\n no bgp network import-check\n")
	for i, p := range c.BGP.Peers {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", peers[i], p.ASN)
		if c.Password != "" {
			fmt.Fprintf(&b, " neighbor %s password %s\n", peers[i], c.Password)
		}
		if p.ASN != c.BGP.ASN {
			fmt.Fprintf(&b, " neighbor %s ebgp-multihop 255\n", peers[i])
		}
		// FRR's default is two minutes; a router configured after the speaker starts is reached sooner.
		fmt.Fprintf(&b, " neighbor %s timers connect 10\n", peers[i])
	}
	families := []struct {
		name   string
		v4     bool
		always bool
	}{{"ipv4", true, true}, {"ipv6", false, false}}
	for _, f := range families {
		var routes []netip.Addr
		for _, a := range c.Addresses {
			if a.Is4() == f.v4 {
				routes = append(routes, a)
			}
		}
		// IPv4 is always activated, so the sessions stay up with nothing to announce.
		if len(routes) == 0 && !f.always {
			continue
		}
		fmt.Fprintf(&b, " !\n address-family %s unicast\n", f.name)
		for _, a := range routes {
			fmt.Fprintf(&b, "  network %s\n", netip.PrefixFrom(a, a.BitLen()))
		}
		for _, p := range peers {
			fmt.Fprintf(&b, "  neighbor %s activate\n  neighbor %s next-hop-self\n  neighbor %s route-map %s in\n", p, p, p, acceptNone)
		}
		b.WriteString(" exit-address-family\n")
	}
	b.WriteString("exit\n!\n")
	return b.String(), nil
}

// Speaker runs the speaker's container through the container runtime the
// bootstrap engine uses.
type Speaker struct {
	// Runner runs the container runtime. Required.
	Runner engine.CommandRunner
	// Logger receives progress; slog.Default when nil.
	Logger *slog.Logger
	// Timeout bounds the wait for a session to come up; DefaultTimeout when zero.
	Timeout time.Duration
	poll    time.Duration
}

// Start runs the speaker with c and waits until a session with one of the
// routers is Established. A speaker already running with the same
// configuration is kept; one with another is replaced.
func (s *Speaker) Start(ctx context.Context, c Config) error {
	files, err := renderFiles(c)
	if err != nil {
		return err
	}
	exists, running := s.state(ctx, c.Name)
	if !running || !sameFiles(c.Dir, files) {
		if err := writeFiles(c.Dir, files); err != nil {
			return err
		}
		if exists {
			if out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "rm", "-f", c.Name); err != nil {
				return fmt.Errorf("removing the BGP speaker %s: %w: %s", c.Name, err, strings.TrimSpace(out))
			}
		}
		if out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "run", "-d", "--name", c.Name, "--network", "host",
			"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_ADMIN",
			"-v", c.Dir+":/etc/frr:ro", c.Image); err != nil {
			return fmt.Errorf("starting the BGP speaker %s from %s: %w: %s", c.Name, c.Image, err, strings.TrimSpace(out))
		}
		s.log().Info("started the BGP speaker", "container", c.Name, "asn", c.BGP.ASN, "announces", c.Addresses)
	}
	return s.waitEstablished(ctx, c)
}

// Withdraw stops announcing gone. c is the speaker's configuration without
// them: the running speaker drops their routes and keeps its sessions, and
// c is what a later Start compares with.
func (s *Speaker) Withdraw(ctx context.Context, c Config, gone []netip.Addr) error {
	files, err := renderFiles(c)
	if err != nil {
		return err
	}
	if _, running := s.state(ctx, c.Name); running {
		for _, a := range gone {
			family := "ipv4"
			if !a.Is4() {
				family = "ipv6"
			}
			if out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "exec", c.Name, "vtysh",
				"-c", "configure terminal", "-c", fmt.Sprintf("router bgp %d", c.BGP.ASN),
				"-c", "address-family "+family+" unicast", "-c", "no network "+netip.PrefixFrom(a, a.BitLen()).String()); err != nil {
				return fmt.Errorf("withdrawing %s from the BGP speaker %s: %w: %s", a, c.Name, err, strings.TrimSpace(out))
			}
			s.log().Info("the BGP speaker withdrew an address", "container", c.Name, "address", a)
		}
	}
	// After the routes are gone: a file that still lists them makes the next Start replace the speaker.
	return writeFiles(c.Dir, files)
}

// Stop removes the speaker, which withdraws every route, and its directory.
func (s *Speaker) Stop(ctx context.Context, c Config) error {
	if exists, _ := s.state(ctx, c.Name); exists {
		if out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "rm", "-f", c.Name); err != nil {
			return fmt.Errorf("removing the BGP speaker %s: %w: %s", c.Name, err, strings.TrimSpace(out))
		}
		s.log().Info("stopped the BGP speaker", "container", c.Name)
	}
	if err := os.RemoveAll(c.Dir); err != nil {
		return fmt.Errorf("removing the BGP speaker's configuration: %w", err)
	}
	return nil
}

// state reports whether the container name exists and whether it runs. A
// container the runtime cannot inspect is taken as absent.
func (s *Speaker) state(ctx context.Context, name string) (exists, running bool) {
	out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		return false, false
	}
	return true, strings.TrimSpace(out) == "true"
}

// waitEstablished waits until a session of c's speaker is Established.
func (s *Speaker) waitEstablished(ctx context.Context, c Config) error {
	timeout, poll := s.Timeout, s.poll
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if poll <= 0 {
		poll = pollInterval
	}
	deadline := time.Now().Add(timeout)
	var states map[string]string
	var last error
	for {
		states, last = s.sessions(ctx, c.Name)
		for peer, state := range states {
			if state == "Established" {
				s.log().Info("the BGP speaker's session is up", "container", c.Name, "router", peer)
				return nil
			}
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	report := make([]string, 0, len(c.BGP.Peers))
	for _, p := range c.BGP.Peers {
		state := states[p.Address]
		if state == "" {
			state = "unknown"
		}
		report = append(report, fmt.Sprintf("%s (AS %d) %s", p.Address, p.ASN, state))
	}
	err := fmt.Errorf("no BGP session of the bootstrap host's speaker %s (AS %d) came up within %s: %s; "+
		"each router must peer with this host from AS %d, with %s as its password when it is set",
		c.Name, c.BGP.ASN, timeout, strings.Join(report, ", "), c.BGP.ASN, nicosettings.BGPPasswordEnv)
	if last != nil {
		return fmt.Errorf("%w: %w", err, last)
	}
	return err
}

// sessions returns each configured router's session state, from `show bgp neighbors json`.
func (s *Speaker) sessions(ctx context.Context, name string) (map[string]string, error) {
	out, err := s.Runner.Run(ctx, nil, engine.RuntimeCLI, "exec", name, "vtysh", "-c", "show bgp neighbors json")
	if err != nil {
		return nil, fmt.Errorf("reading the BGP speaker's sessions: %w: %s", err, strings.TrimSpace(out))
	}
	// vtysh may print a warning before the JSON.
	if i := strings.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	var neighbors map[string]struct {
		State string `json:"bgpState"`
	}
	if err := json.Unmarshal([]byte(out), &neighbors); err != nil {
		return nil, fmt.Errorf("reading the BGP speaker's sessions: %w", err)
	}
	states := make(map[string]string, len(neighbors))
	for peer, n := range neighbors {
		states[peer] = n.State
	}
	return states, nil
}

func (s *Speaker) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// RouterID returns the IPv4 address the bootstrap host reaches the first IPv4
// router of peers from, from `ip -o route get`, as a router ID that does not
// change when a service address leaves the host. It is the zero Addr when no
// router has an IPv4 address.
func RouterID(ctx context.Context, runner engine.CommandRunner, peers []nicosettings.BGPPeer) (netip.Addr, error) {
	i := slices.IndexFunc(peers, func(p nicosettings.BGPPeer) bool {
		a, err := netip.ParseAddr(p.Address)
		return err == nil && a.Is4()
	})
	if i < 0 {
		return netip.Addr{}, nil
	}
	out, err := runner.Run(ctx, nil, "ip", "-o", "route", "get", peers[i].Address)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("finding the bootstrap host's route to BGP router %s: %w: %s", peers[i].Address, err, strings.TrimSpace(out))
	}
	// "<dst> via <gw> dev <dev> src <addr> uid 0 \    cache"
	f := strings.Fields(out)
	if j := slices.Index(f, "src"); j >= 0 && j+1 < len(f) {
		if a, err := netip.ParseAddr(f[j+1]); err == nil && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("the bootstrap host's route to BGP router %s names no IPv4 source address: %s", peers[i].Address, strings.TrimSpace(out))
}

// renderFiles returns the files of c's directory, by name.
func renderFiles(c Config) (map[string][]byte, error) {
	if c.Name == "" || c.Dir == "" || c.Image == "" {
		return nil, errors.New("seedbgp: Name, Dir and Image are required")
	}
	conf, err := Render(c)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{configFile: []byte(conf), daemonsFile: []byte(daemons), vtyshFile: []byte(vtyshConf)}, nil
}

// sameFiles reports whether dir holds exactly files.
func sameFiles(dir string, files map[string][]byte) bool {
	for name, want := range files {
		if have, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(have, want) {
			return false
		}
	}
	return true
}

// writeFiles writes files to dir, each readable by its owner only.
func writeFiles(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the BGP speaker's directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("creating the BGP speaker's directory: %w", err)
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("writing the BGP speaker's configuration: %w", err)
		}
		// WriteFile keeps the mode of a file that already exists.
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("writing the BGP speaker's configuration: %w", err)
		}
	}
	return nil
}
