// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package seedbgp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

func testConfig(t *testing.T) Config {
	return Config{
		Name:  "nvkectl-test-nico-bgp",
		Dir:   filepath.Join(t.TempDir(), "bgp"),
		Image: "quay.io/frrouting/frr@sha256:abc",
		BGP: nicosettings.BGPSpeaker{ASN: 65001, Peers: []nicosettings.BGPPeer{
			{Address: "10.0.0.1", ASN: 65000},
			{Address: "10.0.0.2", ASN: 65001},
		}},
		RouterID:  netip.MustParseAddr("10.0.0.5"),
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.250")},
	}
}

func TestRender(t *testing.T) {
	for name, tt := range map[string]struct {
		edit    func(*Config)
		want    []string
		notWant []string
		err     string
	}{
		"eBGP and iBGP routers, no password": {
			want: []string{
				"router bgp 65001\n bgp router-id 10.0.0.5\n no bgp ebgp-requires-policy\n",
				" neighbor 10.0.0.1 remote-as 65000\n neighbor 10.0.0.1 ebgp-multihop 255\n neighbor 10.0.0.1 timers connect 10\n",
				" neighbor 10.0.0.2 remote-as 65001\n neighbor 10.0.0.2 timers connect 10\n",
				" address-family ipv4 unicast\n  network 192.0.2.10/32\n  network 192.0.2.250/32\n",
				"  neighbor 10.0.0.1 activate\n  neighbor 10.0.0.1 next-hop-self\n  neighbor 10.0.0.1 route-map nvkectl-accept-none in\n",
				"route-map nvkectl-accept-none deny 10\n",
			},
			notWant: []string{"password", "ipv6", "10.0.0.2 ebgp-multihop"},
		},
		"a password on every session": {
			edit: func(c *Config) { c.Password = "s3cr3t!x" },
			want: []string{" neighbor 10.0.0.1 password s3cr3t!x\n", " neighbor 10.0.0.2 password s3cr3t!x\n"},
		},
		"an IPv6 address in its own family": {
			edit: func(c *Config) { c.Addresses = append(c.Addresses, netip.MustParseAddr("2001:db8::1")) },
			want: []string{" address-family ipv6 unicast\n  network 2001:db8::1/128\n  neighbor 10.0.0.1 activate\n"},
		},
		"nothing announced keeps the sessions": {
			edit: func(c *Config) { c.Addresses = nil },
			want: []string{" address-family ipv4 unicast\n  neighbor 10.0.0.1 activate\n"},
		},
		"no router ID leaves it to FRR": {
			edit:    func(c *Config) { c.RouterID = netip.Addr{} },
			notWant: []string{"router-id"},
		},
		"a password with a space": {
			edit: func(c *Config) { c.Password = "two words" },
			err:  "no spaces",
		},
		"no routers": {
			edit: func(c *Config) { c.BGP.Peers = nil },
			err:  "at least one router",
		},
		"a router without an address": {
			edit: func(c *Config) { c.BGP.Peers[0].Address = "router" },
			err:  `router "router"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			if tt.edit != nil {
				tt.edit(&c)
			}
			got, err := Render(c)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			for _, w := range tt.want {
				assert.Contains(t, got, w)
			}
			for _, w := range tt.notWant {
				assert.NotContains(t, got, w)
			}
		})
	}
}

// fakeRuntime is a container runtime holding at most one container.
type fakeRuntime struct {
	exists, running bool
	// sessions is what `show bgp neighbors json` prints.
	sessions string
	calls    []string
}

func (f *fakeRuntime) Run(_ context.Context, _ map[string]string, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	switch {
	case strings.HasPrefix(cmd, "nerdctl inspect"):
		if !f.exists {
			return "no such container", errors.New("exit status 1")
		}
		if f.running {
			return "true\n", nil
		}
		return "false\n", nil
	case strings.HasSuffix(cmd, "show bgp neighbors json"):
		return f.sessions, nil
	}
	f.calls = append(f.calls, cmd)
	switch {
	case strings.HasPrefix(cmd, "nerdctl rm"):
		f.exists, f.running = false, false
	case strings.HasPrefix(cmd, "nerdctl run"):
		f.exists, f.running = true, true
	}
	return "", nil
}

const established = `{"10.0.0.1":{"bgpState":"Established"},"10.0.0.2":{"bgpState":"Active"}}`

func TestSpeakerStart(t *testing.T) {
	c := testConfig(t)
	run := "nerdctl run -d --name nvkectl-test-nico-bgp --network host --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN -v " +
		c.Dir + ":/etc/frr:ro quay.io/frrouting/frr@sha256:abc"
	for name, tt := range map[string]struct {
		rt        fakeRuntime
		sameFiles bool
		want      []string
	}{
		"no speaker yet": {
			want: []string{run},
		},
		"running with the same configuration is kept": {
			rt: fakeRuntime{exists: true, running: true}, sameFiles: true,
		},
		"running with another configuration is replaced": {
			rt:   fakeRuntime{exists: true, running: true},
			want: []string{"nerdctl rm -f nvkectl-test-nico-bgp", run},
		},
		"stopped with the same configuration is replaced": {
			rt: fakeRuntime{exists: true}, sameFiles: true,
			want: []string{"nerdctl rm -f nvkectl-test-nico-bgp", run},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if tt.sameFiles {
				files, err := renderFiles(c)
				require.NoError(t, err)
				require.NoError(t, writeFiles(c.Dir, files))
			} else {
				require.NoError(t, writeFiles(c.Dir, map[string][]byte{configFile: []byte("old")}))
			}
			tt.rt.sessions = established
			s := &Speaker{Runner: &tt.rt, Logger: slog.New(slog.DiscardHandler)}
			require.NoError(t, s.Start(context.Background(), c))
			assert.Equal(t, tt.want, tt.rt.calls)
			conf, err := os.ReadFile(filepath.Join(c.Dir, configFile))
			require.NoError(t, err)
			assert.Contains(t, string(conf), "network 192.0.2.250/32")
			for _, f := range []string{"", configFile, daemonsFile} {
				info, err := os.Stat(filepath.Join(c.Dir, f))
				require.NoError(t, err)
				assert.Zero(t, info.Mode().Perm()&0o077, "%s is readable by others", f)
			}
		})
	}
}

// TestSpeakerStartNoSession: a speaker whose sessions stay down fails, naming each router and its state.
func TestSpeakerStartNoSession(t *testing.T) {
	c := testConfig(t)
	rt := &fakeRuntime{sessions: "% warning\n" + `{"10.0.0.1":{"bgpState":"Active"}}`}
	s := &Speaker{Runner: rt, Logger: slog.New(slog.DiscardHandler), Timeout: time.Millisecond, poll: time.Millisecond}
	err := s.Start(context.Background(), c)
	require.ErrorContains(t, err, "10.0.0.1 (AS 65000) Active, 10.0.0.2 (AS 65001) unknown")
	require.ErrorContains(t, err, nicosettings.BGPPasswordEnv)
}

func TestSpeakerWithdraw(t *testing.T) {
	vip := netip.MustParseAddr("192.0.2.250")
	for name, tt := range map[string]struct {
		running bool
		want    []string
	}{
		"the running speaker drops the route": {
			running: true,
			want: []string{"nerdctl exec nvkectl-test-nico-bgp vtysh -c configure terminal -c router bgp 65001 " +
				"-c address-family ipv4 unicast -c no network 192.0.2.250/32"},
		},
		"no speaker running only rewrites its configuration": {},
	} {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			rt := &fakeRuntime{exists: tt.running, running: tt.running}
			s := &Speaker{Runner: rt, Logger: slog.New(slog.DiscardHandler)}
			c.Addresses = c.Addresses[:1]
			require.NoError(t, s.Withdraw(context.Background(), c, []netip.Addr{vip}))
			assert.Equal(t, tt.want, rt.calls)
			conf, err := os.ReadFile(filepath.Join(c.Dir, configFile))
			require.NoError(t, err)
			assert.NotContains(t, string(conf), "192.0.2.250")
			assert.Contains(t, string(conf), "network 192.0.2.10/32")
		})
	}
}

func TestSpeakerStop(t *testing.T) {
	c := testConfig(t)
	require.NoError(t, writeFiles(c.Dir, map[string][]byte{configFile: []byte("x")}))
	rt := &fakeRuntime{exists: true, running: true}
	s := &Speaker{Runner: rt, Logger: slog.New(slog.DiscardHandler)}
	require.NoError(t, s.Stop(context.Background(), c))
	assert.Equal(t, []string{"nerdctl rm -f nvkectl-test-nico-bgp"}, rt.calls)
	assert.NoDirExists(t, c.Dir)
	rt.calls = nil
	require.NoError(t, s.Stop(context.Background(), c), "a second Stop finds nothing to do")
	assert.Empty(t, rt.calls)
}

type routeRunner struct{ out string }

func (r routeRunner) Run(context.Context, map[string]string, string, ...string) (string, error) {
	return r.out, nil
}

func TestRouterID(t *testing.T) {
	peers := []nicosettings.BGPPeer{{Address: "2001:db8::1"}, {Address: "10.0.0.1"}}
	id, err := RouterID(context.Background(), routeRunner{"10.0.0.1 via 10.0.0.254 dev eth0 src 10.0.0.5 uid 0 \\    cache "}, peers)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("10.0.0.5"), id)

	id, err = RouterID(context.Background(), routeRunner{}, peers[:1])
	require.NoError(t, err)
	assert.False(t, id.IsValid(), "no IPv4 router leaves the router ID to FRR")

	_, err = RouterID(context.Background(), routeRunner{"10.0.0.1 dev eth0"}, peers)
	require.ErrorContains(t, err, "no IPv4 source address")
}
