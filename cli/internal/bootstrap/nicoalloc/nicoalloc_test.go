// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicoalloc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

const (
	testSite   = "site-1"
	testTenant = "tenant-1"
	// testKey and testKeyFingerprint are a throwaway public key and the
	// fingerprint `ssh-keygen -lf` prints for it.
	testKey            = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHzZXuE+t/z9qH8OKZb2VM1rqjO303ddEwYrMlqsXGGA nvkectl-test"
	testKeyFingerprint = "S+578gqGCMrr5kqdeWvnnrEIVp3amwn+culd1Rsgx8Q"
	otherKey           = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHrbWIUvbXdnlJvMg5jdHf9TpwP0rUu6FbqUdnwKBY+ other"
)

type obj = map[string]any

// fakeNICo is the slice of NICo REST Ensure calls, kept in memory.
type fakeNICo struct {
	mu        sync.Mutex
	nextID    int
	enabled   bool
	expected  []obj
	machines  []obj
	ipBlocks  []obj
	fullBlock string // allocating from this IP block answers 409
	errorVPC  bool   // VPCs report Error
	objects   map[string][]obj
	requests  []string
	bodies    map[string][]obj
	readCount map[string]int
}

func newFakeNICo() *fakeNICo {
	cpu := obj{"type": "CPU", "name": "Xeon 6354", "cores": 18, "count": 2}
	return &fakeNICo{
		enabled: true,
		expected: []obj{
			{"chassisSerialNumber": "s1", "machineId": "m1"},
			{"chassisSerialNumber": "s2", "machineId": "m2"},
			{"chassisSerialNumber": "s3", "machineId": nil},
		},
		machines: []obj{
			{"id": "m1", "status": "Ready", "instanceTypeId": nil, "machineCapabilities": []obj{
				cpu,
				{"type": "Memory", "name": "DDR5", "capacity": "512GiB", "count": 16},
				{"type": "GPU", "name": "H100", "count": 8},
				{"type": "CPU", "name": "trailing ", "count": 1},
			}},
			{"id": "m2", "status": "Ready", "instanceTypeId": nil, "machineCapabilities": []obj{
				cpu,
				{"type": "Memory", "name": "DDR5", "capacity": "512GiB", "count": 16},
				{"type": "GPU", "name": "H100", "count": 8},
				{"type": "CPU", "name": "trailing ", "count": 1},
			}},
			// m3 is matched by its DMI serial: NICo has not linked its expected machine yet.
			{"id": "m3", "status": "Ready", "serialNumber": "s3", "instanceTypeId": nil, "machineCapabilities": []obj{
				cpu, {"type": "Memory", "name": "DDR5", "capacity": "256GiB", "count": 8},
			}},
		},
		ipBlocks: []obj{
			{"id": "manual", "name": "manual", "tenantId": nil, "prefix": "10.9.0.0", "prefixLength": 16, "protocolVersion": "IPv4", "status": "Ready"},
			{"id": "small", "name": "site-fabric-ipv4-10-1-0-0-28", "tenantId": nil, "prefix": "10.1.0.0", "prefixLength": 28, "protocolVersion": "IPv4", "status": "Ready"},
			{"id": "full", "name": "site-fabric-ipv4-10-2-0-0-20", "tenantId": nil, "prefix": "10.2.0.0", "prefixLength": 20, "protocolVersion": "IPv4", "status": "Ready"},
			{"id": "fabric", "name": "site-fabric-ipv4-10-3-0-0-16", "tenantId": nil, "prefix": "10.3.0.0", "prefixLength": 16, "protocolVersion": "IPv4", "status": "Ready"},
		},
		fullBlock: "full",
		objects:   map[string][]obj{},
		bodies:    map[string][]obj{},
		readCount: map[string]int{},
	}
}

// posts returns the bodies POSTed (or PATCHed) to path.
func (f *fakeNICo) posts(path string) []obj {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[path]
}

func (f *fakeNICo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		writeJSON(w, http.StatusOK, obj{"access_token": "example-token", "token_type": "bearer", "expires_in": 3600})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2/org/ncx/nico/")
	q := r.URL.Query()
	var body obj
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, obj{"message": err.Error()})
			return
		}
	}
	f.requests = append(f.requests, r.Method+" "+path)
	if r.Method != http.MethodGet {
		f.bodies[r.Method+" "+path] = append(f.bodies[r.Method+" "+path], body)
	}
	if r.Method == http.MethodGet && q.Get("pageNumber") != "" && q.Get("pageNumber") != "1" {
		writeJSON(w, http.StatusOK, []obj{})
		return
	}
	parts := strings.Split(path, "/")
	switch {
	case path == "service-account/current":
		writeJSON(w, http.StatusOK, obj{"enabled": f.enabled, "infrastructureProviderId": "provider-1", "tenantId": testTenant})
	case path == "expected-machine":
		writeJSON(w, http.StatusOK, f.expected)
	case path == "machine":
		writeJSON(w, http.StatusOK, f.machines)
	case path == "ipblock":
		writeJSON(w, http.StatusOK, f.ipBlocks)
	case len(parts) == 4 && parts[0] == "instance" && parts[3] == "machine" && r.Method == http.MethodPost:
		for _, id := range body["machineIds"].([]any) {
			for _, m := range f.machines {
				if m["id"] == id {
					m["instanceTypeId"] = parts[2]
				}
			}
		}
		writeJSON(w, http.StatusCreated, []obj{})
	case len(parts) == 4 && parts[0] == "allocation" && r.Method == http.MethodPatch:
		for _, al := range f.objects["allocation"] {
			for _, c := range al["allocationConstraints"].([]obj) {
				if al["id"] == parts[1] && c["id"] == parts[3] {
					c["constraintValue"] = body["constraintValue"]
				}
			}
		}
		writeJSON(w, http.StatusOK, obj{})
	default:
		f.collection(w, r.Method, path, q.Get("vpcId"), body)
	}
}

// collection serves list, create, read and update for the plain collections.
func (f *fakeNICo) collection(w http.ResponseWriter, method, path, vpcID string, body obj) {
	kind, id := path, ""
	if i := strings.LastIndex(path, "/"); i > 0 && path != "instance/type" {
		kind, id = path[:i], path[i+1:]
	}
	switch {
	case method == http.MethodGet && id == "":
		items := []obj{}
		for _, o := range f.objects[kind] {
			if vpcID == "" || o["vpcId"] == vpcID {
				items = append(items, o)
			}
		}
		writeJSON(w, http.StatusOK, items)
	case method == http.MethodGet:
		o := f.find(kind, id)
		if o == nil {
			writeJSON(w, http.StatusNotFound, obj{"message": "not found"})
			return
		}
		// A new network object is Ready on its second read.
		f.readCount[path]++
		if f.readCount[path] > 1 {
			o["status"] = statusReady
		}
		if kind == "vpc" && f.errorVPC {
			o["status"] = statusError
		}
		writeJSON(w, http.StatusOK, o)
	case method == http.MethodPost:
		if kind == "allocation" && f.allocationConflict(body) {
			writeJSON(w, http.StatusConflict, obj{"message": "Could not create child IPAM entry"})
			return
		}
		f.nextID++
		o := obj{"id": fmt.Sprintf("%s-%d", strings.ReplaceAll(kind, "/", "-"), f.nextID), "status": "Pending"}
		for k, v := range body {
			o[k] = v
		}
		switch kind {
		case "allocation":
			c := obj{"id": fmt.Sprintf("constraint-%d", f.nextID)}
			for k, v := range body["allocationConstraints"].([]any)[0].(map[string]any) {
				c[k] = v
			}
			if c["resourceType"] == "IPBlock" {
				c["derivedResourceId"] = "tenant-block-of-" + c["resourceTypeId"].(string)
			}
			o["allocationConstraints"] = []obj{c}
		case "sshkey":
			o["fingerprint"] = fakeFingerprint(body["publicKey"].(string))
		case "sshkeygroup":
			o["version"] = "v1"
			o["sshKeys"] = idObjects(body["sshKeyIds"])
			o["siteAssociations"] = siteAssociations(body["siteIds"])
		}
		f.objects[kind] = append(f.objects[kind], o)
		writeJSON(w, http.StatusCreated, o)
	case method == http.MethodPatch && kind == "sshkeygroup":
		o := f.find(kind, id)
		o["sshKeys"] = idObjects(body["sshKeyIds"])
		o["siteAssociations"] = siteAssociations(body["siteIds"])
		writeJSON(w, http.StatusOK, o)
	default:
		writeJSON(w, http.StatusNotFound, obj{"message": method + " " + path + " is not served"})
	}
}

func (f *fakeNICo) allocationConflict(body obj) bool {
	c := body["allocationConstraints"].([]any)[0].(map[string]any)
	return c["resourceTypeId"] == f.fullBlock
}

func (f *fakeNICo) find(kind, id string) obj {
	for _, o := range f.objects[kind] {
		if o["id"] == id {
			return o
		}
	}
	return nil
}

func fakeFingerprint(key string) string {
	if key == testKey {
		return testKeyFingerprint
	}
	fp, _ := fingerprint(key)
	return fp
}

func idObjects(ids any) []obj {
	out := []obj{}
	for _, id := range ids.([]any) {
		out = append(out, obj{"id": id})
	}
	return out
}

func siteAssociations(ids any) []obj {
	out := []obj{}
	for _, id := range ids.([]any) {
		out = append(out, obj{"site": obj{"id": id}})
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func startFake(t *testing.T, f *fakeNICo) *nicorest.Client {
	t.Helper()
	old := pollInterval
	pollInterval = time.Millisecond
	t.Cleanup(func() { pollInterval = old })
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return nicorest.New(srv.URL, "ncx", nicorest.DefaultAPIName,
		nicorest.ClientCredentials{TokenURL: srv.URL + "/token", ClientID: "ncx-service", ClientSecret: "example-secret"})
}

func testConfig(rest *nicorest.Client, vpcType string, serials ...string) Config {
	return Config{
		REST:              rest,
		SiteID:            testSite,
		Name:              "site-a",
		Serials:           serials,
		ControlPlaneCount: len(serials),
		Allocation: nicosettings.Allocation{
			VPCType: vpcType, TenantBlockPrefixLength: 24, SubnetPrefixLength: 26,
		},
		SSHPublicKey: testKey + "\n",
		Timeout:      5 * time.Second,
		Logger:       slog.New(slog.DiscardHandler),
	}
}

func constraintOf(t *testing.T, body obj) map[string]any {
	t.Helper()
	cs, ok := body["allocationConstraints"].([]any)
	require.True(t, ok)
	require.Len(t, cs, 1)
	return cs[0].(map[string]any)
}

func TestEnsure_CreatesEverything(t *testing.T) {
	fake := newFakeNICo()
	res, err := Ensure(context.Background(), testConfig(startFake(t, fake), nicosettings.VPCTypeEthernetVirtualizer, "s1", "s2", "s3"))
	require.NoError(t, err)

	types := fake.posts("POST instance/type")
	require.Len(t, types, 1)
	assert.Equal(t, "site-a-control-plane", types[0]["name"])
	assert.Equal(t, testSite, types[0]["siteId"])
	// Only the CPU capability every machine reports alike: m3's memory differs,
	// GPUs are not CPU or memory, and a name with a trailing blank is refused by REST.
	assert.Equal(t, []any{map[string]any{"type": "CPU", "name": "Xeon 6354", "cores": float64(18), "count": float64(2)}},
		types[0]["machineCapabilities"])

	assoc := fake.posts("POST instance/type/" + res.InstanceTypeID + "/machine")
	require.Len(t, assoc, 1)
	assert.Equal(t, []any{"m1", "m2", "m3"}, assoc[0]["machineIds"])

	allocs := fake.posts("POST allocation")
	require.Len(t, allocs, 3, "the machines, then the full fabric block, then the one with room")
	assert.Equal(t, map[string]any{"resourceType": "InstanceType", "resourceTypeId": res.InstanceTypeID, "constraintType": "Reserved", "constraintValue": float64(3)},
		constraintOf(t, allocs[0]))
	assert.Equal(t, testTenant, allocs[0]["tenantId"])
	assert.Equal(t, "full", constraintOf(t, allocs[1])["resourceTypeId"])
	assert.Equal(t, map[string]any{"resourceType": "IPBlock", "resourceTypeId": "fabric", "constraintType": "Reserved", "constraintValue": float64(24)},
		constraintOf(t, allocs[2]))
	assert.Equal(t, "site-a-network", allocs[2]["name"])

	vpcs := fake.posts("POST vpc")
	require.Len(t, vpcs, 1)
	assert.Equal(t, "ETHERNET_VIRTUALIZER", vpcs[0]["networkVirtualizationType"])

	subnets := fake.posts("POST subnet")
	require.Len(t, subnets, 1)
	assert.Equal(t, obj{"name": "site-a-control-plane", "vpcId": res.VPCID, "ipv4BlockId": "tenant-block-of-fabric", "prefixLength": float64(26)}, subnets[0])
	assert.Empty(t, fake.posts("POST vpc-prefix"))

	keys := fake.posts("POST sshkey")
	require.Len(t, keys, 1)
	assert.Equal(t, testKey, keys[0]["publicKey"], "the key is sent without its trailing newline")
	groups := fake.posts("POST sshkeygroup")
	require.Len(t, groups, 1)
	assert.Equal(t, []any{testSite}, groups[0]["siteIds"])

	assert.NotEmpty(t, res.InstanceTypeID)
	assert.NotEmpty(t, res.VPCID)
	assert.NotEmpty(t, res.SubnetID)
	assert.Empty(t, res.VPCPrefixID)
	assert.NotEmpty(t, res.SSHKeyGroupID)
}

// TestEnsure_RerunReusesAndGrows: a second run finds every object by name or
// fingerprint, adds only the new machine, and grows the machine allocation.
func TestEnsure_RerunReusesAndGrows(t *testing.T) {
	fake := newFakeNICo()
	rest := startFake(t, fake)
	first, err := Ensure(context.Background(), testConfig(rest, nicosettings.VPCTypeEthernetVirtualizer, "s1", "s2"))
	require.NoError(t, err)

	second, err := Ensure(context.Background(), testConfig(rest, nicosettings.VPCTypeEthernetVirtualizer, "s1", "s2", "s3"))
	require.NoError(t, err)
	assert.Equal(t, first, second)

	for _, path := range []string{"POST instance/type", "POST vpc", "POST subnet", "POST sshkey", "POST sshkeygroup"} {
		assert.Len(t, fake.posts(path), 1, "%s after a rerun", path)
	}
	assert.Len(t, fake.posts("POST allocation"), 3, "the first run's machines, full block and fabric block")

	assoc := fake.posts("POST instance/type/" + first.InstanceTypeID + "/machine")
	require.Len(t, assoc, 2)
	assert.Equal(t, []any{"m3"}, assoc[1]["machineIds"])

	var grown []obj
	for path, bodies := range fake.bodies {
		if strings.HasPrefix(path, "PATCH allocation/") {
			grown = append(grown, bodies...)
		}
	}
	assert.Equal(t, []obj{{"constraintValue": float64(3)}}, grown)
}

// TestEnsure_RerunWithANewKey adds the new key to the existing group rather
// than creating another group.
func TestEnsure_RerunWithANewKey(t *testing.T) {
	fake := newFakeNICo()
	rest := startFake(t, fake)
	first, err := Ensure(context.Background(), testConfig(rest, nicosettings.VPCTypeEthernetVirtualizer, "s1"))
	require.NoError(t, err)

	cfg := testConfig(rest, nicosettings.VPCTypeEthernetVirtualizer, "s1")
	cfg.SSHPublicKey = otherKey
	second, err := Ensure(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, first.SSHKeyGroupID, second.SSHKeyGroupID)

	keys := fake.posts("POST sshkey")
	require.Len(t, keys, 2)
	patches := fake.posts("PATCH sshkeygroup/" + first.SSHKeyGroupID)
	require.Len(t, patches, 1)
	assert.Equal(t, []any{testSite}, patches[0]["siteIds"])
	assert.Len(t, patches[0]["sshKeyIds"], 2)
	assert.Equal(t, "v1", patches[0]["version"])
}

func TestEnsure_FNN(t *testing.T) {
	fake := newFakeNICo()
	res, err := Ensure(context.Background(), testConfig(startFake(t, fake), nicosettings.VPCTypeFNN, "s1", "s2"))
	require.NoError(t, err)

	vpcs := fake.posts("POST vpc")
	require.Len(t, vpcs, 1)
	assert.Equal(t, "FNN", vpcs[0]["networkVirtualizationType"])
	prefixes := fake.posts("POST vpc-prefix")
	require.Len(t, prefixes, 1)
	assert.Equal(t, obj{"name": "site-a-control-plane", "vpcId": res.VPCID, "ipBlockId": "tenant-block-of-fabric", "prefixLength": float64(26)}, prefixes[0])
	assert.Empty(t, fake.posts("POST subnet"))
	assert.NotEmpty(t, res.VPCPrefixID)
	assert.Empty(t, res.SubnetID)
}

func TestEnsure_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*fakeNICo, *Config)
		wantErr string
	}{
		{
			name:    "not a service account",
			mutate:  func(f *fakeNICo, _ *Config) { f.enabled = false },
			wantErr: "service account",
		},
		{
			name:    "a machine never discovered",
			mutate:  func(_ *fakeNICo, c *Config) { c.Serials = append(c.Serials, "s9"); c.Timeout = 50 * time.Millisecond },
			wantErr: "s9: not discovered yet",
		},
		{
			name: "a machine not Ready",
			mutate: func(f *fakeNICo, c *Config) {
				f.machines[1]["status"] = "Initializing"
				c.Timeout = 50 * time.Millisecond
			},
			wantErr: "s2: machine m2 is Initializing",
		},
		{
			name:    "a machine in another instance type",
			mutate:  func(f *fakeNICo, _ *Config) { f.machines[0]["instanceTypeId"] = "someone-elses" },
			wantErr: "machine m1 (serial s1) already belongs to instance type someone-elses",
		},
		{
			name: "no fabric block with room",
			mutate: func(f *fakeNICo, c *Config) {
				f.ipBlocks = f.ipBlocks[:2]
				c.Timeout = 50 * time.Millisecond
			},
			wantErr: "no Ready site fabric IPv4 block of /24 or shorter; found [10.1.0.0/28 Ready]",
		},
		{
			name:    "the VPC fails",
			mutate:  func(f *fakeNICo, _ *Config) { f.errorVPC = true },
			wantErr: "the VPC site-a is in Error",
		},
		{
			name:    "more control-plane machines than listed",
			mutate:  func(_ *fakeNICo, c *Config) { c.ControlPlaneCount = 5 },
			wantErr: "ControlPlaneCount 5 exceeds the 2 machines listed",
		},
		{
			name:    "an unknown VPC type",
			mutate:  func(_ *fakeNICo, c *Config) { c.Allocation.VPCType = "flat" },
			wantErr: `Allocation.VPCType "flat"`,
		},
		{
			name:    "a subnet no longer than the tenant block",
			mutate:  func(_ *fakeNICo, c *Config) { c.Allocation.SubnetPrefixLength = 24 },
			wantErr: "SubnetPrefixLength must be longer",
		},
		{
			name:    "not a public key",
			mutate:  func(_ *fakeNICo, c *Config) { c.SSHPublicKey = "not-a-key" },
			wantErr: "SSHPublicKey is not an OpenSSH public key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeNICo()
			cfg := testConfig(startFake(t, fake), nicosettings.VPCTypeEthernetVirtualizer, "s1", "s2")
			tt.mutate(fake, &cfg)
			_, err := Ensure(context.Background(), cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCommonCapabilities(t *testing.T) {
	cpu := map[string]any{"type": "CPU", "name": "Xeon", "count": float64(2)}
	mem := map[string]any{"type": "Memory", "name": "DDR5", "capacity": "512GiB"}
	tests := []struct {
		name     string
		machines [][]map[string]any
		want     []map[string]any
	}{
		{name: "identical machines", machines: [][]map[string]any{{cpu, mem}, {mem, cpu}}, want: []map[string]any{cpu, mem}},
		{
			name: "a differing value drops the capability",
			machines: [][]map[string]any{
				{cpu, mem},
				{cpu, {"type": "Memory", "name": "DDR5", "capacity": "256GiB"}},
			},
			want: []map[string]any{cpu},
		},
		{
			name:     "other types are left out",
			machines: [][]map[string]any{{cpu, {"type": "GPU", "name": "H100", "count": float64(8)}}},
			want:     []map[string]any{cpu},
		},
		{name: "nothing in common", machines: [][]map[string]any{{cpu}, {mem}}, want: []map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ms []machine
			for _, caps := range tt.machines {
				ms = append(ms, machine{MachineCapabilities: caps})
			}
			assert.Equal(t, tt.want, commonCapabilities(ms))
		})
	}
}

func TestFingerprint(t *testing.T) {
	got, err := fingerprint(testKey)
	require.NoError(t, err)
	assert.Equal(t, testKeyFingerprint, got, "must match ssh-keygen -lf, which NICo REST computes the same way")

	_, err = fingerprint("ssh-ed25519 !!!")
	assert.Error(t, err)
}

func TestFabricBlocks(t *testing.T) {
	block := func(id string, length int) ipBlock {
		return ipBlock{ID: id, Name: siteFabricBlockPrefix + id, Prefix: "10.0.0.0", PrefixLength: length, ProtocolVersion: "IPv4", Status: statusReady}
	}
	tests := []struct {
		name   string
		length int
		want   []string
	}{
		{name: "a longer tenant block is cut from the fabric block", length: 26, want: []string{"a"}},
		{name: "a tenant block of the fabric block's length is a full grant", length: 24, want: []string{"a"}},
		{name: "a shorter tenant block does not fit", length: 23, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fit, _ := fabricBlocks([]ipBlock{block("a", 24)}, tt.length)
			var ids []string
			for _, b := range fit {
				ids = append(ids, b.ID)
			}
			assert.Equal(t, tt.want, ids)
		})
	}
}
