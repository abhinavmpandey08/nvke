// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicoalloc creates, through NICo's REST API, what CAPNICo needs to
// allocate a site's control-plane machines: an instance type holding the
// machines, the tenant's allocations of the machines and of an IP block, a VPC
// with a subnet or VPC prefix cut from that block, and an SSH key group.
package nicoalloc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

const (
	defaultTimeout = 30 * time.Minute
	// pageSize is the largest page NICo REST serves.
	pageSize = 100
	// siteFabricBlockPrefix starts the name NICo REST gives the IP block it
	// makes for each IPv4 site_fabric_prefixes entry.
	siteFabricBlockPrefix = "site-fabric-ipv4-"

	statusReady = "Ready"
	statusError = "Error"
)

// pollInterval is how often a wait asks REST again. A variable so tests run fast.
var pollInterval = 10 * time.Second

// vpcTypes maps Allocation.VPCType to NICo's network virtualization type.
var vpcTypes = map[string]string{
	nicosettings.VPCTypeEthernetVirtualizer: "ETHERNET_VIRTUALIZER",
	nicosettings.VPCTypeFNN:                 "FNN",
}

// Config is what Ensure creates the control plane's NICo objects from.
type Config struct {
	// REST calls the org's REST API with a service-account token.
	REST *nicorest.Client
	// SiteID is the NICo site the machines are in.
	SiteID string
	// Name prefixes the names of the objects Ensure creates: the cluster name.
	Name string
	// Serials are the chassis serials of the machines to use, as the machines
	// file lists them.
	Serials []string
	// ControlPlaneCount is how many control-plane machines the cluster runs. It
	// must not exceed len(Serials).
	ControlPlaneCount int
	// Allocation sizes the tenant block and the subnet or VPC prefix.
	Allocation nicosettings.Allocation
	// SSHPublicKey is the OpenSSH public key put on the machines.
	SSHPublicKey string
	// Timeout bounds the whole of Ensure, waits included. 30 minutes when unset.
	Timeout time.Duration
	// Logger receives progress. slog.Default when nil.
	Logger *slog.Logger
}

// Result holds the IDs of the objects Ensure found or created. SubnetID is set
// for an ethernet-virtualizer VPC, VPCPrefixID for an FNN one.
type Result struct {
	InstanceTypeID string
	VPCID          string
	SubnetID       string
	VPCPrefixID    string
	SSHKeyGroupID  string
}

// Ensure finds, or creates, each object CAPNICo allocates the control plane
// with, and waits until each can be used. Objects are found by name, so a
// second run reuses the first run's objects; it grows the machine allocation
// when more machines are listed. The token must be a service-account token:
// its GET service-account/current creates the org's tenant.
func Ensure(ctx context.Context, cfg Config) (*Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &allocator{cfg: cfg, rest: cfg.REST, log: log.With("component", "nicoalloc", "site", cfg.SiteID)}

	tenantID, err := a.tenant(ctx)
	if err != nil {
		return nil, err
	}
	machines, err := a.machines(ctx)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if res.InstanceTypeID, err = a.instanceType(ctx, machines); err != nil {
		return nil, err
	}
	if err := a.associate(ctx, res.InstanceTypeID, machines); err != nil {
		return nil, err
	}
	if err := a.machineAllocation(ctx, tenantID, res.InstanceTypeID); err != nil {
		return nil, err
	}
	block, err := a.tenantBlock(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if res.VPCID, err = a.vpc(ctx); err != nil {
		return nil, err
	}
	if cfg.Allocation.VPCType == nicosettings.VPCTypeFNN {
		res.VPCPrefixID, err = a.network(ctx, "vpc-prefix", "ipBlockId", res.VPCID, block)
	} else {
		res.SubnetID, err = a.network(ctx, "subnet", "ipv4BlockId", res.VPCID, block)
	}
	if err != nil {
		return nil, err
	}
	if res.SSHKeyGroupID, err = a.sshKeyGroup(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

func (c Config) validate() error {
	var problems []string
	if c.REST == nil {
		problems = append(problems, "REST is required")
	}
	if c.SiteID == "" || c.Name == "" {
		problems = append(problems, "SiteID and Name are required")
	}
	if len(c.Serials) == 0 {
		problems = append(problems, "Serials is empty")
	}
	if c.ControlPlaneCount > len(c.Serials) {
		problems = append(problems, fmt.Sprintf("ControlPlaneCount %d exceeds the %d machines listed", c.ControlPlaneCount, len(c.Serials)))
	}
	if _, ok := vpcTypes[c.Allocation.VPCType]; !ok {
		problems = append(problems, fmt.Sprintf("Allocation.VPCType %q is not %s or %s",
			c.Allocation.VPCType, nicosettings.VPCTypeEthernetVirtualizer, nicosettings.VPCTypeFNN))
	}
	if c.Allocation.TenantBlockPrefixLength < 1 || c.Allocation.SubnetPrefixLength <= c.Allocation.TenantBlockPrefixLength {
		problems = append(problems, "Allocation.SubnetPrefixLength must be longer than a set TenantBlockPrefixLength")
	}
	if _, err := fingerprint(c.SSHPublicKey); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("nicoalloc: %s", strings.Join(problems, "; "))
	}
	return nil
}

type allocator struct {
	cfg  Config
	rest *nicorest.Client
	log  *slog.Logger
}

// The REST objects, reduced to the fields Ensure reads.
type (
	named struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	machine struct {
		ID                  string           `json:"id"`
		SerialNumber        *string          `json:"serialNumber"`
		InstanceTypeID      *string          `json:"instanceTypeId"`
		Status              string           `json:"status"`
		MachineCapabilities []map[string]any `json:"machineCapabilities"`
		serial              string
	}
	expectedMachine struct {
		ChassisSerialNumber string  `json:"chassisSerialNumber"`
		MachineID           *string `json:"machineId"`
	}
	allocation struct {
		ID                    string       `json:"id"`
		Name                  string       `json:"name"`
		TenantID              string       `json:"tenantId"`
		AllocationConstraints []constraint `json:"allocationConstraints"`
	}
	constraint struct {
		ID                string  `json:"id"`
		ResourceType      string  `json:"resourceType"`
		ResourceTypeID    string  `json:"resourceTypeId"`
		ConstraintValue   int     `json:"constraintValue"`
		DerivedResourceID *string `json:"derivedResourceId"`
	}
	ipBlock struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		TenantID        *string `json:"tenantId"`
		Prefix          string  `json:"prefix"`
		PrefixLength    int     `json:"prefixLength"`
		ProtocolVersion string  `json:"protocolVersion"`
		Status          string  `json:"status"`
	}
	vpc struct {
		ID                        string  `json:"id"`
		Name                      string  `json:"name"`
		NetworkVirtualizationType *string `json:"networkVirtualizationType"`
	}
	sshKey struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	sshKeyGroup struct {
		ID               string  `json:"id"`
		Name             string  `json:"name"`
		Version          *string `json:"version"`
		SSHKeys          []named `json:"sshKeys"`
		SiteAssociations []struct {
			Site *named `json:"site"`
		} `json:"siteAssociations"`
	}
)

// tenant returns the org's tenant ID, which GET service-account/current
// creates, with a Ready tenant account, when it does not exist.
func (a *allocator) tenant(ctx context.Context) (string, error) {
	var sa struct {
		Enabled  bool    `json:"enabled"`
		TenantID *string `json:"tenantId"`
	}
	if err := a.rest.Do(ctx, http.MethodGet, "service-account/current", nil, &sa); err != nil {
		return "", fmt.Errorf("nicoalloc: reading the service account: %w", err)
	}
	if !sa.Enabled || sa.TenantID == nil {
		return "", errors.New("nicoalloc: NICo REST does not treat the token as a service account; " +
			"it needs a client-credentials token and keycloak.serviceAccount true in its issuer config")
	}
	return *sa.TenantID, nil
}

// machines waits until REST knows each of cfg.Serials as a machine that is
// Ready, or already has an instance type, and returns them in the same order.
// A serial is matched through the expected machine NICo linked to it, or else
// through the machine's DMI serial.
func (a *allocator) machines(ctx context.Context) ([]machine, error) {
	site := url.QueryEscape(a.cfg.SiteID)
	var found []machine
	err := a.poll(ctx, "the machines to be Ready in NICo REST", func() (bool, string, error) {
		expected, err := list[expectedMachine](ctx, a.rest, "expected-machine?siteId="+site)
		if err != nil {
			return false, "", fmt.Errorf("nicoalloc: listing expected machines: %w", err)
		}
		all, err := list[machine](ctx, a.rest, "machine?siteId="+site)
		if err != nil {
			return false, "", fmt.Errorf("nicoalloc: listing machines: %w", err)
		}
		var pending []string
		found, pending = pickMachines(a.cfg.Serials, expected, all)
		return len(pending) == 0, strings.Join(pending, ", "), nil
	})
	return found, err
}

// pickMachines returns the machine of each serial, and a description of each
// serial without a usable one.
func pickMachines(serials []string, expected []expectedMachine, all []machine) ([]machine, []string) {
	byID := map[string]machine{}
	bySerial := map[string]machine{}
	for _, m := range all {
		byID[m.ID] = m
		if m.SerialNumber != nil {
			bySerial[*m.SerialNumber] = m
		}
	}
	for _, em := range expected {
		if m, ok := byID[ptr(em.MachineID)]; ok {
			bySerial[em.ChassisSerialNumber] = m
		}
	}
	var found []machine
	var pending []string
	for _, serial := range serials {
		m, ok := bySerial[serial]
		switch {
		case !ok:
			pending = append(pending, serial+": not discovered yet")
		case m.InstanceTypeID == nil && m.Status != statusReady && m.Status != "Reset":
			pending = append(pending, fmt.Sprintf("%s: machine %s is %s", serial, m.ID, m.Status))
		default:
			m.serial = serial
			found = append(found, m)
		}
	}
	return found, pending
}

// instanceType returns the ID of the instance type <Name>-control-plane,
// creating it with the CPU and memory capabilities every machine reports alike.
func (a *allocator) instanceType(ctx context.Context, machines []machine) (string, error) {
	name := a.cfg.Name + "-control-plane"
	types, err := list[named](ctx, a.rest, "instance/type?siteId="+url.QueryEscape(a.cfg.SiteID))
	if err != nil {
		return "", fmt.Errorf("nicoalloc: listing instance types: %w", err)
	}
	if t := findNamed(types, name); t != nil {
		return t.ID, nil
	}
	body := map[string]any{"name": name, "siteId": a.cfg.SiteID, "machineCapabilities": commonCapabilities(machines)}
	var created named
	if err := a.rest.Do(ctx, http.MethodPost, "instance/type", body, &created); err != nil {
		return "", fmt.Errorf("nicoalloc: creating the instance type %s: %w", name, err)
	}
	a.log.Info("created the instance type", "name", name, "id", created.ID)
	return created.ID, nil
}

// commonCapabilities returns the CPU and memory capabilities every machine
// reports with the same values, which the machines therefore all match.
func commonCapabilities(machines []machine) []map[string]any {
	count := map[string]int{}
	caps := map[string]map[string]any{}
	var order []string
	for _, m := range machines {
		seen := map[string]bool{}
		for _, c := range m.MachineCapabilities {
			name, _ := c["name"].(string)
			// REST refuses a name shorter than 2 or with surrounding blanks.
			if (c["type"] != "CPU" && c["type"] != "Memory") || len(name) < 2 || strings.TrimSpace(name) != name {
				continue
			}
			raw, _ := json.Marshal(c) // map keys marshal sorted, so equal capabilities give equal keys
			key := string(raw)
			if seen[key] {
				continue
			}
			seen[key] = true
			if count[key] == 0 {
				order = append(order, key)
				caps[key] = c
			}
			count[key]++
		}
	}
	out := []map[string]any{}
	for _, key := range order {
		if count[key] == len(machines) {
			out = append(out, caps[key])
		}
	}
	return out
}

// associate adds to the instance type each machine that has none, and refuses
// a machine that has another.
func (a *allocator) associate(ctx context.Context, instanceTypeID string, machines []machine) error {
	var ids []string
	for _, m := range machines {
		switch {
		case m.InstanceTypeID == nil:
			ids = append(ids, m.ID)
		case *m.InstanceTypeID != instanceTypeID:
			return fmt.Errorf("nicoalloc: machine %s (serial %s) already belongs to instance type %s, not %s-control-plane",
				m.ID, m.serial, *m.InstanceTypeID, a.cfg.Name)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if err := a.rest.Do(ctx, http.MethodPost, "instance/type/"+instanceTypeID+"/machine", map[string]any{"machineIds": ids}, nil); err != nil {
		return fmt.Errorf("nicoalloc: adding %d machines to the instance type: %w", len(ids), err)
	}
	a.log.Info("added machines to the instance type", "count", len(ids))
	return nil
}

// machineAllocation gives the tenant every listed machine: the allocation
// <Name>-control-plane reserves len(Serials) machines of the instance type,
// grown when it reserves fewer.
func (a *allocator) machineAllocation(ctx context.Context, tenantID, instanceTypeID string) error {
	name := a.cfg.Name + "-control-plane"
	want := len(a.cfg.Serials)
	existing, err := a.findAllocation(ctx, name, tenantID)
	if err != nil {
		return err
	}
	if existing == nil {
		_, err := a.createAllocation(ctx, name, tenantID, "InstanceType", instanceTypeID, want)
		return err
	}
	c := existing.constraint("InstanceType")
	if c == nil || c.ResourceTypeID != instanceTypeID {
		return fmt.Errorf("nicoalloc: the allocation %s does not reserve the instance type %s; delete it and run again", name, instanceTypeID)
	}
	if c.ConstraintValue >= want {
		return nil
	}
	path := "allocation/" + existing.ID + "/constraint/" + c.ID
	if err := a.rest.Do(ctx, http.MethodPatch, path, map[string]any{"constraintValue": want}, nil); err != nil {
		return fmt.Errorf("nicoalloc: growing the allocation %s to %d machines: %w", name, want, err)
	}
	a.log.Info("grew the machine allocation", "name", name, "from", c.ConstraintValue, "to", want)
	return nil
}

// tenantBlock returns the tenant IP block the allocation <Name>-network
// carves from a site fabric IP block, creating the allocation from the first
// such block with room once NICo REST has made one.
func (a *allocator) tenantBlock(ctx context.Context, tenantID string) (string, error) {
	name := a.cfg.Name + "-network"
	existing, err := a.findAllocation(ctx, name, tenantID)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return derived(existing, name)
	}
	length := a.cfg.Allocation.TenantBlockPrefixLength
	var candidates []ipBlock
	err = a.poll(ctx, "NICo REST to make the site's fabric IP blocks", func() (bool, string, error) {
		blocks, err := list[ipBlock](ctx, a.rest, "ipblock?siteId="+url.QueryEscape(a.cfg.SiteID))
		if err != nil {
			return false, "", fmt.Errorf("nicoalloc: listing IP blocks: %w", err)
		}
		var seen []string
		candidates, seen = fabricBlocks(blocks, length)
		return len(candidates) > 0, fmt.Sprintf("no Ready site fabric IPv4 block of /%d or shorter; found %v", length, seen), nil
	})
	if err != nil {
		return "", err
	}
	var errs []error
	for _, b := range candidates {
		created, err := a.createAllocation(ctx, name, tenantID, "IPBlock", b.ID, length)
		if nicorest.IsStatus(err, http.StatusConflict) {
			errs = append(errs, err) // no room left in this block
			continue
		}
		if err != nil {
			return "", err
		}
		return derived(created, name)
	}
	return "", errors.Join(errs...)
}

// fabricBlocks returns the site fabric IP blocks a /length tenant block can be
// cut from, a block of the same length as a full grant, and every site fabric block's prefix.
func fabricBlocks(blocks []ipBlock, length int) ([]ipBlock, []string) {
	var fit []ipBlock
	var seen []string
	for _, b := range blocks {
		if !strings.HasPrefix(b.Name, siteFabricBlockPrefix) || b.TenantID != nil || b.ProtocolVersion != "IPv4" {
			continue
		}
		seen = append(seen, fmt.Sprintf("%s/%d %s", b.Prefix, b.PrefixLength, b.Status))
		if b.Status == statusReady && b.PrefixLength <= length {
			fit = append(fit, b)
		}
	}
	return fit, seen
}

func derived(al *allocation, name string) (string, error) {
	c := al.constraint("IPBlock")
	if c == nil || c.DerivedResourceID == nil {
		return "", fmt.Errorf("nicoalloc: the allocation %s has no tenant IP block; delete it and run again", name)
	}
	return *c.DerivedResourceID, nil
}

func (a *allocator) findAllocation(ctx context.Context, name, tenantID string) (*allocation, error) {
	all, err := list[allocation](ctx, a.rest, "allocation?siteId="+url.QueryEscape(a.cfg.SiteID))
	if err != nil {
		return nil, fmt.Errorf("nicoalloc: listing allocations: %w", err)
	}
	for i := range all {
		if all[i].Name == name && all[i].TenantID == tenantID {
			return &all[i], nil
		}
	}
	return nil, nil
}

func (a *allocator) createAllocation(ctx context.Context, name, tenantID, resourceType, resourceID string, value int) (*allocation, error) {
	body := map[string]any{
		"name": name, "tenantId": tenantID, "siteId": a.cfg.SiteID,
		"allocationConstraints": []map[string]any{{
			"resourceType": resourceType, "resourceTypeId": resourceID, "constraintType": "Reserved", "constraintValue": value,
		}},
	}
	var created allocation
	if err := a.rest.Do(ctx, http.MethodPost, "allocation", body, &created); err != nil {
		return nil, fmt.Errorf("nicoalloc: creating the allocation %s: %w", name, err)
	}
	a.log.Info("created the allocation", "name", name, "resourceType", resourceType, "value", value)
	return &created, nil
}

func (al *allocation) constraint(resourceType string) *constraint {
	for i := range al.AllocationConstraints {
		if al.AllocationConstraints[i].ResourceType == resourceType {
			return &al.AllocationConstraints[i]
		}
	}
	return nil
}

// vpc returns the ID of the VPC <Name>, creating it with the network
// virtualization type the settings ask for, once it is Ready.
func (a *allocator) vpc(ctx context.Context) (string, error) {
	want := vpcTypes[a.cfg.Allocation.VPCType]
	vpcs, err := list[vpc](ctx, a.rest, "vpc?siteId="+url.QueryEscape(a.cfg.SiteID))
	if err != nil {
		return "", fmt.Errorf("nicoalloc: listing VPCs: %w", err)
	}
	var id string
	for _, v := range vpcs {
		if v.Name != a.cfg.Name {
			continue
		}
		if got := ptr(v.NetworkVirtualizationType); got != want {
			return "", fmt.Errorf("nicoalloc: the VPC %s is %s, the settings ask for %s; delete it and run again", v.Name, got, want)
		}
		id = v.ID
	}
	if id == "" {
		body := map[string]any{"name": a.cfg.Name, "siteId": a.cfg.SiteID, "networkVirtualizationType": want}
		var created vpc
		if err := a.rest.Do(ctx, http.MethodPost, "vpc", body, &created); err != nil {
			return "", fmt.Errorf("nicoalloc: creating the VPC %s: %w", a.cfg.Name, err)
		}
		a.log.Info("created the VPC", "name", a.cfg.Name, "type", want)
		id = created.ID
	}
	return id, a.waitReady(ctx, "vpc/"+id, "the VPC "+a.cfg.Name)
}

// network returns the ID of the subnet or VPC prefix (kind) <Name>-control-plane
// in the VPC, creating it from the tenant block, once it is Ready. blockField
// is the create request's field for the block.
func (a *allocator) network(ctx context.Context, kind, blockField, vpcID, block string) (string, error) {
	name := a.cfg.Name + "-control-plane"
	existing, err := list[named](ctx, a.rest, kind+"?vpcId="+url.QueryEscape(vpcID))
	if err != nil {
		return "", fmt.Errorf("nicoalloc: listing the VPC's %ss: %w", kind, err)
	}
	var id string
	if n := findNamed(existing, name); n != nil {
		id = n.ID
	} else {
		body := map[string]any{"name": name, "vpcId": vpcID, blockField: block, "prefixLength": a.cfg.Allocation.SubnetPrefixLength}
		var created named
		if err := a.rest.Do(ctx, http.MethodPost, kind, body, &created); err != nil {
			return "", fmt.Errorf("nicoalloc: creating the %s %s: %w", kind, name, err)
		}
		a.log.Info("created the "+kind, "name", name, "prefixLength", a.cfg.Allocation.SubnetPrefixLength)
		id = created.ID
	}
	return id, a.waitReady(ctx, kind+"/"+id, "the "+kind+" "+name)
}

// sshKeyGroup returns the ID of the SSH key group <Name>, holding the SSH key
// and the site, creating the key and the group or adding them to it as needed.
func (a *allocator) sshKeyGroup(ctx context.Context) (string, error) {
	fp, _ := fingerprint(a.cfg.SSHPublicKey) // checked by validate
	keys, err := list[sshKey](ctx, a.rest, "sshkey")
	if err != nil {
		return "", fmt.Errorf("nicoalloc: listing SSH keys: %w", err)
	}
	var keyID string
	for _, k := range keys {
		if k.Fingerprint == fp {
			keyID = k.ID
		}
	}
	if keyID == "" {
		var created named
		body := map[string]any{"name": a.cfg.Name, "publicKey": strings.TrimSpace(a.cfg.SSHPublicKey)}
		if err := a.rest.Do(ctx, http.MethodPost, "sshkey", body, &created); err != nil {
			return "", fmt.Errorf("nicoalloc: creating the SSH key %s (an older key of that name must be deleted first): %w", a.cfg.Name, err)
		}
		a.log.Info("created the SSH key", "name", a.cfg.Name, "fingerprint", "SHA256:"+fp)
		keyID = created.ID
	}

	groups, err := list[sshKeyGroup](ctx, a.rest, "sshkeygroup")
	if err != nil {
		return "", fmt.Errorf("nicoalloc: listing SSH key groups: %w", err)
	}
	for _, g := range groups {
		if g.Name != a.cfg.Name {
			continue
		}
		var siteIDs, keyIDs []string
		for _, s := range g.SiteAssociations {
			if s.Site != nil {
				siteIDs = append(siteIDs, s.Site.ID)
			}
		}
		for _, k := range g.SSHKeys {
			keyIDs = append(keyIDs, k.ID)
		}
		if slices.Contains(siteIDs, a.cfg.SiteID) && slices.Contains(keyIDs, keyID) {
			return g.ID, nil
		}
		// An update replaces both lists, so it carries what the group already holds.
		body := map[string]any{
			"siteIds":   appendMissing(siteIDs, a.cfg.SiteID),
			"sshKeyIds": appendMissing(keyIDs, keyID),
			"version":   g.Version,
		}
		if err := a.rest.Do(ctx, http.MethodPatch, "sshkeygroup/"+g.ID, body, nil); err != nil {
			return "", fmt.Errorf("nicoalloc: adding the SSH key and site to the SSH key group %s: %w", g.Name, err)
		}
		a.log.Info("added the SSH key and site to the SSH key group", "name", g.Name)
		return g.ID, nil
	}
	var created named
	body := map[string]any{"name": a.cfg.Name, "siteIds": []string{a.cfg.SiteID}, "sshKeyIds": []string{keyID}}
	if err := a.rest.Do(ctx, http.MethodPost, "sshkeygroup", body, &created); err != nil {
		return "", fmt.Errorf("nicoalloc: creating the SSH key group %s: %w", a.cfg.Name, err)
	}
	a.log.Info("created the SSH key group", "name", a.cfg.Name)
	return created.ID, nil
}

// fingerprint returns the SHA-256 fingerprint of an OpenSSH public key in the
// form NICo REST stores it: unpadded base64, without the SHA256: prefix.
func fingerprint(publicKey string) (string, error) {
	fields := strings.Fields(publicKey)
	if len(fields) < 2 {
		return "", errors.New("SSHPublicKey is not an OpenSSH public key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", errors.New("SSHPublicKey is not an OpenSSH public key: its key is not base64")
	}
	sum := sha256.Sum256(blob)
	return base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// waitReady polls path until the object's status is Ready, and fails on Error.
func (a *allocator) waitReady(ctx context.Context, path, what string) error {
	return a.poll(ctx, what+" to be Ready", func() (bool, string, error) {
		var obj struct {
			Status string `json:"status"`
		}
		if err := a.rest.Do(ctx, http.MethodGet, path, nil, &obj); err != nil {
			return false, "", fmt.Errorf("nicoalloc: reading %s: %w", what, err)
		}
		if obj.Status == statusError {
			return false, "", fmt.Errorf("nicoalloc: %s is in Error; its status history in NICo REST says why", what)
		}
		return obj.Status == statusReady, "status " + obj.Status, nil
	})
}

// poll calls check until it reports done or fails, or ctx ends; the timeout
// error carries the last state check described.
func (a *allocator) poll(ctx context.Context, what string, check func() (done bool, state string, err error)) error {
	state := "no answer from NICo REST"
	timedOut := func() error { return fmt.Errorf("nicoalloc: timed out waiting for %s: %s", what, state) }
	for {
		done, s, err := check()
		if err != nil && ctx.Err() != nil {
			return timedOut() // the deadline cut the request; the last state says more
		}
		if err != nil || done {
			return err
		}
		state = s
		a.log.Info("waiting for "+what, "state", state)
		select {
		case <-ctx.Done():
			return timedOut()
		case <-time.After(pollInterval):
		}
	}
}

// list returns every item of the REST list at path, one page at a time.
func list[T any](ctx context.Context, rest *nicorest.Client, path string) ([]T, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	var all []T
	for page := 1; ; page++ {
		var items []T
		if err := rest.Do(ctx, http.MethodGet, fmt.Sprintf("%s%spageSize=%d&pageNumber=%d", path, sep, pageSize, page), nil, &items); err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < pageSize {
			return all, nil
		}
	}
}

func findNamed(items []named, name string) *named {
	for i := range items {
		if items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func appendMissing(ids []string, id string) []string {
	if slices.Contains(ids, id) {
		return ids
	}
	return append(ids, id)
}

func ptr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
