// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicosettings

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads the settings file at path, resolves its relative paths from the file's directory, reads the machines
// file, the SSH public key and the Core values' site config, and validates all
// of it. Unknown fields are refused. The error lists every problem, one per line.
func Load(path string) (*Settings, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving the NICo settings path: %w", err)
	}
	s := &Settings{Path: abs}
	if err := decodeStrict(abs, &s.File); err != nil {
		return nil, fmt.Errorf("NICo settings %s: %w", abs, err)
	}
	dir := filepath.Dir(abs)
	for _, p := range []*string{&s.CoreValues, &s.Machines, &s.Allocation.SSHPublicKey, &s.HandoverDir} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}

	var p problems
	if s.Machines != "" {
		if err := decodeStrict(s.Machines, &s.MachineList); err != nil {
			p.addf("machines %s: %v", s.Machines, err)
		}
	}
	if s.Allocation.SSHPublicKey != "" {
		if key, err := os.ReadFile(s.Allocation.SSHPublicKey); err != nil {
			p.addf("allocation.sshPublicKey: %v", err)
		} else if s.SSHPublicKeyData = strings.TrimSpace(string(key)); s.SSHPublicKeyData == "" {
			p.addf("allocation.sshPublicKey %s is empty", s.Allocation.SSHPublicKey)
		}
	}
	siteConfigRead := false
	if s.CoreValues != "" {
		if data, err := os.ReadFile(s.CoreValues); err != nil {
			p.addf("coreValues: %v", err)
		} else if s.SiteConfig, err = ParseSiteConfig(data); err != nil {
			p.addf("coreValues %s: %v", s.CoreValues, err)
		} else {
			siteConfigRead = true
		}
	}
	s.validate(&p, siteConfigRead)
	if err := p.err(); err != nil {
		return nil, err
	}
	return s, nil
}

// decodeStrict decodes the YAML file at path into out, refusing unknown fields.
func decodeStrict(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the file is empty")
		}
		// yaml.v3 puts one problem per line; keep the error on one.
		return errors.New(strings.Join(strings.Fields(err.Error()), " "))
	}
	return nil
}

// problems collects every problem found, so one error can list them all.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// err returns the problems one per line, or nil when there are none.
func (p problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return errors.New(strings.Join(p, "\n"))
}
