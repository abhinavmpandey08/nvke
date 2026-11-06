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

// Load reads the settings file at path, reads the site config from its Core
// values, and validates all of it. Unknown fields are refused, except inside
// coreValues. handoverDir is the directory the handover bundle is written to;
// one that already holds a bundle is refused. The error lists every problem,
// one per line.
func Load(path, handoverDir string) (*Settings, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving the NICo settings path: %w", err)
	}
	s := &Settings{Path: abs, HandoverDir: handoverDir}
	if err := decodeStrict(abs, &s.File); err != nil {
		return nil, fmt.Errorf("NICo settings %s: %w", abs, err)
	}
	// A block scalar leaves a trailing newline on the key.
	s.Allocation.SSHPublicKey = strings.TrimSpace(s.Allocation.SSHPublicKey)

	var p problems
	siteConfigRead := false
	if len(s.CoreValues) > 0 {
		if data, err := yaml.Marshal(s.CoreValues); err != nil {
			p.addf("coreValues: %v", err)
		} else if s.SiteConfig, err = ParseSiteConfig(data); err != nil {
			p.addf("coreValues: %v", err)
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
