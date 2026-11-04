// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"
)

// checkTimeout bounds one attempt of a check.
const checkTimeout = 10 * time.Second

// verify checks that the installed NICo answers on its published addresses:
// REST accepts a token from inst's credentials, the API presents a
// certificate for its host name, PXE serves HTTP on both its ports, and, when
// NICo runs the .forge resolver, carbide-api.forge resolves to the API through
// it. Each check is retried until cfg.Timeout.
func (e *Engine) verify(ctx context.Context, cfg Config, inst *Installed) error {
	if cfg.Settings == nil || inst == nil {
		return errors.New("nicodeploy: Settings and the installed NICo are required to verify it")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	a := cfg.Settings.Addresses
	rest := inst.REST()
	type check struct {
		what  string
		check func(context.Context) error
	}
	checks := []check{
		{"NICo REST at " + inst.RESTEndpoint + " to accept a token", func(ctx context.Context) error {
			return rest.Do(ctx, http.MethodGet, "site", nil, nil)
		}},
		{"the NICo API at " + a.API + " to present a certificate for " + cfg.Settings.APIHostname, func(ctx context.Context) error {
			return checkCertificate(ctx, net.JoinHostPort(a.API, "443"), cfg.Settings.APIHostname)
		}},
		{"NICo PXE at " + a.PXE + ":80", func(ctx context.Context) error {
			return checkHTTP(ctx, "http://"+net.JoinHostPort(a.PXE, "80")+"/metrics")
		}},
		{"NICo PXE at " + a.PXE + ":8080", func(ctx context.Context) error {
			return checkHTTP(ctx, "http://"+net.JoinHostPort(a.PXE, "8080")+"/metrics")
		}},
	}
	if a.DNS != "" {
		checks = append(checks, check{"carbide-api.forge to resolve to " + a.API + " through " + a.DNS, func(ctx context.Context) error {
			return checkResolves(ctx, net.JoinHostPort(a.DNS, "53"), "carbide-api.forge", a.API)
		}})
	}
	for _, c := range checks {
		var last error
		if err := e.until(ctx, timeout, c.what, func(ctx context.Context) (bool, error) {
			attempt, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()
			last = c.check(attempt)
			return last == nil, nil
		}); err != nil {
			return fmt.Errorf("%w: %w", err, last)
		}
	}
	e.log.Info("NICo answers on its addresses", "api", a.API, "rest", inst.RESTEndpoint, "pxe", a.PXE)
	return nil
}

// checkCertificate checks that the TLS server at addr presents a certificate
// valid for hostname. Only the names are checked: the issuing CA is NICo's.
func checkCertificate(ctx context.Context, addr, hostname string) error {
	named := false
	d := tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // the names are checked below; nvkectl does not hold NICo's CA
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate presented")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if err := leaf.VerifyHostname(hostname); err != nil {
				return err
			}
			named = true
			return nil
		},
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	// A server that wants a client certificate refuses the handshake after presenting its own.
	if named {
		return nil
	}
	if err == nil {
		err = errors.New("no certificate presented")
	}
	return err
}

// checkHTTP checks that url answers 200.
func checkHTTP(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return nil
}

// checkResolves checks that the DNS server at addr resolves name to want.
func checkResolves(ctx context.Context, addr, name, want string) error {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	// The trailing dot keeps the host's search domains out of the query.
	got, err := r.LookupHost(ctx, name+".")
	if err != nil {
		return err
	}
	if !slices.Contains(got, want) {
		return fmt.Errorf("%s resolves to %v, not %s", name, got, want)
	}
	return nil
}
