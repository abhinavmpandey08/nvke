// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nicorest calls NICo's REST API with an OAuth2 client-credentials token.
package nicorest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultAPIName is the API name NICo's REST API serves under.
const DefaultAPIName = "nico"

// Client calls one org of a NICo REST API.
type Client struct {
	endpoint string
	orgID    string
	apiName  string
	http     *http.Client
}

// ClientCredentials is an OAuth2 client of the identity provider NICo's REST API trusts.
type ClientCredentials struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
}

// New returns a Client for the org orgID of the REST API at endpoint, served
// under apiName, that fetches its tokens with creds.
func New(endpoint, orgID, apiName string, creds ClientCredentials) *Client {
	base := &http.Client{Timeout: 30 * time.Second}
	cc := clientcredentials.Config{ClientID: creds.ClientID, ClientSecret: creds.ClientSecret, TokenURL: creds.TokenURL}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, base)
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		orgID:    orgID,
		apiName:  apiName,
		http:     &http.Client{Timeout: base.Timeout, Transport: &oauth2.Transport{Source: cc.TokenSource(ctx), Base: base.Transport}},
	}
}

// StatusError is a response the REST API answered with a status other than 2xx.
type StatusError struct {
	Method string
	Path   string
	Code   int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("NICo REST %s %s: %d %s", e.Method, e.Path, e.Code, strings.TrimSpace(e.Body))
}

// IsStatus reports whether err is a StatusError with code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Do sends method to path, relative to /v2/org/<org>/<apiName>, with in as a
// JSON body when it is not nil, and decodes the JSON answer into out when it
// is not nil. path may carry a query string.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding the body of %s %s: %w", method, path, err)
		}
		body = bytes.NewReader(b)
	}
	url := fmt.Sprintf("%s/v2/org/%s/%s/%s", c.endpoint, c.orgID, c.apiName, strings.TrimLeft(path, "/"))
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("NICo REST %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("NICo REST %s %s: reading the answer: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{Method: method, Path: path, Code: resp.StatusCode, Body: string(raw)}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("NICo REST %s %s: decoding the answer: %w", method, path, err)
	}
	return nil
}
