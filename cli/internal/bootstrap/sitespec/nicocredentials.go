// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sitespec

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dsx-ai-factory/nvke/cli/internal/deploypath/stackconfig"
	"github.com/dsx-ai-factory/nvke/cli/internal/envalias"
)

const (
	// NicoCredentialsEnv names the variable that holds the path to the NICo
	// client credentials. It is read on the host that runs the bootstrap, and
	// the credentials never enter the site spec.
	NicoCredentialsEnv = "NVKECTL_NICO_CREDENTIALS"

	// NicoInsecureEndpointEnv, set to 1, lets infra.nico.remote.endpoint and
	// the credentials' tokenURL be http URLs. The bootstrap sends the NICo
	// bearer token or client secret to them, so without it only https is
	// accepted; it is for a local or simulated NICo. infra.nico.managed needs
	// it too: the NICo the bootstrap installs serves REST over http.
	NicoInsecureEndpointEnv = "NVKECTL_NICO_ALLOW_INSECURE_ENDPOINT"

	// DefaultNicoAPIName is the API name in the NICo API path that CAPNICo is
	// given when infra.nico.remote.apiName is unset.
	DefaultNicoAPIName = "forge"
)

// structuredCredentialKey matches a key of the OAuth client-credentials form,
// in a YAML, JSON or KEY=VALUE file.
var structuredCredentialKey = regexp.MustCompile(`(?im)(^|[{,])\s*"?(tokenURL|clientID|clientSecret)"?\s*[:=]`)

// NicoCredentialsPath returns the path NVKECTL_NICO_CREDENTIALS names, or "".
func NicoCredentialsPath() string {
	return envalias.Get(NicoCredentialsEnv)
}

// NicoCredentials is what the bootstrap reaches an existing NICo's REST API
// with: a bearer Token, or an OAuth2 client (TokenURL, ClientID, ClientSecret).
type NicoCredentials struct {
	Token        string `yaml:"-"`
	TokenURL     string `yaml:"tokenURL"`
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
}

// ReadNicoCredentials reads the NICo credentials file at path. The format is
// told from the content: a file with tokenURL, clientID or clientSecret is the
// client-credentials form, a YAML or JSON map that must set all three, with
// tokenURL an http or https URL; anything else is a bearer token, one value
// with no whitespace inside it.
//
// The errors name neither path nor content: an operator who sets the variable
// to the token itself, rather than to a file holding it, must not see the token
// printed back.
func ReadNicoCredentials(path string) (NicoCredentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return NicoCredentials{}, errors.New("the file it names cannot be read (" + err.Error() +
			"); it must be the path of a file that holds the NICo token or client credentials, not the token itself")
	}
	content := strings.TrimSpace(string(data))
	switch {
	case content == "":
		return NicoCredentials{}, errors.New("the file it names is empty")
	case structuredCredentialKey.MatchString(content):
		return readClientCredentials(content)
	case strings.ContainsAny(content, " \t\r\n"):
		return NicoCredentials{}, errors.New("the file it names must hold only the NICo token, one value with no whitespace in it")
	}
	return NicoCredentials{Token: content}, nil
}

// readClientCredentials decodes the client-credentials form. Its errors carry
// no detail from the decoder, which would quote the content.
func readClientCredentials(content string) (NicoCredentials, error) {
	var creds NicoCredentials
	dec := yaml.NewDecoder(strings.NewReader(content))
	dec.KnownFields(true)
	if err := dec.Decode(&creds); err != nil {
		return NicoCredentials{}, errors.New("the file it names holds tokenURL, clientID or clientSecret, " +
			"but is not a YAML or JSON map of exactly those three keys")
	}
	var missing []string
	for _, f := range [][2]string{{"tokenURL", creds.TokenURL}, {"clientID", creds.ClientID}, {"clientSecret", creds.ClientSecret}} {
		if f[1] == "" {
			missing = append(missing, f[0])
		}
	}
	if len(missing) > 0 {
		return NicoCredentials{}, errors.New("the client credentials in the file it names need tokenURL, clientID and clientSecret; missing: " +
			strings.Join(missing, ", "))
	}
	if !validHTTPEndpoint(creds.TokenURL) {
		return NicoCredentials{}, errors.New("the tokenURL in the file it names must be an http or https URL")
	}
	return creds, nil
}

// NodeLoginFromEnv reads the login rendered into every node CAPNICo creates
// from NVKECTL_NODE_USER and NVKECTL_NODE_PASSWORD, trimmed. It names each one
// that is unset or holds a character the templates cannot carry, one problem
// per line, applying the same rules as stackconfig.CredentialsFromEnv, so the
// bootstrap and the stack install accept the same login.
func NodeLoginFromEnv() (user, password string, err error) {
	user = strings.TrimSpace(envalias.Get(stackconfig.EnvNodeUser))
	password = strings.TrimSpace(envalias.Get(stackconfig.EnvNodePassword))
	var problems []string
	for _, env := range [][2]string{{stackconfig.EnvNodeUser, user}, {stackconfig.EnvNodePassword, password}} {
		switch {
		case env[1] == "":
			problems = append(problems, env[0]+" is not set: the controller refuses to render a node's user data without the login")
		case !stackconfig.TemplateSafe(env[1]):
			problems = append(problems, env[0]+": the value holds a character the templates cannot carry (a quote, a backslash or a control character)")
		}
	}
	if len(problems) > 0 {
		return "", "", errors.New(strings.Join(problems, "\n"))
	}
	return user, password, nil
}
