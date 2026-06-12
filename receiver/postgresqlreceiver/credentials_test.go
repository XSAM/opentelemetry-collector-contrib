// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/config/configcredentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
)

// staticProvider is a test credentials provider that returns a fixed credential.
// It re-reads from pointers so a test can mutate the returned secret between calls
// to simulate rotation.
type staticProvider struct {
	configcredentials.NopWatcher
	username *string
	secret   string
}

func (p *staticProvider) GetCredential(context.Context) (*configcredentials.Credential, error) {
	return &configcredentials.Credential{Username: p.username, Secret: p.secret}, nil
}

func baseConfigWithProvider(p configcredentials.Provider) postgreSQLConfig {
	return postgreSQLConfig{
		username:           "configured_user",
		address:            confignet.AddrConfig{Endpoint: "localhost:5432", Transport: confignet.TransportTypeTCP},
		credentialProvider: p,
	}
}

func TestConnectionString_ProviderSuppliesSecret(t *testing.T) {
	cfg := baseConfigWithProvider(&staticProvider{secret: "minted-token"})
	cs, err := cfg.ConnectionString()
	require.NoError(t, err)

	assert.Contains(t, cs, "password=minted-token", "provider secret goes into the password slot")
	assert.Contains(t, cs, "user=configured_user", "nil provider username falls back to the configured username")
}

func TestConnectionString_ProviderOverridesUsername(t *testing.T) {
	dynUser := "v-vault-generated"
	cfg := baseConfigWithProvider(&staticProvider{username: &dynUser, secret: "pw"})
	cs, err := cfg.ConnectionString()
	require.NoError(t, err)

	assert.Contains(t, cs, "user=v-vault-generated", "non-nil provider username overrides the configured one")
	assert.Contains(t, cs, "password=pw")
}

func TestConnectionString_NoProviderUsesStaticPassword(t *testing.T) {
	cfg := postgreSQLConfig{
		username: "u",
		password: "static-pw",
		address:  confignet.AddrConfig{Endpoint: "localhost:5432", Transport: confignet.TransportTypeTCP},
	}
	cs, err := cfg.ConnectionString()
	require.NoError(t, err)
	assert.Contains(t, cs, "password=static-pw")
}

func TestConnectionString_PullRefreshOnRebuild(t *testing.T) {
	p := &staticProvider{secret: "token-v1"}
	cfg := baseConfigWithProvider(p)

	cs1, err := cfg.ConnectionString()
	require.NoError(t, err)
	assert.Contains(t, cs1, "password=token-v1")

	// Simulate the provider rotating its token; a fresh ConnectionString (as built
	// per *sql.DB by getDB) must pick up the new value without any restart.
	p.secret = "token-v2"
	cs2, err := cfg.ConnectionString()
	require.NoError(t, err)
	assert.Contains(t, cs2, "password=token-v2")
}

func TestConfigValidate_PasswordAndCredentialsMutuallyExclusive(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "static"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrPasswordAndCredentials)
}

func TestConfigValidate_CredentialsWithoutPasswordIsValid(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	require.NoError(t, cfg.Validate(), "an authentication block satisfies the credential requirement without a password")
}

// fakeCredExtension is a minimal credentials-provider extension for tests: it
// lives in a host extension map and builds a provider from inline config, without
// importing the real aws_iam package.
type fakeCredExtension struct{}

func (fakeCredExtension) Start(context.Context, component.Host) error { return nil }
func (fakeCredExtension) Shutdown(context.Context) error              { return nil }
func (fakeCredExtension) CreateDefaultConfig() component.Config       { return &fakeCredConfig{} }

func (fakeCredExtension) CreateProvider(_ configcredentials.ProviderSettings, cfg component.Config) (configcredentials.Provider, error) {
	c := cfg.(*fakeCredConfig)
	if c.Region == "" {
		return nil, errors.New("fake: region required")
	}
	return &staticProvider{secret: "fake-token"}, nil
}

type fakeCredConfig struct {
	Region string `mapstructure:"region"`
}

func credExtMap() map[component.ID]component.Component {
	return map[component.ID]component.Component{
		component.MustNewID("aws_iam"): fakeCredExtension{},
	}
}

func TestResolveCredentialProvider_BuildsFromHostExtension(t *testing.T) {
	// The auth-type key matches a declared extension in the host map; the inline
	// config is unmarshaled into it and a provider is built.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	p, err := cfg.resolveCredentialProvider(credExtMap())
	require.NoError(t, err)
	require.NotNil(t, p, "a matching declared extension yields a provider")
}

func TestResolveCredentialProvider_NoMatchingExtension(t *testing.T) {
	// The auth-type key names an extension that is not declared in the host map.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	_, err := cfg.resolveCredentialProvider(map[component.ID]component.Component{})
	require.Error(t, err, "no declared extension matches the auth-type key")
}

func TestResolveCredentialProvider_NoAuthReturnsNil(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "pw"

	p, err := cfg.resolveCredentialProvider(credExtMap())
	require.NoError(t, err)
	assert.Nil(t, p, "no authentication block means no provider; the static password is used")
}

func TestNewPoolClientFactory_RefusesAuth(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	_, err := newPoolClientFactory(cfg)
	require.Error(t, err, "the connection pool gate is incompatible with an expiring credential")
	assert.True(t, strings.Contains(err.Error(), "connection_pool"))
}
