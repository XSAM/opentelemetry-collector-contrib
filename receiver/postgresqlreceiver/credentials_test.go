// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver

import (
	"context"
	"errors"
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

func TestNewPoolClientFactory_AcceptsCredentials(t *testing.T) {
	// The connection pool now composes with a credentials block: the pool re-mints
	// per physical connection via credentialConnector, so an expiring token no
	// longer goes stale. The pool accepts an injected provider and still caches one
	// *sql.DB per database.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Credentials = configcredentials.Config{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	f := newPoolClientFactory(cfg)
	t.Cleanup(func() { require.NoError(t, f.close()) }) // close pooled *sql.DBs so goleak stays clean

	// With a provider injected, getClient builds a *sql.DB backed by the
	// credential-resolving connector (sql.OpenDB is lazy, so no real dial here) and
	// caches one per database.
	f.setCredentialProvider(&staticProvider{secret: "minted-token"})
	c1, err := f.getClient("db1")
	require.NoError(t, err)
	require.NotNil(t, c1)
	c2, err := f.getClient("db1")
	require.NoError(t, err)
	assert.Same(t, c1.(*postgreSQLClient).client, c2.(*postgreSQLClient).client, "the pool caches one *sql.DB per database")
}

// countingProvider counts GetCredential calls and always errors, so the
// credentialConnector short-circuits before dialing — letting a test assert how
// many times the credential was resolved without a live database.
type countingProvider struct {
	configcredentials.NopWatcher
	calls int
}

func (p *countingProvider) GetCredential(context.Context) (*configcredentials.Credential, error) {
	p.calls++
	return nil, errors.New("mint failed")
}

func TestCredentialConnector_ResolvesPerConnect(t *testing.T) {
	// Each database/sql connection-open calls Connect, which must re-resolve the
	// credential — that is what keeps a long-lived pool from dialing with a stale
	// token. A counting provider proves one resolution per Connect.
	p := &countingProvider{}
	cfg := baseConfigWithProvider(p)
	conn := &credentialConnector{cfg: cfg}

	_, err1 := conn.Connect(context.Background())
	require.Error(t, err1, "the provider errors, surfaced before any dial")
	_, err2 := conn.Connect(context.Background())
	require.Error(t, err2)

	assert.Equal(t, 2, p.calls, "the credential is resolved once per Connect, not once per pool")
}

func TestCredentialConnector_PerConnectionRefresh(t *testing.T) {
	// A rotated secret must reach the next connection's DSN without rebuilding the
	// pool — the per-connect resolution in connectionString(ctx) is what delivers it.
	p := &staticProvider{secret: "token-v1"}
	cfg := baseConfigWithProvider(p)

	cs1, err := cfg.connectionString(context.Background())
	require.NoError(t, err)
	assert.Contains(t, cs1, "password=token-v1")

	p.secret = "token-v2"
	cs2, err := cfg.connectionString(context.Background())
	require.NoError(t, err)
	assert.Contains(t, cs2, "password=token-v2", "the next connection picks up the rotated secret")
}
