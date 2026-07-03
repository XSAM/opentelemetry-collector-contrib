// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/confmap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/config/configdbauth"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth"
)

// staticProvider is a test credentials provider that returns a fixed credential.
// It re-reads from pointers so a test can mutate the returned secret between calls
// to simulate rotation.
type staticProvider struct {
	username *string
	secret   string
}

func (p *staticProvider) GetCredential(context.Context, dbauth.Request, map[string]any) (*dbauth.Credential, error) {
	return &dbauth.Credential{Username: p.username, Secret: p.secret}, nil
}

func baseConfigWithProvider(p dbauth.Provider) postgreSQLConfig {
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

func TestConfigValidate_PasswordAndDBAuthMutuallyExclusive(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "static"
	cfg.DBAuth = configdbauth.Config{ProviderConfigs: map[string]any{"aws_iam": nil}}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrPasswordAndDBAuth)
}

func TestConfigValidate_DBAuthWithoutPasswordIsValid(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.DBAuth = configdbauth.Config{ProviderConfigs: map[string]any{"aws_iam": nil}}

	require.NoError(t, cfg.Validate(), "a db_auth block satisfies the credential requirement without a password")
}

// fakeCredExtension is a minimal credentials-provider extension for tests: it
// lives in a host extension map and implements dbauth.Provider directly, without
// importing the real aws_iam package.
type fakeCredExtension struct {
	secret string
}

func (fakeCredExtension) Start(context.Context, component.Host) error { return nil }
func (fakeCredExtension) Shutdown(context.Context) error              { return nil }

func (f fakeCredExtension) GetCredential(context.Context, dbauth.Request, map[string]any) (*dbauth.Credential, error) {
	return &dbauth.Credential{Secret: f.secret}, nil
}

func credExtMap() map[component.ID]component.Component {
	return map[component.ID]component.Component{
		component.MustNewID("aws_iam"): fakeCredExtension{secret: "fake-token"},
	}
}

func TestResolveCredentialProvider_ResolvesFromHostExtension(t *testing.T) {
	// The configured provider ID matches a declared extension in the host map, and
	// that extension implements dbauth.Provider, so it resolves.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.DBAuth = configdbauth.Config{ProviderConfigs: map[string]any{"aws_iam": nil}}

	p, _, err := cfg.resolveCredentialProvider(credExtMap())
	require.NoError(t, err)
	require.NotNil(t, p, "a matching declared provider extension resolves")
}

func TestResolveCredentialProvider_NoMatchingExtension(t *testing.T) {
	// The configured provider ID names an extension that is not declared in the host map.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.DBAuth = configdbauth.Config{ProviderConfigs: map[string]any{"aws_iam": nil}}

	_, _, err := cfg.resolveCredentialProvider(map[component.ID]component.Component{})
	require.Error(t, err, "no declared extension matches the provider ID")
}

func TestResolveCredentialProvider_NoAuthReturnsNil(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "pw"

	p, _, err := cfg.resolveCredentialProvider(credExtMap())
	require.NoError(t, err)
	assert.Nil(t, p, "no db_auth block means no provider; the static password is used")
}

func TestNewPoolClientFactory_AcceptsDBAuth(t *testing.T) {
	// The connection pool now composes with a db_auth block: the pool re-mints
	// per physical connection via credentialConnector, so an expiring token no
	// longer goes stale. The pool accepts an injected provider and still caches one
	// *sql.DB per database.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.DBAuth = configdbauth.Config{ProviderConfigs: map[string]any{"aws_iam": nil}}

	f := newPoolClientFactory(cfg)
	t.Cleanup(func() { require.NoError(t, f.close()) }) // close pooled *sql.DBs so goleak stays clean

	// With a provider injected, getClient builds a *sql.DB backed by the
	// credential-resolving connector (sql.OpenDB is lazy, so no real dial here) and
	// caches one per database.
	f.setCredentialProvider(&staticProvider{secret: "minted-token"}, nil)
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
	calls int
}

func (p *countingProvider) GetCredential(context.Context, dbauth.Request, map[string]any) (*dbauth.Credential, error) {
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

func TestConfigUnmarshal_DBAuthInlineOverride(t *testing.T) {
	// The receiver config's db_auth block is a type-keyed block: the single key is
	// the provider extension's component ID and its inline value is the override
	// passed to the provider. Confirm mapstructure's ",remain" capture round-trips
	// the real YAML shape into ProviderConfigs and that resolveCredentialProvider
	// returns that inline value as the args threaded to GetCredential.
	cfg := createDefaultConfig().(*Config)
	conf := confmap.NewFromStringMap(map[string]any{
		"endpoint": "db.example.com:5432",
		"username": "monitor",
		"db_auth": map[string]any{
			"aws_iam": map[string]any{"region": "us-east-1"},
		},
	})
	require.NoError(t, conf.Unmarshal(cfg))
	require.NoError(t, cfg.Validate())

	require.Equal(t,
		map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
		cfg.DBAuth.ProviderConfigs,
		"the whole db_auth block is captured by the ,remain tag")

	provider, args, err := cfg.resolveCredentialProvider(credExtMap())
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.Equal(t, map[string]any{"region": "us-east-1"}, args,
		"the inline value under the provider ID is threaded to GetCredential as the override")
}
