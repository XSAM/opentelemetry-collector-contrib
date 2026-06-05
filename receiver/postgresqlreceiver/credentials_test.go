// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configcredentials"
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

func TestConfigValidate_PasswordAndAuthMutuallyExclusive(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "static"
	cfg.Authentication = configcredentials.Authentication{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrPasswordAndAuth)
}

func TestConfigValidate_AuthWithoutPasswordIsValid(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Authentication = configcredentials.Authentication{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	require.NoError(t, cfg.Validate(), "an authentication block satisfies the credential requirement without a password")
}

func TestResolveCredentialProvider_BuildsFromOperatorConfig(t *testing.T) {
	// The operator supplies the provider's mint inputs (endpoint, db_user) inline;
	// the receiver does not inject them, staying agnostic to the provider schema.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.Authentication = configcredentials.Authentication{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{
			"region":   "us-east-1",
			"endpoint": "db.example.com:5432",
			"db_user":  "monitor",
		}},
	}

	p, err := cfg.resolveCredentialProvider()
	require.NoError(t, err)
	require.NotNil(t, p, "a fully-configured authentication block yields a provider")
}

func TestResolveCredentialProvider_MissingMintInputsErrors(t *testing.T) {
	// Without the provider's required inputs, resolve fails — the receiver does not
	// silently fill them in.
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "db.example.com:5432"
	cfg.Username = "monitor"
	cfg.Authentication = configcredentials.Authentication{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	_, err := cfg.resolveCredentialProvider()
	require.Error(t, err, "aws_iam requires endpoint and db_user from the operator")
}

func TestResolveCredentialProvider_NoAuthReturnsNil(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Password = "pw"

	p, err := cfg.resolveCredentialProvider()
	require.NoError(t, err)
	assert.Nil(t, p, "no authentication block means no provider; the static password is used")
}

func TestNewPoolClientFactory_RefusesAuth(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = "localhost:5432"
	cfg.Username = "u"
	cfg.Authentication = configcredentials.Authentication{
		ProviderConfigs: map[string]any{"aws_iam": map[string]any{"region": "us-east-1"}},
	}

	_, err := newPoolClientFactory(cfg)
	require.Error(t, err, "the connection pool gate is incompatible with an expiring credential")
	assert.True(t, strings.Contains(err.Error(), "connection_pool"))
}
