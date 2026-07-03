// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/extension"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth"
)

// fakeMinter records calls and returns a canned token without touching AWS.
type fakeMinter struct {
	token    string
	notAfter time.Time
	err      error
	calls    int64
	lastTgt  target
}

func (f *fakeMinter) Token(_ context.Context, t target) (string, time.Time, error) {
	atomic.AddInt64(&f.calls, 1)
	f.lastTgt = t
	return f.token, f.notAfter, f.err
}

func newExtensionWithMinter(c *Config, m tokenMinter) *iamExtension {
	return &iamExtension{cfg: c, minter: m}
}

// newProviderExtension creates the extension via the factory and asserts it
// implements dbauth.Provider — the dual role consumers depend on.
func newProviderExtension(t *testing.T, cfg *Config) dbauth.Provider {
	t.Helper()
	ext, err := createExtension(context.Background(), extension.Settings{}, cfg)
	require.NoError(t, err)
	p, ok := ext.(dbauth.Provider)
	require.True(t, ok, "the aws_iam extension must implement dbauth.Provider")
	return p
}

func TestFactory_TypeAndStability(t *testing.T) {
	f := NewFactory()
	assert.Equal(t, "aws_iam", f.Type().String())
}

func TestFactory_DefaultConfig(t *testing.T) {
	cfg := NewFactory().CreateDefaultConfig()
	_, ok := cfg.(*Config)
	assert.True(t, ok, "default config is *Config")
}

func TestExtension_ImplementsProvider(t *testing.T) {
	p := newProviderExtension(t, &Config{Region: "us-east-1"})
	require.NotNil(t, p)
}

func TestExtension_StartShutdownNoop(t *testing.T) {
	ext, err := createExtension(context.Background(), extension.Settings{}, &Config{Region: "us-east-1"})
	require.NoError(t, err)
	require.NoError(t, ext.Start(context.Background(), nil))
	require.NoError(t, ext.Shutdown(context.Background()))
}

func TestGetCredential(t *testing.T) {
	exp := time.Unix(2000, 0)
	m := &fakeMinter{token: "rds-token", notAfter: exp}
	e := newExtensionWithMinter(&Config{Region: "us-east-1", RoleARN: "arn:role"}, m)

	cred, err := e.GetCredential(context.Background(), dbauth.Request{Endpoint: "db:5432", Username: "monitor"}, nil)
	require.NoError(t, err)

	assert.Nil(t, cred.Username, "AWS IAM supplies no username; consumer uses its configured one")
	assert.Equal(t, "rds-token", cred.Secret)
	require.NotNil(t, cred.NotAfter)
	assert.Equal(t, exp, *cred.NotAfter)

	// The request's endpoint/username plus the extension's region/role_arn are
	// threaded to the minter as the per-connection target.
	assert.Equal(t,
		target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor", RoleARN: "arn:role"},
		m.lastTgt)
}

func TestGetCredential_MintError(t *testing.T) {
	sentinel := errors.New("mint failed")
	e := newExtensionWithMinter(&Config{Region: "us-east-1"}, &fakeMinter{err: sentinel})
	_, err := e.GetCredential(context.Background(), dbauth.Request{Endpoint: "db:5432", Username: "monitor"}, nil)
	require.ErrorIs(t, err, sentinel)
}

func TestGetCredential_ExtensionArgsOverrideRegion(t *testing.T) {
	// The extension's configured region is the default; a consumer's inline
	// db_auth override for that provider replaces individual fields for its calls
	// only, without mutating the shared extension config.
	exp := time.Unix(2000, 0)
	m := &fakeMinter{token: "rds-token", notAfter: exp}
	e := newExtensionWithMinter(&Config{Region: "us-east-2", RoleARN: "arn:role"}, m)

	cred, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"},
		map[string]any{"region": "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, "rds-token", cred.Secret)

	// The override replaces the region; role_arn is untouched (not in the override).
	assert.Equal(t,
		target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor", RoleARN: "arn:role"},
		m.lastTgt)

	// The override is per call: the extension's own config is unchanged, so a
	// later call with no override falls back to the configured default.
	assert.Equal(t, "us-east-2", e.cfg.Region, "the shared extension config is not mutated by an override")
	_, err = e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "us-east-2", m.lastTgt.Region, "with no override the configured default is used")
}

func TestGetCredential_RegionFromOverrideOnly(t *testing.T) {
	// The extension is declared with no region — the "declare aws_iam once, let
	// each receiver supply its region" pattern. A receiver's override provides the
	// region, and minting succeeds against it. This is why region is not a
	// config-load requirement on the extension.
	exp := time.Unix(2000, 0)
	m := &fakeMinter{token: "rds-token", notAfter: exp}
	e := newExtensionWithMinter(&Config{}, m)

	cred, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"},
		map[string]any{"region": "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, "rds-token", cred.Secret)
	assert.Equal(t,
		target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"},
		m.lastTgt, "the region comes entirely from the receiver's override")
}

func TestGetCredential_NoRegionFromEitherSourceErrors(t *testing.T) {
	// Region is required to mint, but only at mint time and from either source.
	// When neither the extension nor the override supplies it, the call errors
	// before reaching the minter rather than minting against an empty region.
	m := &fakeMinter{token: "rds-token"}
	e := newExtensionWithMinter(&Config{}, m)

	// Neither source: no default on the extension, no override.
	_, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"}, nil)
	require.ErrorIs(t, err, errNoRegion)

	// An override that explicitly clears the region is likewise rejected.
	e = newExtensionWithMinter(&Config{Region: "us-east-2"}, m)
	_, err = e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"},
		map[string]any{"region": ""})
	require.ErrorIs(t, err, errNoRegion)

	assert.Equal(t, int64(0), m.calls, "a missing region never reaches the minter")
}

func TestGetCredential_EndpointAndDBUserFromConfig(t *testing.T) {
	// When the receiver makes a request with no endpoint/username, the extension's
	// own configured endpoint and db_user are used — the lowest-precedence source.
	m := &fakeMinter{token: "rds-token", notAfter: time.Unix(2000, 0)}
	e := newExtensionWithMinter(&Config{Region: "us-east-1", Endpoint: "cfg-db:5432", DBUser: "cfg_user"}, m)

	_, err := e.GetCredential(context.Background(), dbauth.Request{}, nil)
	require.NoError(t, err)
	assert.Equal(t,
		target{Endpoint: "cfg-db:5432", Region: "us-east-1", DBUser: "cfg_user"},
		m.lastTgt, "with an empty request the extension's configured endpoint/db_user are used")
}

func TestGetCredential_RequestOutranksConfigEndpointAndDBUser(t *testing.T) {
	// The receiver's per-connection request outranks the extension's own configured
	// endpoint/db_user: a receiver that supplies its own values gets those, not the
	// extension's provider-wide defaults.
	m := &fakeMinter{token: "rds-token", notAfter: time.Unix(2000, 0)}
	e := newExtensionWithMinter(&Config{Region: "us-east-1", Endpoint: "cfg-db:5432", DBUser: "cfg_user"}, m)

	_, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "req-db:5432", Username: "req_user"}, nil)
	require.NoError(t, err)
	assert.Equal(t,
		target{Endpoint: "req-db:5432", Region: "us-east-1", DBUser: "req_user"},
		m.lastTgt, "the request's endpoint/username outrank the extension's configured ones")
}

func TestGetCredential_OverrideOutranksRequestEndpointAndDBUser(t *testing.T) {
	// The db_auth override is the highest-precedence source: endpoint/db_user set
	// inline under the provider ID win over both the request and the extension
	// config. This is the case the user's config exercises.
	m := &fakeMinter{token: "rds-token", notAfter: time.Unix(2000, 0)}
	e := newExtensionWithMinter(&Config{Region: "us-east-1", Endpoint: "cfg-db:5432", DBUser: "cfg_user"}, m)

	_, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "req-db:5432", Username: "req_user"},
		map[string]any{"endpoint": "override-db:5432", "db_user": "override_user"})
	require.NoError(t, err)
	assert.Equal(t,
		target{Endpoint: "override-db:5432", Region: "us-east-1", DBUser: "override_user"},
		m.lastTgt, "the db_auth override outranks both the request and the extension config")

	// The override is per call: the shared extension config is not mutated.
	assert.Equal(t, "cfg-db:5432", e.cfg.Endpoint, "the shared extension config is not mutated by an override")
	assert.Equal(t, "cfg_user", e.cfg.DBUser)
}

func TestGetCredential_ExtensionArgsUnknownKeyErrors(t *testing.T) {
	// confmap unmarshals strictly: an override key that is not one of the
	// provider's config fields (a typo such as "regionn") is rejected rather than
	// silently dropped, so the misspelled override never leaves the default region
	// silently in place. The valid "region" alongside it does not rescue the call.
	m := &fakeMinter{token: "rds-token"}
	e := newExtensionWithMinter(&Config{Region: "us-east-2"}, m)

	_, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"},
		map[string]any{"region": "us-east-1", "regionn": "us-east-1"})
	require.Error(t, err, "an unrecognized override key is an operator error, not ignored")
	assert.Contains(t, err.Error(), "regionn", "the error names the offending key")
	assert.Equal(t, int64(0), m.calls, "an invalid override never reaches the minter")
}
