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

func TestConfig_Validate(t *testing.T) {
	require.ErrorIs(t, (&Config{}).Validate(), errNoRegion)
	require.NoError(t, (&Config{Region: "us-east-1"}).Validate())
	require.NoError(t, (&Config{Region: "us-east-1", RoleARN: "arn:role"}).Validate())
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

func TestGetCredential_ExtensionArgsClearingRequiredFieldErrors(t *testing.T) {
	// An override that clears a required field (region) fails the merged config's
	// validation rather than minting against an empty region.
	m := &fakeMinter{token: "rds-token"}
	e := newExtensionWithMinter(&Config{Region: "us-east-2"}, m)

	_, err := e.GetCredential(context.Background(),
		dbauth.Request{Endpoint: "db:5432", Username: "monitor"},
		map[string]any{"region": ""})
	require.ErrorIs(t, err, errNoRegion)
	assert.Equal(t, int64(0), m.calls, "an invalid override never reaches the minter")
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
