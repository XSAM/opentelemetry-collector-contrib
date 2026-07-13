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
	e := newExtensionWithMinter(&Config{Region: "us-east-1"}, m)

	cred, err := e.GetCredential(context.Background(), dbauth.Request{Endpoint: "db:5432", Username: "monitor"})
	require.NoError(t, err)

	assert.Nil(t, cred.Username, "AWS IAM supplies no username; consumer uses its configured one")
	assert.Equal(t, "rds-token", cred.Secret)
	require.NotNil(t, cred.NotAfter)
	assert.Equal(t, exp, *cred.NotAfter)

	// The request's endpoint/username plus the extension's region are threaded to
	// the minter as the per-connection target.
	assert.Equal(t,
		target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"},
		m.lastTgt)
}

func TestGetCredential_MintError(t *testing.T) {
	sentinel := errors.New("mint failed")
	e := newExtensionWithMinter(&Config{Region: "us-east-1"}, &fakeMinter{err: sentinel})
	_, err := e.GetCredential(context.Background(), dbauth.Request{Endpoint: "db:5432", Username: "monitor"})
	require.ErrorIs(t, err, sentinel)
}

func TestGetCredential_EndpointAndDBUserFromConfig(t *testing.T) {
	// When the receiver makes a request with no endpoint/username, the extension's
	// own configured endpoint and db_user are used — the fallback source.
	m := &fakeMinter{token: "rds-token", notAfter: time.Unix(2000, 0)}
	e := newExtensionWithMinter(&Config{Region: "us-east-1", Endpoint: "cfg-db:5432", DBUser: "cfg_user"}, m)

	_, err := e.GetCredential(context.Background(), dbauth.Request{})
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
		dbauth.Request{Endpoint: "req-db:5432", Username: "req_user"})
	require.NoError(t, err)
	assert.Equal(t,
		target{Endpoint: "req-db:5432", Region: "us-east-1", DBUser: "req_user"},
		m.lastTgt, "the request's endpoint/username outrank the extension's configured ones")
}
