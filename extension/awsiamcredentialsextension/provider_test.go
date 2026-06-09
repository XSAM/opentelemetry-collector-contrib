// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamcredentialsextension

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configcredentials"
	"go.opentelemetry.io/collector/extension"
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

func newProviderWithMinter(c *providerConfig, m tokenMinter) *provider {
	return &provider{
		minter: m,
		target: target{Endpoint: c.Endpoint, Region: c.Region, DBUser: c.DBUser, RoleARN: c.RoleARN},
	}
}

// newProviderFactory creates the extension and asserts it implements
// ProviderFactory — the dual role consumers depend on.
func newProviderFactory(t *testing.T) configcredentials.ProviderFactory {
	t.Helper()
	ext, err := createExtension(context.Background(), extension.Settings{}, &Config{})
	require.NoError(t, err)
	pf, ok := ext.(configcredentials.ProviderFactory)
	require.True(t, ok, "the aws_iam extension must implement configcredentials.ProviderFactory")
	return pf
}

func TestFactory_TypeAndStability(t *testing.T) {
	f := NewFactory()
	assert.Equal(t, "aws_iam", f.Type().String())
}

func TestExtension_DefaultProviderConfig(t *testing.T) {
	pf := newProviderFactory(t)
	_, ok := pf.CreateDefaultConfig().(*providerConfig)
	assert.True(t, ok, "default provider config is *providerConfig")
}

func TestExtension_CreateProvider_ValidatesConfig(t *testing.T) {
	pf := newProviderFactory(t)
	// Missing region/endpoint/db_user must fail Validate.
	_, err := pf.CreateProvider(configcredentials.ProviderSettings{}, &providerConfig{})
	require.ErrorIs(t, err, errNoRegion)

	_, err = pf.CreateProvider(configcredentials.ProviderSettings{}, &providerConfig{Region: "us-east-1"})
	require.ErrorIs(t, err, errNoEndpoint)

	_, err = pf.CreateProvider(configcredentials.ProviderSettings{}, &providerConfig{Region: "us-east-1", Endpoint: "db:5432"})
	require.ErrorIs(t, err, errNoDBUser)
}

func TestExtension_CreateProvider_BuildsProvider(t *testing.T) {
	pf := newProviderFactory(t)
	p, err := pf.CreateProvider(configcredentials.ProviderSettings{}, &providerConfig{
		Region: "us-east-1", Endpoint: "db:5432", DBUser: "monitor",
	})
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestExtension_StartShutdownNoop(t *testing.T) {
	ext, err := createExtension(context.Background(), extension.Settings{}, &Config{})
	require.NoError(t, err)
	require.NoError(t, ext.Start(context.Background(), nil))
	require.NoError(t, ext.Shutdown(context.Background()))
}

func TestProvider_GetCredential(t *testing.T) {
	exp := time.Unix(2000, 0)
	m := &fakeMinter{token: "rds-token", notAfter: exp}
	c := &providerConfig{Region: "us-east-1", Endpoint: "db:5432", DBUser: "monitor", RoleARN: "arn:role"}
	p := newProviderWithMinter(c, m)

	cred, err := p.GetCredential(context.Background())
	require.NoError(t, err)

	assert.Nil(t, cred.Username, "AWS IAM supplies no username; consumer uses its configured one")
	assert.Equal(t, "rds-token", cred.Secret)
	require.NotNil(t, cred.NotAfter)
	assert.Equal(t, exp, *cred.NotAfter)
	// target (incl. role_arn) is threaded to the minter.
	assert.Equal(t, target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor", RoleARN: "arn:role"}, m.lastTgt)
}

func TestProvider_GetCredential_MintError(t *testing.T) {
	sentinel := errors.New("mint failed")
	p := newProviderWithMinter(&providerConfig{}, &fakeMinter{err: sentinel})
	_, err := p.GetCredential(context.Background())
	require.ErrorIs(t, err, sentinel)
}

func TestProvider_WatchIsNoop(t *testing.T) {
	// Embedded NopWatcher: Watch registers successfully and never fires.
	var p configcredentials.Provider = newProviderWithMinter(&providerConfig{}, &fakeMinter{})
	called := false
	stop, err := p.Watch(context.Background(), func(*configcredentials.Credential) { called = true })
	require.NoError(t, err)
	require.NotNil(t, stop)
	assert.NotPanics(t, stop)
	assert.False(t, called)
}
