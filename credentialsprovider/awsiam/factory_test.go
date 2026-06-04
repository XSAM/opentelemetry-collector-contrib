// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configcredentials"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"
)

// fakeMinter records calls and returns a canned token without touching AWS.
type fakeMinter struct {
	token    string
	notAfter time.Time
	err      error
	calls    int64
	lastTgt  iamauth.Target
}

func (f *fakeMinter) Token(_ context.Context, t iamauth.Target) (string, time.Time, error) {
	atomic.AddInt64(&f.calls, 1)
	f.lastTgt = t
	return f.token, f.notAfter, f.err
}

func newProviderWithMinter(c *Config, m minter) *provider {
	return &provider{
		minter: m,
		target: iamauth.Target{Endpoint: c.Endpoint, Region: c.Region, DBUser: c.DBUser, RoleARN: c.RoleARN},
	}
}

func TestFactory_TypeAndDefaultConfig(t *testing.T) {
	f := NewFactory()
	assert.Equal(t, "aws_iam", f.Type())
	_, ok := f.CreateDefaultConfig().(*Config)
	assert.True(t, ok, "default config is *Config")
}

func TestFactory_CreateProvider_ValidatesConfig(t *testing.T) {
	f := NewFactory()
	// Missing region/endpoint/db_user must fail Validate.
	_, err := f.CreateProvider(configcredentials.ProviderSettings{}, &Config{})
	require.ErrorIs(t, err, errNoRegion)

	_, err = f.CreateProvider(configcredentials.ProviderSettings{}, &Config{Region: "us-east-1"})
	require.ErrorIs(t, err, errNoEndpoint)

	_, err = f.CreateProvider(configcredentials.ProviderSettings{}, &Config{Region: "us-east-1", Endpoint: "db:5432"})
	require.ErrorIs(t, err, errNoDBUser)
}

func TestFactory_CreateProvider_BuildsProvider(t *testing.T) {
	f := NewFactory()
	p, err := f.CreateProvider(configcredentials.ProviderSettings{}, &Config{
		Region: "us-east-1", Endpoint: "db:5432", DBUser: "monitor",
	})
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestProvider_GetCredential(t *testing.T) {
	exp := time.Unix(2000, 0)
	m := &fakeMinter{token: "rds-token", notAfter: exp}
	c := &Config{Region: "us-east-1", Endpoint: "db:5432", DBUser: "monitor", RoleARN: "arn:role"}
	p := newProviderWithMinter(c, m)

	cred, err := p.GetCredential(context.Background())
	require.NoError(t, err)

	assert.Nil(t, cred.Username, "AWS IAM supplies no username; consumer uses its configured one")
	assert.Equal(t, "rds-token", cred.Secret)
	require.NotNil(t, cred.NotAfter)
	assert.Equal(t, exp, *cred.NotAfter)
	// Target (incl. role_arn) is threaded to the minter.
	assert.Equal(t, iamauth.Target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor", RoleARN: "arn:role"}, m.lastTgt)
}

func TestProvider_GetCredential_MintError(t *testing.T) {
	sentinel := errors.New("mint failed")
	p := newProviderWithMinter(&Config{}, &fakeMinter{err: sentinel})
	_, err := p.GetCredential(context.Background())
	require.ErrorIs(t, err, sentinel)
}

func TestProvider_WatchIsNoop(t *testing.T) {
	// Embedded NopWatcher: Watch registers successfully and never fires.
	var p configcredentials.Provider = newProviderWithMinter(&Config{}, &fakeMinter{})
	called := false
	stop, err := p.Watch(context.Background(), func(*configcredentials.Credential) { called = true })
	require.NoError(t, err)
	require.NotNil(t, stop)
	assert.NotPanics(t, stop)
	assert.False(t, called)
}
