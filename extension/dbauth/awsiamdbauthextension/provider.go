// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth/awsiamdbauthextension"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth"
)

// tokenMinter is the subset of *minter the extension uses. Defined as an
// interface so tests inject a fake without touching AWS.
type tokenMinter interface {
	Token(ctx context.Context, t target) (token string, notAfter time.Time, err error)
}

// iamExtension is the aws_iam provider. It is a Collector extension (so it lives
// in the host extension map) that also implements dbauth.Provider. It mints
// short-lived RDS IAM auth tokens on demand, cached per target until shortly
// before expiry, and supplies them as the connection secret.
type iamExtension struct {
	cfg    *Config
	minter tokenMinter
}

var (
	_ extension.Extension = (*iamExtension)(nil)
	_ dbauth.Provider     = (*iamExtension)(nil)
)

func (*iamExtension) Start(context.Context, component.Host) error { return nil }
func (*iamExtension) Shutdown(context.Context) error              { return nil }

// GetCredential mints (or returns a cached) RDS IAM auth token for the resolved
// endpoint and user and returns it as the Secret. Username is nil — the consumer
// uses its own configured username.
//
// The endpoint and database user are taken from the per-connection dbauth.Request
// when it supplies them; otherwise they fall back to the extension's own config.
// The region has no request source and comes only from the extension config,
// where it is required (validated at load).
func (e *iamExtension) GetCredential(ctx context.Context, req dbauth.Request) (*dbauth.Credential, error) {
	endpoint := e.cfg.Endpoint
	if req.Endpoint != "" {
		endpoint = req.Endpoint
	}
	dbUser := e.cfg.DBUser
	if req.Username != "" {
		dbUser = req.Username
	}

	token, notAfter, err := e.minter.Token(ctx, target{
		Endpoint: endpoint,
		Region:   e.cfg.Region,
		DBUser:   dbUser,
	})
	if err != nil {
		return nil, err
	}
	return &dbauth.Credential{
		Secret:   token,
		NotAfter: &notAfter,
	}, nil
}
