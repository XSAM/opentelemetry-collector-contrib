// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth/awsiamdbauthextension"

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
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
// Each mint input is resolved from up to three sources, highest precedence first:
//
//  1. the receiver's inline db_auth override (extensionArgs),
//  2. the per-connection dbauth.Request the receiver made, and
//  3. the extension's own config.
//
// So a value set in the db_auth block wins; otherwise the receiver's own endpoint
// and username are used; otherwise the extension's configured defaults apply. The
// region has no request source, so for it this collapses to override-then-config;
// it must resolve to a non-empty value from one of those before a token can be
// minted, so an empty merged region is an error here.
func (e *iamExtension) GetCredential(ctx context.Context, req dbauth.Request, extensionArgs map[string]any) (*dbauth.Credential, error) {
	cfg, err := e.mergedConfig(req, extensionArgs)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		return nil, errNoRegion
	}
	token, notAfter, err := e.minter.Token(ctx, target{
		Endpoint: cfg.Endpoint,
		Region:   cfg.Region,
		DBUser:   cfg.DBUser,
		RoleARN:  cfg.RoleARN,
	})
	if err != nil {
		return nil, err
	}
	return &dbauth.Credential{
		Secret:   token,
		NotAfter: &notAfter,
	}, nil
}

// mergedConfig returns the effective config for a single GetCredential call. It
// layers the three input sources so that precedence falls out of the merge order:
// it starts from a copy of the extension's own config, seeds the request's
// per-connection endpoint/user onto it (so the request outranks the extension's
// own endpoint/db_user), then overlays extensionArgs last (so a db_auth override
// outranks both). The extension's own config is never mutated, so concurrent calls
// with different requests or overrides do not interfere.
//
// confmap unmarshals strictly, so an override key that is not one of this
// provider's config fields (typically a typo such as "regionn") fails here rather
// than being silently dropped — the same strictness the Collector applies to
// every component config. That is deliberate: silently ignoring a misspelled
// region override would keep minting against the default region while the operator
// believes they switched, so the mistake is surfaced instead.
func (e *iamExtension) mergedConfig(req dbauth.Request, extensionArgs map[string]any) (*Config, error) {
	merged := *e.cfg
	// The request's per-connection inputs sit beneath a db_auth override but above
	// the extension's own endpoint/db_user, so seed them before overlaying the
	// override. An empty request field leaves the extension's default in place.
	if req.Endpoint != "" {
		merged.Endpoint = req.Endpoint
	}
	if req.Username != "" {
		merged.DBUser = req.Username
	}
	if len(extensionArgs) > 0 {
		if err := confmap.NewFromStringMap(extensionArgs).Unmarshal(&merged); err != nil {
			return nil, fmt.Errorf("aws_iam: invalid db_auth override: %w", err)
		}
	}
	return &merged, nil
}
