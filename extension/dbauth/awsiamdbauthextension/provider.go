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

// GetCredential mints (or returns a cached) RDS IAM auth token for the requested
// endpoint and user and returns it as the Secret. Username is nil — the consumer
// uses its own configured username. The endpoint and user come from the request;
// the region and optional role_arn come from the extension's own config, with any
// per-consumer overrides in extensionArgs merged over them for this call only.
func (e *iamExtension) GetCredential(ctx context.Context, req dbauth.Request, extensionArgs map[string]any) (*dbauth.Credential, error) {
	cfg, err := e.mergedConfig(extensionArgs)
	if err != nil {
		return nil, err
	}
	token, notAfter, err := e.minter.Token(ctx, target{
		Endpoint: req.Endpoint,
		Region:   cfg.Region,
		DBUser:   req.Username,
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

// mergedConfig returns the effective config for a single GetCredential call: a
// copy of the extension's own config with extensionArgs overlaid on top. Only the
// keys present in extensionArgs are overridden; the rest keep the configured
// defaults. The extension's own config is never mutated, so concurrent calls with
// different overrides do not interfere. The merged config is re-validated because
// an override may itself clear a required field (e.g. region: "").
//
// confmap unmarshals strictly, so an override key that is not one of this
// provider's config fields (typically a typo such as "regionn") fails here rather
// than being silently dropped — the same strictness the Collector applies to
// every component config. That is deliberate: silently ignoring a misspelled
// region override would keep minting against the default region while the operator
// believes they switched, so the mistake is surfaced instead.
func (e *iamExtension) mergedConfig(extensionArgs map[string]any) (*Config, error) {
	merged := *e.cfg
	if len(extensionArgs) > 0 {
		if err := confmap.NewFromStringMap(extensionArgs).Unmarshal(&merged); err != nil {
			return nil, fmt.Errorf("aws_iam: invalid db_auth override: %w", err)
		}
		if err := merged.Validate(); err != nil {
			return nil, fmt.Errorf("aws_iam: invalid db_auth override: %w", err)
		}
	}
	return &merged, nil
}
