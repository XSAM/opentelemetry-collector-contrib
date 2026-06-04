// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package awsiam provides an AWS RDS IAM database-authentication credentials
// provider for the configcredentials framework. It mints short-lived RDS auth
// tokens and supplies them as the connection secret, so a database receiver can
// authenticate to RDS/Aurora with IAM instead of a static password.
package awsiam // import "github.com/open-telemetry/opentelemetry-collector-contrib/credentialsprovider/awsiam"

import (
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configcredentials"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"
)

// typeStr is the inline auth-type key: authentication: { aws_iam: {...} }.
const typeStr = "aws_iam"

// NewFactory returns the aws_iam credentials provider factory. A consuming
// component adds it to the explicit []configcredentials.ProviderFactory it passes
// to Authentication.Resolve — there is no global registration.
func NewFactory() configcredentials.ProviderFactory {
	return &factory{}
}

type factory struct{}

func (*factory) Type() string { return typeStr }

func (*factory) CreateDefaultConfig() component.Config { return &Config{} }

func (*factory) CreateProvider(_ configcredentials.ProviderSettings, cfg component.Config) (configcredentials.Provider, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("aws_iam: unexpected config type %T", cfg)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &provider{
		minter: iamauth.NewMinter(),
		target: iamauth.Target{
			Endpoint: c.Endpoint,
			Region:   c.Region,
			DBUser:   c.DBUser,
			RoleARN:  c.RoleARN,
		},
	}, nil
}
