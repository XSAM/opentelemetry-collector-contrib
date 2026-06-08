// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package iamauth // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"

import "errors"

// Config is the inline sub-config for the aws_iam credentials provider:
//
//	credentials:
//	  aws_iam:
//	    region: us-east-1
//	    role_arn: arn:aws:iam::123456789012:role/db-access  # optional
//
// Endpoint and DBUser are mint inputs the provider needs but that a consumer
// already knows (its own endpoint and configured username). A receiver populates
// them into this sub-config before resolving, so operators do not repeat them.
type Config struct {
	// Region is the AWS region of the database. Required.
	Region string `mapstructure:"region"`

	// Endpoint is the database endpoint (host:port) the token is minted for.
	// Sourced by the consuming receiver.
	Endpoint string `mapstructure:"endpoint"`

	// DBUser is the database user the token authenticates. Sourced by the
	// consuming receiver from its configured username.
	DBUser string `mapstructure:"db_user"`

	// RoleARN, when set, is assumed before minting the token (cross-account access).
	RoleARN string `mapstructure:"role_arn,omitempty"`

	// prevent unkeyed literal initialization
	_ struct{}
}

var (
	errNoRegion   = errors.New("aws_iam: region is required")
	errNoEndpoint = errors.New("aws_iam: endpoint is required (the consuming component must supply it)")
	errNoDBUser   = errors.New("aws_iam: db_user is required (the consuming component must supply it)")
)

// Validate checks the required mint inputs are present.
func (c *Config) Validate() error {
	if c.Region == "" {
		return errNoRegion
	}
	if c.Endpoint == "" {
		return errNoEndpoint
	}
	if c.DBUser == "" {
		return errNoDBUser
	}
	return nil
}
