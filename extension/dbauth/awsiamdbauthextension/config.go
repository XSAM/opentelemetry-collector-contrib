// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth/awsiamdbauthextension"

import "errors"

// Config is the aws_iam provider extension's config. It carries only the
// provider-wide inputs an operator sets once on the extension:
//
//	extensions:
//	  aws_iam:
//	    region: us-east-1
//	    role_arn: arn:aws:iam::123456789012:role/db-access  # optional
//
// The per-connection mint inputs — the database endpoint and user — are not set
// here; they travel with each GetCredential call as a dbauth.Request, sourced
// from the consuming component's own endpoint and configured username, so an
// operator never repeats them.
type Config struct {
	// Region is the AWS region of the database. Required.
	Region string `mapstructure:"region"`

	// RoleARN, when set, is assumed before minting the token (cross-account access).
	RoleARN string `mapstructure:"role_arn,omitempty"`

	// prevent unkeyed literal initialization
	_ struct{}
}

var errNoRegion = errors.New("aws_iam: region is required")

// Validate checks the required provider-wide inputs are present.
func (c *Config) Validate() error {
	if c.Region == "" {
		return errNoRegion
	}
	return nil
}
