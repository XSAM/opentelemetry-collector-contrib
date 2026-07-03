// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth/awsiamdbauthextension"

import "errors"

// Config is the aws_iam provider extension's config. It carries the provider-wide
// inputs an operator may set on the extension:
//
//	extensions:
//	  aws_iam:
//	    region: us-east-1                                    # optional default
//	    role_arn: arn:aws:iam::123456789012:role/db-access  # optional
//	    # endpoint / db_user: optional, normally supplied by the receiver instead
//
// Every field is optional here. Region may instead be supplied per-receiver
// through the db_auth override (see the provider's GetCredential), so an extension
// declared with no region is valid as long as every receiver that references it
// supplies one; the region must be resolved from one source or the other before a
// token can be minted. The per-connection mint inputs — the database endpoint and
// user — normally travel with each GetCredential call as a dbauth.Request, sourced
// from the consuming component's own endpoint and configured username, so an
// operator never repeats them. Endpoint and DBUser exist for the cases where the
// operator wants to pin them explicitly (or override the receiver's values via the
// db_auth block); when set they take precedence over the request.
type Config struct {
	// Region is the AWS region of the database. Optional here: it may be set as a
	// provider-wide default, or supplied per-receiver via the db_auth override. It
	// must be resolved (from either source) before a token can be minted; that is
	// enforced at mint time, not at config load, because the override is not known
	// until a receiver calls GetCredential.
	Region string `mapstructure:"region"`

	// Endpoint, when set, is the database endpoint (host:port) the token is minted
	// for. Optional: the consuming receiver normally supplies its own endpoint with
	// each request, leaving this empty. When set here — or in the db_auth override —
	// it takes precedence over the request's endpoint for those calls.
	Endpoint string `mapstructure:"endpoint,omitempty"`

	// DBUser, when set, is the database user the token authenticates. Optional in the
	// same way as Endpoint: the receiver's configured username is used by default,
	// and a value set here — or in the db_auth override — takes precedence over it.
	DBUser string `mapstructure:"db_user,omitempty"`

	// RoleARN, when set, is assumed before minting the token (cross-account access).
	RoleARN string `mapstructure:"role_arn,omitempty"`

	// prevent unkeyed literal initialization
	_ struct{}
}

// errNoRegion is returned at mint time when neither the extension's own config nor
// the receiver's db_auth override supplies a region. It is intentionally not a
// config-load Validate error: the region may legitimately be absent from the
// extension and present only in each receiver's override.
var errNoRegion = errors.New("aws_iam: region must be set on the extension or in the receiver's db_auth override")
