// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiam // import "github.com/open-telemetry/opentelemetry-collector-contrib/credentialsprovider/awsiam"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/config/configcredentials"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"
)

// minter is the subset of *iamauth.Minter the provider uses. Defined as an
// interface so tests inject a fake without touching AWS.
type minter interface {
	Token(ctx context.Context, t iamauth.Target) (token string, notAfter time.Time, err error)
}

// provider implements configcredentials.Provider for AWS RDS IAM authentication.
// The credential is minted on demand and never changes out of band, so the
// provider embeds NopWatcher to satisfy Watch with a no-op.
type provider struct {
	configcredentials.NopWatcher
	target iamauth.Target
	minter minter
}

// GetCredential mints (or returns a cached) RDS IAM auth token and returns it as
// the Secret. Username is nil — the consumer uses its own configured username.
func (p *provider) GetCredential(ctx context.Context) (*configcredentials.Credential, error) {
	token, notAfter, err := p.minter.Token(ctx, p.target)
	if err != nil {
		return nil, err
	}
	return &configcredentials.Credential{
		Secret:   token,
		NotAfter: &notAfter,
	}, nil
}
