// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package iamauth mints short-lived AWS RDS IAM database authentication tokens
// and caches them per target until shortly before they expire. It is a reusable
// helper for credential providers that authenticate to RDS/Aurora with IAM
// (PostgreSQL today, MySQL later) — both use the same RDS token-minting flow.
package iamauth // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// rdsTokenLifetime is the lifetime AWS gives an RDS IAM auth token.
const rdsTokenLifetime = 15 * time.Minute

// refreshMargin is how long before expiry a cached token is considered stale and
// re-minted. A token within this window of expiry is refreshed proactively so a
// connection never opens with a token RDS is about to reject (clock skew,
// in-flight dial time). ~30% of the 15-minute lifetime.
const refreshMargin = 5 * time.Minute

// Target identifies what a token is minted for. Tokens are cached per Target, so
// two connections that differ only by RoleARN do not share a token.
type Target struct {
	// Endpoint is the RDS endpoint in host:port form.
	Endpoint string
	// Region is the AWS region of the database.
	Region string
	// DBUser is the database user the token authenticates.
	DBUser string
	// RoleARN, when set, is assumed before minting (cross-account access).
	RoleARN string
}

// tokenBuilder mints a token for a target. Injectable so tests run without AWS.
type tokenBuilder func(ctx context.Context, t Target) (string, error)

// Minter mints and caches RDS IAM auth tokens. It is safe for concurrent use.
type Minter struct {
	build tokenBuilder
	now   func() time.Time

	mu    sync.Mutex
	cache map[Target]cachedToken
}

type cachedToken struct {
	token    string
	notAfter time.Time
}

// NewMinter returns a Minter that mints real RDS IAM tokens via the AWS SDK,
// using the default credential chain (ECS task role, EC2 instance profile, IRSA).
func NewMinter() *Minter {
	return &Minter{
		build: buildRDSToken,
		now:   time.Now,
		cache: make(map[Target]cachedToken),
	}
}

// Token returns a currently-valid auth token for the target, minting a new one
// when there is no cached token or the cached token is within the refresh margin
// of expiry. It returns the token and the time after which it expires.
func (m *Minter) Token(ctx context.Context, t Target) (token string, notAfter time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.cache[t]; ok && m.now().Before(c.notAfter.Add(-refreshMargin)) {
		return c.token, c.notAfter, nil
	}

	tok, err := m.build(ctx, t)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("iamauth: mint RDS token for %q: %w", t.Endpoint, err)
	}
	exp := m.now().Add(rdsTokenLifetime)
	m.cache[t] = cachedToken{token: tok, notAfter: exp}
	return tok, exp, nil
}

// buildRDSToken is the production tokenBuilder: it resolves AWS credentials from
// the default chain (optionally assuming RoleARN) and calls the RDS auth helper.
func buildRDSToken(ctx context.Context, t Target) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(t.Region))
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}

	creds := cfg.Credentials
	if t.RoleARN != "" {
		creds = aws.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), t.RoleARN),
		)
	}

	return auth.BuildAuthToken(ctx, t.Endpoint, t.Region, t.DBUser, creds)
}
