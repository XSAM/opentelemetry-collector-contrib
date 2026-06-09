// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package awsiamcredentialsextension provides AWS RDS IAM database authentication
// for the config/configcredentials framework. It is a config-less Collector
// extension that also implements configcredentials.ProviderFactory: it mints
// short-lived RDS IAM auth tokens (cached per target until shortly before expiry)
// and supplies them as the connection secret. Receivers discover it via the host
// extension map and build a Provider from their own inline credentials config.
package awsiamcredentialsextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/awsiamcredentialsextension"

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

// target identifies what a token is minted for. Tokens are cached per target, so
// two connections that differ only by RoleARN do not share a token.
type target struct {
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
type tokenBuilder func(ctx context.Context, t target) (string, error)

// minter mints and caches RDS IAM auth tokens. It is safe for concurrent use.
type minter struct {
	build tokenBuilder
	now   func() time.Time

	mu    sync.Mutex
	cache map[target]cachedToken
}

type cachedToken struct {
	token    string
	notAfter time.Time
}

// newMinter returns a minter that mints real RDS IAM tokens via the AWS SDK,
// using the default credential chain (ECS task role, EC2 instance profile, IRSA).
func newMinter() *minter {
	return &minter{
		build: buildRDSToken,
		now:   time.Now,
		cache: make(map[target]cachedToken),
	}
}

// Token returns a currently-valid auth token for the target, minting a new one
// when there is no cached token or the cached token is within the refresh margin
// of expiry. It returns the token and the time after which it expires.
func (m *minter) Token(ctx context.Context, t target) (token string, notAfter time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.cache[t]; ok && m.now().Before(c.notAfter.Add(-refreshMargin)) {
		return c.token, c.notAfter, nil
	}

	tok, err := m.build(ctx, t)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("aws_iam: mint RDS token for %q: %w", t.Endpoint, err)
	}
	exp := m.now().Add(rdsTokenLifetime)
	m.cache[t] = cachedToken{token: tok, notAfter: exp}
	return tok, exp, nil
}

// buildRDSToken is the production tokenBuilder: it resolves AWS credentials from
// the default chain (optionally assuming RoleARN) and calls the RDS auth helper.
func buildRDSToken(ctx context.Context, t target) (string, error) {
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
