// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamdbauthextension

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMinter returns a minter with an injected builder and a controllable
// clock, so tests exercise caching/refresh without touching AWS.
func newTestMinter(build tokenBuilder, now func() time.Time) *minter {
	return &minter{build: build, now: now, cache: make(map[target]cachedToken)}
}

func TestMinter_MintsAndReturnsExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newTestMinter(
		func(context.Context, target) (string, error) { return "tok-1", nil },
		func() time.Time { return now },
	)

	tok, notAfter, err := m.Token(context.Background(), target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"})
	require.NoError(t, err)
	assert.Equal(t, "tok-1", tok)
	assert.Equal(t, now.Add(rdsTokenLifetime), notAfter)
}

func TestMinter_CachedTokenReused(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls int
	m := newTestMinter(
		func(context.Context, target) (string, error) { calls++; return fmt.Sprintf("tok-%d", calls), nil },
		func() time.Time { return now },
	)
	tgt := target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"}

	tok1, _, err := m.Token(context.Background(), tgt)
	require.NoError(t, err)
	tok2, _, err := m.Token(context.Background(), tgt)
	require.NoError(t, err)

	assert.Equal(t, tok1, tok2, "an unexpired cached token is reused without re-minting")
	assert.Equal(t, 1, calls)
}

func TestMinter_RefreshesNearExpiry(t *testing.T) {
	cur := time.Unix(1000, 0)
	var calls int
	m := newTestMinter(
		func(context.Context, target) (string, error) { calls++; return fmt.Sprintf("tok-%d", calls), nil },
		func() time.Time { return cur },
	)
	tgt := target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"}

	tok1, _, err := m.Token(context.Background(), tgt)
	require.NoError(t, err)

	// Advance to within the refresh margin of expiry: a new token is minted.
	cur = cur.Add(rdsTokenLifetime - refreshMargin + time.Second)
	tok2, _, err := m.Token(context.Background(), tgt)
	require.NoError(t, err)

	assert.NotEqual(t, tok1, tok2, "a token within the refresh margin is re-minted")
	assert.Equal(t, 2, calls)
}

func TestMinter_DBUserInCacheKey(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls int
	m := newTestMinter(
		func(_ context.Context, tgt target) (string, error) { calls++; return "tok-" + tgt.DBUser, nil },
		func() time.Time { return now },
	)

	base := target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"}
	other := base
	other.DBUser = "reader"

	a, _, err := m.Token(context.Background(), base)
	require.NoError(t, err)
	b, _, err := m.Token(context.Background(), other)
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "targets differing only by DBUser must not share a cached token")
	assert.Equal(t, 2, calls)
}

func TestMinter_ConcurrentCallsDoNotOverMint(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls int64
	m := newTestMinter(
		func(context.Context, target) (string, error) { atomic.AddInt64(&calls, 1); return "tok", nil },
		func() time.Time { return now },
	)
	tgt := target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := m.Token(context.Background(), tgt)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), atomic.LoadInt64(&calls), "concurrent callers for one target mint at most once")
}

func TestMinter_BuildErrorPropagates(t *testing.T) {
	sentinel := errors.New("credential chain failed")
	m := newTestMinter(
		func(context.Context, target) (string, error) { return "", sentinel },
		func() time.Time { return time.Unix(1000, 0) },
	)

	tok, _, err := m.Token(context.Background(), target{Endpoint: "db:5432", Region: "us-east-1", DBUser: "monitor"})
	require.ErrorIs(t, err, sentinel)
	assert.Empty(t, tok, "no token is returned on mint failure")
}
