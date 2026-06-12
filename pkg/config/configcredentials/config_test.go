// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcredentials

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
)

// erroringFactory is a credentials provider extension whose CreateProvider always
// fails.
type erroringFactory struct {
	err error
}

func (*erroringFactory) Start(context.Context, component.Host) error { return nil }
func (*erroringFactory) Shutdown(context.Context) error              { return nil }
func (*erroringFactory) CreateDefaultConfig() component.Config       { return &fakeFactoryConfig{} }

func (f *erroringFactory) CreateProvider(ProviderSettings, component.Config) (Provider, error) {
	return nil, f.err
}

// notAProvider is an extension that does not implement ProviderFactory.
type notAProvider struct{}

func (notAProvider) Start(context.Context, component.Host) error { return nil }
func (notAProvider) Shutdown(context.Context) error              { return nil }

// extMap builds a host extension map from one extension under the given type/name.
func extMap(typ string, ext component.Component) map[component.ID]component.Component {
	return map[component.ID]component.Component{component.MustNewID(typ): ext}
}

func TestConfig_IsEmpty(t *testing.T) {
	assert.True(t, Config{}.IsEmpty())
	assert.False(t, Config{ProviderConfigs: map[string]any{"aws_iam": map[string]any{}}}.IsEmpty())
}

func TestConfig_Validate(t *testing.T) {
	require.NoError(t, Config{}.Validate())
	require.NoError(t, Config{ProviderConfigs: map[string]any{"aws_iam": nil}}.Validate())

	err := Config{ProviderConfigs: map[string]any{"aws_iam": nil, "file": nil}}.Validate()
	require.ErrorIs(t, err, errMultipleProviders)
}

func TestConfig_Resolve_MatchesExtensionByType(t *testing.T) {
	f := &fakeFactory{}
	auth := Config{ProviderConfigs: map[string]any{
		"aws_iam": map[string]any{"region": "ap-northeast-2"},
	}}

	p, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", f))
	require.NoError(t, err)
	require.NotNil(t, p)

	// Inline sub-config is unmarshaled into the matched extension's config.
	require.NotNil(t, f.gotCfg)
	assert.Equal(t, "ap-northeast-2", f.gotCfg.Region)
}

func TestConfig_Resolve_OptOutWhenEmpty(t *testing.T) {
	p, err := Config{}.Resolve(ProviderSettings{}, extMap("aws_iam", &fakeFactory{}))
	require.NoError(t, err)
	assert.Nil(t, p, "no auth type configured resolves to no provider, no error")
}

func TestConfig_Resolve_NoMatchingExtension(t *testing.T) {
	auth := Config{ProviderConfigs: map[string]any{"vault": map[string]any{}}}
	_, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", &fakeFactory{}))
	require.ErrorIs(t, err, errNoExtension)
}

func TestConfig_Resolve_ExtensionNotAProvider(t *testing.T) {
	auth := Config{ProviderConfigs: map[string]any{"aws_iam": map[string]any{}}}
	_, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", notAProvider{}))
	require.ErrorIs(t, err, errNotProvider)
}

func TestConfig_Resolve_MultipleTypes(t *testing.T) {
	auth := Config{ProviderConfigs: map[string]any{
		"aws_iam": map[string]any{},
		"vault":   map[string]any{},
	}}
	_, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", &fakeFactory{}))
	require.ErrorIs(t, err, errMultipleProviders)
}

func TestConfig_Resolve_NoBody(t *testing.T) {
	// "aws_iam:" with no sub-config still resolves; the extension gets its default config.
	f := &fakeFactory{}
	auth := Config{ProviderConfigs: map[string]any{"aws_iam": nil}}
	p, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", f))
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, f.gotCfg)
	assert.Equal(t, "", f.gotCfg.Region)
}

func TestConfig_Resolve_CreateProviderError(t *testing.T) {
	sentinel := errors.New("mint failed")
	auth := Config{ProviderConfigs: map[string]any{"aws_iam": map[string]any{}}}
	_, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", &erroringFactory{err: sentinel}))
	require.ErrorIs(t, err, sentinel)
}

func TestConfig_Resolve_UnmarshalError(t *testing.T) {
	// region is a string field; a nested-map value fails to unmarshal.
	auth := Config{ProviderConfigs: map[string]any{
		"aws_iam": map[string]any{"region": map[string]any{"nested": "notastring"}},
	}}
	_, err := auth.Resolve(ProviderSettings{}, extMap("aws_iam", &fakeFactory{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal config")
}

func TestConfig_Resolve_InvalidProviderType(t *testing.T) {
	// A malformed provider-type key cannot be a component type, so resolve errors
	// (rather than panicking).
	auth := Config{ProviderConfigs: map[string]any{"aws-iam": map[string]any{}}}
	_, err := auth.Resolve(ProviderSettings{}, map[component.ID]component.Component{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid provider type")
}
