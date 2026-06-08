// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package iamauth // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configcredentials"
	"go.opentelemetry.io/collector/extension"
)

// typeStr is the extension's component type and the inline credentials provider-type key a
// receiver uses: credentials: { aws_iam: {...} }.
const typeStr = "aws_iam"

var componentType = component.MustNewType(typeStr)

// NewFactory returns the aws_iam credentials provider as a Collector extension
// factory. The extension is declared once (and listed in service.extensions) so
// any receiver can discover it via the host extension map; it holds no config and
// no per-connection state. Each receiver supplies its own provider config inline
// and the extension builds an independent Provider per receiver.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		componentType,
		func() component.Config { return &extensionConfig{} },
		createExtension,
		component.StabilityLevelDevelopment,
	)
}

// extensionConfig is the extension's own (empty) config. The per-connection
// credential config lives in the consuming receiver's credentials block, not
// here, so this carries no fields.
type extensionConfig struct {
	_ struct{}
}

func createExtension(context.Context, extension.Settings, component.Config) (extension.Extension, error) {
	return &iamExtension{}, nil
}

// iamExtension is a config-less, no-op extension that also implements
// configcredentials.ProviderFactory: it exists only so receivers can discover the
// aws_iam provider type via the host extension map, then build a Provider from
// their own inline config.
type iamExtension struct{}

var (
	_ extension.Extension               = (*iamExtension)(nil)
	_ configcredentials.ProviderFactory = (*iamExtension)(nil)
)

func (*iamExtension) Start(context.Context, component.Host) error { return nil }
func (*iamExtension) Shutdown(context.Context) error              { return nil }

// CreateDefaultConfig returns the zero per-connection provider config into which a
// receiver's inline credentials.aws_iam block is unmarshaled.
func (*iamExtension) CreateDefaultConfig() component.Config { return &Config{} }

// CreateProvider builds a Provider bound to one receiver's config. It is stateless
// with respect to the extension, so the single declared extension can serve many
// receivers with different configs concurrently.
func (*iamExtension) CreateProvider(_ configcredentials.ProviderSettings, cfg component.Config) (configcredentials.Provider, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("aws_iam: unexpected config type %T", cfg)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &provider{
		minter: NewMinter(),
		target: Target{
			Endpoint: c.Endpoint,
			Region:   c.Region,
			DBUser:   c.DBUser,
			RoleARN:  c.RoleARN,
		},
	}, nil
}
