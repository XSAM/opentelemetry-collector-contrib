// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awsiamcredentialsextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/awsiamcredentialsextension"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configcredentials"
	"go.opentelemetry.io/collector/extension"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/awsiamcredentialsextension/internal/metadata"
)

// NewFactory returns the aws_iam credentials provider as a Collector extension
// factory. The extension is declared once (and listed in service.extensions) so
// any receiver can discover it via the host extension map; it holds no config and
// no per-connection state. Each receiver supplies its own provider config inline
// and the extension builds an independent Provider per receiver.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &Config{} },
		createExtension,
		metadata.ExtensionStability,
	)
}

// Config is the extension's own (empty) config. The per-connection credential
// config lives in the consuming receiver's credentials block, not here, so this
// carries no fields.
type Config struct {
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
func (*iamExtension) CreateDefaultConfig() component.Config { return &providerConfig{} }

// CreateProvider builds a Provider bound to one receiver's config. It is stateless
// with respect to the extension, so the single declared extension can serve many
// receivers with different configs concurrently.
func (*iamExtension) CreateProvider(_ configcredentials.ProviderSettings, cfg component.Config) (configcredentials.Provider, error) {
	c, ok := cfg.(*providerConfig)
	if !ok {
		return nil, fmt.Errorf("aws_iam: unexpected config type %T", cfg)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &provider{
		minter: newMinter(),
		target: target{
			Endpoint: c.Endpoint,
			Region:   c.Region,
			DBUser:   c.DBUser,
			RoleARN:  c.RoleARN,
		},
	}, nil
}
