// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcredentials // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/config/configcredentials"

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
)

var (
	errMultipleProviders = errors.New("credentials: exactly one provider may be configured")
	errNoExtension       = errors.New("credentials: no enabled extension found for provider type")
	errNotProvider       = errors.New("credentials: extension does not implement a credentials provider")
)

// Config is the embeddable credentials config a connection-oriented component
// squashes into its own config under a "credentials" key. Exactly one provider
// type is set, and its value is that provider's sub-config:
//
//	credentials:
//	  aws_iam:
//	    region: ap-northeast-2
//
// The provider-type key (here "aws_iam") selects the credentials-provider
// extension whose component type matches it. Resolve unmarshals the sub-config
// into the extension's provider config and builds the Provider.
type Config struct {
	// ProviderConfigs holds the inline provider config, keyed by provider-type
	// name. The ",remain" tag captures every key in the credentials block; exactly
	// one is expected. It holds raw config, not Provider instances — it is exported
	// only because mapstructure cannot populate unexported fields. Treat it as
	// read-only and prefer the IsEmpty/Validate/Resolve methods.
	ProviderConfigs map[string]any `mapstructure:",remain"`
}

// IsEmpty reports whether no provider is configured. A component treats an empty
// Config as "credentials not in use" and falls back to its existing static
// credential fields — the framework is opt-in.
func (c Config) IsEmpty() bool {
	return len(c.ProviderConfigs) == 0
}

// Validate fails when more than one provider is configured. Zero is allowed
// (opt-out); the unknown-provider case is reported by Resolve, which is the only
// place the host extension map is known.
func (c Config) Validate() error {
	if len(c.ProviderConfigs) > 1 {
		return fmt.Errorf("%w, got %d", errMultipleProviders, len(c.ProviderConfigs))
	}
	return nil
}

// Resolve finds the credentials provider extension whose component type matches
// the configured provider-type key, unmarshals the inline sub-config into the
// extension's provider config, and builds the Provider. The extensions argument is
// the host extension map (component.Host.GetExtensions()), so this is called from
// a consuming component's Start, mirroring configauth.Config.GetServerAuthenticator.
//
// It returns (nil, nil) when no provider is configured (opt-out). It returns an
// error when more than one provider is set, when no enabled extension matches the
// provider-type key, when the matching extension does not implement
// ProviderFactory, or when the inline sub-config fails to unmarshal.
func (c Config) Resolve(set ProviderSettings, extensions map[component.ID]component.Component) (Provider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.IsEmpty() {
		return nil, nil
	}

	providerType, raw := c.single()
	componentType, err := component.NewType(providerType)
	if err != nil {
		return nil, fmt.Errorf("credentials: invalid provider type %q: %w", providerType, err)
	}

	// Find the enabled extension whose component type matches the provider-type
	// key. The model expects a single unnamed instance per provider type.
	var factory ProviderFactory
	for id, ext := range extensions {
		if id.Type() != componentType {
			continue
		}
		f, ok := ext.(ProviderFactory)
		if !ok {
			return nil, fmt.Errorf("%w: %q", errNotProvider, id)
		}
		factory = f
		set.ID = id
		break
	}
	if factory == nil {
		return nil, fmt.Errorf("%w: %q", errNoExtension, providerType)
	}

	cfg := factory.CreateDefaultConfig()
	if raw != nil {
		if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("credentials: failed to unmarshal config for provider %q: %w", providerType, err)
		}
	}

	return factory.CreateProvider(set, cfg)
}

// single returns the sole configured provider type and its sub-config as a string
// map. Callers must ensure exactly one key is set (Validate + non-empty). The
// sub-config is nil when the key has no value (e.g. "aws_iam:" with no body).
func (c Config) single() (string, map[string]any) {
	for k, v := range c.ProviderConfigs {
		sub, _ := v.(map[string]any)
		return k, sub
	}
	return "", nil
}
