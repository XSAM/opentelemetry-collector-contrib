// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"

import (
	"errors"
	"fmt"
	"net"
	"time"

	"go.opentelemetry.io/collector/config/configcredentials"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/iamauth"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver/internal/metadata"
)

// Errors for missing required config parameters.
const (
	ErrNoUsername          = "invalid config: missing username"
	ErrNoPassword          = "invalid config: missing password" // #nosec G101 - not hardcoded credentials
	ErrNotSupported        = "invalid config: field '%s' not supported"
	ErrTransportsSupported = "invalid config: 'transport' must be 'tcp' or 'unix'"
	ErrHostPort            = "invalid config: 'endpoint' must be in the form <host>:<port> no matter what 'transport' is configured"
	// #nosec G101 - not hardcoded credentials
	ErrPasswordAndAuth = "invalid config: set either 'password' or 'authentication', not both"
)

type TopQueryCollection struct {
	MaxRowsPerQuery        int64         `mapstructure:"max_rows_per_query"`
	TopNQuery              int64         `mapstructure:"top_n_query"`
	MaxExplainEachInterval int64         `mapstructure:"max_explain_each_interval"`
	QueryPlanCacheSize     int           `mapstructure:"query_plan_cache_size"`
	QueryPlanCacheTTL      time.Duration `mapstructure:"query_plan_cache_ttl"`
	CollectionInterval     time.Duration `mapstructure:"collection_interval"`
	// prevent unkeyed literal initialization
	_ struct{}
}

type QuerySampleCollection struct {
	MaxRowsPerQuery int64 `mapstructure:"max_rows_per_query"`
	// prevent unkeyed literal initialization
	_ struct{}
}

type Config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`
	Username                       string              `mapstructure:"username"`
	Password                       configopaque.String `mapstructure:"password"`
	// Authentication optionally sources the connection credential from a
	// credentials provider (e.g. AWS IAM) instead of a static password. When set,
	// the provider supplies the password at connection-open time. Mutually
	// exclusive with the top-level password field.
	Authentication                configcredentials.Authentication `mapstructure:"authentication,omitempty"`
	Databases                     []string                         `mapstructure:"databases"`
	ExcludeDatabases              []string                         `mapstructure:"exclude_databases"`
	confignet.AddrConfig          `mapstructure:",squash"`         // provides Endpoint and Transport
	configtls.ClientConfig        `mapstructure:"tls,omitempty"`   // provides SSL details
	ConnectionPool                `mapstructure:"connection_pool,omitempty"`
	metadata.MetricsBuilderConfig `mapstructure:",squash"`
	metadata.LogsBuilderConfig    `mapstructure:",squash"`
	QuerySampleCollection         `mapstructure:"query_sample_collection,omitempty"`
	TopQueryCollection            `mapstructure:"top_query_collection,omitempty"`
}

type ConnectionPool struct {
	MaxIdleTime *time.Duration `mapstructure:"max_idle_time,omitempty"`
	MaxLifetime *time.Duration `mapstructure:"max_lifetime,omitempty"`
	MaxIdle     *int           `mapstructure:"max_idle,omitempty"`
	MaxOpen     *int           `mapstructure:"max_open,omitempty"`
}

func (cfg *Config) Validate() error {
	var err error
	if cfg.Username == "" {
		err = multierr.Append(err, errors.New(ErrNoUsername))
	}

	// Credential source precedence (R12): a static password and an authentication
	// block are mutually exclusive. A username alongside an authentication block is
	// expected — the provider may use it as a mint input. When an authentication
	// block is configured, the password is supplied by the provider, so the
	// top-level password is not required.
	authConfigured := !cfg.Authentication.IsEmpty()
	switch {
	case authConfigured && cfg.Password != "":
		err = multierr.Append(err, errors.New(ErrPasswordAndAuth))
	case !authConfigured && cfg.Password == "":
		err = multierr.Append(err, errors.New(ErrNoPassword))
	}
	if authConfigured {
		if authErr := cfg.Authentication.Validate(); authErr != nil {
			err = multierr.Append(err, authErr)
		}
	}

	// The lib/pq module does not support overriding ServerName or specifying supported TLS versions
	if cfg.ServerName != "" {
		err = multierr.Append(err, fmt.Errorf(ErrNotSupported, "ServerName"))
	}
	if cfg.MaxVersion != "" {
		err = multierr.Append(err, fmt.Errorf(ErrNotSupported, "MaxVersion"))
	}
	if cfg.MinVersion != "" {
		err = multierr.Append(err, fmt.Errorf(ErrNotSupported, "MinVersion"))
	}

	switch cfg.Transport {
	case confignet.TransportTypeTCP, confignet.TransportTypeUnix:
		_, _, endpointErr := net.SplitHostPort(cfg.Endpoint)
		if endpointErr != nil {
			err = multierr.Append(err, errors.New(ErrHostPort))
		}
	default:
		err = multierr.Append(err, errors.New(ErrTransportsSupported))
	}

	return err
}

// credentialProviderFactories is the set of credential providers this receiver
// supports under its authentication block. Supplied as an explicit slice — there
// is no global registration.
func credentialProviderFactories() []configcredentials.ProviderFactory {
	return []configcredentials.ProviderFactory{iamauth.NewFactory()}
}

// resolveCredentialProvider builds the credential provider from the authentication
// block, or returns (nil, nil) when no authentication block is configured (the
// receiver then uses its static password). Provider-specific inputs (such as the
// AWS IAM provider's endpoint and db_user) come from the operator's inline
// provider config — the receiver does not inject them, keeping it agnostic to any
// provider's config schema.
func (cfg *Config) resolveCredentialProvider() (configcredentials.Provider, error) {
	if cfg.Authentication.IsEmpty() {
		return nil, nil
	}
	return cfg.Authentication.Resolve(configcredentials.ProviderSettings{}, credentialProviderFactories())
}
