// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/config/configcredentials"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"

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
	ErrPasswordAndCredentials = "invalid config: set either 'password' or 'credentials', not both"
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
	// Credentials optionally sources the connection credential from a credentials
	// provider extension (e.g. AWS IAM) instead of a static password. When set, the
	// provider supplies the password at connection-open time. Mutually exclusive
	// with the top-level password field.
	Credentials                   configcredentials.Config       `mapstructure:"credentials,omitempty"`
	Databases                     []string                       `mapstructure:"databases"`
	ExcludeDatabases              []string                       `mapstructure:"exclude_databases"`
	confignet.AddrConfig          `mapstructure:",squash"`       // provides Endpoint and Transport
	configtls.ClientConfig        `mapstructure:"tls,omitempty"` // provides SSL details
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

	// Credential source precedence (R12): a static password and a credentials
	// block are mutually exclusive. A username alongside a credentials block is
	// expected — the provider may use it as a mint input. When a credentials block
	// is configured, the password is supplied by the provider, so the top-level
	// password is not required.
	credsConfigured := !cfg.Credentials.IsEmpty()
	switch {
	case credsConfigured && cfg.Password != "":
		err = multierr.Append(err, errors.New(ErrPasswordAndCredentials))
	case !credsConfigured && cfg.Password == "":
		err = multierr.Append(err, errors.New(ErrNoPassword))
	}
	if credsConfigured {
		if credsErr := cfg.Credentials.Validate(); credsErr != nil {
			err = multierr.Append(err, credsErr)
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

// resolveCredentialProvider builds the credential provider from the credentials
// block by finding the matching credentials-provider extension in the host
// extension map, or returns (nil, nil) when no credentials block is configured
// (the receiver then uses its static password). The receiver imports no provider
// packages and supplies no factory list — the provider type is discovered from the
// declared extensions. Provider-specific inputs (such as the AWS IAM provider's
// endpoint and db_user) come from the operator's inline provider config, keeping
// the receiver agnostic to any provider's config schema.
func (cfg *Config) resolveCredentialProvider(extensions map[component.ID]component.Component) (configcredentials.Provider, error) {
	if cfg.Credentials.IsEmpty() {
		return nil, nil
	}
	return cfg.Credentials.Resolve(configcredentials.ProviderSettings{}, extensions)
}
