// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"

import (
	"database/sql"
	"errors"
	"sync"

	"github.com/lib/pq"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/config/configcredentials"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver/internal/metadata"
)

type postgreSQLClientFactory interface {
	getClient(database string) (client, error)
	// setCredentialProvider injects the credential provider resolved from the host
	// extension map at Start. Nil means no credentials block (static password).
	setCredentialProvider(configcredentials.Provider)
	close() error
}

// newClientFactory selects the pool or default client factory based on the
// connection-pool feature gate. The credential provider (if any) is resolved from
// the host extension map later, at scraper Start, and injected via
// setCredentialProvider — the host is not available at receiver-create time.
func newClientFactory(cfg *Config) (postgreSQLClientFactory, error) {
	if metadata.ReceiverPostgresqlConnectionPoolFeatureGate.IsEnabled() {
		return newPoolClientFactory(cfg)
	}
	return newDefaultClientFactory(cfg), nil
}

// defaultClientFactory creates one PG connection per call
type defaultClientFactory struct {
	baseConfig postgreSQLConfig
}

func newDefaultClientFactory(cfg *Config) *defaultClientFactory {
	return &defaultClientFactory{
		baseConfig: postgreSQLConfig{
			username: cfg.Username,
			password: string(cfg.Password),
			address:  cfg.AddrConfig,
			tls:      cfg.ClientConfig,
		},
	}
}

func (d *defaultClientFactory) setCredentialProvider(p configcredentials.Provider) {
	d.baseConfig.credentialProvider = p
}

func (d *defaultClientFactory) getClient(database string) (client, error) {
	db, err := getDB(d.baseConfig, database)
	if err != nil {
		return nil, err
	}
	return &postgreSQLClient{client: db, closeFn: db.Close}, nil
}

func (*defaultClientFactory) close() error {
	return nil
}

// poolClientFactory creates one PG connection per database, keeping a pool of connections
type poolClientFactory struct {
	sync.Mutex
	baseConfig postgreSQLConfig
	poolConfig *ConnectionPool
	pool       map[string]*sql.DB
	closed     bool
}

func newPoolClientFactory(cfg *Config) (*poolClientFactory, error) {
	// The connection pool caches a *sql.DB per database for the process lifetime,
	// so a credential resolved once at pool creation would never refresh — an
	// expiring token (e.g. AWS IAM, ~15m) would go stale. Until pooled refresh is
	// implemented, refuse the combination rather than silently serving stale
	// credentials (R11a).
	if !cfg.Credentials.IsEmpty() {
		return nil, errors.New("invalid config: the connection_pool feature gate is not supported with a 'credentials' block, because pooled connections would not refresh an expiring credential")
	}
	poolCfg := cfg.ConnectionPool
	return &poolClientFactory{
		baseConfig: postgreSQLConfig{
			username: cfg.Username,
			password: string(cfg.Password),
			address:  cfg.AddrConfig,
			tls:      cfg.ClientConfig,
		},
		poolConfig: &poolCfg,
		pool:       make(map[string]*sql.DB),
		closed:     false,
	}, nil
}

// setCredentialProvider is a no-op: the pool factory refuses a credentials
// block at construction (see newPoolClientFactory), so it never receives a
// provider.
func (*poolClientFactory) setCredentialProvider(configcredentials.Provider) {}

func (p *poolClientFactory) getClient(database string) (client, error) {
	p.Lock()
	defer p.Unlock()
	db, ok := p.pool[database]
	if !ok {
		var err error
		db, err = getDB(p.baseConfig, database)
		p.setPoolSettings(db)
		if err != nil {
			return nil, err
		}
		p.pool[database] = db
	}
	return &postgreSQLClient{client: db, closeFn: nil}, nil
}

func (p *poolClientFactory) close() error {
	p.Lock()
	defer p.Unlock()

	if p.closed {
		return nil
	}

	if p.pool != nil {
		var err error
		for _, db := range p.pool {
			if closeErr := db.Close(); closeErr != nil {
				err = multierr.Append(err, closeErr)
			}
		}
		if err != nil {
			return err
		}
	}

	p.closed = true
	return nil
}

func (p *poolClientFactory) setPoolSettings(db *sql.DB) {
	if p.poolConfig == nil {
		return
	}
	if p.poolConfig.MaxIdleTime != nil {
		db.SetConnMaxIdleTime(*p.poolConfig.MaxIdleTime)
	}
	if p.poolConfig.MaxLifetime != nil {
		db.SetConnMaxLifetime(*p.poolConfig.MaxLifetime)
	}
	if p.poolConfig.MaxIdle != nil {
		db.SetMaxIdleConns(*p.poolConfig.MaxIdle)
	}
	if p.poolConfig.MaxOpen != nil {
		db.SetMaxOpenConns(*p.poolConfig.MaxOpen)
	}
}

func getDB(cfg postgreSQLConfig, database string) (*sql.DB, error) {
	if database != "" {
		cfg.database = database
	}
	connectionString, err := cfg.ConnectionString()
	if err != nil {
		return nil, err
	}
	conn, err := pq.NewConnector(connectionString)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(conn), nil
}
