# Connection Credentials Configuration

> **Status: in development.** This package and its interfaces are experimental
> and may change in breaking ways before stabilizing.

This package provides the configuration and interfaces for supplying a
credential to a **connection-oriented** component at the moment it opens a
connection — for example, a database receiver that needs a username and password
(or a short-lived token) to dial its database.

It is the connection-time counterpart to core's
[`configauth`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/config/configauth).
`configauth` handles **transport-level** authentication for outgoing HTTP/gRPC
requests (a `RoundTripper` or `PerRPCCredentials` per request) and carries no
notion of expiry. A database driver needs something different: a credential at
connection-open time that may expire (an AWS RDS IAM token lives ~15 minutes) or
change out of band (a rotated `.pgpass` file). That shape does not fit the
transport interfaces, so this is a distinct config package, not an extension of
`configauth`.

> **Location note.** This package currently lives in contrib
> (`pkg/config/configcredentials`) rather than core (`config/configcredentials`)
> deliberately: it lets the framework and its first provider/receiver ship and be
> evaluated entirely within contrib, without waiting on a core release. If the
> SIG accepts the design, the natural home is core, alongside `configauth` — the
> package is written to move there unchanged (only its import path differs).

## How a provider is declared and selected

A credential provider is a Collector **extension** that also implements
`ProviderFactory`. It is declared once (and listed in `service.extensions`), then
each component selects it by an inline provider-type key in its `credentials`
block — the key matches the extension's component type:

```yaml
extensions:
  aws_iam:                       # declared once, config-less

receivers:
  postgresql/this:
    endpoint: this-db:5432
    username: monitor
    credentials:
      aws_iam:                   # inline, receiver-owned config
        region: us-east-1
        endpoint: this-db:5432
        db_user: monitor
  postgresql/another:
    endpoint: another-db:5432
    username: reader
    credentials:
      aws_iam:
        region: us-east-2
        endpoint: another-db:5432
        db_user: reader

service:
  extensions: [aws_iam]
```

The extension holds **no config and no state** — its `Start`/`Shutdown` are
no-ops. It exists only so any component can discover the provider type via the
host extension map. The per-connection config lives in the consuming component's
`credentials` block; the component unmarshals it and calls the factory's
`CreateProvider`, which returns a `Provider` bound to that component's config. The
call is stateless, so one declared extension serves many components with different
configs.

This means:

- A provider type is **registered once** (one extension in the collector build);
  any receiver can use it with no per-receiver provider list to maintain, and new
  providers require no receiver code changes.
- Databases that do **not** share credentials (the common case) each keep their own
  inline config next to their receiver — one extension declaration covers all of
  them, with no per-database extension instance.
- Resolution mirrors `config/configauth`: the component finds the provider in
  `host.GetExtensions()` at `Start()`, not via an `init()` registry.

## The credential

Every provider returns the same fixed value, regardless of provider type:

```go
type Credential struct {
    Username *string    // nil: use the consumer's configured username
    Secret   string     // opaque: a password or a minted token
    NotAfter *time.Time // nil: no expiry applies; advisory only
}
```

The struct carries credential *material* and nothing about *how* to apply it —
the consuming component decides where the secret goes (for a SQL driver, usually
the password slot of a connection string). It has no auth-mode discriminator and
no mechanism field; the pointer fields are load-bearing:

- `Username == nil` means the provider supplies no username and the consumer
  should fall back to its own configured username. A non-nil pointer (including a
  pointer to the empty string) means the provider generated the username and the
  consumer must use it. Dynamic providers such as Vault mint both a username and a
  secret per lease, which is why this is a pointer rather than a plain string.
- `NotAfter == nil` means no expiry applies (a static password). When set, it is
  an advisory hint for observability — the provider owns refresh-before-expiry, so
  consumers need not act on it.

## Genericity

The same `Credential` and the same `Provider` interface cover every connection
credential shape without an interface change. How each maps onto the struct:

| Provider               | `Username`        | `Secret`               | `NotAfter`        |
| ---------------------- | ----------------- | ---------------------- | ----------------- |
| Static (inline / file) | from config/file  | the password           | `nil`             |
| AWS IAM (RDS/Aurora)   | `nil`             | minted RDS auth token  | now + ~15m        |
| Azure Managed Identity | `nil`             | minted access token    | token expiry      |
| GCP Cloud SQL IAM      | `nil`             | minted access token    | token expiry      |
| Vault dynamic creds    | minted (non-nil)  | minted password        | lease expiry      |

Auth types that need no username and no secret — Windows integrated
authentication, Azure EntraID with a managed identity that the driver resolves
itself — are **not** modeled in the credential. They are a receiver-side config
choice under which a credential provider is simply not invoked; the receiver
configures its driver for integrated auth directly.

## Implementing a provider

A provider is a Collector extension whose component implements `ProviderFactory`
in addition to `extension.Extension`. The extension is config-less; the factory
builds a `Provider` from the consumer's inline config.

```go
type Provider interface {
    GetCredential(ctx context.Context) (*Credential, error)
    Watch(ctx context.Context, onChange func(*Credential)) (stop func(), err error)
}
```

`GetCredential` returns the credential valid at the time of the call; the
provider owns any caching and refresh, so a consumer may call it on every
connection-open and trust the result is current. `Watch` lets a provider notify
the consumer when its credential changes out of band (a rotated file). Providers
whose credential never changes out of band — anything that mints on demand, like
AWS IAM — embed `NopWatcher` to satisfy `Watch` with a no-op, so consumers call
`Watch` unconditionally without a capability type assertion.

Any connection inputs a provider needs (an endpoint, a database user) come from
its own factory sub-config, not from the framework — the interface deliberately
carries no connection-shaped parameters.

### Conformance expectations

Implementations are expected to:

- Return a valid credential, or an error, honoring context cancellation in
  `GetCredential`.
- Be safe for concurrent use. A connection pool opens many connections
  concurrently, so `GetCredential` may be called from multiple goroutines;
  providers that mint and cache should de-duplicate concurrent refreshes rather
  than minting per call.
- Refresh before `NotAfter` where applicable, so a pulled credential is never
  already expired by the time the consumer dials.
- Never log the secret. `Credential.Secret` is opaque material; keep it out of
  logs, traces, and error messages.

These are expectations, not yet a machine-checked contract — an exported
conformance test kit is intentionally deferred. Until it ships, the expectations
above are the contract a provider author should hold themselves to.

Generic providers useful to many users may be accepted into the contrib
distribution; open an issue with a proposal. Otherwise, a custom provider can be
compiled into a custom Collector built with the
[OpenTelemetry Collector Builder](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder).
