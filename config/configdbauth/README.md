# Database Authentication Configuration

> **Status: in development.** This package and its interfaces are experimental
> and may change in breaking ways before stabilizing.

This package provides the configuration for wiring a **connection-oriented**
component to a credential provider that supplies a credential at the moment the
component opens a connection — for example, a database receiver that needs a
username and password (or a short-lived token) to dial its database.

It is the configuration half of the `db_auth` framework. The provider
**interface** it resolves (`Provider`, `Credential`, `Request`) lives in a
separate, dependency-light module,
[`extension/dbauth`](../../extension/dbauth), so a provider extension can
implement the interface without taking on this package's confmap dependency —
the same split core uses between `extensionauth` (interface) and `configauth`
(config).

It is the connection-time counterpart to core's
[`configauth`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/config/configauth).
`configauth` handles **transport-level** authentication for outgoing HTTP/gRPC
requests (a `RoundTripper` or `PerRPCCredentials` per request) and carries no
notion of expiry. A database driver needs something different: a credential at
connection-open time that may expire (an AWS RDS IAM token lives ~15 minutes).
That shape does not fit the transport interfaces, so this is a distinct config
package, not an extension of `configauth`.

> **Location note.** These packages currently live in contrib
> (`config/configdbauth` and `extension/dbauth`) rather than core
> deliberately: it lets the framework and its first provider/receiver ship and be
> evaluated entirely within contrib, without waiting on a core release. If the
> SIG accepts the design, the natural home is core, alongside `configauth` — the
> packages are written to move there unchanged (only their import paths differ).

## How a provider is declared and selected

A credential provider is a Collector **extension** that also implements
`dbauth.Provider`. It is declared once (and listed in `service.extensions`) with
its provider-wide configuration, then each component references it **by component
ID** inside its `db_auth` block — the value of the block is the provider's
component ID:

```yaml
extensions:
  aws_iam:                       # declared once, with provider-wide config
    region: us-east-2
  aws_iam/west:                  # a second instance for a different region
    region: us-west-2

receivers:
  postgresql/this:
    endpoint: this-db:5432
    username: monitor
    db_auth: aws_iam             # reference the extension by ID
  postgresql/another:
    endpoint: another-db:5432
    username: reader
    db_auth: aws_iam/west        # reference a differently-configured instance

service:
  extensions: [aws_iam, aws_iam/west]
```

The extension holds all provider-wide configuration (here, the AWS region). To
vary that configuration across components, declare multiple extension instances
(`aws_iam`, `aws_iam/west`) and point each component at the one it needs. There
is no inline override in the `db_auth` block — the value is only a reference.

The **per-connection** inputs a provider needs — the endpoint to connect to, the
database user — are *not* configured on the extension or repeated in the
`db_auth` block. The consuming component already knows them (its own
`endpoint` and `username`) and passes them to the provider with each
`GetCredential` call as a `dbauth.Request`. So one declared extension serves many
components that differ only by endpoint/user, with no per-database extension
instance and nothing repeated.

This means:

- A provider is **declared once per configuration** (one extension instance in
  the collector build); any receiver can reference it by ID, with no per-receiver
  provider list to maintain, and new providers require no receiver code changes.
- Databases that share provider config reference one instance; a database that
  needs a different provider-wide value references a separate declared instance.
- Resolution mirrors `config/configauth`: the component finds the provider in
  `host.GetExtensions()` at `Start()`, not via an `init()` registry.

## The credential and the request

The provider interface, `Credential`, and `Request` are defined in
[`extension/dbauth`](../../../extension/dbauth):

```go
type Provider interface {
    GetCredential(ctx context.Context, req Request) (*Credential, error)
}

type Request struct {
    Endpoint string // host:port the credential is for
    Username string // the consumer's configured username
}

type Credential struct {
    Username *string    // nil: use the consumer's configured username
    Secret   string     // opaque: a password or a minted token
    NotAfter *time.Time // nil: no expiry applies; advisory only
}
```

`Request` carries the per-connection inputs the consumer supplies on every call;
a provider uses the fields it needs (AWS IAM mints a token scoped to `Endpoint`
for `Username`) and ignores the rest. Provider-wide configuration (such as the
AWS region) lives on the extension's own config, not in the request.

The `Credential` carries credential *material* and nothing about *how* to apply
it — the consuming component decides where the secret goes (for a SQL driver,
usually the password slot of a connection string). The pointer fields are
load-bearing:

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

A provider is a Collector extension that implements `dbauth.Provider` in addition
to `extension.Extension`. The extension carries the provider-wide config; the
per-connection inputs arrive with each `GetCredential` call.

`GetCredential` returns the credential valid at the time of the call; the
provider owns any caching and refresh, so a consumer may call it on every
connection-open and trust the result is current.

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
