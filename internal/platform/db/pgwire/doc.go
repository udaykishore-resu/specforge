// Package pgwire implements a minimal PostgreSQL wire-protocol driver for
// database/sql.
//
// # Why this exists
//
// SpecForge's repository layer is written against database/sql, so the concrete
// driver is a deployment choice rather than an architectural one. This package
// provides a dependency-free driver covering exactly the protocol surface the
// platform uses: startup and authentication (trust, cleartext, MD5,
// SCRAM-SHA-256), TLS negotiation, simple queries for migrations, the extended
// query protocol for parameterised statements, transactions with explicit
// isolation levels, and query cancellation.
//
// It exists so the platform builds and runs with no third-party modules. It is
// deliberately small and auditable, and it is not a general-purpose driver: it
// does not implement COPY, LISTEN/NOTIFY, binary result formats, or the full
// type catalogue.
//
// # Production guidance
//
// For production deployments, register github.com/jackc/pgx/v5/stdlib instead
// and set `db.driver: pgx` in the configuration. Nothing above
// internal/platform/db changes, because every repository targets database/sql.
// See internal/platform/db/driver_pgx.go (build tag `pgx`).
//
// # Concurrency
//
// A Conn is not safe for concurrent use; database/sql guarantees serialised
// access per connection. Cancellation runs on a separate connection, as the
// protocol requires.
package pgwire
