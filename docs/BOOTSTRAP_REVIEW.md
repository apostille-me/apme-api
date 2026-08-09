# Production scaffold review

## Product boundary

`apme-api` is the Rust Axum REST and WebSocket API service for **Apostille Me**. It supports secure apostille, legalization, document intake, status tracking, and jurisdiction-aware case workflows.

## Review focus

- Keep REST, WebSocket, CLI, sync, and generated-client contracts versioned and semantically aligned.
- Keep credentials, government documents, identity evidence, vector source payloads, access tokens, and other sensitive records out of logs and fixtures.
- Preserve tenant isolation, idempotency, bounded payloads, structured errors, health/readiness probes, graceful shutdown, and OpenTelemetry-compatible instrumentation.
- Pin cross-repository Git dependencies to immutable commits and update them through reviewed pull requests.
- Treat local in-memory or SQLite fallbacks as development paths; production uses managed PostgreSQL/Supabase with migrations, backups, and row-level authorization where applicable.

## Validation before merge

Run the repository's checked-in CI workflow, formatting and lint gates, unit tests, contract checks, and any available integration tests. The publication bundle also verifies Git integrity, branch ancestry, canonical origins, structured configuration, and secret signatures across the complete fleet.
