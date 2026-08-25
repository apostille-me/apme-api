# apme-api

Axum REST and WebSocket API server for Apostille Me.

**Product:** Apostille Me — Case operations for visa and apostille consulting.

Track sanitized client references, document workflows, destination jurisdictions, appointments, deadlines, and case events for a visa and apostille consulting firm.

## Safety and production boundary

This software is an operational starter and does not provide legal advice. Keep identity documents and sensitive case files out of logs and this bootstrap data model; production use requires encryption, access controls, retention rules, auditability, and jurisdiction-specific professional review.

The runtime now uses the official Shared Auth Rust guard for local ES256/JWKS
verification, protected introspection for immediate revocation, and PostgreSQL-owned
tenant membership and roles. It also uses durable idempotent case mutations,
optimistic versions, encrypted-object references, retention/legal holds, and
tamper-evident event and audit chains. Production use still requires rate limits,
observability, tested backup/object-store/KMS procedures, incident response, dependency
review, and secret management.

## Identity and tenant boundary

Set all authentication and database values at runtime; startup fails closed if any
required value is absent:

```text
DATABASE_URL
SHARED_AUTH_BASE_URL
SHARED_AUTH_ISSUER
SHARED_AUTH_AUDIENCE
SHARED_AUTH_INTROSPECTION_CREDENTIAL
```

`SHARED_AUTH_INTROSPECTION_CREDENTIAL` is an independent service credential and must
not be the end-user token. Every case REST request uses `Authorization: Bearer ...`
and an explicit `x-apme-tenant-id` UUID. The token supplies only the stable Shared
Auth user/session identity; the API reloads membership and role from
`apme_tenant_memberships`. Create and transition requests additionally require an
`Idempotency-Key` header. Request tracing records the method and outcome, not the URI,
headers, tenant/case identifiers, bearer credential, or document reference.

The official Shared Auth Rust client is pinned to commit
`cc57a85b276bee81ad94decc87df2f48d49cab9f`. Protected introspection sends the strict
`IntrospectionRequest` envelope, caps responses at 64 KiB, requires
`apme:cases:read` or `apme:cases:write`, and fails closed on authority errors or exact
issuer, audience, session, lifetime, or scope mismatches. The independent service
credential is attached only by the client. Ores structured logging is pinned to
`ca176fb6768a9750d262a536952268625ffd3a8a`; bearer values, service credentials,
tenant identifiers, document references, URLs, headers, and bodies are not log fields.

The WebSocket handshake uses the same local verification, protected introspection,
and database membership check. Select the tenant explicitly with
`/ws?tenant_id=<uuid>` and optionally select one case with `&case_id=<uuid>`. Published
events carry an internal tenant scope and are filtered before serialization.

## Browser origin policy

The API no longer accepts wildcard browser origins. Configure a comma-separated list of
exact origins with `CORS_ALLOWED_ORIGINS`:

```bash
export CORS_ALLOWED_ORIGINS='https://app.apostille.me,https://admin.apostille.me'
```

Each value must be an `http` or `https` origin without a path, query, or fragment. When
`APP_ENV=production`, `CORS_ALLOWED_ORIGINS` is required and startup fails closed if it
is missing or invalid. Local development defaults to `http://127.0.0.1:3000` and
`http://localhost:3000`; set the variable explicitly when using another development
origin.

The allowlist includes `Authorization`, `Content-Type`, `x-apme-tenant-id`, and
`Idempotency-Key`; wildcard origins and credential-bearing cross-origin defaults are
not accepted.

## Web-to-API interaction avenues

The reviewed data-plane contract has four deliberately distinct avenues:

1. The web tier may perform a literal tenant-predicated SeaORM read in an explicit
   read-only transaction. It cannot migrate or mutate through that connection.
2. Stateless HTTP uses the routes below, a fresh end-user bearer, exact tenant
   membership, bounded bodies and timeouts, and no redirect-following client policy.
3. Stateful TCP is opt-in through `APME_API_TCP_BIND` and requires a server
   certificate/key plus `APME_API_TCP_CLIENT_CA_FILE`. Connections are mTLS-only,
   length-delimited, concurrency/idle/request-count bounded, and every frame carries a
   fresh bearer that is re-introspected before a tenant-scoped read.
4. Durable async status uses the credential-free
   `apme.web_api.outbox.status`/`apme.web_api.inbox.status.*` JetStream pair. The API
   requires TLS, an external NATS credentials file, pre-provisioned file-backed
   streams, work-queue request retention, bounded delivery, a durable pull consumer,
   explicit acknowledgement, broker deduplication, correlated response IDs, and
   bounded payloads. User and service bearer tokens are forbidden in messages.

TCP configuration is completed with `APME_API_TCP_TLS_CERT_FILE`,
`APME_API_TCP_TLS_KEY_FILE`, and the bounded optional connection settings documented
in `src/transport.rs`. JetStream configuration uses `APME_NATS_URL` (which must be
`tls://`), `APME_NATS_CREDENTIALS_FILE`, and optional pre-provisioned stream/consumer
names. Omitting an avenue's enabling variable leaves that listener disabled; a
partially configured enabled avenue fails startup.

## Routes

- `GET /healthz`, `GET /readyz`, `GET /metrics`
- `GET|POST /api/v1/cases`
- `GET /api/v1/cases/{id}`
- `POST /api/v1/cases/{id}/transition`
- `POST /api/v1/cases/{id}/rotate-object` (administrator only; reference/digest/key version)
- `GET /ws?tenant_id=<uuid>[&case_id=<uuid>]` for scoped JSON event envelopes

The server applies the pinned `apme-interfaces` tenant persistence migration before it
accepts traffic. Run `cargo test --all-targets` against PostgreSQL to execute real
two-connection idempotency/version races, restart durability, tenant isolation,
retention/legal-hold, encrypted-reference key rotation, and tamper-detection canaries.

Generated clients have not yet consumed the new retry/conflict fixtures. A production
promotion must also exercise two deployed tenants over REST and WebSocket, expired and
revoked live sessions, allowlisted and rejected preflights, backup/restore continuity,
and object-store key rotation without exposing document credentials.

```bash
cargo run
```

The Zed package manifest records dependency intent and the locked Rust validation
command. No `.zpkg.lock` is committed until a real Zed resolver successfully produces
one.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).
