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

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).
