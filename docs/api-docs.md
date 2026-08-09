# Canonical API documentation

`apme-api` implements the fleet `ore.api-docs.v1` HTTP contract.

## Public same-origin routes

- `GET /.well-known/api-docs` — discovery, provenance, digest, and API/MCP pairing.
- `GET /openapi.json` — canonical public OpenAPI 3.1 document.
- `GET /api/docs.json` — exact-byte compatibility alias.
- `GET /api/docs` — static operation catalog.
- `GET /docs/api` — compatibility alias.

The documentation router is state-free and composed outside the permissive case API CORS layer. It receives normal HTTP tracing but does not receive the case store or event broadcaster. It never accepts case input, reads applicant or document metadata, serializes a case, subscribes to `case.created` events, or opens a WebSocket.

## MCP pairing

The manifest pairs this API with `apostille-me/apme-mcp-server.rs`. The paired MCP server exposes only the five baseline read-only documentation tools:

- `api_docs_discover`
- `api_docs_get_openapi`
- `api_docs_validate`
- `api_docs_list_operations`
- `api_docs_describe_operation`

Only the service banner, health, and readiness operations are MCP-exposed. The following remain documented but unavailable through the baseline MCP catalog:

- Prometheus-style case-count metrics;
- case listing and case lookup, which may contain applicant and document metadata;
- case creation, which stores a case and emits a complete `case.created` event;
- the case-event WebSocket, which streams complete case event payloads.

All `POST`, `PUT`, `PATCH`, and `DELETE` operations are classified as mutating by the fleet rule. `GET` operations that expose case data, operational counts, or long-lived event streams remain `x-ore-mcp-expose=false`.

## Promotion gate

Production promotion requires:

1. successful API and MCP source CI on immutable heads;
2. exact manifest and OpenAPI bytes embedded by the MCP repository;
3. successful credential-free certification in `apostille-me-test/.github`;
4. eight unique operations, exactly three exposed system reads, zero exposed mutations, and case/WebSocket non-exposure;
5. unchanged API and MCP heads between test evidence and merge.

No Cloudflare DNS, Worker, R2, origin, route, or secret change is required by this same-origin documentation standard.
