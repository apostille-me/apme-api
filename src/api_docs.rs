//! Canonical public API-documentation routes and discovery manifest.
//!
//! The documentation surface contains route metadata only. It never reads case
//! records, accepts case input, subscribes to case events, or opens WebSockets.

use axum::{
    body::Body,
    http::{header, Response, StatusCode},
    routing::get,
    Router,
};

pub const DISCOVERY_PATH: &str = "/.well-known/api-docs";
pub const OPENAPI_PATH: &str = "/openapi.json";
pub const OPENAPI_ALIAS: &str = "/api/docs.json";
pub const DOCS_PATH: &str = "/api/docs";
pub const DOCS_ALIAS: &str = "/docs/api";
pub const OPENAPI_SHA256: &str =
    "3f71046f7308a2957ec94de435ed57bf081865c97ec6e538858d26d7d72fa762";

const OPENAPI_ETAG: &str =
    "\"3f71046f7308a2957ec94de435ed57bf081865c97ec6e538858d26d7d72fa762\"";
const OPENAPI_MEDIA_TYPE: &str = "application/vnd.oai.openapi+json;version=3.1";
const OPENAPI: &str = include_str!("../openapi/apme.openapi.json");
const MANIFEST: &str = include_str!("../openapi/api-docs.manifest.json");
const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Apostille Me API documentation</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0 auto; max-width: 72rem; padding: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid currentColor; padding: .55rem; text-align: left; }
    .mutating { font-weight: 700; }
    .restricted { font-style: italic; }
  </style>
</head>
<body>
  <h1>Apostille Me API</h1>
  <p id="provenance">Loading the canonical OpenAPI contract…</p>
  <p>This catalog describes routes only. It never loads applicant, document, or case-event data.</p>
  <table>
    <thead><tr><th>Method</th><th>Path</th><th>Operation</th><th>Summary</th><th>MCP catalog</th></tr></thead>
    <tbody id="operations"></tbody>
  </table>
  <script>
    (async () => {
      const manifestResponse = await fetch('/.well-known/api-docs', {redirect: 'error'});
      if (!manifestResponse.ok) throw new Error('manifest unavailable');
      const manifest = await manifestResponse.json();
      const specResponse = await fetch(manifest.public.openapi.path, {redirect: 'error'});
      if (!specResponse.ok) throw new Error('OpenAPI unavailable');
      const spec = await specResponse.json();
      document.querySelector('#provenance').textContent =
        `${spec.info.title} ${spec.info.version} · SHA-256 ${manifest.public.openapi.sha256}`;
      const rows = [];
      for (const [path, item] of Object.entries(spec.paths)) {
        for (const method of ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']) {
          const operation = item[method];
          if (!operation) continue;
          rows.push({path, method: method.toUpperCase(), operation});
        }
      }
      rows.sort((a, b) => a.operation.operationId.localeCompare(b.operation.operationId));
      const body = document.querySelector('#operations');
      for (const row of rows) {
        const tr = document.createElement('tr');
        if (row.operation['x-ore-mcp-mutating']) tr.classList.add('mutating');
        if (!row.operation['x-ore-mcp-expose']) tr.classList.add('restricted');
        const values = [
          row.method,
          row.path,
          row.operation.operationId,
          row.operation.summary,
          row.operation['x-ore-mcp-expose'] ? 'read-only metadata' : 'not exposed'
        ];
        for (const value of values) {
          const td = document.createElement('td');
          td.textContent = value;
          tr.appendChild(td);
        }
        body.appendChild(tr);
      }
    })().catch((error) => {
      document.querySelector('#provenance').textContent = `Documentation error: ${error.message}`;
    });
  </script>
</body>
</html>
"#;

/// Return the state-free, same-origin API-documentation router.
pub fn router() -> Router {
    Router::new()
        .route(DISCOVERY_PATH, get(discovery))
        .route(OPENAPI_PATH, get(openapi))
        .route(OPENAPI_ALIAS, get(openapi))
        .route(DOCS_PATH, get(docs))
        .route(DOCS_ALIAS, get(docs))
}

async fn discovery() -> Response<Body> {
    response(MANIFEST, "application/json", false, false)
}

async fn openapi() -> Response<Body> {
    response(OPENAPI, OPENAPI_MEDIA_TYPE, false, true)
}

async fn docs() -> Response<Body> {
    response(DOCS_HTML, "text/html; charset=utf-8", true, false)
}

fn response(
    body: &'static str,
    content_type: &'static str,
    html: bool,
    openapi_etag: bool,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .header("x-openapi-sha256", OPENAPI_SHA256)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if openapi_etag {
        builder = builder.header(header::ETAG, OPENAPI_ETAG);
    }
    if html {
        builder = builder.header(
            "content-security-policy",
            "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
        );
    }
    builder
        .body(Body::from(body))
        .expect("static API-documentation response must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        http::{Method, Request},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    async fn fetch(path: &str, method: Method) -> Response<Body> {
        router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("documentation router must respond")
    }

    #[tokio::test]
    async fn openapi_alias_is_exact_byte_for_byte() {
        let canonical = fetch(OPENAPI_PATH, Method::GET).await;
        let alias = fetch(OPENAPI_ALIAS, Method::GET).await;
        assert_eq!(canonical.status(), StatusCode::OK);
        assert_eq!(alias.status(), StatusCode::OK);
        assert_eq!(
            canonical
                .headers()
                .get("x-openapi-sha256")
                .expect("digest header")
                .to_str()
                .expect("digest header text"),
            OPENAPI_SHA256
        );
        assert_eq!(
            canonical
                .headers()
                .get(header::ETAG)
                .expect("ETag")
                .to_str()
                .expect("ETag text"),
            OPENAPI_ETAG
        );
        let canonical = to_bytes(canonical.into_body(), 1024 * 1024)
            .await
            .expect("canonical body must be bounded");
        let alias = to_bytes(alias.into_body(), 1024 * 1024)
            .await
            .expect("alias body must be bounded");
        assert_eq!(canonical, alias);
        assert_eq!(canonical.as_ref(), OPENAPI.as_bytes());
    }

    #[tokio::test]
    async fn manifest_names_canonical_pair_and_head_is_empty() {
        let response = fetch(DISCOVERY_PATH, Method::GET).await;
        let body = to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("manifest body must be bounded");
        let manifest: Value = serde_json::from_slice(&body).expect("manifest must be JSON");
        assert_eq!(manifest["schemaVersion"], "ore.api-docs.v1");
        assert_eq!(manifest["public"]["openapi"]["sha256"], OPENAPI_SHA256);
        assert_eq!(
            manifest["mcp"]["repository"],
            "apostille-me/apme-mcp-server.rs"
        );
        assert_eq!(manifest["mcp"]["mode"], "read-only");
        assert_eq!(manifest["internal"]["available"], false);

        let head = fetch(OPENAPI_PATH, Method::HEAD).await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()
                .get(header::CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("content type text"),
            OPENAPI_MEDIA_TYPE
        );
        assert!(
            to_bytes(head.into_body(), 1)
                .await
                .expect("HEAD response must be empty")
                .is_empty()
        );
    }

    #[test]
    fn checked_in_openapi_covers_all_application_routes() {
        let source = include_str!("main.rs");
        for fragment in [
            r#".route("/", get(index))"#,
            r#".route("/healthz", get(health))"#,
            r#".route("/readyz", get(health))"#,
            r#".route("/metrics", get(metrics))"#,
            r#".route("/api/v1/cases", get(list_records).post(create_record))"#,
            r#".route("/api/v1/cases/{id}", get(get_record))"#,
            r#".route("/ws", get(websocket))"#,
        ] {
            assert!(
                source.contains(fragment),
                "missing application route source fragment {fragment}"
            );
        }

        let value: Value = serde_json::from_str(OPENAPI).expect("OpenAPI must be JSON");
        let paths = value["paths"].as_object().expect("paths must be an object");
        let expected = [
            ("/", "get"),
            ("/healthz", "get"),
            ("/readyz", "get"),
            ("/metrics", "get"),
            ("/api/v1/cases", "get"),
            ("/api/v1/cases", "post"),
            ("/api/v1/cases/{id}", "get"),
            ("/ws", "get"),
        ];
        for (path, method) in expected {
            assert!(
                paths
                    .get(path)
                    .and_then(Value::as_object)
                    .is_some_and(|item| item.contains_key(method)),
                "OpenAPI is missing {} {}",
                method.to_ascii_uppercase(),
                path
            );
        }
        assert_eq!(paths.len(), 7);
    }

    #[test]
    fn only_system_reads_are_mcp_exposed() {
        let value: Value = serde_json::from_str(OPENAPI).expect("OpenAPI must be JSON");
        assert_eq!(value["openapi"], "3.1.0");
        let paths = value["paths"].as_object().expect("paths must be an object");
        let mut operation_ids = std::collections::BTreeSet::new();
        let mut exposed = Vec::new();
        let mut operation_count = 0usize;
        for (path, item) in paths {
            assert!(!path.starts_with("/internal/"));
            let item = item.as_object().expect("path item must be an object");
            for method in [
                "get", "post", "put", "patch", "delete", "head", "options", "trace",
            ] {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                operation_count += 1;
                let operation_id = operation["operationId"]
                    .as_str()
                    .expect("operationId must be a string");
                assert!(operation_ids.insert(operation_id.to_owned()));
                assert_eq!(operation["x-ore-visibility"], "public");
                assert!(matches!(
                    operation["x-ore-stability"].as_str(),
                    Some("stable" | "beta" | "experimental")
                ));
                let mutating = operation["x-ore-mcp-mutating"]
                    .as_bool()
                    .expect("mutation flag must be Boolean");
                let mcp_expose = operation["x-ore-mcp-expose"]
                    .as_bool()
                    .expect("exposure flag must be Boolean");
                assert_eq!(mutating, !matches!(method, "get" | "head" | "options"));
                assert!(!(mutating && mcp_expose));
                if mcp_expose {
                    exposed.push(operation_id);
                }
                if operation["tags"].as_array().is_some_and(|tags| {
                    tags.iter().any(|tag| {
                        matches!(tag.as_str(), Some("operations" | "cases" | "realtime"))
                    })
                }) {
                    assert!(
                        !mcp_expose,
                        "case, metrics, or realtime operation was MCP-exposed: {operation_id}"
                    );
                }
            }
        }
        assert_eq!(operation_count, 8);
        assert_eq!(operation_ids.len(), 8);
        assert_eq!(
            exposed,
            ["getServiceBanner", "getHealth", "getReadiness"]
        );
    }
}
