use apme_api::{
    auth::{AuthFailure, AuthService},
    cases::{CaseService, CaseServiceError},
};
use apme_interfaces::{
    cases::{
        CaseEventReceipt, CaseMutationResult, CreateCaseCommand, PersistedCase,
        RotateEncryptedObjectCommand, TransitionCaseCommand,
    },
    security::{CaseSubscription, TenantContext, VerifiedSubject},
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, Query, State, WebSocketUpgrade,
    },
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};
use tokio::sync::broadcast;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use uuid::Uuid;

const DEFAULT_DEV_ORIGINS: &str = "http://127.0.0.1:3000,http://localhost:3000";
const TENANT_HEADER: &str = "x-apme-tenant-id";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

#[derive(Clone)]
struct AppState {
    auth: AuthService,
    cases: CaseService,
    events: broadcast::Sender<TenantEvent>,
}

#[derive(Debug, Clone, Serialize)]
struct TenantEvent {
    tenant_id: Uuid,
    case_id: Uuid,
    event: CaseEventReceipt,
}

#[derive(Debug, Deserialize)]
struct WebSocketQuery {
    tenant_id: Uuid,
    #[serde(default)]
    case_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
    version: &'a str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();

    let auth = AuthService::from_env()?;
    let cases = CaseService::from_env().await?;
    cases.migrate().await?;
    let cors = cors_layer_from_env()?;
    let (events, _) = broadcast::channel(256);
    let state = AppState {
        auth,
        cases,
        events,
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/cases", get(list_cases).post(create_case))
        .route("/api/v1/cases/{id}", get(get_case))
        .route(
            "/api/v1/cases/{id}/transition",
            axum::routing::post(transition_case),
        )
        .route(
            "/api/v1/cases/{id}/rotate-object",
            axum::routing::post(rotate_encrypted_object),
        )
        .route("/ws", get(websocket))
        .layer(cors)
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<_>| {
                tracing::info_span!("http.request", method = %request.method())
            },
        ))
        .with_state(state);
    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Apostille Me API listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn cors_layer_from_env() -> Result<CorsLayer, Box<dyn Error>> {
    let configured = env::var("CORS_ALLOWED_ORIGINS").ok();
    let raw = match configured {
        Some(value) => value,
        None if env::var("APP_ENV").is_ok_and(|value| value.eq_ignore_ascii_case("production")) => {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "CORS_ALLOWED_ORIGINS is required when APP_ENV=production",
            )
            .into());
        }
        None => DEFAULT_DEV_ORIGINS.to_owned(),
    };

    cors_layer(&raw)
}

fn cors_layer(raw: &str) -> Result<CorsLayer, Box<dyn Error>> {
    let origins = parse_allowed_origins(raw)?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static(TENANT_HEADER),
            HeaderName::from_static(IDEMPOTENCY_HEADER),
        ]))
}

fn parse_allowed_origins(raw: &str) -> Result<Vec<HeaderValue>, Box<dyn Error>> {
    let candidates: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .collect();

    if candidates.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "CORS_ALLOWED_ORIGINS must contain at least one origin",
        )
        .into());
    }

    let mut origins = Vec::with_capacity(candidates.len());
    for origin in candidates {
        if origin == "*" {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "wildcard CORS origins are not allowed",
            )
            .into());
        }

        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!("CORS origin must use http or https: {origin}"),
                )
            })?;
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
        {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!("CORS origin must not contain a path, query, or fragment: {origin}"),
            )
            .into());
        }

        origins.push(origin.parse::<HeaderValue>()?);
    }

    Ok(origins)
}

async fn index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "apme-api",
        "product": "Apostille Me",
        "rest": "/api/v1/cases",
        "websocket": "/ws"
    }))
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        service: "apme-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn metrics(State(state): State<AppState>) -> Result<String, ApiError> {
    let case_count: i64 = sqlx::query_scalar("select count(*) from apme_cases")
        .fetch_one(state.cases.pool())
        .await
        .map_err(|error| ApiError::Cases(CaseServiceError::Storage(error)))?;
    Ok(format!(
        "# TYPE apme_records gauge\napme_records {case_count}\n"
    ))
}

async fn list_cases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PersistedCase>>, ApiError> {
    let (_, context) = authorized_tenant(&state, &headers).await?;
    Ok(Json(state.cases.list_cases(&context).await?))
}

async fn get_case(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PersistedCase>, ApiError> {
    let (subject, context) = authorized_tenant(&state, &headers).await?;
    let case = state.cases.get_case(&context, id).await?;
    state
        .cases
        .record_access(&context, &subject, case.id)
        .await?;
    Ok(Json(case))
}

async fn create_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(command): Json<CreateCaseCommand>,
) -> Result<(StatusCode, Json<CaseMutationResult>), ApiError> {
    let (subject, context) = authorized_tenant(&state, &headers).await?;
    let idempotency_key = idempotency_key(&headers)?;
    let mutation = state
        .cases
        .create_case(&context, &subject, idempotency_key, &command, Utc::now())
        .await?;
    let status = if mutation.replayed {
        StatusCode::OK
    } else {
        publish_mutation(&state, &mutation);
        StatusCode::CREATED
    };
    Ok((status, Json(mutation)))
}

async fn transition_case(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(command): Json<TransitionCaseCommand>,
) -> Result<Json<CaseMutationResult>, ApiError> {
    let (subject, context) = authorized_tenant(&state, &headers).await?;
    let idempotency_key = idempotency_key(&headers)?;
    let mutation = state
        .cases
        .transition_case(
            &context,
            &subject,
            id,
            idempotency_key,
            &command,
            Utc::now(),
        )
        .await?;
    if !mutation.replayed {
        publish_mutation(&state, &mutation);
    }
    Ok(Json(mutation))
}

async fn rotate_encrypted_object(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(command): Json<RotateEncryptedObjectCommand>,
) -> Result<Json<CaseMutationResult>, ApiError> {
    let (subject, context) = authorized_tenant(&state, &headers).await?;
    let idempotency_key = idempotency_key(&headers)?;
    let mutation = state
        .cases
        .rotate_encrypted_object(
            &context,
            &subject,
            id,
            idempotency_key,
            &command,
            Utc::now(),
        )
        .await?;
    if !mutation.replayed {
        publish_mutation(&state, &mutation);
    }
    Ok(Json(mutation))
}

fn publish_mutation(state: &AppState, mutation: &CaseMutationResult) {
    let _ = state.events.send(TenantEvent {
        tenant_id: mutation.case.tenant_id,
        case_id: mutation.case.id,
        event: mutation.event.clone(),
    });
}

async fn authorized_tenant(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(VerifiedSubject, TenantContext), ApiError> {
    let subject = state.auth.authenticate(headers).await?;
    let tenant_id = tenant_id(headers)?;
    let context = state.cases.tenant_context(&subject, tenant_id).await?;
    Ok((subject, context))
}

fn tenant_id(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    headers
        .get(TENANT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ApiError::Validation("x-apme-tenant-id must be a UUID".into()))
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::Validation("Idempotency-Key is required".into()))
}

async fn websocket(
    ws: WebSocketUpgrade,
    Query(query): Query<WebSocketQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let subject = state.auth.authenticate(&headers).await?;
    state
        .cases
        .tenant_context(&subject, query.tenant_id)
        .await?;
    let subscription = CaseSubscription {
        tenant_id: query.tenant_id,
        case_id: query.case_id,
    };
    let receiver = state.events.subscribe();
    Ok(ws.on_upgrade(move |socket| socket_loop(socket, receiver, subscription)))
}

async fn socket_loop(
    socket: WebSocket,
    mut events: broadcast::Receiver<TenantEvent>,
    subscription: CaseSubscription,
) {
    let (mut sender, mut receiver) = socket.split();
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) if subscription_allows(&subscription, &event) => {
                    let Ok(text) = serde_json::to_string(&event) else { break };
                    if sender.send(Message::Text(text.into())).await.is_err() { break; }
                },
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {},
                Err(broadcast::error::RecvError::Closed) => break,
            },
            message = receiver.next() => match message {
                Some(Ok(Message::Ping(data)))
                    if sender.send(Message::Pong(data.clone())).await.is_err() => break,
                Some(Ok(Message::Ping(_))) => {},
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {},
            }
        }
    }
}

fn subscription_allows(subscription: &CaseSubscription, event: &TenantEvent) -> bool {
    subscription.tenant_id == event.tenant_id
        && subscription
            .case_id
            .is_none_or(|case_id| case_id == event.case_id)
}

#[derive(Debug)]
enum ApiError {
    Authentication(AuthFailure),
    Cases(CaseServiceError),
    Validation(String),
}

impl From<AuthFailure> for ApiError {
    fn from(value: AuthFailure) -> Self {
        Self::Authentication(value)
    }
}

impl From<CaseServiceError> for ApiError {
    fn from(value: CaseServiceError) -> Self {
        Self::Cases(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Authentication(AuthFailure::Unauthorized) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", None)
            }
            Self::Authentication(AuthFailure::Forbidden)
            | Self::Cases(CaseServiceError::NotAuthorized) => {
                (StatusCode::FORBIDDEN, "forbidden", None)
            }
            Self::Authentication(AuthFailure::Degraded)
            | Self::Cases(CaseServiceError::Storage(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            ),
            Self::Cases(CaseServiceError::NotFound) => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Cases(CaseServiceError::IdempotencyConflict) => {
                (StatusCode::CONFLICT, "idempotency_key_reused", None)
            }
            Self::Cases(CaseServiceError::StaleVersion) => {
                (StatusCode::CONFLICT, "stale_version", None)
            }
            Self::Cases(CaseServiceError::InvalidTransition) => {
                (StatusCode::CONFLICT, "invalid_transition", None)
            }
            Self::Cases(CaseServiceError::KeyVersionRollback) => {
                (StatusCode::CONFLICT, "key_version_rollback", None)
            }
            Self::Cases(CaseServiceError::Validation(message)) | Self::Validation(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation",
                Some(message),
            ),
        };
        let body = match message {
            Some(message) => serde_json::json!({"error":code, "message":message}),
            None => serde_json::json!({"error":code}),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn accepts_explicit_http_and_https_origins() {
        let origins = parse_allowed_origins("https://app.apostille.me, http://127.0.0.1:3000")
            .expect("valid origins should parse");

        let rendered: Vec<&str> = origins
            .iter()
            .map(|origin| origin.to_str().expect("origin is visible ASCII"))
            .collect();
        assert_eq!(
            rendered,
            vec!["https://app.apostille.me", "http://127.0.0.1:3000"]
        );
    }

    #[test]
    fn rejects_wildcard_origin() {
        let error = parse_allowed_origins("*").expect_err("wildcard must fail");
        assert!(error.to_string().contains("wildcard"));
    }

    #[test]
    fn rejects_empty_origin_list() {
        let error = parse_allowed_origins(" , ").expect_err("empty list must fail");
        assert!(error.to_string().contains("at least one origin"));
    }

    #[test]
    fn rejects_origin_with_path() {
        let error = parse_allowed_origins("https://app.apostille.me/callback")
            .expect_err("origin path must fail");
        assert!(error.to_string().contains("path, query, or fragment"));
    }

    #[tokio::test]
    async fn cors_preflight_allows_only_configured_origin_and_headers() {
        let app = Router::new()
            .route("/api/v1/cases", get(|| async { StatusCode::NO_CONTENT }))
            .layer(cors_layer("https://app.apostille.me").unwrap());
        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/cases")
                    .header("origin", "https://app.apostille.me")
                    .header("access-control-request-method", "POST")
                    .header(
                        "access-control-request-headers",
                        "authorization,content-type,x-apme-tenant-id,idempotency-key",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            allowed
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.apostille.me"
        );
        assert!(allowed
            .headers()
            .get("access-control-allow-headers")
            .is_some());

        let rejected = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/cases")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(rejected
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[test]
    fn websocket_filter_requires_exact_tenant_and_optional_case() {
        let tenant = Uuid::new_v4();
        let case = Uuid::new_v4();
        let event = TenantEvent {
            tenant_id: tenant,
            case_id: case,
            event: CaseEventReceipt {
                event_id: Uuid::new_v4(),
                tenant_id: tenant,
                case_id: case,
                case_version: 1,
                event_type: "case.created".into(),
                occurred_at: Utc::now(),
                event_hash: "00".repeat(32),
            },
        };
        assert!(subscription_allows(
            &CaseSubscription {
                tenant_id: tenant,
                case_id: None,
            },
            &event
        ));
        assert!(subscription_allows(
            &CaseSubscription {
                tenant_id: tenant,
                case_id: Some(case),
            },
            &event
        ));
        assert!(!subscription_allows(
            &CaseSubscription {
                tenant_id: Uuid::new_v4(),
                case_id: None,
            },
            &event
        ));
        assert!(!subscription_allows(
            &CaseSubscription {
                tenant_id: tenant,
                case_id: Some(Uuid::new_v4()),
            },
            &event
        ));
    }
}
