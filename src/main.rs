use apme_interfaces::{Case, CaseEvent, CreateCase};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::{broadcast, RwLock};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use uuid::Uuid;

const DEFAULT_DEV_ORIGINS: &str = "http://127.0.0.1:3000,http://localhost:3000";

#[derive(Clone)]
struct AppState {
    records: Arc<RwLock<BTreeMap<Uuid, Case>>>,
    events: broadcast::Sender<String>,
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

    let cors = cors_layer_from_env()?;
    let (events, _) = broadcast::channel(256);
    let state = AppState {
        records: Arc::new(RwLock::new(BTreeMap::new())),
        events,
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/cases", get(list_records).post(create_record))
        .route("/api/v1/cases/{id}", get(get_record))
        .route("/ws", get(websocket))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
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
        None
            if env::var("APP_ENV")
                .is_ok_and(|value| value.eq_ignore_ascii_case("production")) =>
        {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "CORS_ALLOWED_ORIGINS is required when APP_ENV=production",
            )
            .into());
        }
        None => DEFAULT_DEV_ORIGINS.to_owned(),
    };

    let origins = parse_allowed_origins(&raw)?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]))
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

        origins.push(HeaderValue::from_str(origin)?);
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

async fn metrics(State(state): State<AppState>) -> String {
    format!(
        "# TYPE apme_records gauge\napme_records {}\n",
        state.records.read().await.len()
    )
}

async fn list_records(State(state): State<AppState>) -> Json<Vec<Case>> {
    Json(state.records.read().await.values().cloned().collect())
}

async fn get_record(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<Case>, ApiError> {
    state
        .records
        .read()
        .await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn create_record(
    State(state): State<AppState>,
    Json(input): Json<CreateCase>,
) -> Result<(StatusCode, Json<Case>), ApiError> {
    let now = Utc::now();
    let record = input
        .into_record(Uuid::new_v4(), now)
        .map_err(|error| ApiError::Validation(error.to_string()))?;
    state
        .records
        .write()
        .await
        .insert(record.id, record.clone());
    let event = CaseEvent {
        event_id: Uuid::new_v4(),
        event_type: "case.created".into(),
        occurred_at: now,
        data: record.clone(),
    };
    let _ = state
        .events
        .send(serde_json::to_string(&event).expect("serializable event"));
    Ok((StatusCode::CREATED, Json(record)))
}

async fn websocket(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| socket_loop(socket, state.events.subscribe()))
}

async fn socket_loop(socket: WebSocket, mut events: broadcast::Receiver<String>) {
    let (mut sender, mut receiver) = socket.split();
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(text) => {
                    if sender.send(Message::Text(text.into())).await.is_err() { break; }
                },
                Err(broadcast::error::RecvError::Closed) => break,
                _ => {},
            },
            message = receiver.next() => match message {
                Some(Ok(Message::Ping(data))) => {
                    if sender.send(Message::Pong(data)).await.is_err() { break; }
                },
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {},
            }
        }
    }
}

#[derive(Debug)]
enum ApiError {
    NotFound,
    Validation(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"not_found"})),
            )
                .into_response(),
            Self::Validation(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error":"validation", "message":message})),
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_explicit_http_and_https_origins() {
        let origins = parse_allowed_origins(
            "https://app.apostille.me, http://127.0.0.1:3000",
        )
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
}
