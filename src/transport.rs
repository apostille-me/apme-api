//! Opt-in API adapters for the stateful and durable asynchronous avenues.
//!
//! HTTP remains the ordinary request boundary in `main`. The TCP listener is
//! persistent, framed, mutually authenticated with TLS, bounded, and
//! re-introspects a fresh user bearer in every frame. JetStream is restricted
//! to credential-free service-status work over pre-provisioned file streams.

#[cfg(feature = "tcp-transport")]
pub mod tcp {
    use std::{env, fs::File, io::BufReader, path::PathBuf, sync::Arc, time::Duration};

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::{watch, Semaphore},
        time::timeout,
    };
    use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    use uuid::Uuid;

    use crate::{authorize_token, AppState};

    const MAX_REQUEST_BYTES: usize = 20 * 1024;
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    const DEFAULT_MAX_CONNECTIONS: usize = 128;
    const DEFAULT_MAX_REQUESTS: usize = 64;
    const DEFAULT_IDLE_SECONDS: usize = 15;

    #[derive(Clone, Debug)]
    pub struct Config {
        pub bind: String,
        pub certificate_path: PathBuf,
        pub private_key_path: PathBuf,
        pub client_ca_path: PathBuf,
        pub max_connections: usize,
        pub max_requests_per_connection: usize,
        pub idle_timeout: Duration,
    }

    impl Config {
        pub fn from_env() -> Result<Option<Self>> {
            let Some(bind) = optional_env("APME_API_TCP_BIND") else {
                return Ok(None);
            };
            Ok(Some(Self {
                bind,
                certificate_path: required_path("APME_API_TCP_TLS_CERT_FILE")?,
                private_key_path: required_path("APME_API_TCP_TLS_KEY_FILE")?,
                client_ca_path: required_path("APME_API_TCP_CLIENT_CA_FILE")?,
                max_connections: bounded_env(
                    "APME_API_TCP_MAX_CONNECTIONS",
                    DEFAULT_MAX_CONNECTIONS,
                    1,
                    4_096,
                )?,
                max_requests_per_connection: bounded_env(
                    "APME_API_TCP_MAX_REQUESTS_PER_CONNECTION",
                    DEFAULT_MAX_REQUESTS,
                    1,
                    4_096,
                )?,
                idle_timeout: Duration::from_secs(bounded_env(
                    "APME_API_TCP_IDLE_TIMEOUT_SECONDS",
                    DEFAULT_IDLE_SECONDS,
                    1,
                    300,
                )? as u64),
            }))
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FrameRequest {
        request_id: Uuid,
        tenant_id: Uuid,
        bearer_token: String,
        operation: Operation,
    }

    #[derive(Clone, Copy, Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Operation {
        ListCases,
    }

    #[derive(Debug, Serialize)]
    struct FrameResponse {
        request_id: Uuid,
        status: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        payload: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<&'static str>,
    }

    pub struct Server {
        listener: TcpListener,
        acceptor: TlsAcceptor,
        state: AppState,
        config: Config,
        permits: Arc<Semaphore>,
    }

    impl Server {
        pub async fn bind(config: Config, state: AppState) -> Result<Self> {
            let listener = TcpListener::bind(&config.bind)
                .await
                .with_context(|| format!("bind Apostille Me mTLS service at {}", config.bind))?;
            let acceptor = TlsAcceptor::from(Arc::new(load_tls_config(&config)?));
            Ok(Self {
                listener,
                acceptor,
                state,
                permits: Arc::new(Semaphore::new(config.max_connections)),
                config,
            })
        }

        pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        changed.context("mTLS shutdown channel closed")?;
                        return Ok(());
                    }
                    accepted = self.listener.accept() => {
                        let (stream, _) = accepted.context("accept Apostille Me mTLS connection")?;
                        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                            continue;
                        };
                        let acceptor = self.acceptor.clone();
                        let state = self.state.clone();
                        let config = self.config.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            if let Err(error) = serve_connection(stream, state, &config).await {
                                tracing::warn!(error = %error, "bounded mTLS connection ended");
                            }
                        });
                    }
                }
            }
        }
    }

    async fn serve_connection(
        stream: TlsStream<TcpStream>,
        state: AppState,
        config: &Config,
    ) -> Result<()> {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_REQUEST_BYTES)
            .length_field_length(4)
            .new_codec();
        let mut framed = Framed::new(stream, codec);
        for _ in 0..config.max_requests_per_connection {
            let Some(frame) = timeout(config.idle_timeout, framed.next())
                .await
                .context("mTLS connection idle timeout")?
            else {
                return Ok(());
            };
            let frame = frame.context("read bounded mTLS frame")?;
            let response = execute(&state, &frame).await;
            anyhow::ensure!(
                !response.is_empty() && response.len() <= MAX_RESPONSE_BYTES,
                "invalid response frame length"
            );
            timeout(config.idle_timeout, framed.send(Bytes::from(response)))
                .await
                .context("mTLS response timeout")??;
        }
        Ok(())
    }

    async fn execute(state: &AppState, bytes: &[u8]) -> Vec<u8> {
        let Ok(request) = serde_json::from_slice::<FrameRequest>(bytes) else {
            return encode_failure(Uuid::nil(), "invalid_request");
        };
        let context = match authorize_token(
            state,
            &request.bearer_token,
            request.tenant_id,
            &[apme_api::auth::CASES_READ_SCOPE],
        )
        .await
        {
            Ok((_, context)) => context,
            Err(error) => return encode_failure(request.request_id, error.code()),
        };
        let payload = match request.operation {
            Operation::ListCases => match state.cases.list_cases(&context).await {
                Ok(cases) => json!({"cases": cases, "mode": "stateful_mtls_tcp"}),
                Err(_) => return encode_failure(request.request_id, "temporarily_unavailable"),
            },
        };
        serde_json::to_vec(&FrameResponse {
            request_id: request.request_id,
            status: "ok",
            payload: Some(payload),
            error: None,
        })
        .ok()
        .filter(|value| value.len() <= MAX_RESPONSE_BYTES)
        .unwrap_or_else(|| encode_failure(request.request_id, "response_too_large"))
    }

    fn encode_failure(request_id: Uuid, error: &'static str) -> Vec<u8> {
        serde_json::to_vec(&FrameResponse {
            request_id,
            status: "error",
            payload: None,
            error: Some(error),
        })
        .unwrap_or_else(|_| br#"{"status":"error","error":"encoding_failed"}"#.to_vec())
    }

    fn load_tls_config(config: &Config) -> Result<rustls::ServerConfig> {
        let mut certificates_reader = BufReader::new(
            File::open(&config.certificate_path).context("open mTLS server certificate")?,
        );
        let certificates = rustls_pemfile::certs(&mut certificates_reader)
            .collect::<std::io::Result<Vec<_>>>()
            .context("parse mTLS server certificate")?;
        anyhow::ensure!(
            !certificates.is_empty(),
            "server certificate chain is empty"
        );
        let mut private_key_reader =
            BufReader::new(File::open(&config.private_key_path).context("open mTLS server key")?);
        let private_key = rustls_pemfile::private_key(&mut private_key_reader)
            .context("parse mTLS server key")?
            .context("mTLS server key is missing")?;
        let mut roots = rustls::RootCertStore::empty();
        let mut client_ca_reader =
            BufReader::new(File::open(&config.client_ca_path).context("open mTLS client CA")?);
        let client_cas = rustls_pemfile::certs(&mut client_ca_reader)
            .collect::<std::io::Result<Vec<_>>>()
            .context("parse mTLS client CA")?;
        anyhow::ensure!(!client_cas.is_empty(), "client CA bundle is empty");
        for certificate in client_cas {
            roots.add(certificate).context("invalid mTLS client CA")?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build mandatory client-certificate verifier")?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .context("mTLS certificate and key do not match")
    }

    fn optional_env(name: &str) -> Option<String> {
        env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    fn required_path(name: &str) -> Result<PathBuf> {
        optional_env(name)
            .map(PathBuf::from)
            .with_context(|| format!("{name} is required when mTLS is enabled"))
    }

    fn bounded_env(name: &str, default: usize, minimum: usize, maximum: usize) -> Result<usize> {
        let value = match optional_env(name) {
            Some(value) => value
                .parse::<usize>()
                .with_context(|| format!("{name} must be an integer"))?,
            None => default,
        };
        anyhow::ensure!(
            (minimum..=maximum).contains(&value),
            "{name} is out of bounds"
        );
        Ok(value)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn request_is_strict_bounded_and_requires_a_fresh_user_bearer() {
            let request_id = Uuid::new_v4();
            let tenant_id = Uuid::new_v4();
            let valid = format!(
                r#"{{"request_id":"{request_id}","tenant_id":"{tenant_id}","bearer_token":"synthetic.token","operation":"list_cases"}}"#
            );
            assert!(valid.len() <= MAX_REQUEST_BYTES);
            assert!(serde_json::from_str::<FrameRequest>(&valid).is_ok());
            let injected = format!(
                r#"{{"request_id":"{request_id}","tenant_id":"{tenant_id}","bearer_token":"synthetic.token","operation":"list_cases","subject":"injected"}}"#
            );
            assert!(serde_json::from_str::<FrameRequest>(&injected).is_err());
        }
    }
}

#[cfg(feature = "nats-transport")]
pub mod nats {
    use std::{env, path::PathBuf, time::Duration};

    use anyhow::{Context, Result};
    use async_nats::{
        jetstream::{
            self,
            consumer::{self, AckPolicy},
            message::{AckKind, PublishMessage},
            stream::{RetentionPolicy, StorageType},
        },
        ConnectOptions,
    };
    use bytes::Bytes;
    use futures_util::StreamExt;
    use serde::{Deserialize, Serialize};
    use tokio::sync::watch;
    use uuid::Uuid;

    use crate::AppState;

    pub const REQUEST_SUBJECT: &str = "apme.web_api.outbox.status";
    pub const RESPONSE_SUBJECT_PREFIX: &str = "apme.web_api.inbox.status";
    const REQUEST_SCHEMA: &str = "apme.async-status-request.v1";
    const RESPONSE_SCHEMA: &str = "apme.async-status-response.v1";
    const MAX_SIGNAL_BYTES: usize = 4 * 1024;
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    const DEFAULT_REQUEST_STREAM: &str = "APME_STATUS_OUTBOX";
    const DEFAULT_RESPONSE_STREAM: &str = "APME_STATUS_INBOX";
    const DEFAULT_CONSUMER: &str = "apme-api-status";

    #[derive(Clone, Debug)]
    pub struct Config {
        pub url: String,
        pub credentials_path: PathBuf,
        pub request_stream: String,
        pub response_stream: String,
        pub consumer: String,
    }

    impl Config {
        pub fn from_env() -> Result<Option<Self>> {
            let Some(url) = optional_env("APME_NATS_URL") else {
                return Ok(None);
            };
            let config = Self {
                url,
                credentials_path: PathBuf::from(required_env("APME_NATS_CREDENTIALS_FILE")?),
                request_stream: optional_env("APME_NATS_REQUEST_STREAM")
                    .unwrap_or_else(|| DEFAULT_REQUEST_STREAM.to_owned()),
                response_stream: optional_env("APME_NATS_RESPONSE_STREAM")
                    .unwrap_or_else(|| DEFAULT_RESPONSE_STREAM.to_owned()),
                consumer: optional_env("APME_NATS_CONSUMER")
                    .unwrap_or_else(|| DEFAULT_CONSUMER.to_owned()),
            };
            config.validate()?;
            Ok(Some(config))
        }

        fn validate(&self) -> Result<()> {
            let authority = self
                .url
                .strip_prefix("tls://")
                .context("APME_NATS_URL must use tls://")?
                .split('/')
                .next()
                .unwrap_or_default();
            anyhow::ensure!(
                !authority.is_empty() && !authority.contains('@'),
                "NATS credentials must come from the credentials file"
            );
            for value in [&self.request_stream, &self.response_stream, &self.consumer] {
                anyhow::ensure!(safe_topology_name(value), "invalid JetStream topology name");
            }
            Ok(())
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StatusRequest {
        schema: String,
        operation_id: Uuid,
    }

    #[derive(Debug, Serialize)]
    struct StatusResponse {
        schema: &'static str,
        operation_id: Uuid,
        status: &'static str,
        service: &'static str,
        database_ready: bool,
    }

    pub struct Worker {
        context: jetstream::Context,
        consumer: consumer::PullConsumer,
        _state: AppState,
    }

    impl Worker {
        pub async fn connect(config: Config, state: AppState) -> Result<Self> {
            config.validate()?;
            let options = ConnectOptions::with_credentials_file(&config.credentials_path)
                .await
                .context("load NATS credentials")?
                .require_tls(true)
                .name("apme-api")
                .connection_timeout(Duration::from_secs(5))
                .subscription_capacity(256);
            let context = jetstream::new(
                options
                    .connect(&config.url)
                    .await
                    .context("connect to NATS over TLS")?,
            );
            let request_stream = context
                .get_stream(&config.request_stream)
                .await
                .context("get pre-provisioned request stream")?;
            validate_request_stream(request_stream.cached_info())?;
            let response_stream = context
                .get_stream(&config.response_stream)
                .await
                .context("get pre-provisioned response stream")?;
            validate_response_stream(response_stream.cached_info())?;
            let consumer: consumer::PullConsumer = request_stream
                .get_consumer(&config.consumer)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("get pre-provisioned durable consumer: {error}")
                })?;
            validate_consumer(consumer.cached_info(), &config.consumer)?;
            Ok(Self {
                context,
                consumer,
                _state: state,
            })
        }

        pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
            let mut messages = self
                .consumer
                .messages()
                .await
                .context("start durable JetStream pull consumer")?;
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        changed.context("JetStream shutdown channel closed")?;
                        return Ok(());
                    }
                    next = messages.next() => {
                        let Some(next) = next else {
                            anyhow::bail!("durable JetStream consumer ended");
                        };
                        self.handle(next.context("receive JetStream message")?).await?;
                    }
                }
            }
        }

        async fn handle(&self, message: jetstream::Message) -> Result<()> {
            let Ok(operation_id) = decode_signal(&message.payload) else {
                message
                    .ack_with(AckKind::Term)
                    .await
                    .map_err(|error| anyhow::anyhow!("terminate invalid signal: {error}"))?;
                return Ok(());
            };
            let payload = serde_json::to_vec(&StatusResponse {
                schema: RESPONSE_SCHEMA,
                operation_id,
                status: "ok",
                service: "apme-api",
                database_ready: true,
            })
            .context("encode async status response")?;
            anyhow::ensure!(
                payload.len() <= MAX_RESPONSE_BYTES,
                "status response too large"
            );
            self.context
                .send_publish(
                    format!("{RESPONSE_SUBJECT_PREFIX}.{operation_id}"),
                    PublishMessage::build()
                        .payload(Bytes::from(payload))
                        .message_id(format!("apme-status-response-{operation_id}")),
                )
                .await
                .context("publish durable status response")?
                .await
                .context("await durable status response acknowledgement")?;
            message
                .ack()
                .await
                .map_err(|error| anyhow::anyhow!("ack request after durable response: {error}"))?;
            Ok(())
        }
    }

    fn decode_signal(payload: &[u8]) -> Result<Uuid, ()> {
        if payload.len() > MAX_SIGNAL_BYTES {
            return Err(());
        }
        let signal = serde_json::from_slice::<StatusRequest>(payload).map_err(|_| ())?;
        if signal.schema != REQUEST_SCHEMA {
            return Err(());
        }
        Ok(signal.operation_id)
    }

    fn validate_request_stream(info: &jetstream::stream::Info) -> Result<()> {
        let config = &info.config;
        anyhow::ensure!(
            config.storage == StorageType::File,
            "request stream must use file storage"
        );
        anyhow::ensure!(
            config.retention == RetentionPolicy::WorkQueue,
            "request stream must use work-queue retention"
        );
        anyhow::ensure!(
            config.subjects.iter().any(|value| value == REQUEST_SUBJECT),
            "request stream does not own canonical subject"
        );
        anyhow::ensure!(
            !config.duplicate_window.is_zero(),
            "request stream requires dedupe"
        );
        Ok(())
    }

    fn validate_response_stream(info: &jetstream::stream::Info) -> Result<()> {
        let config = &info.config;
        anyhow::ensure!(
            config.storage == StorageType::File,
            "response stream must use file storage"
        );
        anyhow::ensure!(
            config.retention == RetentionPolicy::Limits,
            "response stream must use limits retention"
        );
        anyhow::ensure!(
            config.allow_direct,
            "response stream must allow direct reads"
        );
        anyhow::ensure!(
            config
                .subjects
                .iter()
                .any(|value| value == &format!("{RESPONSE_SUBJECT_PREFIX}.*")),
            "response stream does not own canonical subjects"
        );
        anyhow::ensure!(
            !config.duplicate_window.is_zero(),
            "response stream requires dedupe"
        );
        Ok(())
    }

    fn validate_consumer(info: &consumer::Info, expected: &str) -> Result<()> {
        let config = &info.config;
        anyhow::ensure!(
            config.deliver_subject.is_none(),
            "consumer must be pull based"
        );
        anyhow::ensure!(
            config.durable_name.as_deref() == Some(expected),
            "consumer durable name mismatch"
        );
        anyhow::ensure!(
            config.ack_policy == AckPolicy::Explicit,
            "consumer requires explicit acks"
        );
        anyhow::ensure!(
            config.filter_subject == REQUEST_SUBJECT,
            "consumer filter mismatch"
        );
        anyhow::ensure!(
            (2..=100).contains(&config.max_deliver),
            "consumer max_deliver out of bounds"
        );
        anyhow::ensure!(
            (1..=4_096).contains(&config.max_ack_pending),
            "consumer max_ack_pending out of bounds"
        );
        Ok(())
    }

    fn safe_topology_name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }

    fn optional_env(name: &str) -> Option<String> {
        env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    fn required_env(name: &str) -> Result<String> {
        optional_env(name).with_context(|| format!("{name} is required when JetStream is enabled"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn signal_is_strict_bounded_and_credential_free() {
            let valid = br#"{"schema":"apme.async-status-request.v1","operation_id":"018f5cc6-6d8b-7b2a-9f38-269e6a7b1f11"}"#;
            assert!(decode_signal(valid).is_ok());
            assert!(
                decode_signal(br#"{"schema":"apme.async-status-request.v1","operation_id":"018f5cc6-6d8b-7b2a-9f38-269e6a7b1f11","bearer_token":"attack"}"#).is_err()
            );
            assert!(decode_signal(&vec![b'x'; MAX_SIGNAL_BYTES + 1]).is_err());
        }

        #[test]
        fn broker_configuration_requires_tls_and_external_credentials() {
            let config = Config {
                url: "nats://localhost:4222".to_owned(),
                credentials_path: "unused.creds".into(),
                request_stream: DEFAULT_REQUEST_STREAM.to_owned(),
                response_stream: DEFAULT_RESPONSE_STREAM.to_owned(),
                consumer: DEFAULT_CONSUMER.to_owned(),
            };
            assert!(config.validate().is_err());
        }
    }
}
