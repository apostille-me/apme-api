use std::{fs, path::Path};

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("contract source must exist")
}

#[test]
fn dependency_contract_uses_reviewed_immutable_revisions() {
    let cargo = read("Cargo.toml");
    assert!(cargo.contains("cc57a85b276bee81ad94decc87df2f48d49cab9f"));
    assert!(cargo.contains("ca176fb6768a9750d262a536952268625ffd3a8a"));
    assert!(cargo.contains("async-nats"));
    assert!(cargo.contains("sea-orm"));
    assert!(cargo.contains("tokio-rustls"));
}

#[test]
fn protected_introspection_is_scoped_bounded_and_service_authenticated() {
    let auth = read("src/auth.rs");
    assert!(auth.contains("SharedAuthClient::try_new"));
    assert!(auth.contains("with_service_credential"));
    assert!(auth.contains("with_max_response_bytes"));
    assert!(auth.contains("introspect_with_requirements"));
    assert!(auth.contains("apme:cases:read"));
}

#[test]
fn api_exposes_bounded_http_framed_mtls_and_durable_jetstream() {
    let source = read("src/transport.rs");
    for required in [
        "MAX_REQUEST_BYTES",
        "MAX_RESPONSE_BYTES",
        "TlsAcceptor",
        "LengthDelimitedCodec",
        "AckPolicy::Explicit",
        "RetentionPolicy::WorkQueue",
        "StorageType::File",
        "duplicate_window",
        "message_id",
    ] {
        assert!(source.contains(required), "missing {required}");
    }
}

#[test]
fn transport_contract_never_persists_or_logs_bearers() {
    let source = read("src/transport.rs");
    assert!(!source.contains("tracing::info!(bearer"));
    assert!(!source.contains("tracing::debug!(bearer"));
    assert!(!source.contains("bearer_token VARCHAR"));
    assert!(!source.contains("bearer_token TEXT"));
}
