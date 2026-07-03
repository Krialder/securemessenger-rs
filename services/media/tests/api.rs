//! Integrationstests des Medien-Dienstes: Upload/Download-Roundtrip,
//! Auth- und Formfehler, Rate-Limit. identity ersetzt ein Fake-Gateway,
//! die Blob-Ablage ist der In-Memory-Objektspeicher.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::identity_client::{AccountDevices, CallerIdentity, IdentityGateway};
use http_body_util::BodyExt;
use media::api::{app, AppState, MAX_MEDIA_BYTES};
use object_store::memory::InMemory;
use tower::ServiceExt;

struct FakeIdentity {
    tokens: HashMap<String, CallerIdentity>,
}

#[async_trait]
impl IdentityGateway for FakeIdentity {
    async fn introspect(&self, token: &str) -> Result<Option<CallerIdentity>, String> {
        if token == "kaputt" {
            return Err("identity nicht erreichbar".to_string());
        }
        Ok(self.tokens.get(token).cloned())
    }

    async fn account_devices(&self, _handle: &str) -> Result<Option<AccountDevices>, String> {
        Ok(None)
    }
}

fn test_app() -> Router {
    let mut tokens = HashMap::new();
    tokens.insert(
        "token-alice".to_string(),
        CallerIdentity {
            handle: "alice".to_string(),
            device_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
        },
    );
    app(AppState::new(
        Arc::new(InMemory::new()),
        Arc::new(FakeIdentity { tokens }),
    ))
}

async fn send_raw(
    app: &Router,
    method: &str,
    uri: &str,
    body: Vec<u8>,
    bearer: Option<&str>,
) -> (StatusCode, Bytes) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes)
}

fn json(bytes: &Bytes) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn upload_download_roundtrip() {
    let app = test_app();
    let blob = b"chiffretext-blob \x00\x01\x02".to_vec();

    let (status, body) = send_raw(&app, "POST", "/media", blob.clone(), Some("token-alice")).await;
    assert_eq!(status, StatusCode::CREATED, "{}", json(&body));
    let reference = json(&body)["ref"].as_str().unwrap().to_string();

    let (status, body) = send_raw(
        &app,
        "GET",
        &format!("/media/{reference}"),
        Vec::new(),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.to_vec(), blob, "Blob kommt bitidentisch zurück");
}

#[tokio::test]
async fn rejects_bad_requests() {
    let app = test_app();

    // Ohne Token 401, identity-Ausfall 500 (nie 401).
    for bearer in [None, Some("unbekannt")] {
        let (status, _) = send_raw(&app, "POST", "/media", b"x".to_vec(), bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send_raw(&app, "POST", "/media", b"x".to_vec(), Some("kaputt")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // Leerer Body und Übergröße.
    let (status, body) = send_raw(&app, "POST", "/media", Vec::new(), Some("token-alice")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["code"], "empty_media");
    let (status, body) = send_raw(
        &app,
        "POST",
        "/media",
        vec![0u8; MAX_MEDIA_BYTES + 1],
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(&body)["code"], "media_too_large");

    // Unbekannte (gültige UUID) und unparsebare (Nicht-UUID) Referenzen:
    // beide 404 unknown_ref aus dem Handler. Der Nicht-UUID-Fall bleibt ein
    // einzelnes Pfadsegment, sonst fängt ihn der Router-404 vor dem Handler ab
    // (ein `../`-Pfad ist gar kein Lookup, das schützt schon das Routing).
    for reference in ["00000000-0000-4000-8000-000000000000", "kein-gueltiger-ref"] {
        let (status, body) = send_raw(
            &app,
            "GET",
            &format!("/media/{reference}"),
            Vec::new(),
            Some("token-alice"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "ref {reference}");
        assert_eq!(json(&body)["code"], "unknown_ref");
    }
}

#[tokio::test]
async fn upload_rate_limit_returns_429() {
    let app = test_app();
    // Limit ist 30/min je Konto: die ersten 30 gehen durch, die 31. nicht.
    for i in 0..30 {
        let (status, _) = send_raw(
            &app,
            "POST",
            "/media",
            b"blob".to_vec(),
            Some("token-alice"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "Upload {i}");
    }
    let (status, body) = send_raw(
        &app,
        "POST",
        "/media",
        b"blob".to_vec(),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(&body)["code"], "rate_limited");
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let app = test_app();
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send_raw(&app, "GET", uri, Vec::new(), None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
    // Nach ein paar Anfragen liefert /metrics die SLI-Reihen.
    send_raw(&app, "POST", "/media", b"x".to_vec(), None).await;
    let (_, body) = send_raw(&app, "GET", "/metrics", Vec::new(), None).await;
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("http_requests_total"));
    assert!(text.contains("http_request_duration_seconds_bucket"));
}
