//! Integrationstests der HTTP-Schicht des Schlüssel-Verzeichnisses.
//!
//! identity wird durch ein Fake-Gateway ersetzt: die Tests bestimmen selbst,
//! welche Tokens gelten und welche Geräte ein Konto hat. Die echte
//! HTTP-Anbindung an identity deckt der Ende-zu-Ende-Test in tests/pg.rs
//! des identity-Dienstes nicht ab; sie bleibt bewusst dünn (reqwest-Aufrufe)
//! und wird über den Compose-Rauchtest geprüft.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::identity_client::{AccountDevices, CallerIdentity, DeviceInfo, IdentityGateway};
use directory::api::{app, AppState};
use directory::store::InMemoryPrekeyStore;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const DEV_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// Fake-Gateway: feste Token- und Kontotabellen statt HTTP.
#[derive(Default)]
struct FakeIdentity {
    tokens: HashMap<String, CallerIdentity>,
    accounts: HashMap<String, AccountDevices>,
}

#[async_trait]
impl IdentityGateway for FakeIdentity {
    async fn introspect(&self, token: &str) -> Result<Option<CallerIdentity>, String> {
        if token == "kaputt" {
            return Err("identity nicht erreichbar".to_string());
        }
        Ok(self.tokens.get(token).cloned())
    }

    async fn account_devices(&self, handle: &str) -> Result<Option<AccountDevices>, String> {
        Ok(self.accounts.get(handle).cloned())
    }
}

/// Standard-Aufbau: alice mit zwei Geräten, Token "token-a" gehört Gerät A.
fn test_app() -> Router {
    let mut fake = FakeIdentity::default();
    fake.tokens.insert(
        "token-a".to_string(),
        CallerIdentity {
            handle: "alice".to_string(),
            device_id: DEV_A.to_string(),
        },
    );
    fake.accounts.insert(
        "alice".to_string(),
        AccountDevices {
            id: "00000000-0000-4000-8000-00000000a11c".to_string(),
            handle: "alice".to_string(),
            identity_key: "aWRlbnRpdHk=".to_string(),
            devices: vec![
                DeviceInfo {
                    id: DEV_A.to_string(),
                    public_key: "a2V5LWE=".to_string(),
                    not_after: 4102444800,
                },
                DeviceInfo {
                    id: DEV_B.to_string(),
                    public_key: "a2V5LWI=".to_string(),
                    not_after: 4102444800,
                },
            ],
        },
    );
    app(AppState::new(
        Arc::new(InMemoryPrekeyStore::default()),
        Arc::new(fake),
    ))
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn prekey(id: &str) -> Value {
    json!({ "id": id, "key": "cHJla2V5" })
}

fn full_upload() -> Value {
    json!({
        "signed_prekey": prekey("11111111-0000-4000-8000-000000000001"),
        "pq_signed_prekey": prekey("11111111-0000-4000-8000-000000000002"),
        "one_time_prekeys": [
            prekey("11111111-0000-4000-8000-000000000003"),
            prekey("11111111-0000-4000-8000-000000000004"),
        ],
        "pq_one_time_prekeys": [
            prekey("11111111-0000-4000-8000-000000000005"),
        ],
    })
}

#[tokio::test]
async fn upload_and_bundle_flow() {
    let app = test_app();

    // Upload für das eigene Gerät, Antwort nennt die Restbestände.
    let (status, body) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(full_upload()),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["one_time"], 2);
    assert_eq!(body["pq_one_time"], 1);

    // Bündel-Abruf: Gerät A hat Schlüssel, Gerät B ein leeres Bündel.
    let (status, body) = send(&app, "GET", "/keys/alice", None, Some("token-a")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["handle"], "alice");
    assert_eq!(body["identity_key"], "aWRlbnRpdHk=");
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    let dev_a = devices.iter().find(|d| d["device_id"] == DEV_A).unwrap();
    assert_eq!(
        dev_a["signed_prekey"]["id"],
        "11111111-0000-4000-8000-000000000001"
    );
    assert_eq!(
        dev_a["one_time_prekey"]["id"],
        "11111111-0000-4000-8000-000000000003"
    );
    let dev_b = devices.iter().find(|d| d["device_id"] == DEV_B).unwrap();
    assert!(dev_b.get("signed_prekey").is_none());

    // Konsumierung: zweiter Abruf zieht den nächsten Einmal-Prekey, ...
    let (_, body) = send(&app, "GET", "/keys/alice", None, Some("token-a")).await;
    let devices = body["devices"].as_array().unwrap();
    let dev_a = devices.iter().find(|d| d["device_id"] == DEV_A).unwrap();
    assert_eq!(
        dev_a["one_time_prekey"]["id"],
        "11111111-0000-4000-8000-000000000004"
    );
    // ... der dritte bekommt keinen mehr, der signierte bleibt.
    let (_, body) = send(&app, "GET", "/keys/alice", None, Some("token-a")).await;
    let devices = body["devices"].as_array().unwrap();
    let dev_a = devices.iter().find(|d| d["device_id"] == DEV_A).unwrap();
    assert!(dev_a.get("one_time_prekey").is_none());
    assert_eq!(
        dev_a["signed_prekey"]["id"],
        "11111111-0000-4000-8000-000000000001"
    );

    // Zählstand über GET /keys/prekeys.
    let (status, body) = send(&app, "GET", "/keys/prekeys", None, Some("token-a")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["one_time"], 0);
    assert_eq!(body["pq_one_time"], 0);
}

#[tokio::test]
async fn rejects_bad_requests() {
    let app = test_app();

    // Ohne Token gibt es nichts.
    for (method, uri) in [
        ("GET", "/keys/alice"),
        ("GET", "/keys/prekeys"),
        ("POST", "/keys/prekeys"),
    ] {
        let body = (method == "POST").then(full_upload);
        let (status, _) = send(&app, method, uri, body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }

    // identity-Ausfall wird 500, nicht 401: Clients sollen nicht ausloggen.
    let (status, _) = send(&app, "GET", "/keys/alice", None, Some("kaputt")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // Unbekanntes Konto.
    let (status, body) = send(&app, "GET", "/keys/nobody", None, Some("token-a")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "account_not_found");

    // Leerer Upload.
    let (status, body) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(json!({})),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "empty_upload");

    // Kaputte Prekey-ID und kaputtes Base64.
    let (status, body) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(json!({ "one_time_prekeys": [{ "id": "keine-uuid", "key": "cHJla2V5" }] })),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_prekey");
    let (status, body) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(json!({ "one_time_prekeys": [prekey("11111111-0000-4000-8000-00000000000a"), { "id": "11111111-0000-4000-8000-00000000000b", "key": "kein base64!" }] })),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_prekey");

    // Doppelte Prekey-ID ist ein Konflikt.
    let (status, _) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(json!({ "one_time_prekeys": [prekey("11111111-0000-4000-8000-00000000000c")] })),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &app,
        "POST",
        "/keys/prekeys",
        Some(json!({ "one_time_prekeys": [prekey("11111111-0000-4000-8000-00000000000c")] })),
        Some("token-a"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "prekey_id_taken");
}

#[tokio::test]
async fn bundle_fetch_is_rate_limited_per_caller() {
    let app = test_app();
    // 30 Abrufe je Abrufer und Minute gehen durch (auch mit leeren
    // Pools ist das ein 200), der 31. bekommt 429: der Abruf konsumiert
    // fremden Vorrat und darf nicht zum Leersaugen taugen.
    for i in 0..30 {
        let (status, _) = send(&app, "GET", "/keys/alice", None, Some("token-a")).await;
        assert_eq!(status, StatusCode::OK, "Abruf {i}");
    }
    let (status, body) = send(&app, "GET", "/keys/alice", None, Some("token-a")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let app = test_app();
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send(&app, "GET", uri, None, None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
}
