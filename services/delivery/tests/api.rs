//! Integrationstests der HTTP- und WebSocket-Schicht der Zustellung.
//!
//! identity ersetzt ein Fake-Gateway (die Tests bestimmen Tokens und
//! Gerätemengen selbst); die Ablage ist die In-Memory-Umsetzung. Der
//! WebSocket-Test fährt einen echten TCP-Listener hoch, weil sich der
//! Upgrade-Handshake nicht sinnvoll über tower::oneshot treiben lässt.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::identity_client::{AccountDevices, CallerIdentity, DeviceInfo, IdentityGateway};
use delivery::api::{app, AppState};
use delivery::store::InMemoryMessageStore;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const DEV_BOB: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV_BOB_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DEV_ALICE: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const ACC_BOB: &str = "00000000-0000-4000-8000-0000000000b0";
const ACC_ALICE: &str = "00000000-0000-4000-8000-0000000000a1";

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

fn device(id: &str) -> DeviceInfo {
    DeviceInfo {
        id: id.to_string(),
        public_key: "a2V5".to_string(),
        not_after: 4102444800,
    }
}

/// alice (1 Gerät, Token "token-alice") schickt an bob (2 Geräte,
/// Token "token-bob" gehört Gerät 1).
fn fake_identity() -> FakeIdentity {
    let mut fake = FakeIdentity::default();
    fake.tokens.insert(
        "token-alice".to_string(),
        CallerIdentity {
            handle: "alice".to_string(),
            device_id: DEV_ALICE.to_string(),
        },
    );
    fake.tokens.insert(
        "token-bob".to_string(),
        CallerIdentity {
            handle: "bob".to_string(),
            device_id: DEV_BOB.to_string(),
        },
    );
    fake.accounts.insert(
        "alice".to_string(),
        AccountDevices {
            id: ACC_ALICE.to_string(),
            handle: "alice".to_string(),
            identity_key: "aWQtYQ==".to_string(),
            devices: vec![device(DEV_ALICE)],
        },
    );
    fake.accounts.insert(
        "bob".to_string(),
        AccountDevices {
            id: ACC_BOB.to_string(),
            handle: "bob".to_string(),
            identity_key: "aWQtYg==".to_string(),
            devices: vec![device(DEV_BOB), device(DEV_BOB_2)],
        },
    );
    fake
}

fn test_app() -> Router {
    app(AppState::new(
        Arc::new(InMemoryMessageStore::default()),
        Arc::new(fake_identity()),
    ))
}

/// Wie test_app, aber mit freigeschalteten /internal-Routen.
fn test_app_internal() -> Router {
    app(AppState::new(
        Arc::new(InMemoryMessageStore::default()),
        Arc::new(fake_identity()),
    )
    .with_internal_token("dienst-geheim"))
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

/// Wie send, aber mit x-internal-token statt Bearer (Dienst-zu-Dienst).
async fn send_internal(
    app: &Router,
    method: &str,
    uri: &str,
    body: Value,
    secret: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(secret) = secret {
        builder = builder.header("x-internal-token", secret);
    }
    let request = builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
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

fn envelope(id: &str, recipient: &str, device_id: &str) -> Value {
    json!({
        "id": id,
        "recipient": recipient,
        "device_id": device_id,
        "envelope": "Y2hpZmZyZQ==",
    })
}

const ENV_1: &str = "11111111-0000-4000-8000-000000000001";
const ENV_2: &str = "11111111-0000-4000-8000-000000000002";
const ENV_3: &str = "11111111-0000-4000-8000-000000000003";

#[tokio::test]
async fn submit_fetch_ack_roundtrip() {
    let app = test_app();

    // Fächer an beide bob-Geräte in einem Stapel.
    let batch = json!({ "envelopes": [
        envelope(ENV_1, "bob", DEV_BOB),
        envelope(ENV_2, "bob", DEV_BOB_2),
    ]});
    let (status, body) = send(
        &app,
        "POST",
        "/messages",
        Some(batch.clone()),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["duplicates"], 0);

    // Retry desselben Stapels ist idempotent.
    let (status, body) = send(&app, "POST", "/messages", Some(batch), Some("token-alice")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 0);
    assert_eq!(body["duplicates"], 2);

    // bob holt ab: nur die Hülle des eigenen Geräts, Abholen räumt nicht weg.
    let (status, body) = send(&app, "GET", "/messages", None, Some("token-bob")).await;
    assert_eq!(status, StatusCode::OK);
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["id"], ENV_1);
    assert_eq!(messages[0]["envelope"], "Y2hpZmZyZQ==");
    assert!(messages[0]["received_at"].as_u64().unwrap() > 0);
    let (_, body) = send(&app, "GET", "/messages", None, Some("token-bob")).await;
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);

    // Ack räumt weg und ist idempotent.
    let ack = json!({ "ids": [ENV_1] });
    let (status, body) = send(
        &app,
        "POST",
        "/messages/ack",
        Some(ack.clone()),
        Some("token-bob"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], 1);
    let (_, body) = send(&app, "GET", "/messages", None, Some("token-bob")).await;
    assert!(body["messages"].as_array().unwrap().is_empty());
    let (_, body) = send(&app, "POST", "/messages/ack", Some(ack), Some("token-bob")).await;
    assert_eq!(body["removed"], 0);

    // Auch nach dem Ack bleibt der Retry ein Duplikat (kein Doppel-Empfang).
    let (_, body) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_1, "bob", DEV_BOB)] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(body["duplicates"], 1);
}

#[tokio::test]
async fn rejects_bad_requests() {
    let app = test_app();
    let valid = json!({ "envelopes": [envelope(ENV_3, "bob", DEV_BOB)] });

    // Ohne Token gibt es nichts; identity-Ausfall ist 500, nie 401.
    for (method, uri, body) in [
        ("POST", "/messages", Some(valid.clone())),
        ("GET", "/messages", None),
        ("POST", "/messages/ack", Some(json!({ "ids": [ENV_3] }))),
    ] {
        let (status, _) = send(&app, method, uri, body.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        let (status, _) = send(&app, method, uri, body, Some("kaputt")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{method} {uri}");
    }

    // Unbekannter Empfänger und fremdes/unbekanntes Gerät.
    let (status, body) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_3, "nobody", DEV_BOB)] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "unknown_recipient");
    let (status, body) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_3, "bob", DEV_ALICE)] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "unknown_device");

    // Formfehler: leerer Stapel, kaputte ID, kaputtes Base64.
    let (status, body) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "empty_batch");
    for broken in [
        json!({ "envelopes": [{ "id": "keine-uuid", "recipient": "bob", "device_id": DEV_BOB, "envelope": "Y2hpZmZyZQ==" }] }),
        json!({ "envelopes": [{ "id": ENV_3, "recipient": "bob", "device_id": DEV_BOB, "envelope": "kein base64!" }] }),
        json!({ "envelopes": [{ "id": ENV_3, "recipient": "bob", "device_id": DEV_BOB, "envelope": "" }] }),
    ] {
        let (status, body) =
            send(&app, "POST", "/messages", Some(broken), Some("token-alice")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_envelope");
    }

    // Ack-Grenzen.
    let (status, body) = send(
        &app,
        "POST",
        "/messages/ack",
        Some(json!({ "ids": [] })),
        Some("token-bob"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_ack");
    let (status, _) = send(
        &app,
        "POST",
        "/messages/ack",
        Some(json!({ "ids": ["keine-uuid"] })),
        Some("token-bob"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Ein Gerät kann nur die eigene Inbox bestätigen: bobs Ack auf eine
    // fremde Hülle entfernt nichts.
    let (_, body) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_3, "alice", DEV_ALICE)] })),
        Some("token-bob"),
    )
    .await;
    assert_eq!(body["accepted"], 1);
    let (_, body) = send(
        &app,
        "POST",
        "/messages/ack",
        Some(json!({ "ids": [ENV_3] })),
        Some("token-bob"),
    )
    .await;
    assert_eq!(body["removed"], 0);
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let app = test_app();
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send(&app, "GET", uri, None, None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
}

/// Fährt die App auf einem echten Port hoch und liefert die Basis-Adresse.
async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn websocket_hints_after_auth() {
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let app = test_app();
    let addr = serve(app.clone()).await;

    // Verbinden und mit dem ersten Frame authentifizieren.
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("WS-Handshake");
    socket
        .send(WsMessage::Text(r#"{"token":"token-bob"}"#.into()))
        .await
        .unwrap();

    // Nachricht an bobs Gerät über die HTTP-Seite derselben App einliefern.
    let (status, _) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_1, "bob", DEV_BOB)] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Der Hinweis kommt, trägt aber weder Inhalt noch Absender.
    let hint = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("Hinweis vor Ablauf der Frist")
        .expect("Verbindung offen")
        .expect("Frame lesbar");
    assert_eq!(
        hint.into_text().unwrap().as_str(),
        r#"{"event":"message.waiting"}"#
    );

    // Eine Nachricht an ein anderes Gerät erzeugt hier keinen Hinweis.
    send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_2, "bob", DEV_BOB_2)] })),
        Some("token-alice"),
    )
    .await;
    let quiet = tokio::time::timeout(std::time::Duration::from_millis(300), socket.next()).await;
    assert!(quiet.is_err(), "kein Hinweis für fremde Geräte");
}

#[tokio::test]
async fn websocket_rejects_bad_auth_and_hints_on_backlog() {
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let app = test_app();
    let addr = serve(app.clone()).await;

    // Ungültiges Token: Close mit App-Code 4401.
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap();
    socket
        .send(WsMessage::Text(r#"{"token":"falsch"}"#.into()))
        .await
        .unwrap();
    let close = socket.next().await.unwrap().unwrap();
    match close {
        WsMessage::Close(Some(frame)) => assert_eq!(u16::from(frame.code), 4401),
        other => panic!("Close-Frame erwartet, kam {other:?}"),
    }

    // Wartet schon etwas beim Verbinden, kommt der Hinweis sofort.
    let (status, _) = send(
        &app,
        "POST",
        "/messages",
        Some(json!({ "envelopes": [envelope(ENV_3, "bob", DEV_BOB)] })),
        Some("token-alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap();
    socket
        .send(WsMessage::Text(r#"{"token":"token-bob"}"#.into()))
        .await
        .unwrap();
    let hint = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("Backlog-Hinweis")
        .unwrap()
        .unwrap();
    assert_eq!(
        hint.into_text().unwrap().as_str(),
        r#"{"event":"message.waiting"}"#
    );
}

/// Fragt die Präsenz so lange ab, bis die Erwartung eintritt; die WS-
/// Registrierung läuft asynchron zur HTTP-Seite.
async fn wait_for_presence(app: &Router, device: &str, expect_online: bool) {
    for _ in 0..50 {
        let (status, body) = send_internal(
            app,
            "POST",
            "/internal/presence/query",
            json!({ "device_ids": [device] }),
            Some("dienst-geheim"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let online = body["online"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == device);
        if online == expect_online {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("Präsenz von {device} wurde nicht {expect_online}");
}

#[tokio::test]
async fn internal_routes_deliver_events_and_track_presence() {
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    // Ohne konfiguriertes Secret existieren die Routen nicht.
    let plain = test_app();
    let (status, _) = send_internal(
        &plain,
        "POST",
        "/internal/events",
        json!({ "device_ids": [DEV_BOB], "event": { "event": "x" } }),
        Some("egal"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let app = test_app_internal();

    // Falsches oder fehlendes Secret: 401.
    for secret in [None, Some("falsch")] {
        let (status, body) = send_internal(
            &app,
            "POST",
            "/internal/events",
            json!({ "device_ids": [DEV_BOB], "event": { "event": "x" } }),
            secret,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_internal_token");
    }

    // Formfehler: leere Geräteliste, Event ohne event-Feld.
    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/events",
        json!({ "device_ids": [], "event": { "event": "x" } }),
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_event");
    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/events",
        json!({ "device_ids": [DEV_BOB], "event": { "titel": "ohne marke" } }),
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_event");

    // Niemand verbunden: Präsenz leer, Event verpufft (connected 0).
    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/presence/query",
        json!({ "device_ids": [DEV_BOB, DEV_BOB_2] }),
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["online"].as_array().unwrap().is_empty());

    // bob verbindet sich: Präsenz kippt, Events erreichen den Socket.
    let addr = serve(app.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .unwrap();
    socket
        .send(WsMessage::Text(r#"{"token":"token-bob"}"#.into()))
        .await
        .unwrap();
    wait_for_presence(&app, DEV_BOB, true).await;

    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/events",
        json!({
            "device_ids": [DEV_BOB, DEV_BOB_2],
            "event": { "event": "integration.notification", "tenant": "azubi-os", "title": "Bericht freigegeben" },
        }),
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["connected"], 1, "nur Gerät 1 ist verbunden");

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("Benachrichtigung vor Ablauf der Frist")
        .unwrap()
        .unwrap();
    let event: Value = serde_json::from_str(frame.into_text().unwrap().as_str()).unwrap();
    assert_eq!(event["event"], "integration.notification");
    assert_eq!(event["tenant"], "azubi-os");
    assert_eq!(event["title"], "Bericht freigegeben");

    // Trennen: die Präsenz räumt sich selbst auf (RAII-Guard).
    drop(socket);
    wait_for_presence(&app, DEV_BOB, false).await;
}
