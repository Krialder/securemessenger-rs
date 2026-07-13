//! Integrationstests der Integrations-API.
//!
//! identity und delivery ersetzen Fake-Gateways; die Mandanten-Ablage
//! ist die In-Memory-Umsetzung. Geprüft wird der volle Weg: Mandant
//! anlegen (interne Route), Token tauschen, Benachrichtigung auslösen,
//! Präsenz abfragen, dazu die Fehlerfälle (Scopes, Rate-Limit,
//! Mandanten-Grenzen).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::identity_client::{AccountDevices, CallerIdentity, DeviceInfo, IdentityGateway};
use http_body_util::BodyExt;
use integrations::api::{app, AppState};
use integrations::realtime_client::RealtimeGateway;
use integrations::store::InMemoryTenantStore;
use integrations::webhook::{Delivery, WebhookSender};
use serde_json::{json, Value};
use tower::ServiceExt;

const DEV_KAI: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV_KAI_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

struct FakeIdentity {
    accounts: HashMap<String, AccountDevices>,
}

#[async_trait]
impl IdentityGateway for FakeIdentity {
    async fn introspect(&self, _token: &str) -> Result<Option<CallerIdentity>, String> {
        // Die Integrations-API authentifiziert Mandanten, keine Nutzer;
        // introspect bleibt ungenutzt.
        Ok(None)
    }

    async fn account_devices(&self, handle: &str) -> Result<Option<AccountDevices>, String> {
        if handle == "kaputt" {
            return Err("identity nicht erreichbar".to_string());
        }
        Ok(self.accounts.get(handle).cloned())
    }
}

/// Fake-delivery: merkt sich gepushte Events und beantwortet Präsenz
/// aus einer konfigurierten Menge verbundener Geräte.
#[derive(Default)]
struct FakeRealtime {
    online: Mutex<Vec<String>>,
    pushed: Mutex<Vec<(Vec<String>, Value)>>,
}

#[async_trait]
impl RealtimeGateway for FakeRealtime {
    async fn push_event(
        &self,
        device_ids: &[String],
        event: serde_json::Value,
    ) -> Result<u32, String> {
        let online = self.online.lock().unwrap();
        let connected = device_ids.iter().filter(|d| online.contains(d)).count() as u32;
        drop(online);
        self.pushed
            .lock()
            .unwrap()
            .push((device_ids.to_vec(), event));
        Ok(connected)
    }

    async fn query_presence(&self, device_ids: &[String]) -> Result<Vec<String>, String> {
        let online = self.online.lock().unwrap();
        Ok(device_ids
            .iter()
            .filter(|d| online.contains(d))
            .cloned()
            .collect())
    }
}

/// Fake-Zustellung: merkt sich jede signierte Webhook-Lieferung, statt sie
/// per HTTP zu schicken.
#[derive(Default)]
struct FakeWebhookSender {
    sent: Mutex<Vec<Delivery>>,
}

#[async_trait]
impl WebhookSender for FakeWebhookSender {
    async fn deliver(&self, delivery: Delivery) -> Result<(), String> {
        self.sent.lock().unwrap().push(delivery);
        Ok(())
    }
}

fn fake_identity() -> FakeIdentity {
    let mut accounts = HashMap::new();
    accounts.insert(
        "kai".to_string(),
        AccountDevices {
            id: "00000000-0000-4000-8000-0000000000aa".to_string(),
            handle: "kai".to_string(),
            identity_key: "aWQ=".to_string(),
            devices: vec![
                DeviceInfo {
                    id: DEV_KAI.to_string(),
                    public_key: "a2V5".to_string(),
                    not_after: 4102444800,
                },
                DeviceInfo {
                    id: DEV_KAI_2.to_string(),
                    public_key: "a2V5".to_string(),
                    not_after: 4102444800,
                },
            ],
        },
    );
    FakeIdentity { accounts }
}

fn test_app() -> (Router, Arc<FakeRealtime>) {
    let realtime = Arc::new(FakeRealtime::default());
    let state = AppState::new(
        Arc::new(InMemoryTenantStore::default()),
        Arc::new(fake_identity()),
        realtime.clone(),
    )
    .with_internal_token("dienst-geheim");
    (app(state), realtime)
}

/// Wie test_app, aber mit einem Fake-Webhook-Sender, den der Test einsieht.
fn test_app_with_webhooks() -> (Router, Arc<FakeWebhookSender>) {
    let sender = Arc::new(FakeWebhookSender::default());
    let state = AppState::new(
        Arc::new(InMemoryTenantStore::default()),
        Arc::new(fake_identity()),
        Arc::new(FakeRealtime::default()),
    )
    .with_internal_token("dienst-geheim")
    .with_webhook_sender(sender.clone());
    (app(state), sender)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
    internal_secret: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(secret) = internal_secret {
        builder = builder.header("x-internal-token", secret);
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

/// Fragt am OAuth2-Token-Endpunkt ein Token ab: form-kodiert (RFC 6749).
/// `params` sind die Body-Felder; `basic` schaltet die Client-Zugangsdaten
/// stattdessen auf den HTTP-Basic-Header um (client_secret_basic). Die Werte
/// (Mandantenname, Hex-Secret) sind URL-sicher, daher reicht schlichtes
/// Zusammensetzen.
async fn send_token(
    app: &Router,
    params: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (StatusCode, Value) {
    let form = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method("POST")
        .uri("/integrations/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some((id, secret)) = basic {
        use base64::Engine as _;
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        builder = builder.header(header::AUTHORIZATION, format!("Basic {cred}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(form)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Legt einen Mandanten an und tauscht direkt ein Token; liefert
/// (client_id, client_secret, access_token).
async fn provision_tenant(app: &Router, name: &str, scopes: Value) -> (String, String, String) {
    let (status, body) = send(
        app,
        "POST",
        "/internal/tenants",
        Some(json!({ "name": name, "scopes": scopes })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let client_id = body["client_id"].as_str().unwrap().to_string();
    let client_secret = body["client_secret"].as_str().unwrap().to_string();

    let (status, body) = send_token(
        app,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    let token = body["access_token"].as_str().unwrap().to_string();
    (client_id, client_secret, token)
}

#[tokio::test]
async fn notify_and_presence_flow() {
    let (app, realtime) = test_app();
    let (_, _, token) = provision_tenant(&app, "azubi-os", json!(["notify", "presence"])).await;

    // Benachrichtigung: erreicht beide Geräte, eines ist verbunden.
    realtime.online.lock().unwrap().push(DEV_KAI.to_string());
    let (status, body) = send(
        &app,
        "POST",
        "/integrations/azubi-os/notify",
        Some(json!({ "handle": "kai", "title": "Bericht freigegeben" })),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"], 2);
    assert_eq!(body["connected"], 1);

    // Das Event ist markiert und minimal: Mandant, Titel, sonst nichts.
    {
        let pushed = realtime.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1);
        let (devices, event) = &pushed[0];
        assert_eq!(devices.len(), 2);
        assert_eq!(event["event"], "integration.notification");
        assert_eq!(event["tenant"], "azubi-os");
        assert_eq!(event["title"], "Bericht freigegeben");
        assert_eq!(event.as_object().unwrap().len(), 3, "kein weiterer Inhalt");
    }

    // Präsenz: ein verbundenes Gerät genügt für online.
    let (status, body) = send(
        &app,
        "GET",
        "/integrations/azubi-os/presence/kai",
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["online"], true);

    realtime.online.lock().unwrap().clear();
    let (_, body) = send(
        &app,
        "GET",
        "/integrations/azubi-os/presence/kai",
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body["online"], false);

    // Unbekannter Nutzer und identity-Ausfall.
    let (status, body) = send(
        &app,
        "POST",
        "/integrations/azubi-os/notify",
        Some(json!({ "handle": "niemand", "title": "x" })),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "unknown_user");
    let (status, _) = send(
        &app,
        "GET",
        "/integrations/azubi-os/presence/kaputt",
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn tenants_are_isolated_and_scoped() {
    let (app, _) = test_app();
    let (_, _, notify_only) = provision_tenant(&app, "nur-notify", json!(["notify"])).await;
    let (_, _, other) = provision_tenant(&app, "anderes-projekt", json!(["notify"])).await;

    // Fremder Mandantenpfad: 403, auch mit gültigem Token.
    let (status, body) = send(
        &app,
        "POST",
        "/integrations/nur-notify/notify",
        Some(json!({ "handle": "kai", "title": "x" })),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "tenant_mismatch");

    // Fehlender Scope: 403.
    let (status, body) = send(
        &app,
        "GET",
        "/integrations/nur-notify/presence/kai",
        None,
        Some(&notify_only),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "missing_scope");

    // Ohne oder mit unbekanntem Token: 401.
    for bearer in [None, Some("unbekannt")] {
        let (status, _) = send(
            &app,
            "POST",
            "/integrations/nur-notify/notify",
            Some(json!({ "handle": "kai", "title": "x" })),
            bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Titel-Grenzen.
    for bad_title in ["", "   ", &"x".repeat(201)] {
        let (status, body) = send(
            &app,
            "POST",
            "/integrations/nur-notify/notify",
            Some(json!({ "handle": "kai", "title": bad_title })),
            Some(&notify_only),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_title");
    }
}

#[tokio::test]
async fn token_exchange_rejects_bad_credentials() {
    let (app, _) = test_app();
    let (client_id, client_secret, _) =
        provision_tenant(&app, "projekt-x", json!(["notify"])).await;

    // Falsches Secret und unbekannte Client-ID: identische 401-Antwort im
    // OAuth2-Fehlerschema ({error, error_description}).
    for (id, secret) in [
        (client_id.as_str(), "falsches-secret"),
        ("unbekannt", client_secret.as_str()),
    ] {
        let (status, body) = send_token(
            &app,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", id),
                ("client_secret", secret),
            ],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }
}

#[tokio::test]
async fn token_accepts_http_basic_and_rejects_wrong_grant() {
    let (app, _) = test_app();
    let (client_id, client_secret, _) =
        provision_tenant(&app, "basic-projekt", json!(["notify", "presence"])).await;

    // HTTP-Basic statt Body-Parameter (client_secret_basic): muss klappen,
    // damit jede OAuth2-Bibliothek in ihrer Standard-Konfiguration anbindet.
    let (status, body) = send_token(
        &app,
        &[("grant_type", "client_credentials")],
        Some((&client_id, &client_secret)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    // Die gewaehrten Scopes stehen in der Antwort (RFC 6749).
    let granted = body["scope"].as_str().unwrap();
    assert!(granted.contains("notify") && granted.contains("presence"));

    // Falscher grant_type: unsupported_grant_type (400).
    let (status, body) = send_token(
        &app,
        &[
            ("grant_type", "password"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");

    // Angefragter Scope ausserhalb der Mandanten-Rechte: invalid_scope (400).
    let (status, body) = send_token(
        &app,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "notify webhook"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn narrow_scope_token_cannot_exceed_its_grant() {
    // Least Privilege je Token: der Mandant darf notify UND presence, stellt
    // aber ein Token nur fuer notify aus. Dieses Token darf dann keine
    // Praesenz abfragen, obwohl der Mandant das Recht haette.
    let (app, _) = test_app();
    let (client_id, client_secret, _) =
        provision_tenant(&app, "eng", json!(["notify", "presence"])).await;

    let (status, body) = send_token(
        &app,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "notify"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Die Antwort spiegelt genau den verengten Scope, nicht die vollen Rechte.
    assert_eq!(body["scope"], "notify");
    let narrow = body["access_token"].as_str().unwrap().to_string();

    // notify: erlaubt.
    let (status, _) = send(
        &app,
        "POST",
        "/integrations/eng/notify",
        Some(json!({ "handle": "kai", "title": "geht" })),
        Some(&narrow),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // presence: 403, obwohl der Mandant das Recht hat, das Token aber nicht.
    let (status, body) = send(
        &app,
        "GET",
        "/integrations/eng/presence/kai",
        None,
        Some(&narrow),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "missing_scope");
}

#[tokio::test]
async fn rate_limit_returns_429_with_retry_after() {
    let (app, _) = test_app();
    let (status, body) = send(
        &app,
        "POST",
        "/internal/tenants",
        Some(json!({ "name": "knapp", "scopes": ["presence"], "rate_limit": 2 })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let client_id = body["client_id"].as_str().unwrap().to_string();
    let client_secret = body["client_secret"].as_str().unwrap().to_string();
    let (status, body) = send_token(
        &app,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();

    // Zwei Anfragen passen ins Fenster, die dritte nicht.
    for _ in 0..2 {
        let (status, _) = send(
            &app,
            "GET",
            "/integrations/knapp/presence/kai",
            None,
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let request = Request::builder()
        .method("GET")
        .uri("/integrations/knapp/presence/kai")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("Retry-After gesetzt");
    assert!((1..=60).contains(&retry_after));
}

#[tokio::test]
async fn tenant_creation_is_guarded_and_validated() {
    let (app, _) = test_app();

    // Falsches oder fehlendes internes Secret: 401.
    for secret in [None, Some("falsch")] {
        let (status, _) = send(
            &app,
            "POST",
            "/internal/tenants",
            Some(json!({ "name": "wer-auch-immer", "scopes": ["notify"] })),
            None,
            secret,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Ohne konfiguriertes Secret existiert die Route nicht.
    let bare = integrations::api::app(AppState::new(
        Arc::new(InMemoryTenantStore::default()),
        Arc::new(fake_identity()),
        Arc::new(FakeRealtime::default()),
    ));
    let (status, _) = send(
        &bare,
        "POST",
        "/internal/tenants",
        Some(json!({ "name": "egal", "scopes": ["notify"] })),
        None,
        Some("egal"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Validierung: Name, Scopes, Rate-Limit, Dubletten.
    for (body, code) in [
        (
            json!({ "name": "AB", "scopes": ["notify"] }),
            "invalid_name",
        ),
        (
            json!({ "name": "-falsch", "scopes": ["notify"] }),
            "invalid_name",
        ),
        (json!({ "name": "projekt", "scopes": [] }), "invalid_scopes"),
        (
            json!({ "name": "projekt", "scopes": ["admin"] }),
            "invalid_scopes",
        ),
        (
            json!({ "name": "projekt", "scopes": ["notify"], "rate_limit": 0 }),
            "invalid_rate_limit",
        ),
    ] {
        let (status, response) = send(
            &app,
            "POST",
            "/internal/tenants",
            Some(body),
            None,
            Some("dienst-geheim"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["code"], code);
    }

    let (status, _) = send(
        &app,
        "POST",
        "/internal/tenants",
        Some(json!({ "name": "doppelt", "scopes": ["notify"] })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(
        &app,
        "POST",
        "/internal/tenants",
        Some(json!({ "name": "doppelt", "scopes": ["notify"] })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "name_taken");
}

#[tokio::test]
async fn webhook_registration_and_presence_fanout() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::{Verifier, VerifyingKey};

    let (app, sender) = test_app_with_webhooks();
    let (_, _, token) = provision_tenant(&app, "azubi-os", json!(["notify", "presence"])).await;

    // Der oeffentliche Schluessel ist ohne Auth abrufbar.
    let (status, key) = send(&app, "GET", "/integrations/webhook-key", None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(key["alg"], "Ed25519");
    let pubkey = key["public_key"].as_str().unwrap().to_string();

    // Endpunkt fuer den Handle "kai" registrieren.
    let (status, wh) = send(
        &app,
        "POST",
        "/integrations/azubi-os/webhooks",
        Some(json!({
            "url": "https://azubios.example/hook",
            "events": ["presence.changed"],
            "handles": ["kai"]
        })),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{wh}");
    let wh_id = wh["id"].as_str().unwrap().to_string();

    // Die Liste zeigt genau ihn.
    let (status, list) = send(
        &app,
        "GET",
        "/integrations/azubi-os/webhooks",
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Praesenz-Ereignis fuer kai (mit Uebergangs-Nummer) -> eine Zustellung.
    let (status, res) = send(
        &app,
        "POST",
        "/internal/presence-event",
        Some(json!({ "handle": "kai", "online": true, "seq": 7 })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{res}");
    assert_eq!(res["matched"], 1);
    assert_eq!(res["delivered"], 1);

    {
        let deliveries = sender.sent.lock().unwrap();
        assert_eq!(deliveries.len(), 1);
        let d = &deliveries[0];
        assert_eq!(d.url, "https://azubios.example/hook");
        assert_eq!(d.event, "presence.changed");
        let env: Value = serde_json::from_slice(&d.body).unwrap();
        assert_eq!(env["type"], "presence.changed");
        assert_eq!(env["tenant"], "azubi-os");
        assert_eq!(env["data"]["handle"], "kai");
        assert_eq!(env["data"]["online"], true);
        // Die Uebergangs-Nummer reist mit (der Empfaenger ordnet danach).
        assert_eq!(env["data"]["seq"], 7);

        // Die Signatur prueft mit dem veroeffentlichten Schluessel ueber
        // die kanonische Nachricht {timestamp}.{body}.
        let pub_bytes: [u8; 32] = B64.decode(&pubkey).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let sig_bytes: [u8; 64] = B64.decode(&d.signature).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let mut msg = format!("{}.", d.timestamp).into_bytes();
        msg.extend_from_slice(&d.body);
        assert!(vk.verify(&msg, &sig).is_ok(), "Signatur muss pruefen");
    }

    // Ein nicht abonnierter Handle: keine Zustellung (Abo je Handle).
    let (_, res) = send(
        &app,
        "POST",
        "/internal/presence-event",
        Some(json!({ "handle": "niemand", "online": true })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(res["matched"], 0);
    assert_eq!(sender.sent.lock().unwrap().len(), 1);

    // Loeschen -> 204, danach kein Treffer mehr.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/integrations/azubi-os/webhooks/{wh_id}"),
        None,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, res) = send(
        &app,
        "POST",
        "/internal/presence-event",
        Some(json!({ "handle": "kai", "online": false })),
        None,
        Some("dienst-geheim"),
    )
    .await;
    assert_eq!(res["matched"], 0);
}

#[tokio::test]
async fn webhook_allows_local_target_only_with_flag() {
    // Mit gesetzter Freigabe (lokaler Lauf) ist ein Loopback-Ziel erlaubt,
    // das die Vorgabe (SSRF-Schutz) sonst abweist.
    let sender = Arc::new(FakeWebhookSender::default());
    let state = AppState::new(
        Arc::new(InMemoryTenantStore::default()),
        Arc::new(fake_identity()),
        Arc::new(FakeRealtime::default()),
    )
    .with_internal_token("dienst-geheim")
    .with_webhook_sender(sender)
    .allow_private_webhooks(true);
    let app = app(state);
    let (_, _, token) = provision_tenant(&app, "lokal", json!(["presence"])).await;

    let (status, body) = send(
        &app,
        "POST",
        "/integrations/lokal/webhooks",
        Some(json!({ "url": "http://127.0.0.1:9099/hook", "events": ["presence.changed"], "handles": ["kai"] })),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn webhook_requires_scope_and_isolates_tenants() {
    let (app, _sender) = test_app_with_webhooks();
    let (_, _, notify_only) = provision_tenant(&app, "nur-notify", json!(["notify"])).await;
    let (_, _, other) = provision_tenant(&app, "anderes", json!(["notify", "presence"])).await;

    // presence.changed ohne presence-Scope: 403 missing_scope.
    let (status, body) = send(
        &app,
        "POST",
        "/integrations/nur-notify/webhooks",
        Some(json!({ "url": "https://x/h", "events": ["presence.changed"], "handles": ["kai"] })),
        Some(&notify_only),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "missing_scope");

    // Fremder Mandantenpfad: 403 tenant_mismatch.
    let (status, body) = send(
        &app,
        "POST",
        "/integrations/nur-notify/webhooks",
        Some(json!({ "url": "https://x/h", "events": ["presence.changed"], "handles": ["kai"] })),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "tenant_mismatch");

    // Validierung: URL, Ereignis, Handles, SSRF-Ziel.
    for (payload, code) in [
        (
            json!({ "url": "ftp://x", "events": ["presence.changed"], "handles": ["kai"] }),
            "invalid_url",
        ),
        // SSRF: interne/Loopback-Ziele sind ohne Freigabe verboten.
        (
            json!({ "url": "http://127.0.0.1:9000/x", "events": ["presence.changed"], "handles": ["kai"] }),
            "invalid_url",
        ),
        (
            json!({ "url": "http://169.254.169.254/latest/meta-data", "events": ["presence.changed"], "handles": ["kai"] }),
            "invalid_url",
        ),
        (
            json!({ "url": "http://localhost/x", "events": ["presence.changed"], "handles": ["kai"] }),
            "invalid_url",
        ),
        (
            json!({ "url": "https://x/h", "events": ["unbekannt"], "handles": ["kai"] }),
            "invalid_events",
        ),
        (
            json!({ "url": "https://x/h", "events": ["presence.changed"], "handles": [] }),
            "invalid_handles",
        ),
    ] {
        let (status, body) = send(
            &app,
            "POST",
            "/integrations/anderes/webhooks",
            Some(payload),
            Some(&other),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], code);
    }

    // Unbekannten Endpunkt loeschen: 404.
    let (status, body) = send(
        &app,
        "DELETE",
        "/integrations/anderes/webhooks/gibt-es-nicht",
        None,
        Some(&other),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "unknown_webhook");
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let (app, _) = test_app();
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send(&app, "GET", uri, None, None, None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
}
