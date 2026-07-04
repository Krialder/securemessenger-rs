//! Integrationstests der HTTP-Schicht über tower::oneshot, ohne echten Socket.
//!
//! Die Client-Seite (Schlüssel, Credentials, Requests) liegt in
//! tests/helpers/mod.rs und wird vom PG-Test mitbenutzt.

mod helpers;

use axum::http::StatusCode;
use axum::Router;
use helpers::{key, login_body, register_body, send, signed_device};
use identity::api::{app, AppState};
use serde_json::json;

// Geräte-IDs sind client-erzeugte UUIDs (kanonische Form); Tests nehmen
// feste Werte statt Zufall, damit Fehlermeldungen reproduzierbar bleiben.
const DEV_LAPTOP: &str = "11111111-1111-4111-8111-111111111111";
const DEV_HANDY: &str = "22222222-2222-4222-8222-222222222222";
const DEV_FIRST: &str = "33333333-3333-4333-8333-333333333333";
const DEV_SECOND: &str = "44444444-4444-4444-8444-444444444444";
const DEV_MISC: &str = "55555555-5555-4555-8555-555555555555";
const DEV_UNKNOWN: &str = "99999999-9999-4999-8999-999999999999";

fn test_app() -> Router {
    app(AppState::new_in_memory())
}

/// Fängt KT-Meldungen ab, um den Meldepfad zu prüfen.
#[derive(Default)]
struct FakeKt {
    updates: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl identity::kt_notify::KtNotifier for FakeKt {
    async fn key_set_changed(&self, handle: &str, commitment: &[u8]) {
        self.updates
            .lock()
            .unwrap()
            .push((handle.to_string(), commitment.to_vec()));
    }
}

#[tokio::test]
async fn key_changes_are_reported_to_kt() {
    let fake = std::sync::Arc::new(FakeKt::default());
    let app = app(AppState::new_in_memory().with_kt_notifier(fake.clone()));
    let identity = key(8);

    // Die Meldung läuft fire-and-forget im Hintergrund; bis zur
    // erwarteten Anzahl pollen statt schlafen.
    async fn wait_for(fake: &FakeKt, count: usize) -> Vec<(String, Vec<u8>)> {
        for _ in 0..100 {
            {
                let updates = fake.updates.lock().unwrap();
                if updates.len() >= count {
                    return updates.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("KT-Meldung {count} kam nicht");
    }

    // Registrierung meldet das erste Commitment.
    let register = register_body(&identity, "karla", "korrektes-pferd-batterie", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let updates = wait_for(&fake, 1).await;
    assert_eq!(updates[0].0, "karla");
    assert_eq!(updates[0].1.len(), 32, "SHA-256-Commitment");

    // Gerät dazu: neue Meldung mit anderem Commitment.
    let login = login_body("karla", "korrektes-pferd-batterie", DEV_FIRST);
    let (_, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    let access = body["access_token"].as_str().unwrap().to_string();
    let device = signed_device(&identity, "karla", DEV_SECOND, 43);
    let (status, _) = send(&app, "POST", "/devices", Some(device), Some(&access)).await;
    assert_eq!(status, StatusCode::CREATED);
    let updates = wait_for(&fake, 2).await;
    assert_ne!(
        updates[0].1, updates[1].1,
        "Gerät dazu muss das Commitment ändern"
    );

    // Revocation: dritte Meldung, Commitment wieder wie am Anfang
    // (gleiche gültige Gerätemenge wie nach der Registrierung).
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/devices/{DEV_SECOND}"),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let updates = wait_for(&fake, 3).await;
    assert_eq!(
        updates[0].1, updates[2].1,
        "nach der Revocation gilt wieder die alte Gerätemenge"
    );
}

#[tokio::test]
async fn hot_paths_are_rate_limited() {
    let app = test_app();
    let identity = key(9);

    // Login: 10 Versuche je Handle und Minute, der elfte bekommt 429 mit
    // Retry-After. Ein anderes Handle hat sein eigenes Fenster.
    for _ in 0..10 {
        let login = login_body("gustav", "egal-hier", DEV_MISC);
        let (status, _) = send(&app, "POST", "/sessions", Some(login), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let login = login_body("gustav", "egal-hier", DEV_MISC);
    let (status, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
    let login = login_body("anderes-handle", "egal-hier", DEV_MISC);
    let (status, _) = send(&app, "POST", "/sessions", Some(login), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "eigenes Fenster je Handle"
    );

    // Registrierung: 5 Versuche je Handle und Minute. Der sechste ist
    // 429, obwohl das Handle längst vergeben ist - das Limit greift vor
    // der Fachlogik.
    let register = register_body(&identity, "hanna", "korrektes-pferd-batterie", DEV_MISC);
    for i in 0..5 {
        let expected = if i == 0 {
            StatusCode::CREATED
        } else {
            StatusCode::CONFLICT
        };
        let (status, _) = send(&app, "POST", "/accounts", Some(register.clone()), None).await;
        assert_eq!(status, expected, "Registrierung {i}");
    }
    let (status, body) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn registration_requires_proof_of_work_when_configured() {
    // Kleine Schwierigkeit, damit der Test schnell bleibt.
    let app = app(AppState::new_in_memory().with_pow_difficulty(12));
    let identity = key(17);

    // Ohne nonce: abgewiesen mit pow_required.
    let register = register_body(&identity, "poworka", "korrektes-pferd-batterie", DEV_FIRST);
    let (status, body) = send(&app, "POST", "/accounts", Some(register.clone()), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "pow_required");

    // GET /pow nennt die Schwierigkeit.
    let (status, info) = send(&app, "GET", "/pow", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["difficulty"], 12);

    // Mit gültigem nonce: angenommen.
    let nonce = pow::solve("poworka", 12).expect("nonce");
    let mut with_pow = register;
    with_pow["pow_nonce"] = json!(nonce);
    let (status, _) = send(&app, "POST", "/accounts", Some(with_pow), None).await;
    assert_eq!(status, StatusCode::CREATED);

    // Ein falscher nonce fällt durch.
    let identity2 = key(18);
    let mut bad = register_body(
        &identity2,
        "poworkb",
        "korrektes-pferd-batterie",
        DEV_SECOND,
    );
    bad["pow_nonce"] = json!(1u64);
    let (status, body) = send(&app, "POST", "/accounts", Some(bad), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "pow_required");
}

/// Sealed-Sender-Ausgabe: der Trust Root ist öffentlich, das Zertifikat
/// gibt es nur mit gültiger Session, und es hängt an genau diesem Trust
/// Root, mit dem registrierten Geräteschlüssel darin.
#[tokio::test]
async fn sender_certificates_are_issued_and_chain_to_trust_root() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    let issuer = std::sync::Arc::new(sealed_cert::Issuer::from_seed(&[9u8; 32]).unwrap());
    let app = app(AppState::new_in_memory().with_sealed_sender(issuer));

    // Der Anker ist ohne Token abrufbar (er ist öffentlich).
    let (status, info) = send(&app, "GET", "/sealed-sender", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let trust_root = info["trust_root"].as_str().unwrap().to_string();

    // Ohne Session kein Zertifikat.
    let (status, _) = send(&app, "GET", "/sender-certificate", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Registrieren mit einem echten libsignal-Identitätsschlüssel als
    // Geräteschlüssel (wie CLI und Web es tun), dann anmelden.
    let identity = key(21);
    let device_key = BASE64.encode(
        libsignal_protocol::KeyPair::generate(&mut rand::rng())
            .public_key
            .serialize(),
    );
    let register = json!({
        "handle": "siegler",
        "password": "korrektes-pferd-batterie",
        "identity_key": helpers::b64_public(&identity),
        "device": helpers::signed_device_with_key(&identity, "siegler", DEV_FIRST, &device_key),
    });
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let login = login_body("siegler", "korrektes-pferd-batterie", DEV_FIRST);
    let (_, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    let (status, body) = send(&app, "GET", "/sender-certificate", None, Some(&access)).await;
    assert_eq!(status, StatusCode::OK, "Antwort war: {body}");

    // Kette und Inhalt: gültig gegen unseren Trust Root, Handle stimmt,
    // und im Zertifikat steht der registrierte Schlüssel, kein eingereichter.
    let cert = libsignal_protocol::SenderCertificate::deserialize(
        &BASE64
            .decode(body["certificate"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let root =
        libsignal_protocol::PublicKey::deserialize(&BASE64.decode(&trust_root).unwrap()).unwrap();
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(cert
        .validate(
            &root,
            libsignal_protocol::Timestamp::from_epoch_millis(now_millis)
        )
        .unwrap());
    assert_eq!(cert.sender_uuid().unwrap(), "siegler");
    assert_eq!(BASE64.encode(cert.key().unwrap().serialize()), device_key);
}

#[tokio::test]
async fn register_login_logout_flow() {
    let app = test_app();
    let identity = key(1);

    // Registrierung legt Konto und erstes Gerät an, Anzeigename fällt aufs
    // Handle zurück.
    let register = register_body(&identity, "alice", "korrektes-pferd-batterie", DEV_LAPTOP);
    let (status, body) = send(&app, "POST", "/accounts", Some(register.clone()), None).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["handle"], "alice");
    assert_eq!(body["display_name"], "alice");
    assert_eq!(body["device_id"], DEV_LAPTOP);

    // Doppeltes Handle wird abgelehnt.
    let (status, body) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "handle_taken");

    // Falsches Passwort, unbekanntes Handle und unbekanntes Gerät geben
    // dieselbe Antwort, damit sich nichts über das Konto abfragen lässt.
    for body_json in [
        login_body("alice", "voellig-falsches-passwort", DEV_LAPTOP),
        login_body("nobody", "voellig-falsches-passwort", DEV_LAPTOP),
        login_body("alice", "korrektes-pferd-batterie", DEV_UNKNOWN),
    ] {
        let (status, body) = send(&app, "POST", "/sessions", Some(body_json), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_credentials");
    }

    // Login liefert ein OAuth-förmiges Token-Paar.
    let login = login_body("alice", "korrektes-pferd-batterie", DEV_LAPTOP);
    let (status, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    assert_eq!(status, StatusCode::OK);
    let access = body["access_token"]
        .as_str()
        .expect("Access-Token")
        .to_string();
    let refresh = body["refresh_token"]
        .as_str()
        .expect("Refresh-Token")
        .to_string();
    assert_eq!(access.len(), 64);
    assert_eq!(refresh.len(), 64);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);

    // Logout ist idempotent und verrät nicht, ob das Token existierte.
    let (status, _) = send(&app, "DELETE", "/sessions", None, Some(&access)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "DELETE", "/sessions", None, Some(&access)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Logout widerruft die ganze Familie: auch das Refresh-Token ist tot.
    let refresh_req = json!({ "refresh_token": refresh });
    let (status, body) = send(&app, "POST", "/sessions/refresh", Some(refresh_req), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_refresh_token");
}

#[tokio::test]
async fn refresh_rotates_and_detects_reuse() {
    let app = test_app();
    let identity = key(2);
    let register = register_body(&identity, "erika", "korrektes-pferd-batterie", DEV_HANDY);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let login = login_body("erika", "korrektes-pferd-batterie", DEV_HANDY);
    let (_, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    let refresh1 = body["refresh_token"].as_str().unwrap().to_string();

    // Rotation liefert ein neues Paar.
    let (status, body) = send(
        &app,
        "POST",
        "/sessions/refresh",
        Some(json!({ "refresh_token": refresh1 })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh1, refresh2);

    // Das rotierte Token noch einmal: generisches 401 nach außen, intern
    // widerruft die Reuse-Erkennung die Familie, also stirbt auch das neue.
    let (status, _) = send(
        &app,
        "POST",
        "/sessions/refresh",
        Some(json!({ "refresh_token": refresh1 })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "POST",
        "/sessions/refresh",
        Some(json!({ "refresh_token": refresh2 })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_invalid_input() {
    let app = test_app();
    let identity = key(3);

    let (status, body) = send(
        &app,
        "POST",
        "/accounts",
        Some(register_body(&identity, "ab", "lang-genug-123", DEV_MISC)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_handle");

    let (status, body) = send(
        &app,
        "POST",
        "/accounts",
        Some(register_body(&identity, "charlie", "kurz", DEV_MISC)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_password");

    let (status, body) = send(
        &app,
        "POST",
        "/accounts",
        Some(register_body(
            &identity,
            "charlie",
            "lang-genug-123",
            "kein-uuid-geraet",
        )),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_device");

    // Credential von einem fremden Schlüssel signiert: Registrierung platzt.
    let mut forged = register_body(&identity, "charlie", "lang-genug-123", DEV_MISC);
    forged["device"] = signed_device(&key(99), "charlie", DEV_MISC, 42);
    let (status, body) = send(&app, "POST", "/accounts", Some(forged), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_credential");
}

#[tokio::test]
async fn device_management_flow() {
    let app = test_app();
    let identity = key(4);
    let register = register_body(&identity, "dora", "korrektes-pferd-batterie", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("dora", "korrektes-pferd-batterie", DEV_FIRST)),
        None,
    )
    .await;
    let access1 = body["access_token"].as_str().unwrap().to_string();

    // Ohne Token gibt es keine Geräteliste.
    let (status, _) = send(&app, "GET", "/devices", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Anfangs genau das Registrierungs-Gerät.
    let (status, body) = send(&app, "GET", "/devices", None, Some(&access1)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], DEV_FIRST);

    // Zweites Gerät freischalten: Credential clientseitig signiert, das
    // bestehende Gerät reicht es authentifiziert ein.
    let second = signed_device(&identity, "dora", DEV_SECOND, 43);
    let (status, _) = send(
        &app,
        "POST",
        "/devices",
        Some(second.clone()),
        Some(&access1),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(&app, "GET", "/devices", None, Some(&access1)).await;
    assert_eq!(body.as_array().unwrap().len(), 2);

    // Dieselbe Geräte-ID noch einmal: Konflikt.
    let (status, body) = send(&app, "POST", "/devices", Some(second), Some(&access1)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "device_id_taken");

    // Das neue Gerät kann sich anmelden.
    let (status, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("dora", "korrektes-pferd-batterie", DEV_SECOND)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let access2 = body["access_token"].as_str().unwrap().to_string();

    // Das eigene Gerät lässt sich nicht entfernen (Aussperr-Schutz).
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/devices/{DEV_FIRST}"),
        None,
        Some(&access1),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "own_device");

    // Gerät 1 entfernt Gerät 2: dessen Session stirbt sofort mit, ein neuer
    // Login mit dem revozierten Gerät scheitert generisch.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/devices/{DEV_SECOND}"),
        None,
        Some(&access1),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "GET", "/devices", None, Some(&access2)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("dora", "korrektes-pferd-batterie", DEV_SECOND)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Die revozierte ID bleibt gesperrt (Credential-Replay-Schutz), …
    let replay = signed_device(&identity, "dora", DEV_SECOND, 43);
    let (status, body) = send(&app, "POST", "/devices", Some(replay), Some(&access1)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "device_id_taken");

    // … nochmal entfernen geht nicht, Unbekanntes ist 404.
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/devices/{DEV_SECOND}"),
        None,
        Some(&access1),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "device_not_found");

    // Die Liste zeigt wieder genau ein Gerät.
    let (_, body) = send(&app, "GET", "/devices", None, Some(&access1)).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], DEV_FIRST);
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let app = test_app();
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send(&app, "GET", uri, None, None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
}

/// Wie helpers::send, aber mit x-internal-token statt Bearer: die
/// Dienst-zu-Dienst-Seite der /internal-Routen.
async fn send_internal(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    internal_token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if let Some(token) = internal_token {
        builder = builder.header("x-internal-token", token);
    }
    let request = match body {
        Some(value) => builder
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn internal_routes_for_service_to_service() {
    // Ohne konfiguriertes Secret existieren die Routen nicht (404), damit
    // ein Deployment ohne INTERNAL_TOKEN keine interne Fläche zeigt.
    let closed = test_app();
    let introspect_req = json!({ "token": "egal" });
    let (status, _) = send_internal(
        &closed,
        "POST",
        "/internal/introspect",
        Some(introspect_req),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let app = app(AppState::new_in_memory().with_internal_token("geheim"));
    let identity = key(7);
    let register = register_body(&identity, "ines", "korrektes-pferd-batterie", DEV_MISC);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("ines", "korrektes-pferd-batterie", DEV_MISC)),
        None,
    )
    .await;
    let access = body["access_token"].as_str().unwrap().to_string();

    // Falsches oder fehlendes Secret: 401.
    for wrong in [None, Some("falsch")] {
        let (status, _) = send_internal(
            &app,
            "POST",
            "/internal/introspect",
            Some(json!({ "token": access })),
            wrong,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Gültiges Token wird zur Identität aufgelöst ...
    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/introspect",
        Some(json!({ "token": access })),
        Some("geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true);
    assert_eq!(body["handle"], "ines");
    assert_eq!(body["device_id"], DEV_MISC);

    // ... ein unbekanntes ist inaktiv, ohne Felder zu verraten.
    let (status, body) = send_internal(
        &app,
        "POST",
        "/internal/introspect",
        Some(json!({ "token": "unbekannt" })),
        Some("geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], false);
    assert!(body.get("handle").is_none());

    // Gerätemenge samt Konto-Identitätsschlüssel; Unbekanntes ist 404.
    let (status, body) = send_internal(
        &app,
        "GET",
        "/internal/accounts/ines/devices",
        None,
        Some("geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["handle"], "ines");
    assert!(body["identity_key"].as_str().is_some());
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert_eq!(body["devices"][0]["id"], DEV_MISC);
    let (status, _) = send_internal(
        &app,
        "GET",
        "/internal/accounts/nobody/devices",
        None,
        Some("geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
