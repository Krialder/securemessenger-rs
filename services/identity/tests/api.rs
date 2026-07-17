//! Integrationstests der HTTP-Schicht über tower::oneshot, ohne echten Socket.
//!
//! Die Client-Seite (Schlüssel, Credentials, Requests) liegt in
//! tests/helpers/mod.rs und wird vom PG-Test mitbenutzt.

mod helpers;

use axum::http::StatusCode;
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::Signer;
use helpers::{b64_public, key, login_body, register_body, send, signed_device, FAR_FUTURE};
use identity::api::{app, AppState};
use identity::credential::{credential_message, rotation_message};
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
async fn register_takes_display_name_and_free_password_charset() {
    let app = test_app();
    let identity = key(60);

    // Das Passwort hat bewusst NUR eine Längenregel (NIST-Linie, keine
    // Kompositionsregeln): Großbuchstaben, Umlaute, Leer- und Sonderzeichen
    // gehen durch. Der Anzeigename trägt Groß-/Kleinschreibung und
    // Leerzeichen (Vor- und Nachname); nur der Handle bleibt die technische
    // Kennung (a-z, 0-9, _ . -). Dieser Test schreibt beides fest, damit
    // eine spätere Validierungs-Änderung es nicht still verengt.
    let password = "Größeres!Geheimnis 2026";
    let mut register = register_body(&identity, "kai-delor", password, DEV_LAPTOP);
    register["display_name"] = json!("Kai Delor");
    let (status, body) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED, "Antwort war: {body}");
    assert_eq!(body["display_name"], "Kai Delor");

    // Die Anmeldung mit genau diesem Passwort klappt und trägt den bei der
    // Registrierung gewählten Namen zurück (Vorbelegung der Einstellungen).
    let login = login_body("kai-delor", password, DEV_LAPTOP);
    let (status, body) = send(&app, "POST", "/sessions", Some(login), None).await;
    assert_eq!(status, StatusCode::OK, "Antwort war: {body}");
    assert_eq!(body["display_name"], "Kai Delor");
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

#[tokio::test]
async fn provision_relay_round_trips_and_404s() {
    let app = test_app();
    // 32 Hex-Zeichen = das erwartete Kanal-ID-Format (16 Byte).
    let channel = "abcdef0123456789abcdef0123456789";

    // Ablegen, dann holen: Nonce und Chiffretext kommen unverändert zurück.
    let (status, _) = send(
        &app,
        "POST",
        "/provision",
        Some(json!({ "channel": channel, "nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVy" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Zweites Ablegen auf denselben Kanal: erster gewinnt (409). Vor dem
    // GET geprüft, weil der GET den Kanal verbraucht.
    let (status, body) = send(
        &app,
        "POST",
        "/provision",
        Some(json!({ "channel": channel, "nonce": "eA==", "ciphertext": "eQ==" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "channel_taken");

    // Erster GET liefert den Antrag ...
    let (status, body) = send(&app, "GET", &format!("/provision/{channel}"), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["nonce"], "bm9uY2U=");
    assert_eq!(body["ciphertext"], "Y2lwaGVy");

    // ... ein zweiter GET nicht mehr (consume-on-read): der Kanal ist weg.
    let (status, _) = send(&app, "GET", &format!("/provision/{channel}"), None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unbekannter Kanal: 404 ohne weitere Auskunft.
    let (status, _) = send(
        &app,
        "GET",
        "/provision/00000000000000000000000000000000",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Kaputte Kanal-ID beim Ablegen: 400.
    let (status, body) = send(
        &app,
        "POST",
        "/provision",
        Some(json!({ "channel": "zu-kurz", "nonce": "eA==", "ciphertext": "eQ==" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_channel");
}

#[tokio::test]
async fn password_change_verifies_old_revokes_others_and_relogins() {
    let app = test_app();
    let identity = key(9);

    // Konto mit Erstgerät, plus ein Zweitgerät.
    let register = register_body(&identity, "pia", "altes-langes-passwort", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("pia", "altes-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    let first_access = body["access_token"].as_str().unwrap().to_string();

    let device2 = signed_device(&identity, "pia", DEV_SECOND, 20);
    let (status, _) = send(&app, "POST", "/devices", Some(device2), Some(&first_access)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("pia", "altes-langes-passwort", DEV_SECOND)),
        None,
    )
    .await;
    let second_access = body["access_token"].as_str().unwrap().to_string();

    // Falsches altes Passwort: abgelehnt, nichts geändert.
    let (status, body) = send(
        &app,
        "POST",
        "/sessions/password",
        Some(json!({ "current_password": "falsch", "new_password": "neues-langes-passwort" })),
        Some(&first_access),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_credentials");

    // Ohne Token: abgelehnt (ein Passwortwechsel braucht eine Session).
    let (status, _) = send(
        &app,
        "POST",
        "/sessions/password",
        Some(json!({ "current_password": "altes-langes-passwort", "new_password": "neues-langes-passwort" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Zu kurzes neues Passwort: 400.
    let (status, body) = send(
        &app,
        "POST",
        "/sessions/password",
        Some(json!({ "current_password": "altes-langes-passwort", "new_password": "kurz" })),
        Some(&first_access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_password");

    // Korrekt: 204.
    let (status, _) = send(
        &app,
        "POST",
        "/sessions/password",
        Some(json!({ "current_password": "altes-langes-passwort", "new_password": "neues-langes-passwort" })),
        Some(&first_access),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Das anfragende Gerät behält seine Session ...
    let (status, _) = send(&app, "GET", "/devices", None, Some(&first_access)).await;
    assert_eq!(status, StatusCode::OK);
    // ... das andere Gerät ist abgemeldet (Session widerrufen).
    let (status, _) = send(&app, "GET", "/devices", None, Some(&second_access)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Anmeldung: altes Passwort scheitert, neues klappt.
    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("pia", "altes-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("pia", "neues-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn account_deletion_schedules_reports_and_undeletes() {
    let app = test_app();
    let identity = key(13);

    let register = register_body(&identity, "quinn", "quinns-langes-passwort", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("quinn", "quinns-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    let access = body["access_token"].as_str().unwrap().to_string();
    // Ein aktives Konto trägt keine Löschfrist in der Login-Antwort.
    assert!(body.get("deletion_pending_until").is_none());

    // Falsches Passwort: abgelehnt, nichts vorgemerkt.
    let (status, body) = send(
        &app,
        "DELETE",
        "/accounts",
        Some(json!({ "password": "falsch" })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_credentials");

    // Ohne Token: abgelehnt.
    let (status, _) = send(
        &app,
        "DELETE",
        "/accounts",
        Some(json!({ "password": "quinns-langes-passwort" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Korrekt: 200 mit Frist.
    let (status, body) = send(
        &app,
        "DELETE",
        "/accounts",
        Some(json!({ "password": "quinns-langes-passwort" })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["deletion_pending_until"].as_u64().unwrap() > 0);

    // Die nächste Anmeldung meldet die laufende Löschung.
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("quinn", "quinns-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    assert!(body["deletion_pending_until"].as_u64().unwrap() > 0);

    // Widerrufen: 204, danach ist die Frist weg.
    let (status, _) = send(&app, "POST", "/accounts/undelete", None, Some(&access)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("quinn", "quinns-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    assert!(body.get("deletion_pending_until").is_none());
}

#[tokio::test]
async fn display_name_changes_and_shows_in_login() {
    let app = test_app();
    let identity = key(14);

    let register = register_body(&identity, "rita", "ritas-langes-passwort", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("rita", "ritas-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    let access = body["access_token"].as_str().unwrap().to_string();
    // Ohne eigenen Namen gilt der Handle (Registrierungs-Rückfall).
    assert_eq!(body["display_name"], "rita");

    // Ohne Token: abgelehnt.
    let (status, _) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "Rita B." })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Nur Weißraum und Überlänge: abgelehnt.
    let (status, body) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "   " })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_display_name");
    let (status, _) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "x".repeat(65) })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Nur unsichtbare Zeichen (Zero-Width-Space): sähe leer aus, abgelehnt.
    let (status, body) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "\u{200B}\u{200B}" })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_display_name");

    // Bidi-Override (RTL-Spoofing-Muster): abgelehnt.
    let (status, _) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "Alice\u{202E}gro.bank" })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // ZWJ in einer Emoji-Sequenz bleibt erlaubt (legitime Namen).
    let (status, body) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "Rita \u{1F469}\u{200D}\u{1F4BB}" })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "Rita \u{1F469}\u{200D}\u{1F4BB}");

    // Gültig: 200 mit der getrimmten Form; die nächste Anmeldung trägt sie.
    let (status, body) = send(
        &app,
        "PATCH",
        "/accounts",
        Some(json!({ "display_name": "  Rita B.  " })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "Rita B.");
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("rita", "ritas-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    assert_eq!(body["display_name"], "Rita B.");
}

#[tokio::test]
async fn identity_rotation_replaces_key_and_rejects_old_signatures() {
    let app = test_app();
    // Das erste Gerät nutzt den Geräteschlüssel key(42) (register_body).
    let dev_pk = b64_public(&key(42));
    let r1 = key(13); // alter Wurzelschlüssel

    let register = register_body(&r1, "rob", "robs-langes-passwort", DEV_FIRST);
    let (status, _) = send(&app, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body) = send(
        &app,
        "POST",
        "/sessions",
        Some(login_body("rob", "robs-langes-passwort", DEV_FIRST)),
        None,
    )
    .await;
    let access = body["access_token"].as_str().unwrap().to_string();

    // Eine falsch signierte Rotation (nicht vom alten Schlüssel) wird
    // abgewiesen, bevor irgendetwas geändert wird.
    let r2 = key(99);
    let new_key = b64_public(&r2);
    let wrong = key(200);
    let bad_sig = BASE64.encode(
        wrong
            .sign(rotation_message("rob", &new_key).as_bytes())
            .to_bytes(),
    );
    let (status, body) = send(
        &app,
        "POST",
        "/accounts/rotate-identity",
        Some(json!({ "new_identity_key": new_key, "rotation_signature": bad_sig, "devices": [] })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Eigener Code, damit ein wiederaufnehmender Client den Kontinuitäts-
    // fehler vom Geräte-Credential-Fehler unterscheiden kann (ADR-0010).
    assert_eq!(body["code"], "invalid_continuity");

    // Eine unvollständige Rotation (Gerät fehlt) wird abgewiesen.
    let good_sig = BASE64.encode(
        r1.sign(rotation_message("rob", &new_key).as_bytes())
            .to_bytes(),
    );
    let (status, body) = send(
        &app,
        "POST",
        "/accounts/rotate-identity",
        Some(json!({ "new_identity_key": new_key, "rotation_signature": good_sig, "devices": [] })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "incomplete_rotation");

    // Korrekte Rotation: gültige Kontinuitätssignatur, jedes Gerät mit dem
    // NEUEN Schlüssel neu signiert. Der Ablauf wird zugleich erneuert (ein
    // frischer, vom bisherigen abweichender not_after); der Dienst zeichnet
    // gegen genau diesen Wert und speichert ihn (ADR-0010, Finding 2).
    let rotated_not_after = FAR_FUTURE - 1000;
    let new_cred = BASE64.encode(
        r2.sign(credential_message("rob", DEV_FIRST, &dev_pk, rotated_not_after).as_bytes())
            .to_bytes(),
    );
    let (status, _) = send(
        &app,
        "POST",
        "/accounts/rotate-identity",
        Some(json!({
            "new_identity_key": new_key,
            "rotation_signature": good_sig,
            "devices": [{ "id": DEV_FIRST, "credential": new_cred, "not_after": rotated_not_after }],
        })),
        Some(&access),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Der erneuerte Ablauf ist gespeichert: die Geräteliste zeigt den neuen
    // not_after, nicht mehr den ursprünglichen aus der Registrierung.
    let (_, devices) = send(&app, "GET", "/devices", None, Some(&access)).await;
    let first = devices
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == DEV_FIRST)
        .unwrap();
    assert_eq!(first["not_after"].as_u64().unwrap(), rotated_not_after);

    // Der neue Schlüssel ist jetzt aktiv: ein mit R2 signiertes Gerät wird
    // angenommen, ein mit dem ALTEN R1 signiertes nicht mehr.
    let dev_new = signed_device(&r2, "rob", DEV_SECOND, 43);
    let (status, _) = send(&app, "POST", "/devices", Some(dev_new), Some(&access)).await;
    assert_eq!(status, StatusCode::CREATED);
    let dev_old = signed_device(&r1, "rob", DEV_MISC, 44);
    let (status, body) = send(&app, "POST", "/devices", Some(dev_old), Some(&access)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_credential");
}
