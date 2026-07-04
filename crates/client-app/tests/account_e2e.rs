//! End-to-End-Beweis des Konto-Layers gegen den echten identity-Dienst.
//!
//! Startet den identity-Router (In-Memory-Ablage) auf einem Ephemeralport und
//! fährt Registrierung, Login, Rotation und Logout über die
//! client-app-Bibliothek. Kein externes Backend, keine Datenbank: der Beweis
//! läuft hermetisch im Testprozess und deckt genau die Vertragsstelle ab, an
//! der Client und Dienst sich treffen (Credential-Signatur, Feldnamen, Codes).

#![cfg(not(target_arch = "wasm32"))]

use std::time::{SystemTime, UNIX_EPOCH};

use client_app::account::IdentityKeypair;
use client_app::{ClientError, IdentityClient, NewAccount};

/// Startet den identity-Dienst auf `127.0.0.1:0` und liefert seine Basis-URL.
async fn start_identity() -> String {
    start_identity_with(identity::api::AppState::new_in_memory()).await
}

async fn start_identity_with(state: identity::api::AppState) -> String {
    let app = identity::api::app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Ephemeralport");
    let addr = listener.local_addr().expect("lokale Adresse");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("identity-Server");
    });
    format!("http://{addr}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}

#[tokio::test]
async fn register_login_refresh_logout_roundtrip() {
    let client = IdentityClient::new(start_identity().await);

    let account_key = IdentityKeypair::generate();
    let device_key = IdentityKeypair::generate();
    let device_id = uuid::Uuid::new_v4().to_string();
    let not_after = now_unix() + 60 * 60 * 24 * 365;

    let account = client
        .register(&NewAccount {
            handle: "alice",
            display_name: Some("Alice"),
            password: "supersecret-passwort",
            account_key: &account_key,
            device_public_key: &device_key.public_b64(),
            device_id: &device_id,
            not_after,
        })
        .await
        .expect("Registrierung");
    assert_eq!(account.handle, "alice");
    assert_eq!(account.device_id, device_id);

    let session = client
        .login("alice", "supersecret-passwort", &device_id)
        .await
        .expect("Login");
    assert_eq!(session.token_type, "Bearer");
    assert!(!session.access_token.is_empty());

    // Rotation liefert ein anderes Access-Token als der Login.
    let rotated = client
        .refresh(&session.refresh_token)
        .await
        .expect("Refresh");
    assert_ne!(rotated.access_token, session.access_token);

    client.logout(&rotated.access_token).await.expect("Logout");
}

/// Verlangt der Dienst einen Proof-of-Work, löst der Client ihn selbst:
/// die Registrierung geht durch, ohne dass der Aufrufer davon weiß.
#[tokio::test]
async fn register_solves_proof_of_work_transparently() {
    let url =
        start_identity_with(identity::api::AppState::new_in_memory().with_pow_difficulty(12)).await;
    let client = IdentityClient::new(&url);
    assert_eq!(client.pow_difficulty().await.expect("pow-Info"), 12);

    let account_key = IdentityKeypair::generate();
    let device_key = IdentityKeypair::generate();
    let device_id = uuid::Uuid::new_v4().to_string();
    let account = client
        .register(&NewAccount {
            handle: "powuser",
            display_name: None,
            password: "korrektes-pferd-batterie",
            account_key: &account_key,
            device_public_key: &device_key.public_b64(),
            device_id: &device_id,
            not_after: now_unix() + 3600,
        })
        .await
        .expect("Registrierung mit gelöstem Proof-of-Work");
    assert_eq!(account.handle, "powuser");
}

#[tokio::test]
async fn login_with_wrong_password_is_rejected() {
    let client = IdentityClient::new(start_identity().await);

    let account_key = IdentityKeypair::generate();
    let device_key = IdentityKeypair::generate();
    let device_id = uuid::Uuid::new_v4().to_string();

    client
        .register(&NewAccount {
            handle: "bob",
            display_name: None,
            password: "correct-horse-batterie",
            account_key: &account_key,
            device_public_key: &device_key.public_b64(),
            device_id: &device_id,
            not_after: now_unix() + 3600,
        })
        .await
        .expect("Registrierung");

    let error = client
        .login("bob", "falsches-passwort", &device_id)
        .await
        .expect_err("falsches Passwort muss scheitern");
    match error {
        ClientError::Api { status, .. } => assert_eq!(status, 401),
        other => panic!("unerwarteter Fehler: {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_handle_is_rejected() {
    let client = IdentityClient::new(start_identity().await);
    let account_key = IdentityKeypair::generate();
    let device_key = IdentityKeypair::generate();

    client
        .register(&NewAccount {
            handle: "carol",
            display_name: None,
            password: "ein-langes-passwort",
            account_key: &account_key,
            device_public_key: &device_key.public_b64(),
            device_id: &uuid::Uuid::new_v4().to_string(),
            not_after: now_unix() + 3600,
        })
        .await
        .expect("erste Registrierung");

    // Zweites Konto, gleiches Handle, frische Schlüssel und Geräte-ID: der
    // Dienst muss am vergebenen Handle scheitern, nicht an etwas anderem.
    let other_account = IdentityKeypair::generate();
    let other_device = IdentityKeypair::generate();
    let error = client
        .register(&NewAccount {
            handle: "carol",
            display_name: None,
            password: "ein-langes-passwort",
            account_key: &other_account,
            device_public_key: &other_device.public_b64(),
            device_id: &uuid::Uuid::new_v4().to_string(),
            not_after: now_unix() + 3600,
        })
        .await
        .expect_err("zweites Konto auf dasselbe Handle muss scheitern");
    match error {
        ClientError::Api { status, code, .. } => {
            assert_eq!(status, 409);
            assert_eq!(code, "handle_taken");
        }
        other => panic!("unerwarteter Fehler: {other:?}"),
    }
}
