//! End-to-End-Beweis der Contact Discovery über den echten identity-Router.
//!
//! Bob löst den ihm bekannten Handle "alice" auf, ohne dass der Server den
//! Klartext sieht: er blendet den Handle, der Dienst wertet die OPRF aus,
//! Bob entblendet und schlägt nach. Das Ergebnis ist Alices interne
//! Adresse und Konto-Identitätsschlüssel, bereit für die KT-Prüfung. Ein
//! unbekannter Handle liefert kein Konto.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::discovery::DiscoveryClient;
use client_app::{IdentityClient, NewAccount};
use client_core::onetoone::Device;

const INTERNAL_SECRET: &str = "test-internes-secret";

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Ephemeralport");
    let addr = listener.local_addr().expect("lokale Adresse");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Testserver");
    });
    format!("http://{addr}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit")
        .as_secs()
}

async fn register(client: &IdentityClient, handle: &'static str, seed: u32) -> String {
    let mut device = Device::new(handle, 1, seed).expect("Gerät");
    let device_public = BASE64.encode(device.identity_public().await.expect("Identität"));
    let account_key = IdentityKeypair::generate();
    let device_id = uuid::Uuid::new_v4().to_string();
    client
        .register(&NewAccount {
            handle,
            display_name: None,
            password: "ein-sehr-langes-passwort",
            account_key: &account_key,
            device_public_key: &device_public,
            device_id: &device_id,
            not_after: now_unix() + 3600,
        })
        .await
        .expect("Registrierung");
    let session = client
        .login(handle, "ein-sehr-langes-passwort", &device_id)
        .await
        .expect("Login");
    session.access_token
}

#[tokio::test]
async fn discovery_resolves_known_handle_obliviously() {
    // identity mit konfigurierter Discovery (fester OPRF-Seed).
    let oprf = Arc::new(oprf::ServerKey::from_seed(&[3u8; 32]).expect("OPRF-Schlüssel"));
    let identity_url = serve(identity::api::app(
        identity::api::AppState::new_in_memory()
            .with_internal_token(INTERNAL_SECRET)
            .with_discovery_oprf(oprf),
    ))
    .await;
    let identity_client = IdentityClient::new(&identity_url);
    let discovery = DiscoveryClient::new(&identity_url);

    let alice_token = register(&identity_client, "alice", 11).await;
    let bob_token = register(&identity_client, "bob", 22).await;

    // Alice löst sich selbst auf und bekommt ihre eigene interne Adresse und
    // ihren Konto-Identitätsschlüssel zurück.
    let resolved = discovery
        .resolve(&alice_token, "alice")
        .await
        .expect("Auflösung")
        .expect("Alice ist auffindbar");
    assert_eq!(resolved.handle, "alice");
    assert!(!resolved.id.is_empty(), "interne Adresse geliefert");
    assert!(
        !resolved.identity_key.is_empty(),
        "Identitätsschlüssel geliefert"
    );

    // Bob löst Alice auf und bekommt genau dasselbe Konto (der Server hat
    // ihren Handle nie im Klartext gesehen).
    let bob_sees = discovery
        .resolve(&bob_token, "alice")
        .await
        .expect("Auflösung")
        .expect("Alice ist auffindbar");
    assert_eq!(bob_sees.id, resolved.id, "beide lösen dasselbe Konto auf");
    assert_eq!(bob_sees.identity_key, resolved.identity_key);

    // Ein unbekannter Handle liefert kein Konto (kein Rateverfahren).
    let missing = discovery
        .resolve(&bob_token, "niemand")
        .await
        .expect("Auflösung");
    assert!(missing.is_none(), "unbekannter Handle ist nicht auffindbar");
}
