//! End-to-End-Beweis des Nachrichten-Layers über die echte Dienstkette.
//!
//! identity, directory und delivery laufen als echte Router in-process
//! (In-Memory-Ablagen, verbunden über die /internal-Routen mit Shared
//! Secret, wie im Cluster). Zwei Nutzer registrieren sich mit ihrer
//! libsignal-Identität als Geräteschlüssel (ADR-0009), veröffentlichen
//! Prekey-Bündel, bauen per PQXDH eine Sitzung auf und tauschen über die
//! Zustellung Ende-zu-Ende verschlüsselte Nachrichten in beide Richtungen.
//! Nebenbei der Kernbeweis des Projekts: die Ablage der Zustellung enthält
//! zu keinem Zeitpunkt Klartext.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use client_app::account::IdentityKeypair;
use client_app::delivery::{DeliveryClient, OutgoingEnvelope};
use client_app::directory::DirectoryClient;
use client_app::prekeys::{bundle_from_directory, device_id_from_u32, publication_from_bundle};
use client_app::{wire, IdentityClient, NewAccount};
use client_core::libsignal_protocol::ProtocolAddress;
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

/// Baut die Dienstkette wie im Cluster: identity mit /internal-Routen,
/// directory und delivery lösen Tokens und Geräte über das Gateway auf.
async fn start_stack() -> (String, String, String) {
    let identity_url = serve(identity::api::app(
        identity::api::AppState::new_in_memory().with_internal_token(INTERNAL_SECRET),
    ))
    .await;

    let directory_url = serve(directory::api::app(directory::api::AppState::new(
        Arc::new(directory::store::InMemoryPrekeyStore::default()),
        Arc::new(common::identity_client::HttpIdentityGateway::new(
            &identity_url,
            INTERNAL_SECRET,
        )),
    )))
    .await;

    let delivery_url = serve(delivery::api::app(delivery::api::AppState::new(
        Arc::new(delivery::store::InMemoryMessageStore::default()),
        Arc::new(common::identity_client::HttpIdentityGateway::new(
            &identity_url,
            INTERNAL_SECRET,
        )),
    )))
    .await;

    (identity_url, directory_url, delivery_url)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}

/// Ein Testnutzer: Krypto-Kern-Gerät plus Konto und Session auf den echten
/// Diensten.
struct User {
    handle: &'static str,
    device: Device,
    server_device_id: String,
    access_token: String,
}

/// Registriert und meldet einen Nutzer an: die serialisierte
/// libsignal-Identität ist der Geräteschlüssel im Credential (ADR-0009).
async fn onboard(identity_client: &IdentityClient, handle: &'static str, seed: u32) -> User {
    let mut device = Device::new(handle, 1, seed).expect("Gerät");
    let device_public = {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        BASE64.encode(device.identity_public().await.expect("Identität"))
    };
    let account_key = IdentityKeypair::generate();
    let server_device_id = uuid::Uuid::new_v4().to_string();

    identity_client
        .register(&NewAccount {
            handle,
            display_name: None,
            password: "ein-sehr-langes-passwort",
            account_key: &account_key,
            device_public_key: &device_public,
            device_id: &server_device_id,
            not_after: now_unix() + 3600,
        })
        .await
        .expect("Registrierung");
    let session = identity_client
        .login(handle, "ein-sehr-langes-passwort", &server_device_id)
        .await
        .expect("Login");

    User {
        handle,
        device,
        server_device_id,
        access_token: session.access_token,
    }
}

#[tokio::test]
async fn two_users_exchange_e2ee_messages_over_real_services() {
    let (identity_url, directory_url, delivery_url) = start_stack().await;
    let identity_client = IdentityClient::new(identity_url);
    let directory_client = DirectoryClient::new(directory_url);
    let delivery_client = DeliveryClient::new(delivery_url);

    let mut alice = onboard(&identity_client, "alice", 11).await;
    let mut bob = onboard(&identity_client, "bob", 22).await;

    // Beide veröffentlichen ihre Bündel im Verzeichnis.
    for user in [&mut alice, &mut bob] {
        let bundle = user.device.publish_prekey_bundle().await.expect("Bündel");
        let publication = publication_from_bundle(&bundle).expect("Blobs");
        let counts = directory_client
            .publish(&user.access_token, &publication)
            .await
            .expect("Prekey-Upload");
        assert_eq!(counts.one_time, 1);
    }

    // Bob holt Alices Bündel (konsumiert ihren Einmal-Prekey) und baut die
    // PQXDH-Sitzung auf.
    let bundles = directory_client
        .bundles(&bob.access_token, "alice")
        .await
        .expect("Bündel-Abruf");
    assert_eq!(bundles.devices.len(), 1);
    let alice_bundle_json = &bundles.devices[0];
    assert_eq!(alice_bundle_json.device_id, alice.server_device_id);
    let (alice_bundle, alice_protocol_device) =
        bundle_from_directory(alice_bundle_json).expect("Bündel-Rekonstruktion");

    let alice_address = ProtocolAddress::new(
        alice.handle.to_string(),
        device_id_from_u32(alice_protocol_device).expect("Gerätenummer"),
    );
    bob.device
        .establish_session(&alice_address, &alice_bundle)
        .await
        .expect("PQXDH-Aufbau");

    // Bob verschlüsselt, rahmt und reicht bei der Zustellung ein.
    let plaintext = b"hallo alice, ende-zu-ende";
    let message = bob
        .device
        .encrypt(&alice_address, plaintext)
        .await
        .expect("Verschlüsselung");
    let envelope = wire::seal(bob.handle, 1, &message).expect("Framing");
    let outcome = delivery_client
        .submit(
            &bob.access_token,
            &[OutgoingEnvelope {
                id: uuid::Uuid::new_v4().to_string(),
                recipient: "alice".to_string(),
                device_id: alice.server_device_id.clone(),
                envelope,
            }],
        )
        .await
        .expect("Einreichen");
    assert_eq!(outcome.accepted, 1);

    // Alice holt ab. Die Hülle darf den Klartext nirgends enthalten: was
    // die Zustellung gespeichert hat, ist Chiffretext plus Framing.
    let waiting = delivery_client
        .fetch(&alice.access_token)
        .await
        .expect("Abholen");
    assert_eq!(waiting.len(), 1);
    {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let stored = BASE64.decode(&waiting[0].envelope).expect("Hülle Base64");
        let haystack = String::from_utf8_lossy(&stored);
        assert!(
            !haystack.contains("hallo alice"),
            "Klartext darf nie in der Ablage der Zustellung liegen"
        );
    }

    let opened = wire::open(&waiting[0].envelope).expect("Hülle öffnen");
    assert_eq!(opened.from, "bob");
    let bob_address = ProtocolAddress::new(
        opened.from.clone(),
        device_id_from_u32(opened.from_device).expect("Gerätenummer"),
    );
    let decrypted = alice
        .device
        .decrypt(&bob_address, &opened.message)
        .await
        .expect("Entschlüsselung");
    assert_eq!(decrypted, plaintext);

    // Bestätigen räumt weg.
    let removed = delivery_client
        .ack(&alice.access_token, &[waiting[0].id.clone()])
        .await
        .expect("Ack");
    assert_eq!(removed, 1);
    assert!(delivery_client
        .fetch(&alice.access_token)
        .await
        .expect("zweites Abholen")
        .is_empty());

    // Gegenrichtung: Alice antwortet über dieselbe Sitzung (normale
    // Ratchet-Nachricht, kein zweiter Bündel-Abruf nötig).
    let reply_plain = b"hallo bob, es funktioniert";
    let reply = alice
        .device
        .encrypt(&bob_address, reply_plain)
        .await
        .expect("Antwort verschlüsseln");
    let reply_envelope = wire::seal(alice.handle, 1, &reply).expect("Framing");
    delivery_client
        .submit(
            &alice.access_token,
            &[OutgoingEnvelope {
                id: uuid::Uuid::new_v4().to_string(),
                recipient: "bob".to_string(),
                device_id: bob.server_device_id.clone(),
                envelope: reply_envelope,
            }],
        )
        .await
        .expect("Antwort einreichen");

    let waiting = delivery_client
        .fetch(&bob.access_token)
        .await
        .expect("Bob holt ab");
    assert_eq!(waiting.len(), 1);
    let opened = wire::open(&waiting[0].envelope).expect("Hülle öffnen");
    let decrypted = bob
        .device
        .decrypt(&alice_address, &opened.message)
        .await
        .expect("Bob entschlüsselt");
    assert_eq!(decrypted, reply_plain);
}
