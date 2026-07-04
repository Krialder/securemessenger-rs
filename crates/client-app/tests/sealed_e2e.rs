//! End-to-End-Beweis für Sealed Sender über die echte Dienstkette.
//!
//! identity (mit Zertifikatsausgabe), directory und delivery laufen als
//! echte Router in-process. Alice holt sich ein Absender-Zertifikat,
//! versiegelt eine Nachricht an Bob und reicht sie ohne Token ein; die
//! Zustellung kennt den Absender damit weder aus der Authentifizierung
//! noch aus der Hülle. Bob entsiegelt gegen den Trust Root und erfährt
//! den Absender aus der geprüften Zertifikatskette. Der Kernbeweis: die
//! gespeicherte Hülle enthält das Absender-Handle nirgends.

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

/// Dienstkette wie im Cluster, identity zusätzlich mit dem
/// Sealed-Sender-Aussteller (fester Test-Trust-Root).
async fn start_stack() -> (String, String, String) {
    let issuer = Arc::new(sealed_cert::Issuer::from_seed(&[5u8; 32]).expect("Aussteller"));
    let identity_url = serve(identity::api::app(
        identity::api::AppState::new_in_memory()
            .with_internal_token(INTERNAL_SECRET)
            .with_sealed_sender(issuer),
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

struct User {
    handle: &'static str,
    device: Device,
    server_device_id: String,
    access_token: String,
}

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
async fn sealed_sender_hides_the_sender_from_the_server() {
    let (identity_url, directory_url, delivery_url) = start_stack().await;
    let identity_client = IdentityClient::new(identity_url);
    let directory_client = DirectoryClient::new(directory_url);
    let delivery_client = DeliveryClient::new(delivery_url);

    let mut alice = onboard(&identity_client, "alice", 41).await;
    let mut bob = onboard(&identity_client, "bob", 42).await;

    // Bob veröffentlicht sein Bündel, Alice baut die Sitzung auf.
    let bundle = bob.device.publish_prekey_bundle().await.expect("Bündel");
    let publication = publication_from_bundle(&bundle).expect("Blobs");
    directory_client
        .publish(&bob.access_token, &publication)
        .await
        .expect("Prekey-Upload");
    let bundles = directory_client
        .bundles(&alice.access_token, "bob")
        .await
        .expect("Bündel-Abruf");
    let (bob_bundle, bob_protocol_device) =
        bundle_from_directory(&bundles.devices[0]).expect("Bündel-Rekonstruktion");
    let bob_address = ProtocolAddress::new(
        bob.handle.to_string(),
        device_id_from_u32(bob_protocol_device).expect("Gerätenummer"),
    );
    alice
        .device
        .establish_session(&bob_address, &bob_bundle)
        .await
        .expect("PQXDH-Aufbau");

    // Trust Root und Absender-Zertifikat vom identity-Dienst.
    let trust_root = identity_client
        .sealed_sender_trust_root()
        .await
        .expect("Trust-Root-Abruf")
        .expect("Zertifikatsausgabe ist aktiv");
    let certificate = identity_client
        .sender_certificate(&alice.access_token, 1)
        .await
        .expect("Absender-Zertifikat");
    assert!(certificate.expires_at_millis > now_unix() * 1000);

    // Versiegeln, rahmen, ohne Token einreichen.
    let plaintext = b"versiegelt, der server sieht mich nicht";
    let sealed = alice
        .device
        .seal_message(&bob_address, &certificate.certificate, plaintext)
        .await
        .expect("Versiegeln");
    let envelope = wire::seal_sealed(&sealed).expect("Framing");
    let outcome = delivery_client
        .submit_sealed(&[OutgoingEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "bob".to_string(),
            device_id: bob.server_device_id.clone(),
            envelope,
            ..OutgoingEnvelope::default()
        }])
        .await
        .expect("Einreichen ohne Token");
    assert_eq!(outcome.accepted, 1);

    // Bob holt ab. Der Kernbeweis: die gespeicherte Hülle enthält weder
    // Klartext noch das Absender-Handle; die Zustellung könnte den
    // Absender nicht einmal durch Parsen ihrer eigenen Ablage lernen.
    let waiting = delivery_client
        .fetch(&bob.access_token)
        .await
        .expect("Abholen");
    assert_eq!(waiting.len(), 1);
    {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let stored = BASE64.decode(&waiting[0].envelope).expect("Hülle Base64");
        let haystack = String::from_utf8_lossy(&stored).into_owned();
        assert!(!haystack.contains("versiegelt"), "kein Klartext im Lager");
        assert!(
            !haystack.contains("alice"),
            "kein Absender-Handle in der versiegelten Hülle"
        );
        // Auch der Base64-dekodierte innere Blob trägt das Handle nicht.
        let blob = wire::open_sealed(&waiting[0].envelope).expect("Framing öffnen");
        let inner = String::from_utf8_lossy(&blob).into_owned();
        assert!(!inner.contains("alice"));
    }

    // Entsiegeln: erst hier, nach Prüfung der Zertifikatskette, steht der
    // Absender fest, und der Ratchet läuft normal weiter.
    assert!(matches!(
        wire::classify(&waiting[0].envelope),
        wire::Framed::Sealed
    ));
    let blob = wire::open_sealed(&waiting[0].envelope).expect("Framing öffnen");
    let unsealed = bob
        .device
        .unseal_message(&trust_root, &blob)
        .await
        .expect("Entsiegeln");
    assert_eq!(unsealed.sender, "alice");
    assert_eq!(unsealed.sender_device_id, 1);
    assert_eq!(unsealed.plaintext, plaintext);

    delivery_client
        .ack(&bob.access_token, &[waiting[0].id.clone()])
        .await
        .expect("Ack");
}
