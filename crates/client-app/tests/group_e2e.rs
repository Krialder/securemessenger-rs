//! End-to-End-Beweis der MLS-Gruppen über die echte Dienstkette.
//!
//! identity, directory und delivery laufen als echte Router in-process.
//! Drei Nutzer bilden eine Gruppe: Alice gründet sie, lädt Bob und Carol
//! über deren MLS-KeyPackages (aus dem Verzeichnis) ein und verteilt die
//! Welcome-Nachrichten über den Zustelldienst. Danach tauschen alle drei
//! eine Ende-zu-Ende verschlüsselte Gruppennachricht; der Server sieht nur
//! opake Blobs. Die MLS-Krypto liegt vollständig im Kern (`GroupSession`),
//! diese Schicht bewegt nur die Blobs.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::delivery::{DeliveryClient, GroupOutgoing};
use client_app::directory::DirectoryClient;
use client_app::prekeys::{new_uuid, DirectoryPrekey};
use client_app::{wire, IdentityClient, NewAccount};
use client_core::group::{GroupMember, GroupSession};
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
        .expect("Systemzeit")
        .as_secs()
}

/// Ein Gruppen-Teilnehmer: Konto und Session auf den echten Diensten plus
/// sein MLS-Mitglied (Identität, Ablage, Signaturschlüssel).
struct Party {
    handle: &'static str,
    access_token: String,
    mls: Option<GroupMember>,
}

async fn onboard(identity_client: &IdentityClient, handle: &'static str, seed: u32) -> Party {
    let mut device = Device::new(handle, 1, seed).expect("Gerät");
    let device_public = BASE64.encode(device.identity_public().await.expect("Identität"));
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
    Party {
        handle,
        access_token: session.access_token,
        mls: Some(GroupMember::new(handle.as_bytes()).expect("MLS-Mitglied")),
    }
}

/// Holt die wartenden Gruppen-Hüllen eines Teilnehmers, entrahmt sie und
/// bestätigt sie. Liefert die MLS-Blobs in Eingangsreihenfolge.
async fn drain_group_blobs(delivery: &DeliveryClient, token: &str) -> Vec<Vec<u8>> {
    let waiting = delivery.fetch(token).await.expect("Abholen");
    let mut blobs = Vec::new();
    let mut acked = Vec::new();
    for message in &waiting {
        if let wire::Framed::Group = wire::classify(&message.envelope) {
            let opened = wire::open_group(&message.envelope).expect("Gruppen-Hülle");
            blobs.push(opened.blob);
        }
        acked.push(message.id.clone());
    }
    if !acked.is_empty() {
        delivery.ack(token, &acked).await.expect("Ack");
    }
    blobs
}

#[tokio::test]
async fn three_users_exchange_a_group_message_over_real_services() {
    let (identity_url, directory_url, delivery_url) = start_stack().await;
    let identity_client = IdentityClient::new(identity_url);
    let directory = DirectoryClient::new(directory_url);
    let delivery = DeliveryClient::new(delivery_url);

    let alice = onboard(&identity_client, "alice", 11).await;
    let mut bob = onboard(&identity_client, "bob", 22).await;
    let mut carol = onboard(&identity_client, "carol", 33).await;

    // Bob und Carol veröffentlichen je ein MLS-KeyPackage im Verzeichnis,
    // damit Alice sie einladen kann.
    for party in [&bob, &carol] {
        let blob = party
            .mls
            .as_ref()
            .unwrap()
            .key_package_blob()
            .expect("KeyPackage-Blob");
        directory
            .publish_mls_key_packages(
                &party.access_token,
                &[DirectoryPrekey {
                    id: new_uuid(),
                    key: BASE64.encode(&blob),
                }],
            )
            .await
            .expect("KeyPackage-Upload");
    }

    // Alice gründet die Gruppe: der Dienst löst die Handles zu Zielgeräten
    // auf (drei Geräte).
    let group_id = new_uuid();
    let members: Vec<String> = ["alice", "bob", "carol"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let created = delivery
        .create_group(&alice.access_token, &group_id, &members)
        .await
        .expect("Gruppe anlegen");
    assert_eq!(created.epoch, 0);
    assert_eq!(created.devices, 3);

    // Alice startet ihre Gruppensitzung und holt Bobs und Carols
    // KeyPackages (konsumiert je eins).
    let mut alice_group = GroupSession::create(b"alice").expect("Gruppe gründen");
    let mut invite_blobs = Vec::new();
    let mut invited_devices = Vec::new();
    for handle in ["bob", "carol"] {
        let packages = directory
            .mls_key_packages(&alice.access_token, handle)
            .await
            .expect("KeyPackage-Abruf");
        assert_eq!(packages.devices.len(), 1, "{handle} hat ein KeyPackage");
        let entry = &packages.devices[0];
        invite_blobs.push(
            BASE64
                .decode(&entry.key_package)
                .expect("KeyPackage-Base64"),
        );
        invited_devices.push(entry.device_id.clone());
    }

    // Ein Commit lädt beide neuen Mitglieder ein; der Welcome geht an ihre
    // Geräte, der Commit-Epochenwechsel serialisiert über den Dienst.
    let outcome = alice_group
        .add_members(&invite_blobs)
        .expect("Mitglieder einladen");
    assert_eq!(alice_group.member_count(), 3);
    let welcome_fanout: Vec<GroupOutgoing> = invited_devices
        .iter()
        .map(|device_id| GroupOutgoing {
            id: new_uuid(),
            device_id: device_id.clone(),
            envelope: wire::seal_group(&group_id, &outcome.welcome).expect("Welcome rahmen"),
        })
        .collect();
    let commit = delivery
        .group_commit(&alice.access_token, &group_id, 0, &members, &welcome_fanout)
        .await
        .expect("Commit");
    assert_eq!(commit.epoch, 1, "Epoche steigt mit dem Commit");
    assert_eq!(commit.accepted, 2);

    // Bob und Carol holen ihren Welcome ab und treten bei.
    let bob_member = bob.mls.take().unwrap();
    let bob_welcome = drain_group_blobs(&delivery, &bob.access_token).await;
    assert_eq!(bob_welcome.len(), 1, "genau ein Welcome für Bob");
    let mut bob_group =
        GroupSession::join_group(bob_member, &bob_welcome[0]).expect("Bob tritt bei");
    assert_eq!(bob_group.member_count(), 3);

    let carol_member = carol.mls.take().unwrap();
    let carol_welcome = drain_group_blobs(&delivery, &carol.access_token).await;
    let mut carol_group =
        GroupSession::join_group(carol_member, &carol_welcome[0]).expect("Carol tritt bei");
    assert_eq!(carol_group.member_count(), 3);

    // Alice schickt eine Gruppennachricht an Bobs und Carols Geräte.
    let ciphertext = alice_group
        .create_message(b"hallo gruppe, ende-zu-ende")
        .expect("Gruppennachricht");
    let message_fanout: Vec<GroupOutgoing> = invited_devices
        .iter()
        .map(|device_id| GroupOutgoing {
            id: new_uuid(),
            device_id: device_id.clone(),
            envelope: wire::seal_group(&group_id, &ciphertext).expect("Nachricht rahmen"),
        })
        .collect();
    let sent = delivery
        .group_messages(&alice.access_token, &group_id, &message_fanout)
        .await
        .expect("Gruppennachricht senden");
    assert_eq!(sent.accepted, 2);

    // Beide holen ab und entschlüsseln denselben Klartext.
    for (group, party) in [(&mut bob_group, &bob), (&mut carol_group, &carol)] {
        let blobs = drain_group_blobs(&delivery, &party.access_token).await;
        assert_eq!(blobs.len(), 1, "{} bekommt die Nachricht", party.handle);
        let plaintext = group.process(&blobs[0]).expect("verarbeiten");
        assert_eq!(
            plaintext.as_deref(),
            Some(b"hallo gruppe, ende-zu-ende".as_slice()),
            "{} entschlüsselt die Gruppennachricht",
            party.handle
        );
    }
}
