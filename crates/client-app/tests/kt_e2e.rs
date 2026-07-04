//! End-to-End-Beweis der KT-Selbstprüfung über die echte Dienstkette.
//!
//! identity und kt laufen als echte Router in-process, verbunden wie im
//! Cluster: identity meldet jede Schlüsseländerung fire-and-forget an
//! kt's interne Update-Route, der Epochen-Publisher bündelt sie zu
//! signierten Wurzeln. Der Client registriert sich, holt seine
//! Gerätemenge und prüft per `verify_self`, dass im Verzeichnis exakt
//! sein Commitment steht.
//!
//! Der zweite Teil ist das Abnahmekriterium aus GOAL.md (Meilenstein 1):
//! ein untergeschobener Schlüssel, hier als manipuliertes Commitment
//! direkt ins Verzeichnis gemeldet, muss bei der Selbstprüfung auffallen.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::kt::KtClient;
use client_app::{ClientError, IdentityClient, NewAccount};
use kt::directory::KtDirectory;
use kt::keys::{RootSigner, SecretVrf};
use kt::store::{InMemoryKtStore, KtStore};

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
        .expect("Systemzeit nach 1970")
        .as_secs()
}

/// Wartet, bis die fire-and-forget-Meldung von identity bei kt angekommen
/// ist, und veröffentlicht sie als Epoche. Nötig, weil die Meldung
/// asynchron neben der Registrierungs-Antwort läuft.
async fn publish_next_epoch(
    directory: &KtDirectory,
    store: &dyn KtStore,
) -> kt::store::EpochRecord {
    for _ in 0..100 {
        if let Some(record) = directory
            .publish_pending(store)
            .await
            .expect("Epoche veröffentlichen")
        {
            return record;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("keine wartenden KT-Updates: die identity-Meldung kam nie an");
}

#[tokio::test]
async fn self_check_passes_and_detects_planted_key() {
    // kt in-process: In-Memory-Log, deterministische Test-Schlüssel.
    let store: Arc<dyn KtStore> = Arc::new(InMemoryKtStore::default());
    let directory = Arc::new(
        KtDirectory::rebuild(
            store.as_ref(),
            SecretVrf::from_seed_b64(&BASE64.encode([1u8; 32])).unwrap(),
            RootSigner::from_seed_b64(&BASE64.encode([2u8; 32])).unwrap(),
        )
        .await
        .expect("frisches KT-Verzeichnis"),
    );
    let kt_url = serve(kt::api::app(
        kt::api::AppState::new(store.clone(), directory.clone())
            .with_internal_token(INTERNAL_SECRET),
    ))
    .await;

    // identity meldet Schlüsseländerungen an kt, wie im Cluster über HTTP.
    let identity_url = serve(identity::api::app(
        identity::api::AppState::new_in_memory()
            .with_internal_token(INTERNAL_SECRET)
            .with_kt_notifier(Arc::new(identity::kt_notify::HttpKtNotifier::new(
                &kt_url,
                INTERNAL_SECRET,
            ))),
    ))
    .await;

    // Registrierung wie ein echter Client; der Geräteschlüssel ist für
    // KT opak, ein fester Wert genügt (die libsignal-Bindung beweist
    // messaging_e2e).
    let account_key = IdentityKeypair::generate();
    let device_id = uuid::Uuid::new_v4().to_string();
    let identity_client = IdentityClient::new(&identity_url);
    identity_client
        .register(&NewAccount {
            handle: "kt-alice",
            display_name: None,
            password: "korrektes-batterie-pferd",
            account_key: &account_key,
            device_public_key: &BASE64.encode([7u8; 32]),
            device_id: &device_id,
            not_after: now_unix() + 3600,
        })
        .await
        .expect("Registrierung");
    let session = identity_client
        .login("kt-alice", "korrektes-batterie-pferd", &device_id)
        .await
        .expect("Login");

    let record = publish_next_epoch(&directory, store.as_ref()).await;
    assert_eq!(record.epoch, 1, "erste Epoche trägt die Registrierung");

    // Selbstprüfung: eigene Gerätemenge holen, Commitment nachrechnen,
    // Beweis verifizieren. Muss gegen Epoche 1 bestehen.
    let devices = identity_client
        .devices(&session.access_token)
        .await
        .expect("eigene Gerätemenge");
    assert_eq!(devices.len(), 1);
    let kt_client = KtClient::new(&kt_url);
    let check = kt_client
        .verify_self("kt-alice", &account_key.public_b64(), &devices, None)
        .await
        .expect("Selbstprüfung gegen das unverfälschte Verzeichnis");
    assert_eq!(check.epoch, 1);
    assert_eq!(check.version, 1);

    // Mit gepinntem, korrektem Wurzelschlüssel besteht sie ebenso.
    let info = kt_client.info().await.expect("kt-Info");
    kt_client
        .verify_self(
            "kt-alice",
            &account_key.public_b64(),
            &devices,
            Some(&info.root_signing_key),
        )
        .await
        .expect("Selbstprüfung mit gepinntem Schlüssel");

    // Ein falsch gepinnter Schlüssel fällt sofort auf.
    let wrong_pin = BASE64.encode([9u8; 32]);
    let err = kt_client
        .verify_self(
            "kt-alice",
            &account_key.public_b64(),
            &devices,
            Some(&wrong_pin),
        )
        .await
        .expect_err("fremder Pin darf nicht bestehen");
    assert!(matches!(err, ClientError::KeyTransparency(_)), "{err}");

    // Abnahmekriterium: der Betreiber schiebt ein manipuliertes Commitment
    // unter (stiller Schlüsseltausch) und veröffentlicht eine neue Epoche.
    // Die Selbstprüfung muss den Tausch melden, nicht still bestehen.
    let planted = BASE64.encode(b"untergeschobener-schluessel");
    let response = reqwest::Client::new()
        .post(format!("{kt_url}/internal/updates"))
        .header("x-internal-token", INTERNAL_SECRET)
        .json(&serde_json::json!({ "handle": "kt-alice", "value": planted }))
        .send()
        .await
        .expect("Rogue-Update einreichen");
    assert!(response.status().is_success());
    let record = publish_next_epoch(&directory, store.as_ref()).await;
    assert_eq!(record.epoch, 2, "zweite Epoche trägt den Rogue-Key");

    let err = kt_client
        .verify_self("kt-alice", &account_key.public_b64(), &devices, None)
        .await
        .expect_err("untergeschobener Schlüssel muss auffallen");
    match &err {
        ClientError::KeyTransparency(detail) => {
            assert!(
                detail.contains("weicht von den eigenen veröffentlichten Schlüsseln ab"),
                "Alarm nennt den Grund: {detail}"
            );
        }
        other => panic!("erwartet KeyTransparency-Alarm, bekam: {other}"),
    }

    // Auditor-Prüfung: das Log ist zwischen Epoche 1 und 2 append-only. Der
    // Rogue-Key ist eine Erweiterung, keine Umschreibung; die Konsistenz
    // hält also (den Tausch fängt die Selbstprüfung, nicht der Auditor).
    kt_client
        .verify_consistency(1, 2, None)
        .await
        .expect("die Wurzelfolge muss append-only sein");
}
