//! Integrationstests des PgKtStore gegen echtes PostgreSQL plus der
//! Neustart-Beweis: Wiederaufbau aus der persistierten Historie.
//!
//! Laufen nur mit TEST_DATABASE_URL_KT (eigene Datenbank je Dienst),
//! sonst still übersprungen. Achtung: die Tests teilen sich die
//! kt-Tabellen; jeder Lauf hängt neue Epochen an, was der
//! append-only-Semantik entspricht.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use kt::directory::KtDirectory;
use kt::keys::{RootSigner, SecretVrf};
use kt::pg::{connect_and_migrate, PgKtStore};
use kt::store::KtStore;

fn seed(byte: u8) -> String {
    BASE64.encode([byte; 32])
}

async fn store() -> Option<Arc<dyn KtStore>> {
    let url = std::env::var("TEST_DATABASE_URL_KT").ok()?;
    let pool = connect_and_migrate(&url)
        .await
        .expect("Test-Datenbank erreichbar und migrierbar");
    Some(Arc::new(PgKtStore::new(pool)))
}

#[tokio::test]
async fn epochs_survive_restart_and_rebuild_matches() {
    let Some(store) = store().await else {
        return;
    };
    // Feste Schlüssel: derselbe Wiederaufbau wie im echten Neustart.
    let vrf = SecretVrf::from_seed_b64(&seed(11)).unwrap();
    let signer = RootSigner::from_seed_b64(&seed(12)).unwrap();

    // "Erster Prozesslauf": Verzeichnis aufbauen, eine Epoche anhängen.
    let directory = KtDirectory::rebuild(store.as_ref(), vrf.clone(), signer)
        .await
        .expect("Wiederaufbau aus bestehender Historie");
    let handle = format!("nutzer-{}", uuid_like());
    store.queue_update(&handle, b"commitment-1").await.unwrap();
    let record = directory
        .publish_pending(store.as_ref())
        .await
        .unwrap()
        .expect("neue Epoche");

    // Die Wurzel liegt persistent vor.
    let stored = store
        .epoch(record.epoch)
        .await
        .unwrap()
        .expect("Wurzel gespeichert");
    assert_eq!(stored.root_hash, record.root_hash);
    assert_eq!(stored.signature, record.signature);

    // "Zweiter Prozesslauf": Wiederaufbau aus der Datenbank muss ohne
    // Integritätsfehler durchlaufen und dieselbe jüngste Wurzel sehen.
    let signer = RootSigner::from_seed_b64(&seed(12)).unwrap();
    let rebuilt = KtDirectory::rebuild(store.as_ref(), vrf, signer)
        .await
        .expect("Neustart-Wiederaufbau deterministisch");
    let (proof, epoch_hash) = rebuilt
        .lookup(&handle)
        .await
        .unwrap()
        .expect("Handle nach Neustart auffindbar");
    assert_eq!(epoch_hash.epoch(), record.epoch);
    drop(proof);
}

/// Eindeutige Handles je Lauf, ohne uuid-Dependency im Test.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::process::id()
    )
}
