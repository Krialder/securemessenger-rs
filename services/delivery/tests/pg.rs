//! Integrationstests der Nachrichten-Ablage gegen echtes PostgreSQL.
//!
//! Laufen nur mit TEST_DATABASE_URL_DELIVERY (eigene Datenbank je Dienst,
//! siehe ENTWICKLUNG.md), sonst still übersprungen. Prüft neben der
//! Store-Semantik vor allem, was In-Memory nicht beweisen kann: die
//! Monatspartitionen und die Deduplizierung über die eigene Tabelle.

use std::sync::Arc;

use delivery::domain::NewMessage;
use delivery::groups::{GroupError, GroupStore};
use delivery::pg::{connect_and_migrate, PgGroupStore, PgMessageStore};
use delivery::store::MessageStore;
use uuid::Uuid;

async fn store() -> Option<PgMessageStore> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL_DELIVERY") else {
        eprintln!("TEST_DATABASE_URL_DELIVERY nicht gesetzt, PG-Test übersprungen");
        return None;
    };
    Some(PgMessageStore::new(
        connect_and_migrate(&url)
            .await
            .expect("Test-Datenbank erreichbar"),
    ))
}

async fn group_store() -> Option<PgGroupStore> {
    let url = std::env::var("TEST_DATABASE_URL_DELIVERY").ok()?;
    Some(PgGroupStore::new(
        connect_and_migrate(&url)
            .await
            .expect("Test-Datenbank erreichbar"),
    ))
}

fn message(device: &str) -> NewMessage {
    NewMessage {
        id: Uuid::new_v4().to_string(),
        recipient_id: Uuid::new_v4().to_string(),
        device_id: device.to_string(),
        envelope: "Y2hpZmZyZXRleHQ=".to_string(),
        franking_tag: Some("dGFn".to_string()),
    }
}

#[tokio::test]
async fn roundtrip_dedupe_and_ack() {
    let Some(store) = store().await else { return };
    let device = Uuid::new_v4().to_string();

    // Stapel ablegen: die Monatspartition entsteht dabei automatisch.
    let first = message(&device);
    let second = message(&device);
    let outcome = store
        .store_batch(vec![first.clone(), second.clone()])
        .await
        .unwrap();
    assert_eq!(outcome.accepted, 2);
    assert_eq!(outcome.duplicates, 0);
    assert!(store.has_waiting(&device).await.unwrap());

    // Retry: beides Duplikate, gemischter Stapel zählt getrennt.
    let third = message(&device);
    let outcome = store
        .store_batch(vec![first.clone(), third.clone()])
        .await
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.duplicates, 1);

    // Abholen: Eingangsreihenfolge, Blob und Tag unversehrt zurück. Die
    // volle Reihenfolge ist Teil des Vertrags (seq, Migration 0002); vorher
    // entschied bei Mikrosekunden-Kollisionen die zufällige UUID.
    let waiting = store.fetch(&device, 100).await.unwrap();
    assert_eq!(waiting.len(), 3);
    assert_eq!(waiting[0].id, first.id);
    assert_eq!(waiting[1].id, second.id);
    assert_eq!(waiting[2].id, third.id);
    assert_eq!(waiting[0].envelope, "Y2hpZmZyZXRleHQ=");
    assert_eq!(waiting[0].franking_tag.as_deref(), Some("dGFn"));
    assert!(waiting[0].received_at > 0);

    // Abholen räumt nicht weg, das Ack schon; fremde Geräte-Inbox bleibt.
    assert_eq!(store.fetch(&device, 100).await.unwrap().len(), 3);
    let removed = store
        .acknowledge(&device, &[first.id.clone(), second.id.clone()])
        .await
        .unwrap();
    assert_eq!(removed, 2);
    let rest = store.fetch(&device, 100).await.unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].id, third.id);

    // Nach dem Ack bleibt der Dedupe-Merker: kein Doppel-Empfang durch
    // späte Retries.
    let outcome = store.store_batch(vec![first]).await.unwrap();
    assert_eq!(outcome.duplicates, 1);
    assert_eq!(store.fetch(&device, 100).await.unwrap().len(), 1);
}

#[tokio::test]
async fn concurrent_batches_share_one_partition() {
    let Some(store) = store().await else { return };
    let store = Arc::new(store);

    // Mehrere Prozesse legen gleichzeitig los (kalter Partitions-Cache):
    // der Advisory Lock serialisiert das CREATE, alle Batches landen.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        let device = Uuid::new_v4().to_string();
        tasks.push(tokio::spawn(async move {
            let outcome = store
                .store_batch(vec![message(&device), message(&device)])
                .await
                .unwrap();
            assert_eq!(outcome.accepted, 2);
            store.fetch(&device, 10).await.unwrap().len()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 2);
    }
}

#[tokio::test]
async fn franking_tag_roundtrips_as_absent_when_empty() {
    let Some(store) = store().await else { return };
    let device = Uuid::new_v4().to_string();
    let mut msg = message(&device);
    msg.franking_tag = None;
    store.store_batch(vec![msg]).await.unwrap();
    let waiting = store.fetch(&device, 10).await.unwrap();
    assert_eq!(waiting[0].franking_tag, None);
}

/// Konkurrierende Commits gegen dieselbe Epoche über echtes PostgreSQL:
/// die Zeilensperre serialisiert sie, genau einer gewinnt und erhöht die
/// Epoche, alle anderen bekommen StaleEpoch. Das ist die Auflösungsregel
/// aus specs/mls-delivery-service.md, gegen die echte Datenbank geprüft
/// (In-Memory kann die Transaktions-Serialisierung nicht beweisen).
#[tokio::test]
async fn concurrent_commits_serialize_over_postgres() {
    let Some(store) = group_store().await else {
        return;
    };
    let store = Arc::new(store);
    let group = Uuid::new_v4().to_string();
    let a = Uuid::new_v4().to_string();
    let b = Uuid::new_v4().to_string();
    store
        .create_group(&group, &[a.clone(), b.clone()])
        .await
        .unwrap();

    // Vier Mitglieder committen gleichzeitig gegen Epoche 0.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        let group = group.clone();
        let newcomer = Uuid::new_v4().to_string();
        let members = vec![a.clone(), b.clone(), newcomer];
        tasks.push(tokio::spawn(async move {
            store.commit(&group, 0, &members).await
        }));
    }
    let mut winners = 0;
    let mut stale = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(epoch) => {
                winners += 1;
                assert_eq!(epoch, 1, "der Gewinner hebt auf Epoche 1");
            }
            Err(GroupError::StaleEpoch { current }) => {
                stale += 1;
                assert_eq!(current, 1, "die Verlierer sehen die schon erhöhte Epoche");
            }
            Err(other) => panic!("unerwarteter Fehler: {other}"),
        }
    }
    assert_eq!(winners, 1, "genau ein Commit gewinnt");
    assert_eq!(stale, 3, "die übrigen drei sind veraltet");

    // Die Gruppe steht auf Epoche 1 mit den drei Geräten des Gewinners.
    let state = store.state(&group).await.unwrap();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.devices.len(), 3);
}
