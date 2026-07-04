//! Integrationstests des Prekey-Pools gegen echtes PostgreSQL.
//!
//! Laufen nur mit TEST_DATABASE_URL (siehe ENTWICKLUNG.md), sonst still
//! übersprungen. Der Kern ist der Nebenläufigkeits-Beweis: parallele
//! Bündel-Abrufe dürfen nie denselben Einmal-Prekey liefern
//! (FOR UPDATE SKIP LOCKED, datenmodell.md).

use std::collections::HashSet;
use std::sync::Arc;

use directory::domain::{PoolCounts, Prekey, PrekeyKind};
use directory::pg::{connect_and_migrate, PgPrekeyStore};
use directory::store::{PrekeyStore, PrekeyUpload, StoreError};
use uuid::Uuid;

async fn store() -> Option<PgPrekeyStore> {
    // Eigene Variable statt TEST_DATABASE_URL: jeder Dienst hat seine
    // eigene Datenbank (architektur.md), und die sqlx-Migrationstabellen
    // beider Dienste dürfen sich nicht in die Quere kommen.
    let Ok(url) = std::env::var("TEST_DATABASE_URL_DIRECTORY") else {
        eprintln!("TEST_DATABASE_URL_DIRECTORY nicht gesetzt, PG-Test übersprungen");
        return None;
    };
    Some(PgPrekeyStore::new(
        connect_and_migrate(&url)
            .await
            .expect("Test-Datenbank erreichbar"),
    ))
}

fn upload(kind: PrekeyKind) -> PrekeyUpload {
    PrekeyUpload {
        kind,
        prekey: Prekey {
            id: Uuid::new_v4().to_string(),
            key: "cHJla2V5LWJsb2I=".to_string(),
        },
    }
}

#[tokio::test]
async fn roundtrip_rotation_and_conflicts() {
    let Some(store) = store().await else { return };
    let device = Uuid::new_v4().to_string();

    // Voller Upload, Zählstand stimmt.
    let signed = upload(PrekeyKind::Signed);
    let one_time = upload(PrekeyKind::OneTime);
    store
        .upload(
            &device,
            vec![
                signed.clone(),
                one_time.clone(),
                upload(PrekeyKind::PqSigned),
                upload(PrekeyKind::PqOneTime),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        store.counts(&device).await.unwrap(),
        PoolCounts {
            one_time: 1,
            pq_one_time: 1,
            mls_key_package: 0,
        }
    );

    // Bündel: alles belegt, Einmal-Prekeys konsumiert, signierte nicht.
    let bundle = store.take_bundle(&device).await.unwrap();
    assert_eq!(bundle.signed.as_ref().unwrap().id, signed.prekey.id);
    assert_eq!(bundle.one_time.as_ref().unwrap().id, one_time.prekey.id);
    assert_eq!(bundle.one_time.unwrap().key, "cHJla2V5LWJsb2I=");
    let second = store.take_bundle(&device).await.unwrap();
    assert!(second.signed.is_some());
    assert!(second.one_time.is_none());

    // Rotation ersetzt den signierten Prekey.
    let new_signed = upload(PrekeyKind::Signed);
    store
        .upload(&device, vec![new_signed.clone()])
        .await
        .unwrap();
    let bundle = store.take_bundle(&device).await.unwrap();
    assert_eq!(bundle.signed.unwrap().id, new_signed.prekey.id);

    // Doppelte ID platzt am Primärschlüssel.
    let dup = upload(PrekeyKind::OneTime);
    store.upload(&device, vec![dup.clone()]).await.unwrap();
    let err = store.upload(&device, vec![dup]).await.unwrap_err();
    assert_eq!(err, StoreError::PrekeyIdTaken);
}

#[tokio::test]
async fn concurrent_bundle_calls_never_share_a_one_time_prekey() {
    let Some(store) = store().await else { return };
    let store = Arc::new(store);
    let device = Uuid::new_v4().to_string();

    // 5 Einmal-Prekeys, 8 parallele Abrufe: genau 5 bekommen einen, und
    // alle 5 sind verschieden. Mehr Abrufe als Vorrat, damit auch der
    // Leerlauf-Pfad unter Konkurrenz läuft.
    let uploads: Vec<PrekeyUpload> = (0..5).map(|_| upload(PrekeyKind::OneTime)).collect();
    store.upload(&device, uploads).await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let device = device.clone();
        tasks.push(tokio::spawn(async move {
            store.take_bundle(&device).await.unwrap().one_time
        }));
    }
    let mut seen = HashSet::new();
    let mut hits = 0;
    for task in tasks {
        if let Some(prekey) = task.await.unwrap() {
            hits += 1;
            assert!(
                seen.insert(prekey.id.clone()),
                "Einmal-Prekey {} doppelt ausgeliefert",
                prekey.id
            );
        }
    }
    assert_eq!(hits, 5, "genau der Vorrat wird ausgeliefert");
    assert_eq!(
        store.counts(&device).await.unwrap(),
        PoolCounts::default(),
        "Pool ist leer"
    );
}

/// MLS-KeyPackages über echtes PostgreSQL: einzeln konsumiert (jedes nur
/// einmal), getrennt vom PQXDH-Bündel und separat gezählt.
#[tokio::test]
async fn mls_key_packages_claim_over_postgres() {
    let Some(store) = store().await else { return };
    let device = Uuid::new_v4().to_string();
    store
        .upload(
            &device,
            vec![
                upload(PrekeyKind::MlsKeyPackage),
                upload(PrekeyKind::MlsKeyPackage),
                upload(PrekeyKind::OneTime),
            ],
        )
        .await
        .unwrap();
    assert_eq!(store.counts(&device).await.unwrap().mls_key_package, 2);

    // Der Bündel-Abruf lässt die KeyPackages unangetastet.
    store.take_bundle(&device).await.unwrap();
    assert_eq!(store.counts(&device).await.unwrap().mls_key_package, 2);

    // Zwei Claims liefern zwei verschiedene Pakete, der dritte nichts.
    let first = store.take_mls_key_package(&device).await.unwrap().unwrap();
    let second = store.take_mls_key_package(&device).await.unwrap().unwrap();
    assert_ne!(first.id, second.id);
    assert!(store.take_mls_key_package(&device).await.unwrap().is_none());
    assert_eq!(store.counts(&device).await.unwrap().mls_key_package, 0);
}
