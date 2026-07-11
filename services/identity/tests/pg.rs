//! Integrationstests gegen echtes PostgreSQL.
//!
//! Laufen nur, wenn TEST_DATABASE_URL gesetzt ist (z. B.
//! postgres://postgres:dev@localhost:5432/identity), sonst still übersprungen:
//! cargo test soll ohne laufende Datenbank grün bleiben, die PG-Pfade werden
//! dafür vor jedem Commit einmal mit Datenbank ausgeführt (ENTWICKLUNG.md).
//!
//! Jeder Test nutzt eigene Handles, damit parallele Ausführung und
//! liegengebliebene Daten früherer Läufe nicht stören.

mod helpers;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use helpers::{key, login_body, register_body, send};
use identity::api::{app, AppState};
use identity::domain::{Account, Device};
use identity::pg::{connect_and_migrate, PgAccountStore, PgSessionStore};
use identity::session::{RefreshError, SessionConfig, SessionIdentity, SessionStore};
use identity::store::{AccountStore, StoreError};
use uuid::Uuid;

/// Verbindet zur Test-Datenbank oder meldet None (Test wird übersprungen).
async fn pool() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL nicht gesetzt, PG-Test übersprungen");
        return None;
    };
    Some(
        connect_and_migrate(&url)
            .await
            .expect("Test-Datenbank erreichbar"),
    )
}

fn b64(seed: u8) -> String {
    BASE64.encode([seed; 32])
}

fn account(handle: &str) -> Account {
    Account {
        id: Uuid::new_v4().to_string(),
        handle: handle.to_string(),
        display_name: handle.to_string(),
        password_hash: "$argon2id$fake".to_string(),
        identity_key: b64(1),
        deletion_pending_until: None,
    }
}

fn device(seed: u8) -> Device {
    Device {
        id: Uuid::new_v4().to_string(),
        name: "Testgerät".to_string(),
        public_key: b64(seed),
        credential: b64(seed.wrapping_add(1)),
        not_after: i64::MAX as u64,
        revoked: false,
        protocol_device_id: 0,
    }
}

/// Eindeutiges Handle pro Testlauf, damit Wiederholungen nicht kollidieren.
fn unique_handle(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..12])
}

#[tokio::test]
async fn account_roundtrip_and_conflicts() {
    let Some(pool) = pool().await else { return };
    let store = PgAccountStore::new(pool);
    let handle = unique_handle("pg-konto");

    let first = device(10);
    store.create(account(&handle), first.clone()).await.unwrap();

    // Lesen liefert die Base64-Werte unverändert zurück (BYTEA-Roundtrip).
    let loaded = store.get(&handle).await.unwrap().expect("Konto existiert");
    assert_eq!(loaded.handle, handle);
    assert_eq!(loaded.identity_key, b64(1));

    // Handle-Eindeutigkeit setzt die Datenbank durch.
    let err = store
        .create(account(&handle), device(11))
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::HandleTaken);

    // Geräte-IDs sind global eindeutig: dieselbe ID unter anderem Konto platzt.
    let other = unique_handle("pg-konto2");
    let mut clash = device(12);
    clash.id = first.id.clone();
    let err = store.create(account(&other), clash).await.unwrap_err();
    assert_eq!(err, StoreError::DeviceIdTaken);
}

#[tokio::test]
async fn deletion_schedule_cancel_and_purge() {
    let Some(pool) = pool().await else { return };
    let store = PgAccountStore::new(pool);
    let handle = unique_handle("pg-loeschen");
    let first = device(30);
    store.create(account(&handle), first.clone()).await.unwrap();
    store.add_device(&handle, device(31)).await.unwrap();

    // Vormerken: die Frist kommt als Unix-Sekunden zurück (TIMESTAMPTZ ->
    // Epoche), das Konto bleibt.
    let deadline = 4_000_000_000u64; // fern in der Zukunft
    store.schedule_deletion(&handle, deadline).await.unwrap();
    let loaded = store.get(&handle).await.unwrap().unwrap();
    assert_eq!(loaded.deletion_pending_until, Some(deadline));
    assert_eq!(store.purge_deleted(deadline - 1).await, Ok(0));
    assert!(store.get(&handle).await.unwrap().is_some());

    // Widerruf: wieder aktiv, ein späterer Purge lässt es stehen.
    store.cancel_deletion(&handle).await.unwrap();
    assert_eq!(
        store
            .get(&handle)
            .await
            .unwrap()
            .unwrap()
            .deletion_pending_until,
        None
    );
    assert_eq!(store.purge_deleted(deadline + 1).await, Ok(0));

    // Mit einer Frist in der Vergangenheit vormerken, dann purgen: das Konto
    // ist weg, die Geräte kaskadieren, die Geräte-ID wird wieder vergebbar.
    store.schedule_deletion(&handle, 1000).await.unwrap();
    assert_eq!(store.purge_deleted(2000).await, Ok(1));
    assert!(store.get(&handle).await.unwrap().is_none());
    let mut reuse = device(32);
    reuse.id = first.id.clone();
    let reborn = unique_handle("pg-neu");
    store.create(account(&reborn), reuse).await.unwrap();

    assert_eq!(
        store.schedule_deletion("pg-gibt-es-nicht", 1).await,
        Err(StoreError::AccountMissing)
    );
}

#[tokio::test]
async fn display_name_update_roundtrip() {
    let Some(pool) = pool().await else { return };
    let store = PgAccountStore::new(pool);
    let handle = unique_handle("pg-name");
    store.create(account(&handle), device(40)).await.unwrap();

    store.set_display_name(&handle, "Neuer Name").await.unwrap();
    assert_eq!(
        store.get(&handle).await.unwrap().unwrap().display_name,
        "Neuer Name"
    );

    assert_eq!(
        store.set_display_name("pg-gibt-es-nicht", "x").await,
        Err(StoreError::AccountMissing)
    );
}

#[tokio::test]
async fn device_lifecycle() {
    let Some(pool) = pool().await else { return };
    let store = PgAccountStore::new(pool);
    let handle = unique_handle("pg-geraete");

    let first = device(20);
    store.create(account(&handle), first.clone()).await.unwrap();

    let second = device(21);
    // Server vergibt die Protokollnummer: erstes Gerät 1, zweites 2.
    assert_eq!(store.add_device(&handle, second.clone()).await, Ok(2));
    let after_add = store.devices(&handle).await.unwrap();
    assert_eq!(after_add[0].protocol_device_id, 1);
    assert_eq!(after_add[1].protocol_device_id, 2);

    // Unbekanntes Konto ist ein eigener Fehler, kein stiller Erfolg.
    let err = store
        .add_device("pg-gibt-es-nicht", device(22))
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::AccountMissing);

    let devices = store.devices(&handle).await.unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].id, first.id); // sortiert nach added_at
    assert_eq!(devices[0].not_after, i64::MAX as u64);

    // Revozieren markiert, löscht nicht, und ist nicht wiederholbar.
    store.revoke_device(&handle, &second.id).await.unwrap();
    let after = store
        .get_device(&handle, &second.id)
        .await
        .unwrap()
        .expect("Gerät bleibt sichtbar");
    assert!(after.revoked);
    let err = store.revoke_device(&handle, &second.id).await.unwrap_err();
    assert_eq!(err, StoreError::DeviceNotFound);

    // Replay-Schutz: die ID bleibt auch nach Revocation vergeben.
    let mut replay = device(23);
    replay.id = second.id.clone();
    let err = store.add_device(&handle, replay).await.unwrap_err();
    assert_eq!(err, StoreError::DeviceIdTaken);

    // Keine UUID: kann nicht existieren, aber kein Fehler.
    assert!(store.get_device(&handle, "laptop").await.unwrap().is_none());
}

#[tokio::test]
async fn session_rotation_and_reuse_detection() {
    let Some(pool) = pool().await else { return };
    let accounts = PgAccountStore::new(pool.clone());
    let sessions = PgSessionStore::new(pool, SessionConfig::default());
    let handle = unique_handle("pg-session");

    let dev = device(30);
    accounts
        .create(account(&handle), dev.clone())
        .await
        .unwrap();
    let identity = SessionIdentity {
        handle: handle.clone(),
        device_id: dev.id.clone(),
    };

    let h = |s: &str| format!("hash-{s}-{}", &handle);
    sessions
        .create(identity.clone(), h("a1"), h("r1"))
        .await
        .unwrap();

    // Access-Token löst zur Identität auf, Unbekanntes zu None.
    let who = sessions.authenticate(&h("a1")).await.unwrap().unwrap();
    assert_eq!(who.handle, handle);
    assert_eq!(who.device_id, dev.id);
    assert!(sessions.authenticate(&h("nix")).await.unwrap().is_none());

    // Rotation: neues Paar gilt, altes Access-Token stirbt.
    let who = sessions.refresh(&h("r1"), h("a2"), h("r2")).await.unwrap();
    assert_eq!(who.device_id, dev.id);
    assert!(sessions.authenticate(&h("a1")).await.unwrap().is_none());
    assert!(sessions.authenticate(&h("a2")).await.unwrap().is_some());

    // Reuse des rotierten Tokens: erkannt, Familie komplett widerrufen.
    let err = sessions
        .refresh(&h("r1"), h("a3"), h("r3"))
        .await
        .unwrap_err();
    assert_eq!(err, RefreshError::ReuseDetected);
    assert!(sessions.authenticate(&h("a2")).await.unwrap().is_none());
    let err = sessions
        .refresh(&h("r2"), h("a4"), h("r4"))
        .await
        .unwrap_err();
    assert_eq!(err, RefreshError::Invalid);
}

#[tokio::test]
async fn session_revocation_paths() {
    let Some(pool) = pool().await else { return };
    let accounts = PgAccountStore::new(pool.clone());
    let sessions = PgSessionStore::new(pool.clone(), SessionConfig::default());
    let handle = unique_handle("pg-revoke");

    let dev = device(40);
    accounts
        .create(account(&handle), dev.clone())
        .await
        .unwrap();
    let identity = SessionIdentity {
        handle: handle.clone(),
        device_id: dev.id.clone(),
    };
    let h = |s: &str| format!("hash-{s}-{}", &handle);

    // Logout über Access-Hash tötet auch das Refresh-Token der Familie.
    sessions
        .create(identity.clone(), h("a1"), h("r1"))
        .await
        .unwrap();
    sessions.revoke_by_access(&h("a1")).await.unwrap();
    let err = sessions
        .refresh(&h("r1"), h("a2"), h("r2"))
        .await
        .unwrap_err();
    assert_eq!(err, RefreshError::Invalid);

    // Geräte-Widerruf beendet alle Sessions genau dieses Geräts.
    sessions
        .create(identity.clone(), h("a3"), h("r3"))
        .await
        .unwrap();
    sessions.revoke_device(&handle, &dev.id).await.unwrap();
    assert!(sessions.authenticate(&h("a3")).await.unwrap().is_none());

    // Abgelaufene Sessions sind sofort ungültig (TTL 0: Ablauf == jetzt).
    let dead = PgSessionStore::new(
        pool,
        SessionConfig {
            access_ttl: Duration::ZERO,
            refresh_ttl: Duration::ZERO,
        },
    );
    dead.create(identity, h("a5"), h("r5")).await.unwrap();
    assert!(dead.authenticate(&h("a5")).await.unwrap().is_none());
    let err = dead.refresh(&h("r5"), h("a6"), h("r6")).await.unwrap_err();
    assert_eq!(err, RefreshError::Invalid);
}

/// Baut die volle HTTP-Schicht über den PG-Stores, wie main.rs es täte.
fn pg_app(pool: sqlx::PgPool) -> axum::Router {
    let session_config = SessionConfig::default();
    app(AppState::with_stores(
        Arc::new(PgAccountStore::new(pool.clone())),
        Arc::new(PgSessionStore::new(pool, session_config)),
        session_config,
    ))
}

#[tokio::test]
async fn http_flow_survives_restart() {
    let Some(pool) = pool().await else { return };
    let handle = unique_handle("pg-http");
    let device_id = Uuid::new_v4().to_string();
    let identity = key(50);

    // Erste App-Instanz: Registrierung über die echte HTTP-Schicht.
    let app1 = pg_app(pool.clone());
    let register = register_body(&identity, &handle, "korrektes-pferd-batterie", &device_id);
    let (status, body) = send(&app1, "POST", "/accounts", Some(register), None).await;
    assert_eq!(status, StatusCode::CREATED, "Registrierung: {body}");

    // Zweite App-Instanz gegen dieselbe Datenbank simuliert einen
    // Prozess-Neustart: Konto und Gerät müssen ihn überleben. Das ist der
    // Unterschied zur In-Memory-Ablage und der eigentliche Zweck der Etappe.
    let app2 = pg_app(pool);
    let login = login_body(&handle, "korrektes-pferd-batterie", &device_id);
    let (status, body) = send(&app2, "POST", "/sessions", Some(login), None).await;
    assert_eq!(status, StatusCode::OK, "Login nach Neustart: {body}");
    let access = body["access_token"].as_str().unwrap().to_string();

    let (status, body) = send(&app2, "GET", "/devices", None, Some(&access)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], device_id.as_str());
}
