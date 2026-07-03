//! PostgreSQL-Umsetzung des Prekey-Pools (sqlx, Schema in migrations/).
//!
//! Kernstück ist die atomare Konsumierung der Einmal-Prekeys mit
//! FOR UPDATE SKIP LOCKED (datenmodell.md): zwei gleichzeitige
//! Sitzungsaufbauten ziehen nie denselben Schlüssel, ohne aufeinander zu
//! warten - der zweite überspringt die gesperrte Zeile und nimmt die nächste.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::{DeviceBundle, PoolCounts, Prekey, PrekeyKind};
use crate::store::{PrekeyStore, PrekeyUpload, StoreError};

/// Baut den Verbindungspool und fährt die eingebetteten Migrationen;
/// schlägt eine fehl, soll der Prozess gar nicht erst Requests annehmen.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, String> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| format!("PostgreSQL-Verbindung fehlgeschlagen: {e}"))?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| format!("Migration fehlgeschlagen: {e}"))?;
    Ok(pool)
}

pub struct PgPrekeyStore {
    pool: PgPool,
}

impl PgPrekeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// Übersetzt Constraint-Verletzungen: doppelte Prekey-ID ist ein
/// Client-Konflikt, alles andere Infrastruktur.
fn map_conflict(e: sqlx::Error) -> StoreError {
    if let Some(db) = e.as_database_error() {
        if db.constraint() == Some("prekeys_pkey") {
            return StoreError::PrekeyIdTaken;
        }
    }
    StoreError::Backend(e.to_string())
}

/// IDs sind an der API als kanonische UUIDs validiert; ein Parse-Fehler
/// hier ist ein Programmierfehler, kein Nutzerfehler.
fn parse_uuid(value: &str, what: &str) -> Result<Uuid, StoreError> {
    Uuid::try_parse(value).map_err(|e| StoreError::Backend(format!("{what} keine UUID mehr: {e}")))
}

fn decode_key(value: &str) -> Result<Vec<u8>, StoreError> {
    BASE64
        .decode(value)
        .map_err(|e| StoreError::Backend(format!("Prekey ist kein Base64 mehr: {e}")))
}

fn row_to_prekey(row: &sqlx::postgres::PgRow) -> Prekey {
    let id: Uuid = row.get("id");
    let key: Vec<u8> = row.get("key");
    Prekey {
        id: id.to_string(),
        key: BASE64.encode(key),
    }
}

#[async_trait]
impl PrekeyStore for PgPrekeyStore {
    async fn upload(&self, device_id: &str, uploads: Vec<PrekeyUpload>) -> Result<(), StoreError> {
        let device_id = parse_uuid(device_id, "Geräte-ID")?;
        // Ein Stapel ist eine Transaktion: entweder kommt der ganze Upload
        // an oder nichts, halbe Pools gibt es nicht.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        for upload in uploads {
            if !upload.kind.is_one_time() {
                // Rotation: der bisherige signierte Prekey dieses Typs wird
                // ersetzt, nicht ergänzt (wöchentliche Rotation, datenmodell.md).
                sqlx::query(
                    "UPDATE prekeys SET used = TRUE \
                     WHERE device_id = $1 AND kind = $2 AND used = FALSE",
                )
                .bind(device_id)
                .bind(upload.kind.as_str())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
            let id = parse_uuid(&upload.prekey.id, "Prekey-ID")?;
            let key = decode_key(&upload.prekey.key)?;
            sqlx::query("INSERT INTO prekeys (id, device_id, kind, key) VALUES ($1, $2, $3, $4)")
                .bind(id)
                .bind(device_id)
                .bind(upload.kind.as_str())
                .bind(&key)
                .execute(&mut *tx)
                .await
                .map_err(map_conflict)?;
        }
        tx.commit().await.map_err(backend)
    }

    async fn counts(&self, device_id: &str) -> Result<PoolCounts, StoreError> {
        let device_id = parse_uuid(device_id, "Geräte-ID")?;
        let rows = sqlx::query(
            "SELECT kind, count(*) AS n FROM prekeys \
             WHERE device_id = $1 AND used = FALSE AND kind IN ('one_time', 'pq_one_time') \
             GROUP BY kind",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let mut counts = PoolCounts::default();
        for row in rows {
            let kind: String = row.get("kind");
            let n: i64 = row.get("n");
            let n = u64::try_from(n).unwrap_or(0);
            match kind.as_str() {
                "one_time" => counts.one_time = n,
                "pq_one_time" => counts.pq_one_time = n,
                _ => {}
            }
        }
        Ok(counts)
    }

    async fn take_bundle(&self, device_id: &str) -> Result<DeviceBundle, StoreError> {
        let device_id = parse_uuid(device_id, "Geräte-ID")?;
        let mut bundle = DeviceBundle::default();

        // Signierte Prekeys werden nur gelesen; der jüngste unversehrte
        // je Typ ist der aktuelle.
        for (kind, slot) in [
            (PrekeyKind::Signed, &mut bundle.signed),
            (PrekeyKind::PqSigned, &mut bundle.pq_signed),
        ] {
            let row = sqlx::query(
                "SELECT id, key FROM prekeys \
                 WHERE device_id = $1 AND kind = $2 AND used = FALSE \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(device_id)
            .bind(kind.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            *slot = row.as_ref().map(row_to_prekey);
        }

        // Einmal-Prekeys: ziehen und markieren in einem Statement. Das
        // innere SELECT sperrt die älteste freie Zeile, SKIP LOCKED lässt
        // parallele Abrufe an ihr vorbei zur nächsten - keiner wartet,
        // keiner bekommt denselben Schlüssel.
        for (kind, slot) in [
            (PrekeyKind::OneTime, &mut bundle.one_time),
            (PrekeyKind::PqOneTime, &mut bundle.pq_one_time),
        ] {
            let row = sqlx::query(
                "UPDATE prekeys SET used = TRUE WHERE id = ( \
                     SELECT id FROM prekeys \
                     WHERE device_id = $1 AND kind = $2 AND used = FALSE \
                     ORDER BY created_at LIMIT 1 \
                     FOR UPDATE SKIP LOCKED \
                 ) RETURNING id, key",
            )
            .bind(device_id)
            .bind(kind.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            *slot = row.as_ref().map(row_to_prekey);
        }
        Ok(bundle)
    }
}
