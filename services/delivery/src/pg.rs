//! PostgreSQL-Umsetzung der Nachrichten-Ablage (datenmodell.md,
//! Abschnitt "Nachrichten").
//!
//! Die messages-Tabelle ist nach Monat partitioniert; die Partitionen
//! legt dieser Store beim Schreiben an (nicht die Migration), weil sie
//! von der Laufzeit abhängen. Alte Partitionen fallen später per
//! Retention-Job weg, mitsamt der zugehörigen Dedupe-Zeilen.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::{NewMessage, StoreOutcome, WaitingMessage};
use crate::groups::{GroupError, GroupState, GroupStore};
use crate::store::{MessageStore, StoreError};

/// Verbindet und führt die eingebetteten Migrationen aus. Scheitert das,
/// bricht der Start ab (main.rs), statt still ohne Persistenz zu laufen.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, String> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| format!("Verbindung fehlgeschlagen: {e}"))?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| format!("Migration fehlgeschlagen: {e}"))?;
    Ok(pool)
}

pub struct PgMessageStore {
    pool: PgPool,
    /// Bereits sichergestellte Monatspartitionen (Schlüssel: 'YYYYMM').
    /// Nur ein Cache: das CREATE läuft mit IF NOT EXISTS und Advisory
    /// Lock, mehrere Prozesse stören sich nicht.
    ensured_partitions: Mutex<HashSet<String>>,
}

fn backend(error: sqlx::Error) -> StoreError {
    StoreError::Backend(error.to_string())
}

/// UUIDs kommen aus der API bereits validiert bzw. von identity; ein
/// Parse-Fehler hier ist ein Programmierfehler, kein Nutzerfehler.
fn parse_uuid(value: &str, what: &str) -> Result<Uuid, StoreError> {
    Uuid::try_parse(value).map_err(|e| StoreError::Backend(format!("{what} keine UUID: {e}")))
}

fn now_epoch() -> f64 {
    // Mit Subsekunden, damit die Eingangsreihenfolge innerhalb einer
    // Sekunde erhalten bleibt (to_timestamp nimmt double precision).
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl PgMessageStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ensured_partitions: Mutex::new(HashSet::new()),
        }
    }

    /// Stellt die Monatspartition für den Zeitpunkt sicher. Die Grenzen
    /// rechnet PostgreSQL selbst aus (date_trunc), damit Client-Uhr und
    /// Partitionsgrenzen nie auseinanderlaufen; der Advisory Lock
    /// serialisiert konkurrierende CREATEs über Prozesse hinweg.
    async fn ensure_partition(&self, epoch: f64) -> Result<(), StoreError> {
        let row = sqlx::query(
            "SELECT to_char(date_trunc('month', to_timestamp($1)), 'YYYYMM') AS key, \
                    to_char(date_trunc('month', to_timestamp($1)), 'YYYY-MM-DD') AS from_day, \
                    to_char(date_trunc('month', to_timestamp($1)) + interval '1 month', 'YYYY-MM-DD') AS to_day",
        )
        .bind(epoch)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        let key: String = row.get("key");
        {
            let ensured = self
                .ensured_partitions
                .lock()
                .expect("Lock nicht vergiftet");
            if ensured.contains(&key) {
                return Ok(());
            }
        }
        let from_day: String = row.get("from_day");
        let to_day: String = row.get("to_day");
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query("SELECT pg_advisory_xact_lock(431906)")
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        // Werte stammen aus to_char, nicht vom Client; String-Bau ist
        // nötig, weil DDL keine Parameter bindet.
        let ddl = format!(
            "CREATE TABLE IF NOT EXISTS messages_p{key} PARTITION OF messages \
             FOR VALUES FROM ('{from_day}') TO ('{to_day}')"
        );
        sqlx::query(&ddl).execute(&mut *tx).await.map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        self.ensured_partitions
            .lock()
            .expect("Lock nicht vergiftet")
            .insert(key);
        Ok(())
    }
}

#[async_trait]
impl MessageStore for PgMessageStore {
    async fn store_batch(&self, messages: Vec<NewMessage>) -> Result<StoreOutcome, StoreError> {
        let received_at = now_epoch();
        self.ensure_partition(received_at).await?;
        // Ein Batch, eine Transaktion: entweder liegt alles Neue oder
        // nichts. Duplikate erkennt die Dedupe-Tabelle zeilenweise und
        // sind Erfolg (Idempotenz), kein Abbruch.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let mut outcome = StoreOutcome::default();
        for message in messages {
            let id = parse_uuid(&message.id, "Hüllen-ID")?;
            let inserted = sqlx::query(
                "INSERT INTO message_dedupe (id) VALUES ($1) ON CONFLICT (id) DO NOTHING",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            if inserted.rows_affected() == 0 {
                outcome.duplicates += 1;
                continue;
            }
            let envelope = BASE64
                .decode(&message.envelope)
                .map_err(|e| StoreError::Backend(format!("Hülle kein Base64: {e}")))?;
            let franking = match &message.franking_tag {
                Some(tag) => BASE64
                    .decode(tag)
                    .map_err(|e| StoreError::Backend(format!("Franking-Tag kein Base64: {e}")))?,
                None => Vec::new(),
            };
            // Die Eingangsreihenfolge hält die seq-Sequenz (Migration 0002),
            // nicht der Zeitstempel: Mikrosekunden-Offsets in Fließkomma
            // kollidierten nach der to_timestamp-Rundung, und dann entschied
            // die zufällige UUID die Reihenfolge.
            sqlx::query(
                "INSERT INTO messages (id, recipient_id, device_id, envelope, franking_tag, received_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6))",
            )
            .bind(id)
            .bind(parse_uuid(&message.recipient_id, "Empfänger-ID")?)
            .bind(parse_uuid(&message.device_id, "Geräte-ID")?)
            .bind(&envelope)
            .bind(&franking)
            .bind(received_at)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            outcome.accepted += 1;
        }
        tx.commit().await.map_err(backend)?;
        Ok(outcome)
    }

    async fn fetch(&self, device_id: &str, limit: u32) -> Result<Vec<WaitingMessage>, StoreError> {
        let device = parse_uuid(device_id, "Geräte-ID")?;
        let rows = sqlx::query(
            // seq ist die Eingangsreihenfolge (Migration 0002): global
            // monoton je Einreichung, ohne die Mikrosekunden-Kollisionen
            // des Zeitstempels, bei denen die zufällige UUID entschied.
            "SELECT id, envelope, franking_tag, \
                    extract(epoch FROM received_at)::bigint AS received_epoch \
             FROM messages WHERE device_id = $1 \
             ORDER BY seq LIMIT $2",
        )
        .bind(device)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let ids: Vec<Uuid> = rows.iter().map(|r| r.get("id")).collect();
        if !ids.is_empty() {
            // Zustell-Zeitpunkt festhalten (nur beim ersten Abholen);
            // rein informativ, weggeräumt wird erst mit dem Ack.
            sqlx::query(
                "UPDATE messages SET delivered_at = now() \
                 WHERE device_id = $1 AND delivered_at IS NULL AND id = ANY($2)",
            )
            .bind(device)
            .bind(&ids)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        }
        Ok(rows
            .iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                let envelope: Vec<u8> = r.get("envelope");
                let franking: Vec<u8> = r.get("franking_tag");
                let received_at: i64 = r.get("received_epoch");
                WaitingMessage {
                    id: id.to_string(),
                    envelope: BASE64.encode(envelope),
                    franking_tag: if franking.is_empty() {
                        None
                    } else {
                        Some(BASE64.encode(franking))
                    },
                    received_at: u64::try_from(received_at).unwrap_or(0),
                }
            })
            .collect())
    }

    async fn acknowledge(&self, device_id: &str, ids: &[String]) -> Result<u64, StoreError> {
        let device = parse_uuid(device_id, "Geräte-ID")?;
        let mut uuids = Vec::with_capacity(ids.len());
        for id in ids {
            uuids.push(parse_uuid(id, "Hüllen-ID")?);
        }
        // Die Dedupe-Zeilen bleiben absichtlich stehen: ein später Retry
        // des Absenders darf nicht erneut zustellen.
        let result = sqlx::query("DELETE FROM messages WHERE device_id = $1 AND id = ANY($2)")
            .bind(device)
            .bind(&uuids)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(result.rows_affected())
    }

    async fn has_waiting(&self, device_id: &str) -> Result<bool, StoreError> {
        let device = parse_uuid(device_id, "Geräte-ID")?;
        let row =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM messages WHERE device_id = $1) AS waiting")
                .bind(device)
                .fetch_one(&self.pool)
                .await
                .map_err(backend)?;
        Ok(row.get("waiting"))
    }
}

/// PostgreSQL-Umsetzung der Gruppen-Ablage (groups.rs). Teilt den Pool mit
/// der Nachrichten-Ablage; die Commit-Serialisierung läuft über eine
/// Transaktion mit Zeilensperre (`FOR UPDATE`), was der In-Memory-Mutex
/// prozesslokal leistet.
pub struct PgGroupStore {
    pool: PgPool,
}

impl PgGroupStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn group_backend(error: sqlx::Error) -> GroupError {
    GroupError::Backend(error.to_string())
}

fn parse_group_uuid(value: &str) -> Result<Uuid, GroupError> {
    Uuid::try_parse(value).map_err(|e| GroupError::Backend(format!("keine UUID: {e}")))
}

#[async_trait]
impl GroupStore for PgGroupStore {
    async fn create_group(&self, group_id: &str, devices: &[String]) -> Result<(), GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut device_uuids = Vec::with_capacity(devices.len());
        for d in devices {
            device_uuids.push(parse_group_uuid(d)?);
        }
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let inserted = sqlx::query(
            "INSERT INTO groups (id, epoch) VALUES ($1, 0) ON CONFLICT (id) DO NOTHING",
        )
        .bind(gid)
        .execute(&mut *tx)
        .await
        .map_err(group_backend)?;
        if inserted.rows_affected() == 0 {
            return Err(GroupError::GroupExists);
        }
        // Duplikate in der Eingabe fängt der Primärschlüssel; explizit
        // deduplizieren erspart den ON-CONFLICT-Lärm.
        let mut seen = std::collections::HashSet::new();
        for device in device_uuids {
            if seen.insert(device) {
                sqlx::query("INSERT INTO group_devices (group_id, device_id) VALUES ($1, $2)")
                    .bind(gid)
                    .bind(device)
                    .execute(&mut *tx)
                    .await
                    .map_err(group_backend)?;
            }
        }
        tx.commit().await.map_err(group_backend)?;
        Ok(())
    }

    async fn state(&self, group_id: &str) -> Result<GroupState, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let epoch: Option<i64> = sqlx::query_scalar("SELECT epoch FROM groups WHERE id = $1")
            .bind(gid)
            .fetch_optional(&self.pool)
            .await
            .map_err(group_backend)?;
        let Some(epoch) = epoch else {
            return Err(GroupError::UnknownGroup);
        };
        let devices: Vec<Uuid> = sqlx::query_scalar(
            "SELECT device_id FROM group_devices WHERE group_id = $1 ORDER BY device_id",
        )
        .bind(gid)
        .fetch_all(&self.pool)
        .await
        .map_err(group_backend)?;
        Ok(GroupState {
            epoch: u64::try_from(epoch).unwrap_or(0),
            devices: devices.into_iter().map(|d| d.to_string()).collect(),
        })
    }

    async fn commit(
        &self,
        group_id: &str,
        expected_epoch: u64,
        new_devices: &[String],
    ) -> Result<u64, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut device_uuids = Vec::with_capacity(new_devices.len());
        for d in new_devices {
            device_uuids.push(parse_group_uuid(d)?);
        }
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        // Zeilensperre: konkurrierende Commits derselben Gruppe werden
        // serialisiert, der zweite sieht die schon erhöhte Epoche.
        let current: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM groups WHERE id = $1 FOR UPDATE")
                .bind(gid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(group_backend)?;
        let Some(current) = current else {
            return Err(GroupError::UnknownGroup);
        };
        let current = u64::try_from(current).unwrap_or(0);
        if current != expected_epoch {
            return Err(GroupError::StaleEpoch { current });
        }
        let next = current + 1;
        sqlx::query("UPDATE groups SET epoch = $2 WHERE id = $1")
            .bind(gid)
            .bind(i64::try_from(next).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(group_backend)?;
        sqlx::query("DELETE FROM group_devices WHERE group_id = $1")
            .bind(gid)
            .execute(&mut *tx)
            .await
            .map_err(group_backend)?;
        let mut seen = std::collections::HashSet::new();
        for device in device_uuids {
            if seen.insert(device) {
                sqlx::query("INSERT INTO group_devices (group_id, device_id) VALUES ($1, $2)")
                    .bind(gid)
                    .bind(device)
                    .execute(&mut *tx)
                    .await
                    .map_err(group_backend)?;
            }
        }
        tx.commit().await.map_err(group_backend)?;
        Ok(next)
    }
}
