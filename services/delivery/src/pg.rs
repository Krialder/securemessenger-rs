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
use crate::groups::{
    apply_commit, apply_set_role, apply_transfer, apply_update_info, dedup, CommitContext,
    GroupError, GroupMeta, GroupRecord, GroupSettings, GroupState, GroupStore, NewGroup, Role,
};
use crate::store::{MessageStore, PushSubscription, StoreError};

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
            let expires_at = message.expires_at.and_then(|s| i64::try_from(s).ok());
            sqlx::query(
                "INSERT INTO messages (id, recipient_id, device_id, envelope, franking_tag, received_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7)",
            )
            .bind(id)
            .bind(parse_uuid(&message.recipient_id, "Empfänger-ID")?)
            .bind(parse_uuid(&message.device_id, "Geräte-ID")?)
            .bind(&envelope)
            .bind(&franking)
            .bind(received_at)
            .bind(expires_at)
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
            // Abgelaufene Hüllen (expires_at in der Vergangenheit) sind
            // verschwunden und werden nicht mehr ausgeliefert
            // (Disappearing Messages).
            "SELECT id, envelope, franking_tag, \
                    extract(epoch FROM received_at)::bigint AS received_epoch \
             FROM messages WHERE device_id = $1 \
               AND (expires_at IS NULL OR expires_at > extract(epoch FROM now())::bigint) \
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
        let row = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE device_id = $1 \
                AND (expires_at IS NULL OR expires_at > extract(epoch FROM now())::bigint)) AS waiting",
        )
        .bind(device)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.get("waiting"))
    }

    async fn store_franking(&self, message_id: &str, commitment: &[u8]) -> Result<(), StoreError> {
        let id = parse_uuid(message_id, "Hüllen-ID")?;
        // Idempotent: derselbe Fan-out schreibt für dieselbe ID dasselbe
        // Commitment; ON CONFLICT lässt den ersten Eintrag stehen.
        sqlx::query(
            "INSERT INTO franking_log (message_id, commitment) VALUES ($1, $2) \
             ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(id)
        .bind(commitment)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn franking_commitment(&self, message_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let id = parse_uuid(message_id, "Hüllen-ID")?;
        let row = sqlx::query("SELECT commitment FROM franking_log WHERE message_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>("commitment")))
    }

    async fn set_block(&self, owner: &str, blocked: &str, block: bool) -> Result<(), StoreError> {
        if block {
            sqlx::query(
                "INSERT INTO blocks (owner_handle, blocked_handle) VALUES ($1, $2) \
                 ON CONFLICT (owner_handle, blocked_handle) DO NOTHING",
            )
            .bind(owner)
            .bind(blocked)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        } else {
            sqlx::query("DELETE FROM blocks WHERE owner_handle = $1 AND blocked_handle = $2")
                .bind(owner)
                .bind(blocked)
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        }
        Ok(())
    }

    async fn is_blocked(&self, owner: &str, sender: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE owner_handle = $1 AND blocked_handle = $2) AS blocked",
        )
        .bind(owner)
        .bind(sender)
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.get("blocked"))
    }

    async fn list_blocks(&self, owner: &str) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT blocked_handle FROM blocks WHERE owner_handle = $1 ORDER BY blocked_handle",
        )
        .bind(owner)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        Ok(rows.iter().map(|r| r.get("blocked_handle")).collect())
    }

    async fn save_push_subscription(
        &self,
        device_id: &str,
        subscription: &PushSubscription,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO push_subscriptions (device_id, endpoint, p256dh, auth) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (device_id) DO UPDATE SET \
               endpoint = EXCLUDED.endpoint, p256dh = EXCLUDED.p256dh, \
               auth = EXCLUDED.auth, created_at = now()",
        )
        .bind(device_id)
        .bind(&subscription.endpoint)
        .bind(&subscription.p256dh)
        .bind(&subscription.auth)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn remove_push_subscription(&self, device_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM push_subscriptions WHERE device_id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn remove_push_subscription_if_endpoint(
        &self,
        device_id: &str,
        endpoint: &str,
    ) -> Result<(), StoreError> {
        // Bedingtes Löschen in einer Anweisung (atomar): nur wenn der Endpoint
        // noch der gemeldete ist, sonst bleibt ein erneuertes Abo stehen.
        sqlx::query("DELETE FROM push_subscriptions WHERE device_id = $1 AND endpoint = $2")
            .bind(device_id)
            .bind(endpoint)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn push_subscription(
        &self,
        device_id: &str,
    ) -> Result<Option<PushSubscription>, StoreError> {
        let row = sqlx::query(
            "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.map(|r| PushSubscription {
            endpoint: r.get("endpoint"),
            p256dh: r.get("p256dh"),
            auth: r.get("auth"),
        }))
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

/// Lädt den Vollzustand einer Gruppe innerhalb einer Transaktion mit
/// Zeilensperre (`FOR UPDATE`), damit die Regel-Funktionen aus groups.rs
/// darauf arbeiten und konkurrierende Änderungen serialisiert werden.
async fn load_record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    gid: Uuid,
) -> Result<GroupRecord, GroupError> {
    let row = sqlx::query("SELECT epoch, name, settings FROM groups WHERE id = $1 FOR UPDATE")
        .bind(gid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(group_backend)?;
    let Some(row) = row else {
        return Err(GroupError::UnknownGroup);
    };
    let epoch: i64 = row.get("epoch");
    let name: String = row.get("name");
    let settings_json: String = row.get("settings");
    let settings: GroupSettings = serde_json::from_str(&settings_json).unwrap_or_default();
    let devices: Vec<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM group_devices WHERE group_id = $1 ORDER BY device_id",
    )
    .bind(gid)
    .fetch_all(&mut **tx)
    .await
    .map_err(group_backend)?;
    let role_rows = sqlx::query("SELECT handle, role FROM group_roles WHERE group_id = $1")
        .bind(gid)
        .fetch_all(&mut **tx)
        .await
        .map_err(group_backend)?;
    let mut roles = std::collections::HashMap::new();
    for r in role_rows {
        let handle: String = r.get("handle");
        let role: String = r.get("role");
        roles.insert(handle, Role::parse(&role).unwrap_or(Role::Member));
    }
    Ok(GroupRecord {
        epoch: u64::try_from(epoch).unwrap_or(0),
        devices: devices.into_iter().map(|d| d.to_string()).collect(),
        name,
        settings,
        roles,
    })
}

/// Schreibt die Rollen einer Gruppe vollständig neu (kleine Mengen). Muss zu
/// den Handles der geänderten Mitgliedschaft passen.
async fn persist_roles(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    gid: Uuid,
    roles: &std::collections::HashMap<String, Role>,
) -> Result<(), GroupError> {
    sqlx::query("DELETE FROM group_roles WHERE group_id = $1")
        .bind(gid)
        .execute(&mut **tx)
        .await
        .map_err(group_backend)?;
    for (handle, role) in roles {
        sqlx::query("INSERT INTO group_roles (group_id, handle, role) VALUES ($1, $2, $3)")
            .bind(gid)
            .bind(handle)
            .bind(role.as_str())
            .execute(&mut **tx)
            .await
            .map_err(group_backend)?;
    }
    Ok(())
}

async fn persist_devices(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    gid: Uuid,
    devices: &[String],
) -> Result<(), GroupError> {
    sqlx::query("DELETE FROM group_devices WHERE group_id = $1")
        .bind(gid)
        .execute(&mut **tx)
        .await
        .map_err(group_backend)?;
    for device in devices {
        let did = parse_group_uuid(device)?;
        sqlx::query("INSERT INTO group_devices (group_id, device_id) VALUES ($1, $2)")
            .bind(gid)
            .bind(did)
            .execute(&mut **tx)
            .await
            .map_err(group_backend)?;
    }
    Ok(())
}

#[async_trait]
impl GroupStore for PgGroupStore {
    async fn create_group(&self, group_id: &str, new: NewGroup<'_>) -> Result<(), GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let settings_json = serde_json::to_string(&GroupSettings::default())
            .map_err(|e| GroupError::Backend(e.to_string()))?;
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let inserted = sqlx::query(
            "INSERT INTO groups (id, epoch, name, settings) VALUES ($1, 0, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(gid)
        .bind(new.name)
        .bind(&settings_json)
        .execute(&mut *tx)
        .await
        .map_err(group_backend)?;
        if inserted.rows_affected() == 0 {
            return Err(GroupError::GroupExists);
        }
        persist_devices(&mut tx, gid, &dedup(new.devices)).await?;
        // Rollen: Ersteller Owner, restliche Mitglieder Member.
        let mut roles = std::collections::HashMap::new();
        for handle in new.member_handles {
            roles.insert(handle.clone(), Role::Member);
        }
        roles.insert(new.creator.to_string(), Role::Owner);
        persist_roles(&mut tx, gid, &roles).await?;
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

    async fn meta(&self, group_id: &str, reader: &str) -> Result<GroupMeta, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let record = load_record(&mut tx, gid).await?;
        record.require_member(reader)?;
        Ok(record.meta())
    }

    async fn commit(&self, group_id: &str, ctx: CommitContext<'_>) -> Result<u64, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        // Geräte-IDs früh validieren, bevor Zustand geändert wird.
        for d in ctx.new_devices {
            parse_group_uuid(d)?;
        }
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let mut record = load_record(&mut tx, gid).await?;
        // Dieselbe reine Zustandsregel wie der InMemory-Store (Epoche,
        // Autorisierung, Rollen, epoch++); nur die Geräte-/Rollen-Persistenz
        // ist hier SQL.
        let epoch = apply_commit(&mut record, &ctx)?;
        sqlx::query("UPDATE groups SET epoch = $2 WHERE id = $1")
            .bind(gid)
            .bind(i64::try_from(epoch).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(group_backend)?;
        persist_devices(&mut tx, gid, &dedup(ctx.new_devices)).await?;
        persist_roles(&mut tx, gid, &record.roles).await?;
        tx.commit().await.map_err(group_backend)?;
        Ok(record.epoch)
    }

    async fn set_role(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
        role: Role,
    ) -> Result<GroupMeta, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let mut record = load_record(&mut tx, gid).await?;
        apply_set_role(&mut record, actor, target, role)?;
        persist_roles(&mut tx, gid, &record.roles).await?;
        tx.commit().await.map_err(group_backend)?;
        Ok(record.meta())
    }

    async fn transfer_ownership(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
    ) -> Result<GroupMeta, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let mut record = load_record(&mut tx, gid).await?;
        apply_transfer(&mut record, actor, target)?;
        persist_roles(&mut tx, gid, &record.roles).await?;
        tx.commit().await.map_err(group_backend)?;
        Ok(record.meta())
    }

    async fn update_info(
        &self,
        group_id: &str,
        actor: &str,
        name: Option<&str>,
        settings: Option<GroupSettings>,
    ) -> Result<GroupMeta, GroupError> {
        let gid = parse_group_uuid(group_id)?;
        let mut tx = self.pool.begin().await.map_err(group_backend)?;
        let mut record = load_record(&mut tx, gid).await?;
        apply_update_info(&mut record, actor, name, settings)?;
        let settings_json = serde_json::to_string(&record.settings)
            .map_err(|e| GroupError::Backend(e.to_string()))?;
        sqlx::query("UPDATE groups SET name = $2, settings = $3 WHERE id = $1")
            .bind(gid)
            .bind(&record.name)
            .bind(&settings_json)
            .execute(&mut *tx)
            .await
            .map_err(group_backend)?;
        tx.commit().await.map_err(group_backend)?;
        Ok(record.meta())
    }
}
