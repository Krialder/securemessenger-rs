//! PostgreSQL-Umsetzung der Stores (sqlx, Schema in migrations/).
//!
//! Übersetzungsschicht zwischen Domain und Ablage: Die Domain spricht
//! Base64-Strings (das JSON-Format der API), die Datenbank BYTEA und UUID
//! (datenmodell.md). Die Konvertierung lebt genau hier, damit weder die
//! Handler noch das Schema die jeweils andere Form kennen müssen.
//!
//! Fachliche Konflikte kommen als Constraint-Verletzungen zurück
//! (accounts_handle_key, devices_pkey) und werden auf StoreError abgebildet;
//! so bleibt die Eindeutigkeit auch unter parallelen Requests von der
//! Datenbank garantiert statt von Anwendungs-Checks.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::{Account, Device};
use crate::session::{RefreshError, SessionConfig, SessionIdentity, SessionStore};
use crate::store::{AccountStore, StoreError};

/// Baut den Verbindungspool und fährt die eingebetteten Migrationen.
/// Läuft beim Dienststart; schlägt eine Migration fehl, soll der Prozess
/// gar nicht erst Requests annehmen.
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

/// Konten und Geräte in PostgreSQL.
pub struct PgAccountStore {
    pool: PgPool,
}

impl PgAccountStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Dekodiert einen Base64-Wert, der die API-Validierung bereits passiert
/// hat. Ein Fehlschlag hier ist ein Programmierfehler, kein Nutzerfehler,
/// deshalb Backend-Fehler statt 4xx.
fn decode_checked(value: &str, what: &str) -> Result<Vec<u8>, StoreError> {
    BASE64
        .decode(value)
        .map_err(|e| StoreError::Backend(format!("{what} ist kein Base64 mehr: {e}")))
}

/// Geräte-IDs sind UUIDs (API-Validierung); parse für den UUID-Spaltentyp.
fn parse_device_id(id: &str) -> Result<Uuid, StoreError> {
    Uuid::try_parse(id).map_err(|e| StoreError::Backend(format!("Geräte-ID keine UUID mehr: {e}")))
}

/// Übersetzt Unique-Constraint-Verletzungen in fachliche Fehler; alles
/// andere ist ein Backend-Fehler.
fn map_conflict(e: sqlx::Error) -> StoreError {
    if let Some(db) = e.as_database_error() {
        match db.constraint() {
            Some("accounts_handle_key") => return StoreError::HandleTaken,
            Some("devices_pkey") => return StoreError::DeviceIdTaken,
            _ => {}
        }
    }
    StoreError::Backend(e.to_string())
}

fn backend(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn row_to_device(row: &sqlx::postgres::PgRow) -> Device {
    let id: Uuid = row.get("id");
    let identity_key: Vec<u8> = row.get("identity_key");
    let credential_blob: Vec<u8> = row.get("credential_blob");
    let not_after: i64 = row.get("not_after");
    let revoked: bool = row.get("revoked");
    let protocol_device_id: i16 = row.get("protocol_device_id");
    Device {
        id: id.to_string(),
        name: row.get("name"),
        public_key: BASE64.encode(identity_key),
        credential: BASE64.encode(credential_blob),
        // Nie negativ, weil nur validierte Werte geschrieben werden;
        // defensiv klemmt unsigned_abs Unsinn auf einen Ablauf in der
        // Vergangenheit statt in der fernen Zukunft.
        not_after: u64::try_from(not_after).unwrap_or(0),
        revoked,
        // SMALLINT ist i16; die Vergabe hält 1..255, also passt es in u16.
        protocol_device_id: u16::try_from(protocol_device_id).unwrap_or(0),
    }
}

#[async_trait]
impl AccountStore for PgAccountStore {
    async fn create(&self, account: Account, first_device: Device) -> Result<(), StoreError> {
        let identity_key = decode_checked(&account.identity_key, "Konto-Identitätsschlüssel")?;
        let device_key = decode_checked(&first_device.public_key, "Geräteschlüssel")?;
        let credential = decode_checked(&first_device.credential, "Credential")?;
        let device_id = parse_device_id(&first_device.id)?;
        // Eine Transaktion für Konto plus erstes Gerät: entweder entstehen
        // beide oder keines (Aggregat-Invariante aus store.rs).
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Die UUID erzeugt api.rs beim Anlegen; unparsebar hieße Programmierfehler.
        let account_id = Uuid::try_parse(&account.id)
            .map_err(|e| StoreError::Backend(format!("Konto-ID keine UUID: {e}")))?;
        sqlx::query(
            "INSERT INTO accounts (id, handle, display_name, password_hash, identity_key) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(account_id)
        .bind(&account.handle)
        .bind(&account.display_name)
        .bind(&account.password_hash)
        .bind(&identity_key)
        .execute(&mut *tx)
        .await
        .map_err(map_conflict)?;
        // Das erste Gerät ist Nummer 1 (kein anderes existiert).
        sqlx::query(
            "INSERT INTO devices \
                 (id, account_id, name, identity_key, credential_blob, not_after, protocol_device_id) \
             VALUES ($1, $2, $3, $4, $5, $6, 1)",
        )
        .bind(device_id)
        .bind(account_id)
        .bind(&first_device.name)
        .bind(&device_key)
        .bind(&credential)
        .bind(first_device.not_after as i64)
        .execute(&mut *tx)
        .await
        .map_err(map_conflict)?;
        tx.commit().await.map_err(backend)
    }

    async fn get(&self, handle: &str) -> Result<Option<Account>, StoreError> {
        // deletion_pending_until ist TIMESTAMPTZ; als Unix-Sekunden
        // (BIGINT-Epoche) lesen, damit kein sqlx-Zeit-Feature nötig ist und
        // der Wert zum u64-Feld im Fachmodell passt.
        let row = sqlx::query(
            "SELECT id, handle, display_name, password_hash, identity_key, \
                    EXTRACT(EPOCH FROM deletion_pending_until)::BIGINT AS deletion_epoch \
             FROM accounts WHERE handle = $1",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.map(|r| {
            let identity_key: Vec<u8> = r.get("identity_key");
            let id: Uuid = r.get("id");
            let deletion_epoch: Option<i64> = r.get("deletion_epoch");
            Account {
                id: id.to_string(),
                handle: r.get("handle"),
                display_name: r.get("display_name"),
                password_hash: r.get("password_hash"),
                identity_key: BASE64.encode(identity_key),
                deletion_pending_until: deletion_epoch.and_then(|e| u64::try_from(e).ok()),
            }
        }))
    }

    async fn set_password_hash(&self, handle: &str, password_hash: &str) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE accounts SET password_hash = $2 WHERE handle = $1")
            .bind(handle)
            .bind(password_hash)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::AccountMissing);
        }
        Ok(())
    }

    async fn set_display_name(&self, handle: &str, display_name: &str) -> Result<(), StoreError> {
        let result = sqlx::query("UPDATE accounts SET display_name = $2 WHERE handle = $1")
            .bind(handle)
            .bind(display_name)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::AccountMissing);
        }
        Ok(())
    }

    async fn schedule_deletion(&self, handle: &str, deletion_at: u64) -> Result<(), StoreError> {
        // Die Frist als Unix-Sekunden in TIMESTAMPTZ setzen (to_timestamp),
        // status auf deletion_pending. Reines SQL, keine Rust-Zeitarithmetik.
        let result = sqlx::query(
            "UPDATE accounts \
             SET status = 'deletion_pending', deletion_pending_until = to_timestamp($2) \
             WHERE handle = $1",
        )
        .bind(handle)
        .bind(deletion_at as i64)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::AccountMissing);
        }
        Ok(())
    }

    async fn cancel_deletion(&self, handle: &str) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE accounts SET status = 'active', deletion_pending_until = NULL \
             WHERE handle = $1",
        )
        .bind(handle)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::AccountMissing);
        }
        Ok(())
    }

    async fn purge_deleted(&self, now: u64) -> Result<u64, StoreError> {
        // Discovery hat keinen Fremdschlüssel auf accounts, also zuerst die
        // Discovery-Einträge der fälligen Konten löschen; die accounts-Zeile
        // kaskadiert dann Geräte, Sessions und Refresh-Hashes über die
        // Fremdschlüssel (Crypto-Shredding). Eine Transaktion, damit kein
        // halber Zustand entsteht.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query(
            "DELETE FROM discovery WHERE account_id IN \
             (SELECT id FROM accounts \
              WHERE deletion_pending_until IS NOT NULL \
                AND deletion_pending_until <= to_timestamp($1))",
        )
        .bind(now as i64)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        let result = sqlx::query(
            "DELETE FROM accounts \
             WHERE deletion_pending_until IS NOT NULL \
               AND deletion_pending_until <= to_timestamp($1)",
        )
        .bind(now as i64)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(result.rows_affected())
    }

    async fn add_device(&self, handle: &str, device: Device) -> Result<u16, StoreError> {
        let device_key = decode_checked(&device.public_key, "Geräteschlüssel")?;
        let credential = decode_checked(&device.credential, "Credential")?;
        let device_id = parse_device_id(&device.id)?;
        // Transaktion mit Zeilensperre auf dem Konto: die Nummernvergabe
        // (max + 1) und das Einfügen dürfen sich mit einem parallelen
        // add_device desselben Kontos nicht überschneiden, sonst bekämen
        // zwei Geräte dieselbe Nummer.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let account_row = sqlx::query("SELECT id FROM accounts WHERE handle = $1 FOR UPDATE")
            .bind(handle)
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
        let Some(account_row) = account_row else {
            return Err(StoreError::AccountMissing);
        };
        let account_id: Uuid = account_row.get("id");
        // Max über ALLE Geräte des Kontos, auch revozierte: ihre Nummern
        // bleiben gesperrt (revozieren gibt die Nummer nicht frei).
        let next_row = sqlx::query(
            "SELECT COALESCE(MAX(protocol_device_id), 0) + 1 AS next \
             FROM devices WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        let next: i32 = next_row.get("next");
        if next > i32::from(crate::domain::MAX_PROTOCOL_DEVICE_ID) {
            return Err(StoreError::TooManyDevices);
        }
        sqlx::query(
            "INSERT INTO devices \
                 (id, account_id, name, identity_key, credential_blob, not_after, protocol_device_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(device_id)
        .bind(account_id)
        .bind(&device.name)
        .bind(&device_key)
        .bind(&credential)
        .bind(device.not_after as i64)
        .bind(next as i16)
        .execute(&mut *tx)
        .await
        .map_err(map_conflict)?;
        tx.commit().await.map_err(backend)?;
        Ok(next as u16)
    }

    async fn devices(&self, handle: &str) -> Result<Vec<Device>, StoreError> {
        let rows = sqlx::query(
            "SELECT d.id, d.name, d.identity_key, d.credential_blob, d.not_after, \
                    d.protocol_device_id, (d.revoked_at IS NOT NULL) AS revoked \
             FROM devices d JOIN accounts a ON a.id = d.account_id \
             WHERE a.handle = $1 ORDER BY d.added_at",
        )
        .bind(handle)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        Ok(rows.iter().map(row_to_device).collect())
    }

    async fn get_device(
        &self,
        handle: &str,
        device_id: &str,
    ) -> Result<Option<Device>, StoreError> {
        // Keine UUID heißt: kann nicht existieren. Kein Fehler, weil die
        // Anfrage aus Nutzereingaben stammen darf (Login mit device_id).
        let Ok(device_id) = Uuid::try_parse(device_id) else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT d.id, d.name, d.identity_key, d.credential_blob, d.not_after, \
                    d.protocol_device_id, (d.revoked_at IS NOT NULL) AS revoked \
             FROM devices d JOIN accounts a ON a.id = d.account_id \
             WHERE a.handle = $1 AND d.id = $2",
        )
        .bind(handle)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.as_ref().map(row_to_device))
    }

    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), StoreError> {
        let Ok(device_id) = Uuid::try_parse(device_id) else {
            return Err(StoreError::DeviceNotFound);
        };
        let result = sqlx::query(
            "UPDATE devices d SET revoked_at = now() \
             FROM accounts a \
             WHERE d.account_id = a.id AND a.handle = $1 AND d.id = $2 \
               AND d.revoked_at IS NULL",
        )
        .bind(handle)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::DeviceNotFound);
        }
        Ok(())
    }

    async fn index_discovery(
        &self,
        prf_hex: &str,
        record: crate::store::DiscoveryRecord,
    ) -> Result<(), StoreError> {
        let account_id = Uuid::try_parse(&record.id)
            .map_err(|e| StoreError::Backend(format!("Konto-ID keine UUID: {e}")))?;
        // Idempotent: eine erneute Registrierung desselben Handles (nach
        // Löschung) oder ein Nachtrag überschreibt den Eintrag.
        sqlx::query(
            "INSERT INTO discovery (prf, account_id, handle, identity_key) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (prf) DO UPDATE SET \
                 account_id = EXCLUDED.account_id, \
                 handle = EXCLUDED.handle, \
                 identity_key = EXCLUDED.identity_key",
        )
        .bind(prf_hex)
        .bind(account_id)
        .bind(&record.handle)
        .bind(&record.identity_key)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn discovery_lookup(
        &self,
        prf_hex: &str,
    ) -> Result<Option<crate::store::DiscoveryRecord>, StoreError> {
        let row =
            sqlx::query("SELECT account_id, handle, identity_key FROM discovery WHERE prf = $1")
                .bind(prf_hex)
                .fetch_optional(&self.pool)
                .await
                .map_err(backend)?;
        Ok(row.map(|r| {
            let id: Uuid = r.get("account_id");
            crate::store::DiscoveryRecord {
                handle: r.get("handle"),
                id: id.to_string(),
                identity_key: r.get("identity_key"),
            }
        }))
    }
}

/// Session-Familien in PostgreSQL. Ablaufzeiten als Unix-Sekunden (BIGINT),
/// gleiche Semantik wie In-Memory: gültig bis ausschließlich Ablauf.
pub struct PgSessionStore {
    pool: PgPool,
    config: SessionConfig,
}

impl PgSessionStore {
    pub fn new(pool: PgPool, config: SessionConfig) -> Self {
        Self { pool, config }
    }

    fn expiries(&self) -> (i64, i64, i64) {
        let now = now_unix();
        (
            now,
            now + self.config.access_ttl.as_secs() as i64,
            now + self.config.refresh_ttl.as_secs() as i64,
        )
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Systemzeit liegt nach 1970")
        .as_secs() as i64
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn create(
        &self,
        identity: SessionIdentity,
        access_hash: String,
        refresh_hash: String,
    ) -> Result<(), String> {
        let device_id =
            Uuid::try_parse(&identity.device_id).map_err(|e| format!("Geräte-ID: {e}"))?;
        let (now, access_exp, refresh_exp) = self.expiries();
        // Aufräumen wie in der In-Memory-Version bei jedem Login; hält die
        // Tabelle klein, ohne einen eigenen Hintergrund-Job zu brauchen.
        sqlx::query(
            "DELETE FROM session_families WHERE access_expires_at <= $1 AND refresh_expires_at <= $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        let result = sqlx::query(
            "INSERT INTO session_families \
             (account_id, device_id, access_hash, access_expires_at, refresh_hash, refresh_expires_at) \
             SELECT a.id, $2, $3, $4, $5, $6 FROM accounts a WHERE a.handle = $1",
        )
        .bind(&identity.handle)
        .bind(device_id)
        .bind(&access_hash)
        .bind(access_exp)
        .bind(&refresh_hash)
        .bind(refresh_exp)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        if result.rows_affected() == 0 {
            return Err("Konto zur Session nicht gefunden".to_string());
        }
        Ok(())
    }

    async fn authenticate(&self, access_hash: &str) -> Result<Option<SessionIdentity>, String> {
        let row = sqlx::query(
            "SELECT a.handle, s.device_id, s.access_expires_at \
             FROM session_families s JOIN accounts a ON a.id = s.account_id \
             WHERE s.access_hash = $1",
        )
        .bind(access_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        let Some(row) = row else { return Ok(None) };
        let expires_at: i64 = row.get("access_expires_at");
        if expires_at <= now_unix() {
            return Ok(None);
        }
        let device_id: Uuid = row.get("device_id");
        Ok(Some(SessionIdentity {
            handle: row.get("handle"),
            device_id: device_id.to_string(),
        }))
    }

    async fn refresh(
        &self,
        presented_refresh_hash: &str,
        new_access_hash: String,
        new_refresh_hash: String,
    ) -> Result<SessionIdentity, RefreshError> {
        let map_be = |e: sqlx::Error| RefreshError::Backend(e.to_string());
        // Eine Transaktion für Prüfung und Rotation: FOR UPDATE sperrt die
        // Familie, damit zwei gleichzeitige Refreshes desselben Tokens nicht
        // beide durchkommen; der zweite sieht dann den used-Eintrag.
        let mut tx = self.pool.begin().await.map_err(map_be)?;

        // Reuse zuerst: ein rotiertes Token führt über used_refresh_hashes
        // zur Familie zurück, die daraufhin komplett stirbt (RFC 9700).
        let used = sqlx::query("SELECT family_id FROM used_refresh_hashes WHERE refresh_hash = $1")
            .bind(presented_refresh_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_be)?;
        if let Some(row) = used {
            let family_id: i64 = row.get("family_id");
            sqlx::query("DELETE FROM session_families WHERE id = $1")
                .bind(family_id)
                .execute(&mut *tx)
                .await
                .map_err(map_be)?;
            tx.commit().await.map_err(map_be)?;
            return Err(RefreshError::ReuseDetected);
        }

        let row = sqlx::query(
            "SELECT id, account_id, device_id, refresh_expires_at \
             FROM session_families WHERE refresh_hash = $1 FOR UPDATE",
        )
        .bind(presented_refresh_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_be)?;
        let Some(row) = row else {
            return Err(RefreshError::Invalid);
        };
        let family_id: i64 = row.get("id");
        let account_id: Uuid = row.get("account_id");
        let device_id: Uuid = row.get("device_id");
        let refresh_expires_at: i64 = row.get("refresh_expires_at");

        let (now, access_exp, refresh_exp) = self.expiries();
        if refresh_expires_at <= now {
            sqlx::query("DELETE FROM session_families WHERE id = $1")
                .bind(family_id)
                .execute(&mut *tx)
                .await
                .map_err(map_be)?;
            tx.commit().await.map_err(map_be)?;
            return Err(RefreshError::Invalid);
        }

        sqlx::query("INSERT INTO used_refresh_hashes (refresh_hash, family_id) VALUES ($1, $2)")
            .bind(presented_refresh_hash)
            .bind(family_id)
            .execute(&mut *tx)
            .await
            .map_err(map_be)?;
        sqlx::query(
            "UPDATE session_families \
             SET access_hash = $2, access_expires_at = $3, refresh_hash = $4, refresh_expires_at = $5 \
             WHERE id = $1",
        )
        .bind(family_id)
        .bind(&new_access_hash)
        .bind(access_exp)
        .bind(&new_refresh_hash)
        .bind(refresh_exp)
        .execute(&mut *tx)
        .await
        .map_err(map_be)?;
        let handle_row = sqlx::query("SELECT handle FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_be)?;
        tx.commit().await.map_err(map_be)?;
        Ok(SessionIdentity {
            handle: handle_row.get("handle"),
            device_id: device_id.to_string(),
        })
    }

    async fn revoke_by_access(&self, access_hash: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM session_families WHERE access_hash = $1")
            .bind(access_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), String> {
        let Ok(device_id) = Uuid::try_parse(device_id) else {
            return Ok(());
        };
        sqlx::query(
            "DELETE FROM session_families s USING accounts a \
             WHERE s.account_id = a.id AND a.handle = $1 AND s.device_id = $2",
        )
        .bind(handle)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
