//! PostgreSQL-Umsetzung des KtStore (Schema in migrations/).

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::store::{EpochRecord, KtStore, StoreError, Update};

use async_trait::async_trait;

/// Verbindet und führt die eingebetteten Migrationen aus. Schlägt das
/// fehl, bricht der Start ab, statt still ohne Persistenz zu laufen.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, String> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|err| format!("Verbindung fehlgeschlagen: {err}"))?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .map_err(|err| format!("Migration fehlgeschlagen: {err}"))?;
    Ok(pool)
}

pub struct PgKtStore {
    pool: PgPool,
}

impl PgKtStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn backend(err: sqlx::Error) -> StoreError {
    StoreError::Backend(err.to_string())
}

fn row_to_update(row: &sqlx::postgres::PgRow) -> Update {
    let epoch: Option<i64> = row.get("epoch");
    Update {
        seq: row.get("seq"),
        handle: row.get("handle"),
        value: row.get("value"),
        epoch: epoch.map(|e| e as u64),
    }
}

fn row_to_epoch(row: &sqlx::postgres::PgRow) -> EpochRecord {
    let epoch: i64 = row.get("epoch");
    EpochRecord {
        epoch: epoch as u64,
        root_hash: row.get("root_hash"),
        signature: row.get("signature"),
    }
}

#[async_trait]
impl KtStore for PgKtStore {
    async fn queue_update(&self, handle: &str, value: &[u8]) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO kt_updates (handle, value) VALUES ($1, $2)")
            .bind(handle)
            .bind(value)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn pending_updates(&self) -> Result<Vec<Update>, StoreError> {
        let rows = sqlx::query(
            "SELECT seq, handle, value, epoch FROM kt_updates \
             WHERE epoch IS NULL ORDER BY seq",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        Ok(rows.iter().map(row_to_update).collect())
    }

    async fn published_updates(&self) -> Result<Vec<Update>, StoreError> {
        let rows = sqlx::query(
            "SELECT seq, handle, value, epoch FROM kt_updates \
             WHERE epoch IS NOT NULL ORDER BY epoch, seq",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        Ok(rows.iter().map(row_to_update).collect())
    }

    async fn publish_epoch(&self, seqs: &[i64], record: &EpochRecord) -> Result<(), StoreError> {
        // Eine Transaktion: entweder sind Updates markiert UND die
        // Wurzel liegt im Log, oder nichts von beidem. Sonst könnte die
        // Wurzelfolge Updates behaupten, die das Log nicht kennt.
        let mut tx = self.pool.begin().await.map_err(backend)?;
        sqlx::query("UPDATE kt_updates SET epoch = $1 WHERE seq = ANY($2)")
            .bind(record.epoch as i64)
            .bind(seqs)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query("INSERT INTO kt_epochs (epoch, root_hash, signature) VALUES ($1, $2, $3)")
            .bind(record.epoch as i64)
            .bind(&record.root_hash)
            .bind(&record.signature)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn epoch(&self, epoch: u64) -> Result<Option<EpochRecord>, StoreError> {
        let row = sqlx::query("SELECT epoch, root_hash, signature FROM kt_epochs WHERE epoch = $1")
            .bind(epoch as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        Ok(row.map(|r| row_to_epoch(&r)))
    }

    async fn latest_epoch(&self) -> Result<Option<EpochRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT epoch, root_hash, signature FROM kt_epochs ORDER BY epoch DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.map(|r| row_to_epoch(&r)))
    }

    async fn epochs(&self) -> Result<Vec<EpochRecord>, StoreError> {
        let rows = sqlx::query("SELECT epoch, root_hash, signature FROM kt_epochs ORDER BY epoch")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
        Ok(rows.iter().map(row_to_epoch).collect())
    }
}
