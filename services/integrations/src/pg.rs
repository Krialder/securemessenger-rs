//! PostgreSQL-Umsetzung des TenantStore (Schema in migrations/).

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::Tenant;
use crate::store::{NewTenant, StoreError, TenantStore};

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

pub struct PgTenantStore {
    pool: PgPool,
}

impl PgTenantStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn backend(err: sqlx::Error) -> StoreError {
    StoreError::Backend(err.to_string())
}

fn parse_uuid(value: &str, what: &str) -> Result<Uuid, StoreError> {
    // Die UUIDs erzeugt api.rs beim Anlegen; unparsebar hieße Programmierfehler.
    Uuid::try_parse(value).map_err(|_| StoreError::Backend(format!("{what} ist keine UUID")))
}

fn row_to_tenant(row: &sqlx::postgres::PgRow) -> Tenant {
    let id: Uuid = row.get("id");
    let rate_limit: i32 = row.get("rate_limit");
    Tenant {
        id: id.to_string(),
        name: row.get("name"),
        client_id: row.get("oidc_client_id"),
        scopes: row.get("scopes"),
        rate_limit: rate_limit.max(0) as u32,
        // In SQL berechnet (disabled_at IS NOT NULL), weil das
        // Workspace-sqlx bewusst ohne time-Feature auskommt.
        disabled: row.get("disabled"),
    }
}

#[async_trait]
impl TenantStore for PgTenantStore {
    async fn create(&self, tenant: NewTenant) -> Result<(), StoreError> {
        let id = parse_uuid(&tenant.id, "Mandanten-ID")?;
        let result = sqlx::query(
            "INSERT INTO integration_tenants \
                 (id, name, oidc_client_id, secret_hash, scopes, rate_limit) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(&tenant.name)
        .bind(&tenant.client_id)
        .bind(&tenant.secret_hash)
        .bind(&tenant.scopes)
        .bind(tenant.rate_limit as i32)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            // 23505 = unique_violation: Name oder Client-ID schon vergeben.
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                Err(StoreError::NameTaken)
            }
            Err(err) => Err(backend(err)),
        }
    }

    async fn find_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<(Tenant, String)>, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, oidc_client_id, secret_hash, scopes, rate_limit, \
                    (disabled_at IS NOT NULL) AS disabled \
             FROM integration_tenants WHERE oidc_client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.map(|row| {
            let secret_hash: String = row.get("secret_hash");
            (row_to_tenant(&row), secret_hash)
        }))
    }

    async fn save_token(
        &self,
        token_hash: &str,
        tenant_id: &str,
        scopes: &[String],
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let tenant = parse_uuid(tenant_id, "Mandanten-ID")?;
        // Abgelaufene Tokens beim Tausch wegräumen: billig, hält die
        // Tabelle klein und braucht keinen eigenen Wartungsjob.
        sqlx::query("DELETE FROM integration_tokens WHERE expires_at < now()")
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        sqlx::query(
            "INSERT INTO integration_tokens (token_hash, tenant_id, scopes, expires_at) \
             VALUES ($1, $2, $3, to_timestamp($4))",
        )
        .bind(token_hash)
        .bind(tenant)
        .bind(scopes)
        .bind(expires_at as f64)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<Tenant>, StoreError> {
        // k.scopes AS scopes: der zurückgegebene Mandant trägt bewusst die
        // *Token*-Scopes, nicht t.scopes; row_to_tenant liest sie als scopes.
        let row = sqlx::query(
            "SELECT t.id, t.name, t.oidc_client_id, k.scopes AS scopes, t.rate_limit, \
                    (t.disabled_at IS NOT NULL) AS disabled \
             FROM integration_tokens k \
             JOIN integration_tenants t ON t.id = k.tenant_id \
             WHERE k.token_hash = $1 AND k.expires_at > now() AND t.disabled_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(row.map(|row| row_to_tenant(&row)))
    }
}
