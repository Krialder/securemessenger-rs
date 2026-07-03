//! Speicher-Abstraktion für Mandanten und ihre Tokens.
//!
//! Wie in den anderen Diensten: ein Trait, zwei Umsetzungen (In-Memory
//! hier, PostgreSQL in pg.rs), beide mit derselben Semantik.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::domain::Tenant;

#[derive(Debug)]
pub enum StoreError {
    /// Name oder Client-ID schon vergeben.
    NameTaken,
    /// Ablage kaputt oder nicht erreichbar; wird beim Aufrufer 500.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NameTaken => write!(f, "Name ist schon vergeben"),
            StoreError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
        }
    }
}

/// Neuer Mandant, wie ihn die interne Anlage-Route liefert.
#[derive(Debug, Clone)]
pub struct NewTenant {
    pub id: String,
    pub name: String,
    pub client_id: String,
    /// Argon2id-PHC-String; das Klartext-Secret sieht nur der Aufrufer.
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub rate_limit: u32,
}

#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Legt einen Mandanten an; Name und Client-ID sind eindeutig.
    async fn create(&self, tenant: NewTenant) -> Result<(), StoreError>;

    /// Mandant samt Secret-Hash für den Token-Tausch. Auch gesperrte
    /// Mandanten kommen zurück; die Sperre bewertet die API-Schicht,
    /// damit sie einheitlich (401) antworten kann.
    async fn find_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<(Tenant, String)>, StoreError>;

    /// Legt ein Token (als Hash) mit Ablaufzeit ab und räumt bei der
    /// Gelegenheit abgelaufene Tokens weg.
    async fn save_token(
        &self,
        token_hash: &str,
        tenant_id: &str,
        expires_at: u64,
    ) -> Result<(), StoreError>;

    /// Löst einen Token-Hash zum Mandanten auf; None = unbekannt,
    /// abgelaufen oder Mandant gesperrt.
    async fn find_token(&self, token_hash: &str) -> Result<Option<Tenant>, StoreError>;
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}

#[derive(Default)]
struct Inner {
    /// client_id -> (Tenant, secret_hash)
    tenants: HashMap<String, (Tenant, String)>,
    /// token_hash -> (tenant_id, expires_at)
    tokens: HashMap<String, (String, u64)>,
}

/// Prozesslokale Umsetzung für Entwicklung und Tests.
#[derive(Default)]
pub struct InMemoryTenantStore {
    inner: Mutex<Inner>,
}

#[async_trait]
impl TenantStore for InMemoryTenantStore {
    async fn create(&self, tenant: NewTenant) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let name_taken = inner
            .tenants
            .values()
            .any(|(t, _)| t.name == tenant.name || t.client_id == tenant.client_id);
        if name_taken {
            return Err(StoreError::NameTaken);
        }
        inner.tenants.insert(
            tenant.client_id.clone(),
            (
                Tenant {
                    id: tenant.id,
                    name: tenant.name,
                    client_id: tenant.client_id,
                    scopes: tenant.scopes,
                    rate_limit: tenant.rate_limit,
                    disabled: false,
                },
                tenant.secret_hash,
            ),
        );
        Ok(())
    }

    async fn find_by_client_id(
        &self,
        client_id: &str,
    ) -> Result<Option<(Tenant, String)>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner.tenants.get(client_id).cloned())
    }

    async fn save_token(
        &self,
        token_hash: &str,
        tenant_id: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let now = now_epoch();
        inner.tokens.retain(|_, (_, expiry)| *expiry > now);
        inner
            .tokens
            .insert(token_hash.to_string(), (tenant_id.to_string(), expires_at));
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<Tenant>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let Some((tenant_id, expires_at)) = inner.tokens.get(token_hash) else {
            return Ok(None);
        };
        if *expires_at <= now_epoch() {
            return Ok(None);
        }
        let tenant = inner
            .tenants
            .values()
            .find(|(t, _)| &t.id == tenant_id)
            .map(|(t, _)| t.clone())
            .filter(|t| !t.disabled);
        Ok(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_tenant(name: &str) -> NewTenant {
        NewTenant {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            client_id: name.to_string(),
            secret_hash: "phc-platzhalter".to_string(),
            scopes: vec!["notify".to_string()],
            rate_limit: 60,
        }
    }

    #[tokio::test]
    async fn create_enforces_unique_names() {
        let store = InMemoryTenantStore::default();
        store.create(new_tenant("azubi-os")).await.unwrap();
        assert!(matches!(
            store.create(new_tenant("azubi-os")).await,
            Err(StoreError::NameTaken)
        ));
    }

    #[tokio::test]
    async fn token_roundtrip_and_expiry() {
        let store = InMemoryTenantStore::default();
        let tenant = new_tenant("projekt");
        let tenant_id = tenant.id.clone();
        store.create(tenant).await.unwrap();

        store
            .save_token("hash-gueltig", &tenant_id, now_epoch() + 3600)
            .await
            .unwrap();
        store
            .save_token("hash-abgelaufen", &tenant_id, now_epoch().saturating_sub(1))
            .await
            .unwrap();

        let found = store.find_token("hash-gueltig").await.unwrap().unwrap();
        assert_eq!(found.id, tenant_id);
        assert!(store.find_token("hash-abgelaufen").await.unwrap().is_none());
        assert!(store.find_token("hash-unbekannt").await.unwrap().is_none());
    }
}
