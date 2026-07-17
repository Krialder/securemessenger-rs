//! Speicher-Abstraktion für Mandanten und ihre Tokens.
//!
//! Wie in den anderen Diensten: ein Trait, zwei Umsetzungen (In-Memory
//! hier, PostgreSQL in pg.rs), beide mit derselben Semantik.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::domain::{
    delivery_backoff_secs, event_required_scope, OutboxDelivery, Tenant, WebhookEndpoint,
    MAX_DELIVERY_ATTEMPTS,
};

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

    /// Legt ein Token (als Hash) mit den gewährten Scopes und der
    /// Ablaufzeit ab und räumt bei der Gelegenheit abgelaufene Tokens weg.
    /// Die Scopes sind eine Teilmenge der Mandanten-Rechte (Least Privilege
    /// je Token, F100): so kann ein Fremdprojekt bewusst enge Tokens
    /// ausstellen, statt jedem Token die vollen Rechte zu geben.
    async fn save_token(
        &self,
        token_hash: &str,
        tenant_id: &str,
        scopes: &[String],
        expires_at: u64,
    ) -> Result<(), StoreError>;

    /// Löst einen Token-Hash zum Mandanten auf; None = unbekannt,
    /// abgelaufen oder Mandant gesperrt. Der zurückgegebene Mandant trägt
    /// die *Token*-Scopes (nicht zwingend die vollen Mandanten-Scopes),
    /// damit die Autorisierung transparent das enge Token durchsetzt.
    async fn find_token(&self, token_hash: &str) -> Result<Option<Tenant>, StoreError>;

    /// Legt einen Webhook-Endpunkt an, aber nur, wenn der Mandant noch unter
    /// `max_per_tenant` Endpunkten liegt. `false` = der Deckel ist erreicht.
    /// Zaehlen und Einfuegen laufen atomar (eine Sperre bzw. eine Anweisung),
    /// damit gleichzeitige Anlagen den Deckel nicht ueberrennen.
    async fn create_webhook(
        &self,
        endpoint: WebhookEndpoint,
        max_per_tenant: usize,
    ) -> Result<bool, StoreError>;

    /// Alle Webhook-Endpunkte eines Mandanten (fuer die Selbstverwaltung),
    /// stabil nach (created_at, id) sortiert (beide Ablagen gleich).
    async fn list_webhooks(&self, tenant_id: &str) -> Result<Vec<WebhookEndpoint>, StoreError>;

    /// Loescht einen Endpunkt des Mandanten; `false` = es gab keinen mit
    /// dieser ID bei diesem Mandanten (fuer 404, ohne fremde IDs zu verraten).
    /// Die ID ist eine kanonische UUID (der Aufrufer normalisiert sie).
    async fn delete_webhook(&self, tenant_id: &str, id: &str) -> Result<bool, StoreError>;

    /// Alle Endpunkte (ueber alle Mandanten), die ein Ereignis fuer einen
    /// Handle abonniert haben UND deren Mandant nicht gesperrt ist und den
    /// noetigen Scope noch hat. Grundlage der Zustellung: die Berechtigung
    /// wird hier zur Zustellzeit erneut geprueft, nicht nur bei der Anlage.
    async fn find_webhook_subscribers(
        &self,
        handle: &str,
        event: &str,
    ) -> Result<Vec<WebhookEndpoint>, StoreError>;

    /// Reiht eine Zustellung in die Outbox ein (faellig sofort).
    async fn enqueue_webhook_delivery(&self, delivery: OutboxDelivery) -> Result<(), StoreError>;

    /// Nimmt bis zu `limit` faellige, noch nicht zugestellte Zustellungen in
    /// Besitz: erhoeht ihre Versuchszahl und verschiebt sie auf den naechsten
    /// Backoff (damit kein zweiter Worker sie parallel greift), und gibt sie
    /// zum Senden zurueck. Zeilen mit `attempts >= MAX_DELIVERY_ATTEMPTS`
    /// bleiben liegen (Dead Letter).
    async fn claim_due_deliveries(&self, limit: usize) -> Result<Vec<OutboxDelivery>, StoreError>;

    /// Markiert eine Zustellung als erledigt.
    async fn mark_delivery_done(&self, id: &str) -> Result<(), StoreError>;

    /// Vermerkt den letzten Fehler (der naechste Versuch ist schon beim
    /// Claim eingeplant); nur fuer die Nachvollziehbarkeit.
    async fn mark_delivery_error(&self, id: &str, error: &str) -> Result<(), StoreError>;
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}

/// Abgelegtes Token: an welchen Mandanten es gebunden ist, welche Scopes es
/// gewährt (Teilmenge der Mandanten-Rechte) und wann es verfällt.
struct TokenRecord {
    tenant_id: String,
    scopes: Vec<String>,
    expires_at: u64,
}

/// Eine Outbox-Zeile im Prozessspeicher.
struct OutboxRecord {
    url: String,
    event_type: String,
    body: Vec<u8>,
    attempts: u32,
    next_attempt_at: u64,
    delivered: bool,
    last_error: Option<String>,
}

#[derive(Default)]
struct Inner {
    /// client_id -> (Tenant, secret_hash)
    tenants: HashMap<String, (Tenant, String)>,
    /// token_hash -> TokenRecord
    tokens: HashMap<String, TokenRecord>,
    /// webhook-id -> Endpunkt
    webhooks: HashMap<String, WebhookEndpoint>,
    /// delivery-id -> Outbox-Zeile
    outbox: HashMap<String, OutboxRecord>,
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
        scopes: &[String],
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let now = now_epoch();
        inner.tokens.retain(|_, record| record.expires_at > now);
        inner.tokens.insert(
            token_hash.to_string(),
            TokenRecord {
                tenant_id: tenant_id.to_string(),
                scopes: scopes.to_vec(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<Tenant>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let Some(record) = inner.tokens.get(token_hash) else {
            return Ok(None);
        };
        if record.expires_at <= now_epoch() {
            return Ok(None);
        }
        // Der Mandant liefert Identität und Rate-Limit; die *Scopes* kommen
        // vom Token, damit ein eng ausgestelltes Token nicht die vollen
        // Mandanten-Rechte erbt.
        let tenant = inner
            .tenants
            .values()
            .find(|(t, _)| t.id == record.tenant_id)
            .map(|(t, _)| t.clone())
            .filter(|t| !t.disabled)
            .map(|t| Tenant {
                scopes: record.scopes.clone(),
                ..t
            });
        Ok(tenant)
    }

    async fn create_webhook(
        &self,
        endpoint: WebhookEndpoint,
        max_per_tenant: usize,
    ) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        // Zaehlen und Einfuegen unter DERSELBEN Sperre: kein Check-then-act,
        // das den Deckel unter gleichzeitigen Anlagen ueberrennen koennte.
        let count = inner
            .webhooks
            .values()
            .filter(|e| e.tenant_id == endpoint.tenant_id)
            .count();
        if count >= max_per_tenant {
            return Ok(false);
        }
        inner.webhooks.insert(endpoint.id.clone(), endpoint);
        Ok(true)
    }

    async fn list_webhooks(&self, tenant_id: &str) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let mut out: Vec<WebhookEndpoint> = inner
            .webhooks
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .cloned()
            .collect();
        // Stabile Reihenfolge wie PostgreSQL (created_at, id).
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn delete_webhook(&self, tenant_id: &str, id: &str) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        // Nur loeschen, wenn ID UND Mandant passen: ein Mandant darf keinen
        // fremden Endpunkt entfernen.
        let owned = inner
            .webhooks
            .get(id)
            .is_some_and(|e| e.tenant_id == tenant_id);
        if owned {
            inner.webhooks.remove(id);
        }
        Ok(owned)
    }

    async fn find_webhook_subscribers(
        &self,
        handle: &str,
        event: &str,
    ) -> Result<Vec<WebhookEndpoint>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        // Berechtigung zur Zustellzeit erneut pruefen: der Mandant darf nicht
        // gesperrt sein und muss den vom Ereignis geforderten Scope noch haben
        // (ein gesperrter oder entrechteter Mandant bekommt nichts mehr).
        let required = event_required_scope(event);
        Ok(inner
            .webhooks
            .values()
            .filter(|e| e.matches(event, handle))
            .filter(|e| {
                inner
                    .tenants
                    .values()
                    .find(|(t, _)| t.id == e.tenant_id)
                    .is_some_and(|(t, _)| {
                        !t.disabled && required.is_some_and(|scope| t.has_scope(scope))
                    })
            })
            .cloned()
            .collect())
    }

    async fn enqueue_webhook_delivery(&self, delivery: OutboxDelivery) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        inner.outbox.insert(
            delivery.id,
            OutboxRecord {
                url: delivery.url,
                event_type: delivery.event_type,
                body: delivery.body,
                attempts: 0,
                next_attempt_at: now_epoch(),
                delivered: false,
                last_error: None,
            },
        );
        Ok(())
    }

    async fn claim_due_deliveries(&self, limit: usize) -> Result<Vec<OutboxDelivery>, StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let now = now_epoch();
        // Faellige Zeilen, aelteste (frueheste next_attempt_at) zuerst.
        let mut due: Vec<(String, u64)> = inner
            .outbox
            .iter()
            .filter(|(_, r)| {
                !r.delivered && r.next_attempt_at <= now && r.attempts < MAX_DELIVERY_ATTEMPTS
            })
            .map(|(id, r)| (id.clone(), r.next_attempt_at))
            .collect();
        due.sort_by_key(|(_, next)| *next);
        let mut claimed = Vec::new();
        for (id, _) in due.into_iter().take(limit) {
            if let Some(record) = inner.outbox.get_mut(&id) {
                record.attempts += 1;
                // Naechsten Versuch schon einplanen (Claim-Lease = Backoff),
                // damit kein zweiter Durchlauf dieselbe Zeile greift.
                record.next_attempt_at = now + delivery_backoff_secs(record.attempts);
                claimed.push(OutboxDelivery {
                    id: id.clone(),
                    url: record.url.clone(),
                    event_type: record.event_type.clone(),
                    body: record.body.clone(),
                    attempts: record.attempts,
                });
            }
        }
        Ok(claimed)
    }

    async fn mark_delivery_done(&self, id: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        if let Some(record) = inner.outbox.get_mut(id) {
            record.delivered = true;
        }
        Ok(())
    }

    async fn mark_delivery_error(&self, id: &str, error: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        if let Some(record) = inner.outbox.get_mut(id) {
            record.last_error = Some(error.to_string());
        }
        Ok(())
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

        let scopes = vec!["notify".to_string()];
        store
            .save_token("hash-gueltig", &tenant_id, &scopes, now_epoch() + 3600)
            .await
            .unwrap();
        store
            .save_token(
                "hash-abgelaufen",
                &tenant_id,
                &scopes,
                now_epoch().saturating_sub(1),
            )
            .await
            .unwrap();

        let found = store.find_token("hash-gueltig").await.unwrap().unwrap();
        assert_eq!(found.id, tenant_id);
        // Der Mandant hat 'notify'; das enge Token trägt genau diesen Scope.
        assert_eq!(found.scopes, scopes);
        assert!(store.find_token("hash-abgelaufen").await.unwrap().is_none());
        assert!(store.find_token("hash-unbekannt").await.unwrap().is_none());
    }
}
