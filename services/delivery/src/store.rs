//! Speicher-Abstraktion der Zustellung plus In-Memory-Umsetzung.
//!
//! Store-and-forward (F050): Hüllen liegen, bis das Zielgerät sie
//! bestätigt. Beide Umsetzungen (hier und pg.rs) müssen dieselbe
//! Semantik zeigen: globale Deduplizierung über die Hüllen-ID,
//! Abholen ohne Wegräumen, Wegräumen erst mit dem Ack.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::domain::{NewMessage, StoreOutcome, WaitingMessage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Technischer Fehler der Ablage; wird beim Aufrufer immer 500.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
        }
    }
}

#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Legt einen Batch Hüllen ab. Bereits bekannte IDs werden still
    /// übersprungen (Idempotenz); das Ergebnis zählt beides getrennt.
    async fn store_batch(&self, messages: Vec<NewMessage>) -> Result<StoreOutcome, StoreError>;

    /// Wartende Hüllen eines Geräts in Eingangsreihenfolge, ohne sie zu
    /// entfernen: erst das Ack räumt weg, sonst verlöre ein abgestürzter
    /// Client nach dem Abholen Nachrichten.
    async fn fetch(&self, device_id: &str, limit: u32) -> Result<Vec<WaitingMessage>, StoreError>;

    /// Räumt bestätigte Hüllen des Geräts weg, liefert die Anzahl.
    /// Unbekannte IDs sind kein Fehler (Ack ist idempotent). Die
    /// Dedupe-Merker bleiben bestehen, sonst würde ein später Retry
    /// des Absenders erneut zustellen.
    async fn acknowledge(&self, device_id: &str, ids: &[String]) -> Result<u64, StoreError>;

    /// Ob für das Gerät etwas wartet (für den Hinweis beim WS-Verbinden).
    async fn has_waiting(&self, device_id: &str) -> Result<bool, StoreError>;

    /// Bewahrt das Franking-Commitment einer Hülle auf (fürs spätere
    /// Verifizieren einer Meldung). Idempotent: derselbe Fan-out legt für
    /// dieselbe Hüllen-ID dasselbe Commitment ab.
    async fn store_franking(&self, message_id: &str, commitment: &[u8]) -> Result<(), StoreError>;

    /// Das aufbewahrte Commitment einer Hülle, `None` wenn keins vorliegt.
    async fn franking_commitment(&self, message_id: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Setzt oder entfernt einen Blocklisten-Eintrag: `owner` blockiert
    /// `blocked` (`block = true`) beziehungsweise hebt das auf.
    async fn set_block(&self, owner: &str, blocked: &str, block: bool) -> Result<(), StoreError>;

    /// Ob `owner` das Handle `sender` blockiert hat.
    async fn is_blocked(&self, owner: &str, sender: &str) -> Result<bool, StoreError>;

    /// Die Blockliste von `owner` (die blockierten Handles).
    async fn list_blocks(&self, owner: &str) -> Result<Vec<String>, StoreError>;
}

struct StoredEntry {
    id: String,
    envelope: String,
    franking_tag: Option<String>,
    received_at: u64,
    expires_at: Option<u64>,
}

#[derive(Default)]
struct Inner {
    /// Alle je gesehenen Hüllen-IDs, Spiegel der message_dedupe-Tabelle.
    seen_ids: HashSet<String>,
    by_device: HashMap<String, Vec<StoredEntry>>,
    /// Franking-Commitments je Hüllen-ID (Spiegel der franking_log-Tabelle).
    franking: HashMap<String, Vec<u8>>,
    /// Blocklisten je Eigentümer-Handle (Spiegel der blocks-Tabelle).
    blocks: HashMap<String, HashSet<String>>,
}

/// Prozesslokale Ablage für Entwicklung und Tests (Daten enden mit dem
/// Prozess). Gleiche Semantik wie PgMessageStore, siehe Trait-Doku.
#[derive(Default)]
pub struct InMemoryMessageStore {
    inner: Mutex<Inner>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl MessageStore for InMemoryMessageStore {
    async fn store_batch(&self, messages: Vec<NewMessage>) -> Result<StoreOutcome, StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let mut outcome = StoreOutcome::default();
        let received_at = now_unix();
        for message in messages {
            if !inner.seen_ids.insert(message.id.clone()) {
                outcome.duplicates += 1;
                continue;
            }
            outcome.accepted += 1;
            inner
                .by_device
                .entry(message.device_id)
                .or_default()
                .push(StoredEntry {
                    id: message.id,
                    envelope: message.envelope,
                    franking_tag: message.franking_tag,
                    received_at,
                    expires_at: message.expires_at,
                });
        }
        Ok(outcome)
    }

    async fn fetch(&self, device_id: &str, limit: u32) -> Result<Vec<WaitingMessage>, StoreError> {
        let now = now_unix();
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner
            .by_device
            .get(device_id)
            .map(|entries| {
                entries
                    .iter()
                    // Abgelaufene Hüllen sind verschwunden: nicht mehr
                    // ausliefern (Disappearing Messages).
                    .filter(|e| e.expires_at.is_none_or(|exp| exp > now))
                    .take(limit as usize)
                    .map(|e| WaitingMessage {
                        id: e.id.clone(),
                        envelope: e.envelope.clone(),
                        franking_tag: e.franking_tag.clone(),
                        received_at: e.received_at,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn acknowledge(&self, device_id: &str, ids: &[String]) -> Result<u64, StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let Some(entries) = inner.by_device.get_mut(device_id) else {
            return Ok(0);
        };
        let before = entries.len();
        entries.retain(|e| !ids.contains(&e.id));
        Ok((before - entries.len()) as u64)
    }

    async fn has_waiting(&self, device_id: &str) -> Result<bool, StoreError> {
        let now = now_unix();
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner.by_device.get(device_id).is_some_and(|entries| {
            entries
                .iter()
                .any(|e| e.expires_at.is_none_or(|exp| exp > now))
        }))
    }

    async fn store_franking(&self, message_id: &str, commitment: &[u8]) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("Lock nicht vergiftet")
            .franking
            .insert(message_id.to_string(), commitment.to_vec());
        Ok(())
    }

    async fn franking_commitment(&self, message_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("Lock nicht vergiftet")
            .franking
            .get(message_id)
            .cloned())
    }

    async fn set_block(&self, owner: &str, blocked: &str, block: bool) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        if block {
            inner
                .blocks
                .entry(owner.to_string())
                .or_default()
                .insert(blocked.to_string());
        } else if let Some(set) = inner.blocks.get_mut(owner) {
            set.remove(blocked);
        }
        Ok(())
    }

    async fn is_blocked(&self, owner: &str, sender: &str) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("Lock nicht vergiftet")
            .blocks
            .get(owner)
            .is_some_and(|set| set.contains(sender)))
    }

    async fn list_blocks(&self, owner: &str) -> Result<Vec<String>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let mut blocked: Vec<String> = inner
            .blocks
            .get(owner)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        blocked.sort();
        Ok(blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, device: &str) -> NewMessage {
        message_expiring(id, device, None)
    }

    fn message_expiring(id: &str, device: &str, expires_at: Option<u64>) -> NewMessage {
        NewMessage {
            expires_at,
            ..base_message(id, device)
        }
    }

    fn base_message(id: &str, device: &str) -> NewMessage {
        NewMessage {
            id: id.to_string(),
            recipient_id: "00000000-0000-4000-8000-000000000001".to_string(),
            device_id: device.to_string(),
            envelope: "aHVlbGxl".to_string(),
            franking_tag: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn expired_messages_disappear() {
        let store = InMemoryMessageStore::default();
        store
            .store_batch(vec![
                message_expiring("past", "dev-1", Some(1)),
                message_expiring("future", "dev-1", Some(4_102_444_800)),
                message("permanent", "dev-1"),
            ])
            .await
            .unwrap();

        // Die abgelaufene Hülle wird nicht ausgeliefert, die anderen schon.
        let waiting = store.fetch("dev-1", 100).await.unwrap();
        let ids: Vec<&str> = waiting.iter().map(|m| m.id.as_str()).collect();
        assert!(!ids.contains(&"past"), "abgelaufen = verschwunden");
        assert!(ids.contains(&"future"));
        assert!(ids.contains(&"permanent"));

        // has_waiting zählt eine nur-abgelaufene Inbox als leer.
        let store2 = InMemoryMessageStore::default();
        store2
            .store_batch(vec![message_expiring("past", "dev-2", Some(1))])
            .await
            .unwrap();
        assert!(!store2.has_waiting("dev-2").await.unwrap());
    }

    #[tokio::test]
    async fn retry_is_deduplicated() {
        let store = InMemoryMessageStore::default();
        let batch = vec![message("a", "dev-1"), message("b", "dev-1")];
        let first = store.store_batch(batch.clone()).await.unwrap();
        assert_eq!(first.accepted, 2);
        assert_eq!(first.duplicates, 0);

        // Retry desselben Batches: nichts kommt doppelt an.
        let second = store.store_batch(batch).await.unwrap();
        assert_eq!(second.accepted, 0);
        assert_eq!(second.duplicates, 2);
        assert_eq!(store.fetch("dev-1", 100).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fetch_keeps_until_acknowledged() {
        let store = InMemoryMessageStore::default();
        store
            .store_batch(vec![message("a", "dev-1"), message("b", "dev-1")])
            .await
            .unwrap();

        // Abholen räumt nicht weg (Absturz zwischen Abholen und Verarbeiten
        // darf nichts verlieren).
        assert_eq!(store.fetch("dev-1", 100).await.unwrap().len(), 2);
        assert_eq!(store.fetch("dev-1", 100).await.unwrap().len(), 2);
        assert!(store.has_waiting("dev-1").await.unwrap());

        // Erst das Ack entfernt, und nur die bestätigten.
        let removed = store
            .acknowledge("dev-1", &["a".to_string()])
            .await
            .unwrap();
        assert_eq!(removed, 1);
        let remaining = store.fetch("dev-1", 100).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "b");

        // Ack ist idempotent, und ein Retry der Hülle "a" bleibt Duplikat.
        assert_eq!(
            store
                .acknowledge("dev-1", &["a".to_string()])
                .await
                .unwrap(),
            0
        );
        let retry = store
            .store_batch(vec![message("a", "dev-1")])
            .await
            .unwrap();
        assert_eq!(retry.duplicates, 1);
    }

    #[tokio::test]
    async fn inbox_is_per_device_and_limited() {
        let store = InMemoryMessageStore::default();
        store
            .store_batch(vec![
                message("a", "dev-1"),
                message("b", "dev-2"),
                message("c", "dev-1"),
            ])
            .await
            .unwrap();
        assert_eq!(store.fetch("dev-1", 100).await.unwrap().len(), 2);
        assert_eq!(store.fetch("dev-2", 100).await.unwrap().len(), 1);
        assert_eq!(store.fetch("dev-1", 1).await.unwrap().len(), 1);
        assert!(store.fetch("dev-3", 100).await.unwrap().is_empty());
        assert!(!store.has_waiting("dev-3").await.unwrap());
    }
}
