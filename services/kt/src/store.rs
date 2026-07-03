//! Ablage des KT-Dienstes: Update-Log und signierte Wurzeln.
//!
//! PostgreSQL ist die Quelle der Wahrheit (append-only), der Merkle-Baum
//! in akd ist ein Derivat davon (directory.rs). Wie überall: ein Trait,
//! zwei Umsetzungen mit derselben Semantik.

use std::sync::Mutex;

use async_trait::async_trait;

#[derive(Debug)]
pub enum StoreError {
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
        }
    }
}

/// Eine Schlüsseländerung im Log.
#[derive(Debug, Clone)]
pub struct Update {
    pub seq: i64,
    pub handle: String,
    /// Commitment auf die Schlüsselmenge des Kontos; für kt opak.
    pub value: Vec<u8>,
    /// None = wartet auf die nächste Epoche.
    pub epoch: Option<u64>,
}

/// Eine veröffentlichte, signierte Wurzel (STH).
#[derive(Debug, Clone)]
pub struct EpochRecord {
    pub epoch: u64,
    pub root_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

#[async_trait]
pub trait KtStore: Send + Sync {
    /// Hängt eine Schlüsseländerung ans Log an (Epoche offen).
    async fn queue_update(&self, handle: &str, value: &[u8]) -> Result<(), StoreError>;

    /// Alle noch nicht veröffentlichten Updates, in Log-Reihenfolge.
    async fn pending_updates(&self) -> Result<Vec<Update>, StoreError>;

    /// Alle veröffentlichten Updates, in (Epoche, Log)-Reihenfolge; die
    /// Grundlage des deterministischen Wiederaufbaus.
    async fn published_updates(&self) -> Result<Vec<Update>, StoreError>;

    /// Veröffentlicht eine Epoche: markiert die Updates und legt die
    /// signierte Wurzel ab - atomar, damit Log und Wurzelfolge nie
    /// auseinanderlaufen.
    async fn publish_epoch(&self, seqs: &[i64], record: &EpochRecord) -> Result<(), StoreError>;

    /// Wurzel einer Epoche; None = unbekannt.
    async fn epoch(&self, epoch: u64) -> Result<Option<EpochRecord>, StoreError>;

    /// Die jüngste Wurzel; None = noch keine Epoche veröffentlicht.
    async fn latest_epoch(&self) -> Result<Option<EpochRecord>, StoreError>;

    /// Alle Wurzeln in Epochen-Reihenfolge (für den Wiederaufbau-Abgleich).
    async fn epochs(&self) -> Result<Vec<EpochRecord>, StoreError>;
}

/// Prozesslokale Umsetzung für Entwicklung und Tests.
#[derive(Default)]
pub struct InMemoryKtStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    updates: Vec<Update>,
    epochs: Vec<EpochRecord>,
    next_seq: i64,
}

#[async_trait]
impl KtStore for InMemoryKtStore {
    async fn queue_update(&self, handle: &str, value: &[u8]) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        inner.next_seq += 1;
        let seq = inner.next_seq;
        inner.updates.push(Update {
            seq,
            handle: handle.to_string(),
            value: value.to_vec(),
            epoch: None,
        });
        Ok(())
    }

    async fn pending_updates(&self) -> Result<Vec<Update>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner
            .updates
            .iter()
            .filter(|u| u.epoch.is_none())
            .cloned()
            .collect())
    }

    async fn published_updates(&self) -> Result<Vec<Update>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let mut published: Vec<Update> = inner
            .updates
            .iter()
            .filter(|u| u.epoch.is_some())
            .cloned()
            .collect();
        published.sort_by_key(|u| (u.epoch.unwrap_or(0), u.seq));
        Ok(published)
    }

    async fn publish_epoch(&self, seqs: &[i64], record: &EpochRecord) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        for update in inner.updates.iter_mut() {
            if seqs.contains(&update.seq) {
                update.epoch = Some(record.epoch);
            }
        }
        inner.epochs.push(record.clone());
        Ok(())
    }

    async fn epoch(&self, epoch: u64) -> Result<Option<EpochRecord>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner.epochs.iter().find(|e| e.epoch == epoch).cloned())
    }

    async fn latest_epoch(&self) -> Result<Option<EpochRecord>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner.epochs.last().cloned())
    }

    async fn epochs(&self) -> Result<Vec<EpochRecord>, StoreError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        Ok(inner.epochs.clone())
    }
}
