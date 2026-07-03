//! Speicher-Abstraktion des Prekey-Pools plus In-Memory-Umsetzung.
//!
//! Die entscheidende Invariante ist die atomare Konsumierung: zwei
//! gleichzeitige Bündel-Abrufe dürfen nie denselben Einmal-Prekey liefern
//! (datenmodell.md). In PostgreSQL löst das FOR UPDATE SKIP LOCKED, hier
//! der Mutex; beide Umsetzungen müssen dieselbe Semantik zeigen.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::domain::{DeviceBundle, PoolCounts, Prekey, PrekeyKind};

/// Fehler der Ablage. Backend heißt: Infrastruktur kaputt, wird 500;
/// PrekeyIdTaken ist ein Client-Konflikt (doppelt hochgeladene ID).
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    PrekeyIdTaken,
    Backend(String),
}

/// Ein Upload-Posten: Typ plus Schlüssel.
#[derive(Debug, Clone)]
pub struct PrekeyUpload {
    pub kind: PrekeyKind,
    pub prekey: Prekey,
}

#[async_trait]
pub trait PrekeyStore: Send + Sync {
    /// Nimmt einen Upload-Stapel eines Geräts an, atomar. Ein neuer
    /// signierter Prekey ersetzt den alten seines Typs (Rotation),
    /// Einmal-Prekeys füllen den Pool auf.
    async fn upload(&self, device_id: &str, uploads: Vec<PrekeyUpload>) -> Result<(), StoreError>;

    /// Verbleibende Einmal-Prekeys, für die Nachfüll-Entscheidung des Clients.
    async fn counts(&self, device_id: &str) -> Result<PoolCounts, StoreError>;

    /// Baut das Bündel eines Geräts: signierte Prekeys lesen, je einen
    /// Einmal-Prekey pro Typ atomar konsumieren.
    async fn take_bundle(&self, device_id: &str) -> Result<DeviceBundle, StoreError>;
}

#[derive(Debug, Clone)]
struct StoredPrekey {
    id: String,
    kind: PrekeyKind,
    key: String,
    used: bool,
}

/// Prozesslokaler Pool für Entwicklung und Tests. Ein Mutex über allem:
/// Konsumierung und Rotation sind so trivial atomar, und die Zugriffe sind
/// kurz genug, dass Sperr-Konkurrenz hier keine Rolle spielt.
#[derive(Default)]
pub struct InMemoryPrekeyStore {
    // device_id -> Prekeys in Upload-Reihenfolge (FIFO-Konsumierung wie
    // ORDER BY created_at in PostgreSQL).
    inner: Mutex<HashMap<String, Vec<StoredPrekey>>>,
}

impl InMemoryPrekeyStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<StoredPrekey>>> {
        self.inner.lock().expect("Prekey-Lock nie vergiftet")
    }
}

#[async_trait]
impl PrekeyStore for InMemoryPrekeyStore {
    async fn upload(&self, device_id: &str, uploads: Vec<PrekeyUpload>) -> Result<(), StoreError> {
        let mut pools = self.lock();
        // Duplikat-Prüfung über alle Geräte, wie der Primärschlüssel in
        // PostgreSQL: Prekey-IDs sind global eindeutig.
        for upload in &uploads {
            let taken = pools.values().flatten().any(|p| p.id == upload.prekey.id);
            if taken {
                return Err(StoreError::PrekeyIdTaken);
            }
        }
        let pool = pools.entry(device_id.to_string()).or_default();
        for upload in uploads {
            // Rotation: der neue signierte Prekey ersetzt den alten seines
            // Typs; alte Zeilen bleiben als used markiert stehen.
            if !upload.kind.is_one_time() {
                for existing in pool.iter_mut().filter(|p| p.kind == upload.kind) {
                    existing.used = true;
                }
            }
            pool.push(StoredPrekey {
                id: upload.prekey.id,
                kind: upload.kind,
                key: upload.prekey.key,
                used: false,
            });
        }
        Ok(())
    }

    async fn counts(&self, device_id: &str) -> Result<PoolCounts, StoreError> {
        let pools = self.lock();
        let mut counts = PoolCounts::default();
        if let Some(pool) = pools.get(device_id) {
            for p in pool.iter().filter(|p| !p.used) {
                match p.kind {
                    PrekeyKind::OneTime => counts.one_time += 1,
                    PrekeyKind::PqOneTime => counts.pq_one_time += 1,
                    _ => {}
                }
            }
        }
        Ok(counts)
    }

    async fn take_bundle(&self, device_id: &str) -> Result<DeviceBundle, StoreError> {
        let mut pools = self.lock();
        let mut bundle = DeviceBundle::default();
        let Some(pool) = pools.get_mut(device_id) else {
            return Ok(bundle);
        };
        for p in pool.iter_mut() {
            if p.used {
                continue;
            }
            let slot = match p.kind {
                PrekeyKind::Signed => &mut bundle.signed,
                PrekeyKind::PqSigned => &mut bundle.pq_signed,
                PrekeyKind::OneTime => &mut bundle.one_time,
                PrekeyKind::PqOneTime => &mut bundle.pq_one_time,
            };
            if slot.is_some() {
                continue;
            }
            *slot = Some(Prekey {
                id: p.id.clone(),
                key: p.key.clone(),
            });
            // Nur Einmal-Prekeys werden konsumiert; signierte bleiben
            // lesbar, bis die Rotation sie ersetzt.
            if p.kind.is_one_time() {
                p.used = true;
            }
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(kind: PrekeyKind, id: &str) -> PrekeyUpload {
        PrekeyUpload {
            kind,
            prekey: Prekey {
                id: id.to_string(),
                key: format!("key-{id}"),
            },
        }
    }

    #[tokio::test]
    async fn bundle_consumes_one_time_but_not_signed() {
        let store = InMemoryPrekeyStore::default();
        store
            .upload(
                "d1",
                vec![
                    upload(PrekeyKind::Signed, "s1"),
                    upload(PrekeyKind::PqSigned, "ps1"),
                    upload(PrekeyKind::OneTime, "o1"),
                    upload(PrekeyKind::PqOneTime, "po1"),
                ],
            )
            .await
            .unwrap();

        let first = store.take_bundle("d1").await.unwrap();
        assert_eq!(first.signed.unwrap().id, "s1");
        assert_eq!(first.one_time.unwrap().id, "o1");
        assert_eq!(first.pq_one_time.unwrap().id, "po1");

        // Zweiter Abruf: signierte Prekeys noch da, Einmal-Pools leer.
        let second = store.take_bundle("d1").await.unwrap();
        assert_eq!(second.signed.unwrap().id, "s1");
        assert!(second.one_time.is_none());
        assert!(second.pq_one_time.is_none());
    }

    #[tokio::test]
    async fn signed_prekey_rotation_replaces_old() {
        let store = InMemoryPrekeyStore::default();
        store
            .upload("d1", vec![upload(PrekeyKind::Signed, "alt")])
            .await
            .unwrap();
        store
            .upload("d1", vec![upload(PrekeyKind::Signed, "neu")])
            .await
            .unwrap();
        let bundle = store.take_bundle("d1").await.unwrap();
        assert_eq!(bundle.signed.unwrap().id, "neu");
    }

    #[tokio::test]
    async fn duplicate_prekey_id_is_rejected() {
        let store = InMemoryPrekeyStore::default();
        store
            .upload("d1", vec![upload(PrekeyKind::OneTime, "o1")])
            .await
            .unwrap();
        // Auch unter anderem Gerät: IDs sind global eindeutig (Primärschlüssel).
        let err = store
            .upload("d2", vec![upload(PrekeyKind::OneTime, "o1")])
            .await
            .unwrap_err();
        assert_eq!(err, StoreError::PrekeyIdTaken);
    }

    #[tokio::test]
    async fn counts_track_unused_one_time_keys() {
        let store = InMemoryPrekeyStore::default();
        store
            .upload(
                "d1",
                vec![
                    upload(PrekeyKind::OneTime, "o1"),
                    upload(PrekeyKind::OneTime, "o2"),
                    upload(PrekeyKind::PqOneTime, "po1"),
                    upload(PrekeyKind::Signed, "s1"),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            store.counts("d1").await.unwrap(),
            PoolCounts {
                one_time: 2,
                pq_one_time: 1
            }
        );
        store.take_bundle("d1").await.unwrap();
        assert_eq!(
            store.counts("d1").await.unwrap(),
            PoolCounts {
                one_time: 1,
                pq_one_time: 0
            }
        );
    }
}
