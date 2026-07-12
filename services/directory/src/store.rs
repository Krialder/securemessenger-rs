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

/// Obergrenze ungenutzter MLS-KeyPackages je Gerät. Ein Gerät braucht nur
/// wenige gleichzeitig (je Gruppen-Einladung wird eines verbraucht); die
/// Grenze deckelt den Speicher, den ein Gerät im Verzeichnis belegen kann,
/// gegen ein Gerät, das ohne Rücksicht auf den Restbestand nachlädt.
pub const MAX_MLS_KEY_PACKAGES: u64 = 100;

/// Fehler der Ablage. Backend heißt: Infrastruktur kaputt, wird 500;
/// PrekeyIdTaken ist ein Client-Konflikt (doppelt hochgeladene ID);
/// MlsPoolFull heißt: das Gerät hat schon genug KeyPackages liegen.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    PrekeyIdTaken,
    MlsPoolFull,
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

    /// Konsumiert ein MLS-KeyPackage eines Geräts (für einen
    /// Gruppenbeitritt). `None`, wenn der Pool leer ist; dann kann das
    /// Gerät gerade nicht in eine Gruppe eingeladen werden, bis es
    /// nachfüllt. Getrennt von take_bundle, weil KeyPackages nicht zu
    /// den 1:1-PQXDH-Bündeln gehören.
    async fn take_mls_key_package(&self, device_id: &str) -> Result<Option<Prekey>, StoreError>;
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
        // MLS-Pool deckeln: die ungenutzten KeyPackages dieses Geräts plus
        // die neuen dürfen die Obergrenze nicht überschreiten (atomar unter
        // dem Lock, kein TOCTOU).
        let new_mls = uploads
            .iter()
            .filter(|u| u.kind == PrekeyKind::MlsKeyPackage)
            .count() as u64;
        if new_mls > 0 {
            let existing_mls = pool
                .iter()
                .filter(|p| !p.used && p.kind == PrekeyKind::MlsKeyPackage)
                .count() as u64;
            if existing_mls + new_mls > MAX_MLS_KEY_PACKAGES {
                return Err(StoreError::MlsPoolFull);
            }
        }
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
                    PrekeyKind::MlsKeyPackage => counts.mls_key_package += 1,
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
                // KeyPackages gehören nicht ins PQXDH-Bündel und werden
                // hier nie angefasst (eigener Claim-Pfad).
                PrekeyKind::MlsKeyPackage => continue,
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

    async fn take_mls_key_package(&self, device_id: &str) -> Result<Option<Prekey>, StoreError> {
        let mut pools = self.lock();
        let Some(pool) = pools.get_mut(device_id) else {
            return Ok(None);
        };
        for p in pool.iter_mut() {
            if p.used || p.kind != PrekeyKind::MlsKeyPackage {
                continue;
            }
            p.used = true;
            return Ok(Some(Prekey {
                id: p.id.clone(),
                key: p.key.clone(),
            }));
        }
        Ok(None)
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
    async fn mls_pool_is_capped_per_device() {
        let store = InMemoryPrekeyStore::default();
        // Bis zum Deckel füllen ist in Ordnung.
        let full: Vec<PrekeyUpload> = (0..MAX_MLS_KEY_PACKAGES)
            .map(|i| upload(PrekeyKind::MlsKeyPackage, &format!("kp{i}")))
            .collect();
        store.upload("d1", full).await.unwrap();
        assert_eq!(
            store.counts("d1").await.unwrap().mls_key_package,
            MAX_MLS_KEY_PACKAGES
        );

        // Noch eines dazu wird abgelehnt (der Pool ist voll).
        let err = store
            .upload("d1", vec![upload(PrekeyKind::MlsKeyPackage, "kp-extra")])
            .await
            .unwrap_err();
        assert_eq!(err, StoreError::MlsPoolFull);

        // Nach dem Verbrauch eines KeyPackages ist wieder Platz.
        store.take_mls_key_package("d1").await.unwrap();
        store
            .upload("d1", vec![upload(PrekeyKind::MlsKeyPackage, "kp-neu")])
            .await
            .unwrap();
        assert_eq!(
            store.counts("d1").await.unwrap().mls_key_package,
            MAX_MLS_KEY_PACKAGES
        );

        // Der Deckel gilt nur je Gerät: ein anderes Gerät kann füllen.
        store
            .upload("d2", vec![upload(PrekeyKind::MlsKeyPackage, "kp-d2")])
            .await
            .unwrap();
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
                pq_one_time: 1,
                mls_key_package: 0,
            }
        );
        store.take_bundle("d1").await.unwrap();
        assert_eq!(
            store.counts("d1").await.unwrap(),
            PoolCounts {
                one_time: 1,
                pq_one_time: 0,
                mls_key_package: 0,
            }
        );
    }

    #[tokio::test]
    async fn mls_key_packages_are_claimed_once_and_apart_from_bundles() {
        let store = InMemoryPrekeyStore::default();
        store
            .upload(
                "d1",
                vec![
                    upload(PrekeyKind::MlsKeyPackage, "kp1"),
                    upload(PrekeyKind::MlsKeyPackage, "kp2"),
                    upload(PrekeyKind::OneTime, "o1"),
                ],
            )
            .await
            .unwrap();
        assert_eq!(store.counts("d1").await.unwrap().mls_key_package, 2);

        // Ein Bündel-Abruf fasst KeyPackages nicht an.
        let bundle = store.take_bundle("d1").await.unwrap();
        assert!(bundle.one_time.is_some());
        assert_eq!(store.counts("d1").await.unwrap().mls_key_package, 2);

        // KeyPackages werden einzeln konsumiert, jedes nur einmal.
        assert_eq!(
            store.take_mls_key_package("d1").await.unwrap().unwrap().id,
            "kp1"
        );
        assert_eq!(
            store.take_mls_key_package("d1").await.unwrap().unwrap().id,
            "kp2"
        );
        assert!(store.take_mls_key_package("d1").await.unwrap().is_none());
    }
}
