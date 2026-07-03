//! Die verifiable map: akd-Orchestrierung mit deterministischem
//! Wiederaufbau.
//!
//! PostgreSQL hält das append-only Update-Log und die signierten Wurzeln
//! (store.rs); der AZKS von akd lebt im Speicher und wird beim Start aus
//! dem Log wiederaufgebaut - Epoche für Epoche, mit exakt denselben
//! Batches wie bei der Erstveröffentlichung. Stimmen die dabei
//! entstehenden Wurzeln nicht mit den gespeicherten überein, bricht der
//! Start ab: entweder ist das Log manipuliert oder der Code nicht mehr
//! deterministisch, beides darf nie stillschweigend weiterlaufen.
//!
//! [ANNAHME: In-Memory-AZKS mit Wiederaufbau statt eines persistenten
//! akd-Storage-Adapters. Der Wiederaufbau ist O(alle Updates) und trägt
//! die Abteilung Jahre; ein PG-Adapter für akd lohnt erst, wenn der
//! Neustart spürbar wird. Der Determinismus ist durch den
//! Wiederaufbau-Test in tests/ belegt.]

use akd::append_only_zks::AzksParallelismConfig;
use akd::directory::Directory;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, EpochHash, HistoryParams};
use tokio::sync::Mutex;

use crate::keys::{RootSigner, SecretVrf};
use crate::store::{EpochRecord, KtStore, StoreError};

/// Die akd-Konfiguration der Plattform. [ANNAHME:
/// ExperimentalConfiguration mit eigenem Domain-Label; sie ist die von
/// akd empfohlene aktuelle Konfiguration. WhatsAppV1 bliebe die
/// Alternative, wenn Interop mit deren Auditoren nötig würde.]
#[derive(Clone)]
pub struct SmDomainLabel;

impl akd::DomainLabel for SmDomainLabel {
    fn domain_label() -> &'static [u8] {
        b"securemessenger-kt-v1"
    }
}

pub type KtConfiguration = akd::ExperimentalConfiguration<SmDomainLabel>;

type InMemoryDirectory = Directory<KtConfiguration, AsyncInMemoryDatabase, SecretVrf>;

/// Fehler der Verzeichnis-Schicht; Details landen im Log, nach außen
/// wird daraus ein 500.
#[derive(Debug)]
pub enum DirectoryError {
    Backend(String),
    /// Wiederaufbau ergab andere Wurzeln als gespeichert.
    IntegrityViolation(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
            DirectoryError::IntegrityViolation(msg) => {
                write!(f, "Integritätsbruch im KT-Log: {msg}")
            }
        }
    }
}

impl From<StoreError> for DirectoryError {
    fn from(err: StoreError) -> Self {
        DirectoryError::Backend(err.to_string())
    }
}

fn akd_err(err: akd::errors::AkdError) -> DirectoryError {
    DirectoryError::Backend(format!("akd: {err}"))
}

/// Die verifiable map des Dienstes: akd-Directory plus Signer, hinter
/// einem Mutex (Veröffentlichungen sind selten und dürfen sich nie
/// überlappen; Lookups sind read-only auf dem Directory und laufen
/// über akd's eigene Synchronisation).
pub struct KtDirectory {
    directory: Mutex<InMemoryDirectory>,
    signer: RootSigner,
}

impl KtDirectory {
    /// Baut das Verzeichnis aus dem persistierten Log wieder auf und
    /// prüft jede gespeicherte Wurzel gegen den Wiederaufbau.
    pub async fn rebuild(
        store: &dyn KtStore,
        vrf: SecretVrf,
        signer: RootSigner,
    ) -> Result<Self, DirectoryError> {
        let database = AsyncInMemoryDatabase::new();
        let storage = StorageManager::new_no_cache(database);
        let directory =
            Directory::<KtConfiguration, _, _>::new(storage, vrf, AzksParallelismConfig::default())
                .await
                .map_err(akd_err)?;

        let published = store.published_updates().await?;
        let epochs = store.epochs().await?;

        // Updates je Epoche gruppieren (sie kommen sortiert nach
        // (epoch, seq), also reicht sequentielles Zerteilen).
        let mut by_epoch: Vec<(u64, Vec<(AkdLabel, AkdValue)>)> = Vec::new();
        for update in published {
            let epoch = update
                .epoch
                .expect("published_updates liefert nur mit Epoche");
            let entry = (
                AkdLabel::from(update.handle.as_str()),
                AkdValue(update.value.clone()),
            );
            match by_epoch.last_mut() {
                Some((current, batch)) if *current == epoch => batch.push(entry),
                _ => by_epoch.push((epoch, vec![entry])),
            }
        }

        if by_epoch.len() != epochs.len() {
            return Err(DirectoryError::IntegrityViolation(format!(
                "{} Update-Epochen im Log, aber {} gespeicherte Wurzeln",
                by_epoch.len(),
                epochs.len()
            )));
        }

        for ((update_epoch, batch), stored) in by_epoch.into_iter().zip(epochs.iter()) {
            if update_epoch != stored.epoch {
                return Err(DirectoryError::IntegrityViolation(format!(
                    "Update-Epoche {update_epoch} passt nicht zur Wurzel-Epoche {}",
                    stored.epoch
                )));
            }
            let EpochHash(epoch, root_hash) = directory.publish(batch).await.map_err(akd_err)?;
            if epoch != stored.epoch || root_hash.as_slice() != stored.root_hash.as_slice() {
                return Err(DirectoryError::IntegrityViolation(format!(
                    "Wiederaufbau der Epoche {} ergab eine andere Wurzel",
                    stored.epoch
                )));
            }
        }

        Ok(Self {
            directory: Mutex::new(directory),
            signer,
        })
    }

    /// Veröffentlicht die wartenden Updates als neue Epoche: akd-publish,
    /// Wurzel signieren, atomar persistieren. Ohne wartende Updates
    /// passiert nichts (leere Epochen hätten keinen Aussagewert).
    pub async fn publish_pending(
        &self,
        store: &dyn KtStore,
    ) -> Result<Option<EpochRecord>, DirectoryError> {
        let directory = self.directory.lock().await;
        let pending = store.pending_updates().await?;
        if pending.is_empty() {
            return Ok(None);
        }
        let seqs: Vec<i64> = pending.iter().map(|u| u.seq).collect();
        let batch: Vec<(AkdLabel, AkdValue)> = pending
            .iter()
            .map(|u| (AkdLabel::from(u.handle.as_str()), AkdValue(u.value.clone())))
            .collect();
        let EpochHash(epoch, root_hash) = directory.publish(batch).await.map_err(akd_err)?;
        let record = EpochRecord {
            epoch,
            root_hash: root_hash.to_vec(),
            signature: self.signer.sign_root(epoch, &root_hash),
        };
        store.publish_epoch(&seqs, &record).await?;
        Ok(Some(record))
    }

    /// Inklusionsbeweis für ein Handle (aktuelle Epoche). None = Handle
    /// (noch) nicht im Verzeichnis.
    pub async fn lookup(
        &self,
        handle: &str,
    ) -> Result<Option<(akd::LookupProof, EpochHash)>, DirectoryError> {
        let directory = self.directory.lock().await;
        match directory.lookup(AkdLabel::from(handle)).await {
            Ok(result) => Ok(Some(result)),
            Err(akd::errors::AkdError::Storage(akd::errors::StorageError::NotFound(_))) => Ok(None),
            Err(akd::errors::AkdError::Directory(_)) => Ok(None),
            Err(err) => Err(akd_err(err)),
        }
    }

    /// Versionshistorie eines Handles (für die Client-Selbstprüfung).
    pub async fn history(
        &self,
        handle: &str,
    ) -> Result<Option<(akd::HistoryProof, EpochHash)>, DirectoryError> {
        let directory = self.directory.lock().await;
        match directory
            .key_history(&AkdLabel::from(handle), HistoryParams::Complete)
            .await
        {
            Ok(result) => Ok(Some(result)),
            Err(akd::errors::AkdError::Storage(akd::errors::StorageError::NotFound(_))) => Ok(None),
            Err(akd::errors::AkdError::Directory(_)) => Ok(None),
            Err(err) => Err(akd_err(err)),
        }
    }

    /// Append-only-Beweis zwischen zwei Epochen (für Auditoren).
    pub async fn audit(&self, from: u64, to: u64) -> Result<akd::AppendOnlyProof, DirectoryError> {
        let directory = self.directory.lock().await;
        directory.audit(from, to).await.map_err(akd_err)
    }

    /// Der öffentliche VRF-Schlüssel (Clients prüfen damit die Labels).
    pub async fn vrf_public_key(&self) -> Result<Vec<u8>, DirectoryError> {
        let directory = self.directory.lock().await;
        directory
            .get_public_key()
            .await
            .map(|k| k.as_bytes().to_vec())
            .map_err(akd_err)
    }

    pub fn signer(&self) -> &RootSigner {
        &self.signer
    }
}
