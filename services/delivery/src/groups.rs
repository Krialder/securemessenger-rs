//! Gruppen-Zustellung (MLS Delivery Service, specs/mls-delivery-service.md).
//!
//! Der Server hält den kryptografischen Gruppenzustand nicht, den tragen
//! die Clients (TreeKEM). Er hält nur zwei Dinge, die er fürs Zustellen
//! braucht: die Geräteliste einer Gruppe (fürs Fan-out) und eine
//! fortlaufende Epoche je Gruppe (fürs Serialisieren konkurrierender
//! Commits). Die Auflösungsregel für konkurrierende Commits ist die
//! offene Frage aus der Spec, hier festgelegt: first-wins nach Ankunft.
//! Wer gegen eine veraltete Epoche committet, bekommt 409 und die aktuelle
//! Epoche zurück und wendet seinen Commit gegen die neue Epoche neu an.
//!
//! [ANNAHME: Die Bindung zwischen Geräteliste und kryptografischer
//! MLS-Mitgliedschaft prüft der Client (die Spec verlangt das ausdrücklich,
//! der Server ist dafür nicht vertrauenswürdig). Der Server nimmt die
//! Mitglieder-Geräteliste vom committenden Client entgegen; er kann sie
//! nicht kryptografisch verifizieren und tut es auch nicht. External-Commit-
//! Policy und die genauen Reorder-Garantien bleiben offen (Spec).]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;

/// Fehler der Gruppen-Ablage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// Technischer Fehler der Ablage; wird beim Aufrufer 500.
    Backend(String),
    /// Die Gruppe gibt es nicht.
    UnknownGroup,
    /// Eine Gruppe mit dieser ID existiert schon (Anlage).
    GroupExists,
    /// Der Commit zielte auf eine veraltete Epoche; die aktuelle ist
    /// beigelegt, damit der Client neu aufsetzen kann.
    StaleEpoch { current: u64 },
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
            GroupError::UnknownGroup => write!(f, "Gruppe unbekannt"),
            GroupError::GroupExists => write!(f, "Gruppe existiert bereits"),
            GroupError::StaleEpoch { current } => {
                write!(f, "Commit veraltet, aktuelle Epoche {current}")
            }
        }
    }
}

/// Der Gruppenzustand, den der Server hält: aktuelle Epoche und die
/// Mitglieds-Geräte fürs Fan-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    pub epoch: u64,
    pub devices: Vec<String>,
}

#[async_trait]
pub trait GroupStore: Send + Sync {
    /// Legt eine Gruppe mit der ersten Mitglieder-Geräteliste an, Epoche 0.
    /// `GroupExists`, wenn die client-erzeugte ID schon vergeben ist
    /// (idempotenz-sicher: der Aufrufer erkennt seinen eigenen Retry).
    async fn create_group(&self, group_id: &str, devices: &[String]) -> Result<(), GroupError>;

    /// Aktueller Zustand (Epoche und Geräteliste) oder `UnknownGroup`.
    async fn state(&self, group_id: &str) -> Result<GroupState, GroupError>;

    /// Serialisiert einen Commit: nur wenn `expected_epoch` die aktuelle
    /// ist, wird die Epoche um eins erhöht und die Mitgliederliste auf
    /// `new_devices` gesetzt; sonst `StaleEpoch` mit der aktuellen Epoche.
    /// Das ist der Punkt, an dem konkurrierende Commits auseinandergehen
    /// (first-wins nach Ankunft). Liefert die neue Epoche.
    async fn commit(
        &self,
        group_id: &str,
        expected_epoch: u64,
        new_devices: &[String],
    ) -> Result<u64, GroupError>;
}

#[derive(Default)]
struct Inner {
    groups: HashMap<String, GroupState>,
}

/// Prozesslokale Gruppen-Ablage (Tests, Entwicklung). Gleiche Semantik
/// wie die PG-Umsetzung; die Commit-Serialisierung liegt hier im Mutex,
/// dort in einer Transaktion mit Zeilensperre.
#[derive(Default)]
pub struct InMemoryGroupStore {
    inner: Mutex<Inner>,
}

fn dedup(devices: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    devices
        .iter()
        .filter(|d| seen.insert((*d).clone()))
        .cloned()
        .collect()
}

#[async_trait]
impl GroupStore for InMemoryGroupStore {
    async fn create_group(&self, group_id: &str, devices: &[String]) -> Result<(), GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        if inner.groups.contains_key(group_id) {
            return Err(GroupError::GroupExists);
        }
        inner.groups.insert(
            group_id.to_string(),
            GroupState {
                epoch: 0,
                devices: dedup(devices),
            },
        );
        Ok(())
    }

    async fn state(&self, group_id: &str) -> Result<GroupState, GroupError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        inner
            .groups
            .get(group_id)
            .cloned()
            .ok_or(GroupError::UnknownGroup)
    }

    async fn commit(
        &self,
        group_id: &str,
        expected_epoch: u64,
        new_devices: &[String],
    ) -> Result<u64, GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let state = inner
            .groups
            .get_mut(group_id)
            .ok_or(GroupError::UnknownGroup)?;
        if state.epoch != expected_epoch {
            return Err(GroupError::StaleEpoch {
                current: state.epoch,
            });
        }
        state.epoch += 1;
        state.devices = dedup(new_devices);
        Ok(state.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devs(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn create_is_idempotent_guarded() {
        let store = InMemoryGroupStore::default();
        store.create_group("g1", &devs(&["a", "b"])).await.unwrap();
        // Zweite Anlage derselben ID ist ein erkennbarer Fehler, kein
        // stiller Überschreiber.
        assert_eq!(
            store.create_group("g1", &devs(&["c"])).await,
            Err(GroupError::GroupExists)
        );
        let state = store.state("g1").await.unwrap();
        assert_eq!(state.epoch, 0);
        assert_eq!(state.devices, devs(&["a", "b"]));
    }

    #[tokio::test]
    async fn commit_advances_epoch_and_updates_membership() {
        let store = InMemoryGroupStore::default();
        store.create_group("g1", &devs(&["a", "b"])).await.unwrap();

        // Ein Beitritt: Commit gegen Epoche 0, danach Epoche 1 mit drei.
        let epoch = store
            .commit("g1", 0, &devs(&["a", "b", "c"]))
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(
            store.state("g1").await.unwrap().devices,
            devs(&["a", "b", "c"])
        );
    }

    #[tokio::test]
    async fn concurrent_commit_against_stale_epoch_is_rejected() {
        let store = InMemoryGroupStore::default();
        store.create_group("g1", &devs(&["a", "b"])).await.unwrap();

        // Zwei Mitglieder committen gegen Epoche 0; der erste gewinnt.
        assert_eq!(
            store
                .commit("g1", 0, &devs(&["a", "b", "c"]))
                .await
                .unwrap(),
            1
        );
        // Der zweite kommt zu spät und bekommt die aktuelle Epoche zurück,
        // statt den Zustand des ersten zu überschreiben.
        assert_eq!(
            store.commit("g1", 0, &devs(&["a", "b", "d"])).await,
            Err(GroupError::StaleEpoch { current: 1 })
        );
        // Der Gewinner steht unangetastet.
        assert_eq!(
            store.state("g1").await.unwrap().devices,
            devs(&["a", "b", "c"])
        );
    }

    #[tokio::test]
    async fn unknown_group_is_reported() {
        let store = InMemoryGroupStore::default();
        assert_eq!(store.state("nope").await, Err(GroupError::UnknownGroup));
        assert_eq!(
            store.commit("nope", 0, &devs(&["a"])).await,
            Err(GroupError::UnknownGroup)
        );
    }
}
