//! Speicher-Abstraktion für Konten und ihre Geräte.
//!
//! Der Trait trennt die Fachlogik von der konkreten Ablage. Es gibt zwei
//! Umsetzungen: In-Memory (Entwicklung ohne Infrastruktur, schnelle Tests)
//! und PostgreSQL (pg.rs, sqlx). Der Trait ist async, weil die Datenbank es
//! ist; async-trait hält ihn dyn-kompatibel für den `Arc<dyn AccountStore>`
//! im axum-State.
//!
//! Konto und Geräte sind ein Aggregat: `create` nimmt das erste Gerät mit
//! entgegen, weil ein Konto ohne Gerät ein verwaister Zustand wäre, den kein
//! Client erzeugen kann (schnittstellen.md: die Registrierung legt Konto und
//! erstes Gerät zusammen an).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;

use crate::domain::{Account, Device};

/// Ein Discovery-Treffer: das Konto hinter einem gesuchten Handle, so weit
/// der Client es fürs Weiterarbeiten braucht (interne Adresse und
/// Konto-Identitätsschlüssel; den Handle bestätigt er, weil er ihn kannte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub handle: String,
    pub id: String,
    pub identity_key: String,
}

/// Fehler der Ablage: fachliche Konflikte und Backend-Ausfälle in einem
/// Enum, damit Handler beides explizit behandeln müssen (Konflikt wird 4xx,
/// Backend wird 500; ein DB-Ausfall darf nie wie "gibt es nicht" aussehen).
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Das Handle ist bereits vergeben.
    HandleTaken,
    /// Die Geräte-ID ist bereits belegt, auch durch ein revoziertes Gerät
    /// (Credential-Replay-Schutz) und global über alle Konten
    /// (datenmodell.md: devices.id ist Primärschlüssel).
    DeviceIdTaken,
    /// Das Konto existiert nicht (Trait-Vertrag; über die API nicht
    /// erreichbar, weil sie authentifiziert).
    AccountMissing,
    /// Gerät nicht gefunden oder bereits revoziert.
    DeviceNotFound,
    /// Das Konto hat die Höchstzahl an Geräten erreicht (Nummernraum 1..255
    /// erschöpft, auch durch revozierte Geräte, deren Nummern nicht
    /// wiederverwendet werden).
    TooManyDevices,
    /// Ablage nicht erreichbar oder Abfrage fehlgeschlagen. Der Text ist
    /// für Logs, nie für API-Antworten.
    Backend(String),
}

/// Ablage für Konten und Geräte. `Send + Sync`, damit der Store geteilt
/// hinter einem `Arc` in den axum-State passt.
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Legt ein Konto samt erstem Gerät an. Atomar: entweder entstehen
    /// beide oder keines. Das erste Gerät bekommt die Protokollnummer 1; die
    /// Ablage setzt sie, der übergebene Wert im Gerät wird ignoriert.
    async fn create(&self, account: Account, first_device: Device) -> Result<(), StoreError>;
    /// Liest ein Konto anhand des Handles, falls vorhanden.
    async fn get(&self, handle: &str) -> Result<Option<Account>, StoreError>;
    /// Setzt den Passwort-Hash eines Kontos neu (Passwort ändern). Der
    /// Aufrufer hat das alte Passwort schon geprüft und das neue gehasht;
    /// die Ablage tauscht nur den Wert. `AccountMissing`, wenn das Konto
    /// nicht existiert (über die authentifizierte API nicht erreichbar).
    async fn set_password_hash(&self, handle: &str, password_hash: &str) -> Result<(), StoreError>;
    /// Fügt einem Konto ein weiteres Gerät hinzu und vergibt ihm die
    /// nächste freie Protokollnummer (max der vorhandenen, auch revozierter,
    /// plus 1). Liefert die vergebene Nummer zurück, damit der Client sie
    /// als seinen ProtocolAddress-Teil übernehmen kann.
    async fn add_device(&self, handle: &str, device: Device) -> Result<u16, StoreError>;
    /// Alle Geräte des Kontos, auch revozierte; das Flag steht im Gerät.
    /// Leer, wenn das Konto nicht existiert (über die API nicht erreichbar).
    async fn devices(&self, handle: &str) -> Result<Vec<Device>, StoreError>;
    /// Ein einzelnes Gerät des Kontos, falls vorhanden (auch revozierte).
    async fn get_device(&self, handle: &str, device_id: &str)
        -> Result<Option<Device>, StoreError>;
    /// Nimmt ein Gerät aus der gültigen Menge. `DeviceNotFound` auch für
    /// bereits revozierte: die sind fachlich nicht mehr entfernbar.
    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), StoreError>;

    /// Trägt ein Konto unter seinem OPRF-Wert in den Discovery-Index ein
    /// (Contact Discovery, specs/contact-discovery.md). `prf_hex` ist
    /// `PRF_k(handle)` als Hex, vom API-Layer mit dem Server-OPRF-Schlüssel
    /// berechnet; die Ablage kennt die OPRF nicht, sie hält nur den Index.
    async fn index_discovery(
        &self,
        prf_hex: &str,
        record: DiscoveryRecord,
    ) -> Result<(), StoreError>;

    /// Schlägt ein Konto über seinen OPRF-Wert nach. `None`, wenn kein
    /// Konto unter diesem Wert steht (der Client rät nicht, er kannte den
    /// Handle; der Server lernt aus dem Wert nicht den Klartext).
    async fn discovery_lookup(&self, prf_hex: &str) -> Result<Option<DiscoveryRecord>, StoreError>;
}

/// Konto samt Geräten unter einem Schlüssel, damit Anlegen und Geräte-
/// Änderungen unter demselben Lock laufen.
struct Record {
    account: Account,
    devices: Vec<Device>,
}

#[derive(Default)]
struct InMemoryInner {
    records: HashMap<String, Record>,
    /// Global belegte Geräte-IDs, wie der Primärschlüssel in PostgreSQL.
    device_ids: HashSet<String>,
    /// Discovery-Index: OPRF-Wert (Hex) auf Konto-Referenz.
    discovery: HashMap<String, DiscoveryRecord>,
}

/// Prozesslokale Ablage für Entwicklung ohne Infrastruktur und für Tests.
/// Kein .await, solange der Lock gehalten wird, deshalb ist das RwLock
/// im async-Kontext unbedenklich.
#[derive(Default)]
pub struct InMemoryStore {
    inner: RwLock<InMemoryInner>,
}

#[async_trait]
impl AccountStore for InMemoryStore {
    async fn create(&self, account: Account, first_device: Device) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("Store-Lock nicht vergiftet");
        if inner.device_ids.contains(&first_device.id) {
            return Err(StoreError::DeviceIdTaken);
        }
        // Entry-API statt contains_key plus insert: ein Lookup, und die
        // Prüfung und das Einfügen sind untrennbar dieselbe Operation.
        match inner.records.entry(account.handle.clone()) {
            Entry::Occupied(_) => Err(StoreError::HandleTaken),
            Entry::Vacant(slot) => {
                let device_id = first_device.id.clone();
                // Das erste Gerät ist definitionsgemäß Nummer 1.
                let mut first_device = first_device;
                first_device.protocol_device_id = 1;
                slot.insert(Record {
                    account,
                    devices: vec![first_device],
                });
                inner.device_ids.insert(device_id);
                Ok(())
            }
        }
    }

    async fn get(&self, handle: &str) -> Result<Option<Account>, StoreError> {
        Ok(self
            .inner
            .read()
            .expect("Store-Lock nicht vergiftet")
            .records
            .get(handle)
            .map(|r| r.account.clone()))
    }

    async fn set_password_hash(&self, handle: &str, password_hash: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("Store-Lock nicht vergiftet");
        let record = inner
            .records
            .get_mut(handle)
            .ok_or(StoreError::AccountMissing)?;
        record.account.password_hash = password_hash.to_string();
        Ok(())
    }

    async fn add_device(&self, handle: &str, device: Device) -> Result<u16, StoreError> {
        let mut inner = self.inner.write().expect("Store-Lock nicht vergiftet");
        if inner.device_ids.contains(&device.id) {
            return Err(StoreError::DeviceIdTaken);
        }
        let record = inner
            .records
            .get_mut(handle)
            .ok_or(StoreError::AccountMissing)?;
        // Nächste Nummer: max der vorhandenen (auch revozierter) plus 1.
        // Revozierte zählen mit, damit eine Nummer nie wiederkehrt.
        let next = record
            .devices
            .iter()
            .map(|d| d.protocol_device_id)
            .max()
            .unwrap_or(0)
            + 1;
        if next > crate::domain::MAX_PROTOCOL_DEVICE_ID {
            return Err(StoreError::TooManyDevices);
        }
        let device_id = device.id.clone();
        let mut device = device;
        device.protocol_device_id = next;
        record.devices.push(device);
        inner.device_ids.insert(device_id);
        Ok(next)
    }

    async fn devices(&self, handle: &str) -> Result<Vec<Device>, StoreError> {
        Ok(self
            .inner
            .read()
            .expect("Store-Lock nicht vergiftet")
            .records
            .get(handle)
            .map(|r| r.devices.clone())
            .unwrap_or_default())
    }

    async fn get_device(
        &self,
        handle: &str,
        device_id: &str,
    ) -> Result<Option<Device>, StoreError> {
        Ok(self
            .inner
            .read()
            .expect("Store-Lock nicht vergiftet")
            .records
            .get(handle)
            .and_then(|r| r.devices.iter().find(|d| d.id == device_id).cloned()))
    }

    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("Store-Lock nicht vergiftet");
        let record = inner
            .records
            .get_mut(handle)
            .ok_or(StoreError::AccountMissing)?;
        let device = record
            .devices
            .iter_mut()
            .find(|d| d.id == device_id && !d.revoked)
            .ok_or(StoreError::DeviceNotFound)?;
        device.revoked = true;
        Ok(())
    }

    async fn index_discovery(
        &self,
        prf_hex: &str,
        record: DiscoveryRecord,
    ) -> Result<(), StoreError> {
        self.inner
            .write()
            .expect("Store-Lock nicht vergiftet")
            .discovery
            .insert(prf_hex.to_string(), record);
        Ok(())
    }

    async fn discovery_lookup(&self, prf_hex: &str) -> Result<Option<DiscoveryRecord>, StoreError> {
        Ok(self
            .inner
            .read()
            .expect("Store-Lock nicht vergiftet")
            .discovery
            .get(prf_hex)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(handle: &str) -> Account {
        Account {
            id: "00000000-0000-4000-8000-000000000001".into(),
            handle: handle.into(),
            display_name: handle.into(),
            password_hash: "hash".into(),
            identity_key: "key".into(),
        }
    }

    fn device(id: &str) -> Device {
        Device {
            id: id.into(),
            name: id.into(),
            public_key: "pk".into(),
            credential: "sig".into(),
            not_after: i64::MAX as u64,
            revoked: false,
            protocol_device_id: 0,
        }
    }

    #[tokio::test]
    async fn create_and_get() {
        let store = InMemoryStore::default();
        assert!(store.create(account("alice"), device("d1")).await.is_ok());
        assert!(store.get("alice").await.unwrap().is_some());
        assert!(store.get("unbekannt").await.unwrap().is_none());
        assert_eq!(store.devices("alice").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn duplicate_handle_is_rejected() {
        let store = InMemoryStore::default();
        store.create(account("bob"), device("d1")).await.unwrap();
        assert_eq!(
            store.create(account("bob"), device("d2")).await,
            Err(StoreError::HandleTaken)
        );
    }

    #[tokio::test]
    async fn device_ids_are_globally_unique_even_after_revocation() {
        let store = InMemoryStore::default();
        store.create(account("alice"), device("d1")).await.unwrap();
        // Anderes Konto, gleiche ID: global gesperrt wie der PG-Primärschlüssel.
        assert_eq!(
            store.create(account("bob"), device("d1")).await,
            Err(StoreError::DeviceIdTaken)
        );
        assert_eq!(
            store.add_device("alice", device("d1")).await,
            Err(StoreError::DeviceIdTaken)
        );
        store.revoke_device("alice", "d1").await.unwrap();
        // Die ID bleibt gesperrt, sonst wäre das alte Credential für ein
        // neues Gerät mit derselben ID wiederverwendbar.
        assert_eq!(
            store.add_device("alice", device("d1")).await,
            Err(StoreError::DeviceIdTaken)
        );
    }

    #[tokio::test]
    async fn revoke_marks_device_and_is_not_repeatable() {
        let store = InMemoryStore::default();
        store.create(account("alice"), device("d1")).await.unwrap();
        store.add_device("alice", device("d2")).await.unwrap();
        assert!(store.revoke_device("alice", "d2").await.is_ok());
        assert!(
            store
                .get_device("alice", "d2")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert_eq!(
            store.revoke_device("alice", "d2").await,
            Err(StoreError::DeviceNotFound)
        );
    }

    #[tokio::test]
    async fn protocol_device_ids_are_assigned_monotonically() {
        let store = InMemoryStore::default();
        store.create(account("alice"), device("d1")).await.unwrap();
        // Erstes Gerät ist Nummer 1, unabhängig vom übergebenen Platzhalter.
        assert_eq!(
            store.devices("alice").await.unwrap()[0].protocol_device_id,
            1
        );
        assert_eq!(store.add_device("alice", device("d2")).await, Ok(2));
        assert_eq!(store.add_device("alice", device("d3")).await, Ok(3));
        // Revozieren gibt die Nummer NICHT frei: das nächste Gerät ist 4.
        store.revoke_device("alice", "d3").await.unwrap();
        assert_eq!(store.add_device("alice", device("d4")).await, Ok(4));
    }

    #[tokio::test]
    async fn missing_account_yields_account_missing() {
        let store = InMemoryStore::default();
        assert_eq!(
            store.add_device("niemand", device("d1")).await,
            Err(StoreError::AccountMissing)
        );
        assert!(store.devices("niemand").await.unwrap().is_empty());
    }
}
