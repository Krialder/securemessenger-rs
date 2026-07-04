//! Persistente Browser-Ablage: IndexedDB hinter dem synchronen
//! Storage-Trait aus client-app.
//!
//! IndexedDB ist asynchron, der Trait synchron (storage.rs in client-app
//! begründet das). Die Brücke ist der dort schon vorgesehene
//! In-Memory-Spiegel mit asynchronem Flush: alle Zugriffe laufen gegen
//! eine HashMap, jede Mutation schreibt den vollständigen Zustand als
//! einen einzigen Datensatz nach IndexedDB (ein Blob wie bei der
//! FileStorage-JSON-Datei: ein atomarer Tausch statt vieler Einzelkeys,
//! die halb geschrieben zurückbleiben könnten). Geladen wird einmal beim
//! Start über [`BrowserStorage::open`].
//!
//! [ANNAHME: Der Flush ist fire-and-forget (spawn_local); die Reihenfolge
//! stimmt, weil readwrite-Transaktionen auf demselben Object Store in
//! Erstellreihenfolge ausgeführt werden und jeder Flush den Gesamtzustand
//! trägt (der letzte gewinnt). Ein Tab-Schluss unmittelbar nach einer
//! Mutation kann den letzten Flush verlieren; für den Referenz-Web-Client
//! hinnehmbar, dokumentiert als Grenze. Unverschlüsselt wie CLI-Profil
//! und -Zustand; sicherheit.md führt den Browser ohnehin als schwächstes
//! Glied.]

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::storage::KeyValueStorage;
use indexed_db_futures::database::Database;
use indexed_db_futures::prelude::*;
use indexed_db_futures::transaction::TransactionMode;
use wasm_bindgen_futures::spawn_local;

const DB_NAME: &str = "securemessenger";
const STORE_NAME: &str = "state";
/// Schlüssel des einen Zustands-Datensatzes; die Versionsnummer erlaubt
/// später ein Format-Upgrade neben dem alten Datensatz.
const STATE_KEY: &str = "smstate.v1";

pub struct BrowserStorage {
    values: HashMap<String, Vec<u8>>,
}

async fn open_database() -> Result<Database, String> {
    Database::open(DB_NAME)
        .with_version(1u8)
        .with_on_upgrade_needed(|_event, db| {
            if !db.object_store_names().any(|name| name == STORE_NAME) {
                db.create_object_store(STORE_NAME).build()?;
            }
            Ok(())
        })
        .await
        .map_err(|error| format!("IndexedDB nicht verfügbar: {error}"))
}

impl BrowserStorage {
    /// Lädt den gespeicherten Zustand; eine leere Datenbank ist ein
    /// leerer Zustand (erster Besuch).
    pub async fn open() -> Result<Self, String> {
        let db = open_database().await?;
        let tx = db
            .transaction(STORE_NAME)
            .with_mode(TransactionMode::Readonly)
            .build()
            .map_err(|error| format!("IndexedDB-Transaktion: {error}"))?;
        let store = tx
            .object_store(STORE_NAME)
            .map_err(|error| format!("IndexedDB-Store: {error}"))?;
        let stored: Option<String> = store
            .get(STATE_KEY)
            .await
            .map_err(|error| format!("IndexedDB-Lesen: {error}"))?;
        let values = match stored {
            Some(json) => decode_state(&json)?,
            None => HashMap::new(),
        };
        Ok(Self { values })
    }

    /// Serialisiert synchron (der Zustand ist klein, wenige KiB) und
    /// schreibt asynchron; Fehler landen in der Konsole, weil der
    /// synchrone Trait sie nicht mehr zurückgeben kann.
    fn persist(&self) {
        let json = encode_state(&self.values);
        spawn_local(async move {
            if let Err(error) = write_state(json).await {
                web_sys::console::error_1(
                    &format!("Zustand nicht nach IndexedDB geschrieben: {error}").into(),
                );
            }
        });
    }
}

async fn write_state(json: String) -> Result<(), String> {
    let db = open_database().await?;
    let tx = db
        .transaction(STORE_NAME)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|error| format!("Transaktion: {error}"))?;
    tx.object_store(STORE_NAME)
        .map_err(|error| format!("Store: {error}"))?
        .put(json)
        .with_key(STATE_KEY)
        .await
        .map_err(|error| format!("Schreiben: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("Commit: {error}"))?;
    Ok(())
}

/// Dasselbe Format wie die FileStorage-JSON-Datei: Werte Base64, damit
/// der Zustand debugbar bleibt und kein Binär-Marshalling braucht.
fn encode_state(values: &HashMap<String, Vec<u8>>) -> String {
    let encoded: HashMap<&String, String> = values
        .iter()
        .map(|(key, value)| (key, BASE64.encode(value)))
        .collect();
    serde_json::to_string(&encoded).expect("HashMap<String,String> ist immer serialisierbar")
}

fn decode_state(json: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let encoded: HashMap<String, String> =
        serde_json::from_str(json).map_err(|error| format!("Zustand unlesbar: {error}"))?;
    let mut decoded = HashMap::with_capacity(encoded.len());
    for (key, value) in encoded {
        let bytes = BASE64
            .decode(&value)
            .map_err(|_| format!("Zustand: Wert zu '{key}' kein Base64"))?;
        decoded.insert(key, bytes);
    }
    Ok(decoded)
}

impl KeyValueStorage for BrowserStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.values.get(key).cloned())
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        self.values.insert(key.to_string(), value.to_vec());
        self.persist();
        Ok(())
    }

    fn remove(&mut self, key: &str) -> Result<(), String> {
        if self.values.remove(key).is_some() {
            self.persist();
        }
        Ok(())
    }
}
