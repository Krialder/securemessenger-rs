//! Lokale Schlüssel-Werte-Ablage der Clients: der Storage-Trait aus GOAL.md.
//!
//! Hinter diesem Trait liegen die privaten Schlüssel, Sitzungen und der
//! Ratchet-Zustand des Geräts (protocol_store.rs). Die Umsetzungen sind
//! bewusst schlicht: In-Memory für Tests, eine JSON-Datei für den
//! Referenzclient. Der Browser-Client bindet später IndexedDB an.
//!
//! [ANNAHME: Der Trait ist synchron, weil beide heutigen Umsetzungen es
//! sind; die IndexedDB-Anbindung (asynchron) läuft mit der Web-Etappe über
//! einen In-Memory-Spiegel mit asynchronem Flush oder macht den Trait dann
//! async. Die Datei-Ablage ist unverschlüsselt: wer die Datei hat, hat die
//! Identität, wie beim CLI-Profil. Die verschlüsselte Geräte-Ablage
//! (Keystore-Anbindung) ist eine eigene Etappe; sicherheit.md nennt den
//! Web-Client ohnehin als schwächstes Glied.]

use std::collections::HashMap;

/// Schlüssel-Werte-Ablage für Protokoll-Zustand. Werte sind opake Bytes
/// (libsignal-Records); die Schlüssel-Namen vergibt protocol_store.rs.
pub trait KeyValueStorage: 'static {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String>;
    fn remove(&mut self, key: &str) -> Result<(), String>;
}

/// Flüchtige Ablage für Tests; Daten enden mit dem Prozess.
#[derive(Default)]
pub struct InMemoryStorage {
    values: HashMap<String, Vec<u8>>,
}

impl KeyValueStorage for InMemoryStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.values.get(key).cloned())
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        self.values.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn remove(&mut self, key: &str) -> Result<(), String> {
        self.values.remove(key);
        Ok(())
    }
}

/// Datei-Ablage für den Referenzclient: eine JSON-Datei, Werte Base64.
/// Jede Änderung schreibt die Datei neu über eine Temporärdatei plus
/// Umbenennen, damit ein Absturz beim Schreiben nicht den ganzen Zustand
/// (und damit die Sitzungen) zerreißt.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileStorage {
    path: std::path::PathBuf,
    values: HashMap<String, Vec<u8>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileStorage {
    /// Öffnet die Ablage; eine fehlende Datei ist ein leerer Zustand.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let path = path.into();
        let values = match std::fs::read(&path) {
            Ok(bytes) => {
                let encoded: HashMap<String, String> = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("Zustands-Datei unlesbar: {error}"))?;
                let mut decoded = HashMap::with_capacity(encoded.len());
                for (key, value) in encoded {
                    let bytes = BASE64
                        .decode(&value)
                        .map_err(|_| format!("Zustands-Datei: Wert zu '{key}' kein Base64"))?;
                    decoded.insert(key, bytes);
                }
                decoded
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(format!("Zustands-Datei nicht lesbar: {error}")),
        };
        Ok(Self { path, values })
    }

    fn persist(&self) -> Result<(), String> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let encoded: HashMap<&String, String> = self
            .values
            .iter()
            .map(|(key, value)| (key, BASE64.encode(value)))
            .collect();
        let json = serde_json::to_vec_pretty(&encoded)
            .map_err(|error| format!("Zustand nicht serialisierbar: {error}"))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|error| format!("Zustand nicht schreibbar: {error}"))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|error| format!("Zustands-Datei nicht ersetzbar: {error}"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl KeyValueStorage for FileStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.values.get(key).cloned())
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        self.values.insert(key.to_string(), value.to_vec());
        self.persist()
    }

    fn remove(&mut self, key: &str) -> Result<(), String> {
        if self.values.remove(key).is_some() {
            self.persist()?;
        }
        Ok(())
    }
}
