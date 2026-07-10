//! Lokale Schlüssel-Werte-Ablage der Clients: der Storage-Trait aus GOAL.md.
//!
//! Hinter diesem Trait liegen die privaten Schlüssel, Sitzungen und der
//! Ratchet-Zustand des Geräts (protocol_store.rs). Die Umsetzungen sind
//! bewusst schlicht: In-Memory für Tests, eine JSON-Datei für den
//! Referenzclient. Der Browser-Client bindet später IndexedDB an.
//!
//! [ANNAHME: Der Trait ist synchron, weil beide heutigen Umsetzungen es
//! sind; die IndexedDB-Anbindung (asynchron) läuft über einen
//! In-Memory-Spiegel mit asynchronem Flush (clients/web/src/storage.rs).
//! Die Datei-Ablage hat zwei Betriebsarten: `open` schreibt Klartext
//! (Entwicklung, Tests), `open_encrypted` legt den Blob unter einer
//! Passphrase im keystore-Envelope ab.]

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

/// Kodiert die Wert-Map als JSON-Bytes (Werte Base64), das gemeinsame
/// Klartext-Format der Datei- und Browser-Ablage. Debugbar und ohne
/// Binär-Marshalling.
#[cfg(not(target_arch = "wasm32"))]
fn encode_map(values: &HashMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let encoded: HashMap<&String, String> = values
        .iter()
        .map(|(key, value)| (key, BASE64.encode(value)))
        .collect();
    serde_json::to_vec_pretty(&encoded)
        .map_err(|error| format!("Zustand nicht serialisierbar: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
fn decode_map(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let encoded: HashMap<String, String> = serde_json::from_slice(bytes)
        .map_err(|error| format!("Zustands-Datei unlesbar: {error}"))?;
    let mut decoded = HashMap::with_capacity(encoded.len());
    for (key, value) in encoded {
        let raw = BASE64
            .decode(&value)
            .map_err(|_| format!("Zustands-Datei: Wert zu '{key}' kein Base64"))?;
        decoded.insert(key, raw);
    }
    Ok(decoded)
}

/// Datei-Ablage für den Referenzclient. Jede Änderung schreibt die Datei
/// neu über eine Temporärdatei plus Umbenennen, damit ein Absturz beim
/// Schreiben nicht den ganzen Zustand (und damit die Sitzungen) zerreißt.
///
/// Zwei Betriebsarten: `open` schreibt Klartext-JSON (Entwicklung, Tests),
/// `open_encrypted` legt den gesamten Blob unter einer Passphrase im
/// keystore-Envelope ab (Identität, Sitzungen, Kontakte und Verläufe sind
/// dann ohne Passphrase wertlos, auch die Schlüsselnamen). Ein `Sealer`
/// hält den einmal abgeleiteten Schlüssel, damit nicht jedes Schreiben
/// erneut Argon2 zahlt.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileStorage {
    path: std::path::PathBuf,
    values: HashMap<String, Vec<u8>>,
    sealer: Option<keystore::Sealer>,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileStorage {
    /// Öffnet die Ablage im Klartext; eine fehlende Datei ist ein leerer
    /// Zustand. Eine verschlüsselte Datei wird hier NICHT stillschweigend
    /// als Klartext gelesen, sondern klar abgelehnt (die Passphrase fehlt).
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let values = match std::fs::read(&path) {
            Ok(bytes) if keystore::is_sealed(&bytes) => {
                return Err(
                    "Zustands-Datei ist verschlüsselt; mit Passphrase öffnen (SM_PASSPHRASE)."
                        .to_string(),
                )
            }
            Ok(bytes) => decode_map(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(format!("Zustands-Datei nicht lesbar: {error}")),
        };
        Ok(Self {
            path,
            values,
            sealer: None,
        })
    }

    /// Öffnet die Ablage verschlüsselt unter einer Passphrase. Migration:
    /// Ist die vorhandene Datei noch Klartext (älterer Client), wird sie
    /// gelesen und beim nächsten Schreiben verschlüsselt abgelegt. Eine
    /// falsche Passphrase (oder eine manipulierte Datei) scheitert hier.
    pub fn open_encrypted(
        path: impl Into<std::path::PathBuf>,
        passphrase: &str,
    ) -> Result<Self, String> {
        let path = path.into();
        let (values, sealer) = match std::fs::read(&path) {
            Ok(bytes) if keystore::is_sealed(&bytes) => {
                let (sealer, plaintext) =
                    keystore::Sealer::unlock(passphrase, &bytes).map_err(|e| e.to_string())?;
                (decode_map(&plaintext)?, sealer)
            }
            // Klartext-Datei eines älteren Clients: einmal lesen, dann beim
            // ersten Schreiben mit frischem Sealer verschlüsseln.
            Ok(bytes) => (decode_map(&bytes)?, keystore::Sealer::create(passphrase)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (HashMap::new(), keystore::Sealer::create(passphrase))
            }
            Err(error) => return Err(format!("Zustands-Datei nicht lesbar: {error}")),
        };
        Ok(Self {
            path,
            values,
            sealer: Some(sealer),
        })
    }

    fn persist(&self) -> Result<(), String> {
        let json = encode_map(&self.values)?;
        let bytes = match &self.sealer {
            Some(sealer) => sealer.seal(&json),
            None => json,
        };
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)
            .map_err(|error| format!("Zustand nicht schreibbar: {error}"))?;
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
