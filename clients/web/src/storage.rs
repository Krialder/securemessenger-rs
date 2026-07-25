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
//! hinnehmbar, dokumentiert als Grenze.]
//!
//! Verschlüsselung: Der gesamte Zustands-Blob wird unter dem
//! Login-Passwort im keystore-Envelope gesealt (Argon2id +
//! ChaCha20-Poly1305), sodass der blosse IndexedDB-Eintrag ohne Passwort
//! wertlos ist, auch die Schlüsselnamen. Weil der ganze Blob
//! verschlüsselt ist, kennt die App den Handle vor dem Entsperren nicht;
//! ein verschlüsseltes Konto ist deshalb ein eigener Boot-Zustand
//! (`Locked`). Der Sealer wird erst gesetzt, nachdem das Passwort feststeht
//! (bei der Registrierung durch die eigene Wahl, bei der Anmeldung durch
//! die Server-Bestätigung), damit ein falscher Anmeldeversuch die Ablage
//! nicht mit dem falschen Schlüssel verschlüsselt.

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
/// Schlüssel des Ordner-Handles der automatischen Sicherung. Liegt im
/// SELBEN Object Store, aber unter eigenem Schlüssel: so braucht es keine
/// Versions-Erhöhung der Datenbank (die einen Upgrade-Pfad für bestehende
/// Ablagen erzwingen würde). Das Handle ist kein JSON, sondern ein
/// strukturiert klonbares Browser-Objekt, deshalb liegt es neben dem
/// Zustands-Blob und nicht darin.
const BACKUP_FOLDER_KEY: &str = "smbakfolder.v1";

pub struct BrowserStorage {
    /// Der entschlüsselte Zustand; leer, solange eine verschlüsselte Ablage
    /// noch nicht entsperrt ist.
    values: HashMap<String, Vec<u8>>,
    /// Der beim Start geladene Roh-Blob (gesealt oder Klartext), bis zum
    /// Entsperren aufbewahrt; `None` bei erstem Besuch.
    raw: Option<Vec<u8>>,
    /// Gesetzt, sobald das Passwort feststeht; dann wird verschlüsselt
    /// geschrieben.
    sealer: Option<keystore::Sealer>,
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
    /// Lädt den gespeicherten Zustand. Ein gesealter Blob wird NICHT
    /// entschlüsselt (das Passwort fehlt), sondern roh aufbewahrt; ein
    /// Klartext-Blob (älterer Client) wird dekodiert. Eine leere Datenbank
    /// ist ein leerer Zustand (erster Besuch).
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
        // Der IndexedDB-Wert ist immer ein String: neue Schreibvorgänge
        // legen Base64(Blob) ab, ältere legten rohes JSON ab. Weil JSON nie
        // gültiges Base64 ist (es beginnt mit '{'), unterscheidet die
        // Base64-Dekodierbarkeit die beiden Formate sauber.
        let stored: Option<String> = store
            .get(STATE_KEY)
            .await
            .map_err(|error| format!("IndexedDB-Lesen: {error}"))?;
        let Some(text) = stored else {
            return Ok(Self {
                values: HashMap::new(),
                raw: None,
                sealer: None,
            });
        };
        let bytes = match BASE64.decode(&text) {
            // Neues Format: der dekodierte Blob ist gesealt oder (defensiv)
            // roher Klartext.
            Ok(bytes) => bytes,
            // Altes Format: rohes JSON, kein Base64.
            Err(_) => text.into_bytes(),
        };
        if keystore::is_sealed(&bytes) {
            // Gesealt: roh halten, erst unlock entschlüsselt.
            Ok(Self {
                values: HashMap::new(),
                raw: Some(bytes),
                sealer: None,
            })
        } else {
            // Klartext (Migration): dekodieren, damit der Handle sofort
            // lesbar ist; verschlüsselt wird beim nächsten Passwort.
            Ok(Self {
                values: decode_state(&bytes)?,
                raw: Some(bytes),
                sealer: None,
            })
        }
    }

    /// Ob überhaupt ein Konto in der Ablage liegt (für die Boot-Entscheidung
    /// Registrieren gegen Anmelden).
    pub fn has_state(&self) -> bool {
        self.raw.is_some()
    }

    /// Ob eine verschlüsselte Ablage vorliegt, die noch entsperrt werden
    /// muss (der Handle ist dann vor dem Passwort unbekannt).
    pub fn is_locked(&self) -> bool {
        self.sealer.is_none() && self.raw.as_deref().is_some_and(keystore::is_sealed)
    }

    /// Entsperrt eine gesealte Ablage mit dem Passwort: entschlüsselt den
    /// Blob, füllt die Werte und merkt sich den Sealer. Bei einer nicht
    /// gesealten Ablage (frisch oder Klartext) tut es nichts (es gibt nichts
    /// zu entschlüsseln, das Verschlüsseln übernimmt `adopt_passphrase` nach
    /// der Passwort-Bestätigung). Falsche Passphrase: Fehler.
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), String> {
        if self.sealer.is_some() {
            return Ok(());
        }
        let Some(bytes) = self.raw.as_deref() else {
            return Ok(());
        };
        if !keystore::is_sealed(bytes) {
            return Ok(());
        }
        let (sealer, plaintext) =
            keystore::Sealer::unlock(passphrase, bytes).map_err(|e| e.to_string())?;
        self.values = decode_state(&plaintext)?;
        self.sealer = Some(sealer);
        Ok(())
    }

    /// Legt den Verschlüsselungs-Schlüssel aus dem (nun feststehenden)
    /// Passwort fest und schreibt den Zustand sofort verschlüsselt. Für
    /// frische Konten (Registrierung) und die Migration einer alten
    /// Klartext-Ablage nach erfolgreicher Anmeldung. Ist bereits ein Sealer
    /// gesetzt (gesealt entsperrt), passiert nichts.
    pub fn adopt_passphrase(&mut self, passphrase: &str) {
        if self.sealer.is_some() {
            return;
        }
        self.sealer = Some(keystore::Sealer::create(passphrase));
        self.persist();
    }

    /// Bereitet die Neuversiegelung unter einer NEUEN Passphrase vor
    /// (Passwortwechsel): ersetzt den Sealer bedingungslos und liefert den
    /// unter dem neuen Schlüssel versiegelten Blob zum Schreiben zurück. Der
    /// Aufrufer schreibt ihn anschließend mit [`write_state`] und wartet das
    /// Ergebnis ab, damit ein fehlgeschlagener IndexedDB-Schreibvorgang nicht
    /// still bleibt (dann stünde der Dienst auf dem neuen, die Ablage aber auf
    /// dem alten Passwort, und die nächste Anmeldung sperrte sich aus). Bewusst
    /// getrennt vom Schreiben, damit der `RefCell`-Borrow nicht über das
    /// `await` gehalten wird. Nötig, weil die lokale Ablage unter dem
    /// Login-Passwort verschlüsselt ist.
    pub fn reseal_prepare(&mut self, passphrase: &str) -> String {
        let sealer = keystore::Sealer::create(passphrase);
        let json = encode_state(&self.values);
        let stored = BASE64.encode(sealer.seal(json.as_bytes()));
        self.sealer = Some(sealer);
        stored
    }

    /// Erzeugt eine Sicherungs-Datei des gesamten Zustands, versiegelt unter
    /// einer Sicherungs-Passphrase (`backup`-Modul, smbak.v1). Braucht einen
    /// entsperrten Zustand (angemeldet); der Aufrufer bietet den Download an.
    pub fn export_backup(&self, passphrase: &str) -> Result<Vec<u8>, String> {
        let json = encode_state(&self.values);
        client_app::backup::seal(json.as_bytes(), passphrase)
    }

    /// Stellt den Zustand aus einer Sicherungs-Datei wieder her: entschlüsselt
    /// mit der Sicherungs-Passphrase und ERSETZT den gesamten Zustand. Wird
    /// bewusst NICHT sofort geschrieben: der Sealer bleibt offen, damit die
    /// anschließende Anmeldung die Ablage unter dem Konto-Passwort versiegelt
    /// (kein Klartext im Ruhezustand und kein Passwort, das vom Konto-Passwort
    /// abweicht). Bricht der Nutzer vor der Anmeldung ab, ist nichts
    /// geschrieben und der Import zu wiederholen. Liefert nichts; den Handle
    /// liest der Aufrufer danach aus dem Profil.
    ///
    /// `required_key` muss in der Sicherung liegen (der Profil-Schlüssel),
    /// sonst ist sie kein brauchbares Konto und der bestehende Zustand bleibt
    /// UNANGETASTET (erst prüfen, dann ersetzen), statt ihn gegen eine
    /// unbrauchbare Sicherung einzutauschen.
    pub fn import_backup(
        &mut self,
        file: &[u8],
        passphrase: &str,
        required_key: &str,
    ) -> Result<(), String> {
        let plaintext = client_app::backup::open(file, passphrase)?;
        let values = decode_state(&plaintext)?;
        if !values.contains_key(required_key) {
            return Err("Die Sicherung enthält kein Konto.".to_string());
        }
        self.values = values;
        self.sealer = None;
        // has_state() soll true melden (ein Konto liegt vor); der Blob ist
        // aber unversiegelt, also is_locked() = false -> die Anmeldung für den
        // wiederhergestellten Handle greift.
        self.raw = Some(plaintext);
        Ok(())
    }

    /// Serialisiert synchron (der Zustand ist klein, wenige KiB), sealt ihn
    /// mit dem Sealer, falls gesetzt, und schreibt asynchron; Fehler landen
    /// in der Konsole, weil der synchrone Trait sie nicht mehr zurückgeben
    /// kann.
    fn persist(&self) {
        let json = encode_state(&self.values);
        let blob = match &self.sealer {
            Some(sealer) => sealer.seal(json.as_bytes()),
            None => json.into_bytes(),
        };
        // Immer als Base64-String ablegen (siehe open): ein einheitlicher
        // IndexedDB-Werttyp, und der gesealte Binär-Blob bleibt speicherbar.
        let stored = BASE64.encode(&blob);
        spawn_local(async move {
            if let Err(error) = write_state(stored).await {
                web_sys::console::error_1(
                    &format!("Zustand nicht nach IndexedDB geschrieben: {error}").into(),
                );
            }
        });
    }
}

/// Legt das Ordner-Handle der automatischen Sicherung ab. Das Handle ist ein
/// Browser-Objekt (strukturiert klonbar), IndexedDB kann es also direkt
/// speichern; JSON könnte es nicht, deshalb der eigene Weg neben dem
/// Zustands-Blob.
pub async fn save_backup_folder(handle: wasm_bindgen::JsValue) -> Result<(), String> {
    let db = open_database().await?;
    let tx = db
        .transaction(STORE_NAME)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|error| format!("Transaktion: {error}"))?;
    tx.object_store(STORE_NAME)
        .map_err(|error| format!("Store: {error}"))?
        .put(handle)
        .with_key(BACKUP_FOLDER_KEY)
        .await
        .map_err(|error| format!("Ordner-Handle nicht gespeichert: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("Commit: {error}"))?;
    Ok(())
}

/// Holt das abgelegte Ordner-Handle zurück. `None`, wenn keiner gewählt wurde.
/// Ob die Schreib-Erlaubnis noch gilt, sagt das Handle selbst (der Browser
/// kann sie zwischen zwei Besuchen verlieren, siehe `folder`-Modul).
pub async fn load_backup_folder() -> Option<wasm_bindgen::JsValue> {
    let db = open_database().await.ok()?;
    let tx = db
        .transaction(STORE_NAME)
        .with_mode(TransactionMode::Readonly)
        .build()
        .ok()?;
    let store = tx.object_store(STORE_NAME).ok()?;
    let stored: Option<wasm_bindgen::JsValue> = store.get(BACKUP_FOLDER_KEY).await.ok().flatten();
    stored
}

/// Entfernt das Ordner-Handle (Nutzer schaltet die automatische Sicherung ab).
pub async fn clear_backup_folder() -> Result<(), String> {
    let db = open_database().await?;
    let tx = db
        .transaction(STORE_NAME)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|error| format!("Transaktion: {error}"))?;
    tx.object_store(STORE_NAME)
        .map_err(|error| format!("Store: {error}"))?
        .delete(BACKUP_FOLDER_KEY)
        .await
        .map_err(|error| format!("Ordner-Handle nicht entfernt: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("Commit: {error}"))?;
    Ok(())
}

/// Schreibt den (bereits kodierten) Zustands-Blob nach IndexedDB und wartet
/// die Bestätigung ab. Öffentlich, damit `reseal_prepare` und der Aufrufer
/// den Schreibvorgang getrennt vom `RefCell`-Borrow abwarten können.
pub async fn write_state(stored: String) -> Result<(), String> {
    let db = open_database().await?;
    let tx = db
        .transaction(STORE_NAME)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|error| format!("Transaktion: {error}"))?;
    tx.object_store(STORE_NAME)
        .map_err(|error| format!("Store: {error}"))?
        .put(stored)
        .with_key(STATE_KEY)
        .await
        .map_err(|error| format!("Schreiben: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("Commit: {error}"))?;
    Ok(())
}

/// Der innere Klartext des Blobs: dieselbe JSON-Map wie bei der
/// FileStorage-Datei (Werte Base64), debugbar und ohne Binär-Marshalling.
fn encode_state(values: &HashMap<String, Vec<u8>>) -> String {
    let encoded: HashMap<&String, String> = values
        .iter()
        .map(|(key, value)| (key, BASE64.encode(value)))
        .collect();
    serde_json::to_string(&encoded).expect("HashMap<String,String> ist immer serialisierbar")
}

fn decode_state(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    let encoded: HashMap<String, String> =
        serde_json::from_slice(bytes).map_err(|error| format!("Zustand unlesbar: {error}"))?;
    let mut decoded = HashMap::with_capacity(encoded.len());
    for (key, value) in encoded {
        let raw = BASE64
            .decode(&value)
            .map_err(|_| format!("Zustand: Wert zu '{key}' kein Base64"))?;
        decoded.insert(key, raw);
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
