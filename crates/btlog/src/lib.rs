//! Binary-Transparency-Log: der Mechanismus (ADR-0007).
//!
//! Reproducible Builds beantworten die Frage "entspricht dieses Binary dem
//! Quellcode?"; Binary Transparency beantwortet die zweite, ohne die die
//! erste wenig hilft: "haben alle dasselbe Binary bekommen?". Dafür wird
//! jedes Release-Artefakt (Name, Version, SHA-256) in ein append-only Log
//! eingetragen. Die Einträge sind hash-verkettet (jeder Eintrag trägt den
//! Hash seines Vorgängers), und der Kopf (Anzahl plus Ketten-Hash) ist
//! Ed25519-signiert. Ein Auditor mit einer Kopie des Logs erkennt damit
//! jede nachträgliche Änderung, Löschung oder Umordnung: Sie bricht die
//! Kette oder die Signatur. Ein Client, der sein Binary im Log findet,
//! weiß, dass er dasselbe bekommen hat, das öffentlich protokolliert ist;
//! ein gezielt untergeschobenes Sonder-Binary stünde nicht im Log.
//!
//! Kein Eigenbau-Krypto: SHA-256 und Ed25519 kommen aus den geprüften
//! Bibliotheken, die Kette ist eine Datenstruktur darüber (dasselbe
//! Muster wie Certificate Transparency, auf das Nötigste reduziert).
//!
//! [ANNAHME: Eine Hash-Kette statt eines Merkle-Baums. Sie gibt einem
//! Voll-Kopie-Auditor dieselbe Append-only-Garantie, nur Inklusions-
//! Beweise gegen Dritte ohne Voll-Kopie brauchen den Baum; die liefert
//! die Betriebs-Stufe (Rekor/Sigstore oder akd), die dieses Format nur
//! ablöst, nicht erweitert. Ablage als JSON-Zeilen plus Kopf-Datei: das
//! Log ist selbst ein Release-Artefakt und soll diff- und spiegelbar
//! sein, ein Log-Dienst ist Betrieb, nicht Mechanismus.]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fehler des Logs, als beschreibender Text: die Aufrufer (Werkzeug,
/// Tests) machen daraus eine Meldung, keine Fallunterscheidung.
#[derive(Debug)]
pub struct BtError(pub String);

impl std::fmt::Display for BtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BtError {}

fn err(message: impl Into<String>) -> BtError {
    BtError(message.into())
}

/// Ein Log-Eintrag: ein veröffentlichtes Artefakt. Die Hashes reisen im
/// JSON als Base64 (Projektkonvention), intern als rohe 32 Bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LogEntry {
    /// Fortlaufende Position, beginnend bei 0; redundant zur Zeilennummer,
    /// aber im Eintrag selbst, damit die kanonischen Bytes sie binden.
    pub index: u64,
    /// Artefaktname, z. B. `sm.exe` oder `securemessenger/identity:1.4.0`.
    pub artifact: String,
    /// Versionsangabe des Releases.
    pub version: String,
    /// SHA-256 des Artefakts (Base64).
    pub sha256: String,
    /// Bauzeitpunkt in Unix-Sekunden; der Aufrufer liefert ihn (das
    /// Werkzeug nimmt `SOURCE_DATE_EPOCH`, die Reproducible-Builds-
    /// Konvention, und fällt sonst auf die aktuelle Zeit zurück).
    pub built_at: u64,
    /// Hash des Vorgänger-Eintrags (Base64); beim ersten Eintrag 32
    /// Null-Bytes. Diese Verkettung macht das Log append-only.
    pub prev_hash: String,
}

/// Der signierte Kopf: bindet Anzahl und Ketten-Hash. Wer den Kopf hat
/// und dem Schlüssel traut, kann jede Log-Kopie vollständig prüfen.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LogHead {
    pub count: u64,
    /// Hash des letzten Eintrags (Base64); bei leerem Log 32 Null-Bytes.
    pub head_hash: String,
    /// Ed25519-Signatur über die kanonischen Kopf-Bytes (Base64).
    pub signature: String,
}

const ZERO_HASH: [u8; 32] = [0u8; 32];

fn decode_hash(b64: &str, what: &str) -> Result<[u8; 32], BtError> {
    let raw = BASE64
        .decode(b64)
        .map_err(|_| err(format!("{what} ist kein Base64")))?;
    raw.try_into()
        .map_err(|_| err(format!("{what} hat nicht 32 Bytes")))
}

/// Die kanonischen Bytes eines Eintrags (`smbt.v1`): Domain-Präfix, feste
/// Breiten für die binären Felder und ein Längen-Präfix (u64, Big Endian)
/// vor jedem variabel langen Feld. Über genau diese Bytes läuft der
/// Ketten-Hash; JSON ist nur Transport, nie Hash-Grundlage.
///
/// Das Längen-Präfix statt eines Trennzeichens macht die Kodierung
/// injektiv: Mit einem Trenner (etwa 0x00) ließe sich die Grenze zwischen
/// Artefakt und Version verschieben, sobald ein Feldwert das Trennzeichen
/// selbst enthält, und zwei verschiedene Einträge fielen auf dieselben
/// signierten Bytes zusammen. Eine kanonische Kodierung eines
/// Transparenz-Mechanismus muss diese Eigenschaft unabhängig davon haben,
/// wie vertrauenswürdig der Signierer ist.
pub fn entry_bytes(entry: &LogEntry) -> Result<Vec<u8>, BtError> {
    let sha256 = decode_hash(&entry.sha256, "sha256")?;
    let prev = decode_hash(&entry.prev_hash, "prev_hash")?;
    let mut bytes = Vec::with_capacity(80 + entry.artifact.len() + entry.version.len());
    bytes.extend_from_slice(b"smbt.v1");
    bytes.extend_from_slice(&entry.index.to_be_bytes());
    bytes.extend_from_slice(&prev);
    bytes.extend_from_slice(&(entry.artifact.len() as u64).to_be_bytes());
    bytes.extend_from_slice(entry.artifact.as_bytes());
    bytes.extend_from_slice(&(entry.version.len() as u64).to_be_bytes());
    bytes.extend_from_slice(entry.version.as_bytes());
    bytes.extend_from_slice(&sha256);
    bytes.extend_from_slice(&entry.built_at.to_be_bytes());
    Ok(bytes)
}

/// Der Hash eines Eintrags: SHA-256 über die kanonischen Bytes.
pub fn entry_hash(entry: &LogEntry) -> Result<[u8; 32], BtError> {
    Ok(Sha256::digest(entry_bytes(entry)?).into())
}

/// Die kanonischen Bytes des Kopfs (`smbth.v1`), die Signatur-Grundlage.
pub fn head_bytes(count: u64, head_hash: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 8 + 32);
    bytes.extend_from_slice(b"smbth.v1");
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(head_hash);
    bytes
}

/// Hängt ein Artefakt an das Log an und liefert den neuen Eintrag samt
/// frisch signiertem Kopf. Der Aufrufer persistiert beides; die Funktion
/// selbst ist rein, damit die Tests sie ohne Dateisystem treiben können.
pub fn append(
    entries: &[LogEntry],
    artifact: &str,
    version: &str,
    sha256: &[u8; 32],
    built_at: u64,
    signing_key: &SigningKey,
) -> Result<(LogEntry, LogHead), BtError> {
    let prev_hash = match entries.last() {
        Some(last) => entry_hash(last)?,
        None => ZERO_HASH,
    };
    let entry = LogEntry {
        index: entries.len() as u64,
        artifact: artifact.to_string(),
        version: version.to_string(),
        sha256: BASE64.encode(sha256),
        built_at,
        prev_hash: BASE64.encode(prev_hash),
    };
    let head_hash = entry_hash(&entry)?;
    let count = entry.index + 1;
    let signature = signing_key.sign(&head_bytes(count, &head_hash));
    let head = LogHead {
        count,
        head_hash: BASE64.encode(head_hash),
        signature: BASE64.encode(signature.to_bytes()),
    };
    Ok((entry, head))
}

/// Prüft eine vollständige Log-Kopie gegen ihren signierten Kopf: die
/// Indizes sind lückenlos, die Kette schließt sich, der Kopf bindet den
/// letzten Eintrag, und die Signatur stammt vom erwarteten Schlüssel.
/// Jede Abweichung (geänderter, gelöschter, eingeschobener oder
/// umgeordneter Eintrag) bricht genau eine dieser Prüfungen.
pub fn verify(
    entries: &[LogEntry],
    head: &LogHead,
    verifying_key: &VerifyingKey,
) -> Result<(), BtError> {
    if head.count != entries.len() as u64 {
        return Err(err(format!(
            "Kopf nennt {} Einträge, die Kopie hat {}",
            head.count,
            entries.len()
        )));
    }
    let mut prev = ZERO_HASH;
    for (i, entry) in entries.iter().enumerate() {
        if entry.index != i as u64 {
            return Err(err(format!(
                "Eintrag an Position {i} trägt Index {}",
                entry.index
            )));
        }
        let claimed_prev = decode_hash(&entry.prev_hash, "prev_hash")?;
        if claimed_prev != prev {
            return Err(err(format!("Kette bricht bei Eintrag {i}")));
        }
        prev = entry_hash(entry)?;
    }
    let head_hash = decode_hash(&head.head_hash, "head_hash")?;
    if head_hash != prev {
        return Err(err("Kopf-Hash passt nicht zum letzten Eintrag"));
    }
    let signature_raw = BASE64
        .decode(&head.signature)
        .map_err(|_| err("Signatur ist kein Base64"))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_raw)
        .map_err(|_| err("Signatur hat kein Ed25519-Format"))?;
    verifying_key
        .verify(&head_bytes(head.count, &head_hash), &signature)
        .map_err(|_| err("Kopf-Signatur ist ungültig"))
}

/// Sucht ein Artefakt über seinen SHA-256 im Log. Linear, weil ein
/// Release-Log Hunderte Einträge hat, nicht Millionen; Inklusions-Beweise
/// ohne Voll-Kopie sind Sache der Betriebs-Stufe (Modul-Kommentar).
pub fn find_by_sha256<'a>(entries: &'a [LogEntry], sha256: &[u8; 32]) -> Option<&'a LogEntry> {
    let needle = BASE64.encode(sha256);
    entries.iter().find(|e| e.sha256 == needle)
}

/// Baut den Signierschlüssel aus einem 32-Byte-Seed (`BT_SIGNING_KEY`,
/// Base64), analog zu KT_SIGNING_KEY.
pub fn signing_key_from_seed(seed: &[u8]) -> Result<SigningKey, BtError> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| err("Signierschlüssel-Seed muss 32 Bytes haben"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Liest einen öffentlichen Schlüssel (32 Bytes) für die Prüfung.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, BtError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| err("öffentlicher Schlüssel muss 32 Bytes haben"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| err("kein gültiger Ed25519-Schlüssel"))
}

/// Serialisiert Einträge als JSON-Zeilen (eine pro Eintrag), das
/// Dateiformat von `log.jsonl`.
pub fn to_jsonl(entries: &[LogEntry]) -> Result<String, BtError> {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&serde_json::to_string(entry).map_err(|e| err(e.to_string()))?);
        out.push('\n');
    }
    Ok(out)
}

/// Liest Einträge aus JSON-Zeilen; leere Zeilen sind erlaubt (Datei-Ende).
pub fn from_jsonl(text: &str) -> Result<Vec<LogEntry>, BtError> {
    let mut entries = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogEntry = serde_json::from_str(line)
            .map_err(|e| err(format!("Zeile {} unlesbar: {e}", number + 1)))?;
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_log(n: usize, signer: &SigningKey) -> (Vec<LogEntry>, LogHead) {
        let mut entries = Vec::new();
        let mut head = None;
        for i in 0..n {
            let sha = Sha256::digest(format!("artefakt-{i}").as_bytes()).into();
            let (entry, new_head) = append(
                &entries,
                &format!("sm-{i}.exe"),
                "1.0.0",
                &sha,
                1_700_000_000 + i as u64,
                signer,
            )
            .unwrap();
            entries.push(entry);
            head = Some(new_head);
        }
        (entries, head.expect("mindestens ein Eintrag"))
    }

    #[test]
    fn append_verify_and_lookup_roundtrip() {
        let signer = key(1);
        let (entries, head) = sample_log(3, &signer);
        verify(&entries, &head, &signer.verifying_key()).unwrap();

        // Ein enthaltenes Artefakt wird gefunden, ein fremdes nicht.
        let sha: [u8; 32] = Sha256::digest(b"artefakt-1").into();
        assert_eq!(find_by_sha256(&entries, &sha).unwrap().index, 1);
        let foreign: [u8; 32] = Sha256::digest(b"nie veroeffentlicht").into();
        assert!(find_by_sha256(&entries, &foreign).is_none());

        // Der Datei-Roundtrip verliert nichts.
        let text = to_jsonl(&entries).unwrap();
        let reloaded = from_jsonl(&text).unwrap();
        assert_eq!(reloaded, entries);
        verify(&reloaded, &head, &signer.verifying_key()).unwrap();
    }

    #[test]
    fn any_tampering_breaks_verification() {
        let signer = key(1);
        let (entries, head) = sample_log(3, &signer);
        let public = signer.verifying_key();

        // Inhalt eines Eintrags aendern: die Kette bricht.
        let mut changed = entries.clone();
        changed[1].version = "1.0.1-boese".to_string();
        assert!(verify(&changed, &head, &public).is_err(), "Aenderung");

        // Eintrag entfernen: Anzahl im Kopf passt nicht mehr.
        let mut truncated = entries.clone();
        truncated.pop();
        assert!(verify(&truncated, &head, &public).is_err(), "Loeschung");

        // Einträge umordnen: Index- und Kettenpruefung schlagen an.
        let mut reordered = entries.clone();
        reordered.swap(0, 1);
        assert!(verify(&reordered, &head, &public).is_err(), "Umordnung");

        // Fremder Schluessel: die Kopf-Signatur ist ungueltig.
        let foreign = key(2).verifying_key();
        assert!(verify(&entries, &head, &foreign).is_err(), "fremder Kopf");

        // Unversehrt bleibt unversehrt.
        verify(&entries, &head, &public).unwrap();
    }

    /// Injektivität der kanonischen Bytes: die Feldgrenze zwischen
    /// Artefakt und Version darf sich nicht verschieben lassen. Genau
    /// diese Kollision war mit 0x00-Trennern konstruierbar (Review-Fund):
    /// {artifact: "sm.exe\x001.0", version: "x"} und {artifact: "sm.exe",
    /// version: "1.0\x00x"} fielen auf dieselben Bytes zusammen; mit
    /// Längen-Präfixen unterscheiden sie sich.
    #[test]
    fn canonical_bytes_bind_field_boundaries() {
        let base = LogEntry {
            index: 0,
            artifact: "sm.exe\u{0}1.0".to_string(),
            version: "x".to_string(),
            sha256: BASE64.encode([7u8; 32]),
            built_at: 1_700_000_000,
            prev_hash: BASE64.encode(ZERO_HASH),
        };
        let shifted = LogEntry {
            artifact: "sm.exe".to_string(),
            version: "1.0\u{0}x".to_string(),
            ..base.clone()
        };
        assert_ne!(
            entry_hash(&base).unwrap(),
            entry_hash(&shifted).unwrap(),
            "verschobene Feldgrenze muss einen anderen Hash ergeben"
        );
    }

    #[test]
    fn empty_log_verifies_against_zero_head() {
        // Ein leeres Log ist pruefbar, wenn der Kopf den Null-Hash traegt
        // und korrekt signiert ist (der Zustand vor dem ersten Release).
        let signer = key(3);
        let signature = signer.sign(&head_bytes(0, &ZERO_HASH));
        let head = LogHead {
            count: 0,
            head_hash: BASE64.encode(ZERO_HASH),
            signature: BASE64.encode(signature.to_bytes()),
        };
        verify(&[], &head, &signer.verifying_key()).unwrap();
    }
}
