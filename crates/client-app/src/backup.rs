//! Sicherungs-Datei (`smbak.v1`): ein tragbarer, passwort-geschützter Export
//! des gesamten Geräte-Zustands.
//!
//! Wer seinen Browser-Cache leert (oder ein Gerät verliert), verliert damit
//! den lokalen Schlüssel-Zustand: die Geräte-Identität, die Sitzungen, die
//! MLS-Gruppen und den Verlauf. Ohne Sicherung bliebe nur, das Gerät neu zu
//! koppeln oder das Konto neu anzulegen. Die Sicherungs-Datei legt den
//! Zustand tragbar und verschlüsselt ab, sodass er sich auf einem frischen
//! Client wiederherstellen lässt.
//!
//! Format: der Magic-Präfix `smbak.v1` kennzeichnet die Datei, dahinter ein
//! keystore-Envelope (`smks.v1`: Argon2id-Schlüsselableitung aus der
//! Sicherungs-Passphrase, ChaCha20-Poly1305). Der INHALT des Envelopes ist
//! client-spezifisch und für dieses Modul opak: der Web-Client legt seine
//! Zustands-Map ab, das CLI ein Bündel aus Profil und Zustand. Eine Sicherung
//! stellt denselben Client-Typ wieder her (Web -> Web), kein Format-Austausch
//! zwischen den Clients.
//!
//! Die Sicherungs-Passphrase ist unabhängig vom Konto-Passwort (die Datei
//! verlässt das Gerät, ihr Schutz soll nicht am Server-Login hängen). Sie
//! schützt die Datei im Ruhezustand; nach dem Import meldet sich der Nutzer
//! wie gewohnt mit dem Konto-Passwort an, das die lokale Ablage dann wieder
//! darunter versiegelt.

const BACKUP_MAGIC: &[u8] = b"smbak.v1";

/// Mindestlänge der Sicherungs-Passphrase (in Zeichen). Die Datei verlässt
/// das Gerät und schützt den Konto-Wurzelschlüssel; eine leere oder triviale
/// Passphrase wäre trotz Argon2 wertlos, weil das Salt im Klartext danebenn
/// liegt und ein Dateibesitzer den Schlüssel dann mit einer einzigen
/// Ableitung nachrechnet. Gleiche Untergrenze wie das Konto-Passwort. Der
/// Salt liegt zwar im Klartext neben dem Chiffretext, verhindert aber nur
/// Vorab-Tabellen; gegen eine kurze Passphrase hilft er nicht.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Versiegelt einen (client-spezifischen) Zustands-Blob unter einer
/// Sicherungs-Passphrase zu einer Sicherungs-Datei. Weist eine zu kurze
/// Passphrase ab (siehe [`MIN_PASSPHRASE_LEN`]).
pub fn seal(payload: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "Das Sicherungs-Passwort braucht mindestens {MIN_PASSPHRASE_LEN} Zeichen \
             (es schützt den Konto-Wurzelschlüssel)."
        ));
    }
    let sealer = keystore::Sealer::create(passphrase);
    let inner = sealer.seal(payload);
    let mut out = Vec::with_capacity(BACKUP_MAGIC.len() + inner.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Öffnet eine Sicherungs-Datei: prüft den Magic-Präfix, entschlüsselt den
/// keystore-Envelope mit der Passphrase und liefert den Zustands-Blob. Eine
/// falsche Passphrase, eine fremde/keine Sicherungs-Datei oder eine
/// Manipulation scheitern mit einer klaren Meldung.
pub fn open(backup: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let inner = backup
        .strip_prefix(BACKUP_MAGIC)
        .ok_or("Das ist keine SecureMessenger-Sicherungsdatei (smbak.v1).")?;
    let (_sealer, payload) = keystore::Sealer::unlock(passphrase, inner)
        .map_err(|_| "Falsches Sicherungs-Passwort oder beschädigte Datei.".to_string())?;
    Ok(payload)
}

/// Ob ein Byte-Blob eine Sicherungs-Datei ist (Präfix-Prüfung), etwa um beim
/// Import ein versehentlich gewähltes fremdes File früh abzuweisen.
pub fn is_backup(bytes: &[u8]) -> bool {
    bytes.starts_with(BACKUP_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_returns_the_payload() {
        let payload = b"{\"handle\":\"kai\",\"state\":\"...\"}";
        let file = seal(payload, "sicherungs-passwort").unwrap();
        assert!(is_backup(&file));
        assert_eq!(open(&file, "sicherungs-passwort").unwrap(), payload);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let file = seal(b"geheim", "richtiges-passwort").unwrap();
        assert!(open(&file, "falsches-passwort").is_err());
    }

    #[test]
    fn short_passphrase_is_refused() {
        assert!(seal(b"geheim", "kurz").is_err());
        // Genau an der Grenze (12 Zeichen) zulässig.
        assert!(seal(b"geheim", "abcdefghijkl").is_ok());
    }

    #[test]
    fn foreign_file_is_rejected() {
        // Ein roher keystore-Envelope ohne den smbak-Präfix ist keine
        // Sicherungsdatei.
        let bare = keystore::Sealer::create("pw").seal(b"x");
        assert!(!is_backup(&bare));
        assert!(open(&bare, "pw").is_err());
    }

    #[test]
    fn tamper_is_rejected() {
        let mut file = seal(b"geheim", "langes-passwort").unwrap();
        let last = file.len() - 1;
        file[last] ^= 0x01;
        assert!(open(&file, "langes-passwort").is_err());
    }
}
