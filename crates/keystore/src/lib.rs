//! Verschlüsselte Geräte-Ablage: der Passphrase-Tresor um den
//! Ablage-Blob der Clients.
//!
//! Das Problem: Identität, Sitzungen, Kontakte und Verläufe liegen bisher
//! als Klartext-JSON auf der Platte (CLI) beziehungsweise in IndexedDB
//! (Web). Wer die Datei hat, hat das Konto. Der Tresor schiebt eine
//! Passphrase davor: Der gesamte Blob wird unter einem aus der Passphrase
//! abgeleiteten Schlüssel authentifiziert verschlüsselt. Weil der ganze
//! Blob gesealt wird und nicht Wert für Wert, sind auch die Schlüsselnamen
//! (`contact/bob`, `history/alice`) geschützt, nicht nur die Werte.
//!
//! Kein Eigenbau: Die Schlüsselableitung ist Argon2id (RFC 9106, der
//! Standard gegen Brute-Force auf gestohlene Ablagen), die Verschlüsselung
//! ist ChaCha20-Poly1305 (authentifiziert: jede Manipulation und jede
//! falsche Passphrase fällt bei der Entschlüsselung auf). Dieses Crate
//! komponiert die beiden geprüften Primitive zu einem versionierten
//! Envelope, mehr nicht.
//!
//! Argon2id läuft genau einmal beim Entsperren (`create`/`unlock`); danach
//! hält der [`Sealer`] den abgeleiteten Schlüssel und dasselbe Salt, sodass
//! jedes weitere `seal` nur die billige AEAD-Operation ist. Das ist
//! wichtig, weil eine Ablage bei jeder Änderung neu geschrieben wird und
//! ein Argon2-Lauf pro Nachricht die Clients unbenutzbar langsam machte.
//!
//! Envelope-Format (`smks.v1`): Domain-Präfix, Salt, Nonce, Chiffretext.
//! Das Präfix geht als Associated Data in die AEAD ein, damit ein Vertauschen
//! der Version auffällt; Salt und Nonce liegen im Klartext davor, denn sie
//! sind kein Geheimnis, nur je Ablage beziehungsweise je Schreibvorgang
//! einmalig.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore as _;
use zeroize::Zeroize;

/// Domain-Präfix und Version des Envelopes; zugleich Associated Data der
/// AEAD.
const MAGIC: &[u8] = b"smks.v1";
/// Salt-Länge der Schlüsselableitung (128 Bit).
pub const SALT_LEN: usize = 16;
/// Nonce-Länge von ChaCha20-Poly1305 (96 Bit).
pub const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Fehler des Tresors, bewusst grobkörnig: Der Aufrufer soll nicht
/// unterscheiden können, ob die Passphrase falsch war oder der Chiffretext
/// manipuliert, denn beides ist derselbe Fall "öffnet nicht".
#[derive(Debug, PartialEq, Eq)]
pub enum KeystoreError {
    /// Das Envelope ist zu kurz, hat das falsche Präfix oder eine unbekannte
    /// Version.
    Malformed,
    /// Entschlüsselung fehlgeschlagen: falsche Passphrase oder manipuliert.
    WrongPassphraseOrTampered,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::Malformed => write!(f, "kein gültiges Keystore-Envelope"),
            KeystoreError::WrongPassphraseOrTampered => {
                write!(f, "falsche Passphrase oder manipulierte Ablage")
            }
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Feste Argon2id-Parameter, damit ein einmal versiegelter Blob (vor allem
/// eine tragbare, langlebige Sicherungsdatei) auch nach einem Update der
/// argon2-Bibliothek noch mit demselben Schlüssel öffnet: das Envelope trägt
/// die Parameter NICHT mit, die Ableitung muss also reproduzierbar sein. Die
/// Bibliotheks-Defaults haben sich schon einmal geändert (m_cost 4096 -> 19456
/// zwischen 0.4 und 0.5); diese Werte pinnen den 0.5-Default (RFC-9106-nah:
/// 19 MiB Speicher, 2 Durchläufe, 1 Spur), sodass bestehende Envelopes weiter
/// öffnen und ein späteres Update nichts unlesbar macht.
const ARGON2_M_COST: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Leitet den 32-Byte-Schlüssel deterministisch aus Passphrase und Salt ab.
/// Argon2id mit fest gepinnten Parametern (siehe oben); die Ableitung ist
/// absichtlich teuer, deshalb ruft der [`Sealer`] sie nur einmal.
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("gepinnte Argon2-Parameter sind gültig");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // hash_password_into mit rohem Salt scheitert nur bei absurden
    // Parametern (Salt zu kurz/lang); SALT_LEN liegt im gültigen Bereich,
    // der expect ist damit unerreichbar.
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("Argon2id mit gültigem Salt und 32-Byte-Ausgabe");
    key
}

/// Hält den entsperrten Schlüssel und das Salt der Ablage. Schreibt mit
/// `seal` beliebig oft, ohne Argon2 erneut zu zahlen. Der Schlüssel wird
/// beim Fallenlassen aus dem Speicher gewischt.
pub struct Sealer {
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Sealer {
    /// Ein frischer Tresor für eine neue Ablage: erzeugt ein zufälliges Salt
    /// und leitet den Schlüssel ab. Das erste `seal` schreibt das Salt ins
    /// Envelope.
    pub fn create(passphrase: &str) -> Sealer {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        Sealer {
            key: derive_key(passphrase, &salt),
            salt,
        }
    }

    /// Öffnet ein vorhandenes Envelope: prüft Format und Version, leitet den
    /// Schlüssel aus Passphrase und dem gespeicherten Salt ab und
    /// entschlüsselt. Liefert den Klartext plus einen Sealer, der mit
    /// demselben Salt/Schlüssel weiterschreibt.
    pub fn unlock(passphrase: &str, envelope: &[u8]) -> Result<(Sealer, Vec<u8>), KeystoreError> {
        let parts = split_envelope(envelope)?;
        let key = derive_key(passphrase, &parts.salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&parts.nonce),
                Payload {
                    msg: parts.ciphertext,
                    aad: MAGIC,
                },
            )
            .map_err(|_| KeystoreError::WrongPassphraseOrTampered)?;
        Ok((
            Sealer {
                key,
                salt: parts.salt,
            },
            plaintext,
        ))
    }

    /// Verschlüsselt einen Klartext-Blob zu einem Envelope. Frischer Nonce
    /// je Aufruf (Pflicht bei AEAD), gespeichertes Salt.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        // encrypt scheitert nur bei Nachrichten jenseits der ChaCha-Grenze
        // (2^38 Byte); ein Ablage-Blob liegt bei wenigen KiB.
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: MAGIC,
                },
            )
            .expect("ChaCha20-Poly1305 verschlüsselt einen kleinen Blob");
        let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }
}

/// Die zerlegten Bestandteile eines Envelopes.
struct EnvelopeParts<'a> {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

/// Zerlegt ein Envelope in Salt, Nonce und Chiffretext, nachdem Präfix und
/// Mindestlänge geprüft sind.
fn split_envelope(envelope: &[u8]) -> Result<EnvelopeParts<'_>, KeystoreError> {
    let header = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if envelope.len() < header || !envelope.starts_with(MAGIC) {
        return Err(KeystoreError::Malformed);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    salt.copy_from_slice(&envelope[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    nonce.copy_from_slice(&envelope[MAGIC.len() + SALT_LEN..header]);
    Ok(EnvelopeParts {
        salt,
        nonce,
        ciphertext: &envelope[header..],
    })
}

/// Ob ein Byte-Blob ein Keystore-Envelope ist (Präfix-Prüfung). Für die
/// Migration: eine alte Klartext-Ablage trägt das Präfix nicht, und der
/// Client kann sie einmal lesen und beim nächsten Schreiben sealen.
pub fn is_sealed(blob: &[u8]) -> bool {
    blob.starts_with(MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unlock_roundtrip() {
        let sealer = Sealer::create("korrektes-pferd-batterie");
        let secret = b"identitaet, sitzungen, kontakte";
        let envelope = sealer.seal(secret);

        assert!(is_sealed(&envelope));
        let (_reopened, plaintext) = Sealer::unlock("korrektes-pferd-batterie", &envelope).unwrap();
        assert_eq!(plaintext, secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = Sealer::create("richtige-passphrase").seal(b"geheim");
        assert!(matches!(
            Sealer::unlock("falsche-passphrase", &envelope),
            Err(KeystoreError::WrongPassphraseOrTampered)
        ));
    }

    #[test]
    fn any_tampering_fails() {
        let envelope = Sealer::create("pw").seal(b"eine laengere geheime nachricht");
        // Jedes einzelne gekippte Byte im Chiffretext-Teil bricht die
        // Poly1305-Pruefung; auch Salt und Nonce sind Teil des Envelopes.
        for i in 0..envelope.len() {
            let mut bad = envelope.clone();
            bad[i] ^= 0x01;
            // Ein gekipptes Präfix-Byte ist Malformed, alles andere ist
            // WrongPassphraseOrTampered; beide sind Fehler, nie Ok.
            assert!(
                Sealer::unlock("pw", &bad).is_err(),
                "Byte {i} muss auffallen"
            );
        }
    }

    #[test]
    fn continued_sealer_reuses_salt_but_fresh_nonce() {
        // Nach unlock schreibt der Sealer mit demselben Salt weiter (kein
        // erneutes Argon2), aber jeder Nonce ist frisch: zwei Envelopes
        // desselben Klartexts unterscheiden sich.
        let first = Sealer::create("pw").seal(b"gleich");
        let (sealer, _) = Sealer::unlock("pw", &first).unwrap();
        let a = sealer.seal(b"gleich");
        let b = sealer.seal(b"gleich");
        assert_ne!(a, b, "frischer Nonce je seal");
        // Beide öffnen weiterhin mit der Passphrase.
        assert_eq!(Sealer::unlock("pw", &a).unwrap().1, b"gleich");
        assert_eq!(Sealer::unlock("pw", &b).unwrap().1, b"gleich");
    }

    #[test]
    fn malformed_envelopes_are_rejected_not_panicking() {
        assert!(matches!(
            Sealer::unlock("pw", b""),
            Err(KeystoreError::Malformed)
        ));
        assert!(matches!(
            Sealer::unlock("pw", b"smks.v1"),
            Err(KeystoreError::Malformed)
        ));
        assert!(matches!(
            Sealer::unlock(
                "pw",
                b"anderes-praefix-mit-genug-laenge-fuer-den-header-abc"
            ),
            Err(KeystoreError::Malformed)
        ));
        assert!(!is_sealed(b"{\"profile/v1\":\"...\"}"));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let envelope = Sealer::create("pw").seal(b"");
        assert_eq!(Sealer::unlock("pw", &envelope).unwrap().1, b"");
    }
}
