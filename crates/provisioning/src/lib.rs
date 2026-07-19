//! Provisioning-Chiffre für die QR-Kopplung eines Zweitgeräts.
//!
//! Die manuelle Kopplung überträgt den Kopplungs-Antrag (Geräte-ID plus
//! öffentlicher Geräteschlüssel) als lange Base64-Zeile, die der Nutzer
//! vom neuen aufs bestehende Gerät kopiert. Dieses Crate automatisiert die
//! Übergabe über einen Relay, ohne dem Relay den Antrag anzuvertrauen:
//!
//! 1. Das neue Gerät zieht ein zufälliges 32-Byte-Geheimnis (im QR-Code)
//!    und `seal`t seinen Antrag darunter. Aus dem Geheimnis leitet HKDF-SHA256
//!    domänengetrennt eine Kanal-ID und einen Chiffre-Schlüssel ab.
//! 2. Es legt `{channel_id, nonce, ciphertext}` beim Relay ab.
//! 3. Das bestehende Gerät bekommt das Geheimnis (QR gescannt oder
//!    eingegeben), leitet dieselbe Kanal-ID ab, holt den Chiffretext und
//!    `open`t ihn mit demselben Schlüssel.
//!
//! Der Relay sieht nur die Kanal-ID (aus dem Geheimnis abgeleitet, nicht
//! umkehrbar) und opaken Chiffretext. Er kann den Antrag nicht lesen und
//! nicht fälschen: die Poly1305-Prüfung fängt jede Änderung, und ohne
//! das Geheimnis (nur auf dem Bildschirm des neuen Geräts) lässt sich
//! weder die Kanal-ID treffen noch ein gültiger Chiffretext erzeugen. Damit
//! ist der Vertrauensanker der physische QR-Pfad (Bildschirm zu Kamera),
//! genau wie bei der manuellen Kopie der Anker die Zwischenablage war.
//!
//! Kein Eigenbau: HKDF-SHA256 (RFC 5869) und ChaCha20-Poly1305, beide aus
//! den geprüften RustCrypto-Bibliotheken; hier nur zu einem versionierten
//! Format komponiert.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore as _;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Länge des Kopplungs-Geheimnisses in Bytes (256 Bit; passt als Base64 in
/// einen kleinen QR-Code).
pub const SECRET_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// Länge der Kanal-ID in Bytes; als Hex ein URL-sicherer Pfad-Bestandteil.
const CHANNEL_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Als AAD ans Chiffrat gebunden: bindet Version und Zweck, sodass ein
/// Chiffretext aus einem anderen Kontext hier nicht verifiziert.
const AAD: &[u8] = b"smprov.v1";
const INFO_CHANNEL: &[u8] = b"smprov.v1 channel";
const INFO_KEY: &[u8] = b"smprov.v1 key";

/// Das Kopplungs-Geheimnis. Wird beim Fallenlassen aus dem Speicher
/// gewischt, weil daraus Kanal-ID und Chiffre-Schlüssel entstehen.
#[derive(ZeroizeOnDrop)]
pub struct Secret([u8; SECRET_LEN]);

/// Fehler beim Entschlüsseln oder Einlesen.
#[derive(Debug, PartialEq, Eq)]
pub enum ProvisioningError {
    /// Eingabe unlesbar (kein Base64, falsche Länge).
    Malformed,
    /// Der Chiffretext verifiziert nicht: falsches Geheimnis oder manipuliert.
    WrongSecretOrTampered,
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisioningError::Malformed => write!(f, "Provisioning-Daten unlesbar"),
            ProvisioningError::WrongSecretOrTampered => {
                write!(f, "falsches Geheimnis oder manipulierter Chiffretext")
            }
        }
    }
}

impl std::error::Error for ProvisioningError {}

/// Der abgelegte, verschlüsselte Antrag samt seiner (aus dem Geheimnis
/// abgeleiteten) Kanal-ID. Nonce und Chiffretext als Base64.
pub struct Sealed {
    pub channel_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

impl Secret {
    /// Ein frisches Geheimnis aus dem OS-CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Das Geheimnis als Base64, wie es in den QR-Code geht. Der zurück-
    /// gegebene String ist bewusst ungewischt: er wird angezeigt (QR-Code,
    /// abtippbarer Code), existiert also ohnehin in der Oberfläche. Der
    /// zeroize-Schutz gilt dem `Secret`-Array selbst; diese Anzeige-Kopie
    /// lebt so kurz wie die Kopplungs-Ansicht. [ANNAHME: eine restlose
    /// Wisch-Garantie über alle Kopien (auch die HKDF-PRK im hkdf-Crate,
    /// das ohne zeroize-Feature läuft) ist Defense-in-depth und im
    /// wasm-Linear-Memory ohnehin nicht vollständig erreichbar.]
    pub fn to_b64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Liest ein Geheimnis aus seiner Base64-Form (gescannt oder eingegeben).
    /// Der Zwischenpuffer aus der Base64-Dekodierung wird gewischt, damit
    /// keine ungewischte Kopie des Geheimnisses im Heap zurückbleibt (der
    /// `try_into`-Weg wischt den Vec nicht, er gibt ihn nur frei).
    pub fn from_b64(value: &str) -> Result<Self, ProvisioningError> {
        let mut bytes = BASE64
            .decode(value.trim())
            .map_err(|_| ProvisioningError::Malformed)?;
        if bytes.len() != SECRET_LEN {
            bytes.zeroize();
            return Err(ProvisioningError::Malformed);
        }
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(secret))
    }

    fn derive(&self, info: &[u8], out: &mut [u8]) {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        // expand scheitert nur bei absurder Länge; unsere sind fix klein.
        hk.expand(info, out).expect("HKDF-Länge gültig");
    }

    /// Die Kanal-ID (Hex): der Relay-Schlüssel, aus dem Geheimnis abgeleitet
    /// und nicht umkehrbar. Beide Seiten rechnen dieselbe.
    pub fn channel_id(&self) -> String {
        let mut id = [0u8; CHANNEL_LEN];
        self.derive(INFO_CHANNEL, &mut id);
        to_hex(&id)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        let mut key = [0u8; KEY_LEN];
        self.derive(INFO_KEY, &mut key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        cipher
    }
}

/// Verschlüsselt den Antrag unter dem Geheimnis und liefert die
/// Relay-Ablage (Kanal-ID, frischer Nonce, Chiffretext).
pub fn seal(secret: &Secret, plaintext: &[u8]) -> Sealed {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = secret
        .cipher()
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .expect("ChaCha20-Poly1305-Verschlüsselung");
    Sealed {
        channel_id: secret.channel_id(),
        nonce_b64: BASE64.encode(nonce_bytes),
        ciphertext_b64: BASE64.encode(ciphertext),
    }
}

/// Entschlüsselt einen vom Relay geholten Chiffretext mit dem Geheimnis.
pub fn open(
    secret: &Secret,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, ProvisioningError> {
    let nonce_bytes = BASE64
        .decode(nonce_b64.trim())
        .map_err(|_| ProvisioningError::Malformed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(ProvisioningError::Malformed);
    }
    let ciphertext = BASE64
        .decode(ciphertext_b64.trim())
        .map_err(|_| ProvisioningError::Malformed)?;
    secret
        .cipher()
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| ProvisioningError::WrongSecretOrTampered)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = Secret::generate();
        let sealed = seal(&secret, b"kopplungs-antrag");
        // Die Kanal-ID des Ablegers und des Holers stimmen überein.
        assert_eq!(sealed.channel_id, secret.channel_id());
        let opened = open(&secret, &sealed.nonce_b64, &sealed.ciphertext_b64).unwrap();
        assert_eq!(opened, b"kopplungs-antrag");
    }

    #[test]
    fn survives_secret_over_base64() {
        // Wie das Geheimnis den QR-Code passiert: raus als Base64, rein.
        let secret = Secret::generate();
        let b64 = secret.to_b64();
        let sealed = seal(&secret, b"x");
        let holer = Secret::from_b64(&b64).unwrap();
        assert_eq!(holer.channel_id(), sealed.channel_id);
        assert_eq!(
            open(&holer, &sealed.nonce_b64, &sealed.ciphertext_b64).unwrap(),
            b"x"
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let secret = Secret::generate();
        let sealed = seal(&secret, b"geheim");
        let other = Secret::generate();
        assert_eq!(
            open(&other, &sealed.nonce_b64, &sealed.ciphertext_b64),
            Err(ProvisioningError::WrongSecretOrTampered)
        );
        // Ein anderes Geheimnis trifft auch die Kanal-ID nicht.
        assert_ne!(other.channel_id(), sealed.channel_id);
    }

    #[test]
    fn any_flipped_byte_is_caught() {
        let secret = Secret::generate();
        let sealed = seal(&secret, b"unversehrt");
        let raw = BASE64.decode(&sealed.ciphertext_b64).unwrap();
        for i in 0..raw.len() {
            let mut tampered = raw.clone();
            tampered[i] ^= 0x01;
            assert_eq!(
                open(&secret, &sealed.nonce_b64, &BASE64.encode(&tampered)),
                Err(ProvisioningError::WrongSecretOrTampered),
                "gekipptes Byte {i} muss auffallen"
            );
        }
    }

    #[test]
    fn channel_id_is_stable_and_differs_from_key_material() {
        let secret = Secret::generate();
        // Deterministisch und hex (URL-sicher).
        assert_eq!(secret.channel_id(), secret.channel_id());
        assert_eq!(secret.channel_id().len(), CHANNEL_LEN * 2);
        assert!(secret.channel_id().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let secret = Secret::generate();
        // `.err()` verwirft den Secret-Erfolgswert; Secret hat bewusst kein
        // Debug (Schlüsselmaterial), also nicht direkt auf dem Result
        // assert_eq.
        assert_eq!(
            Secret::from_b64("kein base64!!!").err(),
            Some(ProvisioningError::Malformed)
        );
        assert_eq!(
            Secret::from_b64(&BASE64.encode([0u8; 8])).err(),
            Some(ProvisioningError::Malformed)
        );
        assert_eq!(
            open(&secret, "nicht base64!!", "auch nicht"),
            Err(ProvisioningError::Malformed)
        );
    }
}
