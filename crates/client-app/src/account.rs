//! Konto- und Geräteschlüssel plus Geräte-Credential (Client-Seite).
//!
//! Der Konto-Identitätsschlüssel (Ed25519) ist die Wurzel der
//! Geräte-Identitätsbindung (dokumentation/specs/geraete-identitaet.md). Er
//! signiert für jedes Gerät ein Credential im Format `smdc.v1`, das den
//! öffentlichen Geräteschlüssel, die Geräte-ID und die Gültigkeit an das Konto
//! bindet. Der private Wurzelschlüssel verlässt das Gerät nie; der Server
//! verifiziert nur (services/identity/src/credential.rs).
//!
//! Das ist Identitätsbindung, keine Nachrichten-Kryptografie, und gehört
//! deshalb in die Protokoll-Orchestrierung, nicht in den Krypto-Kern. Die
//! Signatur kommt unverändert aus ed25519-dalek; hier wird nichts selbst
//! konstruiert.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore as _;

/// Ein Ed25519-Schlüsselpaar, dessen privater Teil das Gerät nie verlässt.
/// Newtype über `SigningKey`, damit Kodierung und Signatur an einer Stelle
/// liegen und der private Schlüssel nicht versehentlich herausgereicht wird.
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    /// Erzeugt ein frisches Schlüsselpaar aus dem System-CSPRNG (nativ das
    /// OS, im Browser WebCrypto, siehe .cargo/config.toml). `from_bytes` ist
    /// für Ed25519 total, ein beliebiger 32-Byte-Seed ist ein gültiger
    /// privater Schlüssel.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Rekonstruiert ein Schlüsselpaar aus seinen 32 Seed-Bytes (Ablage).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Die 32 Seed-Bytes des privaten Schlüssels, nur so weit exponiert, wie
    /// die persistente Ablage sie braucht. Wer das aufruft, hält Schlüssel in
    /// der Hand und muss sie schützen.
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Der öffentliche Schlüssel als Base64 (STANDARD), wie ihn identity und
    /// directory als `identity_key` bzw. `public_key` erwarten.
    pub fn public_b64(&self) -> String {
        BASE64.encode(self.signing.verifying_key().to_bytes())
    }

    /// Signiert eine Nachricht mit rohem Ed25519, Ergebnis Base64.
    fn sign_b64(&self, message: &[u8]) -> String {
        BASE64.encode(self.signing.sign(message).to_bytes())
    }
}

/// Die zu signierende Credential-Nachricht. Muss Byte für Byte zur
/// Server-Seite passen (services/identity/src/credential.rs
/// `credential_message`), sonst scheitert `verify_strict` dort. Newline-
/// getrennt und versioniert; die API-Validierungen stellen sicher, dass kein
/// Feld selbst ein Newline enthält.
pub fn credential_message(
    handle: &str,
    device_id: &str,
    device_public_key_b64: &str,
    not_after: u64,
) -> String {
    format!("smdc.v1\n{handle}\n{device_id}\n{device_public_key_b64}\n{not_after}")
}

/// Baut ein signiertes Geräte-Credential: der Konto-Wurzelschlüssel signiert
/// die Bindung des Geräteschlüssels an Handle, Geräte-ID und Ablaufzeitpunkt.
pub fn build_device_credential(
    account: &IdentityKeypair,
    handle: &str,
    device_id: &str,
    device_public_key_b64: &str,
    not_after: u64,
) -> String {
    let message = credential_message(handle, device_id, device_public_key_b64, not_after);
    account.sign_b64(message.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    /// Spiegelbild der Server-Prüfung (credential.rs `verify_device_credential`),
    /// auf den Signaturkern reduziert: was der Client signiert, muss der
    /// Konto-Identitätsschlüssel per `verify_strict` bestätigen.
    #[test]
    fn credential_verifies_against_account_key() {
        let account = IdentityKeypair::generate();
        let device = IdentityKeypair::generate();
        let device_pub = device.public_b64();
        let not_after = 2_000_000_000;

        let credential =
            build_device_credential(&account, "alice", "dev-1", &device_pub, not_after);

        let account_pub_bytes: [u8; 32] = BASE64
            .decode(account.public_b64())
            .unwrap()
            .try_into()
            .unwrap();
        let verifying = VerifyingKey::from_bytes(&account_pub_bytes).unwrap();
        let sig_bytes: [u8; 64] = BASE64.decode(&credential).unwrap().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        let message = credential_message("alice", "dev-1", &device_pub, not_after);

        assert!(verifying
            .verify_strict(message.as_bytes(), &signature)
            .is_ok());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let account = IdentityKeypair::generate();
        let device = IdentityKeypair::generate();
        let device_pub = device.public_b64();
        let credential =
            build_device_credential(&account, "alice", "dev-1", &device_pub, 2_000_000_000);

        let account_pub_bytes: [u8; 32] = BASE64
            .decode(account.public_b64())
            .unwrap()
            .try_into()
            .unwrap();
        let verifying = VerifyingKey::from_bytes(&account_pub_bytes).unwrap();
        let sig_bytes: [u8; 64] = BASE64.decode(&credential).unwrap().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        // Signiert wurde dev-1; ein anderes Feld muss die Prüfung scheitern lassen.
        let message = credential_message("alice", "dev-2", &device_pub, 2_000_000_000);

        assert!(verifying
            .verify_strict(message.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn seed_roundtrip_preserves_key() {
        let original = IdentityKeypair::generate();
        let restored = IdentityKeypair::from_seed(&original.to_seed());
        assert_eq!(original.public_b64(), restored.public_b64());
    }
}
