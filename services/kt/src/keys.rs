//! Schlüssel des KT-Dienstes: Wurzel-Signaturen und VRF.
//!
//! Die per Spec geforderte Ausnahme von der "Backend verifiziert
//! nur"-Regel: dieser Dienst hält den Ed25519-Signaturschlüssel der
//! Wurzeln (Clients und Auditoren prüfen damit den append-only Log) und
//! den privaten VRF-Schlüssel (verschleiert die Handle-Labels gegen
//! Durchzählen, specs/key-transparency.md "VRF gegen das Durchzählen").
//! Beide Schlüssel kommen aus Secrets; ohne Konfiguration erzeugt der
//! Dienst flüchtige Schlüssel und warnt - Wurzeln wären dann nach einem
//! Neustart nicht mehr verifizierbar, gut genug nur für lokale
//! Entwicklung.

use akd::ecvrf::VRFKeyStorage;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

/// Signiert die Wurzeln des append-only Logs. Das Format ist bewusst
/// simpel und kanonisch: Domain-Präfix, Epoche big-endian, Wurzel-Hash.
pub struct RootSigner {
    key: SigningKey,
}

/// Kanonische Bytes, die signiert werden: Format `smkt.v1` aus dem
/// geteilten kt-format-Crate, damit Clients exakt dieselben Bytes prüfen.
pub use kt_format::root_message;

impl RootSigner {
    /// Aus einem Base64-kodierten 32-Byte-Seed (Secret `KT_SIGNING_KEY`).
    pub fn from_seed_b64(seed_b64: &str) -> Result<Self, String> {
        let bytes = BASE64
            .decode(seed_b64)
            .map_err(|_| "KT_SIGNING_KEY ist kein gültiges Base64".to_string())?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "KT_SIGNING_KEY muss 32 Byte lang sein".to_string())?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Flüchtiger Schlüssel für lokale Entwicklung (Warnung im Log).
    pub fn ephemeral() -> Self {
        Self {
            key: SigningKey::from_bytes(&random_seed()),
        }
    }

    pub fn sign_root(&self, epoch: u64, root_hash: &[u8]) -> Vec<u8> {
        self.key.sign(&root_message(epoch, root_hash)).to_vec()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Öffentlicher Schlüssel, Base64: das, was Clients pinnen.
    pub fn public_key_b64(&self) -> String {
        BASE64.encode(self.key.verifying_key().as_bytes())
    }
}

/// Flüchtige Schlüssel kommen aus dem OS-CSPRNG (rand::rngs::OsRng),
/// wie überall im Projekt: kein selbstgebauter Zufall.
fn random_seed() -> [u8; 32] {
    use rand::TryRngCore as _;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .expect("OS-Zufallsquelle verfügbar");
    seed
}

/// VRF-Schlüsselablage für akd: liefert den privaten VRF-Schlüssel aus
/// dem Secret `KT_VRF_KEY` (Base64, 32 Byte Ed25519-Seed, siehe
/// akd-Doku) bzw. einen flüchtigen Dev-Schlüssel.
#[derive(Clone)]
pub struct SecretVrf {
    key_bytes: Vec<u8>,
}

impl SecretVrf {
    pub fn from_seed_b64(seed_b64: &str) -> Result<Self, String> {
        let bytes = BASE64
            .decode(seed_b64)
            .map_err(|_| "KT_VRF_KEY ist kein gültiges Base64".to_string())?;
        if bytes.len() != 32 {
            return Err("KT_VRF_KEY muss 32 Byte lang sein".to_string());
        }
        Ok(Self { key_bytes: bytes })
    }

    pub fn ephemeral() -> Self {
        Self {
            key_bytes: random_seed().to_vec(),
        }
    }
}

#[async_trait::async_trait]
impl VRFKeyStorage for SecretVrf {
    async fn retrieve(&self) -> Result<Vec<u8>, akd::ecvrf::VrfError> {
        Ok(self.key_bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn signature_roundtrip_and_key_pinning() {
        let signer = RootSigner::from_seed_b64(&BASE64.encode([7u8; 32])).unwrap();
        let root = [42u8; 32];
        let signature = signer.sign_root(3, &root);

        let verifying = signer.verifying_key();
        let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(verifying.verify(&root_message(3, &root), &sig).is_ok());
        // Andere Epoche, gleiche Wurzel: Signatur passt nicht mehr.
        assert!(verifying.verify(&root_message(4, &root), &sig).is_err());
        // Derselbe Seed ergibt denselben öffentlichen Schlüssel (Pinning).
        let again = RootSigner::from_seed_b64(&BASE64.encode([7u8; 32])).unwrap();
        assert_eq!(signer.public_key_b64(), again.public_key_b64());
    }

    #[test]
    fn rejects_bad_seeds() {
        assert!(RootSigner::from_seed_b64("kein base64!").is_err());
        assert!(RootSigner::from_seed_b64(&BASE64.encode([1u8; 16])).is_err());
        assert!(SecretVrf::from_seed_b64(&BASE64.encode([1u8; 16])).is_err());
    }
}
