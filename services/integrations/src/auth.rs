//! Secrets und Tokens der Mandanten.
//!
//! Kein Krypto-Eigenbau: Argon2id aus der geprüften Bibliothek für die
//! Client-Secrets (sie sind langlebig wie Passwörter, NF040), SHA-256
//! für die kurzlebigen Tokens (256 Bit Zufall, Brute-Force über den
//! Digest ist aussichtslos; Argon2 wäre hier nur Latenz). Gleiche
//! Begründung wie in services/identity/src/auth.rs.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};

/// Erzeugt ein Client-Secret aus 32 Byte OS-Zufall (hex). Es wird dem
/// Betreiber genau einmal bei der Anlage gezeigt und danach nur noch als
/// Argon2id-Hash gehalten.
pub fn new_client_secret() -> String {
    random_hex()
}

/// Hasht ein Client-Secret mit Argon2id (PHC-String). Bewusst teuer;
/// liegt nur im Token-Tausch, nicht im Pfad jeder API-Anfrage.
pub fn hash_secret(secret: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

/// Prüft ein Client-Secret gegen den gespeicherten PHC-String.
pub fn verify_secret(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Erzeugt ein opakes Mandanten-Token (hex, 64 Zeichen). Kein Format mit
/// eingebetteten Claims; der Zustand liegt im TenantStore.
pub fn new_tenant_token() -> String {
    random_hex()
}

/// SHA-256-Hex eines Tokens für Ablage und Lookup.
pub fn token_hash(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hash_roundtrip() {
        let secret = new_client_secret();
        let phc = hash_secret(&secret).unwrap();
        assert!(verify_secret(&secret, &phc));
        assert!(!verify_secret("falsches-secret", &phc));
    }

    #[test]
    fn verify_rejects_garbage_hash() {
        assert!(!verify_secret("egal", "kein-phc-string"));
    }

    #[test]
    fn tokens_vary_and_hash_deterministically() {
        let a = new_tenant_token();
        let b = new_tenant_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(token_hash(&a), token_hash(&a));
        assert_ne!(token_hash(&a), token_hash(&b));
    }
}
