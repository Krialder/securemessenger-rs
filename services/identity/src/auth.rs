//! Passwort-Hashing und Session-Token.
//!
//! Kein Krypto-Eigenbau: das Hashing kommt aus der geprüften argon2-Bibliothek
//! (Argon2id mit den OWASP-orientierten Default-Parametern, NF040), der
//! Zufall aus dem CSPRNG des Betriebssystems.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};

/// Hasht ein Passwort mit Argon2id und zufälligem Salt. Der Rückgabewert ist
/// ein PHC-String, der Algorithmus, Parameter, Salt und Hash enthält.
/// Achtung: bewusst teuer (rund 100 ms), im Request-Pfad nur über
/// `spawn_blocking` aufrufen.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

/// Prüft ein Passwort gegen einen gespeicherten Argon2-PHC-String.
/// Gibt bei ungültigem Hash-Format `false` zurück, statt zu paniken.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Erzeugt ein opakes Token aus 32 Byte OS-Zufall (hex, 64 Zeichen),
/// verwendet für Access- wie Refresh-Token. Bewusst kein selbstgebautes
/// Token-Format mit eingebetteten Claims; der Zustand liegt im SessionStore.
pub fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// SHA-256-Hex eines Tokens für Ablage und Lookup. Anders als beim Passwort
/// genügt ein schneller Hash: das Token trägt 256 Bit Zufall, Brute-Force
/// über den Hash ist aussichtslos, Argon2 wäre hier nur Latenz ohne Gewinn.
/// Abgelegt wird ausschließlich der Hash, damit ein Auszug der Ablage keine
/// gültigen Tokens liefert.
pub fn token_hash(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
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
    fn hash_and_verify_roundtrip() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("falsches passwort", &phc));
    }

    #[test]
    fn verify_rejects_garbage_hash() {
        assert!(!verify_password("egal", "kein-gueltiger-phc-string"));
    }

    #[test]
    fn token_has_expected_length_and_varies() {
        let a = new_session_token();
        let b = new_session_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn token_hash_is_deterministic_and_distinct() {
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_ne!(token_hash("abc"), token_hash("abd"));
        assert_eq!(token_hash("abc").len(), 64);
    }
}
