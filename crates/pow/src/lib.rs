//! Proof-of-Work als Sybil-Bremse bei der Registrierung
//! (specs/sealed-sender-und-abuse.md).
//!
//! Ohne Telefonnummer fehlt die natürliche Bremse gegen Massenkonten. Ein
//! kleiner Rechenaufwand pro Registrierung bringt sie zurück: Der Client
//! sucht einen `nonce`, sodass `SHA-256(handle || 0x00 || nonce)` mit
//! mindestens `difficulty_bits` Nullbits beginnt. Der Server prüft das in
//! einem Hash. Weil der Aufwand am Handle hängt, lässt er sich nicht über
//! Konten hinweg wiederverwenden.
//!
//! Bewusst eine Bremse, kein Riegel (so nennt es die Spec): Proof-of-Work
//! trifft schwache Geräte härter als ein Botnetz, die Asymmetrie ist
//! begrenzt. Er wirkt nur zusammen mit Franking und den empfängerseitigen
//! Kontrollen. Kein Eigenbau: SHA-256 aus der geprüften sha2-Bibliothek,
//! hashcash-artig zusammengesetzt.
//!
//! [ANNAHME: Die Bindung ist Handle plus nonce, ohne server-gestellte
//! Frische; ein Angreifer kann für sein Wunsch-Handle vorab rechnen. Ein
//! server-gestelltes Challenge-Token (mit Ablauf) gegen Vorausrechnen ist
//! die nächste Stufe und braucht einen Challenge-Endpunkt.]

use sha2::{Digest, Sha256};

/// Zählt die führenden Nullbits eines Byte-Feldes.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in bytes {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Der Hash über Handle und nonce, dessen führende Nullbits die Schwierigkeit
/// bestimmen. Das Nulltrennzeichen verhindert, dass verschiedene
/// Handle/nonce-Paare denselben Vorraum bilden.
fn digest(handle: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(handle.as_bytes());
    hasher.update([0x00]);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Prüft, ob ein `nonce` die geforderte Schwierigkeit für das Handle
/// erfüllt. Der Server ruft genau das auf, ein Hash.
pub fn verify(handle: &str, nonce: u64, difficulty_bits: u32) -> bool {
    leading_zero_bits(&digest(handle, nonce)) >= difficulty_bits
}

/// Sucht einen `nonce`, der die Schwierigkeit erfüllt (Client-Seite). Zählt
/// linear hoch; der erwartete Aufwand verdoppelt sich je zusätzlichem Bit.
/// `None`, falls der u64-Raum ausgeht (bei sinnvollen Schwierigkeiten
/// unerreichbar).
pub fn solve(handle: &str, difficulty_bits: u32) -> Option<u64> {
    (0..=u64::MAX).find(|&nonce| leading_zero_bits(&digest(handle, nonce)) >= difficulty_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solved_nonce_verifies() {
        // Kleine Schwierigkeit, damit der Test schnell bleibt.
        let nonce = solve("alice", 12).expect("nonce gefunden");
        assert!(verify("alice", nonce, 12));
    }

    #[test]
    fn wrong_handle_or_low_effort_fails() {
        let nonce = solve("alice", 12).expect("nonce gefunden");
        // Derselbe nonce gilt nicht für ein anderes Handle (Bindung).
        assert!(!verify("bob", nonce, 12));
        // Und ein beliebiger nonce erfüllt hohe Schwierigkeit fast nie.
        assert!(!verify("alice", 0, 24));
    }

    #[test]
    fn zero_difficulty_accepts_anything() {
        // Ohne geforderte Bits ist jeder nonce gültig (Bremse aus).
        assert!(verify("alice", 12345, 0));
    }
}
