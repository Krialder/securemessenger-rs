//! Message Franking: das Commitment fürs Abuse-Reporting
//! (specs/sealed-sender-und-abuse.md).
//!
//! Das Problem: Unter Sealed Sender kennt der Server den Absender nicht,
//! wie meldet ein Empfänger dann eine missbräuchliche Nachricht beweisbar,
//! ohne dass sich Meldungen fälschen lassen? Die Antwort ist ein
//! kryptografisches Commitment. Der Absender wählt beim Senden einen
//! zufälligen Franking-Schlüssel `K_f`, bildet `C = HMAC(K_f, Klartext)`
//! und hängt `C` an die Hülle. Der Server bewahrt `C` auf, ohne den Inhalt
//! oder `K_f` zu sehen. `K_f` reist Ende-zu-Ende zum Empfänger. Meldet der
//! Empfänger, deckt er `(Klartext, K_f)` auf; der Server rechnet
//! `HMAC(K_f, Klartext)` nach und prüft, ob es dem aufbewahrten `C`
//! gleicht. Nur eine wirklich so gesendete Nachricht öffnet das Commitment,
//! also lässt sich keine Meldung fälschen, und die E2E bleibt unberührt.
//!
//! Kein Eigenbau: Committing über HMAC-SHA256 ist die Standard-Konstruktion
//! für Message Franking (Grubbs, Lu, Ristenpart). Dieses Crate legt sie an
//! einer Stelle fest, damit Client (committen) und Server (verifizieren)
//! dieselbe Rechnung machen.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Länge des Franking-Schlüssels in Bytes (256 Bit, wie der HMAC-Ausgang).
pub const KEY_LEN: usize = 32;

/// Ein frischer, zufälliger Franking-Schlüssel aus dem OS-CSPRNG. Der
/// Absender erzeugt ihn je Nachricht; er reist Ende-zu-Ende zum Empfänger,
/// der ihn beim Melden aufdeckt.
pub fn new_key() -> [u8; KEY_LEN] {
    use rand::RngCore as _;
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Das Franking-Commitment `HMAC(K_f, Klartext)`. Der Absender bildet es
/// beim Senden und hängt es an die Hülle; der Server bewahrt es auf.
pub fn commit(franking_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(franking_key).expect("HMAC nimmt Schlüssel jeder Länge");
    mac.update(plaintext);
    mac.finalize().into_bytes().to_vec()
}

/// Prüft eine Meldung: öffnet der aufgedeckte Schlüssel samt Klartext das
/// aufbewahrte Commitment? Konstante Zeit beim Vergleich, damit die
/// Prüfung nichts über das Commitment durchsickern lässt.
pub fn verify(franking_key: &[u8], plaintext: &[u8], commitment: &[u8]) -> bool {
    let recomputed = commit(franking_key, plaintext);
    recomputed.ct_eq(commitment).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_opening_verifies() {
        let key = new_key();
        let message = b"treffen wir uns um drei";
        let commitment = commit(&key, message);
        assert!(
            verify(&key, message, &commitment),
            "der echte Absender-Schlüssel muss das Commitment öffnen"
        );
    }

    #[test]
    fn forged_report_is_rejected() {
        let key = new_key();
        let commitment = commit(&key, b"das original");

        // Fremder Schlüssel: die Meldung ist gefälscht.
        assert!(!verify(&new_key(), b"das original", &commitment));
        // Anderer Klartext unter demselben Schlüssel: ebenfalls gefälscht
        // (der Absender hat das nie so gesagt).
        assert!(!verify(&key, b"etwas untergeschobenes", &commitment));
    }

    #[test]
    fn keys_and_commitments_differ_per_message() {
        assert_ne!(new_key(), new_key(), "Schlüssel sind zufällig");
        let key = new_key();
        assert_ne!(
            commit(&key, b"a"),
            commit(&key, b"b"),
            "verschiedene Nachrichten ergeben verschiedene Commitments"
        );
    }
}
