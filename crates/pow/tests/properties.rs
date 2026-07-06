//! Property-Tests der Proof-of-Work-Bremse: Lösen und Prüfen müssen für
//! beliebige Handles zusammenpassen, sonst sperrt die Registrierung
//! regelkonforme Clients aus oder lässt Rechenverweigerer durch.

use proptest::prelude::*;

proptest! {
    /// Schwierigkeit 0 heißt Bremse aus: jeder nonce ist gültig.
    #[test]
    fn zero_difficulty_accepts_any_nonce(handle in ".{0,64}", nonce in any::<u64>()) {
        prop_assert!(pow::verify(&handle, nonce, 0));
    }

    /// Was `solve` findet, akzeptiert `verify`: die Client- und die
    /// Server-Seite rechnen dieselbe Bedingung. Kleine Schwierigkeiten,
    /// damit der Test schnell bleibt (2^8 Hashes im Erwartungswert).
    #[test]
    fn solved_nonce_always_verifies(handle in ".{0,64}", difficulty in 0u32..=8) {
        let nonce = pow::solve(&handle, difficulty).expect("Lösung existiert");
        prop_assert!(pow::verify(&handle, nonce, difficulty));
    }

    /// Monotonie: ein nonce, der n Nullbits erfüllt, erfüllt auch jede
    /// kleinere Forderung. Ohne sie könnte ein Server-Upgrade der
    /// Schwierigkeit alte, korrekt gerechnete nonces wertlos machen,
    /// obwohl sie mehr geleistet haben.
    #[test]
    fn verification_is_monotonic_in_difficulty(handle in ".{0,32}", difficulty in 1u32..=8) {
        let nonce = pow::solve(&handle, difficulty).expect("Lösung existiert");
        for lower in 0..=difficulty {
            prop_assert!(pow::verify(&handle, nonce, lower));
        }
    }
}
