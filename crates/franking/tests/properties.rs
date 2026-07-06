//! Property-Tests des Franking-Commitments: die Invarianten gelten für
//! beliebige Nachrichten und Schlüssel, nicht nur für die handverlesenen
//! Beispiele der Unit-Tests. proptest erzeugt die Eingaben und verkleinert
//! Gegenbeispiele automatisch.

use proptest::prelude::*;

proptest! {
    /// Rundlauf: was mit einem Schlüssel committet wurde, verifiziert mit
    /// genau diesem Schlüssel und genau dieser Nachricht.
    #[test]
    fn commit_verifies_for_any_message(message in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let key = franking::new_key();
        let commitment = franking::commit(&key, &message);
        prop_assert!(franking::verify(&key, &message, &commitment));
    }

    /// Bindung: jede Änderung an der Nachricht lässt die Verifikation
    /// scheitern. Genau diese Eigenschaft macht eine Meldung beweisbar;
    /// ein Empfänger kann keine andere Nachricht unterschieben.
    #[test]
    fn any_message_change_breaks_verification(
        message in proptest::collection::vec(any::<u8>(), 1..1024),
        flip_at in any::<usize>(),
    ) {
        let key = franking::new_key();
        let commitment = franking::commit(&key, &message);
        let mut changed = message.clone();
        let at = flip_at % changed.len();
        changed[at] ^= 0x01;
        prop_assert!(!franking::verify(&key, &changed, &commitment));
    }

    /// Bindung an den Schlüssel: ein fremder Schlüssel verifiziert nicht.
    /// Ohne diese Eigenschaft könnte der Server mit einem eigenen
    /// Schlüssel ein "Commitment" für erfundenen Inhalt bestätigen.
    #[test]
    fn foreign_key_breaks_verification(message in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let key = franking::new_key();
        let foreign = franking::new_key();
        prop_assume!(key != foreign);
        let commitment = franking::commit(&key, &message);
        prop_assert!(!franking::verify(&foreign, &message, &commitment));
    }

    /// Manipulierte Commitments (beliebige Bytes, auch falsche Länge)
    /// verifizieren nie und lösen vor allem keine Panik aus.
    #[test]
    fn arbitrary_commitment_bytes_never_verify_or_panic(
        message in proptest::collection::vec(any::<u8>(), 0..256),
        bogus in proptest::collection::vec(any::<u8>(), 0..96),
    ) {
        let key = franking::new_key();
        let real = franking::commit(&key, &message);
        prop_assume!(bogus != real);
        prop_assert!(!franking::verify(&key, &message, &bogus));
    }
}
