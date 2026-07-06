//! Property-Tests der kanonischen KT-Bytes: das Konto-Commitment muss
//! unabhängig von der Antwort-Reihenfolge des Servers sein und auf jede
//! inhaltliche Änderung reagieren. Beides zusammen macht die
//! Selbstprüfung belastbar: gleiche Gerätemenge ergibt immer denselben
//! Hash, eine andere nie.

use kt_format::{account_commitment, CommitmentDevice};
use proptest::prelude::*;

/// Erzeugt eine kleine Gerätemenge mit eindeutigen IDs (die Fachlogik
/// garantiert Eindeutigkeit über die Datenbank; das Commitment setzt sie
/// voraus).
fn devices_strategy() -> impl Strategy<Value = Vec<(String, String, u64)>> {
    proptest::collection::btree_map("[a-f0-9]{8}", ("[A-Za-z0-9+/=]{16}", any::<u64>()), 1..6)
        .prop_map(|map| {
            map.into_iter()
                .map(|(id, (key, not_after))| (id, key, not_after))
                .collect()
        })
}

fn as_commitment_devices(raw: &[(String, String, u64)]) -> Vec<CommitmentDevice<'_>> {
    raw.iter()
        .map(|(id, key, not_after)| CommitmentDevice {
            id,
            public_key: key,
            not_after: *not_after,
        })
        .collect()
}

proptest! {
    /// Reihenfolge-Unabhängigkeit: identity liefert Geräte in
    /// Datenbank-Reihenfolge, der Client in seiner; beide müssen dasselbe
    /// Commitment rechnen.
    #[test]
    fn commitment_ignores_device_order(
        raw in devices_strategy(),
        seed in any::<u64>(),
        identity_key in "[A-Za-z0-9+/=]{16}",
    ) {
        let original = account_commitment(&identity_key, &as_commitment_devices(&raw));
        // Deterministische Permutation aus dem Seed (Fisher-Yates mit
        // einfachem LCG): proptest soll die Reihenfolge treiben, nicht
        // ein globaler Zufall, damit Gegenbeispiele reproduzierbar sind.
        let mut shuffled = raw.clone();
        let mut state = seed;
        for i in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state >> 33) as usize % (i + 1);
            shuffled.swap(i, j);
        }
        let permuted = account_commitment(&identity_key, &as_commitment_devices(&shuffled));
        prop_assert_eq!(original, permuted);
    }

    /// Empfindlichkeit: ändert sich irgendein Feld irgendeines Geräts,
    /// ändert sich das Commitment. Sonst könnte ein Server einen
    /// Schlüsseltausch verstecken, ohne dass die Selbstprüfung anschlägt.
    #[test]
    fn commitment_reacts_to_any_field_change(
        raw in devices_strategy(),
        which in any::<usize>(),
        field in 0usize..3,
        identity_key in "[A-Za-z0-9+/=]{16}",
    ) {
        let original = account_commitment(&identity_key, &as_commitment_devices(&raw));
        let mut changed = raw.clone();
        let at = which % changed.len();
        match field {
            0 => changed[at].0.push('x'),
            1 => changed[at].1.push('x'),
            _ => changed[at].2 = changed[at].2.wrapping_add(1),
        }
        let mutated = account_commitment(&identity_key, &as_commitment_devices(&changed));
        prop_assert_ne!(original, mutated);
    }
}
