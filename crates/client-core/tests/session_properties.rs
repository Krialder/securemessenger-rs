//! Property-Test der Krypto-Integration: beliebige Nachrichteninhalte
//! überleben eine PQXDH-Sitzung in beliebiger Zustell-Reihenfolge. Der
//! Ratchet puffert übersprungene Message-Keys; genau diese Eigenschaft
//! wird hier über zufällige Permutationen getrieben statt über das eine
//! handgebaute Beispiel des Roundtrip-Tests.
//!
//! Wenige proptest-Fälle (12), weil jeder Fall einen vollen
//! Sitzungsaufbau samt ML-KEM-Schlüsselerzeugung bezahlt; die Breite
//! kommt aus den zufälligen Inhalten und Reihenfolgen je Fall.

use client_core::onetoone::Device;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn out_of_order_delivery_decrypts_for_any_contents(
        messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..256), 1..5),
        seed in any::<u64>(),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("Tokio-Laufzeit");
        runtime.block_on(async {
            let mut alice = Device::new("alice", 1, 51).unwrap();
            let mut bob = Device::new("bob", 1, 52).unwrap();
            let bundle = bob.publish_prekey_bundle().await.unwrap();
            let bob_address = bob.address().clone();
            let alice_address = alice.address().clone();
            alice.establish_session(&bob_address, &bundle).await.unwrap();

            // Alle Nachrichten verschlüsseln, dann in einer aus dem Seed
            // abgeleiteten Permutation zustellen (deterministisch, damit
            // proptest Gegenbeispiele reproduzieren kann).
            let mut sealed = Vec::with_capacity(messages.len());
            for message in &messages {
                sealed.push(alice.encrypt(&bob_address, message).await.unwrap());
            }
            let mut order: Vec<usize> = (0..sealed.len()).collect();
            let mut state = seed;
            for i in (1..order.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = (state >> 33) as usize % (i + 1);
                order.swap(i, j);
            }

            for &i in &order {
                let plaintext = bob.decrypt(&alice_address, &sealed[i]).await.unwrap();
                assert_eq!(plaintext, messages[i], "Nachricht {i} muss unversehrt ankommen");
            }
        });
    }
}
