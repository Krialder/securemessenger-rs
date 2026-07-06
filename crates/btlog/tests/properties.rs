//! Property-Tests des Binary-Transparency-Logs: die Append-only-Garantie
//! muss gegen beliebige Manipulationen halten, nicht nur gegen die drei
//! handgebauten Fälle der Unit-Tests, und die Parser dürfen auf fremdem
//! Text niemals in Panik geraten (das Log kommt von außen).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn build_log(payloads: &[Vec<u8>], signer: &SigningKey) -> (Vec<btlog::LogEntry>, btlog::LogHead) {
    let mut entries = Vec::new();
    let mut head = None;
    for (i, payload) in payloads.iter().enumerate() {
        let sha: [u8; 32] = Sha256::digest(payload).into();
        let (entry, new_head) = btlog::append(
            &entries,
            &format!("artefakt-{i}"),
            "1.0.0",
            &sha,
            1_700_000_000 + i as u64,
            signer,
        )
        .expect("Anhängen gelingt");
        entries.push(entry);
        head = Some(new_head);
    }
    (entries, head.expect("mindestens ein Eintrag"))
}

proptest! {
    /// Rundlauf für beliebige Artefakt-Inhalte: bauen, prüfen, über die
    /// Datei serialisieren, wieder prüfen.
    #[test]
    fn build_verify_roundtrip(payloads in proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..64), 1..6)) {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let (entries, head) = build_log(&payloads, &signer);
        btlog::verify(&entries, &head, &signer.verifying_key()).expect("gültig");
        let reloaded = btlog::from_jsonl(&btlog::to_jsonl(&entries).unwrap()).unwrap();
        btlog::verify(&reloaded, &head, &signer.verifying_key()).expect("nach Datei-Rundlauf gültig");
    }

    /// Jede Einzelfeld-Änderung an irgendeinem Eintrag lässt die Prüfung
    /// scheitern: genau die Eigenschaft, die "append-only" bedeutet.
    #[test]
    fn any_single_field_mutation_fails_verification(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..32), 1..5),
        which in any::<usize>(),
        field in 0usize..5,
    ) {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let (mut entries, head) = build_log(&payloads, &signer);
        let at = which % entries.len();
        match field {
            0 => entries[at].artifact.push('x'),
            1 => entries[at].version.push('x'),
            2 => entries[at].built_at = entries[at].built_at.wrapping_add(1),
            3 => {
                // sha256 auf einen anderen gültigen Hash umbiegen.
                let other: [u8; 32] = Sha256::digest(b"anderes artefakt").into();
                prop_assume!(entries[at].sha256 != BASE64.encode(other));
                entries[at].sha256 = BASE64.encode(other);
            }
            _ => entries[at].index = entries[at].index.wrapping_add(1),
        }
        prop_assert!(btlog::verify(&entries, &head, &signer.verifying_key()).is_err());
    }

    /// Der Zeilen-Parser überlebt beliebigen Text: entweder ein sauberer
    /// Fehler oder ein Ergebnis, nie eine Panik. Das Log ist eine fremde
    /// Eingabe (gespiegelt, heruntergeladen), Robustheit ist Pflicht.
    #[test]
    fn jsonl_parser_never_panics(text in ".{0,512}") {
        let _ = btlog::from_jsonl(&text);
    }

    /// Auch kaputte Base64-Felder in strukturell gültigem JSON führen zu
    /// Fehlern, nie zu Paniken; verify behandelt sie als ungültig.
    #[test]
    fn verify_survives_corrupt_hash_fields(garbage in ".{0,48}") {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let (mut entries, head) = build_log(&[b"a".to_vec()], &signer);
        entries[0].prev_hash = garbage.clone();
        prop_assert!(btlog::verify(&entries, &head, &signer.verifying_key()).is_err());
        let mut entries2 = entries;
        entries2[0].prev_hash = BASE64.encode([0u8; 32]);
        entries2[0].sha256 = garbage;
        prop_assert!(btlog::verify(&entries2, &head, &signer.verifying_key()).is_err());
    }
}
