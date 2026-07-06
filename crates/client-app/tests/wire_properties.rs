//! Property-Tests des Wire-Framings: die Parser stehen an der
//! Vertrauensgrenze (jede Hülle kommt über den Zustelldienst von fremden
//! Absendern) und dürfen auf keiner Eingabe in Panik geraten; das wäre
//! ein Denial-of-Service per Nachricht. Zusätzlich die Rundläufe der
//! beiden Framings, deren Inhalt hier frei wählbar ist (Gruppen- und
//! Sealed-Blobs sind opake Bytes).
//!
//! Das ist der Fuzzing-Teil der Roadmap (Phase 6, "Fuzzing für Parser
//! und Wire-Code") in Property-Form: proptest erzeugt die Eingaben und
//! verkleinert Gegenbeispiele, ein separates Fuzz-Harness (cargo-fuzz)
//! braucht nightly und bleibt der CI-Ausbaustufe.

#![cfg(not(target_arch = "wasm32"))]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::wire;
use proptest::prelude::*;

proptest! {
    /// Beliebiger Text: kein Parser paniert, alle liefern Wert oder Fehler.
    #[test]
    fn parsers_never_panic_on_arbitrary_text(input in ".{0,512}") {
        let _ = wire::classify(&input);
        let _ = wire::open(&input);
        let _ = wire::open_group(&input);
        let _ = wire::open_sealed(&input);
    }

    /// Beliebige Bytes hinter gültigem Base64: dringt an der ersten
    /// Dekodier-Schicht vorbei bis in die JSON- und Feld-Prüfungen.
    #[test]
    fn parsers_never_panic_on_arbitrary_base64(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
        let input = BASE64.encode(&raw);
        let _ = wire::classify(&input);
        let _ = wire::open(&input);
        let _ = wire::open_group(&input);
        let _ = wire::open_sealed(&input);
    }

    /// Strukturell gültiges JSON bis in die tiefste Schicht: Die Version
    /// wird gewichtet aus den ECHTEN Konstanten gezogen (ein reiner
    /// Zufallsstring träfe die acht Zeichen praktisch nie, und alle
    /// Parser kehrten schon an der Versionsprüfung um; Review-Fund),
    /// die Byte-Felder sind meist gültiges Base64 beliebiger Bytes und
    /// die Typen teils absichtlich falsch. So erreichen die Fälle den
    /// msg_type-Dispatch und die libsignal-Deserialisierer
    /// (PreKeySignalMessage/SignalMessage::try_from) mit missgebildeten
    /// Bytes: genau die fremden Parser an der Vertrauensgrenze.
    #[test]
    fn parsers_never_panic_on_arbitrary_json_envelopes(
        version in prop_oneof![
            3 => Just("smenv.v1".to_string()),
            3 => Just("smgrp.v1".to_string()),
            3 => Just("smssl.v1".to_string()),
            1 => ".{0,16}".prop_map(String::from),
        ],
        payload in prop_oneof![
            3 => proptest::collection::vec(any::<u8>(), 0..256)
                .prop_map(|b| serde_json::Value::String(BASE64.encode(b))),
            1 => ".{0,64}".prop_map(serde_json::Value::from),
        ],
        // 2 und 3 sind Whisper und PreKey (die echten Dispatch-Zweige),
        // der Rest trifft den unbekannten-Typ-Pfad.
        msg_type in prop_oneof![
            2 => Just(serde_json::Value::from(2u8)),
            2 => Just(serde_json::Value::from(3u8)),
            1 => any::<u8>().prop_map(serde_json::Value::from),
            1 => Just(serde_json::Value::String("drei".to_string())),
        ],
        from_device in prop_oneof![
            2 => any::<u32>().prop_map(serde_json::Value::from),
            1 => Just(serde_json::Value::String("eins".to_string())),
        ],
        drop_field in 0usize..8,
    ) {
        let mut json = serde_json::json!({
            "v": version,
            "from": "absender",
            "from_device": from_device,
            "msg_type": msg_type,
            "ciphertext": payload,
            "group_id": "gruppe",
            "blob": payload,
        });
        // Auch fehlende Felder sind Teil der Eingabeklasse: serde muss
        // sie als Fehler melden, nie als Panik.
        let fields = ["v", "from", "from_device", "msg_type", "ciphertext", "group_id", "blob"];
        if drop_field < fields.len() {
            json.as_object_mut().unwrap().remove(fields[drop_field]);
        }
        let input = BASE64.encode(json.to_string());
        let _ = wire::classify(&input);
        let _ = wire::open(&input);
        let _ = wire::open_group(&input);
        let _ = wire::open_sealed(&input);
    }

    /// Rundlauf des Sealed-Framings: jeder Blob kommt unverändert zurück,
    /// und classify erkennt die Hülle als Sealed.
    #[test]
    fn sealed_framing_roundtrips(blob in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let framed = wire::seal_sealed(&blob).expect("Framing gelingt");
        prop_assert!(matches!(wire::classify(&framed), wire::Framed::Sealed));
        prop_assert_eq!(wire::open_sealed(&framed).expect("Öffnen gelingt"), blob);
    }

    /// Rundlauf des Gruppen-Framings: Gruppen-ID und Blob überleben
    /// unverändert, classify routet zur Gruppe.
    #[test]
    fn group_framing_roundtrips(
        group_id in "[a-f0-9-]{1,40}",
        blob in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let framed = wire::seal_group(&group_id, &blob).expect("Framing gelingt");
        prop_assert!(matches!(wire::classify(&framed), wire::Framed::Group));
        let opened = wire::open_group(&framed).expect("Öffnen gelingt");
        prop_assert_eq!(opened.group_id, group_id);
        prop_assert_eq!(opened.blob, blob);
    }

    /// Die Framings verwechseln sich nicht, alle sechs Richtungen: keine
    /// Hülle öffnet in einem fremden Codepfad. Die 1:1-Hülle wird von
    /// Hand gebaut (eine echte bräuchte eine Ratchet-Sitzung), mit genau
    /// den Feldern, die `wire::seal` erzeugt.
    #[test]
    fn framings_do_not_cross_open(blob in proptest::collection::vec(any::<u8>(), 0..256)) {
        let sealed = wire::seal_sealed(&blob).unwrap();
        prop_assert!(wire::open(&sealed).is_err());
        prop_assert!(wire::open_group(&sealed).is_err());
        let group = wire::seal_group("gruppe", &blob).unwrap();
        prop_assert!(wire::open(&group).is_err());
        prop_assert!(wire::open_sealed(&group).is_err());
        let one_to_one = BASE64.encode(
            serde_json::json!({
                "v": "smenv.v1",
                "from": "absender",
                "from_device": 1,
                "msg_type": 2,
                "ciphertext": BASE64.encode(&blob),
            })
            .to_string(),
        );
        prop_assert!(matches!(wire::classify(&one_to_one), wire::Framed::OneToOne));
        prop_assert!(wire::open_group(&one_to_one).is_err());
        prop_assert!(wire::open_sealed(&one_to_one).is_err());
    }
}
