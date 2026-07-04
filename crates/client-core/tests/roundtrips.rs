//! Integrations-Beweise für den Krypto-Kern: die gepinnten Bibliotheken
//! arbeiten in unserer Orchestrierung korrekt zusammen. Das sind keine
//! Krypto-Tests (die liegen bei libsignal/OpenMLS), sondern Beweise,
//! dass Sitzungsaufbau, Nachrichtenumlauf, Out-of-Order und Gruppen
//! über unsere Wrapper funktionieren.

use client_core::group::{GroupMember, GroupSession, CIPHERSUITE};
use client_core::libsignal_protocol::{CiphertextMessage, SignalProtocolError};
use client_core::onetoone::Device;
use client_core::openmls::prelude::tls_codec::*;
use client_core::openmls::prelude::*;

/// Über die Leitung und zurück: serialisiert eine ausgehende MLS-Nachricht
/// ins TLS-Wire-Format und liest sie als eingehende wieder ein - so, wie
/// sie später durch den Zustelldienst liefe.
fn over_the_wire(message: MlsMessageOut) -> MlsMessageIn {
    let bytes = message.to_bytes().expect("MLS-Nachricht serialisierbar");
    MlsMessageIn::tls_deserialize_exact(bytes).expect("MLS-Nachricht deserialisierbar")
}

#[tokio::test]
async fn pqxdh_session_and_double_ratchet_roundtrip() {
    let mut alice = Device::new("alice-device", 1, 11).unwrap();
    let mut bob = Device::new("bob-device", 1, 22).unwrap();

    // bob veröffentlicht ein Bündel, alice baut die Sitzung auf.
    let bundle = bob.publish_prekey_bundle().await.unwrap();
    let bob_address = bob.address().clone();
    let alice_address = alice.address().clone();
    alice
        .establish_session(&bob_address, &bundle)
        .await
        .unwrap();

    // Die erste Nachricht ist eine PreKey-Nachricht und trägt den
    // ML-KEM-Chiffretext: der Beweis, dass der PQ-Anteil auf der
    // Leitung liegt und nicht strippbar wäre, ohne den Handshake zu
    // zerstören (specs/krypto-kern.md "PQXDH und die Hybrid-Bindung").
    let first = alice.encrypt(&bob_address, b"hallo bob").await.unwrap();
    match &first {
        CiphertextMessage::PreKeySignalMessage(message) => {
            assert!(
                message.kyber_ciphertext().is_some(),
                "PQXDH-Aufbau muss den KEM-Chiffretext tragen"
            );
        }
        other => panic!("PreKey-Nachricht erwartet, kam {:?}", other.message_type()),
    }
    assert_eq!(
        bob.decrypt(&alice_address, &first).await.unwrap(),
        b"hallo bob"
    );

    // Antwort in Gegenrichtung: ab jetzt normale Ratchet-Nachrichten.
    let reply = bob.encrypt(&alice_address, b"hallo alice").await.unwrap();
    assert!(matches!(reply, CiphertextMessage::SignalMessage(_)));
    assert_eq!(
        alice.decrypt(&bob_address, &reply).await.unwrap(),
        b"hallo alice"
    );

    // Out-of-Order: die zweite Nachricht kommt vor der ersten an; der
    // Ratchet puffert den übersprungenen Message-Key.
    let m1 = alice.encrypt(&bob_address, b"nachricht 1").await.unwrap();
    let m2 = alice.encrypt(&bob_address, b"nachricht 2").await.unwrap();
    assert_eq!(
        bob.decrypt(&alice_address, &m2).await.unwrap(),
        b"nachricht 2"
    );
    assert_eq!(
        bob.decrypt(&alice_address, &m1).await.unwrap(),
        b"nachricht 1"
    );

    // Replay derselben Nachricht wird als Duplikat erkannt, nicht
    // erneut entschlüsselt.
    let replay = bob.decrypt(&alice_address, &m2).await;
    assert!(
        matches!(replay, Err(SignalProtocolError::DuplicatedMessage(_, _))),
        "Replay muss als Duplikat abgewiesen werden, kam {replay:?}"
    );

    // Safety Number: beide Seiten sehen dieselbe Nummer (symmetrische
    // Konstruktion), und ein Dritter mit anderem Schlüssel eine andere.
    let alice_sees = alice
        .safety_number(&bob_address)
        .await
        .unwrap()
        .expect("Bobs Schlüssel liegt nach der Sitzung in der Ablage");
    let bob_sees = bob
        .safety_number(&alice_address)
        .await
        .unwrap()
        .expect("Alices Schlüssel liegt nach der Sitzung in der Ablage");
    assert_eq!(
        alice_sees, bob_sees,
        "beide Seiten müssen dieselbe Sicherheitsnummer sehen"
    );
    assert_eq!(alice_sees.len(), 60, "Signal-Format: 60 Ziffern");

    // Unbekannte Adresse: keine Nummer statt einer erfundenen.
    let stranger = libsignal_protocol::ProtocolAddress::new(
        "fremd".to_string(),
        libsignal_protocol::DeviceId::new(1).unwrap(),
    );
    assert!(alice.safety_number(&stranger).await.unwrap().is_none());
}

#[test]
fn mls_group_roundtrip_with_pinned_ciphersuite() {
    // Die Festlegung aus der Spec, als Zahl nachgeprüft.
    assert_eq!(u16::from(CIPHERSUITE), 0x0003);

    let alice = GroupMember::new(b"alice").unwrap();
    let bob = GroupMember::new(b"bob").unwrap();

    // alice gründet die Gruppe und lädt bob über dessen KeyPackage ein.
    let mut alice_group = alice.create_group().unwrap();
    assert_eq!(alice_group.ciphersuite(), CIPHERSUITE);

    let bob_key_package = bob.key_package().unwrap();
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice.provider(),
            alice.signer(),
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice.provider()).unwrap();

    let MlsMessageBodyIn::Welcome(welcome) = over_the_wire(welcome).extract() else {
        panic!("Welcome-Nachricht erwartet");
    };
    let mut bob_group = bob.join(welcome).unwrap();

    // Beide sehen denselben Gruppenzustand.
    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(bob_group.members().count(), 2);
    assert_eq!(
        alice_group
            .export_secret(alice.provider().crypto(), "beweis", &[], 32)
            .unwrap(),
        bob_group
            .export_secret(bob.provider().crypto(), "beweis", &[], 32)
            .unwrap(),
        "Exporter-Secret muss auf beiden Seiten gleich sein"
    );

    // Anwendungsnachricht alice -> bob, über das Wire-Format.
    let message = alice_group
        .create_message(alice.provider(), alice.signer(), b"hallo gruppe")
        .unwrap();
    let processed = bob_group
        .process_message(
            bob.provider(),
            over_the_wire(message)
                .try_into_protocol_message()
                .expect("Protokollnachricht"),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            assert_eq!(application.into_bytes(), b"hallo gruppe");
        }
        _ => panic!("Anwendungsnachricht erwartet"),
    }

    // Und zurück: bob -> alice.
    let reply = bob_group
        .create_message(bob.provider(), bob.signer(), b"hallo alice")
        .unwrap();
    let processed = alice_group
        .process_message(
            alice.provider(),
            over_the_wire(reply)
                .try_into_protocol_message()
                .expect("Protokollnachricht"),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            assert_eq!(application.into_bytes(), b"hallo alice");
        }
        _ => panic!("Anwendungsnachricht erwartet"),
    }
}

/// Die Byte-Ein-Byte-Aus-Schnittstelle `GroupSession`, wie sie der Client
/// über den Zustelldienst nutzt: alle Blobs sind opak, nichts an der
/// Schnittstelle setzt libsignal/OpenMLS-Typen voraus. Beweist einen
/// Beitritt über KeyPackage plus Welcome und den Nachrichtenumlauf.
#[test]
fn group_session_byte_interface_roundtrip() {
    // Bob erzeugt sein KeyPackage (die privaten Anteile bleiben in seiner
    // Ablage); als Blob geht es später über das Verzeichnis.
    let bob_member = GroupMember::new(b"bob").unwrap();
    let bob_key_package = bob_member.key_package_blob().unwrap();

    // Alice gründet die Gruppe und lädt Bob über den KeyPackage-Blob ein.
    let mut alice = GroupSession::create(b"alice").unwrap();
    assert_eq!(alice.member_count(), 1);
    let outcome = alice.add_members(&[bob_key_package]).unwrap();
    assert_eq!(alice.member_count(), 2);

    // Bob tritt über den Welcome-Blob mit derselben Ablage bei.
    let mut bob = GroupSession::join_group(bob_member, &outcome.welcome).unwrap();
    assert_eq!(bob.member_count(), 2);
    assert_eq!(alice.epoch(), bob.epoch(), "beide auf derselben Epoche");

    // Anwendungsnachricht hin und zurück, nur über Blobs.
    let ciphertext = alice.create_message(b"hallo gruppe").unwrap();
    assert_eq!(
        bob.process(&ciphertext).unwrap().as_deref(),
        Some(b"hallo gruppe".as_slice())
    );
    let reply = bob.create_message(b"hallo zurueck").unwrap();
    assert_eq!(
        alice.process(&reply).unwrap().as_deref(),
        Some(b"hallo zurueck".as_slice())
    );
}
