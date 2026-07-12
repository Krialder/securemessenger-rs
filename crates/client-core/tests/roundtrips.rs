//! Integrations-Beweise für den Krypto-Kern: die gepinnten Bibliotheken
//! arbeiten in unserer Orchestrierung korrekt zusammen. Das sind keine
//! Krypto-Tests (die liegen bei libsignal/OpenMLS), sondern Beweise,
//! dass Sitzungsaufbau, Nachrichtenumlauf, Out-of-Order und Gruppen
//! über unsere Wrapper funktionieren.

use client_core::group::{GroupApplication, GroupInbound, GroupMember, GroupSession, CIPHERSUITE};
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

    // Schlüsselwechsel-Erkennung: der gespeicherte Identitätsschlüssel des
    // Kontakts ist der aus der Sitzung; ein Erstkontakt hat keinen.
    let stored = alice
        .stored_identity(&bob_address)
        .await
        .unwrap()
        .expect("Bobs Schlüssel liegt nach der Sitzung");
    assert_eq!(
        stored,
        bob.identity_public().await.unwrap(),
        "gespeichert ist genau Bobs Geräteschlüssel"
    );
    assert!(
        alice.stored_identity(&stranger).await.unwrap().is_none(),
        "ein unbekannter Kontakt hat keinen gespeicherten Schlüssel"
    );
}

/// Sealed Sender über die selbst ausgestellte Zertifikatskette: Alice
/// versiegelt mit einem Zertifikat aus `sealed-cert`, Bob entsiegelt gegen
/// den Trust Root und erfährt den Absender erst aus der geprüften Hülle.
#[tokio::test]
async fn sealed_sender_roundtrip_with_issued_certificate() {
    let mut alice = Device::new("alice", 1, 31).unwrap();
    let mut bob = Device::new("bob", 1, 32).unwrap();
    let bundle = bob.publish_prekey_bundle().await.unwrap();
    let bob_address = bob.address().clone();
    alice
        .establish_session(&bob_address, &bundle)
        .await
        .unwrap();

    // Der "identity-Dienst" stellt Alices Zertifikat aus: gebunden an
    // Handle, Gerätenummer und ihren registrierten Identitätsschlüssel.
    let issuer = sealed_cert::Issuer::from_seed(&[42u8; 32]).unwrap();
    let alice_identity = alice.identity_public().await.unwrap();
    let far_future = 4_102_444_800_000u64; // Unix-Millisekunden, Jahr 2100
    let certificate = issuer
        .issue("alice", 1, &alice_identity, far_future)
        .unwrap();

    // Versiegeln und entsiegeln: der Absender steckt in der Hülle, nicht
    // daneben; die Kette wird gegen den Trust Root geprüft.
    let sealed = alice
        .seal_message(&bob_address, &certificate, b"kein absender im klartext")
        .await
        .unwrap();
    let unsealed = bob
        .unseal_message(&issuer.trust_root_public(), &sealed)
        .await
        .unwrap();
    assert_eq!(unsealed.sender, "alice");
    assert_eq!(unsealed.sender_device_id, 1);
    assert_eq!(unsealed.plaintext, b"kein absender im klartext");

    // Die Hülle selbst enthält das Handle nirgends im Klartext: der
    // Zustelldienst könnte den Absender nicht herauslesen.
    let haystack = String::from_utf8_lossy(&sealed).into_owned();
    assert!(
        !haystack.contains("alice"),
        "der Absender darf in der versiegelten Hülle nicht lesbar sein"
    );

    // Ein fremder Trust Root lehnt die Hülle ab: genau die Stelle, an der
    // ein untergeschobener Aussteller auffliegt.
    let foreign = sealed_cert::Issuer::from_seed(&[43u8; 32]).unwrap();
    let sealed_again = alice
        .seal_message(&bob_address, &certificate, b"zweiter versuch")
        .await
        .unwrap();
    assert!(
        bob.unseal_message(&foreign.trust_root_public(), &sealed_again)
            .await
            .is_err(),
        "eine Hülle mit fremder Zertifikatskette muss scheitern"
    );

    // Ein abgelaufenes Zertifikat scheitert ebenfalls, noch vor der
    // Entschlüsselung.
    let expired = issuer.issue("alice", 1, &alice_identity, 1_000).unwrap();
    let sealed_expired = alice
        .seal_message(&bob_address, &expired, b"zu spaet")
        .await
        .unwrap();
    assert!(
        bob.unseal_message(&issuer.trust_root_public(), &sealed_expired)
            .await
            .is_err(),
        "ein abgelaufenes Zertifikat darf nicht mehr entsiegeln"
    );
}

#[test]
fn mls_group_roundtrip_with_pinned_ciphersuite() {
    // Die Festlegung aus der Spec, als Zahl nachgeprüft.
    assert_eq!(u16::from(CIPHERSUITE), 0x0003);

    let alice = GroupMember::new(b"alice").unwrap();
    let bob = GroupMember::new(b"bob").unwrap();

    // alice gründet die Gruppe (unter einer Zustell-ID) und lädt bob über
    // dessen KeyPackage ein.
    let mut alice_group = alice.create_group(b"gruppe-1").unwrap();
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

/// Entpackt eine Anwendungsnachricht aus dem `process`-Ergebnis; alles
/// andere ist im jeweiligen Test ein Fehler.
fn expect_application(inbound: GroupInbound) -> GroupApplication {
    match inbound {
        GroupInbound::Application(application) => application,
        GroupInbound::Updated => panic!("Anwendungsnachricht erwartet, kam Updated"),
        GroupInbound::RemovedSelf => panic!("Anwendungsnachricht erwartet, kam RemovedSelf"),
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
    let alice_member = GroupMember::new(b"alice").unwrap();
    let mut alice = GroupSession::create(alice_member, b"gruppe-bytes").unwrap();
    assert_eq!(alice.member_count(), 1);
    let outcome = alice.add_members(&[bob_key_package]).unwrap();
    // Der Commit ist erst vorgemerkt (Epoche unverändert), bis der
    // Zustelldienst ihn annimmt; hier: sofort anwenden.
    assert_eq!(alice.member_count(), 1);
    alice.merge_pending().unwrap();
    assert_eq!(alice.member_count(), 2);

    // Bob tritt über den Welcome-Blob mit derselben Ablage bei; die
    // Gruppen-ID aus der Welcome ist die der Gründung.
    let mut bob = GroupSession::join_group(bob_member, &outcome.welcome).unwrap();
    assert_eq!(bob.member_count(), 2);
    assert_eq!(alice.epoch(), bob.epoch(), "beide auf derselben Epoche");
    assert_eq!(bob.group_id(), b"gruppe-bytes".to_vec());

    // Anwendungsnachricht hin und zurück, nur über Blobs; der Absender
    // kommt aus der von MLS geprüften Credential, nicht aus der Hülle.
    let ciphertext = alice.create_message(b"hallo gruppe").unwrap();
    let inbound = expect_application(bob.process(&ciphertext).unwrap());
    assert_eq!(inbound.plaintext, b"hallo gruppe");
    assert_eq!(inbound.sender_identity, b"alice");
    let reply = bob.create_message(b"hallo zurueck").unwrap();
    let inbound = expect_application(alice.process(&reply).unwrap());
    assert_eq!(inbound.plaintext, b"hallo zurueck");
    assert_eq!(inbound.sender_identity, b"bob");

    // Die Mitgliederliste kommt aus dem Ratchet-Tree.
    let mut identities = bob.member_identities();
    identities.sort();
    assert_eq!(identities, vec![b"alice".to_vec(), b"bob".to_vec()]);
}

/// Der Neustart-Beweis der persistenten MLS-Ablage: beide Seiten frieren
/// ihren Zustand mit `export_state` ein, werden aus den Blobs
/// wiederhergestellt (`GroupMember::restore` plus `GroupSession::load`
/// über die Zustell-ID) und setzen den Ratchet in beide Richtungen fort.
/// Genau das braucht die CLI (Prozess je Befehl) und der Browser (Reload).
#[test]
fn group_session_survives_restart_via_exported_state() {
    // Runde 1: Gruppe gründen, Bob tritt bei, eine Nachricht fließt.
    let bob_member = GroupMember::new(b"bob").unwrap();
    let bob_key_package = bob_member.key_package_blob().unwrap();
    // Bobs Zustand SOFORT nach der KeyPackage-Erzeugung einfrieren: die
    // privaten Anteile müssen den "Neustart" bis zur Welcome überleben.
    let bob_state_before_join = bob_member.export_state().unwrap();

    let alice_member = GroupMember::new(b"alice").unwrap();
    let mut alice = GroupSession::create(alice_member, b"gruppe-neustart").unwrap();
    let outcome = alice.add_members(&[bob_key_package]).unwrap();
    // Vorgemerkten Commit anwenden (der Dienst hätte ihn angenommen).
    alice.merge_pending().unwrap();

    // "Neustart" auf Bobs Seite: Mitglied aus dem Blob, Beitritt klappt,
    // weil die KeyPackage-Privatteile im wiederhergestellten Zustand liegen.
    let bob_restored = GroupMember::restore(b"bob", &bob_state_before_join).unwrap();
    let mut bob = GroupSession::join_group(bob_restored, &outcome.welcome).unwrap();
    let first = alice.create_message(b"vor dem neustart").unwrap();
    assert_eq!(
        expect_application(bob.process(&first).unwrap()).plaintext,
        b"vor dem neustart"
    );
    // Export NACH der letzten Operation beider Seiten: auch das Erzeugen
    // einer Nachricht rückt den Sende-Ratchet vor. Ein Export davor ließe
    // die wiederhergestellte Alice dieselbe Ratchet-Position erneut nutzen,
    // und Bob wiese den schon konsumierten Schlüssel ab (Forward Secrecy;
    // genau so schlug die erste Fassung dieses Tests fehl).
    let alice_state = alice.export_state().unwrap();
    let bob_state = bob.export_state().unwrap();
    drop(alice);
    drop(bob);

    // "Neustart" beider Seiten: Zustand aus den Blobs, Gruppe über die
    // Zustell-ID laden, Ratchet läuft in beide Richtungen weiter.
    let alice_member = GroupMember::restore(b"alice", &alice_state).unwrap();
    let mut alice = GroupSession::load(alice_member, b"gruppe-neustart")
        .unwrap()
        .expect("Alices Ablage kennt die Gruppe");
    let bob_member = GroupMember::restore(b"bob", &bob_state).unwrap();
    let mut bob = GroupSession::load(bob_member, b"gruppe-neustart")
        .unwrap()
        .expect("Bobs Ablage kennt die Gruppe");
    assert_eq!(alice.member_count(), 2);
    assert_eq!(bob.member_count(), 2);

    let second = alice.create_message(b"nach dem neustart").unwrap();
    assert_eq!(
        expect_application(bob.process(&second).unwrap()).plaintext,
        b"nach dem neustart"
    );
    let reply = bob.create_message(b"zurueck nach neustart").unwrap();
    assert_eq!(
        expect_application(alice.process(&reply).unwrap()).plaintext,
        b"zurueck nach neustart"
    );

    // Eine unbekannte Gruppen-ID lädt nichts (kein Fehler, kein Panik).
    let stranger = GroupMember::restore(b"alice", &alice.export_state().unwrap()).unwrap();
    assert!(GroupSession::load(stranger, b"gibt-es-nicht")
        .unwrap()
        .is_none());
}

/// Mitglied entfernen mit MLS-Neuschlüsseln: der Entfernte erkennt seine
/// Entfernung am Commit (`RemovedSelf`), kann NICHTS mehr aus der neuen
/// Epoche lesen, und seine Alt-Epochen-Nachrichten weisen die
/// Verbliebenen ab. Genau die Eigenschaft, um die es beim Entfernen geht
/// (etwa nach der Revocation eines Geräts).
#[test]
fn removed_member_is_rekeyed_out() {
    // Dreiergruppe: alice gründet, bob und carol treten bei.
    let bob_member = GroupMember::new(b"bob").unwrap();
    let bob_kp = bob_member.key_package_blob().unwrap();
    let carol_member = GroupMember::new(b"carol").unwrap();
    let carol_kp = carol_member.key_package_blob().unwrap();
    let alice_member = GroupMember::new(b"alice").unwrap();
    let mut alice = GroupSession::create(alice_member, b"gruppe-remove").unwrap();
    let outcome = alice.add_members(&[bob_kp, carol_kp]).unwrap();
    alice.merge_pending().unwrap();
    let mut bob = GroupSession::join_group(bob_member, &outcome.welcome).unwrap();
    let mut carol = GroupSession::join_group(carol_member, &outcome.welcome).unwrap();
    assert_eq!(alice.member_count(), 3);

    // alice entfernt carol; der Commit ist vorgemerkt (Epoche noch
    // unverändert), bis der Dienst ihn annimmt. Erst dann anwenden.
    let commit = alice.remove_members(&[b"carol".to_vec()]).unwrap();
    assert_eq!(alice.member_count(), 3, "vor merge_pending unverändert");
    alice.merge_pending().unwrap();
    assert_eq!(alice.member_count(), 2);
    assert!(matches!(
        bob.process(&commit).unwrap(),
        GroupInbound::Updated
    ));
    assert_eq!(bob.member_count(), 2);
    assert!(matches!(
        carol.process(&commit).unwrap(),
        GroupInbound::RemovedSelf
    ));

    // Die neue Epoche bleibt carol verschlossen: bob liest, carol nicht
    // (ihre Gruppe ist beendet, die Verarbeitung scheitert).
    let secret = alice.create_message(b"ohne carol").unwrap();
    assert_eq!(
        expect_application(bob.process(&secret).unwrap()).plaintext,
        b"ohne carol"
    );
    assert!(carol.process(&secret).is_err());

    // carols Aufräumen: forget löscht den Gruppenzustand aus der Ablage,
    // ein Laden über die ID findet nichts mehr.
    let carol_member = carol.forget().unwrap();
    let carol_state = carol_member.export_state().unwrap();
    let carol_restored = GroupMember::restore(b"carol", &carol_state).unwrap();
    assert!(GroupSession::load(carol_restored, b"gruppe-remove")
        .unwrap()
        .is_none());

    // Ein Unbeteiligter kann niemanden entfernen: die Identität fehlt.
    assert!(alice.remove_members(&[b"gibt-es-nicht".to_vec()]).is_err());
}

/// Der Kern der Commit-Sicherheit: ein Commit wird erst NACH der Annahme
/// durch den Zustelldienst angewandt. Verliert man das Wettrennen (409,
/// ein anderes Mitglied war schneller), bleibt die eigene Epoche
/// unverändert (kein Fork), und der Gewinner-Commit lässt sich anwenden.
/// Ohne diese Trennung läge die eigene Epoche für immer neben der
/// Dienst-Wahrheit, und keine Entfernung ginge mehr durch (auch keine
/// sicherheitskritische nach einer Geräte-Kompromittierung).
#[test]
fn losing_a_commit_race_recovers_without_forking() {
    let bob_member = GroupMember::new(b"bob").unwrap();
    let bob_kp = bob_member.key_package_blob().unwrap();
    let carol_member = GroupMember::new(b"carol").unwrap();
    let carol_kp = carol_member.key_package_blob().unwrap();
    let alice_member = GroupMember::new(b"alice").unwrap();
    let mut alice = GroupSession::create(alice_member, b"gruppe-race").unwrap();
    let outcome = alice.add_members(&[bob_kp, carol_kp]).unwrap();
    alice.merge_pending().unwrap();
    let mut bob = GroupSession::join_group(bob_member, &outcome.welcome).unwrap();
    let start_epoch = alice.epoch();

    // Beide bauen gleichzeitig einen Remove-Commit für carol. bob gewinnt
    // beim Dienst und wendet an; alice bekommt ein 409 und wendet NICHT an
    // (sie ruft merge_pending nie auf, ihr Commit bleibt vorgemerkt).
    let _alices_commit = alice.remove_members(&[b"carol".to_vec()]).unwrap();
    let bobs_commit = bob.remove_members(&[b"carol".to_vec()]).unwrap();
    bob.merge_pending().unwrap();

    // Kein Fork: alices Epoche ist unverändert. Sie verarbeitet bobs
    // Gewinner-Commit; ihr vorgemerkter eigener wird dabei verworfen.
    assert_eq!(alice.epoch(), start_epoch, "kein Fork vor der Annahme");
    assert!(matches!(
        alice.process(&bobs_commit).unwrap(),
        GroupInbound::Updated
    ));
    assert_eq!(
        alice.epoch(),
        bob.epoch(),
        "beide auf derselben neuen Epoche"
    );
    assert_eq!(alice.member_count(), 2);

    // Der Ratchet läuft weiter: bob sendet in der neuen Epoche, alice liest.
    let msg = bob.create_message(b"nach dem rennen").unwrap();
    assert_eq!(
        expect_application(alice.process(&msg).unwrap()).plaintext,
        b"nach dem rennen"
    );
}

/// Manipulierte oder abgeschnittene Zustands-Blobs werden abgewiesen,
/// bevor etwas davon in den Provider gelangt.
#[test]
fn corrupted_group_state_is_rejected() {
    let member = GroupMember::new(b"mallory").unwrap();
    let state = member.export_state().unwrap();

    // Falsche Formatkennung.
    let mut wrong_magic = state.clone();
    wrong_magic[0] ^= 0xff;
    assert!(GroupMember::restore(b"mallory", &wrong_magic).is_err());

    // Abgeschnitten mitten in einem Eintrag.
    let truncated = &state[..state.len() - 3];
    assert!(GroupMember::restore(b"mallory", truncated).is_err());

    // Überzählige Bytes am Ende.
    let mut padded = state.clone();
    padded.extend_from_slice(b"rest");
    assert!(GroupMember::restore(b"mallory", &padded).is_err());

    // Der unverfälschte Blob stellt wieder her.
    assert!(GroupMember::restore(b"mallory", &state).is_ok());
}
