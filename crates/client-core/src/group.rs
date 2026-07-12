//! Gruppen: MLS (RFC 9420) aus OpenMLS.
//!
//! Die Plattform-Festlegungen aus specs/krypto-kern.md liegen hier an
//! genau einer Stelle: die Cipher-Suite 0x0003 (ChaCha20-Poly1305,
//! einheitlich über die Plattform und ohne AES-Hardware schnell) und
//! das Skipped-Keys-Fenster. Die Suite ist klassisch; der PQ-Pfad für
//! Gruppen folgt, sobald der MLS-Combiner-Draft in OpenMLS landet.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (Suite 0x0003,
/// specs/krypto-kern.md "MLS-Cipher-Suite").
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Zielwert aus der Spec: bis etwa 2000 übersprungene Keys pro Sitzung,
/// sonst wird der Puffer ein Speicher-DoS.
const MAX_FORWARD_DISTANCE: u32 = 2000;
/// Wie viele bereits konsumierte Schlüssel für verspätete (umgeordnete)
/// Nachrichten vorgehalten werden. [ANNAHME: 10; die Spec nennt nur das
/// Vorwärts-Fenster.]
const OUT_OF_ORDER_TOLERANCE: u32 = 10;

fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAX_FORWARD_DISTANCE)
}

/// Formatkennung des exportierten MLS-Zustands (`export_state`). Bewusst
/// längenpräfixiert statt getrennt (die btlog-Lehre: Trennzeichen
/// kollidieren mit Nutzdaten, Längen nicht).
const STATE_MAGIC: &[u8] = b"smmls.v1";

/// Ein Gruppenmitglied: Provider (Krypto und Ablage), Credential und
/// Signaturschlüssel. [ANNAHME: BasicCredential, bis die Geräte-
/// Credentials aus specs/geraete-identitaet.md die MLS-Credentials
/// stellen.] Der Provider hält alle MLS-Geheimnisse (Signierschlüssel,
/// KeyPackage-Privatteile, Gruppenzustände) in seiner Ablage; über
/// `export_state`/`restore` überlebt genau diese Ablage einen
/// Prozess-Neustart, verschlüsselt abgelegt von der Client-Schicht
/// (keystore). Ein Gerät hat EIN Mitglied für alle seine Gruppen.
pub struct GroupMember {
    provider: OpenMlsRustCrypto,
    credential: CredentialWithKey,
    signer: SignatureKeyPair,
}

impl GroupMember {
    pub fn new(identity: &[u8]) -> Result<Self, String> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity.to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|err| format!("Signaturschlüssel: {err}"))?;
        signer
            .store(provider.storage())
            .map_err(|err| format!("Schlüsselablage: {err}"))?;
        Ok(Self {
            provider,
            credential: CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
            signer,
        })
    }

    pub fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    /// Ein frisches KeyPackage - das, was ein Mitglied veröffentlicht,
    /// damit andere es in Gruppen einladen können.
    pub fn key_package(&self) -> Result<KeyPackageBundle, String> {
        KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|err| format!("KeyPackage: {err}"))
    }

    /// Erzeugt eine neue Gruppe unter der gegebenen Gruppen-ID mit den
    /// Plattform-Festlegungen. Die ID ist die des Zustelldienstes (UUID
    /// als Bytes), damit ein Neustart die Gruppe über `MlsGroup::load`
    /// unter derselben ID wiederfindet; eine zufällige interne ID ließe
    /// sich nach dem Laden nicht mehr der Zustell-Gruppe zuordnen. Der
    /// Ratchet-Tree reist in der Welcome-Nachricht mit, damit der
    /// Beitritt keinen separaten Tree-Abruf braucht.
    pub fn create_group(&self, group_id: &[u8]) -> Result<MlsGroup, String> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(sender_ratchet())
            .build();
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|err| format!("Gruppe anlegen: {err}"))
    }

    /// Exportiert den kompletten MLS-Zustand dieses Mitglieds als opaken
    /// Blob: die Provider-Ablage (Signierschlüssel, KeyPackage-Privatteile,
    /// alle Gruppenzustände) plus den öffentlichen Signierschlüssel als
    /// Wiederfinde-Anker. Nach JEDER zustandsändernden Operation (Gruppe
    /// anlegen, beitreten, Nachricht erzeugen oder verarbeiten, Mitglieder
    /// hinzufügen) neu exportieren und ablegen, sonst reißt der Ratchet
    /// beim nächsten Laden. Der Blob enthält private Schlüssel; die
    /// Client-Schicht legt ihn nur verschlüsselt ab (keystore).
    pub fn export_state(&self) -> Result<Vec<u8>, String> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "MLS-Ablage-Lock vergiftet".to_string())?;
        // Sortiert exportieren: deterministische Blobs erleichtern Tests
        // und Vergleiche; die HashMap-Ordnung wäre zufällig.
        let mut entries: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let public = self.signer.to_public_vec();
        let mut out = Vec::with_capacity(64 + entries.len() * 128);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&(public.len() as u32).to_be_bytes());
        out.extend_from_slice(&public);
        out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (key, value) in entries {
            out.extend_from_slice(&(key.len() as u32).to_be_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    /// Stellt ein Mitglied aus einem exportierten Zustand wieder her.
    /// `identity` muss dieselbe sein wie beim Anlegen (das eigene Handle):
    /// das Credential wird daraus neu gebaut, der Signierschlüssel kommt
    /// aus der wiederhergestellten Ablage. Ein manipulierter oder
    /// abgeschnittener Blob wird abgewiesen, bevor irgendetwas davon in
    /// den Provider gelangt.
    pub fn restore(identity: &[u8], state: &[u8]) -> Result<Self, String> {
        let rest = state
            .strip_prefix(STATE_MAGIC)
            .ok_or("MLS-Zustand: unbekanntes Format")?;
        let (public, rest) = read_prefixed(rest, "Signierschlüssel")?;
        let (count_bytes, mut rest) = split_checked(rest, 8, "Eintragszahl")?;
        let count = u64::from_be_bytes(count_bytes.try_into().expect("8 Bytes"));
        let mut values = std::collections::HashMap::new();
        for _ in 0..count {
            let (key, after_key) = read_prefixed(rest, "Ablage-Schlüssel")?;
            let (value, after_value) = read_prefixed(after_key, "Ablage-Wert")?;
            values.insert(key.to_vec(), value.to_vec());
            rest = after_value;
        }
        if !rest.is_empty() {
            return Err("MLS-Zustand: überzählige Bytes am Ende".to_string());
        }
        let provider = OpenMlsRustCrypto::default();
        *provider
            .storage()
            .values
            .write()
            .map_err(|_| "MLS-Ablage-Lock vergiftet".to_string())? = values;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or("MLS-Zustand: Signierschlüssel fehlt in der Ablage")?;
        let credential = BasicCredential::new(identity.to_vec());
        Ok(Self {
            provider,
            credential: CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
            signer,
        })
    }

    /// Tritt einer Gruppe über die Welcome-Nachricht bei.
    pub fn join(&self, welcome: Welcome) -> Result<MlsGroup, String> {
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(sender_ratchet())
            .build();
        StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|err| format!("Welcome verarbeiten: {err}"))?
            .into_group(&self.provider)
            .map_err(|err| format!("Beitritt: {err}"))
    }

    /// Ein frisches KeyPackage als opaker Blob (TLS-Wire-Format), fertig
    /// fürs Verzeichnis. Die privaten Anteile bleiben in der Ablage dieses
    /// Mitglieds; nur mit derselben Ablage lässt sich später der zugehörige
    /// Welcome verarbeiten (`join_group`).
    pub fn key_package_blob(&self) -> Result<Vec<u8>, String> {
        let bundle = self.key_package()?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|err| format!("KeyPackage serialisieren: {err}"))
    }
}

/// Liest einen u32-längenpräfixierten Abschnitt; lehnt zu kurze Eingaben
/// mit dem benannten Feld ab, damit ein kaputter Blob eine deutbare
/// Fehlermeldung ergibt statt eines Panics.
fn read_prefixed<'a>(input: &'a [u8], what: &str) -> Result<(&'a [u8], &'a [u8]), String> {
    let (len_bytes, rest) = split_checked(input, 4, what)?;
    let len = u32::from_be_bytes(len_bytes.try_into().expect("4 Bytes")) as usize;
    split_checked(rest, len, what)
}

fn split_checked<'a>(
    input: &'a [u8],
    at: usize,
    what: &str,
) -> Result<(&'a [u8], &'a [u8]), String> {
    if input.len() < at {
        return Err(format!("MLS-Zustand: {what} abgeschnitten"));
    }
    Ok(input.split_at(at))
}

/// Eine laufende Gruppensitzung: ein Mitglied plus sein MLS-Gruppenzustand
/// (TreeKEM). Die Byte-Ein-Byte-Aus-Schnittstelle hält die MLS-Krypto
/// vollständig im Kern; die Client-Schicht (client-app) bewegt die opaken
/// Blobs nur über den Zustelldienst und interpretiert sie nie.
///
/// Der Zustand überlebt Neustarts über das Mitglied: OpenMLS schreibt
/// jede Änderung in die Provider-Ablage, `export_state` friert sie ein,
/// und `load` findet die Gruppe nach `GroupMember::restore` unter ihrer
/// Zustell-ID wieder. Die Client-Schicht exportiert nach jeder
/// zustandsändernden Operation.
pub struct GroupSession {
    member: GroupMember,
    group: MlsGroup,
}

impl GroupSession {
    /// Gründet eine neue Gruppe unter der Zustell-Gruppen-ID mit diesem
    /// Mitglied als erstem und einzigem Teilnehmer. Das Mitglied kommt vom
    /// Aufrufer (frisch oder wiederhergestellt), damit ein Gerät EIN
    /// Mitglied über alle Gruppen teilt und dessen Ablage alles hält.
    pub fn create(member: GroupMember, group_id: &[u8]) -> Result<Self, String> {
        let group = member.create_group(group_id)?;
        Ok(Self { member, group })
    }

    /// Lädt eine bestehende Gruppe aus der Ablage des Mitglieds über ihre
    /// Zustell-ID. `Ok(None)`, wenn die Ablage diese Gruppe nicht kennt
    /// (nie beigetreten oder Zustand verloren): der Aufrufer entscheidet,
    /// ob das ein Fehler ist.
    pub fn load(member: GroupMember, group_id: &[u8]) -> Result<Option<Self>, String> {
        let group = MlsGroup::load(member.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(|err| format!("Gruppe laden: {err}"))?;
        Ok(group.map(|group| Self { member, group }))
    }

    /// Tritt einer Gruppe über einen Welcome-Blob bei. Das Mitglied muss
    /// dasselbe sein, das zuvor das eingeladene KeyPackage erzeugt hat
    /// (dieselbe Ablage hält die privaten Anteile).
    pub fn join_group(member: GroupMember, welcome_blob: &[u8]) -> Result<Self, String> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_blob)
            .map_err(|err| format!("Welcome-Blob unlesbar: {err}"))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err("Blob ist keine Welcome-Nachricht".to_string());
        };
        let group = member.join(welcome)?;
        Ok(Self { member, group })
    }

    /// Lädt Mitglieder über ihre KeyPackage-Blobs ein. Liefert den
    /// Commit-Blob (für die schon vorhandenen Mitglieder) und den
    /// Welcome-Blob (für die neuen); der Aufrufer verteilt beide über den
    /// Zustelldienst. Der Commit ist danach lokal angewandt.
    pub fn add_members(
        &mut self,
        key_package_blobs: &[Vec<u8>],
    ) -> Result<AddMembersOutcome, String> {
        let mut key_packages = Vec::with_capacity(key_package_blobs.len());
        for blob in key_package_blobs {
            let kp_in = KeyPackageIn::tls_deserialize_exact(blob.as_slice())
                .map_err(|err| format!("KeyPackage-Blob unlesbar: {err}"))?;
            let validated = kp_in
                .validate(self.member.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|err| format!("KeyPackage ungültig: {err:?}"))?;
            key_packages.push(validated);
        }
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&self.member.provider, &self.member.signer, &key_packages)
            .map_err(|err| format!("Mitglieder hinzufügen: {err}"))?;
        self.group
            .merge_pending_commit(&self.member.provider)
            .map_err(|err| format!("Commit anwenden: {err}"))?;
        Ok(AddMembersOutcome {
            commit: commit
                .to_bytes()
                .map_err(|err| format!("Commit serialisieren: {err}"))?,
            welcome: welcome
                .to_bytes()
                .map_err(|err| format!("Welcome serialisieren: {err}"))?,
        })
    }

    /// Verschlüsselt eine Anwendungsnachricht zu einem Wire-Blob.
    pub fn create_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        self.group
            .create_message(&self.member.provider, &self.member.signer, plaintext)
            .map_err(|err| format!("Gruppennachricht erzeugen: {err}"))?
            .to_bytes()
            .map_err(|err| format!("Gruppennachricht serialisieren: {err}"))
    }

    /// Verarbeitet einen eingehenden Wire-Blob. Eine Anwendungsnachricht
    /// liefert ihren Klartext; ein Handshake (Commit anderer Mitglieder)
    /// wird angewandt und ergibt `None`.
    pub fn process(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let message = MlsMessageIn::tls_deserialize_exact(wire)
            .map_err(|err| format!("Gruppen-Blob unlesbar: {err}"))?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|err| format!("keine Protokollnachricht: {err}"))?;
        let processed = self
            .group
            .process_message(&self.member.provider, protocol)
            .map_err(|err| format!("Gruppennachricht verarbeiten: {err}"))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(Some(application.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&self.member.provider, *staged)
                    .map_err(|err| format!("fremden Commit anwenden: {err}"))?;
                Ok(None)
            }
            // Proposals ohne Commit halten wir nicht vor: unsere Commits
            // tragen ihre Proposals selbst (add_members).
            _ => Ok(None),
        }
    }

    /// Anzahl der Mitglieder in der aktuellen Epoche.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Die aktuelle MLS-Epoche (steigt mit jedem angewandten Commit).
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Die Gruppen-ID (bei plattform-eigenen Gruppen die Zustell-ID als
    /// Bytes; nach einem Beitritt kommt sie aus der Welcome-Nachricht).
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Exportiert den MLS-Zustand des tragenden Mitglieds (siehe
    /// `GroupMember::export_state`): nach jeder zustandsändernden
    /// Operation aufrufen und verschlüsselt ablegen.
    pub fn export_state(&self) -> Result<Vec<u8>, String> {
        self.member.export_state()
    }

    /// Gibt das tragende Mitglied zurück, etwa um nach einer Operation an
    /// dieser Gruppe eine weitere Gruppe desselben Geräts zu laden.
    pub fn into_member(self) -> GroupMember {
        self.member
    }
}

/// Ergebnis von `add_members`: die beiden zu verteilenden Blobs.
pub struct AddMembersOutcome {
    /// Commit für die bereits vorhandenen Mitglieder.
    pub commit: Vec<u8>,
    /// Welcome für die neu eingeladenen Mitglieder.
    pub welcome: Vec<u8>,
}
