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

/// Ein Gruppenmitglied: Provider (Krypto und Ablage), Credential und
/// Signaturschlüssel. [ANNAHME: BasicCredential, bis die Geräte-
/// Credentials aus specs/geraete-identitaet.md die MLS-Credentials
/// stellen; die Ablage ist der In-Memory-Provider bis zur Client-Etappe.]
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

    /// Erzeugt eine neue Gruppe mit den Plattform-Festlegungen. Der
    /// Ratchet-Tree reist in der Welcome-Nachricht mit, damit der
    /// Beitritt keinen separaten Tree-Abruf braucht.
    pub fn create_group(&self) -> Result<MlsGroup, String> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(sender_ratchet())
            .build();
        MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .map_err(|err| format!("Gruppe anlegen: {err}"))
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

/// Eine laufende Gruppensitzung: ein Mitglied plus sein MLS-Gruppenzustand
/// (TreeKEM). Die Byte-Ein-Byte-Aus-Schnittstelle hält die MLS-Krypto
/// vollständig im Kern; die Client-Schicht (client-app) bewegt die opaken
/// Blobs nur über den Zustelldienst und interpretiert sie nie.
///
/// [ANNAHME: Die Ablage ist der In-Memory-Provider (wie beim 1:1-Kern bis
/// zur persistenten Geräte-Ablage). Ein Prozessende verliert den
/// Gruppenzustand; die persistente MLS-Ablage ist eine eigene Etappe.]
pub struct GroupSession {
    member: GroupMember,
    group: MlsGroup,
}

impl GroupSession {
    /// Gründet eine neue Gruppe mit diesem Mitglied als erstem und
    /// einzigem Teilnehmer.
    pub fn create(identity: &[u8]) -> Result<Self, String> {
        let member = GroupMember::new(identity)?;
        let group = member.create_group()?;
        Ok(Self { member, group })
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
}

/// Ergebnis von `add_members`: die beiden zu verteilenden Blobs.
pub struct AddMembersOutcome {
    /// Commit für die bereits vorhandenen Mitglieder.
    pub commit: Vec<u8>,
    /// Welcome für die neu eingeladenen Mitglieder.
    pub welcome: Vec<u8>,
}
