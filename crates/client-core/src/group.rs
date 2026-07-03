//! Gruppen: MLS (RFC 9420) aus OpenMLS.
//!
//! Die Plattform-Festlegungen aus specs/krypto-kern.md liegen hier an
//! genau einer Stelle: die Cipher-Suite 0x0003 (ChaCha20-Poly1305,
//! einheitlich über die Plattform und ohne AES-Hardware schnell) und
//! das Skipped-Keys-Fenster. Die Suite ist klassisch; der PQ-Pfad für
//! Gruppen folgt, sobald der MLS-Combiner-Draft in OpenMLS landet.

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
}
