//! 1:1-Sitzungen: PQXDH-Aufbau und Double Ratchet aus libsignal.
//!
//! Dieses Modul konstruiert nichts selbst - es orchestriert die
//! gepinnte Bibliothek. Die Hybrid-Bindung (X25519-Anteile und
//! ML-KEM-Geheimnis gemeinsam durch die KDF, Chiffretext in den
//! Associated Data) liegt vollständig in libsignal; genau an dieser
//! Stelle brechen eigene Konstruktionen (specs/krypto-kern.md
//! "PQXDH und die Hybrid-Bindung").
//!
//! Die Ablage ist austauschbar (`ProtocolStoreParts`): Tests und schnelle
//! Läufe nutzen den In-Memory-Store der Bibliothek, echte Clients stecken
//! eine persistente Ablage hinein (client-app), ohne dass die
//! Orchestrierung hier doppelt existiert.
//!
//! [ANNAHME: Der KEM-Typ ist ML-KEM-1024, wie ihn libsignal für PQXDH
//! produktiv verwendet. Die FFI-Schicht folgt mit der nativen
//! Client-Etappe.]

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, DeviceId,
    Fingerprint, GenericSignedPreKey as _, IdentityKeyPair, IdentityKeyStore,
    InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemSessionStore,
    InMemSignalProtocolStore, InMemSignedPreKeyStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle, PreKeyRecord, PreKeyStore, ProtocolAddress, SessionStore, SignalProtocolError,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

/// Zugriff auf die fünf Teil-Ablagen des Signal-Protokolls.
///
/// libsignals Protokoll-Funktionen (`message_decrypt` und Verwandte)
/// verlangen die Teil-Ablagen als getrennte `&mut`-Referenzen; ein einzelner
/// Typ, der alle fünf Traits implementiert, ließe sich nicht fünffach
/// mutabel ausleihen. Deshalb liefert `parts` alle Referenzen in einem
/// Zug aus disjunkten Feldern.
pub trait ProtocolStoreParts {
    type Sessions: SessionStore;
    type Identities: IdentityKeyStore;
    type PreKeys: PreKeyStore;
    type SignedPreKeys: SignedPreKeyStore;
    type KyberPreKeys: KyberPreKeyStore;

    #[allow(clippy::type_complexity)]
    fn parts(
        &mut self,
    ) -> (
        &mut Self::Sessions,
        &mut Self::Identities,
        &mut Self::PreKeys,
        &mut Self::SignedPreKeys,
        &mut Self::KyberPreKeys,
    );
}

/// Der In-Memory-Store der Bibliothek erfüllt den Zuschnitt direkt; seine
/// Teil-Ablagen sind öffentliche Felder.
impl ProtocolStoreParts for InMemSignalProtocolStore {
    type Sessions = InMemSessionStore;
    type Identities = InMemIdentityKeyStore;
    type PreKeys = InMemPreKeyStore;
    type SignedPreKeys = InMemSignedPreKeyStore;
    type KyberPreKeys = InMemKyberPreKeyStore;

    fn parts(
        &mut self,
    ) -> (
        &mut Self::Sessions,
        &mut Self::Identities,
        &mut Self::PreKeys,
        &mut Self::SignedPreKeys,
        &mut Self::KyberPreKeys,
    ) {
        (
            &mut self.session_store,
            &mut self.identity_store,
            &mut self.pre_key_store,
            &mut self.signed_pre_key_store,
            &mut self.kyber_pre_key_store,
        )
    }
}

/// Ein Gerät mit Identitätsschlüssel und Protokoll-Ablage. Bewusst
/// schmal: genug für Sitzungsaufbau und Nachrichtenumlauf. Ohne
/// Typ-Parameter läuft es in-memory (Tests); echte Clients stecken über
/// `with_store` eine persistente Ablage hinein.
pub struct Device<S: ProtocolStoreParts = InMemSignalProtocolStore> {
    address: ProtocolAddress,
    store: S,
    /// Fortlaufende IDs für Prekeys; jede Art zählt gemeinsam hoch,
    /// damit keine ID doppelt vergeben wird. Bei persistenter Ablage
    /// speichert der Aufrufer den Stand (`next_prekey_id`) und reicht ihn
    /// beim nächsten Start wieder hinein.
    next_prekey_id: u32,
}

/// Die aktuelle Zeit als `SystemTime`. Auf `wasm32-unknown-unknown` paniert
/// `SystemTime::now()` zur Laufzeit (keine System-Uhr im Browser-Sandkasten),
/// deshalb kommt die Zeit dort aus der JavaScript-Uhr; die Arithmetik
/// `UNIX_EPOCH + Duration` ist plattformneutral.
fn now() -> SystemTime {
    #[cfg(target_arch = "wasm32")]
    {
        UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
    }
}

fn now_millis() -> u64 {
    now()
        .duration_since(UNIX_EPOCH)
        .expect("Zeit nach 1970")
        .as_millis() as u64
}

fn parse_device_id(device_id: u8) -> Result<DeviceId, SignalProtocolError> {
    DeviceId::new(device_id)
        .map_err(|_| SignalProtocolError::InvalidArgument("device_id muss > 0 sein".to_string()))
}

impl Device {
    /// Erzeugt ein Gerät mit frischem Identitätsschlüssel (in-memory).
    pub fn new(
        user_id: &str,
        device_id: u8,
        registration_id: u32,
    ) -> Result<Self, SignalProtocolError> {
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let address = ProtocolAddress::new(user_id.to_string(), parse_device_id(device_id)?);
        Ok(Self {
            address,
            store: InMemSignalProtocolStore::new(identity, registration_id)?,
            next_prekey_id: 1,
        })
    }

    /// Rekonstruiert ein Gerät aus einem serialisierten Identitäts-
    /// Schlüsselpaar (`identity_keypair_bytes`), in-memory: Sitzungen und
    /// Prekeys sind danach leer. Für erhaltenen Zustand nimmt man
    /// `with_store` mit einer persistenten Ablage.
    pub fn from_identity_bytes(
        user_id: &str,
        device_id: u8,
        registration_id: u32,
        identity_bytes: &[u8],
    ) -> Result<Self, SignalProtocolError> {
        let identity = IdentityKeyPair::try_from(identity_bytes)?;
        let address = ProtocolAddress::new(user_id.to_string(), parse_device_id(device_id)?);
        Ok(Self {
            address,
            store: InMemSignalProtocolStore::new(identity, registration_id)?,
            next_prekey_id: 1,
        })
    }
}

impl<S: ProtocolStoreParts> Device<S> {
    /// Baut ein Gerät über einer beliebigen Protokoll-Ablage. Die Ablage
    /// muss die eigene Identität bereits kennen (`get_identity_key_pair`
    /// liefert sie); `next_prekey_id` ist der gespeicherte Zählerstand,
    /// bei frischer Ablage 1.
    pub fn with_store(
        user_id: &str,
        device_id: u8,
        store: S,
        next_prekey_id: u32,
    ) -> Result<Self, SignalProtocolError> {
        let address = ProtocolAddress::new(user_id.to_string(), parse_device_id(device_id)?);
        Ok(Self {
            address,
            store,
            next_prekey_id,
        })
    }

    pub fn address(&self) -> &ProtocolAddress {
        &self.address
    }

    /// Der aktuelle Prekey-ID-Zähler; bei persistenter Ablage nach jedem
    /// `publish_prekey_bundle` zu sichern.
    pub fn next_prekey_id(&self) -> u32 {
        self.next_prekey_id
    }

    /// Die serialisierte öffentliche libsignal-Identität (33 Bytes mit
    /// Typ-Präfix). Nach ADR-0009 ist sie der Geräteschlüssel im
    /// Geräte-Credential und der `identity_key` des Bündels im Verzeichnis.
    pub async fn identity_public(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
        let (_, identities, _, _, _) = self.store.parts();
        let identity = identities.get_identity_key_pair().await?;
        Ok(identity.identity_key().serialize().into_vec())
    }

    /// Das serialisierte Identitäts-Schlüsselpaar (privater Teil!) für die
    /// Geräte-Ablage. Wer das aufruft, hält den Sitzungs-Vertrauensanker in
    /// der Hand und muss ihn schützen.
    pub async fn identity_keypair_bytes(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
        let (_, identities, _, _, _) = self.store.parts();
        let identity = identities.get_identity_key_pair().await?;
        Ok(identity.serialize().into_vec())
    }

    /// Die libsignal-Registration-ID des Geräts (Teil des Prekey-Bündels).
    pub async fn registration_id(&mut self) -> Result<u32, SignalProtocolError> {
        let (_, identities, _, _, _) = self.store.parts();
        identities.get_local_registration_id().await
    }

    /// Die Sicherheitsnummer (Safety Number) zum Vergleich mit einem
    /// Kontakt: libsignals `Fingerprint` über beide Identitätsschlüssel,
    /// als Ziffernfolge. Sie ist symmetrisch, beide Seiten sehen dieselbe
    /// Nummer; stimmt sie nicht überein, spricht einer der beiden mit
    /// einem fremden Schlüssel. `None`, solange der Kontakt-Schlüssel
    /// nicht in der Ablage liegt (noch keine Sitzung).
    ///
    /// [ANNAHME: Version 2 und 5200 Iterationen wie bei Signal produktiv;
    /// als stabile Kennungen dienen die Handles (Signal nimmt dort
    /// Telefonnummern, die es hier nicht gibt). Kein Eigenbau: die
    /// Konstruktion kommt unverändert aus libsignal.]
    pub async fn safety_number(
        &mut self,
        remote: &ProtocolAddress,
    ) -> Result<Option<String>, SignalProtocolError> {
        let local_name = self.address.name().to_string();
        let (_, identities, _, _, _) = self.store.parts();
        let local = identities.get_identity_key_pair().await?;
        let Some(remote_key) = identities.get_identity(remote).await? else {
            return Ok(None);
        };
        // Der Fingerprint-Fehlertyp kennt keinen Weg nach
        // SignalProtocolError; mit festen, gültigen Parametern (Iterationen
        // im erlaubten Bereich, 64-Byte-Hashes) ist er praktisch
        // unerreichbar, das Mapping hält die Device-API einheitlich.
        let fingerprint_error = |error: libsignal_protocol::FingerprintError| {
            SignalProtocolError::InvalidArgument(format!("Fingerprint: {error}"))
        };
        let fingerprint = Fingerprint::new(
            2,
            5200,
            local_name.as_bytes(),
            local.identity_key(),
            remote.name().as_bytes(),
            &remote_key,
        )
        .map_err(fingerprint_error)?;
        Ok(Some(
            fingerprint.display_string().map_err(fingerprint_error)?,
        ))
    }

    /// Erzeugt einen frischen Prekey-Satz (signiert, Einmal, ML-KEM-1024),
    /// legt die privaten Hälften in der Ablage ab und liefert das
    /// veröffentlichbare Bündel - das, was das Schlüssel-Verzeichnis
    /// (directory) als opake Blobs verteilt.
    pub async fn publish_prekey_bundle(&mut self) -> Result<PreKeyBundle, SignalProtocolError> {
        let mut rng = rand::rng();

        // IDs vor dem Ablage-Borrow ziehen (disjunkte Felder).
        let pre_key_id = self.next_prekey_id.into();
        let signed_pre_key_id = (self.next_prekey_id + 1).into();
        let kyber_pre_key_id = (self.next_prekey_id + 2).into();
        self.next_prekey_id += 3;
        let device_id = self.address.device_id();

        let (_, identities, prekeys, signed_prekeys, kyber_prekeys) = self.store.parts();
        let identity = identities.get_identity_key_pair().await?;

        let pre_key = KeyPair::generate(&mut rng);
        let signed_pre_key = KeyPair::generate(&mut rng);
        let kyber_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

        // Signierte und PQ-Prekeys tragen eine Signatur des
        // Identitätsschlüssels; der Empfänger prüft sie beim
        // Bündel-Verarbeiten (process_prekey_bundle).
        let signed_sig = identity
            .private_key()
            .calculate_signature(&signed_pre_key.public_key.serialize(), &mut rng)?;
        let kyber_sig = identity
            .private_key()
            .calculate_signature(&kyber_pre_key.public_key.serialize(), &mut rng)?;

        prekeys
            .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key))
            .await?;
        signed_prekeys
            .save_signed_pre_key(
                signed_pre_key_id,
                &SignedPreKeyRecord::new(
                    signed_pre_key_id,
                    Timestamp::from_epoch_millis(now_millis()),
                    &signed_pre_key,
                    &signed_sig,
                ),
            )
            .await?;
        kyber_prekeys
            .save_kyber_pre_key(
                kyber_pre_key_id,
                &KyberPreKeyRecord::new(
                    kyber_pre_key_id,
                    Timestamp::from_epoch_millis(now_millis()),
                    &kyber_pre_key,
                    &kyber_sig,
                ),
            )
            .await?;

        PreKeyBundle::new(
            identities.get_local_registration_id().await?,
            device_id,
            Some((pre_key_id, pre_key.public_key)),
            signed_pre_key_id,
            signed_pre_key.public_key,
            signed_sig.into_vec(),
            kyber_pre_key_id,
            kyber_pre_key.public_key.clone(),
            kyber_sig.into_vec(),
            *identity.identity_key(),
        )
    }

    /// Baut die ausgehende Sitzung zu einem fremden Gerät aus dessen
    /// Prekey-Bündel auf (PQXDH; libsignal verifiziert die Signaturen
    /// und lehnt reine X3DH-Bündel ab).
    pub async fn establish_session(
        &mut self,
        remote: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<(), SignalProtocolError> {
        let mut rng = rand::rng();
        let (sessions, identities, _, _, _) = self.store.parts();
        process_prekey_bundle(
            remote,
            &self.address,
            sessions,
            identities,
            bundle,
            now(),
            &mut rng,
        )
        .await
    }

    /// Verschlüsselt an ein Gerät mit bestehender Sitzung. Die erste
    /// Nachricht nach dem Aufbau ist eine PreKey-Nachricht (trägt das
    /// Aufbau-Material mit), danach normale Ratchet-Nachrichten.
    pub async fn encrypt(
        &mut self,
        to: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<CiphertextMessage, SignalProtocolError> {
        let mut rng = rand::rng();
        let (sessions, identities, _, _, _) = self.store.parts();
        message_encrypt(
            plaintext,
            to,
            &self.address,
            sessions,
            identities,
            now(),
            &mut rng,
        )
        .await
    }

    /// Entschlüsselt eine eingehende Nachricht; PreKey-Nachrichten
    /// bauen dabei die Sitzung auf (und verbrauchen den Einmal-Prekey).
    pub async fn decrypt(
        &mut self,
        from: &ProtocolAddress,
        message: &CiphertextMessage,
    ) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = rand::rng();
        let (sessions, identities, prekeys, signed_prekeys, kyber_prekeys) = self.store.parts();
        message_decrypt(
            message,
            from,
            &self.address,
            sessions,
            identities,
            prekeys,
            signed_prekeys,
            kyber_prekeys,
            &mut rng,
        )
        .await
    }
}
