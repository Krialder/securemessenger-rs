//! Persistente Protokoll-Ablage: libsignals fünf Store-Traits über dem
//! Storage-Trait (storage.rs).
//!
//! Hier liegt keine Kryptografie, nur Ablage: die Records (Sitzungen,
//! Prekeys, Identitäten) kommen serialisiert aus libsignal und gehen
//! unverändert zurück. Die Semantik spiegelt libsignals
//! In-Memory-Referenz (`InMemSignalProtocolStore`), einschließlich der
//! Trust-on-first-use-Identitätsprüfung und des Basisschlüssel-Gedächtnisses
//! gegen wiederverwendete Kyber-Prekeys.
//!
//! Alle fünf Teil-Ablagen teilen sich eine Ablage über `Rc<RefCell<...>>`:
//! libsignal verlangt die Teile als getrennte `&mut`-Referenzen
//! (client-core `ProtocolStoreParts`), und die Store-Traits sind
//! `async_trait(?Send)`, ein `Rc` genügt also auch im Browser. Kein Borrow
//! lebt über ein `await` hinweg; die Storage-Zugriffe sind synchron.

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use client_core::libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey as _, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use client_core::onetoone::ProtocolStoreParts;

use crate::storage::KeyValueStorage;

type Shared<S> = Rc<RefCell<S>>;
type Result<T> = std::result::Result<T, SignalProtocolError>;

const OWN_IDENTITY_KEY: &str = "own/identity";
const OWN_REGISTRATION_KEY: &str = "own/registration_id";

fn backend(error: String) -> SignalProtocolError {
    SignalProtocolError::InvalidState("protocol_store", error)
}

fn address_key(prefix: &str, address: &ProtocolAddress) -> String {
    format!(
        "{prefix}/{}/{}",
        address.name(),
        u32::from(address.device_id())
    )
}

/// Legt die eigene Identität und Registration-ID in einer frischen Ablage
/// ab; der Schritt gehört zur Registrierung, danach liest
/// `get_identity_key_pair` sie von dort.
pub fn store_own_identity<S: KeyValueStorage>(
    storage: &Shared<S>,
    identity_keypair_bytes: &[u8],
    registration_id: u32,
) -> Result<()> {
    let mut storage = storage.borrow_mut();
    storage
        .put(OWN_IDENTITY_KEY, identity_keypair_bytes)
        .map_err(backend)?;
    storage
        .put(OWN_REGISTRATION_KEY, &registration_id.to_be_bytes())
        .map_err(backend)?;
    Ok(())
}

/// Ob die Ablage schon eine eigene Identität trägt.
pub fn has_own_identity<S: KeyValueStorage>(storage: &Shared<S>) -> Result<bool> {
    Ok(storage
        .borrow()
        .get(OWN_IDENTITY_KEY)
        .map_err(backend)?
        .is_some())
}

/// Identitäts-Ablage: eigene Identität plus bekannte fremde Identitäten
/// (Trust on first use, wie die libsignal-Referenz).
pub struct PersistentIdentityStore<S: KeyValueStorage> {
    storage: Shared<S>,
}

#[async_trait(?Send)]
impl<S: KeyValueStorage> IdentityKeyStore for PersistentIdentityStore<S> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        let bytes = self
            .storage
            .borrow()
            .get(OWN_IDENTITY_KEY)
            .map_err(backend)?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_identity_key_pair",
                    "keine eigene Identität in der Ablage".to_string(),
                )
            })?;
        IdentityKeyPair::try_from(bytes.as_slice())
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        let bytes = self
            .storage
            .borrow()
            .get(OWN_REGISTRATION_KEY)
            .map_err(backend)?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_local_registration_id",
                    "keine Registration-ID in der Ablage".to_string(),
                )
            })?;
        let bytes: [u8; 4] = bytes.try_into().map_err(|_| {
            SignalProtocolError::InvalidState(
                "get_local_registration_id",
                "Registration-ID hat die falsche Länge".to_string(),
            )
        })?;
        Ok(u32::from_be_bytes(bytes))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        let key = address_key("identity", address);
        let previous = self.storage.borrow().get(&key).map_err(backend)?;
        let replaced = match &previous {
            Some(bytes) => bytes.as_slice() != identity.serialize().as_ref(),
            None => false,
        };
        self.storage
            .borrow_mut()
            .put(&key, &identity.serialize())
            .map_err(backend)?;
        Ok(IdentityChange::from_changed(replaced))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool> {
        let known = self
            .storage
            .borrow()
            .get(&address_key("identity", address))
            .map_err(backend)?;
        match known {
            // Trust on first use: eine unbekannte Adresse ist vertrauenswürdig.
            None => Ok(true),
            Some(bytes) => Ok(bytes.as_slice() == identity.serialize().as_ref()),
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        let bytes = self
            .storage
            .borrow()
            .get(&address_key("identity", address))
            .map_err(backend)?;
        match bytes {
            Some(bytes) => Ok(Some(IdentityKey::decode(&bytes)?)),
            None => Ok(None),
        }
    }
}

/// Sitzungs-Ablage: ein `SessionRecord` je Protokoll-Adresse. Hier lebt der
/// Ratchet-Zustand über Prozessgrenzen hinweg.
pub struct PersistentSessionStore<S: KeyValueStorage> {
    storage: Shared<S>,
}

#[async_trait(?Send)]
impl<S: KeyValueStorage> SessionStore for PersistentSessionStore<S> {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let bytes = self
            .storage
            .borrow()
            .get(&address_key("session", address))
            .map_err(backend)?;
        match bytes {
            Some(bytes) => Ok(Some(SessionRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        self.storage
            .borrow_mut()
            .put(&address_key("session", address), &record.serialize()?)
            .map_err(backend)
    }
}

/// Einmal-Prekeys: nach Verbrauch entfernt libsignal den Eintrag.
pub struct PersistentPreKeyStore<S: KeyValueStorage> {
    storage: Shared<S>,
}

#[async_trait(?Send)]
impl<S: KeyValueStorage> PreKeyStore for PersistentPreKeyStore<S> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        let bytes = self
            .storage
            .borrow()
            .get(&format!("prekey/{}", u32::from(prekey_id)))
            .map_err(backend)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.storage
            .borrow_mut()
            .put(
                &format!("prekey/{}", u32::from(prekey_id)),
                &record.serialize()?,
            )
            .map_err(backend)
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        self.storage
            .borrow_mut()
            .remove(&format!("prekey/{}", u32::from(prekey_id)))
            .map_err(backend)
    }
}

/// Signierte Prekeys; bleiben bis zur Rotation erhalten.
pub struct PersistentSignedPreKeyStore<S: KeyValueStorage> {
    storage: Shared<S>,
}

#[async_trait(?Send)]
impl<S: KeyValueStorage> SignedPreKeyStore for PersistentSignedPreKeyStore<S> {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        let bytes = self
            .storage
            .borrow()
            .get(&format!("signed-prekey/{}", u32::from(id)))
            .map_err(backend)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.storage
            .borrow_mut()
            .put(
                &format!("signed-prekey/{}", u32::from(id)),
                &record.serialize()?,
            )
            .map_err(backend)
    }
}

/// ML-KEM-Prekeys samt Basisschlüssel-Gedächtnis: dieselbe Kombination aus
/// Kyber- und EC-Prekey darf nie zweimal mit demselben Basisschlüssel
/// verarbeitet werden (Replay-Schutz der Referenz-Umsetzung).
pub struct PersistentKyberPreKeyStore<S: KeyValueStorage> {
    storage: Shared<S>,
}

#[async_trait(?Send)]
impl<S: KeyValueStorage> KyberPreKeyStore for PersistentKyberPreKeyStore<S> {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        let bytes = self
            .storage
            .borrow()
            .get(&format!("kyber-prekey/{}", u32::from(id)))
            .map_err(backend)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.storage
            .borrow_mut()
            .put(
                &format!("kyber-prekey/{}", u32::from(id)),
                &record.serialize()?,
            )
            .map_err(backend)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        let key = format!(
            "kyber-seen/{}/{}",
            u32::from(kyber_prekey_id),
            u32::from(ec_prekey_id)
        );
        let mut seen: Vec<Vec<u8>> = match self.storage.borrow().get(&key).map_err(backend)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                SignalProtocolError::InvalidState(
                    "mark_kyber_pre_key_used",
                    format!("Basisschlüssel-Liste unlesbar: {error}"),
                )
            })?,
            None => Vec::new(),
        };
        let base = base_key.serialize().to_vec();
        if seen.contains(&base) {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".to_owned(),
            ));
        }
        seen.push(base);
        let json = serde_json::to_vec(&seen).map_err(|error| {
            SignalProtocolError::InvalidState(
                "mark_kyber_pre_key_used",
                format!("Basisschlüssel-Liste nicht serialisierbar: {error}"),
            )
        })?;
        self.storage.borrow_mut().put(&key, &json).map_err(backend)
    }
}

/// Die fünf Teil-Ablagen über einer gemeinsamen Storage-Instanz, passend
/// zum `ProtocolStoreParts`-Zuschnitt des Krypto-Kerns.
pub struct PersistentProtocolStore<S: KeyValueStorage> {
    sessions: PersistentSessionStore<S>,
    identities: PersistentIdentityStore<S>,
    prekeys: PersistentPreKeyStore<S>,
    signed_prekeys: PersistentSignedPreKeyStore<S>,
    kyber_prekeys: PersistentKyberPreKeyStore<S>,
}

impl<S: KeyValueStorage> PersistentProtocolStore<S> {
    /// Öffnet die Protokoll-Ablage. Die eigene Identität muss bereits
    /// abgelegt sein (`store_own_identity`), sonst scheitert später jeder
    /// Protokoll-Schritt.
    pub fn open(storage: Shared<S>) -> Self {
        Self {
            sessions: PersistentSessionStore {
                storage: storage.clone(),
            },
            identities: PersistentIdentityStore {
                storage: storage.clone(),
            },
            prekeys: PersistentPreKeyStore {
                storage: storage.clone(),
            },
            signed_prekeys: PersistentSignedPreKeyStore {
                storage: storage.clone(),
            },
            kyber_prekeys: PersistentKyberPreKeyStore { storage },
        }
    }
}

impl<S: KeyValueStorage> ProtocolStoreParts for PersistentProtocolStore<S> {
    type Sessions = PersistentSessionStore<S>;
    type Identities = PersistentIdentityStore<S>;
    type PreKeys = PersistentPreKeyStore<S>;
    type SignedPreKeys = PersistentSignedPreKeyStore<S>;
    type KyberPreKeys = PersistentKyberPreKeyStore<S>;

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
            &mut self.sessions,
            &mut self.identities,
            &mut self.prekeys,
            &mut self.signed_prekeys,
            &mut self.kyber_prekeys,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;
    use client_core::onetoone::Device;

    fn shared() -> Shared<InMemoryStorage> {
        Rc::new(RefCell::new(InMemoryStorage::default()))
    }

    /// Der Kern-Beweis der Persistenz: eine Sitzung wird über einer Ablage
    /// aufgebaut, das Gerät verworfen und aus derselben Ablage neu
    /// erstellt; der Ratchet läuft nahtlos weiter (die zweite Nachricht
    /// ist eine normale Ratchet-Nachricht, kein zweiter Aufbau).
    #[tokio::test]
    async fn session_survives_device_reconstruction() {
        use client_core::libsignal_protocol::CiphertextMessage;

        let alice_storage = shared();
        let bob_storage = shared();
        let mut rng = rand::rng();
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        store_own_identity(&alice_storage, &alice_identity.serialize(), 11).unwrap();
        store_own_identity(&bob_storage, &bob_identity.serialize(), 22).unwrap();

        let mut alice = Device::with_store(
            "alice",
            1,
            PersistentProtocolStore::open(alice_storage.clone()),
            1,
        )
        .unwrap();
        let mut bob = Device::with_store(
            "bob",
            1,
            PersistentProtocolStore::open(bob_storage.clone()),
            1,
        )
        .unwrap();

        let bundle = bob.publish_prekey_bundle().await.unwrap();
        let alice_next = alice.next_prekey_id();
        let bob_next = bob.next_prekey_id();
        let alice_address = alice.address().clone();
        let bob_address = bob.address().clone();

        alice
            .establish_session(&bob_address, &bundle)
            .await
            .unwrap();
        let first = alice.encrypt(&bob_address, b"nachricht 1").await.unwrap();
        assert!(matches!(first, CiphertextMessage::PreKeySignalMessage(_)));
        assert_eq!(
            bob.decrypt(&alice_address, &first).await.unwrap(),
            b"nachricht 1"
        );
        // Rückweg vor dem Neuladen: erst mit Bobs Antwort gilt Alices
        // Sitzung als bestätigt; bis dahin blieben ihre Nachrichten
        // protokollgemäß Aufbau-Nachrichten (unacknowledged PreKey-Zustand).
        let ack = bob.encrypt(&alice_address, b"angekommen").await.unwrap();
        assert_eq!(
            alice.decrypt(&bob_address, &ack).await.unwrap(),
            b"angekommen"
        );

        // Beide Geräte verwerfen und aus den Ablagen neu erstellen.
        drop(alice);
        drop(bob);
        let mut alice = Device::with_store(
            "alice",
            1,
            PersistentProtocolStore::open(alice_storage),
            alice_next,
        )
        .unwrap();
        let mut bob = Device::with_store(
            "bob",
            1,
            PersistentProtocolStore::open(bob_storage),
            bob_next,
        )
        .unwrap();

        // Kein neuer Bündel-Abruf: die Sitzung kommt aus der Ablage, die
        // Folgenachricht ist eine normale Ratchet-Nachricht.
        let second = alice.encrypt(&bob_address, b"nachricht 2").await.unwrap();
        assert!(
            matches!(second, CiphertextMessage::SignalMessage(_)),
            "nach dem Neuladen muss die bestätigte Sitzung weiterlaufen"
        );
        assert_eq!(
            bob.decrypt(&alice_address, &second).await.unwrap(),
            b"nachricht 2"
        );

        // Und die Gegenrichtung über die wiederhergestellte Sitzung.
        let reply = bob.encrypt(&alice_address, b"antwort").await.unwrap();
        assert_eq!(
            alice.decrypt(&bob_address, &reply).await.unwrap(),
            b"antwort"
        );
    }

    /// Ein verbrauchter Einmal-Prekey ist auch nach dem Neuladen weg: die
    /// Wiederholung derselben PreKey-Nachricht scheitert.
    #[tokio::test]
    async fn consumed_prekey_stays_consumed_after_reload() {
        let bob_storage = shared();
        let mut rng = rand::rng();
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        store_own_identity(&bob_storage, &bob_identity.serialize(), 22).unwrap();

        let mut alice = Device::new("alice", 1, 11).unwrap();
        let mut bob = Device::with_store(
            "bob",
            1,
            PersistentProtocolStore::open(bob_storage.clone()),
            1,
        )
        .unwrap();

        let bundle = bob.publish_prekey_bundle().await.unwrap();
        let bob_next = bob.next_prekey_id();
        let alice_address = alice.address().clone();
        let bob_address = bob.address().clone();
        alice
            .establish_session(&bob_address, &bundle)
            .await
            .unwrap();
        let first = alice.encrypt(&bob_address, b"hallo").await.unwrap();
        bob.decrypt(&alice_address, &first).await.unwrap();

        drop(bob);
        let mut bob = Device::with_store(
            "bob",
            1,
            PersistentProtocolStore::open(bob_storage),
            bob_next,
        )
        .unwrap();
        // Replay derselben Aufbau-Nachricht gegen den neu geladenen Bob:
        // muss scheitern, weil der Einmal-Prekey verbraucht und entfernt ist
        // beziehungsweise der Basisschlüssel als gesehen gilt.
        assert!(bob.decrypt(&alice_address, &first).await.is_err());
    }
}
