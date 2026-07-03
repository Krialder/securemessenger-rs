//! Übersetzung zwischen libsignals `PreKeyBundle` und den opaken Blobs des
//! Schlüssel-Verzeichnisses (services/directory).
//!
//! Das Verzeichnis speichert Prekeys als `{id: UUID, key: Base64}` und
//! interpretiert die Bytes nie. Was in den Bytes steht, legt allein der
//! Client fest, und genau das passiert hier: ein versioniertes JSON-Format
//! (`smpk.v1`), das die libsignal-IDs, Schlüssel und Signaturen trägt. Keine
//! Kryptografie, nur Kodierung; Schlüssel und Signaturen kommen unverändert
//! aus dem Krypto-Kern und werden dort geprüft (`process_prekey_bundle`
//! verifiziert die Signaturen gegen die Geräte-Identität, ADR-0009).
//!
//! [ANNAHME: JSON-in-Base64 als Blob-Format, weil debugbar und versioniert;
//! ein kompakteres Binärformat lohnt erst, wenn Bündelgröße ein Thema wird.
//! Die libsignal-Gerätenummer ist bis zur Multi-Device-Etappe konstant 1.]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_core::libsignal_protocol::{kem, DeviceId, IdentityKey, PreKeyBundle, PublicKey};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// Die libsignal-Gerätenummer dieses Clients (ProtocolAddress-Teil).
/// Konstant 1, bis die Multi-Device-Etappe je Gerät eine eigene Nummer
/// vergibt; die Blobs tragen die Nummer bereits mit, damit der Wechsel das
/// Format nicht bricht.
pub const PROTOCOL_DEVICE_ID: u32 = 1;

/// Blob des signierten X25519-Prekeys. Trägt zusätzlich die Bündel-weiten
/// Felder (Registration-ID, Gerätenummer), weil er in jedem Bündel genau
/// einmal vorhanden ist.
#[derive(Serialize, Deserialize)]
struct SignedBlob {
    v: String,
    registration_id: u32,
    protocol_device_id: u32,
    id: u32,
    key: String,
    sig: String,
}

/// Blob des signierten ML-KEM-Prekeys (PQXDH-Pflichtteil).
#[derive(Serialize, Deserialize)]
struct PqSignedBlob {
    v: String,
    id: u32,
    key: String,
    sig: String,
}

/// Blob eines Einmal-X25519-Prekeys.
#[derive(Serialize, Deserialize)]
struct OneTimeBlob {
    v: String,
    id: u32,
    key: String,
}

const BLOB_VERSION: &str = "smpk.v1";

/// Ein Prekey, wie das Verzeichnis ihn annimmt und ausliefert:
/// client-erzeugte UUID plus opaker Base64-Blob.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectoryPrekey {
    pub id: String,
    pub key: String,
}

/// Die Blobs eines frisch erzeugten Bündels, fertig für den Upload an
/// `POST /keys/prekeys`.
pub struct PrekeyPublication {
    pub signed_prekey: DirectoryPrekey,
    pub pq_signed_prekey: DirectoryPrekey,
    pub one_time_prekeys: Vec<DirectoryPrekey>,
}

fn protocol(error: impl std::fmt::Display) -> ClientError {
    ClientError::Protocol(error.to_string())
}

fn encode_blob<T: Serialize>(blob: &T) -> Result<String, ClientError> {
    let json = serde_json::to_vec(blob).map_err(protocol)?;
    Ok(BASE64.encode(json))
}

fn decode_blob<T: for<'de> Deserialize<'de>>(blob_b64: &str, kind: &str) -> Result<T, ClientError> {
    let bytes = BASE64
        .decode(blob_b64)
        .map_err(|_| ClientError::Protocol(format!("{kind}-Blob ist kein Base64")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ClientError::Protocol(format!("{kind}-Blob unlesbar: {error}")))
}

/// UUIDv4 aus dem CSPRNG des Ziels, ohne uuid-Crate: die rand-Abhängigkeit
/// ist ohnehin da, und das uuid-Crate bräuchte fürs wasm-Ziel eine eigene
/// Zufalls-Weiche. Öffentlich, weil Clients (Web) sie für Geräte- und
/// Hüllen-IDs brauchen.
pub fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngCore as _;
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Zerlegt ein frisch erzeugtes `PreKeyBundle` (Krypto-Kern,
/// `publish_prekey_bundle`) in die Verzeichnis-Blobs.
pub fn publication_from_bundle(bundle: &PreKeyBundle) -> Result<PrekeyPublication, ClientError> {
    let signed = SignedBlob {
        v: BLOB_VERSION.to_string(),
        registration_id: bundle.registration_id().map_err(protocol)?,
        protocol_device_id: u32::from(bundle.device_id().map_err(protocol)?),
        id: bundle.signed_pre_key_id().map_err(protocol)?.into(),
        key: BASE64.encode(
            bundle
                .signed_pre_key_public()
                .map_err(protocol)?
                .serialize(),
        ),
        sig: BASE64.encode(bundle.signed_pre_key_signature().map_err(protocol)?),
    };
    let pq_signed = PqSignedBlob {
        v: BLOB_VERSION.to_string(),
        id: bundle.kyber_pre_key_id().map_err(protocol)?.into(),
        key: BASE64.encode(bundle.kyber_pre_key_public().map_err(protocol)?.serialize()),
        sig: BASE64.encode(bundle.kyber_pre_key_signature().map_err(protocol)?),
    };
    let one_time = match (
        bundle.pre_key_id().map_err(protocol)?,
        bundle.pre_key_public().map_err(protocol)?,
    ) {
        (Some(id), Some(key)) => vec![OneTimeBlob {
            v: BLOB_VERSION.to_string(),
            id: id.into(),
            key: BASE64.encode(key.serialize()),
        }],
        _ => Vec::new(),
    };

    Ok(PrekeyPublication {
        signed_prekey: DirectoryPrekey {
            id: new_uuid(),
            key: encode_blob(&signed)?,
        },
        pq_signed_prekey: DirectoryPrekey {
            id: new_uuid(),
            key: encode_blob(&pq_signed)?,
        },
        one_time_prekeys: one_time
            .iter()
            .map(|blob| {
                Ok(DirectoryPrekey {
                    id: new_uuid(),
                    key: encode_blob(blob)?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?,
    })
}

/// Ein Geräte-Bündel, wie `GET /keys/{handle}` es liefert (directory-API).
#[derive(Deserialize, Debug, Clone)]
pub struct DeviceBundleJson {
    /// Server-seitige Geräte-ID (UUID); Adressat der Zustellung.
    pub device_id: String,
    /// Serialisierte libsignal-Identität des Geräts, Base64 (ADR-0009).
    pub identity_key: String,
    pub not_after: u64,
    pub signed_prekey: Option<DirectoryPrekey>,
    pub pq_signed_prekey: Option<DirectoryPrekey>,
    pub one_time_prekey: Option<DirectoryPrekey>,
    pub pq_one_time_prekey: Option<DirectoryPrekey>,
}

fn decode_b64(value: &str, kind: &str) -> Result<Vec<u8>, ClientError> {
    BASE64
        .decode(value)
        .map_err(|_| ClientError::Protocol(format!("{kind} ist kein Base64")))
}

/// Baut aus einem Geräte-Bündel des Verzeichnisses das `PreKeyBundle` für
/// den PQXDH-Aufbau. Liefert zusätzlich die libsignal-Gerätenummer aus dem
/// Blob (für die `ProtocolAddress` des Ziels). Die Signaturprüfung passiert
/// nicht hier, sondern in libsignal beim Verarbeiten des Bündels.
pub fn bundle_from_directory(
    device: &DeviceBundleJson,
) -> Result<(PreKeyBundle, u32), ClientError> {
    let signed_raw = device
        .signed_prekey
        .as_ref()
        .ok_or_else(|| ClientError::Protocol("Bündel ohne signierten Prekey".to_string()))?;
    let pq_raw = device.pq_signed_prekey.as_ref().ok_or_else(|| {
        ClientError::Protocol("Bündel ohne PQ-Prekey (PQXDH-Pflicht)".to_string())
    })?;

    let signed: SignedBlob = decode_blob(&signed_raw.key, "signed_prekey")?;
    let pq: PqSignedBlob = decode_blob(&pq_raw.key, "pq_signed_prekey")?;
    for (version, kind) in [(&signed.v, "signed_prekey"), (&pq.v, "pq_signed_prekey")] {
        if version != BLOB_VERSION {
            return Err(ClientError::Protocol(format!(
                "{kind}: unbekannte Blob-Version {version}"
            )));
        }
    }

    let one_time = match &device.one_time_prekey {
        Some(raw) => {
            let blob: OneTimeBlob = decode_blob(&raw.key, "one_time_prekey")?;
            let key = PublicKey::deserialize(&decode_b64(&blob.key, "one_time_prekey")?)
                .map_err(protocol)?;
            Some((blob.id.into(), key))
        }
        None => None,
    };

    let identity_key = IdentityKey::decode(&decode_b64(&device.identity_key, "identity_key")?)
        .map_err(protocol)?;
    let signed_key =
        PublicKey::deserialize(&decode_b64(&signed.key, "signed_prekey")?).map_err(protocol)?;
    let pq_key =
        kem::PublicKey::deserialize(&decode_b64(&pq.key, "pq_signed_prekey")?).map_err(protocol)?;

    let protocol_device_id = signed.protocol_device_id;
    let device_id = device_id_from_u32(protocol_device_id)?;
    let bundle = PreKeyBundle::new(
        signed.registration_id,
        device_id,
        one_time,
        signed.id.into(),
        signed_key,
        decode_b64(&signed.sig, "signed_prekey-Signatur")?,
        pq.id.into(),
        pq_key,
        decode_b64(&pq.sig, "pq_signed_prekey-Signatur")?,
        identity_key,
    )
    .map_err(protocol)?;
    Ok((bundle, protocol_device_id))
}

/// Übersetzt die Blob-Gerätenummer in eine libsignal-`DeviceId`.
pub fn device_id_from_u32(value: u32) -> Result<DeviceId, ClientError> {
    let byte: u8 = value
        .try_into()
        .map_err(|_| ClientError::Protocol(format!("Gerätenummer {value} über 255")))?;
    DeviceId::new(byte).map_err(|error| ClientError::Protocol(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::onetoone::Device;

    /// Roundtrip durch die Blobs: was ein Gerät veröffentlicht, muss nach
    /// Kodierung und Dekodierung wieder ein Bündel ergeben, mit dem eine
    /// echte PQXDH-Sitzung entsteht.
    #[tokio::test]
    async fn blobs_roundtrip_into_working_bundle() {
        let mut alice = Device::new("alice", 1, 100).unwrap();
        let mut bob = Device::new("bob", 1, 200).unwrap();

        let bundle = bob.publish_prekey_bundle().await.unwrap();
        let publication = publication_from_bundle(&bundle).unwrap();
        assert_eq!(publication.one_time_prekeys.len(), 1);

        // So kommt es aus dem Verzeichnis zurück.
        let device_json = DeviceBundleJson {
            device_id: "00000000-0000-4000-8000-000000000000".to_string(),
            identity_key: BASE64.encode(bob.identity_public().await.unwrap()),
            not_after: 2_000_000_000,
            signed_prekey: Some(publication.signed_prekey.clone()),
            pq_signed_prekey: Some(publication.pq_signed_prekey.clone()),
            one_time_prekey: publication.one_time_prekeys.first().cloned(),
            pq_one_time_prekey: None,
        };
        let (rebuilt, protocol_device_id) = bundle_from_directory(&device_json).unwrap();
        assert_eq!(protocol_device_id, 1);

        let bob_address = bob.address().clone();
        let alice_address = alice.address().clone();
        alice
            .establish_session(&bob_address, &rebuilt)
            .await
            .unwrap();
        let message = alice.encrypt(&bob_address, b"blob-beweis").await.unwrap();
        assert_eq!(
            bob.decrypt(&alice_address, &message).await.unwrap(),
            b"blob-beweis"
        );
    }

    #[test]
    fn missing_pq_prekey_is_rejected() {
        let device_json = DeviceBundleJson {
            device_id: "00000000-0000-4000-8000-000000000000".to_string(),
            identity_key: BASE64.encode([5u8; 33]),
            not_after: 2_000_000_000,
            signed_prekey: Some(DirectoryPrekey {
                id: "x".to_string(),
                key: BASE64.encode(b"{}"),
            }),
            pq_signed_prekey: None,
            one_time_prekey: None,
            pq_one_time_prekey: None,
        };
        assert!(matches!(
            bundle_from_directory(&device_json),
            Err(ClientError::Protocol(_))
        ));
    }
}
