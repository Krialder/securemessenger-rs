//! Wire-Framing der Nachrichtenhüllen: was in der `envelope`-Spalte der
//! Zustellung tatsächlich steht.
//!
//! Die Zustellung (services/delivery) speichert Hüllen als opake
//! Base64-Blobs. Dieses Modul legt deren Inhalt fest: ein versioniertes
//! JSON-Framing (`smenv.v1`) um den serialisierten libsignal-Chiffretext.
//! Keine Kryptografie, nur Rahmung; der Chiffretext kommt unverändert aus
//! dem Krypto-Kern.
//!
//! [ANNAHME: Bis zur Sealed-Sender-Etappe trägt das Framing Absender-Handle
//! und -Gerätenummer im Klartext, denn der Empfänger braucht die
//! Absenderadresse für die Session-Zuordnung (`message_decrypt`). Das ist
//! Metadaten-Sichtbarkeit gegenüber dem Server: er könnte die Blobs parsen,
//! und anders als beim Bearer-Token liegt der Absender damit bis zum Ack in
//! der Ablage. Genau diese Lücke schließt Sealed Sender
//! (specs/sealed-sender-und-abuse.md); sie ist hier bewusst und sichtbar,
//! nicht versteckt.]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_core::libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, PreKeySignalMessage, SignalMessage,
};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

const WIRE_VERSION: &str = "smenv.v1";
const GROUP_WIRE_VERSION: &str = "smgrp.v1";

#[derive(Serialize, Deserialize)]
struct WireEnvelope {
    v: String,
    /// Absender-Handle (Klartext bis Sealed Sender, siehe Modul-Kommentar).
    from: String,
    /// libsignal-Gerätenummer des Absenders (ProtocolAddress-Teil).
    from_device: u32,
    /// libsignal-Nachrichtentyp (PreKey- oder Ratchet-Nachricht).
    msg_type: u8,
    /// Der serialisierte Chiffretext.
    ciphertext: String,
}

/// Eine geöffnete Hülle: Absenderadresse plus Chiffretext, bereit für
/// `Device::decrypt`.
pub struct OpenedEnvelope {
    pub from: String,
    pub from_device: u32,
    pub message: CiphertextMessage,
}

/// Rahmt einen Chiffretext als Hülle für `POST /messages` (Base64).
pub fn seal(
    from: &str,
    from_device: u32,
    message: &CiphertextMessage,
) -> Result<String, ClientError> {
    let envelope = WireEnvelope {
        v: WIRE_VERSION.to_string(),
        from: from.to_string(),
        from_device,
        msg_type: message.message_type() as u8,
        ciphertext: BASE64.encode(message.serialize()),
    };
    let json =
        serde_json::to_vec(&envelope).map_err(|error| ClientError::Protocol(error.to_string()))?;
    Ok(BASE64.encode(json))
}

/// Öffnet eine Hülle aus `GET /messages`. Nur die 1:1-Typen (PreKey- und
/// Ratchet-Nachricht) sind bekannt; alles andere ist in dieser Etappe ein
/// Protokollfehler.
pub fn open(envelope_b64: &str) -> Result<OpenedEnvelope, ClientError> {
    let json = BASE64
        .decode(envelope_b64)
        .map_err(|_| ClientError::Protocol("Hülle ist kein Base64".to_string()))?;
    let envelope: WireEnvelope = serde_json::from_slice(&json)
        .map_err(|error| ClientError::Protocol(format!("Hülle unlesbar: {error}")))?;
    if envelope.v != WIRE_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Hüllen-Version {}",
            envelope.v
        )));
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| ClientError::Protocol("Chiffretext ist kein Base64".to_string()))?;

    let message = match envelope.msg_type {
        t if t == CiphertextMessageType::PreKey as u8 => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext.as_slice())
                .map_err(|error| ClientError::Protocol(error.to_string()))?,
        ),
        t if t == CiphertextMessageType::Whisper as u8 => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext.as_slice())
                .map_err(|error| ClientError::Protocol(error.to_string()))?,
        ),
        other => {
            return Err(ClientError::Protocol(format!(
                "unbekannter Nachrichtentyp {other}"
            )))
        }
    };
    Ok(OpenedEnvelope {
        from: envelope.from,
        from_device: envelope.from_device,
        message,
    })
}

/// Framing der Gruppen-Blobs (`smgrp.v1`): der Server-Posteingang mischt
/// 1:1- und Gruppen-Hüllen, deshalb trägt die Gruppen-Hülle die Gruppen-ID
/// (zur Routung an die richtige `GroupSession`) und den opaken MLS-Blob.
/// Der MLS-Blob ist selbstbeschreibend (Welcome, Commit oder
/// Anwendungsnachricht); ein Absender steht nicht darin, MLS schützt das.
#[derive(Serialize, Deserialize)]
struct GroupEnvelope {
    v: String,
    group_id: String,
    blob: String,
}

/// Eine geöffnete Gruppen-Hülle: Gruppen-ID plus MLS-Blob für
/// `GroupSession::process`.
pub struct OpenedGroupEnvelope {
    pub group_id: String,
    pub blob: Vec<u8>,
}

/// Rahmt einen MLS-Blob (Welcome, Commit oder Nachricht) als Gruppen-Hülle.
pub fn seal_group(group_id: &str, blob: &[u8]) -> Result<String, ClientError> {
    let envelope = GroupEnvelope {
        v: GROUP_WIRE_VERSION.to_string(),
        group_id: group_id.to_string(),
        blob: BASE64.encode(blob),
    };
    let json =
        serde_json::to_vec(&envelope).map_err(|error| ClientError::Protocol(error.to_string()))?;
    Ok(BASE64.encode(json))
}

/// Welche Art Hülle im Posteingang liegt, ohne sie voll zu öffnen: der
/// Client routet 1:1-Hüllen an den Ratchet, Gruppen-Hüllen an die
/// passende MLS-Sitzung.
pub enum Framed {
    OneToOne,
    Group,
    Unknown,
}

/// Klassifiziert eine Hülle nach ihrer Version, ohne den Inhalt zu prüfen.
pub fn classify(envelope_b64: &str) -> Framed {
    let Ok(json) = BASE64.decode(envelope_b64) else {
        return Framed::Unknown;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&json) else {
        return Framed::Unknown;
    };
    match value.get("v").and_then(|v| v.as_str()) {
        Some(WIRE_VERSION) => Framed::OneToOne,
        Some(GROUP_WIRE_VERSION) => Framed::Group,
        _ => Framed::Unknown,
    }
}

/// Öffnet eine Gruppen-Hülle (`smgrp.v1`).
pub fn open_group(envelope_b64: &str) -> Result<OpenedGroupEnvelope, ClientError> {
    let json = BASE64
        .decode(envelope_b64)
        .map_err(|_| ClientError::Protocol("Gruppen-Hülle ist kein Base64".to_string()))?;
    let envelope: GroupEnvelope = serde_json::from_slice(&json)
        .map_err(|error| ClientError::Protocol(format!("Gruppen-Hülle unlesbar: {error}")))?;
    if envelope.v != GROUP_WIRE_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Gruppen-Hüllen-Version {}",
            envelope.v
        )));
    }
    let blob = BASE64
        .decode(&envelope.blob)
        .map_err(|_| ClientError::Protocol("MLS-Blob ist kein Base64".to_string()))?;
    Ok(OpenedGroupEnvelope {
        group_id: envelope.group_id,
        blob,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::onetoone::Device;

    /// Framing-Roundtrip mit echtem Chiffretext: sealen, öffnen,
    /// entschlüsseln.
    #[tokio::test]
    async fn seal_open_roundtrip() {
        let mut alice = Device::new("alice", 1, 10).unwrap();
        let mut bob = Device::new("bob", 1, 20).unwrap();
        let bundle = bob.publish_prekey_bundle().await.unwrap();
        let bob_address = bob.address().clone();
        let alice_address = alice.address().clone();
        alice
            .establish_session(&bob_address, &bundle)
            .await
            .unwrap();
        let message = alice.encrypt(&bob_address, b"wire-beweis").await.unwrap();

        let sealed = seal("alice", 1, &message).unwrap();
        let opened = open(&sealed).unwrap();
        assert_eq!(opened.from, "alice");
        assert_eq!(opened.from_device, 1);
        assert_eq!(
            bob.decrypt(&alice_address, &opened.message).await.unwrap(),
            b"wire-beweis"
        );
    }

    #[test]
    fn rejects_unknown_version_and_type() {
        let bogus = BASE64.encode(
            serde_json::to_vec(&WireEnvelope {
                v: "smenv.v9".to_string(),
                from: "x".to_string(),
                from_device: 1,
                msg_type: 2,
                ciphertext: BASE64.encode(b"x"),
            })
            .unwrap(),
        );
        assert!(matches!(open(&bogus), Err(ClientError::Protocol(_))));

        let bad_type = BASE64.encode(
            serde_json::to_vec(&WireEnvelope {
                v: WIRE_VERSION.to_string(),
                from: "x".to_string(),
                from_device: 1,
                msg_type: 99,
                ciphertext: BASE64.encode(b"x"),
            })
            .unwrap(),
        );
        assert!(matches!(open(&bad_type), Err(ClientError::Protocol(_))));
    }
}
