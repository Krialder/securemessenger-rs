//! Wire-Framing der Nachrichtenhüllen: was in der `envelope`-Spalte der
//! Zustellung tatsächlich steht.
//!
//! Die Zustellung (services/delivery) speichert Hüllen als opake
//! Base64-Blobs. Dieses Modul legt deren Inhalt fest: ein versioniertes
//! JSON-Framing (`smenv.v1`) um den serialisierten libsignal-Chiffretext.
//! Keine Kryptografie, nur Rahmung; der Chiffretext kommt unverändert aus
//! dem Krypto-Kern.
//!
//! Zwei 1:1-Framings existieren nebeneinander: `smenv.v1` trägt
//! Absender-Handle und -Gerätenummer im Klartext (der Empfänger braucht die
//! Absenderadresse für die Session-Zuordnung, `message_decrypt`), `smssl.v1`
//! trägt nur den versiegelten Blob, in dem der Absender mitverschlüsselt
//! steckt (Sealed Sender, specs/sealed-sender-und-abuse.md). Der Absender
//! wählt beim Senden; der Empfänger routet über `classify`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_core::libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, PreKeySignalMessage, SignalMessage,
};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

const WIRE_VERSION: &str = "smenv.v1";
const GROUP_WIRE_VERSION: &str = "smgrp.v1";
const SEALED_WIRE_VERSION: &str = "smssl.v1";

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
    /// Nur auf der Welcome-Hülle einer Einladung: der Gruppenname und der
    /// Handle des Einladenden, damit der Eingeladene sie VOR dem Beitritt
    /// sieht (er ist noch kein Mitglied und kann /meta nicht abfragen). Der
    /// Einladende bezeugt sie; auf Commit-/Anwendungshüllen fehlen sie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inviter: Option<String>,
}

/// Eine geöffnete Gruppen-Hülle: Gruppen-ID plus MLS-Blob für
/// `GroupSession::process`, dazu die Einladungs-Metadaten (nur bei einer
/// Welcome-Hülle gesetzt).
pub struct OpenedGroupEnvelope {
    pub group_id: String,
    pub blob: Vec<u8>,
    pub name: Option<String>,
    pub inviter: Option<String>,
}

/// Rahmt einen MLS-Blob (Commit oder Nachricht) als Gruppen-Hülle.
pub fn seal_group(group_id: &str, blob: &[u8]) -> Result<String, ClientError> {
    seal_group_envelope(group_id, blob, None, None)
}

/// Rahmt eine Welcome-Hülle einer Einladung mit Gruppenname und Einlader.
pub fn seal_group_invite(
    group_id: &str,
    blob: &[u8],
    name: &str,
    inviter: &str,
) -> Result<String, ClientError> {
    seal_group_envelope(
        group_id,
        blob,
        Some(name.to_string()),
        Some(inviter.to_string()),
    )
}

fn seal_group_envelope(
    group_id: &str,
    blob: &[u8],
    name: Option<String>,
    inviter: Option<String>,
) -> Result<String, ClientError> {
    let envelope = GroupEnvelope {
        v: GROUP_WIRE_VERSION.to_string(),
        group_id: group_id.to_string(),
        blob: BASE64.encode(blob),
        name,
        inviter,
    };
    let json =
        serde_json::to_vec(&envelope).map_err(|error| ClientError::Protocol(error.to_string()))?;
    Ok(BASE64.encode(json))
}

/// Framing der Sealed-Sender-Hüllen (`smssl.v1`): nur Version und der
/// versiegelte Blob. Anders als `smenv.v1` steht hier kein Absender, das
/// ist der Punkt der Übung; er steckt mitverschlüsselt im Blob und kommt
/// erst bei `Device::unseal_message` heraus.
#[derive(Serialize, Deserialize)]
struct SealedEnvelope {
    v: String,
    blob: String,
}

/// Rahmt einen versiegelten Blob (aus `Device::seal_message`) als Hülle.
pub fn seal_sealed(blob: &[u8]) -> Result<String, ClientError> {
    let envelope = SealedEnvelope {
        v: SEALED_WIRE_VERSION.to_string(),
        blob: BASE64.encode(blob),
    };
    let json =
        serde_json::to_vec(&envelope).map_err(|error| ClientError::Protocol(error.to_string()))?;
    Ok(BASE64.encode(json))
}

/// Öffnet das Framing einer Sealed-Sender-Hülle; zurück kommt der noch
/// versiegelte Blob für `Device::unseal_message`.
pub fn open_sealed(envelope_b64: &str) -> Result<Vec<u8>, ClientError> {
    let json = BASE64
        .decode(envelope_b64)
        .map_err(|_| ClientError::Protocol("Sealed-Hülle ist kein Base64".to_string()))?;
    let envelope: SealedEnvelope = serde_json::from_slice(&json)
        .map_err(|error| ClientError::Protocol(format!("Sealed-Hülle unlesbar: {error}")))?;
    if envelope.v != SEALED_WIRE_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Sealed-Hüllen-Version {}",
            envelope.v
        )));
    }
    BASE64
        .decode(&envelope.blob)
        .map_err(|_| ClientError::Protocol("versiegelter Blob ist kein Base64".to_string()))
}

/// Welche Art Hülle im Posteingang liegt, ohne sie voll zu öffnen: der
/// Client routet 1:1-Hüllen an den Ratchet, Gruppen-Hüllen an die
/// passende MLS-Sitzung und Sealed-Hüllen an das Entsiegeln.
pub enum Framed {
    OneToOne,
    Group,
    Sealed,
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
        Some(SEALED_WIRE_VERSION) => Framed::Sealed,
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
        name: envelope.name,
        inviter: envelope.inviter,
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
