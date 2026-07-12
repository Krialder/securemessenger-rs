//! Nutzlast-Format der Gruppen-Anwendungsnachrichten (smgpl.v1).
//!
//! MLS liefert der Empfangsseite nur einen opaken Klartext plus die
//! geprüfte Absender-Identität. Dieses kleine versionierte JSON darüber
//! unterscheidet, WAS der Klartext ist: ein Text fürs Gespräch oder der
//! Geräte-Roster der Gruppe. Der Roster ist nötig, weil der Zustelldienst
//! keine GET-Route für die Gerätemenge einer Gruppe hat (bewusst dünner
//! Server) und ein Beigetretener sonst nicht wüsste, an welche Geräte er
//! seine Hüllen adressieren soll: der Gründer schickt die Liste als erste
//! Anwendungsnachricht in die Gruppe, Ende-zu-Ende verschlüsselt wie
//! alles andere. Die Mitglieder-IDENTITÄTEN kommen dagegen aus dem
//! MLS-Ratchet-Tree (`member_identities`), nicht aus dem Roster; der
//! Roster liefert nur die Server-Geräte-IDs fürs Adressieren.

use serde::{Deserialize, Serialize};

use crate::error::ClientError;

const GROUP_PAYLOAD_VERSION: &str = "smgpl.v1";

#[derive(Serialize, Deserialize)]
struct PayloadBlob {
    v: String,
    kind: String,
    /// text: der Gesprächs-Klartext (bei roster leer).
    #[serde(default)]
    text: String,
    /// roster: die Zielgeräte der Gruppe (bei text leer).
    #[serde(default)]
    devices: Vec<RosterDevice>,
}

/// Ein Zielgerät der Gruppe: Handle des Halters plus die Server-Geräte-ID,
/// an die Hüllen adressiert werden.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RosterDevice {
    pub handle: String,
    pub device_id: String,
}

/// Der entschlüsselte Inhalt einer Gruppen-Anwendungsnachricht.
pub enum GroupPayload {
    /// Ein Gesprächstext.
    Text { text: String },
    /// Der Geräte-Roster der Gruppe (vom Gründer bzw. letzten Committer).
    Roster { devices: Vec<RosterDevice> },
}

/// Baut den Klartext-Payload eines Gesprächstexts (wird anschließend von
/// MLS verschlüsselt).
pub fn encode_text(text: &str) -> Vec<u8> {
    let blob = PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "text".to_string(),
        text: text.to_string(),
        devices: Vec::new(),
    };
    serde_json::to_vec(&blob).expect("PayloadBlob ist immer serialisierbar")
}

/// Baut den Klartext-Payload des Geräte-Rosters.
pub fn encode_roster(devices: &[RosterDevice]) -> Vec<u8> {
    let blob = PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "roster".to_string(),
        text: String::new(),
        devices: devices.to_vec(),
    };
    serde_json::to_vec(&blob).expect("PayloadBlob ist immer serialisierbar")
}

/// Liest den Inhalt eines entschlüsselten Gruppen-Payloads.
pub fn decode(payload: &[u8]) -> Result<GroupPayload, ClientError> {
    let blob: PayloadBlob = serde_json::from_slice(payload)
        .map_err(|error| ClientError::Protocol(format!("Gruppen-Payload unlesbar: {error}")))?;
    if blob.v != GROUP_PAYLOAD_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Gruppen-Payload-Version {}",
            blob.v
        )));
    }
    match blob.kind.as_str() {
        "text" => Ok(GroupPayload::Text { text: blob.text }),
        "roster" => Ok(GroupPayload::Roster {
            devices: blob.devices,
        }),
        other => Err(ClientError::Protocol(format!(
            "unbekannter Gruppen-Payload-Typ {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip() {
        match decode(&encode_text("hallo gruppe ä")).unwrap() {
            GroupPayload::Text { text } => assert_eq!(text, "hallo gruppe ä"),
            GroupPayload::Roster { .. } => panic!("text erwartet"),
        }
    }

    #[test]
    fn roster_roundtrip() {
        let devices = vec![
            RosterDevice {
                handle: "bob".to_string(),
                device_id: "d-1".to_string(),
            },
            RosterDevice {
                handle: "carol".to_string(),
                device_id: "d-2".to_string(),
            },
        ];
        match decode(&encode_roster(&devices)).unwrap() {
            GroupPayload::Roster { devices: got } => assert_eq!(got, devices),
            GroupPayload::Text { .. } => panic!("roster erwartet"),
        }
    }

    #[test]
    fn rejects_foreign_and_wrong_version() {
        assert!(decode(b"kein json").is_err());
        let wrong = serde_json::json!({ "v": "smgpl.v9", "kind": "text", "text": "x" });
        assert!(decode(&serde_json::to_vec(&wrong).unwrap()).is_err());
        let unknown = serde_json::json!({ "v": "smgpl.v1", "kind": "poll", "text": "" });
        assert!(decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}
