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
    /// text: die vom Absender vergebene Nachrichten-ID, damit ein späteres
    /// edit/delete sie treffen kann (bei alten Payloads ohne Feld leer).
    #[serde(default)]
    id: String,
    /// edit/delete: die ID der betroffenen Nachricht (sonst leer).
    #[serde(default)]
    target: String,
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
    /// Ein Gesprächstext mit seiner Nachrichten-ID (bei alten Payloads
    /// ohne ID leer, dann nicht bearbeitbar).
    Text { id: String, text: String },
    /// Der Absender ersetzt den Text der Nachricht `target`.
    Edit { target: String, text: String },
    /// Der Absender löscht die Nachricht `target` bei allen.
    Delete { target: String },
    /// Der Geräte-Roster der Gruppe (vom Gründer bzw. letzten Committer).
    Roster { devices: Vec<RosterDevice> },
    /// Die Ansage des Absenders, dass er die Gruppe verlässt. Nur eine
    /// Information: kryptografisch entfernt ihn erst der Remove-Commit
    /// eines verbleibenden Mitglieds (RFC 9420 verbietet den Commit der
    /// eigenen Entfernung).
    Leave,
}

/// Baut den Klartext-Payload eines Gesprächstexts mit ID (wird anschließend
/// von MLS verschlüsselt).
pub fn encode_text(id: &str, text: &str) -> Vec<u8> {
    to_bytes(PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "text".to_string(),
        text: text.to_string(),
        devices: Vec::new(),
        id: id.to_string(),
        target: String::new(),
    })
}

/// Baut den Payload einer Bearbeitung: neuer Text für Nachricht `target`.
pub fn encode_edit(target: &str, text: &str) -> Vec<u8> {
    to_bytes(PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "edit".to_string(),
        text: text.to_string(),
        devices: Vec::new(),
        id: String::new(),
        target: target.to_string(),
    })
}

/// Baut den Payload einer Löschung bei allen für Nachricht `target`.
pub fn encode_delete(target: &str) -> Vec<u8> {
    to_bytes(PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "delete".to_string(),
        text: String::new(),
        devices: Vec::new(),
        id: String::new(),
        target: target.to_string(),
    })
}

/// Baut den Klartext-Payload des Geräte-Rosters.
pub fn encode_roster(devices: &[RosterDevice]) -> Vec<u8> {
    to_bytes(PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "roster".to_string(),
        text: String::new(),
        devices: devices.to_vec(),
        id: String::new(),
        target: String::new(),
    })
}

/// Baut den Klartext-Payload der Verlassen-Ansage.
pub fn encode_leave() -> Vec<u8> {
    to_bytes(PayloadBlob {
        v: GROUP_PAYLOAD_VERSION.to_string(),
        kind: "leave".to_string(),
        text: String::new(),
        devices: Vec::new(),
        id: String::new(),
        target: String::new(),
    })
}

fn to_bytes(blob: PayloadBlob) -> Vec<u8> {
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
        "text" => Ok(GroupPayload::Text {
            id: blob.id,
            text: blob.text,
        }),
        "edit" => Ok(GroupPayload::Edit {
            target: blob.target,
            text: blob.text,
        }),
        "delete" => Ok(GroupPayload::Delete {
            target: blob.target,
        }),
        "roster" => Ok(GroupPayload::Roster {
            devices: blob.devices,
        }),
        "leave" => Ok(GroupPayload::Leave),
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
        match decode(&encode_text("g-1", "hallo gruppe ä")).unwrap() {
            GroupPayload::Text { id, text } => {
                assert_eq!(id, "g-1");
                assert_eq!(text, "hallo gruppe ä");
            }
            _ => panic!("text erwartet"),
        }
    }

    #[test]
    fn edit_roundtrip() {
        match decode(&encode_edit("g-1", "korrigiert ö")).unwrap() {
            GroupPayload::Edit { target, text } => {
                assert_eq!(target, "g-1");
                assert_eq!(text, "korrigiert ö");
            }
            _ => panic!("edit erwartet"),
        }
    }

    #[test]
    fn delete_roundtrip() {
        match decode(&encode_delete("g-1")).unwrap() {
            GroupPayload::Delete { target } => assert_eq!(target, "g-1"),
            _ => panic!("delete erwartet"),
        }
    }

    /// Ein Text-Payload aus der Zeit vor dem id-Feld bleibt lesbar (leere ID).
    #[test]
    fn old_text_without_id_is_readable() {
        let old = serde_json::json!({ "v": "smgpl.v1", "kind": "text", "text": "alt" });
        match decode(&serde_json::to_vec(&old).unwrap()).unwrap() {
            GroupPayload::Text { id, text } => {
                assert!(id.is_empty());
                assert_eq!(text, "alt");
            }
            _ => panic!("text erwartet"),
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
            _ => panic!("roster erwartet"),
        }
    }

    #[test]
    fn leave_roundtrip() {
        assert!(matches!(
            decode(&encode_leave()).unwrap(),
            GroupPayload::Leave
        ));
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
