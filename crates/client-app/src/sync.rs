//! Self-Sync: eine Kopie einer gesendeten Nachricht an die eigenen
//! Zweitgeräte, damit der Verlauf auf allen Geräten des Absenders steht.
//!
//! Der Empfänger-Fanout (eine Hülle je Zielgerät) sorgt schon dafür, dass
//! ein EINGEHENDER Text auf allen Geräten des Empfängers ankommt. Was fehlt,
//! ist der AUSGEHENDE Text: sendet Gerät 1, weiß Gerät 2 nichts davon. Diese
//! Lücke schließt der Self-Sync: der Absender verschlüsselt den Text ein
//! zweites Mal an seine eigenen anderen Geräte.
//!
//! Die Kopie reist als gewöhnliche 1:1-Hülle (`wire::smenv.v1`) von mir an
//! mein anderes Gerät; erkennbar allein am Absender (das eigene Handle:
//! man schreibt sich nie selbst im normalen Fluss). Der KLARTEXT dieser
//! Hülle ist nicht die Nachricht selbst, sondern dieser kleine, versionierte
//! Datensatz: an wen die Original-Nachricht ging und ihr Text. So kann das
//! empfangende Gerät sie als eigene, ausgehende Nachricht im richtigen Chat
//! ablegen.
//!
//! [ANNAHME: Ein einfaches versioniertes JSON-Payload-Format statt eines
//! eigenen Sync-Protokolls (kein Sesame-Geräte-Graph, keine Konfliktauf-
//! lösung). Das trägt für den Referenz-Client (gesendeter Text erscheint
//! überall); ein vollständiges Multi-Device-Sync mit Verlaufs-Nachzug beim
//! Koppeln und Löschungen bleibt die größere, teils externe Stufe.]

use serde::{Deserialize, Serialize};

use crate::error::ClientError;

const SYNC_VERSION: &str = "smsync.v1";

/// Der Typ einer Sync-Kopie. `message` (Vorgabe) ist eine einzelne, gerade
/// gesendete Nachricht; `history` ist ein Stück gespeicherter Verlauf, das
/// ein Erstgerät einem frisch gekoppelten Gerät nachliefert.
fn default_kind() -> String {
    "message".to_string()
}

#[derive(Serialize, Deserialize)]
struct SyncBlob {
    v: String,
    /// Vorgabe `message`, damit alte Payloads ohne Feld lesbar bleiben.
    #[serde(default = "default_kind")]
    kind: String,
    /// Handle des Chat-Partners (Empfänger der Original-Nachricht bzw. der
    /// Chat, zu dem der Verlauf gehört).
    peer: String,
    /// message: Klartext der Original-Nachricht (bei history leer).
    #[serde(default)]
    text: String,
    /// history: die nachgelieferten Verlaufszeilen (bei message leer).
    #[serde(default)]
    lines: Vec<HistLine>,
}

/// Eine Verlaufszeile im Nachzug: Absender-Handle, Klartext und Zeitpunkt.
/// Format wie die Anzeige-Zeile des Web-Clients, damit die Empfangsseite sie
/// direkt in ihre Ablage übernehmen kann.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HistLine {
    pub from: String,
    pub text: String,
    pub at: u64,
}

/// Das entschlüsselte Ergebnis eines Self-Sync-Payloads.
pub enum Synced {
    /// Eine gerade auf einem anderen Gerät gesendete Nachricht.
    Message { peer: String, text: String },
    /// Ein nachgelieferter Verlauf eines Chats (Koppeln).
    History { peer: String, lines: Vec<HistLine> },
}

/// Baut den Klartext-Payload einer Self-Sync-Kopie einer LIVE-Nachricht
/// (wird anschließend wie jeder andere Payload über den Ratchet
/// verschlüsselt).
pub fn encode(peer: &str, text: &str) -> Vec<u8> {
    let blob = SyncBlob {
        v: SYNC_VERSION.to_string(),
        kind: "message".to_string(),
        peer: peer.to_string(),
        text: text.to_string(),
        lines: Vec::new(),
    };
    serde_json::to_vec(&blob).expect("SyncBlob ist immer serialisierbar")
}

/// Baut den Klartext-Payload eines Verlaufs-Nachzugs für EINEN Chat.
pub fn encode_history(peer: &str, lines: &[HistLine]) -> Vec<u8> {
    let blob = SyncBlob {
        v: SYNC_VERSION.to_string(),
        kind: "history".to_string(),
        peer: peer.to_string(),
        text: String::new(),
        lines: lines.to_vec(),
    };
    serde_json::to_vec(&blob).expect("SyncBlob ist immer serialisierbar")
}

/// Liest Ziel und Inhalt aus einem entschlüsselten Self-Sync-Payload.
pub fn decode(payload: &[u8]) -> Result<Synced, ClientError> {
    let blob: SyncBlob = serde_json::from_slice(payload)
        .map_err(|error| ClientError::Protocol(format!("Sync-Payload unlesbar: {error}")))?;
    if blob.v != SYNC_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Sync-Version {}",
            blob.v
        )));
    }
    match blob.kind.as_str() {
        "message" => Ok(Synced::Message {
            peer: blob.peer,
            text: blob.text,
        }),
        "history" => Ok(Synced::History {
            peer: blob.peer,
            lines: blob.lines,
        }),
        other => Err(ClientError::Protocol(format!(
            "unbekannter Sync-Typ {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrip() {
        let payload = encode("bob", "hallo mit umlaut ä");
        match decode(&payload).unwrap() {
            Synced::Message { peer, text } => {
                assert_eq!(peer, "bob");
                assert_eq!(text, "hallo mit umlaut ä");
            }
            Synced::History { .. } => panic!("message erwartet"),
        }
    }

    #[test]
    fn history_roundtrip() {
        let lines = vec![
            HistLine {
                from: "bob".to_string(),
                text: "erste".to_string(),
                at: 100,
            },
            HistLine {
                from: "alice".to_string(),
                text: "zweite".to_string(),
                at: 200,
            },
        ];
        let payload = encode_history("bob", &lines);
        match decode(&payload).unwrap() {
            Synced::History { peer, lines: got } => {
                assert_eq!(peer, "bob");
                assert_eq!(got, lines);
            }
            Synced::Message { .. } => panic!("history erwartet"),
        }
    }

    /// Ein Payload aus der Zeit vor dem history-Feld (nur v, peer, text) muss
    /// weiter als Nachricht lesbar sein (Rückwärtskompatibilität).
    #[test]
    fn old_message_without_kind_field_is_readable() {
        let old = serde_json::json!({ "v": "smsync.v1", "peer": "bob", "text": "alt" });
        let payload = serde_json::to_vec(&old).unwrap();
        match decode(&payload).unwrap() {
            Synced::Message { peer, text } => {
                assert_eq!(peer, "bob");
                assert_eq!(text, "alt");
            }
            Synced::History { .. } => panic!("message erwartet"),
        }
    }

    #[test]
    fn rejects_foreign_and_wrong_version() {
        assert!(decode(b"kein json").is_err());
        let wrong = serde_json::json!({ "v": "smsync.v9", "peer": "x", "text": "y" });
        assert!(decode(&serde_json::to_vec(&wrong).unwrap()).is_err());
    }
}
