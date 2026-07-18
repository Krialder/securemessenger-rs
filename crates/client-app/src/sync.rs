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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
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
    /// message: Klartext der Original-Nachricht (bei history/event leer).
    #[serde(default)]
    text: String,
    /// message: die Nachrichten-ID (Franking-Commitment, Base64), damit die
    /// eigene ausgehende Zeile auf dem anderen Gerät dieselbe ID trägt und
    /// ein späteres Bearbeiten/Löschen sie trifft. Alte Payloads ohne Feld
    /// bleiben lesbar (leere ID, dann nicht bearbeitbar).
    #[serde(default)]
    id: String,
    /// history: die nachgelieferten Verlaufszeilen (sonst leer).
    #[serde(default)]
    lines: Vec<HistLine>,
    /// event: das komplette smmsg-Ereignis (edit/delete) als Base64, damit
    /// ein selbst gesendetes Bearbeiten oder Löschen die eigenen anderen
    /// Geräte erreicht und dort dieselbe Nachricht trifft (sonst leer).
    #[serde(default)]
    event: String,
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
    /// Eine gerade auf einem anderen Gerät gesendete Nachricht mit ihrer ID
    /// (Franking-Commitment; leer bei Alt-Payloads, dann nicht bearbeitbar).
    Message {
        peer: String,
        text: String,
        id: String,
    },
    /// Ein nachgelieferter Verlauf eines Chats (Koppeln).
    History { peer: String, lines: Vec<HistLine> },
    /// Ein smmsg-Änderungsereignis (Bearbeitung oder Löschung), das ein
    /// anderes eigenes Gerät ausgelöst hat. Der Payload sind die rohen
    /// smmsg-Bytes; der Aufrufer deutet sie mit `msg::decode`. Nur aus einer
    /// SEALED Self-Sync-Hülle vertrauenswürdig (der Aufrufer prüft das): das
    /// Sealed-Zertifikat bindet den Absender, die Klartext-Absenderadresse
    /// einer unversiegelten Hülle ist fälschbar.
    Event { peer: String, event: Vec<u8> },
}

/// Baut den Klartext-Payload einer Self-Sync-Kopie einer LIVE-Nachricht
/// (wird anschließend wie jeder andere Payload über den Ratchet
/// verschlüsselt).
pub fn encode(peer: &str, text: &str, id: &str) -> Vec<u8> {
    let blob = SyncBlob {
        v: SYNC_VERSION.to_string(),
        kind: "message".to_string(),
        peer: peer.to_string(),
        text: text.to_string(),
        id: id.to_string(),
        lines: Vec::new(),
        event: String::new(),
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
        id: String::new(),
        lines: lines.to_vec(),
        event: String::new(),
    };
    serde_json::to_vec(&blob).expect("SyncBlob ist immer serialisierbar")
}

/// Baut den Klartext-Payload einer Ereignis-Kopie an die eigenen Geräte: der
/// Chat-Partner plus die rohen smmsg-Bytes (neue Nachricht, Bearbeitung oder
/// Löschung), damit die anderen Geräte dasselbe Ereignis auf dieselbe
/// Nachrichten-ID anwenden.
pub fn encode_event(peer: &str, event: &[u8]) -> Vec<u8> {
    let blob = SyncBlob {
        v: SYNC_VERSION.to_string(),
        kind: "event".to_string(),
        peer: peer.to_string(),
        text: String::new(),
        id: String::new(),
        lines: Vec::new(),
        event: BASE64.encode(event),
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
            id: blob.id,
        }),
        "history" => Ok(Synced::History {
            peer: blob.peer,
            lines: blob.lines,
        }),
        "event" => {
            let event = BASE64
                .decode(&blob.event)
                .map_err(|_| ClientError::Protocol("Sync-Ereignis ist kein Base64".to_string()))?;
            Ok(Synced::Event {
                peer: blob.peer,
                event,
            })
        }
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
        let payload = encode("bob", "hallo mit umlaut ä", "Yzox");
        match decode(&payload).unwrap() {
            Synced::Message { peer, text, id } => {
                assert_eq!(peer, "bob");
                assert_eq!(text, "hallo mit umlaut ä");
                assert_eq!(id, "Yzox");
            }
            _ => panic!("message erwartet"),
        }
    }

    #[test]
    fn event_roundtrip_carries_raw_bytes() {
        let event = crate::msg::encode_edit("Yzox", "neu ä");
        let payload = encode_event("bob", &event);
        match decode(&payload).unwrap() {
            Synced::Event { peer, event: got } => {
                assert_eq!(peer, "bob");
                assert_eq!(got, event);
            }
            _ => panic!("event erwartet"),
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
            _ => panic!("history erwartet"),
        }
    }

    /// Ein Payload aus der Zeit vor dem history-Feld (nur v, peer, text) muss
    /// weiter als Nachricht lesbar sein (Rückwärtskompatibilität).
    #[test]
    fn old_message_without_kind_field_is_readable() {
        let old = serde_json::json!({ "v": "smsync.v1", "peer": "bob", "text": "alt" });
        let payload = serde_json::to_vec(&old).unwrap();
        match decode(&payload).unwrap() {
            Synced::Message { peer, text, id } => {
                assert_eq!(peer, "bob");
                assert_eq!(text, "alt");
                assert!(id.is_empty());
            }
            _ => panic!("message erwartet"),
        }
    }

    #[test]
    fn rejects_foreign_and_wrong_version() {
        assert!(decode(b"kein json").is_err());
        let wrong = serde_json::json!({ "v": "smsync.v9", "peer": "x", "text": "y" });
        assert!(decode(&serde_json::to_vec(&wrong).unwrap()).is_err());
    }
}
