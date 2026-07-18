//! Nutzlast-Format der 1:1-Änderungsereignisse (`smmsg.v1`): Bearbeiten und
//! Löschen einer früher gesendeten Nachricht.
//!
//! Der GEWÖHNLICHE Nachrichtentext reist unverändert als roher Klartext im
//! gefrankten Payload (`franking`-Modul rahmt `K_f || text`); daran ändert
//! dieses Modul nichts, damit ältere Empfänger jede Nachricht weiter als Text
//! lesen. Die STABILE Nachrichten-ID, auf die sich ein Bearbeiten oder
//! Löschen bezieht, ist nicht neu übertragen, sondern das Franking-Commitment
//! `C = HMAC(K_f, text)`: beide Seiten kennen es (der Absender aus dem
//! Franken, der Empfänger rechnet es aus dem empfangenen `K_f` und Text nach),
//! der Server sieht ohnehin nur `C` als Franking-Tag, und ein Dritter, der die
//! Nachricht nicht gesehen hat, kann die ID nicht erraten. So braucht die
//! neue Fähigkeit KEINE inkompatible Text-Rahmung.
//!
//! Nur die beiden NEUEN Ereignisse tragen ein `smmsg.v1`-JSON im gefrankten
//! Payload:
//! - `edit`: ersetzt den Text der Nachricht mit dem Commitment `target`.
//! - `delete`: löscht die Nachricht mit dem Commitment `target` bei allen.
//!
//! Ein alter Empfänger, der ein solches JSON nicht deutet, zeigt es als
//! Text-Zeile (die Bearbeitung/Löschung wendet er nicht an); ein neuer
//! Empfänger erkennt es an `v`/`kind`. Ein roher Text, der zufällig wie ein
//! `smmsg.v1`-edit/-delete aussieht, ist praktisch ausgeschlossen und würde
//! höchstens ins Leere zielen (kein passender `target`).

use serde::{Deserialize, Serialize};

const MSG_VERSION: &str = "smmsg.v1";

#[derive(Serialize, Deserialize)]
struct MsgBlob {
    v: String,
    kind: String,
    /// edit: der neue Text (bei delete leer).
    #[serde(default)]
    text: String,
    /// edit/delete: das Franking-Commitment der betroffenen Nachricht,
    /// Base64.
    #[serde(default)]
    target: String,
}

/// Ein entschlüsseltes 1:1-Ereignis.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    /// Eine gewöhnliche Nachricht (roher Text; kein `smmsg`-Ereignis). Die
    /// ID einer solchen Nachricht ist ihr Franking-Commitment, das der
    /// Aufrufer getrennt bildet.
    Text { text: String },
    /// Der Absender ersetzt den Text der Nachricht `target`.
    Edit { target: String, text: String },
    /// Der Absender löscht die Nachricht `target` bei allen.
    Delete { target: String },
}

/// Baut den Payload einer Bearbeitung: neuer Text für die Nachricht mit dem
/// Commitment `target`.
pub fn encode_edit(target: &str, text: &str) -> Vec<u8> {
    to_bytes(&MsgBlob {
        v: MSG_VERSION.to_string(),
        kind: "edit".to_string(),
        text: text.to_string(),
        target: target.to_string(),
    })
}

/// Baut den Payload einer Löschung bei allen für die Nachricht mit dem
/// Commitment `target`.
pub fn encode_delete(target: &str) -> Vec<u8> {
    to_bytes(&MsgBlob {
        v: MSG_VERSION.to_string(),
        kind: "delete".to_string(),
        text: String::new(),
        target: target.to_string(),
    })
}

fn to_bytes(blob: &MsgBlob) -> Vec<u8> {
    serde_json::to_vec(blob).expect("MsgBlob ist immer serialisierbar")
}

/// Deutet einen entschlüsselten, ENTFRANKTEN 1:1-Payload. Ein gültiges
/// `smmsg.v1` mit `kind` edit/delete ist ein Änderungsereignis; alles andere
/// (roher Text, unbekanntes JSON, ein Alt-Payload) ist eine gewöhnliche
/// Nachricht und wird als Text gezeigt.
pub fn decode(payload: &[u8]) -> Msg {
    if let Ok(blob) = serde_json::from_slice::<MsgBlob>(payload) {
        if blob.v == MSG_VERSION {
            match blob.kind.as_str() {
                "edit" => {
                    return Msg::Edit {
                        target: blob.target,
                        text: blob.text,
                    }
                }
                "delete" => {
                    return Msg::Delete {
                        target: blob.target,
                    }
                }
                // Unbekannter kind: als Text deuten (Vorwärtskompatibilität).
                _ => {}
            }
        }
    }
    Msg::Text {
        text: String::from_utf8_lossy(payload).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_roundtrip() {
        assert_eq!(
            decode(&encode_edit("Yzox", "neu ö")),
            Msg::Edit {
                target: "Yzox".to_string(),
                text: "neu ö".to_string(),
            }
        );
    }

    #[test]
    fn delete_roundtrip() {
        assert_eq!(
            decode(&encode_delete("Yzox")),
            Msg::Delete {
                target: "Yzox".to_string(),
            }
        );
    }

    /// Roher Text bleibt eine gewöhnliche Nachricht (kein Ereignis).
    #[test]
    fn raw_text_is_a_plain_message() {
        assert_eq!(
            decode("treffen um drei ä".as_bytes()),
            Msg::Text {
                text: "treffen um drei ä".to_string(),
            }
        );
    }

    /// Ein unbekannter Ereignistyp verwirft die Zeile nicht, sondern wird als
    /// Text gedeutet.
    #[test]
    fn unknown_kind_falls_back_to_text() {
        let blob = serde_json::json!({ "v": "smmsg.v1", "kind": "poll", "text": "wahl?" });
        let bytes = serde_json::to_vec(&blob).unwrap();
        assert_eq!(
            decode(&bytes),
            Msg::Text {
                text: String::from_utf8_lossy(&bytes).to_string(),
            }
        );
    }
}
