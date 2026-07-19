//! Nutzlast-Format des Anruf-Datenkanals (`smdc.v1`).
//!
//! Jeder 1:1-Anruf trägt neben dem Ton einen WebRTC-Datenkanal (`sm-data`,
//! `call`-Modul). Über ihn läuft das Live-Tippen (Paket E): während man
//! schreibt, sieht der Gesprächspartner den Text Zeichen für Zeichen
//! entstehen, noch bevor er abgeschickt ist. Der Datenkanal ist durch DTLS
//! verschlüsselt (Teil der WebRTC-Sitzung) und läuft Peer-zu-Peer bzw. über
//! den TURN-Relay; der Server sieht ihn nie.
//!
//! Format: ein kleines versioniertes JSON. Bisher nur ein Ereignis:
//! - `typing`: der AKTUELLE Entwurfstext des Absenders (leer = Feld geleert
//!   oder Nachricht abgeschickt, die Vorschau verschwindet dann). Es reist
//!   der ganze Text, nicht ein Tastendruck-Delta: das ist robust gegen
//!   verlorene oder umsortierte Kanal-Nachrichten (die letzte gewinnt).
//!
//! [ANNAHME: Live-Tippen zeigt den Entwurf dem Gesprächspartner in Echtzeit;
//! das ist die gewünschte Funktion, kein Leck (es passiert nur während eines
//! Anrufs und nur, wenn der Nutzer die Funktion einschaltet). Ein
//! unbekanntes `kind` wird ignoriert, damit ein neuerer Client den Kanal um
//! weitere Ereignisse erweitern kann.]

use serde::{Deserialize, Serialize};

const DATACHAN_VERSION: &str = "smdc.v1";

#[derive(Serialize, Deserialize)]
struct DataBlob {
    v: String,
    kind: String,
    #[serde(default)]
    text: String,
}

/// Ein empfangenes Datenkanal-Ereignis.
#[derive(Debug, Clone, PartialEq)]
pub enum DataEvent {
    /// Der Gesprächspartner tippt gerade; `text` ist sein aktueller Entwurf
    /// (leer = Vorschau ausblenden).
    Typing { text: String },
}

/// Baut die Tipp-Nachricht: der aktuelle Entwurfstext.
pub fn encode_typing(text: &str) -> String {
    serde_json::to_string(&DataBlob {
        v: DATACHAN_VERSION.to_string(),
        kind: "typing".to_string(),
        text: text.to_string(),
    })
    .expect("DataBlob ist immer serialisierbar")
}

/// Deutet eine empfangene Datenkanal-Nachricht. `None`, wenn es kein gültiges
/// `smdc.v1` ist oder das `kind` unbekannt (dann ignorieren, nicht anzeigen).
pub fn decode(message: &str) -> Option<DataEvent> {
    let blob: DataBlob = serde_json::from_str(message).ok()?;
    if blob.v != DATACHAN_VERSION {
        return None;
    }
    match blob.kind.as_str() {
        "typing" => Some(DataEvent::Typing { text: blob.text }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_roundtrip() {
        assert_eq!(
            decode(&encode_typing("hallo ä")),
            Some(DataEvent::Typing {
                text: "hallo ä".to_string(),
            })
        );
    }

    #[test]
    fn empty_typing_is_a_clear() {
        assert_eq!(
            decode(&encode_typing("")),
            Some(DataEvent::Typing {
                text: String::new(),
            })
        );
    }

    #[test]
    fn foreign_or_unknown_is_ignored() {
        assert_eq!(decode("kein json"), None);
        assert_eq!(decode(r#"{"v":"smdc.v9","kind":"typing"}"#), None);
        assert_eq!(decode(r#"{"v":"smdc.v1","kind":"poll","text":"x"}"#), None);
    }
}
