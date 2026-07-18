//! Signalisierung für 1:1-Anrufe (`smcall.v1`).
//!
//! Ein Anruf ist WebRTC zwischen zwei Browsern: die Medien (Ton) fliessen
//! direkt (oder über einen TURN-Relay), Ende-zu-Ende zwischen den Geräten.
//! Was der Dienst NICHT vermittelt, ist der Medienstrom; er transportiert nur
//! die Signalisierung (SDP-Angebot/-Antwort und ICE-Kandidaten), und die
//! reist Ende-zu-Ende verschlüsselt durch DENSELBEN 1:1-Kanal wie eine
//! Nachricht (Double Ratchet, smenv.v1-Rahmung). Der Server sieht also weder
//! Ton noch SDP im Klartext.
//!
//! Dieses kleine versionierte JSON ist der Klartext einer solchen
//! Signalisierungs-Hülle. Anders als eine Nachricht wird es NICHT gefrankt
//! (Signalisierung ist flüchtige Steuerung, keine meldbare Nachricht) und
//! landet nicht im Verlauf; die Empfangsseite erkennt es an der Version und
//! reicht es an die Anruf-Steuerung statt an den Chat.
//!
//! [ANNAHME: Die SDP enthält je nach ICE-Politik Kandidaten mit IP-Adressen.
//! Sie Ende-zu-Ende zu verschlüsseln hält sie vom Server fern; ein TURN-Relay
//! sieht die Medien-Metadaten ohnehin, das ist der Preis der NAT-Traversierung
//! und bei jedem WebRTC-Anruf so.]

use serde::{Deserialize, Serialize};

const CALL_VERSION: &str = "smcall.v1";

#[derive(Serialize, Deserialize)]
struct CallBlob {
    v: String,
    kind: String,
    /// Kennung des Anrufs (vom Anrufer vergeben), damit späte oder doppelte
    /// Signale dem richtigen Anruf zugeordnet werden.
    call_id: String,
    /// offer/answer: die SDP (sonst leer).
    #[serde(default)]
    sdp: String,
    /// ice: der serialisierte ICE-Kandidat (sonst leer).
    #[serde(default)]
    candidate: String,
    /// hangup: kurzer Grund (optional, etwa "besetzt", "abgelehnt").
    #[serde(default)]
    reason: String,
}

/// Ein entschlüsseltes Anruf-Signal.
#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    /// Der Anrufer bietet einen Anruf an (SDP-Offer).
    Offer { call_id: String, sdp: String },
    /// Der Angerufene nimmt an (SDP-Answer).
    Answer { call_id: String, sdp: String },
    /// Ein ICE-Kandidat (Trickle-ICE, beidseitig).
    Ice { call_id: String, candidate: String },
    /// Auflegen/Ablehnen/Besetzt mit optionalem Grund.
    Hangup { call_id: String, reason: String },
}

impl Signal {
    /// Die Anruf-Kennung, zu der dieses Signal gehört.
    pub fn call_id(&self) -> &str {
        match self {
            Signal::Offer { call_id, .. }
            | Signal::Answer { call_id, .. }
            | Signal::Ice { call_id, .. }
            | Signal::Hangup { call_id, .. } => call_id,
        }
    }

    /// Serialisiert das Signal in den Klartext-Payload (wird anschließend
    /// über den Ratchet verschlüsselt und als smenv.v1 gesendet).
    pub fn encode(&self) -> Vec<u8> {
        let blob = match self {
            Signal::Offer { call_id, sdp } => CallBlob {
                v: CALL_VERSION.to_string(),
                kind: "offer".to_string(),
                call_id: call_id.clone(),
                sdp: sdp.clone(),
                candidate: String::new(),
                reason: String::new(),
            },
            Signal::Answer { call_id, sdp } => CallBlob {
                v: CALL_VERSION.to_string(),
                kind: "answer".to_string(),
                call_id: call_id.clone(),
                sdp: sdp.clone(),
                candidate: String::new(),
                reason: String::new(),
            },
            Signal::Ice { call_id, candidate } => CallBlob {
                v: CALL_VERSION.to_string(),
                kind: "ice".to_string(),
                call_id: call_id.clone(),
                sdp: String::new(),
                candidate: candidate.clone(),
                reason: String::new(),
            },
            Signal::Hangup { call_id, reason } => CallBlob {
                v: CALL_VERSION.to_string(),
                kind: "hangup".to_string(),
                call_id: call_id.clone(),
                sdp: String::new(),
                candidate: String::new(),
                reason: reason.clone(),
            },
        };
        serde_json::to_vec(&blob).expect("CallBlob ist immer serialisierbar")
    }
}

/// Ob ein entschlüsselter Payload ein Anruf-Signal ist (Versions-Prüfung),
/// damit die Empfangsseite Signalisierung vom Chat trennt, bevor sie den
/// Payload als Nachricht deutet.
pub fn is_signal(payload: &[u8]) -> bool {
    serde_json::from_slice::<CallBlob>(payload).is_ok_and(|blob| blob.v == CALL_VERSION)
}

/// Liest ein Anruf-Signal aus dem entschlüsselten Payload. Fehler bei
/// fremdem/unbekanntem Inhalt.
pub fn decode(payload: &[u8]) -> Result<Signal, String> {
    let blob: CallBlob = serde_json::from_slice(payload)
        .map_err(|error| format!("Anruf-Signal unlesbar: {error}"))?;
    if blob.v != CALL_VERSION {
        return Err(format!("unbekannte Anruf-Version {}", blob.v));
    }
    match blob.kind.as_str() {
        "offer" => Ok(Signal::Offer {
            call_id: blob.call_id,
            sdp: blob.sdp,
        }),
        "answer" => Ok(Signal::Answer {
            call_id: blob.call_id,
            sdp: blob.sdp,
        }),
        "ice" => Ok(Signal::Ice {
            call_id: blob.call_id,
            candidate: blob.candidate,
        }),
        "hangup" => Ok(Signal::Hangup {
            call_id: blob.call_id,
            reason: blob.reason,
        }),
        other => Err(format!("unbekannte Anruf-Art {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(signal: Signal) {
        let encoded = signal.encode();
        assert!(is_signal(&encoded));
        assert_eq!(decode(&encoded).unwrap(), signal);
    }

    #[test]
    fn offer_answer_ice_hangup_roundtrip() {
        roundtrip(Signal::Offer {
            call_id: "c-1".to_string(),
            sdp: "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\n".to_string(),
        });
        roundtrip(Signal::Answer {
            call_id: "c-1".to_string(),
            sdp: "v=0\r\na=recvonly\r\n".to_string(),
        });
        roundtrip(Signal::Ice {
            call_id: "c-1".to_string(),
            candidate: "{\"candidate\":\"candidate:1 1 udp ...\"}".to_string(),
        });
        roundtrip(Signal::Hangup {
            call_id: "c-1".to_string(),
            reason: "abgelehnt".to_string(),
        });
    }

    #[test]
    fn call_id_is_readable() {
        assert_eq!(
            Signal::Ice {
                call_id: "c-9".to_string(),
                candidate: String::new()
            }
            .call_id(),
            "c-9"
        );
    }

    /// Ein Chat-Payload (roher Text oder smmsg) ist KEIN Anruf-Signal: so
    /// trennt die Empfangsseite die beiden sauber.
    #[test]
    fn chat_payloads_are_not_signals() {
        assert!(!is_signal(b"treffen wir uns um drei"));
        assert!(!is_signal(&crate::msg::encode_edit("Yzox", "neu")));
        assert!(decode(b"kein json").is_err());
    }
}
