//! Message-Franking-Rahmung auf Client-Seite
//! (specs/sealed-sender-und-abuse.md).
//!
//! Damit sich eine Nachricht später beweisbar melden lässt, committet sich
//! der Absender beim Senden: er wählt einen zufälligen Franking-Schlüssel
//! `K_f`, bildet `C = HMAC(K_f, Nachricht)` (Crate `franking`) und hängt
//! `C` als Franking-Tag an die Hülle. `K_f` muss den Empfänger erreichen,
//! damit dieser melden kann, darf aber der Server nicht sehen: deshalb
//! reist es Ende-zu-Ende im verschlüsselten Payload. Dieses Modul legt das
//! Payload-Format fest: `K_f` (32 Byte) vorangestellt, dann die Nachricht.
//! Der Server bekommt nur den verschlüsselten Payload und `C` zu sehen.
//!
//! Die Rahmung ist bewusst simpel und trägt keine Version: sie sitzt
//! innerhalb des E2E-Chiffretexts, der Client kontrolliert beide Enden.
//! [ANNAHME: Ein leerer Franking-Tag bleibt erlaubt für Nachrichten ohne
//! Meldbarkeit (etwa Handshakes); dieses Modul rahmt nur, wo Franking
//! gewünscht ist.]

use franking::KEY_LEN;

/// Ein gerahmter Sende-Payload: der verschlüsselte Inhalt (`K_f` plus
/// Nachricht) und das Commitment für den Franking-Tag.
pub struct FrankedMessage {
    /// Was verschlüsselt und gesendet wird: `K_f || Nachricht`.
    pub payload: Vec<u8>,
    /// Das Commitment `C = HMAC(K_f, Nachricht)`, als Franking-Tag an die
    /// Hülle zu hängen (Base64 rechnet der Aufrufer).
    pub commitment: Vec<u8>,
}

/// Rahmt eine Nachricht fürs Senden: erzeugt `K_f`, stellt ihn dem Inhalt
/// voran und bildet das Commitment.
pub fn frank(message: &[u8]) -> FrankedMessage {
    let key = franking::new_key();
    let mut payload = Vec::with_capacity(KEY_LEN + message.len());
    payload.extend_from_slice(&key);
    payload.extend_from_slice(message);
    let commitment = franking::commit(&key, message);
    FrankedMessage {
        payload,
        commitment,
    }
}

/// Ein geöffneter Payload beim Empfang: der Franking-Schlüssel (fürs
/// spätere Melden) und die eigentliche Nachricht.
pub struct OpenedMessage {
    pub franking_key: Vec<u8>,
    pub message: Vec<u8>,
}

/// Öffnet einen empfangenen Payload: trennt `K_f` vom Inhalt. Schlägt fehl,
/// wenn der Payload kürzer als ein Schlüssel ist (dann ist er nicht so
/// gerahmt).
pub fn unfrank(payload: &[u8]) -> Result<OpenedMessage, String> {
    if payload.len() < KEY_LEN {
        return Err("Payload zu kurz für einen Franking-Schlüssel".to_string());
    }
    let (key, message) = payload.split_at(KEY_LEN);
    Ok(OpenedMessage {
        franking_key: key.to_vec(),
        message: message.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frank_unfrank_roundtrip_and_commitment_opens() {
        let message = b"treffen wir uns um drei";
        let franked = frank(message);

        // Der Empfänger trennt Schlüssel und Nachricht.
        let opened = unfrank(&franked.payload).unwrap();
        assert_eq!(opened.message, message);

        // Der aufgedeckte Schlüssel öffnet das Commitment (echte Meldung).
        assert!(franking::verify(
            &opened.franking_key,
            &opened.message,
            &franked.commitment
        ));
    }

    #[test]
    fn short_payload_is_rejected() {
        assert!(unfrank(&[0u8; 8]).is_err());
    }
}
