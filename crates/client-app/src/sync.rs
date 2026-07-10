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

#[derive(Serialize, Deserialize)]
struct SyncBlob {
    v: String,
    /// Handle des echten Empfängers der Original-Nachricht.
    peer: String,
    /// Klartext der Original-Nachricht.
    text: String,
}

/// Baut den Klartext-Payload einer Self-Sync-Kopie (wird anschließend wie
/// jeder andere Payload über den Ratchet verschlüsselt).
pub fn encode(peer: &str, text: &str) -> Vec<u8> {
    let blob = SyncBlob {
        v: SYNC_VERSION.to_string(),
        peer: peer.to_string(),
        text: text.to_string(),
    };
    serde_json::to_vec(&blob).expect("SyncBlob ist immer serialisierbar")
}

/// Das entschlüsselte Ziel und der Text einer Self-Sync-Kopie.
pub struct Synced {
    pub peer: String,
    pub text: String,
}

/// Liest (Empfänger, Text) aus einem entschlüsselten Self-Sync-Payload.
pub fn decode(payload: &[u8]) -> Result<Synced, ClientError> {
    let blob: SyncBlob = serde_json::from_slice(payload)
        .map_err(|error| ClientError::Protocol(format!("Sync-Payload unlesbar: {error}")))?;
    if blob.v != SYNC_VERSION {
        return Err(ClientError::Protocol(format!(
            "unbekannte Sync-Version {}",
            blob.v
        )));
    }
    Ok(Synced {
        peer: blob.peer,
        text: blob.text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = encode("bob", "hallo mit umlaut ä");
        let synced = decode(&payload).unwrap();
        assert_eq!(synced.peer, "bob");
        assert_eq!(synced.text, "hallo mit umlaut ä");
    }

    #[test]
    fn rejects_foreign_and_wrong_version() {
        assert!(decode(b"kein json").is_err());
        let wrong = serde_json::to_vec(&SyncBlob {
            v: "smsync.v9".to_string(),
            peer: "x".to_string(),
            text: "y".to_string(),
        })
        .unwrap();
        assert!(decode(&wrong).is_err());
    }
}
