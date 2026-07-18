//! Kurzlebige TURN-Zugangsdaten für 1:1-Anrufe (F2).
//!
//! WebRTC braucht zur NAT-Traversierung STUN und, wenn beide Seiten hinter
//! symmetrischem NAT sitzen, einen TURN-Relay. Der Relay (coturn) darf nicht
//! offen stehen, sonst missbraucht ihn jeder als Bandbreiten-Proxy. coturn
//! kennt dafür `use-auth-secret`: der Dienst und coturn teilen ein Geheimnis,
//! der Dienst gibt dem Client ein kurzlebiges Zugangsdaten-Paar aus, coturn
//! rechnet dasselbe nach.
//!
//! Format (draft-uberti-behave-turn-rest): `username` ist der Unix-Ablauf-
//! zeitpunkt (Sekunden), `password` = Base64(HMAC-SHA1(secret, username)).
//! coturn prüft die Ablaufzeit und das HMAC selbst; das Geheimnis verlässt
//! den Server nie.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

/// Wie lange ein ausgegebenes Zugangsdaten-Paar gilt (Sekunden). Großzügig
/// genug für einen Verbindungsaufbau samt Reconnect, kurz genug, dass ein
/// abgefangenes Paar bald wertlos ist.
pub const TURN_TTL_SECS: u64 = 3600;

/// Die an den Client ausgegebenen ICE-Server samt kurzlebiger Zugangsdaten.
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct TurnCredentials {
    /// STUN-/TURN-URLs (Betriebs-Konfiguration), z. B.
    /// `["stun:turn.example:3478","turn:turn.example:3478?transport=udp"]`.
    pub urls: Vec<String>,
    /// Nutzername = Ablaufzeitpunkt (Unix-Sekunden) als Text.
    pub username: String,
    /// Passwort = Base64(HMAC-SHA1(secret, username)).
    pub credential: String,
    /// Restgültigkeit in Sekunden (für den Client, wann neu zu holen ist).
    pub ttl: u64,
}

/// Bildet ein kurzlebiges Zugangsdaten-Paar aus dem geteilten Geheimnis. `now`
/// ist die aktuelle Unix-Zeit (Sekunden); der Nutzername ist `now + ttl`.
/// Deterministisch, damit prüfbar.
pub fn credentials(secret: &str, urls: &[String], now: u64, ttl: u64) -> TurnCredentials {
    let username = (now + ttl).to_string();
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC nimmt jede Schlüssellänge");
    mac.update(username.as_bytes());
    let credential = BASE64.encode(mac.finalize().into_bytes());
    TurnCredentials {
        urls: urls.to_vec(),
        username,
        credential,
        ttl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_is_expiry_and_credential_is_hmac() {
        let urls = vec!["turn:turn.example:3478".to_string()];
        let creds = credentials("geheim", &urls, 1_000, 3600);
        assert_eq!(creds.username, "4600"); // now + ttl
        assert_eq!(creds.ttl, 3600);
        assert_eq!(creds.urls, urls);

        // Das Passwort ist reproduzierbar: HMAC-SHA1(secret, username), Base64.
        let mut mac = Hmac::<Sha1>::new_from_slice(b"geheim").unwrap();
        mac.update(b"4600");
        assert_eq!(creds.credential, BASE64.encode(mac.finalize().into_bytes()));
    }

    #[test]
    fn different_secret_yields_different_credential() {
        let urls = vec!["turn:x:3478".to_string()];
        let a = credentials("secret-a", &urls, 1_000, 3600);
        let b = credentials("secret-b", &urls, 1_000, 3600);
        assert_eq!(a.username, b.username); // gleiche Ablaufzeit
        assert_ne!(a.credential, b.credential); // aber anderes HMAC
    }
}
