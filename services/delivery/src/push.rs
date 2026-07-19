//! Inhaltsloser Web-Push (F1): weckt ein Gerät, wenn eine Nachricht eintrifft,
//! während es keinen WebSocket hält (Browser geschlossen).
//!
//! Der Push trägt KEINEN Inhalt (kein verschlüsselter Payload nach RFC 8291),
//! genau wie der WebSocket-Hinweis: der Browser-Service-Worker zeigt eine
//! generische Meldung ("neue Nachricht"), der Client holt die Hülle danach
//! wie sonst per Pull. Damit sieht der fremde Push-Dienst NICHTS über die
//! Nachricht, und der Dienst muss keine Payload-Kryptografie fahren.
//!
//! Autorisiert wird der Push per VAPID (RFC 8292): ein kurzlebiger,
//! ES256-signierter JWT (P-256) plus der öffentliche VAPID-Schlüssel im
//! `Authorization`-Header. Der Client kennt denselben öffentlichen Schlüssel
//! als `applicationServerKey` seines Abos.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

use crate::store::PushSubscription;

/// Wie ein Wecken ausging: zugestellt, oder der Endpoint ist endgültig weg
/// (404/410 vom Push-Dienst), dann räumt der Aufrufer das Abo weg.
#[derive(Debug, PartialEq, Eq)]
pub enum PushDelivery {
    Delivered,
    Gone,
}

/// Schickt inhaltslose Aufweck-Pushs an Browser-Abos. Der `Noop` ist der
/// Default, solange kein VAPID-Schlüssel konfiguriert ist (Push aus, wie die
/// integrations-Anbindung ohne URL).
#[async_trait]
pub trait PushSender: Send + Sync {
    /// Weckt ein Gerät über sein Abo. `Gone` heißt: Endpoint abgelaufen, das
    /// Abo entfernen. `Err` ist ein vorübergehender Fehler.
    async fn wake(&self, subscription: &PushSubscription) -> Result<PushDelivery, String>;

    /// Der öffentliche VAPID-Schlüssel (base64url, unkomprimierter Punkt), den
    /// der Client als `applicationServerKey` braucht. `None`, wenn Push aus ist.
    fn public_key(&self) -> Option<String>;
}

/// Push ist nicht konfiguriert: nichts wird gesendet, kein Schlüssel angeboten.
pub struct NoopPushSender;

#[async_trait]
impl PushSender for NoopPushSender {
    async fn wake(&self, _subscription: &PushSubscription) -> Result<PushDelivery, String> {
        Ok(PushDelivery::Delivered)
    }
    fn public_key(&self) -> Option<String> {
        None
    }
}

/// Das VAPID-Schlüsselpaar: der private ES256-Schlüssel signiert den JWT, der
/// öffentliche Schlüssel (base64url) ist der `applicationServerKey`.
pub struct VapidKeys {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl VapidKeys {
    /// Lädt das Schlüsselpaar aus dem privaten Schlüssel (base64url der rohen
    /// 32-Byte-Skalarform, wie ihn die üblichen VAPID-Werkzeuge ausgeben) und
    /// leitet den öffentlichen Schlüssel ab.
    pub fn from_private_base64(private_b64: &str) -> Result<Self, String> {
        let bytes = B64URL
            .decode(private_b64.trim())
            .map_err(|_| "VAPID_PRIVATE_KEY ist kein base64url".to_string())?;
        let signing_key = SigningKey::from_slice(&bytes)
            .map_err(|_| "VAPID_PRIVATE_KEY ist kein gültiger P-256-Schlüssel".to_string())?;
        let public_key_b64 = B64URL.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        Ok(Self {
            signing_key,
            public_key_b64,
        })
    }
}

/// Sendet echte Web-Pushs: baut je Endpoint einen VAPID-JWT und POSTet
/// inhaltslos an den Push-Dienst.
pub struct VapidPushSender {
    keys: VapidKeys,
    /// VAPID-`sub`: eine Kontaktangabe des Betreibers (mailto: oder https:),
    /// die der Push-Dienst bei Missbrauch anspricht.
    subject: String,
    client: reqwest::Client,
    /// TTL des Pushs in Sekunden: so lange hält der Push-Dienst ihn vor, wenn
    /// das Gerät offline ist.
    ttl_secs: u64,
    /// Injizierbar für den Test (ohne Zeit-Abhängigkeit stabil).
    now_unix: fn() -> u64,
}

impl VapidPushSender {
    pub fn new(keys: VapidKeys, subject: &str) -> Self {
        // Keine Weiterleitungen folgen: sonst könnte ein Push-Endpoint per
        // 30x auf ein internes Ziel zeigen und den SSRF-Filter des Abos
        // umgehen (Defense-in-Depth zur Host-Prüfung beim Abonnieren).
        // Fail-fast statt unwrap_or_default: ein nicht baubarer Client würde
        // sonst still auf den Standard (folgt Weiterleitungen) zurückfallen
        // und genau diese Härtung aushebeln. Gleicher Umgang wie im
        // integrations-Gateway (integrations_client.rs).
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest-Client baubar");
        Self {
            keys,
            subject: subject.to_string(),
            client,
            ttl_secs: 24 * 60 * 60,
            now_unix,
        }
    }

    /// Baut den VAPID-`Authorization`-Header für einen Endpoint: `vapid
    /// t=<jwt>, k=<pubkey>`. Öffentlich fürs Testen der JWT-Struktur.
    pub fn authorization_header(&self, endpoint: &str) -> Result<String, String> {
        let audience = origin_of(endpoint)?;
        let jwt = self.vapid_jwt(&audience)?;
        Ok(format!("vapid t={jwt}, k={}", self.keys.public_key_b64))
    }

    /// Baut den ES256-signierten VAPID-JWT für ein Ziel-`aud` (den Origin des
    /// Push-Dienstes). Läuft nach 12 Stunden ab (RFC 8292 erlaubt bis 24 h).
    fn vapid_jwt(&self, audience: &str) -> Result<String, String> {
        let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let exp = (self.now_unix)() + 12 * 60 * 60;
        let claims = serde_json::json!({
            "aud": audience,
            "exp": exp,
            "sub": self.subject,
        });
        let claims_b64 =
            B64URL.encode(serde_json::to_vec(&claims).map_err(|e| format!("VAPID-Claims: {e}"))?);
        let signing_input = format!("{header}.{claims_b64}");
        // ES256: ECDSA über P-256, intern mit SHA-256; die Signatur ist die
        // feste 64-Byte-Form r||s, genau das JWS-Format.
        let signature: Signature = self.keys.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = B64URL.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

#[async_trait]
impl PushSender for VapidPushSender {
    async fn wake(&self, subscription: &PushSubscription) -> Result<PushDelivery, String> {
        let authorization = self.authorization_header(&subscription.endpoint)?;
        let response = self
            .client
            .post(&subscription.endpoint)
            .header("Authorization", authorization)
            .header("TTL", self.ttl_secs.to_string())
            // Inhaltslos: kein Body, aber der Content-Encoding-Header entfällt,
            // weil kein verschlüsselter Payload reist.
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(|e| format!("Push-Aufruf: {e}"))?;
        let status = response.status();
        if status.is_success() {
            Ok(PushDelivery::Delivered)
        } else if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            // Der Push-Dienst kennt den Endpoint nicht mehr: Abo ist tot.
            Ok(PushDelivery::Gone)
        } else {
            Err(format!("Push-Dienst antwortete {status}"))
        }
    }

    fn public_key(&self) -> Option<String> {
        Some(self.keys.public_key_b64.clone())
    }
}

/// Sekunden seit der Unix-Epoche (für die JWT-Ablaufzeit).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Der Origin (Schema + Host + optional Port) einer Endpoint-URL, das VAPID-
/// `aud`. Bewusst simpel: Schema bis zum dritten `/`.
fn origin_of(endpoint: &str) -> Result<String, String> {
    let after_scheme = endpoint
        .find("://")
        .ok_or_else(|| "Push-Endpoint ohne Schema".to_string())?
        + 3;
    let host_end = endpoint[after_scheme..]
        .find('/')
        .map(|i| after_scheme + i)
        .unwrap_or(endpoint.len());
    Ok(endpoint[..host_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    // Ein fester Testschlüssel (32-Byte-Skalar), base64url.
    fn test_keys() -> VapidKeys {
        let scalar = [7u8; 32];
        VapidKeys::from_private_base64(&B64URL.encode(scalar)).unwrap()
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://fcm.googleapis.com/fcm/send/abc123").unwrap(),
            "https://fcm.googleapis.com"
        );
        assert_eq!(
            origin_of("https://updates.push.services.mozilla.com/wpush/v2/xy").unwrap(),
            "https://updates.push.services.mozilla.com"
        );
        assert!(origin_of("kein-schema").is_err());
    }

    #[test]
    fn public_key_is_the_uncompressed_point() {
        let keys = test_keys();
        // 65 Byte unkomprimiert (0x04 || x || y) -> 87 base64url-Zeichen.
        let raw = B64URL.decode(&keys.public_key_b64).unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn vapid_jwt_is_well_formed_and_signature_verifies() {
        let sender = VapidPushSender::new(test_keys(), "mailto:ops@example.org");
        let header = sender
            .authorization_header("https://fcm.googleapis.com/fcm/send/xyz")
            .unwrap();
        // "vapid t=<jwt>, k=<pubkey>"
        let jwt = header
            .strip_prefix("vapid t=")
            .and_then(|s| s.split(", k=").next())
            .expect("JWT im Header");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT hat drei Teile");

        // Header dekodiert zu ES256.
        let head: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(head["alg"], "ES256");

        // Claims tragen aud/exp/sub.
        let claims: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["sub"], "mailto:ops@example.org");
        assert!(claims["exp"].as_u64().unwrap() > 0);

        // Die Signatur prüft gegen den öffentlichen Schlüssel.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&B64URL.decode(parts[2]).unwrap()).unwrap();
        let vk = VerifyingKey::from_encoded_point(
            &p256::EncodedPoint::from_bytes(B64URL.decode(&test_keys().public_key_b64).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[tokio::test]
    async fn noop_offers_no_key() {
        let noop = NoopPushSender;
        assert_eq!(noop.public_key(), None);
        let sub = PushSubscription {
            endpoint: "https://x/y".to_string(),
            p256dh: String::new(),
            auth: String::new(),
        };
        assert_eq!(noop.wake(&sub).await.unwrap(), PushDelivery::Delivered);
    }
}
