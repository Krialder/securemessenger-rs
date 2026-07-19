//! Signatur und Zustellung der Webhooks.
//!
//! Kein Krypto-Eigenbau und kein pro-Endpunkt-Geheimnis: der Dienst hält
//! EIN Ed25519-Signierpaar (wie das btlog-Crate), veröffentlicht den
//! öffentlichen Teil unter GET /integrations/webhook-key, und jeder
//! Empfänger prüft die Signatur damit. So liegt in der Ablage kein
//! rückholbares Signier-Geheimnis (NF040-Ethos), und ein Fremdprojekt
//! verifiziert alle Webhooks mit EINEM veröffentlichten Schlüssel.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

/// Header-Namen der Zustellung (bewusst mit Präfix, damit sie nicht mit
/// fremden Headern kollidieren).
pub const HEADER_EVENT: &str = "x-securemessenger-event";
pub const HEADER_DELIVERY: &str = "x-securemessenger-delivery";
pub const HEADER_TIMESTAMP: &str = "x-securemessenger-timestamp";
pub const HEADER_SIGNATURE: &str = "x-securemessenger-signature";

/// Hält das Signierpaar und leistet Signatur plus Schlüssel-Veröffentlichung.
pub struct WebhookSigner {
    key: SigningKey,
}

impl WebhookSigner {
    /// Aus einem Base64-kodierten 32-Byte-Seed (Betriebsvorgabe über
    /// INTEGRATIONS_WEBHOOK_SIGNING_KEY), damit der öffentliche Schlüssel
    /// über Neustarts stabil bleibt und Empfänger ihn cachen können.
    pub fn from_seed_b64(seed_b64: &str) -> Result<Self, String> {
        let bytes = BASE64
            .decode(seed_b64.trim())
            .map_err(|err| format!("Seed ist kein Base64: {err}"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Seed muss genau 32 Byte sein".to_string())?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Ephemeres Paar aus OS-Zufall: für den lokalen Lauf ohne gesetzten
    /// Seed. Über einen Neustart ändert sich dann der öffentliche
    /// Schlüssel (Empfänger müssten ihn neu holen); der Aufrufer warnt.
    pub fn ephemeral() -> Self {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Der öffentliche Schlüssel (Base64), wie ihn der Discovery-Endpunkt
    /// ausgibt und der Empfänger zum Prüfen nutzt.
    pub fn public_key_b64(&self) -> String {
        BASE64.encode(self.key.verifying_key().to_bytes())
    }

    /// Signiert die kanonische Nachricht `{timestamp}.{body}` (der
    /// Zeitstempel ist mitsigniert, damit ein Empfänger einen Replay
    /// anhand des Alters abweisen kann). Ergebnis ist die Base64-Signatur.
    pub fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        let mut message = format!("{timestamp}.").into_bytes();
        message.extend_from_slice(body);
        BASE64.encode(self.key.sign(&message).to_bytes())
    }
}

/// Eine fertig signierte Zustellung, wie sie der Sender verschickt.
#[derive(Clone)]
pub struct Delivery {
    pub url: String,
    pub event: String,
    pub delivery_id: String,
    pub timestamp: u64,
    pub signature: String,
    pub body: Vec<u8>,
}

/// Verschickt eine Zustellung. Der Trait entkoppelt die HTTP-Schicht von
/// reqwest, damit Tests einen Fake-Sender stecken können.
#[async_trait]
pub trait WebhookSender: Send + Sync {
    async fn deliver(&self, delivery: Delivery) -> Result<(), String>;
}

/// HTTP-Umsetzung: POST mit den signierten Headern und knappem Timeout
/// (ein langsamer Empfänger darf die Zustellung nicht endlos aufhalten).
pub struct HttpWebhookSender {
    client: reqwest::Client,
}

impl Default for HttpWebhookSender {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            // Keine Weiterleitungen folgen: sonst umginge ein Ziel eine
            // spätere Ziel-Prüfung über ein 302 auf ein internes Ziel
            // (SSRF-Härtung, zusammen mit der Host-Prüfung bei der Anlage).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest-Client baubar");
        Self { client }
    }
}

#[async_trait]
impl WebhookSender for HttpWebhookSender {
    async fn deliver(&self, delivery: Delivery) -> Result<(), String> {
        let response = self
            .client
            .post(&delivery.url)
            .header("content-type", "application/json")
            .header(HEADER_EVENT, &delivery.event)
            .header(HEADER_DELIVERY, &delivery.delivery_id)
            .header(HEADER_TIMESTAMP, delivery.timestamp.to_string())
            .header(HEADER_SIGNATURE, format!("ed25519={}", delivery.signature))
            .body(delivery.body)
            .send()
            .await
            .map_err(|err| format!("Zustellung fehlgeschlagen: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("Empfänger antwortete {}", response.status()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn signature_verifies_with_published_key() {
        let signer = WebhookSigner::ephemeral();
        let body = br#"{"type":"presence.changed"}"#;
        let ts = 1_700_000_000;
        let sig_b64 = signer.sign(ts, body);

        // Ein Empfänger baut die kanonische Nachricht nach und prüft mit
        // dem veröffentlichten Schlüssel.
        let pub_bytes: [u8; 32] = BASE64
            .decode(signer.public_key_b64())
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let sig_bytes: [u8; 64] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let mut message = format!("{ts}.").into_bytes();
        message.extend_from_slice(body);
        assert!(vk.verify(&message, &sig).is_ok());

        // Ein veränderter Zeitstempel bricht die Prüfung.
        let mut tampered = format!("{}.", ts + 1).into_bytes();
        tampered.extend_from_slice(body);
        assert!(vk.verify(&tampered, &sig).is_err());
    }

    #[test]
    fn seed_roundtrip_is_stable() {
        let seed_b64 = BASE64.encode([7u8; 32]);
        let a = WebhookSigner::from_seed_b64(&seed_b64).unwrap();
        let b = WebhookSigner::from_seed_b64(&seed_b64).unwrap();
        assert_eq!(a.public_key_b64(), b.public_key_b64());
        assert!(WebhookSigner::from_seed_b64("kurz").is_err());
    }
}
