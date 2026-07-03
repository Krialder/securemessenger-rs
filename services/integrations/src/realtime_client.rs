//! Anbindung an den delivery-Dienst über dessen /internal-Routen.
//!
//! delivery hält die WebSocket-Verbindungen der Geräte; integrations
//! löst dort Ereignisse aus (F070) und fragt Präsenz ab (F080). Der
//! Trait entkoppelt die HTTP-Schicht von reqwest, damit Tests ein
//! Fake-Gateway stecken können. Fehler heißt immer: delivery nicht
//! erreichbar, also 500 beim Aufrufer.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

#[async_trait]
pub trait RealtimeGateway: Send + Sync {
    /// Verteilt ein Ereignis an die Geräte; liefert, wie viele davon
    /// gerade verbunden sind (nur informativ, Hinweis-Semantik).
    async fn push_event(
        &self,
        device_ids: &[String],
        event: serde_json::Value,
    ) -> Result<u32, String>;

    /// Welche der Geräte sind gerade verbunden?
    async fn query_presence(&self, device_ids: &[String]) -> Result<Vec<String>, String>;
}

/// HTTP-Umsetzung gegen delivery, ausgewiesen per Shared Secret
/// (gleiches Muster wie die identity-Anbindung in crates/common).
pub struct HttpRealtimeGateway {
    client: reqwest::Client,
    base_url: String,
    internal_token: String,
}

impl HttpRealtimeGateway {
    pub fn new(base_url: &str, internal_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_token: internal_token.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct EventResponse {
    connected: u32,
}

#[derive(Deserialize)]
struct PresenceResponse {
    online: Vec<String>,
}

#[async_trait]
impl RealtimeGateway for HttpRealtimeGateway {
    async fn push_event(
        &self,
        device_ids: &[String],
        event: serde_json::Value,
    ) -> Result<u32, String> {
        let response = self
            .client
            .post(format!("{}/internal/events", self.base_url))
            .header("x-internal-token", &self.internal_token)
            .json(&json!({ "device_ids": device_ids, "event": event }))
            .send()
            .await
            .map_err(|err| format!("delivery nicht erreichbar: {err}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "delivery antwortete mit Status {}",
                response.status()
            ));
        }
        let body: EventResponse = response
            .json()
            .await
            .map_err(|err| format!("Antwort von delivery unlesbar: {err}"))?;
        Ok(body.connected)
    }

    async fn query_presence(&self, device_ids: &[String]) -> Result<Vec<String>, String> {
        let response = self
            .client
            .post(format!("{}/internal/presence/query", self.base_url))
            .header("x-internal-token", &self.internal_token)
            .json(&json!({ "device_ids": device_ids }))
            .send()
            .await
            .map_err(|err| format!("delivery nicht erreichbar: {err}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "delivery antwortete mit Status {}",
                response.status()
            ));
        }
        let body: PresenceResponse = response
            .json()
            .await
            .map_err(|err| format!("Antwort von delivery unlesbar: {err}"))?;
        Ok(body.online)
    }
}
