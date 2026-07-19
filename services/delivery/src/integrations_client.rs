//! Ausgehende Anbindung an den integrations-Dienst.
//!
//! delivery hält die WebSocket-Verbindungen und weiß damit als einziger
//! Dienst, wann ein Nutzer online oder offline geht. Diese Präsenz-
//! Änderung meldet es integrations, das daraus die Webhooks der
//! Fremdprojekte speist (Push statt Poll). Die Meldung ist best effort:
//! eine nicht erreichbare integrations-Instanz darf die Zustellung und
//! die Echtzeit-Verbindungen von delivery nie stören.

use async_trait::async_trait;
use serde_json::json;

#[async_trait]
pub trait IntegrationsGateway: Send + Sync {
    /// Meldet, dass ein Handle online (true) oder offline (false) ging.
    /// `seq` ist die fortlaufende Übergangs-Nummer (delivery vergibt sie
    /// unter der Präsenz-Sperre), damit der Empfänger ordnen kann.
    async fn presence_changed(&self, handle: &str, online: bool, seq: u64);
}

/// Tut nichts: ohne gesetzte INTEGRATIONS_URL läuft delivery ohne die
/// Webhook-Anbindung (sie ist optional, der Chat-Kern hängt nicht daran).
pub struct NoopIntegrationsGateway;

#[async_trait]
impl IntegrationsGateway for NoopIntegrationsGateway {
    async fn presence_changed(&self, _handle: &str, _online: bool, _seq: u64) {}
}

/// HTTP-Umsetzung gegen die interne Route von integrations, ausgewiesen per
/// Shared Secret (gleiches Muster wie die identity-Anbindung).
pub struct HttpIntegrationsGateway {
    client: reqwest::Client,
    base_url: String,
    internal_token: String,
}

impl HttpIntegrationsGateway {
    pub fn new(base_url: &str, internal_token: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest-Client baubar");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_token: internal_token.to_string(),
        }
    }
}

#[async_trait]
impl IntegrationsGateway for HttpIntegrationsGateway {
    async fn presence_changed(&self, handle: &str, online: bool, seq: u64) {
        let result = self
            .client
            .post(format!("{}/internal/presence-event", self.base_url))
            .header("x-internal-token", &self.internal_token)
            .json(&json!({ "handle": handle, "online": online, "seq": seq }))
            .send()
            .await;
        match result {
            Ok(response) if !response.status().is_success() => {
                tracing::warn!(status = %response.status(), "integrations wies Präsenz-Ereignis ab");
            }
            Err(error) => {
                tracing::warn!(%error, "Präsenz-Ereignis an integrations fehlgeschlagen");
            }
            Ok(_) => {}
        }
    }
}
