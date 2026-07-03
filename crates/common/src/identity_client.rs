//! Anbindung an den identity-Dienst über dessen /internal-Routen.
//!
//! Dienste wie directory und delivery prüfen Bearer-Tokens nicht selbst:
//! die Session-Ablage gehört dem identity-Dienst, und jeder Dienst hält
//! nur seine eigene Datenbank (architektur.md). Der Trait entkoppelt die
//! HTTP-Schicht von reqwest, damit Tests ein Fake-Gateway stecken können.

use async_trait::async_trait;
use serde::Deserialize;

/// Aufgelöste Identität eines Access-Tokens.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub handle: String,
    pub device_id: String,
}

/// Ein gültiges (nicht revoziertes) Gerät eines Kontos.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub public_key: String,
    pub not_after: u64,
}

/// Konto-Identitätsschlüssel plus Gerätemenge, die Grundlage der Bündel
/// (directory) und der Empfänger-Auflösung (delivery).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountDevices {
    /// Server-erzeugte Konto-UUID, interne Adresse (z. B. recipient_id).
    pub id: String,
    pub handle: String,
    pub identity_key: String,
    pub devices: Vec<DeviceInfo>,
}

/// Fehler heißt hier immer: identity nicht erreichbar oder inkonsistent,
/// also 500 beim Aufrufer, nie 401/404.
#[async_trait]
pub trait IdentityGateway: Send + Sync {
    /// Löst ein Access-Token auf; None = ungültig oder abgelaufen.
    async fn introspect(&self, token: &str) -> Result<Option<CallerIdentity>, String>;

    /// Gerätemenge eines Kontos; None = Konto unbekannt.
    async fn account_devices(&self, handle: &str) -> Result<Option<AccountDevices>, String>;
}

/// HTTP-Umsetzung gegen die /internal-Routen, ausgewiesen per Shared Secret.
pub struct HttpIdentityGateway {
    client: reqwest::Client,
    base_url: String,
    internal_token: String,
}

impl HttpIdentityGateway {
    pub fn new(base_url: &str, internal_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            // Ohne abschließenden Slash gespeichert, die Pfade bringen ihn mit.
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_token: internal_token.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct IntrospectResponse {
    active: bool,
    handle: Option<String>,
    device_id: Option<String>,
}

#[async_trait]
impl IdentityGateway for HttpIdentityGateway {
    async fn introspect(&self, token: &str) -> Result<Option<CallerIdentity>, String> {
        let response = self
            .client
            .post(format!("{}/internal/introspect", self.base_url))
            .header("x-internal-token", &self.internal_token)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| format!("identity nicht erreichbar: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("identity introspect: HTTP {}", response.status()));
        }
        let body: IntrospectResponse = response
            .json()
            .await
            .map_err(|e| format!("identity introspect: Antwort unlesbar: {e}"))?;
        // active=true garantiert die Felder laut API-Vertrag; defensive
        // Prüfung trotzdem, damit ein Vertragsbruch als Fehler auffällt
        // statt als stilles 401.
        match (body.active, body.handle, body.device_id) {
            (true, Some(handle), Some(device_id)) => Ok(Some(CallerIdentity { handle, device_id })),
            (false, _, _) => Ok(None),
            _ => Err("identity introspect: active ohne Identität".to_string()),
        }
    }

    async fn account_devices(&self, handle: &str) -> Result<Option<AccountDevices>, String> {
        let response = self
            .client
            .get(format!(
                "{}/internal/accounts/{handle}/devices",
                self.base_url
            ))
            .header("x-internal-token", &self.internal_token)
            .send()
            .await
            .map_err(|e| format!("identity nicht erreichbar: {e}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(format!("identity devices: HTTP {}", response.status()));
        }
        let body: AccountDevices = response
            .json()
            .await
            .map_err(|e| format!("identity devices: Antwort unlesbar: {e}"))?;
        Ok(Some(body))
    }
}
