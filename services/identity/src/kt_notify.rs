//! Meldung von Schlüsseländerungen an den Key-Transparency-Dienst.
//!
//! Nach jeder Änderung der Schlüsselmenge (Registrierung, Gerät dazu,
//! Gerät revoziert) meldet identity das neue Konto-Commitment an kt
//! (POST /internal/updates), wo es mit der nächsten Epoche im
//! Verzeichnis landet. Die Meldung ist fire-and-forget: ein kt-Ausfall
//! darf niemals Registrierung oder Geräteverwaltung blockieren.
//! [ANNAHME: verpasste Meldungen (kt länger weg) holt erst ein
//! Abgleich-Job der Betriebs-Etappe nach; bis dahin fällt so ein Loch
//! spätestens bei der Client-Selbstprüfung auf, die das eigene
//! Commitment im Verzeichnis vermisst.]

use async_trait::async_trait;

/// Schnittstelle, damit Tests die Meldungen abfangen können.
#[async_trait]
pub trait KtNotifier: Send + Sync {
    /// Meldet: die Schlüsselmenge von `handle` hat jetzt dieses Commitment.
    async fn key_set_changed(&self, handle: &str, commitment: &[u8]);
}

/// Für Entwicklung ohne kt-Dienst: loggt nur.
pub struct NoopKtNotifier;

#[async_trait]
impl KtNotifier for NoopKtNotifier {
    async fn key_set_changed(&self, handle: &str, _commitment: &[u8]) {
        tracing::debug!(%handle, "KT-Meldung übersprungen (kein KT_URL konfiguriert)");
    }
}

/// HTTP-Umsetzung gegen kt's interne Update-Route.
pub struct HttpKtNotifier {
    client: reqwest::Client,
    base_url: String,
    internal_token: String,
}

impl HttpKtNotifier {
    pub fn new(base_url: &str, internal_token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_token: internal_token.to_string(),
        }
    }
}

#[async_trait]
impl KtNotifier for HttpKtNotifier {
    async fn key_set_changed(&self, handle: &str, commitment: &[u8]) {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let result = self
            .client
            .post(format!("{}/internal/updates", self.base_url))
            .header("x-internal-token", &self.internal_token)
            .json(&serde_json::json!({
                "handle": handle,
                "value": BASE64.encode(commitment),
            }))
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::warn!(
                    %handle,
                    status = %response.status(),
                    "KT-Meldung abgewiesen; Verzeichnis läuft nach"
                );
            }
            Err(error) => {
                tracing::warn!(%handle, %error, "KT-Meldung fehlgeschlagen; Verzeichnis läuft nach");
            }
        }
    }
}
