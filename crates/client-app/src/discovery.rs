//! Client der Contact Discovery (specs/contact-discovery.md).
//!
//! Ein Handle zu einem Konto auflösen, ohne dass der Server lernt, wonach
//! gesucht wurde. Der Ablauf ist eine OPRF-Runde plus Nachschlag: der
//! Client blendet den Handle (`oprf::blind`), der identity-Dienst wertet
//! aus (`POST /discovery/evaluate`), der Client entblendet zu
//! `PRF_k(handle)` und schlägt das Konto darüber nach
//! (`POST /discovery/lookup`). Die OPRF-Krypto liegt im geteilten
//! `oprf`-Crate (RFC 9497, kein Eigenbau); hier läuft nur der HTTP-Teil.
//!
//! Der aufgelöste Schlüssel ist noch nicht vertrauenswürdig: Discovery
//! liefert den Einstieg, die Echtheit kommt aus Key Transparency. Der
//! Aufrufer prüft `identity_key` über `crate::kt::KtClient::verify_self`
//! des Kontakts (bzw. den Inklusionsbeweis), bevor er eine Sitzung startet.

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::http::{parse_json, transport};

#[derive(Clone)]
pub struct DiscoveryClient {
    base_url: String,
    http: reqwest::Client,
}

/// Ein aufgelöstes Konto: interne Adresse und Konto-Identitätsschlüssel,
/// bereit für die KT-Prüfung. Der Handle bestätigt nur, was der Aufrufer
/// schon kannte.
#[derive(Deserialize, Debug, Clone)]
pub struct DiscoveredAccount {
    pub handle: String,
    pub id: String,
    pub identity_key: String,
}

#[derive(Serialize)]
struct EvaluateRequest<'a> {
    blinded: &'a str,
}

#[derive(Deserialize)]
struct EvaluateResponse {
    evaluation: String,
}

#[derive(Serialize)]
struct LookupRequest<'a> {
    prf: &'a str,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl DiscoveryClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Löst einen bekannten Handle oblivious zu einem Konto auf. `None`,
    /// wenn kein Konto unter dem Handle steht (der Server lernt den Handle
    /// dabei nicht). Der Schlüssel ist noch gegen KT zu prüfen.
    pub async fn resolve(
        &self,
        access_token: &str,
        handle: &str,
    ) -> Result<Option<DiscoveredAccount>, ClientError> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        // 1. Blenden.
        let query =
            oprf::blind(handle).map_err(|e| ClientError::Protocol(format!("OPRF-Blenden: {e}")))?;

        // 2. Server-Runde.
        let response = self
            .http
            .post(format!("{}/discovery/evaluate", self.base_url))
            .bearer_auth(access_token)
            .json(&EvaluateRequest {
                blinded: &BASE64.encode(&query.blinded),
            })
            .send()
            .await
            .map_err(transport)?;
        let evaluation: EvaluateResponse = parse_json(response).await?;
        let evaluation_bytes = BASE64
            .decode(&evaluation.evaluation)
            .map_err(|_| ClientError::Decode("evaluation kein Base64".to_string()))?;

        // 3. Entblenden zu PRF_k(handle).
        let prf = query
            .finalize(handle, &evaluation_bytes)
            .map_err(|e| ClientError::Protocol(format!("OPRF-Entblenden: {e}")))?;

        // 4. Nachschlagen. 404 heißt: kein Konto, nicht Fehler.
        let response = self
            .http
            .post(format!("{}/discovery/lookup", self.base_url))
            .bearer_auth(access_token)
            .json(&LookupRequest { prf: &hex(&prf) })
            .send()
            .await
            .map_err(transport)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(parse_json(response).await?))
    }
}
