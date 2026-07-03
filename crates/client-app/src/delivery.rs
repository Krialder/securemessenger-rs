//! Client der Zustellung (services/delivery, store-and-forward).
//!
//! `POST /messages` reicht Hüllen ein (eine je Zielgerät), `GET /messages`
//! holt die wartenden Hüllen des eigenen Geräts, `POST /messages/ack`
//! bestätigt verarbeitete. Die Schleife abholen - verarbeiten - bestätigen
//! ersetzt eine Pagination. Die Formen spiegeln
//! services/delivery/src/api.rs; der WebSocket-Hinweiskanal folgt mit der
//! Echtzeit-Etappe (im Browser über gloo-net, nativ über tungstenite).

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::http::{parse_json, transport};

#[derive(Clone)]
pub struct DeliveryClient {
    base_url: String,
    http: reqwest::Client,
}

/// Eine ausgehende Hülle: client-erzeugte ID (Idempotenz), Empfänger-Handle,
/// dessen Server-Geräte-ID und der geframte Chiffretext (wire::seal).
#[derive(Serialize, Debug, Clone)]
pub struct OutgoingEnvelope {
    pub id: String,
    pub recipient: String,
    pub device_id: String,
    pub envelope: String,
}

/// Ergebnis der Annahme: angenommen plus als Duplikat erkannt (Retries
/// zählen als Erfolg, nicht als Fehler).
#[derive(Deserialize, Debug, Clone)]
pub struct SubmitOutcome {
    pub accepted: u64,
    pub duplicates: u64,
}

/// Eine wartende Hülle aus `GET /messages`.
#[derive(Deserialize, Debug, Clone)]
pub struct WaitingEnvelope {
    pub id: String,
    pub envelope: String,
    pub received_at: u64,
}

#[derive(Deserialize)]
struct FetchResponse {
    messages: Vec<WaitingEnvelope>,
}

#[derive(Serialize)]
struct SubmitRequest<'a> {
    envelopes: &'a [OutgoingEnvelope],
}

#[derive(Serialize)]
struct AckRequest<'a> {
    ids: &'a [String],
}

#[derive(Deserialize)]
struct AckResponse {
    removed: u64,
}

impl DeliveryClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// `POST /messages`: reicht einen Stapel Hüllen ein.
    pub async fn submit(
        &self,
        access_token: &str,
        envelopes: &[OutgoingEnvelope],
    ) -> Result<SubmitOutcome, ClientError> {
        let response = self
            .http
            .post(format!("{}/messages", self.base_url))
            .bearer_auth(access_token)
            .json(&SubmitRequest { envelopes })
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /messages`: die wartenden Hüllen des eigenen Geräts, älteste
    /// zuerst. Räumt nichts weg; das tut erst `ack`.
    pub async fn fetch(&self, access_token: &str) -> Result<Vec<WaitingEnvelope>, ClientError> {
        let response = self
            .http
            .get(format!("{}/messages", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        let body: FetchResponse = parse_json(response).await?;
        Ok(body.messages)
    }

    /// `POST /messages/ack`: bestätigt verarbeitete Hüllen; liefert, wie
    /// viele tatsächlich entfernt wurden (idempotent).
    pub async fn ack(&self, access_token: &str, ids: &[String]) -> Result<u64, ClientError> {
        let response = self
            .http
            .post(format!("{}/messages/ack", self.base_url))
            .bearer_auth(access_token)
            .json(&AckRequest { ids })
            .send()
            .await
            .map_err(transport)?;
        let body: AckResponse = parse_json(response).await?;
        Ok(body.removed)
    }
}
