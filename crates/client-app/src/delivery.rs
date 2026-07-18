//! Client der Zustellung (services/delivery, store-and-forward).
//!
//! `POST /messages` reicht Hüllen ein (eine je Zielgerät), `GET /messages`
//! holt die wartenden Hüllen des eigenen Geräts, `POST /messages/ack`
//! bestätigt verarbeitete. Die Schleife abholen - verarbeiten - bestätigen
//! ersetzt eine Pagination. Die Formen spiegeln
//! services/delivery/src/api.rs.
//!
//! Für den WebSocket-Hinweiskanal (`GET /ws`) liegt hier nur der
//! Rahmen-Vertrag (`ws_url`, `ws_auth_frame`, `parse_ws_event`): die
//! Socket-Schleife selbst gehört in die Plattform-Clients (CLI nativ über
//! tungstenite, Browser über gloo-net), weil diese Bibliothek keine
//! Laufzeit-Annahmen macht (kein eigenes tokio, siehe lib.rs).

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::http::{expect_success, parse_json, transport};

#[derive(Clone)]
pub struct DeliveryClient {
    base_url: String,
    http: reqwest::Client,
}

/// Eine ausgehende Hülle: client-erzeugte ID (Idempotenz), Empfänger-Handle,
/// dessen Server-Geräte-ID und der geframte Chiffretext (wire::seal).
/// Optional das Franking-Commitment (Base64), unter dem sich die Nachricht
/// später melden lässt (specs/sealed-sender-und-abuse.md).
#[derive(Serialize, Debug, Clone, Default)]
pub struct OutgoingEnvelope {
    pub id: String,
    pub recipient: String,
    pub device_id: String,
    pub envelope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking_tag: Option<String>,
    /// Ablauf als Unix-Sekunden (Disappearing Messages); optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
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

#[derive(Serialize)]
struct ReportRequest<'a> {
    message_id: &'a str,
    plaintext: &'a str,
    franking_key: &'a str,
}

#[derive(Deserialize)]
struct ReportResponse {
    verified: bool,
}

#[derive(Serialize)]
struct BlockRequest<'a> {
    handle: &'a str,
}

#[derive(Deserialize)]
struct BlocksResponse {
    blocked: Vec<String>,
}

#[derive(Deserialize)]
struct AckResponse {
    removed: u64,
}

#[derive(Deserialize)]
struct VapidKeyResponse {
    public_key: String,
}

#[derive(Serialize)]
struct PushSubscribeRequest<'a> {
    endpoint: &'a str,
    keys: PushKeys<'a>,
}

#[derive(Serialize)]
struct PushKeys<'a> {
    p256dh: &'a str,
    auth: &'a str,
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

    /// `POST /sealed`: reicht Sealed-Sender-Hüllen ein, absichtlich ohne
    /// Token. Ein Bearer würde den Absender gegenüber dem Dienst
    /// identifizieren und den Zweck der Versiegelung zunichtemachen; die
    /// Echtheit des Absenders steckt in der Zertifikatskette der Hülle.
    pub async fn submit_sealed(
        &self,
        envelopes: &[OutgoingEnvelope],
    ) -> Result<SubmitOutcome, ClientError> {
        let response = self
            .http
            .post(format!("{}/sealed", self.base_url))
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

    /// Die WebSocket-URL des Hinweiskanals zu dieser Basis-URL.
    pub fn ws_url(&self) -> String {
        ws_url(&self.base_url)
    }

    /// `GET /push/vapid-key`: der öffentliche VAPID-Schlüssel fürs Abonnieren
    /// (`applicationServerKey`). `None`, wenn der Server Web-Push nicht
    /// anbietet (404); dann blendet der Client die Funktion aus.
    pub async fn vapid_public_key(
        &self,
        access_token: &str,
    ) -> Result<Option<String>, ClientError> {
        let response = self
            .http
            .get(format!("{}/push/vapid-key", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: VapidKeyResponse = parse_json(response).await?;
        Ok(Some(body.public_key))
    }

    /// `POST /push/subscription`: legt das Browser-Push-Abo dieses Geräts ab
    /// (Endpoint plus die Abo-Schlüssel des Browsers).
    pub async fn push_subscribe(
        &self,
        access_token: &str,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
    ) -> Result<(), ClientError> {
        let response = self
            .http
            .post(format!("{}/push/subscription", self.base_url))
            .bearer_auth(access_token)
            .json(&PushSubscribeRequest {
                endpoint,
                keys: PushKeys { p256dh, auth },
            })
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `DELETE /push/subscription`: entfernt das Push-Abo dieses Geräts.
    pub async fn push_unsubscribe(&self, access_token: &str) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(format!("{}/push/subscription", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `POST /reports`: meldet eine Nachricht, indem der Empfänger Klartext
    /// und Franking-Schlüssel aufdeckt. Liefert, ob die Meldung das
    /// aufbewahrte Commitment öffnet (also beweisbar echt ist).
    pub async fn report(
        &self,
        access_token: &str,
        message_id: &str,
        plaintext: &[u8],
        franking_key: &[u8],
    ) -> Result<bool, ClientError> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let response = self
            .http
            .post(format!("{}/reports", self.base_url))
            .bearer_auth(access_token)
            .json(&ReportRequest {
                message_id,
                plaintext: &BASE64.encode(plaintext),
                franking_key: &BASE64.encode(franking_key),
            })
            .send()
            .await
            .map_err(transport)?;
        let body: ReportResponse = parse_json(response).await?;
        Ok(body.verified)
    }

    /// `POST /blocks`: blockiert ein Handle.
    pub async fn block(&self, access_token: &str, handle: &str) -> Result<(), ClientError> {
        let response = self
            .http
            .post(format!("{}/blocks", self.base_url))
            .bearer_auth(access_token)
            .json(&BlockRequest { handle })
            .send()
            .await
            .map_err(transport)?;
        crate::http::expect_success(response).await
    }

    /// `DELETE /blocks/{handle}`: hebt eine Blockierung auf.
    pub async fn unblock(&self, access_token: &str, handle: &str) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(format!("{}/blocks/{handle}", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        crate::http::expect_success(response).await
    }

    /// `GET /blocks`: die eigene Blockliste.
    pub async fn blocks(&self, access_token: &str) -> Result<Vec<String>, ClientError> {
        let response = self
            .http
            .get(format!("{}/blocks", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        let body: BlocksResponse = parse_json(response).await?;
        Ok(body.blocked)
    }

    /// `POST /groups`: legt eine Gruppe an (Mitglieder als Handles, vom
    /// Dienst zu Zielgeräten aufgelöst; der Ersteller wird Owner). `name` ist
    /// der server-sichtbare Gruppenname (leer erlaubt). Liefert die
    /// Anfangsepoche.
    pub async fn create_group(
        &self,
        access_token: &str,
        group_id: &str,
        name: &str,
        members: &[String],
    ) -> Result<GroupCreated, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups", self.base_url))
            .bearer_auth(access_token)
            .json(&CreateGroupRequest {
                group_id,
                name,
                members,
            })
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /groups/{id}/meta`: Name, Einstellungen und Rollen (nur für
    /// Mitglieder).
    pub async fn group_meta(
        &self,
        access_token: &str,
        group_id: &str,
    ) -> Result<GroupMetaInfo, ClientError> {
        let response = self
            .http
            .get(format!("{}/groups/{group_id}/meta", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /groups/{id}/roles`: befördert/degradiert ein Mitglied. Liefert
    /// die aktualisierte Verwaltungssicht.
    pub async fn group_set_role(
        &self,
        access_token: &str,
        group_id: &str,
        target: &str,
        role: GroupRole,
    ) -> Result<GroupMetaInfo, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups/{group_id}/roles", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "target": target, "role": role }))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /groups/{id}/transfer`: übergibt die Owner-Rolle.
    pub async fn group_transfer(
        &self,
        access_token: &str,
        group_id: &str,
        target: &str,
    ) -> Result<GroupMetaInfo, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups/{group_id}/transfer", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "target": target }))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /groups/{id}/info`: ändert Name und/oder Einstellungen.
    pub async fn group_update_info(
        &self,
        access_token: &str,
        group_id: &str,
        name: Option<&str>,
        settings: Option<GroupSettings>,
    ) -> Result<GroupMetaInfo, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups/{group_id}/info", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "name": name, "settings": settings }))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /groups/{id}/commit`: reicht einen Commit gegen `from_epoch`
    /// ein und verteilt die Commit-/Welcome-Hüllen. Ein veralteter Commit
    /// kommt als `ClientError::Api` mit Status 409 und Code `stale_epoch`
    /// zurück; der Aufrufer wendet dann gegen die neue Epoche neu an.
    pub async fn group_commit(
        &self,
        access_token: &str,
        group_id: &str,
        from_epoch: u64,
        members: &[String],
        fanout: &[GroupOutgoing],
    ) -> Result<GroupCommitOutcome, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups/{group_id}/commit", self.base_url))
            .bearer_auth(access_token)
            .json(&CommitRequest {
                from_epoch,
                members,
                fanout,
            })
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /groups/{id}/messages`: fächert eine Anwendungsnachricht an
    /// die Mitglieds-Geräte.
    pub async fn group_messages(
        &self,
        access_token: &str,
        group_id: &str,
        envelopes: &[GroupOutgoing],
    ) -> Result<SubmitOutcome, ClientError> {
        let response = self
            .http
            .post(format!("{}/groups/{group_id}/messages", self.base_url))
            .bearer_auth(access_token)
            .json(&GroupMessagesRequest { envelopes })
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }
}

/// Eine ausgehende Gruppen-Hülle: adressiert genau ein Mitglieds-Gerät.
#[derive(Serialize, Debug, Clone)]
pub struct GroupOutgoing {
    pub id: String,
    pub device_id: String,
    pub envelope: String,
}

/// Antwort von `POST /groups`.
#[derive(Deserialize, Debug, Clone)]
pub struct GroupCreated {
    pub epoch: u64,
    pub devices: usize,
}

/// Antwort von `POST /groups/{id}/commit` bei Erfolg.
#[derive(Deserialize, Debug, Clone)]
pub struct GroupCommitOutcome {
    pub epoch: u64,
    pub accepted: u64,
    pub duplicates: u64,
}

#[derive(Serialize)]
struct CreateGroupRequest<'a> {
    group_id: &'a str,
    name: &'a str,
    members: &'a [String],
}

/// Rolle eines Gruppenmitglieds (Server-durchgesetzt).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

impl GroupRole {
    pub fn label(self) -> &'static str {
        match self {
            GroupRole::Owner => "Besitzer",
            GroupRole::Admin => "Admin",
            GroupRole::Member => "Mitglied",
        }
    }
}

/// Wer darf eine geregelte Aktion: alle Mitglieder oder nur Staff.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GroupPolicy {
    All,
    Admins,
}

/// Gruppen-Einstellungen (spiegelt den Dienst).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupSettings {
    pub invite_policy: GroupPolicy,
    pub announcement: bool,
    pub info_policy: GroupPolicy,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberInfo {
    pub handle: String,
    pub role: GroupRole,
}

/// Verwaltungs-Sicht auf eine Gruppe (Name, Einstellungen, Rollen).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GroupMetaInfo {
    pub name: String,
    pub settings: GroupSettings,
    pub members: Vec<GroupMemberInfo>,
}

#[derive(Serialize)]
struct CommitRequest<'a> {
    from_epoch: u64,
    members: &'a [String],
    fanout: &'a [GroupOutgoing],
}

#[derive(Serialize)]
struct GroupMessagesRequest<'a> {
    envelopes: &'a [GroupOutgoing],
}

/// `GET /ws` als WebSocket-URL: `http` wird `ws`, `https` wird `wss`.
/// Andere Schemata bleiben unangetastet; der Verbindungsaufbau schlägt
/// dann beim Aufrufer fehl, mit dessen Fehlermeldung.
pub fn ws_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let switched = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{switched}/ws")
}

/// Der erste Frame nach dem Verbinden: die Auth binnen 10 Sekunden
/// (services/delivery/src/api.rs `WS_AUTH_TIMEOUT`). Als Frame statt
/// Header, weil Browser-WebSockets keine eigenen Header setzen können.
pub fn ws_auth_frame(access_token: &str) -> String {
    serde_json::json!({ "token": access_token }).to_string()
}

/// Ein Ereignis vom Hinweiskanal. Der Kanal transportiert nie Inhalte,
/// nur Weck-Hinweise und markierte Maschinen-Benachrichtigungen; nach
/// einem Hinweis holt der Client per `fetch` ab und bestätigt per `ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    /// Es warten Hüllen: jetzt `fetch` und `ack` fahren.
    MessageWaiting,
    /// Markierte Benachrichtigung eines Fremdprojekts (F070); trägt
    /// Mandant und Titel, die Details holt der Nutzer im Fremdprojekt.
    Notification { tenant: String, title: String },
    /// Unbekanntes, aber wohlgeformtes Event: ignorierbar, damit neue
    /// Server-Events alte Clients nicht brechen.
    Other { event: String },
}

/// Liest einen Text-Frame des Hinweiskanals. `None` bei Frames ohne
/// `event`-Feld; die wirft der Client weg, statt zu raten.
pub fn parse_ws_event(text: &str) -> Option<WsEvent> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let event = value.get("event")?.as_str()?;
    Some(match event {
        "message.waiting" => WsEvent::MessageWaiting,
        "integration.notification" => WsEvent::Notification {
            tenant: value
                .get("tenant")
                .and_then(|v| v.as_str())
                .unwrap_or("unbekannt")
                .to_string(),
            title: value
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        },
        other => WsEvent::Other {
            event: other.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_switches_scheme_and_appends_path() {
        assert_eq!(ws_url("http://127.0.0.1:8080/"), "ws://127.0.0.1:8080/ws");
        assert_eq!(ws_url("https://chat.example"), "wss://chat.example/ws");
    }

    #[test]
    fn parses_known_and_unknown_events() {
        assert_eq!(
            parse_ws_event(r#"{"event":"message.waiting"}"#),
            Some(WsEvent::MessageWaiting)
        );
        assert_eq!(
            parse_ws_event(
                r#"{"event":"integration.notification","tenant":"azubios","title":"Neue Aufgabe"}"#
            ),
            Some(WsEvent::Notification {
                tenant: "azubios".to_string(),
                title: "Neue Aufgabe".to_string()
            })
        );
        assert_eq!(
            parse_ws_event(r#"{"event":"später.erfunden"}"#),
            Some(WsEvent::Other {
                event: "später.erfunden".to_string()
            })
        );
        assert_eq!(parse_ws_event("kein json"), None);
        assert_eq!(parse_ws_event(r#"{"kein":"event"}"#), None);
    }
}
