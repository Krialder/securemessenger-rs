//! HTTP- und WebSocket-Schicht der Zustellung (F050, store-and-forward).
//!
//! `POST /messages` nimmt Hüllen an (eine je Zielgerät, idempotent über
//! die client-erzeugte ID), `GET /messages` holt die wartenden Hüllen des
//! eigenen Geräts, `POST /messages/ack` räumt bestätigte weg. `GET /ws`
//! hält die Echtzeit-Verbindung: der Server schickt nur Hinweise
//! (message.waiting) und markierte Maschinen-Benachrichtigungen, den
//! Chiffretext holt der Client selbst (schnittstellen.md "Echtzeit-Events").
//!
//! Dazu kommen /internal-Routen für andere Dienste (heute: integrations):
//! Events an verbundene Geräte stoßen und Präsenz abfragen. Wie bei
//! identity sind sie nur eingehängt, wenn INTERNAL_TOKEN gesetzt ist.
//!
//! Der Request trägt kein Absender-Feld und der Dienst speichert keinen
//! Absender. [ANNAHME: Bis zur Sealed-Sender-Etappe ist der Upload über
//! das Bearer-Token authentifiziert; der Dienst erfährt den Absender also
//! flüchtig aus der Session, legt ihn aber nirgends ab. Das anonyme
//! Sende-Credential ersetzt das, sobald der Client-Core es liefert.]
//!
//! Fehlerformat wie überall: JSON mit `code` und `message`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::NewMessage;
use crate::groups::{GroupError, GroupStore, InMemoryGroupStore};
use crate::hub::{HubEvent, RealtimeHub};
use crate::store::MessageStore;
use common::identity_client::{CallerIdentity, IdentityGateway};

/// Obergrenze je Annahme-Stapel: ein Fächer über alle Zielgeräte einer
/// Nachricht (Gruppe mit 50 Mitgliedern à 2 Geräte) plus Luft.
/// [ANNAHME: die Doku nennt keine Zahl.]
const MAX_BATCH: usize = 100;
/// Obergrenze je Hülle nach Base64-Dekodierung. [ANNAHME: 64 KiB; Medien
/// laufen über den Objektspeicher, nicht durch die Zustellung.]
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Abholgröße pro GET; die Ack-Schleife holt den Rest.
const FETCH_LIMIT: u32 = 100;
/// Obergrenze je Ack (mehrere Abholrunden auf einmal bestätigbar).
const MAX_ACK_BATCH: usize = 500;
/// Frist für die erste WebSocket-Nachricht (das Auth-Frame).
const WS_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Obergrenze je interner Event-Zustellung (Geräte eines Kontos plus Luft).
const MAX_INTERNAL_DEVICES: usize = 500;

/// Wer ist gerade verbunden? Geräte-ID auf Anzahl offener Sockets
/// (ein Gerät kann kurzzeitig doppelt verbunden sein, etwa beim
/// Reconnect). Prozesslokal wie die Nabe; Grundlage der Präsenz (F080).
type PresenceRegistry = Arc<Mutex<HashMap<String, u32>>>;

/// Geteilter Zustand: Ablage, identity-Anbindung, Echtzeit-Nabe,
/// Präsenz-Registry und der Guard der /internal-Routen.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn MessageStore>,
    groups: Arc<dyn GroupStore>,
    identity: Arc<dyn IdentityGateway>,
    hub: RealtimeHub,
    presence: PresenceRegistry,
    /// SHA-256-Digest des Shared Secrets; None = interne Routen aus.
    internal_token_hash: Option<String>,
}

impl AppState {
    pub fn new(store: Arc<dyn MessageStore>, identity: Arc<dyn IdentityGateway>) -> Self {
        Self {
            store,
            // Prozesslokale Gruppen-Ablage als Default (Tests, In-Memory-
            // Betrieb); der PG-Betrieb steckt über with_group_store die
            // persistente Umsetzung hinein.
            groups: Arc::new(InMemoryGroupStore::default()),
            identity,
            hub: RealtimeHub::new(),
            presence: Arc::new(Mutex::new(HashMap::new())),
            internal_token_hash: None,
        }
    }

    /// Setzt die persistente Gruppen-Ablage (PG-Betrieb).
    pub fn with_group_store(mut self, groups: Arc<dyn GroupStore>) -> Self {
        self.groups = groups;
        self
    }

    /// Schaltet die /internal-Routen frei (Shared Secret wie bei identity).
    pub fn with_internal_token(mut self, secret: &str) -> Self {
        self.internal_token_hash = Some(sha256_hex(secret));
        self
    }
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Baut den vollständigen Router des Dienstes.
pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", get(|| async { "SecureMessenger delivery service" }))
        .route("/messages", get(fetch).post(submit))
        .route("/messages/ack", post(acknowledge))
        .route("/groups", post(create_group))
        .route("/groups/{group_id}/commit", post(group_commit))
        .route("/groups/{group_id}/messages", post(group_messages))
        .route("/ws", get(websocket));
    // Wie bei identity: ohne konfiguriertes Secret existieren die
    // internen Routen nicht (echtes 404 statt 401-Raterei).
    if state.internal_token_hash.is_some() {
        router = router
            .route("/internal/events", post(internal_events))
            .route("/internal/presence/query", post(internal_presence));
    }
    router
        // 100 Hüllen à 64 KiB sind Base64-kodiert rund 9 MiB; das
        // axum-Default von 2 MiB wäre zu knapp.
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(axum::middleware::from_fn(common::metrics::track))
        .merge(common::ops_router())
        .with_state(state)
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

fn api_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

fn internal() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Interner Fehler",
    )
}

fn invalid_token() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Access-Token ist ungültig oder abgelaufen",
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

/// Löst das Bearer-Token über identity auf. Backend-Fehler (identity weg)
/// werden 500, nie 401: sonst meldet ein identity-Ausfall alle Clients ab.
async fn authenticate(st: &AppState, headers: &HeaderMap) -> Result<Option<CallerIdentity>, ()> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    match st.identity.introspect(token).await {
        Ok(identity) => Ok(identity),
        Err(error) => {
            tracing::error!(%error, "Token-Introspektion fehlgeschlagen");
            Err(())
        }
    }
}

/// Eine Hülle im Annahme-Request. `recipient` ist das Handle, die
/// Geräte-Auflösung prüft der Dienst gegen identity.
#[derive(Deserialize)]
struct EnvelopeJson {
    id: String,
    recipient: String,
    device_id: String,
    envelope: String,
    franking_tag: Option<String>,
}

#[derive(Deserialize)]
struct SubmitRequest {
    envelopes: Vec<EnvelopeJson>,
}

#[derive(Serialize)]
struct SubmitResponse {
    accepted: u64,
    /// Bereits bekannte Hüllen-IDs: der Beweis, dass ein Retry idempotent
    /// ankam, kein Fehler.
    duplicates: u64,
}

/// Kanonische UUID (Kleinschreibung, mit Bindestrichen), wie überall.
fn canonical_uuid(value: &str) -> bool {
    matches!(uuid::Uuid::try_parse(value), Ok(parsed) if parsed.to_string() == value)
}

/// Prüft eine Hülle formal; inhaltlich ist sie eine Blackbox.
fn validate_envelope(e: &EnvelopeJson) -> Result<(), String> {
    if !canonical_uuid(&e.id) {
        return Err("id muss eine UUID in kanonischer Form sein".to_string());
    }
    if !canonical_uuid(&e.device_id) {
        return Err("device_id muss eine UUID in kanonischer Form sein".to_string());
    }
    if e.recipient.trim().is_empty() {
        return Err("recipient fehlt".to_string());
    }
    match BASE64.decode(&e.envelope) {
        Ok(raw) if raw.is_empty() => Err("envelope ist leer".to_string()),
        Ok(raw) if raw.len() > MAX_ENVELOPE_BYTES => {
            Err(format!("envelope überschreitet {MAX_ENVELOPE_BYTES} Bytes"))
        }
        Ok(_) => Ok(()),
        Err(_) => Err("envelope ist kein gültiges Base64".to_string()),
    }?;
    if let Some(tag) = &e.franking_tag {
        if BASE64.decode(tag).is_err() {
            return Err("franking_tag ist kein gültiges Base64".to_string());
        }
    }
    Ok(())
}

/// `POST /messages`: nimmt einen Stapel Hüllen an, prüft die Zielgeräte
/// gegen identity und legt alles in einem Zug ab. Duplikate (Retries)
/// zählen getrennt und sind Erfolg.
async fn submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    if req.envelopes.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_batch",
            "Der Stapel enthält keine Hüllen",
        );
    }
    if req.envelopes.len() > MAX_BATCH {
        return api_error(
            StatusCode::BAD_REQUEST,
            "batch_too_large",
            format!("Höchstens {MAX_BATCH} Hüllen je Aufruf"),
        );
    }
    for envelope in &req.envelopes {
        if let Err(reason) = validate_envelope(envelope) {
            return api_error(StatusCode::BAD_REQUEST, "invalid_envelope", reason);
        }
    }

    // Zielgeräte auflösen: ein identity-Aufruf je Empfänger-Handle. Die
    // Antwort enthält nur gültige (nicht revozierte) Geräte; an revozierte
    // wird nicht mehr zugestellt.
    let mut accounts = std::collections::HashMap::new();
    for envelope in &req.envelopes {
        if accounts.contains_key(&envelope.recipient) {
            continue;
        }
        match st.identity.account_devices(&envelope.recipient).await {
            Ok(Some(account)) => {
                accounts.insert(envelope.recipient.clone(), account);
            }
            Ok(None) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "unknown_recipient",
                    format!("Konto '{}' ist unbekannt", envelope.recipient),
                )
            }
            Err(error) => {
                tracing::error!(%error, "Empfänger-Auflösung fehlgeschlagen");
                return internal();
            }
        }
    }
    let mut messages = Vec::with_capacity(req.envelopes.len());
    for envelope in &req.envelopes {
        let account = &accounts[&envelope.recipient];
        if !account.devices.iter().any(|d| d.id == envelope.device_id) {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown_device",
                format!(
                    "Gerät {} gehört nicht zur gültigen Gerätemenge von '{}'",
                    envelope.device_id, envelope.recipient
                ),
            );
        }
        messages.push(NewMessage {
            id: envelope.id.clone(),
            recipient_id: account.id.clone(),
            device_id: envelope.device_id.clone(),
            envelope: envelope.envelope.clone(),
            franking_tag: envelope.franking_tag.clone(),
        });
    }

    let devices: Vec<String> = messages.iter().map(|m| m.device_id.clone()).collect();
    match st.store.store_batch(messages).await {
        Ok(outcome) => {
            // Hinweis je Zielgerät, auch bei Duplikaten: der Hinweis ist
            // billig und trägt keinen Inhalt, das Gerät holt und sieht
            // selbst, ob etwas wartet.
            let mut seen = std::collections::HashSet::new();
            for device in devices {
                if seen.insert(device.clone()) {
                    st.hub.notify(&device);
                }
            }
            (
                StatusCode::OK,
                Json(SubmitResponse {
                    accepted: outcome.accepted,
                    duplicates: outcome.duplicates,
                }),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "Ablage des Hüllen-Stapels fehlgeschlagen");
            internal()
        }
    }
}

#[derive(Serialize)]
struct WaitingJson {
    id: String,
    envelope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    franking_tag: Option<String>,
    received_at: u64,
}

#[derive(Serialize)]
struct FetchResponse {
    messages: Vec<WaitingJson>,
}

/// `GET /messages`: wartende Hüllen des eigenen Geräts, älteste zuerst.
/// Räumt nichts weg, das tut erst das Ack; die Schleife
/// abholen - verarbeiten - bestätigen ersetzt eine Pagination.
async fn fetch(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    match st.store.fetch(&who.device_id, FETCH_LIMIT).await {
        Ok(messages) => (
            StatusCode::OK,
            Json(FetchResponse {
                messages: messages
                    .into_iter()
                    .map(|m| WaitingJson {
                        id: m.id,
                        envelope: m.envelope,
                        franking_tag: m.franking_tag,
                        received_at: m.received_at,
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "Abholen fehlgeschlagen");
            internal()
        }
    }
}

#[derive(Deserialize)]
struct AckRequest {
    ids: Vec<String>,
}

#[derive(Serialize)]
struct AckResponse {
    removed: u64,
}

/// `POST /messages/ack`: bestätigt verarbeitete Hüllen, danach sind sie
/// weg. Idempotent: unbekannte IDs zählen einfach nicht.
async fn acknowledge(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if req.ids.is_empty() || req.ids.len() > MAX_ACK_BATCH {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_ack",
            format!("Zwischen 1 und {MAX_ACK_BATCH} IDs je Aufruf"),
        );
    }
    if !req.ids.iter().all(|id| canonical_uuid(id)) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_ack",
            "IDs müssen UUIDs in kanonischer Form sein",
        );
    }
    match st.store.acknowledge(&who.device_id, &req.ids).await {
        Ok(removed) => (StatusCode::OK, Json(AckResponse { removed })).into_response(),
        Err(error) => {
            tracing::error!(%error, "Ack fehlgeschlagen");
            internal()
        }
    }
}

// ---- Gruppen-Zustellung (MLS Delivery Service) --------------------------

/// Eine Hülle im Gruppen-Fan-out: adressiert genau ein Mitglieds-Gerät.
/// Kein `recipient`-Handle wie bei 1:1, die Zielgeräte kommen aus der
/// Gruppen-Mitgliederliste.
#[derive(Deserialize)]
struct GroupEnvelopeJson {
    id: String,
    device_id: String,
    envelope: String,
}

fn validate_group_envelope(e: &GroupEnvelopeJson) -> Result<(), String> {
    if !canonical_uuid(&e.id) {
        return Err("id muss eine UUID in kanonischer Form sein".to_string());
    }
    if !canonical_uuid(&e.device_id) {
        return Err("device_id muss eine UUID in kanonischer Form sein".to_string());
    }
    match BASE64.decode(&e.envelope) {
        Ok(raw) if raw.is_empty() => Err("envelope ist leer".to_string()),
        Ok(raw) if raw.len() > MAX_ENVELOPE_BYTES => {
            Err(format!("envelope überschreitet {MAX_ENVELOPE_BYTES} Bytes"))
        }
        Ok(_) => Ok(()),
        Err(_) => Err("envelope ist kein gültiges Base64".to_string()),
    }
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    group_id: String,
    /// Handles der Mitglieder; der Dienst löst sie über identity zu den
    /// Zielgeräten auf (wie beim 1:1-Fan-out).
    members: Vec<String>,
}

#[derive(Serialize)]
struct GroupStateResponse {
    epoch: u64,
    devices: usize,
}

/// Löst eine Handle-Liste zu den gültigen Geräte-IDs auf (ein
/// identity-Aufruf je Handle). Fehler kommen als fertige Antwort zurück.
async fn resolve_member_devices(
    st: &AppState,
    handles: &[String],
) -> Result<Vec<String>, Response> {
    let mut devices = Vec::new();
    let mut seen_handle = std::collections::HashSet::new();
    for handle in handles {
        if !seen_handle.insert(handle.clone()) {
            continue;
        }
        match st.identity.account_devices(handle).await {
            Ok(Some(account)) => {
                for device in account.devices {
                    devices.push(device.id);
                }
            }
            Ok(None) => {
                return Err(api_error(
                    StatusCode::NOT_FOUND,
                    "unknown_member",
                    format!("Konto '{handle}' ist unbekannt"),
                ))
            }
            Err(error) => {
                tracing::error!(%error, "Mitglieder-Auflösung fehlgeschlagen");
                return Err(internal());
            }
        }
    }
    Ok(devices)
}

/// Legt die Hüllen ab und weckt die Zielgeräte; die gemeinsame
/// Fan-out-Logik von Gruppen-Commit und -Nachrichten. `recipient_id` ist
/// die Gruppen-ID: eine Gruppen-Hülle gehört der Gruppe, nicht einem
/// Konto (fetch und ack laufen ohnehin nur über die Geräte-ID). Liefert
/// das Ablage-Ergebnis oder eine fertige Fehlerantwort.
async fn fanout(
    st: &AppState,
    group_id: &str,
    envelopes: &[GroupEnvelopeJson],
) -> Result<crate::domain::StoreOutcome, Response> {
    let messages: Vec<NewMessage> = envelopes
        .iter()
        .map(|e| NewMessage {
            id: e.id.clone(),
            recipient_id: group_id.to_string(),
            device_id: e.device_id.clone(),
            envelope: e.envelope.clone(),
            franking_tag: None,
        })
        .collect();
    let devices: Vec<String> = messages.iter().map(|m| m.device_id.clone()).collect();
    match st.store.store_batch(messages).await {
        Ok(outcome) => {
            let mut seen = std::collections::HashSet::new();
            for device in devices {
                if seen.insert(device.clone()) {
                    st.hub.notify(&device);
                }
            }
            Ok(outcome)
        }
        Err(error) => {
            tracing::error!(%error, "Gruppen-Fan-out fehlgeschlagen");
            Err(internal())
        }
    }
}

/// `POST /groups`: legt eine Gruppe an (client-erzeugte ID, Epoche 0) und
/// löst die Mitglieder-Handles zu den Zielgeräten auf.
async fn create_group(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateGroupRequest>,
) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    if !canonical_uuid(&req.group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    if req.members.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_group",
            "Eine Gruppe braucht mindestens ein Mitglied",
        );
    }
    let devices = match resolve_member_devices(&st, &req.members).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    match st.groups.create_group(&req.group_id, &devices).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(GroupStateResponse {
                epoch: 0,
                devices: devices.len(),
            }),
        )
            .into_response(),
        Err(GroupError::GroupExists) => api_error(
            StatusCode::CONFLICT,
            "group_exists",
            "Eine Gruppe mit dieser ID existiert bereits",
        ),
        Err(error) => {
            tracing::error!(%error, "Gruppe anlegen fehlgeschlagen");
            internal()
        }
    }
}

#[derive(Deserialize)]
struct CommitRequest {
    /// Die Epoche, gegen die der Client committet; passt sie nicht zur
    /// aktuellen, ist der Commit veraltet (409).
    from_epoch: u64,
    /// Die Mitglieder nach dem Commit (Beitritt/Austritt), als Handles.
    members: Vec<String>,
    /// Commit- und Welcome-Hüllen, eine je Zielgerät.
    fanout: Vec<GroupEnvelopeJson>,
}

#[derive(Serialize)]
struct CommitResponse {
    epoch: u64,
    accepted: u64,
    duplicates: u64,
}

#[derive(Serialize)]
struct StaleEpochResponse {
    code: &'static str,
    message: String,
    current_epoch: u64,
}

/// `POST /groups/{id}/commit`: serialisiert einen Commit. Passt die
/// Epoche, wird sie erhöht, die Mitgliederliste ersetzt und der Commit an
/// die Geräte verteilt; sonst 409 mit der aktuellen Epoche (der Verlierer
/// wendet neu an). Das ist die Auflösungsregel für konkurrierende Commits.
async fn group_commit(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<CommitRequest>,
) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    if req.members.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_group",
            "Eine Gruppe braucht mindestens ein Mitglied",
        );
    }
    if req.fanout.len() > MAX_BATCH {
        return api_error(
            StatusCode::BAD_REQUEST,
            "batch_too_large",
            format!("Höchstens {MAX_BATCH} Hüllen je Commit"),
        );
    }
    for envelope in &req.fanout {
        if let Err(reason) = validate_group_envelope(envelope) {
            return api_error(StatusCode::BAD_REQUEST, "invalid_envelope", reason);
        }
    }
    let devices = match resolve_member_devices(&st, &req.members).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    match st.groups.commit(&group_id, req.from_epoch, &devices).await {
        Ok(epoch) => {
            // Erst nach dem erfolgreichen Epochenwechsel verteilen: der
            // Commit ist damit die serialisierende Instanz.
            match fanout(&st, &group_id, &req.fanout).await {
                Ok(outcome) => (
                    StatusCode::OK,
                    Json(CommitResponse {
                        epoch,
                        accepted: outcome.accepted,
                        duplicates: outcome.duplicates,
                    }),
                )
                    .into_response(),
                Err(response) => response,
            }
        }
        Err(GroupError::StaleEpoch { current }) => (
            StatusCode::CONFLICT,
            Json(StaleEpochResponse {
                code: "stale_epoch",
                message: format!("Commit veraltet, aktuelle Epoche {current}"),
                current_epoch: current,
            }),
        )
            .into_response(),
        Err(GroupError::UnknownGroup) => api_error(
            StatusCode::NOT_FOUND,
            "unknown_group",
            "Gruppe ist unbekannt",
        ),
        Err(error) => {
            tracing::error!(%error, "Gruppen-Commit fehlgeschlagen");
            internal()
        }
    }
}

#[derive(Deserialize)]
struct GroupMessagesRequest {
    envelopes: Vec<GroupEnvelopeJson>,
}

/// `POST /groups/{id}/messages`: verteilt Anwendungsnachrichten an die
/// Mitglieds-Geräte. Jede Ziel-Geräte-ID muss zur aktuellen Mitgliederliste
/// gehören, sonst würde die Gruppe zum offenen Relais.
async fn group_messages(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<GroupMessagesRequest>,
) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    if req.envelopes.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_batch",
            "Der Stapel enthält keine Hüllen",
        );
    }
    if req.envelopes.len() > MAX_BATCH {
        return api_error(
            StatusCode::BAD_REQUEST,
            "batch_too_large",
            format!("Höchstens {MAX_BATCH} Hüllen je Aufruf"),
        );
    }
    for envelope in &req.envelopes {
        if let Err(reason) = validate_group_envelope(envelope) {
            return api_error(StatusCode::BAD_REQUEST, "invalid_envelope", reason);
        }
    }
    let state = match st.groups.state(&group_id).await {
        Ok(state) => state,
        Err(GroupError::UnknownGroup) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown_group",
                "Gruppe ist unbekannt",
            )
        }
        Err(error) => {
            tracing::error!(%error, "Gruppenzustand nicht lesbar");
            return internal();
        }
    };
    let members: std::collections::HashSet<&String> = state.devices.iter().collect();
    for envelope in &req.envelopes {
        if !members.contains(&envelope.device_id) {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown_device",
                format!("Gerät {} ist kein Mitglied der Gruppe", envelope.device_id),
            );
        }
    }
    match fanout(&st, &group_id, &req.envelopes).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(SubmitResponse {
                accepted: outcome.accepted,
                duplicates: outcome.duplicates,
            }),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// Erste Nachricht auf dem WebSocket: das Auth-Frame. Als Nachricht statt
/// als Header, weil Browser-WebSockets keine eigenen Header setzen können.
#[derive(Deserialize)]
struct WsAuth {
    token: String,
}

fn waiting_event() -> Message {
    // Nur der Hinweis, nie Inhalt oder Absender (schnittstellen.md).
    Message::Text(r#"{"event":"message.waiting"}"#.into())
}

/// Guard der /internal-Routen: None = ausgewiesen, Some = fertige Absage.
/// Digest-Vergleich wie bei identity, damit das Secret nicht im Klartext
/// durch Vergleichslogik wandert.
fn internal_denied(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = st.internal_token_hash.as_deref() else {
        // Routen sind ohne Konfiguration gar nicht eingehängt; der Zweig
        // existiert nur als Sicherheitsnetz.
        return Some(api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Unbekannter Endpunkt",
        ));
    };
    let presented = headers
        .get("x-internal-token")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());
    match presented {
        Some(secret) if sha256_hex(secret) == expected => None,
        _ => Some(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_internal_token",
            "Internes Token fehlt oder ist falsch",
        )),
    }
}

/// Interner Event-Auftrag: ein fertiges Event-Objekt für eine Menge
/// Geräte. delivery reicht es nur durch und prüft nicht den Inhalt,
/// wohl aber die Form (Objekt mit `event`-Feld), damit Clients nie
/// unparsebaren Text bekommen.
#[derive(Deserialize)]
struct InternalEventRequest {
    device_ids: Vec<String>,
    event: serde_json::Value,
}

#[derive(Serialize)]
struct InternalEventResponse {
    /// Wie viele der Zielgeräte gerade verbunden sind. Nur informativ:
    /// nicht verbundene Geräte verpassen das Ereignis (Hinweis-Semantik).
    connected: u32,
}

/// `POST /internal/events`: verteilt ein Ereignis an verbundene Geräte
/// (heute: integration.notification aus dem integrations-Dienst).
async fn internal_events(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InternalEventRequest>,
) -> Response {
    if let Some(denied) = internal_denied(&st, &headers) {
        return denied;
    }
    if req.device_ids.is_empty() || req.device_ids.len() > MAX_INTERNAL_DEVICES {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_event",
            format!("Zwischen 1 und {MAX_INTERNAL_DEVICES} Geräte je Aufruf"),
        );
    }
    let is_marked_event = req
        .event
        .as_object()
        .and_then(|obj| obj.get("event"))
        .and_then(|v| v.as_str())
        .is_some();
    if !is_marked_event {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_event",
            "event muss ein Objekt mit einem event-Feld (String) sein",
        );
    }
    let event_json = req.event.to_string();
    let mut connected = 0u32;
    {
        let presence = st.presence.lock().expect("Presence-Lock nicht vergiftet");
        for device_id in &req.device_ids {
            if presence.contains_key(device_id) {
                connected += 1;
            }
        }
    }
    for device_id in req.device_ids {
        st.hub.publish(HubEvent::Notification {
            device_id,
            event_json: event_json.clone(),
        });
    }
    (StatusCode::OK, Json(InternalEventResponse { connected })).into_response()
}

#[derive(Deserialize)]
struct InternalPresenceRequest {
    device_ids: Vec<String>,
}

#[derive(Serialize)]
struct InternalPresenceResponse {
    /// Teilmenge der angefragten Geräte mit offener WebSocket-Verbindung.
    online: Vec<String>,
}

/// `POST /internal/presence/query`: welche der Geräte sind verbunden?
/// Bewusst POST mit Body statt GET mit Query, die Liste kann lang sein.
async fn internal_presence(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InternalPresenceRequest>,
) -> Response {
    if let Some(denied) = internal_denied(&st, &headers) {
        return denied;
    }
    if req.device_ids.is_empty() || req.device_ids.len() > MAX_INTERNAL_DEVICES {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            format!("Zwischen 1 und {MAX_INTERNAL_DEVICES} Geräte je Aufruf"),
        );
    }
    let presence = st.presence.lock().expect("Presence-Lock nicht vergiftet");
    let online = req
        .device_ids
        .into_iter()
        .filter(|id| presence.contains_key(id))
        .collect();
    drop(presence);
    (StatusCode::OK, Json(InternalPresenceResponse { online })).into_response()
}

/// RAII-Anmeldung in der Präsenz-Registry: der Eintrag verschwindet mit
/// dem Guard, egal auf welchem Weg die Socket-Schleife endet.
struct PresenceGuard {
    registry: PresenceRegistry,
    device_id: String,
}

impl PresenceGuard {
    fn register(registry: PresenceRegistry, device_id: &str) -> Self {
        {
            let mut map = registry.lock().expect("Presence-Lock nicht vergiftet");
            *map.entry(device_id.to_string()).or_insert(0) += 1;
        }
        Self {
            registry,
            device_id: device_id.to_string(),
        }
    }
}

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        let mut map = self.registry.lock().expect("Presence-Lock nicht vergiftet");
        if let Some(count) = map.get_mut(&self.device_id) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.device_id);
            }
        }
    }
}

/// `GET /ws`: Echtzeit-Hinweise für das authentifizierte Gerät.
async fn websocket(State(st): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| drive_socket(st, socket))
}

async fn drive_socket(st: AppState, mut socket: WebSocket) {
    // Auth-Frame binnen Frist, sonst ist die Verbindung wertlos.
    let first = tokio::time::timeout(WS_AUTH_TIMEOUT, socket.recv()).await;
    let Ok(Some(Ok(Message::Text(text)))) = first else {
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: 4401,
                reason: "auth_required".into(),
            })))
            .await;
        return;
    };
    let token = match serde_json::from_str::<WsAuth>(&text) {
        Ok(auth) => auth.token,
        Err(_) => {
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 4401,
                    reason: "auth_required".into(),
                })))
                .await;
            return;
        }
    };
    let device_id = match st.identity.introspect(&token).await {
        Ok(Some(who)) => who.device_id,
        Ok(None) => {
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 4401,
                    reason: "invalid_token".into(),
                })))
                .await;
            return;
        }
        Err(error) => {
            tracing::error!(%error, "WS-Introspektion fehlgeschlagen");
            // 1011 = interner Fehler; bewusst nicht 4401, der Client soll
            // neu verbinden statt sich abzumelden.
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 1011,
                    reason: "internal".into(),
                })))
                .await;
            return;
        }
    };

    // Ab jetzt ist das Gerät "online" (F080); der Guard räumt den
    // Eintrag auf jedem Rückweg wieder ab.
    let _presence = PresenceGuard::register(st.presence.clone(), &device_id);

    // Abonnieren, bevor der Bestand geprüft wird: was zwischen Prüfung
    // und Abo einträfe, ginge sonst verloren.
    let mut hints = st.hub.subscribe();
    if st.store.has_waiting(&device_id).await.unwrap_or(false)
        && socket.send(waiting_event()).await.is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            hint = hints.recv() => match hint {
                Ok(event) if event.device_id() == device_id => {
                    let message = match event {
                        HubEvent::MessageWaiting { .. } => waiting_event(),
                        HubEvent::Notification { event_json, .. } => {
                            Message::Text(event_json.into())
                        }
                    };
                    if socket.send(message).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                // Hinterhergehinkt: Ereignisse verpasst, womöglich unsere.
                // Ein unbedingter Hinweis ist billig und nie falsch, das
                // Gerät holt ab und sieht selbst. Verpasste
                // Benachrichtigungen sind verschmerzbar (Hinweis-Semantik).
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    if socket.send(waiting_event()).await.is_err() {
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                // Ping/Pong beantwortet axum selbst; Text nach dem
                // Auth-Frame hat keine Bedeutung und wird ignoriert.
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
        }
    }
}
