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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::NewMessage;
use crate::groups::{GroupError, GroupStore, InMemoryGroupStore};
use crate::hub::{HubEvent, RealtimeHub};
use crate::integrations_client::{IntegrationsGateway, NoopIntegrationsGateway};
use crate::push::{NoopPushSender, PushDelivery, PushSender};
use crate::store::{MessageStore, PushSubscription};
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
/// Sealed-Sender-Annahmen je Empfänger-Handle und Minute: die Route ist
/// anonym, also bremst statt eines Tokens der Empfänger-Posteingang.
/// [ANNAHME: 60/min; genug für lebhafte Chats über mehrere Geräte, zu
/// wenig für eine Flutung.]
const SEALED_RATE_LIMIT: u32 = 60;

/// Wer ist gerade verbunden? Geräte-ID auf Anzahl offener Sockets
/// (ein Gerät kann kurzzeitig doppelt verbunden sein, etwa beim
/// Reconnect). Prozesslokal wie die Nabe; Grundlage der Präsenz (F080).
type PresenceRegistry = Arc<Mutex<HashMap<String, u32>>>;

/// Präsenz je HANDLE (nicht je Gerät): zählt die verbundenen Geräte eines
/// Kontos, damit der Übergang online/offline nur beim ERSTEN bzw. LETZTEN
/// Gerät feuert. So bekommt integrations je Nutzer ein Ereignis, nicht je
/// Gerät (ein Konto mit zwei Geräten geht nicht zweimal online).
#[derive(Clone, Default)]
struct HandlePresence {
    counts: Arc<Mutex<HashMap<String, u32>>>,
    /// Fortlaufende Nummer je Übergang. Unter der counts-Sperre vergeben,
    /// damit die Nummern der Übergangs-Reihenfolge folgen; sie reist in den
    /// Webhook, damit ein Empfänger online/offline eindeutig ordnen kann
    /// (die Zustellung selbst ist Best effort und nicht geordnet).
    seq: Arc<AtomicU64>,
}

impl HandlePresence {
    /// Ein Gerät des Handles kommt; `Some(seq)`, wenn er dadurch online wird.
    fn arrive(&self, handle: &str) -> Option<u64> {
        let mut map = self
            .counts
            .lock()
            .expect("Handle-Presence-Lock nicht vergiftet");
        let count = map.entry(handle.to_string()).or_insert(0);
        *count += 1;
        // next_seq unter der Sperre: die Nummern folgen der Übergangsordnung.
        if *count == 1 {
            Some(self.seq.fetch_add(1, Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Ein Gerät des Handles geht; `Some(seq)`, wenn er dadurch offline wird.
    fn leave(&self, handle: &str) -> Option<u64> {
        let mut map = self
            .counts
            .lock()
            .expect("Handle-Presence-Lock nicht vergiftet");
        match map.get_mut(handle) {
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    map.remove(handle);
                    Some(self.seq.fetch_add(1, Ordering::Relaxed))
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

/// Geteilter Zustand: Ablage, identity-Anbindung, Echtzeit-Nabe,
/// Präsenz-Registry und der Guard der /internal-Routen.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn MessageStore>,
    groups: Arc<dyn GroupStore>,
    identity: Arc<dyn IdentityGateway>,
    hub: RealtimeHub,
    presence: PresenceRegistry,
    /// Präsenz je Handle (für die Online/Offline-Übergänge an integrations).
    handle_presence: HandlePresence,
    /// Anbindung an integrations für Präsenz-Webhooks; Noop, wenn keine
    /// INTEGRATIONS_URL gesetzt ist.
    integrations: Arc<dyn IntegrationsGateway>,
    /// Web-Push-Versand; Noop, wenn kein VAPID-Schlüssel gesetzt ist. Weckt
    /// Geräte, die gerade keinen WebSocket halten.
    push: Arc<dyn PushSender>,
    /// Geteiltes Geheimnis für kurzlebige TURN-Zugangsdaten (F2, coturn
    /// use-auth-secret); None = Anrufe aus (der Client blendet sie dann aus).
    turn_secret: Option<String>,
    /// STUN-/TURN-URLs, die der Client als ICE-Server bekommt.
    turn_urls: Vec<String>,
    /// SHA-256-Digest des Shared Secrets; None = interne Routen aus.
    internal_token_hash: Option<String>,
    /// Rate-Limits der anonymen Pfade (Sealed-Sender-Annahme).
    limiter: Arc<common::rate::RateLimiter>,
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
            handle_presence: HandlePresence::default(),
            integrations: Arc::new(NoopIntegrationsGateway),
            push: Arc::new(NoopPushSender),
            turn_secret: None,
            turn_urls: Vec::new(),
            internal_token_hash: None,
            limiter: Arc::new(common::rate::RateLimiter::default()),
        }
    }

    /// Setzt den Web-Push-Versand (VAPID); ohne diesen Aufruf ist Push aus.
    pub fn with_push(mut self, push: Arc<dyn PushSender>) -> Self {
        self.push = push;
        self
    }

    /// Setzt das TURN-Geheimnis und die ICE-Server-URLs (F2). Ohne diesen
    /// Aufruf sind 1:1-Anrufe aus (die /turn-credentials-Route meldet 503,
    /// der Client blendet den Anruf-Knopf aus).
    pub fn with_turn(mut self, secret: &str, urls: Vec<String>) -> Self {
        self.turn_secret = Some(secret.to_string());
        self.turn_urls = urls;
        self
    }

    /// Setzt die persistente Gruppen-Ablage (PG-Betrieb).
    pub fn with_group_store(mut self, groups: Arc<dyn GroupStore>) -> Self {
        self.groups = groups;
        self
    }

    /// Setzt die Anbindung an integrations für Präsenz-Webhooks.
    pub fn with_integrations(mut self, integrations: Arc<dyn IntegrationsGateway>) -> Self {
        self.integrations = integrations;
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
        .route("/sealed", post(submit_sealed))
        .route("/messages/ack", post(acknowledge))
        .route("/reports", post(report_message))
        .route("/blocks", get(list_blocks).post(add_block))
        .route("/blocks/{handle}", delete(remove_block))
        .route("/groups", post(create_group))
        .route("/groups/{group_id}/commit", post(group_commit))
        .route("/groups/{group_id}/messages", post(group_messages))
        // Verwaltung (Rollen, Übergabe, Name/Einstellungen). Name und
        // Rollen liest jeder Mitglied über /meta.
        .route("/groups/{group_id}/meta", get(group_meta))
        .route("/groups/{group_id}/roles", post(group_set_role))
        .route("/groups/{group_id}/transfer", post(group_transfer))
        .route("/groups/{group_id}/info", post(group_update_info))
        // Web-Push: der öffentliche VAPID-Schlüssel (offen, das ist ein
        // öffentlicher Schlüssel), Abo anlegen/entfernen (Bearer je Gerät).
        .route("/push/vapid-key", get(vapid_key))
        .route(
            "/push/subscription",
            post(push_subscribe).delete(push_unsubscribe),
        )
        // 1:1-Anrufe (F2): kurzlebige TURN-Zugangsdaten je angemeldetem Gerät.
        .route("/turn-credentials", get(turn_credentials))
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
    /// Ablauf als Unix-Sekunden (Disappearing Messages); optional.
    expires_at: Option<u64>,
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
    let sender = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller.handle,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    accept_envelopes(&st, &req, Some(&sender)).await
}

/// `POST /sealed`: nimmt Sealed-Sender-Hüllen an, absichtlich ohne
/// Authentifizierung. Ein Bearer-Token würde den Absender gegenüber dem
/// Dienst identifizieren und damit genau das zerstören, was Sealed Sender
/// herstellt; die Absender-Echtheit prüft der Empfänger über die
/// Zertifikatskette in der Hülle (crates/sealed-cert). Gegen Flutung
/// bremst ein Rate-Limit je Empfänger; die Blockliste kann hier nicht
/// serverseitig greifen (der Dienst kennt den Absender nicht), sie wirkt
/// beim Empfänger nach dem Entsiegeln.
///
/// [ANNAHME: Rate-Limit je Empfänger-Handle statt Signals Delivery-Tokens
/// (aus dem Profilschlüssel abgeleitete Empfangs-Berechtigungen). Die
/// Tokens sind die nächste Stufe und ersetzen dann nur diese Bremse,
/// nicht den Annahme-Pfad.]
async fn submit_sealed(State(st): State<AppState>, Json(req): Json<SubmitRequest>) -> Response {
    let mut seen = std::collections::HashSet::new();
    for envelope in &req.envelopes {
        if seen.insert(envelope.recipient.clone()) {
            if let Err(retry_after) = st
                .limiter
                .check(&format!("sealed:{}", envelope.recipient), SEALED_RATE_LIMIT)
            {
                return common::rate::too_many_requests(retry_after);
            }
        }
    }
    accept_envelopes(&st, &req, None).await
}

/// Der gemeinsame Annahme-Kern von `/messages` und `/sealed`: validieren,
/// Zielgeräte auflösen, Blockliste anwenden (nur wenn der Absender bekannt
/// ist), ablegen, Hinweise auslösen.
async fn accept_envelopes(st: &AppState, req: &SubmitRequest, sender: Option<&str>) -> Response {
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
    // Blocklisten je Empfänger einmal abfragen: hat ein Empfänger den
    // Absender blockiert, werden seine Hüllen still verworfen. Der Absender
    // erfährt das nicht (die Hüllen zählen als angenommen), sonst wäre die
    // Blockliste über die Antwort auslesbar. Auf dem Sealed-Pfad gibt es
    // keinen bekannten Absender, dort blockt der Empfänger nach dem
    // Entsiegeln.
    let mut blocked_recipients = std::collections::HashMap::new();
    for recipient in accounts.keys() {
        let blocked = match sender {
            Some(sender) => match st.store.is_blocked(recipient, sender).await {
                Ok(blocked) => blocked,
                Err(error) => {
                    tracing::error!(%error, "Blocklisten-Abfrage fehlgeschlagen");
                    return internal();
                }
            },
            None => false,
        };
        blocked_recipients.insert(recipient.clone(), blocked);
    }

    let mut messages = Vec::with_capacity(req.envelopes.len());
    let mut dropped = 0u64;
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
        if blocked_recipients[&envelope.recipient] {
            // Still verwerfen: der Empfänger hat den Absender blockiert.
            dropped += 1;
            continue;
        }
        messages.push(NewMessage {
            id: envelope.id.clone(),
            recipient_id: account.id.clone(),
            device_id: envelope.device_id.clone(),
            envelope: envelope.envelope.clone(),
            franking_tag: envelope.franking_tag.clone(),
            expires_at: envelope.expires_at,
        });
    }

    // Franking-Commitments der zugestellten Hüllen aufbewahren (fürs spätere
    // Verifizieren einer Meldung). Der Server sieht dabei nur das Commitment,
    // nie Klartext oder Franking-Schlüssel.
    let frankings: Vec<(String, Vec<u8>)> = req
        .envelopes
        .iter()
        .filter(|e| !blocked_recipients[&e.recipient])
        .filter_map(|e| {
            e.franking_tag
                .as_ref()
                .and_then(|tag| BASE64.decode(tag).ok())
                .map(|commitment| (e.id.clone(), commitment))
        })
        .collect();

    let devices: Vec<String> = messages.iter().map(|m| m.device_id.clone()).collect();
    match st.store.store_batch(messages).await {
        Ok(outcome) => {
            for (id, commitment) in frankings {
                if let Err(error) = st.store.store_franking(&id, &commitment).await {
                    tracing::error!(%error, "Franking-Commitment nicht aufbewahrt");
                }
            }
            // Hinweis je Zielgerät, auch bei Duplikaten: der Hinweis ist
            // billig und trägt keinen Inhalt, das Gerät holt und sieht
            // selbst, ob etwas wartet.
            let mut seen = std::collections::HashSet::new();
            for device in &devices {
                if seen.insert(device.clone()) {
                    st.hub.notify(device);
                }
            }
            // Offline-Geräte (kein WebSocket) zusätzlich per Web-Push wecken.
            wake_offline_devices(st, &devices);
            (
                StatusCode::OK,
                Json(SubmitResponse {
                    // Verworfene (blockierte) Hüllen zählen als angenommen,
                    // damit die Antwort die Blockliste nicht verrät.
                    accepted: outcome.accepted + dropped,
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

/// `GET /push/vapid-key`: der öffentliche VAPID-Schlüssel, den der Client als
/// `applicationServerKey` fürs Abo braucht. 404, wenn Push aus ist (kein
/// VAPID-Schlüssel konfiguriert); der Client blendet die Funktion dann aus.
async fn vapid_key(State(st): State<AppState>) -> Response {
    match st.push.public_key() {
        Some(public_key) => Json(VapidKeyResponse { public_key }).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "push_disabled",
            "Web-Push ist auf diesem Server nicht konfiguriert.",
        ),
    }
}

#[derive(Serialize)]
struct VapidKeyResponse {
    public_key: String,
}

/// `GET /turn-credentials`: kurzlebige TURN-Zugangsdaten für den ANGEMELDETEN
/// Nutzer (F2, coturn use-auth-secret). Nur angemeldet, damit der Relay kein
/// offener Bandbreiten-Proxy wird. 503, wenn Anrufe nicht konfiguriert sind
/// (der Client blendet den Anruf-Knopf dann aus).
async fn turn_credentials(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    let Some(secret) = st.turn_secret.as_deref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "calls_disabled",
            "1:1-Anrufe sind auf diesem Server nicht konfiguriert.",
        );
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let creds = crate::turn::credentials(secret, &st.turn_urls, now, crate::turn::TURN_TTL_SECS);
    Json(creds).into_response()
}

#[derive(Deserialize)]
struct PushSubscribeRequest {
    endpoint: String,
    keys: PushKeys,
}

#[derive(Deserialize)]
struct PushKeys {
    p256dh: String,
    auth: String,
}

/// `POST /push/subscription`: legt das Browser-Push-Abo des ANGEMELDETEN
/// Geräts ab (je Gerät eines; ein erneutes Abonnieren ersetzt das alte).
async fn push_subscribe(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PushSubscribeRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    // Nur https-Endpoints (die Push-Dienste sind alle https); das weist ein
    // offensichtlich falsches Feld früh ab.
    if !req.endpoint.starts_with("https://") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_endpoint",
            "Der Push-Endpoint muss eine https-URL sein.",
        );
    }
    // SSRF-Schutz: der Endpoint kommt vom Client; er darf nicht auf ein
    // internes/Loopback-Ziel zeigen, sonst würde der spätere Wake-POST den
    // Dienst ins interne Netz oder auf die Cloud-Metadaten schicken (dieselbe
    // Abwehr wie bei den Webhooks, common::ssrf).
    if common::ssrf::is_blocked_host(&req.endpoint) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_endpoint",
            "Der Push-Endpoint darf nicht auf ein internes oder Loopback-Ziel zeigen.",
        );
    }
    let subscription = PushSubscription {
        endpoint: req.endpoint,
        p256dh: req.keys.p256dh,
        auth: req.keys.auth,
    };
    match st
        .store
        .save_push_subscription(&who.device_id, &subscription)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            tracing::error!(%error, "Push-Abo nicht ablegbar");
            internal()
        }
    }
}

/// `DELETE /push/subscription`: entfernt das Push-Abo des angemeldeten Geräts.
async fn push_unsubscribe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    match st.store.remove_push_subscription(&who.device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            tracing::error!(%error, "Push-Abo nicht entfernbar");
            internal()
        }
    }
}

/// Weckt per Web-Push die Geräte aus `devices`, die gerade KEINEN WebSocket
/// halten (offline): ein verbundenes Gerät bekommt seinen Hinweis schon über
/// die Nabe. Nebenläufig und best effort; ein vom Push-Dienst als abgelaufen
/// gemeldetes Abo (`Gone`) wird entfernt. Ohne konfiguriertes VAPID (Noop)
/// passiert nichts.
fn wake_offline_devices(st: &AppState, devices: &[String]) {
    if st.push.public_key().is_none() {
        return;
    }
    let offline: Vec<String> = {
        let presence = st.presence.lock().expect("Presence-Lock nicht vergiftet");
        let mut seen = std::collections::HashSet::new();
        devices
            .iter()
            .filter(|d| seen.insert((*d).clone()) && !presence.contains_key(*d))
            .cloned()
            .collect()
    };
    for device in offline {
        let st = st.clone();
        tokio::spawn(async move {
            match st.store.push_subscription(&device).await {
                Ok(Some(subscription)) => match st.push.wake(&subscription).await {
                    Ok(PushDelivery::Delivered) => {}
                    Ok(PushDelivery::Gone) => {
                        // Endpoint tot: Abo wegräumen, sonst wecken wir ewig
                        // ins Leere. Aber NUR, wenn der Endpoint noch der
                        // gemeldete ist (sonst löschten wir ein inzwischen
                        // erneuertes, gültiges Abo).
                        if let Err(error) = st
                            .store
                            .remove_push_subscription_if_endpoint(&device, &subscription.endpoint)
                            .await
                        {
                            tracing::error!(%error, "Abgelaufenes Push-Abo nicht entfernbar");
                        }
                    }
                    Err(error) => tracing::warn!(%error, %device, "Push-Wecken fehlgeschlagen"),
                },
                Ok(None) => {}
                Err(error) => tracing::error!(%error, "Push-Abo nicht lesbar"),
            }
        });
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

// ---- Abuse-Abwehr: Meldungen und Blocklisten ----------------------------

#[derive(Deserialize)]
struct ReportRequest {
    /// Die Hüllen-ID der gemeldeten Nachricht (wie abgeholt).
    message_id: String,
    /// Der entschlüsselte Klartext (Base64), den der Empfänger aufdeckt.
    plaintext: String,
    /// Der Franking-Schlüssel `K_f` (Base64), den der Absender E2E
    /// mitschickte und den der Empfänger jetzt aufdeckt.
    franking_key: String,
}

#[derive(Serialize)]
struct ReportResponse {
    /// Ob die Meldung das aufbewahrte Commitment öffnet: nur dann ist sie
    /// echt (die Nachricht wurde wirklich so gesendet).
    verified: bool,
}

/// `POST /reports`: prüft eine Missbrauchs-Meldung. Der Empfänger deckt
/// Klartext und Franking-Schlüssel auf; der Server rechnet das Commitment
/// nach und vergleicht es mit dem aufbewahrten. Öffnet es, ist die Meldung
/// beweisbar echt; sonst ist sie gefälscht. Der Server lernt den Inhalt
/// erst durch die Meldung des Empfängers, nie vorher.
async fn report_message(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReportRequest>,
) -> Response {
    match authenticate(&st, &headers).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    }
    if !canonical_uuid(&req.message_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_report",
            "message_id muss eine UUID in kanonischer Form sein",
        );
    }
    let plaintext = match BASE64.decode(&req.plaintext) {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_report",
                "plaintext ist kein gültiges Base64",
            )
        }
    };
    let franking_key = match BASE64.decode(&req.franking_key) {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_report",
                "franking_key ist kein gültiges Base64",
            )
        }
    };
    let commitment = match st.store.franking_commitment(&req.message_id).await {
        Ok(Some(commitment)) => commitment,
        Ok(None) => {
            // Kein Commitment: die Nachricht trug kein Franking oder ist
            // längst weggeräumt. 404, nicht "nicht verifiziert".
            return api_error(
                StatusCode::NOT_FOUND,
                "no_franking",
                "Zu dieser Nachricht liegt kein Franking-Commitment vor",
            );
        }
        Err(error) => {
            tracing::error!(%error, "Franking-Commitment nicht lesbar");
            return internal();
        }
    };
    let verified = franking::verify(&franking_key, &plaintext, &commitment);
    (StatusCode::OK, Json(ReportResponse { verified })).into_response()
}

#[derive(Deserialize)]
struct BlockRequest {
    /// Das zu blockierende Handle.
    handle: String,
}

#[derive(Serialize)]
struct BlocksResponse {
    blocked: Vec<String>,
}

/// `POST /blocks`: blockiert ein Handle für das eigene Konto. Danach werden
/// Nachrichten dieses Absenders still verworfen (submit).
async fn add_block(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BlockRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if req.handle.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "invalid_block", "handle fehlt");
    }
    if req.handle == who.handle {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_block",
            "Das eigene Konto lässt sich nicht blockieren",
        );
    }
    match st.store.set_block(&who.handle, &req.handle, true).await {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(error) => {
            tracing::error!(%error, "Blockieren fehlgeschlagen");
            internal()
        }
    }
}

/// `DELETE /blocks/{handle}`: hebt eine Blockierung auf.
async fn remove_block(
    State(st): State<AppState>,
    axum::extract::Path(handle): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    match st.store.set_block(&who.handle, &handle, false).await {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(error) => {
            tracing::error!(%error, "Entblocken fehlgeschlagen");
            internal()
        }
    }
}

/// `GET /blocks`: die eigene Blockliste.
async fn list_blocks(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    match st.store.list_blocks(&who.handle).await {
        Ok(blocked) => (StatusCode::OK, Json(BlocksResponse { blocked })).into_response(),
        Err(error) => {
            tracing::error!(%error, "Blockliste nicht lesbar");
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
    /// Anzeigename der Gruppe (server-sichtbares Metadatum, damit die
    /// Einladung ihn zeigen kann). Leer erlaubt (Clients zeigen dann die
    /// Mitglieder).
    #[serde(default)]
    name: String,
    /// Handles der Mitglieder; der Dienst löst sie über identity zu den
    /// Zielgeräten auf (wie beim 1:1-Fan-out).
    members: Vec<String>,
}

#[derive(Serialize)]
struct GroupStateResponse {
    epoch: u64,
    devices: usize,
}

/// Gruppen-Name auf höchstens 128 Zeichen begrenzen (getrimmt) und ohne
/// Steuerzeichen. Leer ist zulässig: der Client fällt dann auf die
/// Mitglieder-Anzeige zurück.
fn valid_group_name(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed.chars().count() <= 128 && !trimmed.chars().any(|c| c.is_control())
}

/// Übersetzt Gruppen-Ablagefehler in HTTP-Antworten. Forbidden/NotMember
/// werden 403 mit der begründenden Meldung (die Regel ist kein Geheimnis).
fn group_error_response(error: GroupError) -> Response {
    match error {
        GroupError::UnknownGroup => api_error(
            StatusCode::NOT_FOUND,
            "unknown_group",
            "Gruppe ist unbekannt",
        ),
        GroupError::NotMember => api_error(
            StatusCode::FORBIDDEN,
            "not_member",
            "Kein Mitglied dieser Gruppe",
        ),
        GroupError::Forbidden(reason) => api_error(StatusCode::FORBIDDEN, "forbidden", reason),
        GroupError::StaleEpoch { current } => (
            StatusCode::CONFLICT,
            Json(StaleEpochResponse {
                code: "stale_epoch",
                message: format!("Commit veraltet, aktuelle Epoche {current}"),
                current_epoch: current,
            }),
        )
            .into_response(),
        GroupError::GroupExists => api_error(
            StatusCode::CONFLICT,
            "group_exists",
            "Eine Gruppe mit dieser ID existiert bereits",
        ),
        error => {
            tracing::error!(%error, "Gruppen-Ablagefehler");
            internal()
        }
    }
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
            expires_at: None,
        })
        .collect();
    let devices: Vec<String> = messages.iter().map(|m| m.device_id.clone()).collect();
    match st.store.store_batch(messages).await {
        Ok(outcome) => {
            let mut seen = std::collections::HashSet::new();
            for device in &devices {
                if seen.insert(device.clone()) {
                    st.hub.notify(device);
                }
            }
            // Offline-Mitglieder (kein WebSocket) zusätzlich per Web-Push wecken.
            wake_offline_devices(st, &devices);
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
    // Der Ersteller wird Owner der Gruppe; sein Handle kommt aus der
    // Introspektion (wurde bisher verworfen).
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if !canonical_uuid(&req.group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    if !valid_group_name(&req.name) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Gruppenname: höchstens 128 Zeichen, keine Steuerzeichen",
        );
    }
    if req.members.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_group",
            "Eine Gruppe braucht mindestens ein Mitglied",
        );
    }
    // Der Ersteller muss selbst in der Mitgliederliste stehen (er wird Owner).
    if !req.members.iter().any(|m| m == &who.handle) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "creator_not_member",
            "Der Ersteller muss selbst Mitglied der Gruppe sein",
        );
    }
    let devices = match resolve_member_devices(&st, &req.members).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    match st
        .groups
        .create_group(
            &req.group_id,
            crate::groups::NewGroup {
                name: req.name.trim(),
                creator: &who.handle,
                member_handles: &req.members,
                devices: &devices,
            },
        )
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(GroupStateResponse {
                epoch: 0,
                devices: devices.len(),
            }),
        )
            .into_response(),
        Err(error) => group_error_response(error),
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
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
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
    // Der Commit setzt die Rechte-Matrix durch (wer darf wen hinzufügen/
    // entfernen); der Aufrufer-Handle kommt aus der Introspektion.
    match st
        .groups
        .commit(
            &group_id,
            crate::groups::CommitContext {
                actor: &who.handle,
                expected_epoch: req.from_epoch,
                new_member_handles: &req.members,
                new_devices: &devices,
            },
        )
        .await
    {
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
        Err(error) => group_error_response(error),
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
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
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
    // Der Absender muss Mitglied sein; im Announcement-Modus zusätzlich Staff.
    // meta() prüft die Mitgliedschaft (NotMember sonst) und liefert die Rolle.
    let meta = match st.groups.meta(&group_id, &who.handle).await {
        Ok(meta) => meta,
        Err(error) => return group_error_response(error),
    };
    if meta.settings.announcement {
        let is_staff = meta
            .members
            .iter()
            .find(|m| m.handle == who.handle)
            .map(|m| {
                matches!(
                    m.role,
                    crate::groups::Role::Owner | crate::groups::Role::Admin
                )
            })
            .unwrap_or(false);
        if !is_staff {
            return api_error(
                StatusCode::FORBIDDEN,
                "announcement_only",
                "In dieser Gruppe dürfen nur Admins senden",
            );
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

/// `GET /groups/{id}/meta`: Name, Einstellungen und Rollen. Nur Mitglieder
/// (der Server kennt den Aufrufer aus der Introspektion).
async fn group_meta(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    match st.groups.meta(&group_id, &who.handle).await {
        Ok(meta) => (StatusCode::OK, Json(meta)).into_response(),
        Err(error) => group_error_response(error),
    }
}

#[derive(Deserialize)]
struct SetRoleRequest {
    target: String,
    role: crate::groups::Role,
}

/// `POST /groups/{id}/roles`: befördert/degradiert ein Mitglied (Rechte-Matrix
/// in groups.rs). Liefert die aktualisierte Verwaltungssicht.
async fn group_set_role(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<SetRoleRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    match st
        .groups
        .set_role(&group_id, &who.handle, &req.target, req.role)
        .await
    {
        Ok(meta) => (StatusCode::OK, Json(meta)).into_response(),
        Err(error) => group_error_response(error),
    }
}

#[derive(Deserialize)]
struct TransferRequest {
    target: String,
}

/// `POST /groups/{id}/transfer`: übergibt die Owner-Rolle. Nur der Owner.
async fn group_transfer(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<TransferRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    match st
        .groups
        .transfer_ownership(&group_id, &who.handle, &req.target)
        .await
    {
        Ok(meta) => (StatusCode::OK, Json(meta)).into_response(),
        Err(error) => group_error_response(error),
    }
}

#[derive(Deserialize)]
struct UpdateInfoRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    settings: Option<crate::groups::GroupSettings>,
}

/// `POST /groups/{id}/info`: ändert Name und/oder Einstellungen (nach
/// info_policy, Standard nur Staff).
async fn group_update_info(
    State(st): State<AppState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateInfoRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if !canonical_uuid(&group_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_group",
            "group_id muss eine UUID in kanonischer Form sein",
        );
    }
    if let Some(name) = &req.name {
        if !valid_group_name(name) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_name",
                "Gruppenname: höchstens 128 Zeichen, keine Steuerzeichen",
            );
        }
    }
    match st
        .groups
        .update_info(
            &group_id,
            &who.handle,
            req.name.as_deref().map(str::trim),
            req.settings,
        )
        .await
    {
        Ok(meta) => (StatusCode::OK, Json(meta)).into_response(),
        Err(error) => group_error_response(error),
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
/// dem Guard, egal auf welchem Weg die Socket-Schleife endet. Der Guard
/// führt zusätzlich die Handle-Präsenz und meldet integrations, wenn ein
/// Handle online (erstes Gerät) oder offline (letztes Gerät) geht.
struct PresenceGuard {
    registry: PresenceRegistry,
    handle_presence: HandlePresence,
    integrations: Arc<dyn IntegrationsGateway>,
    device_id: String,
    handle: String,
}

impl PresenceGuard {
    fn register(
        registry: PresenceRegistry,
        handle_presence: HandlePresence,
        integrations: Arc<dyn IntegrationsGateway>,
        device_id: &str,
        handle: &str,
    ) -> Self {
        {
            let mut map = registry.lock().expect("Presence-Lock nicht vergiftet");
            *map.entry(device_id.to_string()).or_insert(0) += 1;
        }
        // Nur der Übergang 0->1 des Handles ist "kommt online".
        if let Some(seq) = handle_presence.arrive(handle) {
            let gateway = integrations.clone();
            let handle = handle.to_string();
            tokio::spawn(async move { gateway.presence_changed(&handle, true, seq).await });
        }
        Self {
            registry,
            handle_presence,
            integrations,
            device_id: device_id.to_string(),
            handle: handle.to_string(),
        }
    }
}

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        {
            let mut map = self.registry.lock().expect("Presence-Lock nicht vergiftet");
            if let Some(count) = map.get_mut(&self.device_id) {
                *count -= 1;
                if *count == 0 {
                    map.remove(&self.device_id);
                }
            }
        }
        // Nur der Übergang 1->0 des Handles ist "geht offline". Der Aufruf
        // läuft best effort in einer eigenen Task (Drop ist synchron); ein
        // Fehler bleibt beim integrations-Gateway (best effort).
        if let Some(seq) = self.handle_presence.leave(&self.handle) {
            let gateway = self.integrations.clone();
            let handle = self.handle.clone();
            tokio::spawn(async move { gateway.presence_changed(&handle, false, seq).await });
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
    let (device_id, handle) = match st.identity.introspect(&token).await {
        Ok(Some(who)) => (who.device_id, who.handle),
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
    // Eintrag auf jedem Rückweg wieder ab und meldet integrations den
    // Handle-Übergang (erstes/letztes Gerät).
    let _presence = PresenceGuard::register(
        st.presence.clone(),
        st.handle_presence.clone(),
        st.integrations.clone(),
        &device_id,
        &handle,
    );

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

#[cfg(test)]
mod tests {
    use super::HandlePresence;

    #[test]
    fn handle_presence_transitions_on_first_and_last_device() {
        let presence = HandlePresence::default();
        // Erstes Gerät: Handle kommt online (mit einer Übergangs-Nummer).
        let online = presence.arrive("alice");
        assert!(online.is_some());
        // Zweites Gerät desselben Kontos: kein neuer Übergang.
        assert!(presence.arrive("alice").is_none());
        // Ein anderes Konto ist unabhängig.
        assert!(presence.arrive("bob").is_some());
        // Ein Gerät von alice geht: noch ist eines da, kein Übergang.
        assert!(presence.leave("alice").is_none());
        // Das letzte Gerät von alice geht: Handle geht offline.
        let offline = presence.leave("alice");
        assert!(offline.is_some());
        // Die Nummern folgen der Reihenfolge: offline nach online.
        assert!(offline.unwrap() > online.unwrap());
        // Ein weiteres leave auf einem schon offline-Handle feuert nicht.
        assert!(presence.leave("alice").is_none());
        // bob ist davon unberührt und geht mit seinem einzigen Gerät offline.
        assert!(presence.leave("bob").is_some());
    }
}
