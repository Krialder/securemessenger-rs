//! HTTP-Schicht des Key-Transparency-Dienstes (F120).
//!
//! Öffentlich (schnittstellen.md "Key-Transparency-Beweise"):
//! `GET /kt/proof/{handle}` (Inklusionsbeweis, aktuelle Epoche),
//! `GET /kt/history/{handle}` (Versionshistorie für die Selbstprüfung),
//! `GET /kt/epoch/{n}` und `/kt/epoch/latest` (signierte Wurzeln),
//! `GET /kt/consistency?from=&to=` (Append-only-Beweis für Auditoren),
//! `GET /kt/info` (öffentliche Schlüssel zum Pinnen). Die Beweise sind
//! öffentlich: sie verraten ohne VRF-Schlüssel nichts über fremde
//! Handles, und Auditierbarkeit lebt von freiem Zugriff. [ANNAHME:
//! deshalb bewusst ohne Bearer-Auth, anders als die übrigen Dienste.]
//!
//! Intern: `POST /internal/updates` nimmt Schlüsseländerungen vom
//! identity-Dienst an (Shared Secret wie überall); veröffentlicht wird
//! epochenweise durch den Publisher in main.rs.
//!
//! Die Beweis-Strukturen gehen als opakes, Base64-kodiertes
//! bincode-serialisiertes akd-Objekt über die Leitung. [ANNAHME: das
//! Wire-Format der Beweise gehört dem Client-Core (er verifiziert mit
//! derselben akd-Version); ein eigenes JSON-Schema würde nur eine
//! zweite, fehleranfällige Serialisierung erfinden.]

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::directory::{DirectoryError, KtDirectory};
use crate::store::KtStore;

/// Obergrenze je Konsistenz-Anfrage: Auditoren holen große Zeiträume in
/// Schritten. [ANNAHME: 32 Epochen je Aufruf.]
const MAX_AUDIT_SPAN: u64 = 32;

#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn KtStore>,
    directory: Arc<KtDirectory>,
    /// SHA-256-Digest des Shared Secrets; None = interne Route aus.
    internal_token_hash: Option<String>,
}

impl AppState {
    pub fn new(store: Arc<dyn KtStore>, directory: Arc<KtDirectory>) -> Self {
        Self {
            store,
            directory,
            internal_token_hash: None,
        }
    }

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
        .route("/", get(|| async { "SecureMessenger kt service" }))
        .route("/kt/info", get(info))
        .route("/kt/proof/{handle}", get(proof))
        .route("/kt/history/{handle}", get(history))
        .route("/kt/epoch/latest", get(latest_epoch))
        .route("/kt/epoch/{epoch}", get(epoch))
        .route("/kt/consistency", get(consistency));
    if state.internal_token_hash.is_some() {
        router = router.route("/internal/updates", post(internal_updates));
    }
    router
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

fn directory_failure(error: DirectoryError) -> Response {
    tracing::error!(%error, "KT-Verzeichnis-Fehler");
    internal()
}

/// `GET /kt/info`: die öffentlichen Schlüssel, die Clients pinnen
/// (Wurzel-Signatur und VRF), plus die jüngste Epoche.
async fn info(State(st): State<AppState>) -> Response {
    let vrf_public = match st.directory.vrf_public_key().await {
        Ok(key) => BASE64.encode(key),
        Err(error) => return directory_failure(error),
    };
    let latest = match st.store.latest_epoch().await {
        Ok(latest) => latest,
        Err(error) => {
            tracing::error!(%error, "Wurzel-Abruf fehlgeschlagen");
            return internal();
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "root_signing_key": st.directory.signer().public_key_b64(),
            "vrf_public_key": vrf_public,
            "latest_epoch": latest.map(|e| e.epoch),
            "sth_format": "smkt.v1",
        })),
    )
        .into_response()
}

#[derive(Serialize)]
struct EpochJson {
    epoch: u64,
    root_hash: String,
    signature: String,
}

fn epoch_json(record: crate::store::EpochRecord) -> EpochJson {
    EpochJson {
        epoch: record.epoch,
        root_hash: BASE64.encode(record.root_hash),
        signature: BASE64.encode(record.signature),
    }
}

/// `GET /kt/epoch/latest`: die jüngste signierte Wurzel.
async fn latest_epoch(State(st): State<AppState>) -> Response {
    match st.store.latest_epoch().await {
        Ok(Some(record)) => (StatusCode::OK, Json(epoch_json(record))).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "no_epoch",
            "Noch keine Epoche veröffentlicht",
        ),
        Err(error) => {
            tracing::error!(%error, "Wurzel-Abruf fehlgeschlagen");
            internal()
        }
    }
}

/// `GET /kt/epoch/{n}`: die signierte Wurzel einer Epoche.
async fn epoch(State(st): State<AppState>, Path(epoch): Path<u64>) -> Response {
    match st.store.epoch(epoch).await {
        Ok(Some(record)) => (StatusCode::OK, Json(epoch_json(record))).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "unknown_epoch",
            "Epoche ist unbekannt",
        ),
        Err(error) => {
            tracing::error!(%error, "Wurzel-Abruf fehlgeschlagen");
            internal()
        }
    }
}

/// Serialisiert einen akd-Beweis für die Leitung (bincode + Base64).
fn proof_b64<T: serde::Serialize>(proof: &T) -> Option<String> {
    match bincode::serialize(proof) {
        Ok(bytes) => Some(BASE64.encode(bytes)),
        Err(error) => {
            tracing::error!(%error, "Beweis-Serialisierung fehlgeschlagen");
            None
        }
    }
}

/// `GET /kt/proof/{handle}`: Inklusionsbeweis zur aktuellen Epoche.
async fn proof(State(st): State<AppState>, Path(handle): Path<String>) -> Response {
    match st.directory.lookup(&handle).await {
        Ok(Some((proof, epoch_hash))) => {
            let Some(proof) = proof_b64(&proof) else {
                return internal();
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "handle": handle,
                    "epoch": epoch_hash.epoch(),
                    "root_hash": BASE64.encode(epoch_hash.hash()),
                    "proof": proof,
                })),
            )
                .into_response()
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "unknown_handle",
            "Handle ist nicht im Verzeichnis",
        ),
        Err(error) => directory_failure(error),
    }
}

/// `GET /kt/history/{handle}`: Versionshistorie (Selbstprüfung).
async fn history(State(st): State<AppState>, Path(handle): Path<String>) -> Response {
    match st.directory.history(&handle).await {
        Ok(Some((proof, epoch_hash))) => {
            let Some(proof) = proof_b64(&proof) else {
                return internal();
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "handle": handle,
                    "epoch": epoch_hash.epoch(),
                    "root_hash": BASE64.encode(epoch_hash.hash()),
                    "proof": proof,
                })),
            )
                .into_response()
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "unknown_handle",
            "Handle ist nicht im Verzeichnis",
        ),
        Err(error) => directory_failure(error),
    }
}

#[derive(Deserialize)]
struct ConsistencyQuery {
    from: u64,
    to: u64,
}

/// `GET /kt/consistency?from=&to=`: Append-only-Beweis für Auditoren.
async fn consistency(
    State(st): State<AppState>,
    Query(query): Query<ConsistencyQuery>,
) -> Response {
    if query.from == 0 || query.from >= query.to {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_range",
            "from muss >= 1 und kleiner als to sein",
        );
    }
    if query.to - query.from > MAX_AUDIT_SPAN {
        return api_error(
            StatusCode::BAD_REQUEST,
            "range_too_large",
            format!("Höchstens {MAX_AUDIT_SPAN} Epochen je Aufruf"),
        );
    }
    // Beide Epochen müssen existieren, sonst ist die Anfrage sinnlos.
    for epoch in [query.from, query.to] {
        match st.store.epoch(epoch).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "unknown_epoch",
                    format!("Epoche {epoch} ist unbekannt"),
                )
            }
            Err(error) => {
                tracing::error!(%error, "Wurzel-Abruf fehlgeschlagen");
                return internal();
            }
        }
    }
    match st.directory.audit(query.from, query.to).await {
        Ok(proof) => {
            let Some(proof) = proof_b64(&proof) else {
                return internal();
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "from": query.from,
                    "to": query.to,
                    "proof": proof,
                })),
            )
                .into_response()
        }
        Err(error) => directory_failure(error),
    }
}

/// Guard der internen Route (Digest-Vergleich wie überall).
fn internal_denied(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = st.internal_token_hash.as_deref() else {
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

#[derive(Deserialize)]
struct UpdateRequest {
    handle: String,
    /// Base64-kodiertes Commitment (identity berechnet es, kt speichert).
    value: String,
}

/// `POST /internal/updates`: identity meldet eine Schlüsseländerung.
/// Sie wartet im Log auf die nächste Epoche; die Antwort bestätigt nur
/// die Annahme.
async fn internal_updates(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateRequest>,
) -> Response {
    if let Some(denied) = internal_denied(&st, &headers) {
        return denied;
    }
    if req.handle.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "invalid_update", "handle fehlt");
    }
    let value = match BASE64.decode(&req.value) {
        Ok(value) if !value.is_empty() => value,
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_update",
                "value muss nicht-leeres Base64 sein",
            )
        }
    };
    match st.store.queue_update(&req.handle, &value).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => {
            tracing::error!(%error, "Update-Annahme fehlgeschlagen");
            internal()
        }
    }
}
