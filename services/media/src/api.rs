//! HTTP-Schicht des Medien-Dienstes (F180).
//!
//! `POST /media` nimmt einen verschlüsselten Blob an (roher Body, kein
//! JSON: Base64 würde ein Drittel Overhead auf Megabyte-Dateien legen)
//! und liefert eine Referenz; `GET /media/{ref}` liefert den Blob. Beides
//! Bearer-authentifiziert über die interne identity-API.
//!
//! [ANNAHME: Blob max. 50 MiB, Upload-Limit 30/min je Konto; die Doku
//! nennt keine Zahlen. Chunking und resumable Uploads sind eine offene
//! Frage (offene-fragen.md) und kommen später. Abruf mit Konto-Session;
//! Retention/GC verwaister Blobs folgt mit der Betriebs-Etappe.]

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use object_store::ObjectStore;
use serde::Serialize;

use common::identity_client::{CallerIdentity, IdentityGateway};
use common::rate::RateLimiter;

/// Obergrenze je Blob nach Verschlüsselung. [ANNAHME: 50 MiB.]
pub const MAX_MEDIA_BYTES: usize = 50 * 1024 * 1024;
/// Uploads je Konto und Minute. [ANNAHME: 30/min.]
const UPLOAD_RATE_LIMIT: u32 = 30;
/// Abrufe je Konto und Minute; großzügiger, ein Chatverlauf mit Bildern
/// lädt viele Blobs. [ANNAHME: 120/min.]
const DOWNLOAD_RATE_LIMIT: u32 = 120;

/// Geteilter Zustand: Blob-Ablage plus identity-Anbindung.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn ObjectStore>,
    identity: Arc<dyn IdentityGateway>,
    limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(store: Arc<dyn ObjectStore>, identity: Arc<dyn IdentityGateway>) -> Self {
        Self {
            store,
            identity,
            limiter: Arc::new(RateLimiter::default()),
        }
    }
}

/// Baut den vollständigen Router des Dienstes.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "SecureMessenger media service" }))
        .route("/media", post(upload))
        .route("/media/{reference}", get(download))
        // Etwas Luft über dem fachlichen Limit, damit die JSON-Fehler
        // aus dem Handler kommen; erst weit darüber greift axum hart.
        .layer(DefaultBodyLimit::max(MAX_MEDIA_BYTES + 1024 * 1024))
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
async fn authenticate(st: &AppState, headers: &HeaderMap) -> Result<CallerIdentity, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(invalid_token());
    };
    match st.identity.introspect(token).await {
        Ok(Some(caller)) => Ok(caller),
        Ok(None) => Err(invalid_token()),
        Err(error) => {
            tracing::error!(%error, "Token-Introspektion fehlgeschlagen");
            Err(internal())
        }
    }
}

/// Objektname zur Referenz. Flach unter einem Präfix; der Objektspeicher
/// verteilt selbst (S3-Partitionierung braucht keine Verzeichnisbäume).
fn object_path(reference: &str) -> object_store::path::Path {
    object_store::path::Path::from(format!("blobs/{reference}"))
}

#[derive(Serialize)]
struct UploadResponse {
    /// Die Referenz, die in der (verschlüsselten) Nachricht reist.
    r#ref: String,
}

/// `POST /media`: verschlüsselten Blob ablegen, Referenz zurück.
async fn upload(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match authenticate(&st, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(retry_after) = st
        .limiter
        .check(&format!("up:{}", caller.handle), UPLOAD_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    if body.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_media",
            "Der Body ist leer; erwartet wird der verschlüsselte Blob",
        );
    }
    if body.len() > MAX_MEDIA_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "media_too_large",
            format!("Blob überschreitet {MAX_MEDIA_BYTES} Bytes"),
        );
    }
    // Server-erzeugte, nicht ratbare Referenz. Der Inhalt ist für den
    // Dienst eine Blackbox und wird weder geprüft noch interpretiert.
    let reference = uuid::Uuid::new_v4().to_string();
    match st.store.put(&object_path(&reference), body.into()).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(UploadResponse { r#ref: reference }),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "Blob-Ablage fehlgeschlagen");
            internal()
        }
    }
}

/// `GET /media/{ref}`: Blob abrufen. Die Referenz ist eine Capability;
/// mehr Zugriffsschutz gäbe nur Metadaten preis (wer mit wem teilt).
async fn download(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(reference): Path<String>,
) -> Response {
    let caller = match authenticate(&st, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(retry_after) = st
        .limiter
        .check(&format!("down:{}", caller.handle), DOWNLOAD_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    // Referenzen sind UUIDs; alles andere ist gar nicht erst ein Lookup
    // (und kann keine Pfadspiele im Objektnamen treiben).
    if uuid::Uuid::try_parse(&reference).is_err() {
        return api_error(
            StatusCode::NOT_FOUND,
            "unknown_ref",
            "Referenz ist unbekannt",
        );
    }
    match st.store.get(&object_path(&reference)).await {
        Ok(result) => match result.bytes().await {
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response(),
            Err(error) => {
                tracing::error!(%error, "Blob-Lesen fehlgeschlagen");
                internal()
            }
        },
        Err(object_store::Error::NotFound { .. }) => api_error(
            StatusCode::NOT_FOUND,
            "unknown_ref",
            "Referenz ist unbekannt",
        ),
        Err(error) => {
            tracing::error!(%error, "Blob-Abruf fehlgeschlagen");
            internal()
        }
    }
}
