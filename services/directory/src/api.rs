//! HTTP-Schicht des Schlüssel-Verzeichnisses (F110).
//!
//! `GET /keys/{handle}` liefert die Prekey-Bündel aller gültigen Geräte
//! eines Kontos, `POST /keys/prekeys` füllt den eigenen Pool nach,
//! `GET /keys/prekeys` zeigt die Restbestände (Nachfüllen ab 20,
//! datenmodell.md). Authentifiziert wird per Bearer-Token, aufgelöst über
//! die interne identity-API. Der Bündel-Abruf ist pro Abrufer
//! rate-limitiert (Pflichtenheft 5.3): er konsumiert fremden Vorrat.
//!
//! Fehlerformat wie überall: JSON mit `code` und `message`
//! (dokumentation/schnittstellen.md).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::domain::{DeviceBundle, Prekey, PrekeyKind};
use crate::store::{PrekeyStore, PrekeyUpload, StoreError};
use common::identity_client::{CallerIdentity, IdentityGateway};
use common::rate::RateLimiter;

/// Obergrenze je Upload-Stapel. Der Zielbestand sind rund 100 Einmal-Prekeys
/// pro Typ; 500 lässt Luft für Erstbefüllung beider Typen in einem Request
/// und deckelt trotzdem Speicher und Parse-Aufwand pro Aufruf.
const MAX_UPLOAD_BATCH: usize = 500;
/// Bündel-Abrufe je Abrufer und Minute: jeder Abruf konsumiert
/// Einmal-Prekeys der Zielgeräte, ein Amokläufer könnte Pools leeren.
/// [ANNAHME: 30/min; genug für Gruppen-Sitzungsaufbau, zu wenig zum
/// Leersaugen. Das Pflichtenheft fordert das Limit, nennt keine Zahl.]
const BUNDLE_RATE_LIMIT: u32 = 30;

/// Geteilter Zustand: Pool-Ablage plus identity-Anbindung.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn PrekeyStore>,
    identity: Arc<dyn IdentityGateway>,
    limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(store: Arc<dyn PrekeyStore>, identity: Arc<dyn IdentityGateway>) -> Self {
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
        .route("/", get(|| async { "SecureMessenger directory service" }))
        .route("/keys/prekeys", get(counts).post(upload))
        .route("/keys/{handle}", get(bundles))
        .route("/keys/{handle}/mls", get(mls_key_packages))
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

/// Ein Prekey im JSON-Format: client-erzeugte UUID plus opaker Schlüssel.
#[derive(Serialize, Deserialize)]
struct PrekeyJson {
    id: String,
    key: String,
}

fn prekey_json(p: Prekey) -> PrekeyJson {
    PrekeyJson {
        id: p.id,
        key: p.key,
    }
}

#[derive(Deserialize)]
struct UploadRequest {
    /// Neuer signierter Prekey (Rotation ersetzt den alten).
    signed_prekey: Option<PrekeyJson>,
    pq_signed_prekey: Option<PrekeyJson>,
    /// Nachschub für die Einmal-Pools.
    #[serde(default)]
    one_time_prekeys: Vec<PrekeyJson>,
    #[serde(default)]
    pq_one_time_prekeys: Vec<PrekeyJson>,
    /// Nachschub für den MLS-KeyPackage-Pool (Gruppen-Beitritte).
    #[serde(default)]
    mls_key_packages: Vec<PrekeyJson>,
}

#[derive(Serialize)]
struct CountsResponse {
    one_time: u64,
    pq_one_time: u64,
    mls_key_package: u64,
}

/// Prüft einen Prekey aus dem Request: ID muss kanonische UUID sein
/// (Primärschlüssel der Ablage), der Schlüssel gültiges, nicht leeres
/// Base64. Inhalt bleibt opak, der Server interpretiert keine Schlüssel.
fn validate_prekey(p: &PrekeyJson) -> Result<(), &'static str> {
    match uuid::Uuid::try_parse(&p.id) {
        Ok(parsed) if parsed.to_string() == p.id => {}
        _ => return Err("Prekey-ID muss eine UUID in kanonischer Form sein"),
    }
    match BASE64.decode(&p.key) {
        Ok(bytes) if !bytes.is_empty() => Ok(()),
        _ => Err("Prekey-Schlüssel muss nicht-leeres Base64 sein"),
    }
}

/// `POST /keys/prekeys`: füllt den Pool des aufrufenden Geräts. Welches
/// Gerät, bestimmt das Token, nie der Body: ein Gerät kann nur den eigenen
/// Vorrat befüllen. Antwortet mit den neuen Restbeständen.
async fn upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };

    let mut uploads = Vec::new();
    if let Some(p) = req.signed_prekey {
        uploads.push(PrekeyUpload {
            kind: PrekeyKind::Signed,
            prekey: Prekey {
                id: p.id,
                key: p.key,
            },
        });
    }
    if let Some(p) = req.pq_signed_prekey {
        uploads.push(PrekeyUpload {
            kind: PrekeyKind::PqSigned,
            prekey: Prekey {
                id: p.id,
                key: p.key,
            },
        });
    }
    for p in req.one_time_prekeys {
        uploads.push(PrekeyUpload {
            kind: PrekeyKind::OneTime,
            prekey: Prekey {
                id: p.id,
                key: p.key,
            },
        });
    }
    for p in req.pq_one_time_prekeys {
        uploads.push(PrekeyUpload {
            kind: PrekeyKind::PqOneTime,
            prekey: Prekey {
                id: p.id,
                key: p.key,
            },
        });
    }
    for p in req.mls_key_packages {
        uploads.push(PrekeyUpload {
            kind: PrekeyKind::MlsKeyPackage,
            prekey: Prekey {
                id: p.id,
                key: p.key,
            },
        });
    }

    if uploads.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_upload",
            "Der Upload enthält keine Prekeys",
        );
    }
    if uploads.len() > MAX_UPLOAD_BATCH {
        return api_error(
            StatusCode::BAD_REQUEST,
            "batch_too_large",
            "Zu viele Prekeys in einem Request",
        );
    }
    for upload in &uploads {
        let json = PrekeyJson {
            id: upload.prekey.id.clone(),
            key: upload.prekey.key.clone(),
        };
        if let Err(message) = validate_prekey(&json) {
            return api_error(StatusCode::BAD_REQUEST, "invalid_prekey", message);
        }
    }

    match st.store.upload(&who.device_id, uploads).await {
        Ok(()) => {}
        Err(StoreError::PrekeyIdTaken) => {
            return api_error(
                StatusCode::CONFLICT,
                "prekey_id_taken",
                "Eine Prekey-ID ist bereits vergeben",
            )
        }
        Err(StoreError::Backend(error)) => {
            tracing::error!(%error, "Prekey-Upload fehlgeschlagen");
            return internal();
        }
    }
    match st.store.counts(&who.device_id).await {
        Ok(counts) => (
            StatusCode::OK,
            Json(CountsResponse {
                one_time: counts.one_time,
                pq_one_time: counts.pq_one_time,
                mls_key_package: counts.mls_key_package,
            }),
        )
            .into_response(),
        Err(StoreError::Backend(error)) => {
            tracing::error!(%error, "Prekey-Zählung fehlgeschlagen");
            internal()
        }
        Err(_) => internal(),
    }
}

/// `GET /keys/prekeys`: Restbestände des eigenen Geräts, damit der Client
/// weiß, wann er nachfüllen muss (ab 20 verbleibenden).
async fn counts(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    match st.store.counts(&who.device_id).await {
        Ok(counts) => (
            StatusCode::OK,
            Json(CountsResponse {
                one_time: counts.one_time,
                pq_one_time: counts.pq_one_time,
                mls_key_package: counts.mls_key_package,
            }),
        )
            .into_response(),
        Err(StoreError::Backend(error)) => {
            tracing::error!(%error, "Prekey-Zählung fehlgeschlagen");
            internal()
        }
        Err(_) => internal(),
    }
}

#[derive(Serialize)]
struct DeviceBundleResponse {
    device_id: String,
    /// Öffentlicher Geräteschlüssel (Base64), gegen den der Client-Core
    /// die Prekey-Signaturen prüft.
    identity_key: String,
    not_after: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_prekey: Option<PrekeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_signed_prekey: Option<PrekeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    one_time_prekey: Option<PrekeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_one_time_prekey: Option<PrekeyJson>,
}

#[derive(Serialize)]
struct BundlesResponse {
    handle: String,
    /// Öffentlicher Konto-Identitätsschlüssel (Base64).
    identity_key: String,
    devices: Vec<DeviceBundleResponse>,
}

fn bundle_response(
    device_id: String,
    identity_key: String,
    not_after: u64,
    bundle: DeviceBundle,
) -> DeviceBundleResponse {
    DeviceBundleResponse {
        device_id,
        identity_key,
        not_after,
        signed_prekey: bundle.signed.map(prekey_json),
        pq_signed_prekey: bundle.pq_signed.map(prekey_json),
        one_time_prekey: bundle.one_time.map(prekey_json),
        pq_one_time_prekey: bundle.pq_one_time.map(prekey_json),
    }
}

/// `GET /keys/{handle}`: Prekey-Bündel aller gültigen Geräte des Kontos.
/// Konsumiert je Gerät einen Einmal-Prekey pro Typ, atomar; leere Pools
/// liefern das Bündel ohne Einmal-Prekey (Rückfall regelt der Client-Core).
async fn bundles(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    // Nur mit gültiger Session: die Bündel sind öffentliche Schlüssel,
    // aber der Abruf konsumiert Vorrat und bleibt deshalb Konten
    // vorbehalten - und ist pro Abrufer limitiert.
    let caller = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if let Err(retry_after) = st.limiter.check(&caller.handle, BUNDLE_RATE_LIMIT) {
        return common::rate::too_many_requests(retry_after);
    }

    let account = match st.identity.account_devices(&handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Konto ist unbekannt",
            )
        }
        Err(error) => {
            tracing::error!(%error, "Geräteabruf bei identity fehlgeschlagen");
            return internal();
        }
    };

    let mut devices = Vec::with_capacity(account.devices.len());
    for device in account.devices {
        let bundle = match st.store.take_bundle(&device.id).await {
            Ok(bundle) => bundle,
            Err(StoreError::Backend(error)) => {
                tracing::error!(%error, "Bündel-Abruf fehlgeschlagen");
                return internal();
            }
            Err(_) => return internal(),
        };
        devices.push(bundle_response(
            device.id,
            device.public_key,
            device.not_after,
            bundle,
        ));
    }
    (
        StatusCode::OK,
        Json(BundlesResponse {
            handle: account.handle,
            identity_key: account.identity_key,
            devices,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct MlsKeyPackageEntry {
    device_id: String,
    key_package: String,
}

#[derive(Serialize)]
struct MlsKeyPackagesResponse {
    handle: String,
    devices: Vec<MlsKeyPackageEntry>,
}

/// `GET /keys/{handle}/mls`: konsumiert je gültigem Gerät ein
/// MLS-KeyPackage, damit der Abrufer die Geräte in eine Gruppe einladen
/// kann. Getrennt vom PQXDH-Bündel-Abruf, weil KeyPackages nur beim
/// Gruppenbeitritt gebraucht werden. Geräte ohne freies KeyPackage
/// fehlen in der Antwort (der Client lädt sie in dieser Runde nicht ein).
/// Wie der Bündel-Abruf konsumiert er fremden Vorrat und ist deshalb
/// pro Abrufer limitiert.
async fn mls_key_packages(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    let caller = match authenticate(&st, &headers).await {
        Ok(Some(caller)) => caller,
        Ok(None) => return invalid_token(),
        Err(()) => return internal(),
    };
    if let Err(retry_after) = st.limiter.check(&caller.handle, BUNDLE_RATE_LIMIT) {
        return common::rate::too_many_requests(retry_after);
    }

    let account = match st.identity.account_devices(&handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Konto ist unbekannt",
            )
        }
        Err(error) => {
            tracing::error!(%error, "Geräteabruf bei identity fehlgeschlagen");
            return internal();
        }
    };

    let mut devices = Vec::new();
    for device in account.devices {
        match st.store.take_mls_key_package(&device.id).await {
            Ok(Some(prekey)) => devices.push(MlsKeyPackageEntry {
                device_id: device.id,
                key_package: prekey.key,
            }),
            // Kein freies Paket: das Gerät wird in dieser Runde nicht
            // eingeladen, kein Fehler.
            Ok(None) => {}
            Err(StoreError::Backend(error)) => {
                tracing::error!(%error, "KeyPackage-Abruf fehlgeschlagen");
                return internal();
            }
            Err(_) => return internal(),
        }
    }
    (
        StatusCode::OK,
        Json(MlsKeyPackagesResponse {
            handle: account.handle,
            devices,
        }),
    )
        .into_response()
}
