//! HTTP-Schicht der Integrations-API (F070, F080, F100).
//!
//! Fremdprojekte sind Mandanten: sie tauschen client_id plus
//! Client-Secret gegen ein kurzlebiges Token (Client-Credentials-Zuschnitt)
//! und rufen damit `POST /integrations/{tenant}/notify` und
//! `GET /integrations/{tenant}/presence/{handle}`. Jeder Mandant hat
//! eigene Scopes und ein eigenes Rate-Limit (pflichtenheft.md 5.2).
//!
//! Benachrichtigungen sind markierte Maschinen-Hinweise mit minimalem
//! Inhalt, kein Ende-zu-Ende-Chat: der Absender ist ein Server. Der
//! Hinweis trägt nur Mandant und Titel, die Details holt der Nutzer im
//! Fremdprojekt (pflichtenheft.md 5.2 "ehrlich abgegrenzt").
//!
//! [ANNAHME: Mandanten legt der Betrieb über die interne Route
//! POST /internal/tenants an (Shared Secret wie überall); eine
//! Admin-Oberfläche ist nicht Teil dieser Etappe. Token-Laufzeit 1 Stunde.]

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth;
use crate::domain::{Tenant, KNOWN_SCOPES, SCOPE_NOTIFY, SCOPE_PRESENCE};
use crate::realtime_client::RealtimeGateway;
use crate::store::{NewTenant, StoreError, TenantStore};
use common::identity_client::IdentityGateway;
use common::rate::RateLimiter;

/// Token-Laufzeit. [ANNAHME: 1 Stunde; lang genug, dass der Tausch nicht
/// im heißen Pfad liegt, kurz genug, dass ein geleaktes Token schnell
/// verfällt. Die Doku nennt keinen Wert.]
const TOKEN_TTL_SECS: u64 = 3600;
/// Obergrenze für den Titel einer Benachrichtigung: minimaler Inhalt ist
/// Absicht, kein Platz für ganze Berichte.
const MAX_TITLE_CHARS: usize = 200;

/// Geteilter Zustand: Mandanten-Ablage, identity- und delivery-Anbindung,
/// Rate-Limiter und der Guard der internen Anlage-Route.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn TenantStore>,
    identity: Arc<dyn IdentityGateway>,
    realtime: Arc<dyn RealtimeGateway>,
    limiter: Arc<RateLimiter>,
    /// SHA-256-Digest des Shared Secrets; None = interne Route aus.
    internal_token_hash: Option<String>,
}

impl AppState {
    pub fn new(
        store: Arc<dyn TenantStore>,
        identity: Arc<dyn IdentityGateway>,
        realtime: Arc<dyn RealtimeGateway>,
    ) -> Self {
        Self {
            store,
            identity,
            realtime,
            limiter: Arc::new(RateLimiter::default()),
            internal_token_hash: None,
        }
    }

    /// Schaltet die interne Mandanten-Anlage frei (Shared Secret).
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
        .route(
            "/",
            get(|| async { "SecureMessenger integrations service" }),
        )
        .route("/integrations/token", post(token))
        .route("/integrations/{tenant}/notify", post(notify))
        .route("/integrations/{tenant}/presence/{handle}", get(presence));
    // Ohne konfiguriertes Secret existiert die Anlage-Route nicht
    // (gleiches Muster wie die /internal-Routen von identity/delivery).
    if state.internal_token_hash.is_some() {
        router = router.route("/internal/tenants", post(create_tenant));
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

fn invalid_token() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Mandanten-Token ist ungültig oder abgelaufen",
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

/// Löst das Bearer-Token zum Mandanten auf und prüft, dass der Pfad-
/// Mandant zum Token passt: ein Token von Projekt A darf nie unter dem
/// Namen von Projekt B agieren (F100). Backend-Fehler werden 500.
async fn authenticate_tenant(
    st: &AppState,
    headers: &HeaderMap,
    path_tenant: &str,
) -> Result<Tenant, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(invalid_token());
    };
    let tenant = match st.store.find_token(&auth::token_hash(token)).await {
        Ok(Some(tenant)) => tenant,
        Ok(None) => return Err(invalid_token()),
        Err(error) => {
            tracing::error!(%error, "Token-Aufloesung fehlgeschlagen");
            return Err(internal());
        }
    };
    if tenant.name != path_tenant {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "tenant_mismatch",
            "Token gehört zu einem anderen Mandanten",
        ));
    }
    Ok(tenant)
}

/// Scope- und Rate-Limit-Prüfung nach der Authentifizierung.
fn authorize(st: &AppState, tenant: &Tenant, scope: &'static str) -> Option<Response> {
    if !tenant.has_scope(scope) {
        return Some(api_error(
            StatusCode::FORBIDDEN,
            "missing_scope",
            format!("Mandant hat den Scope '{scope}' nicht"),
        ));
    }
    if let Err(retry_after) = st.limiter.check(&tenant.id, tenant.rate_limit) {
        return Some(common::rate::too_many_requests(retry_after));
    }
    None
}

/// Der Token-Request als standardkonformer OAuth2-Client-Credentials-Grant
/// (RFC 6749, Abschnitt 4.4): `application/x-www-form-urlencoded` mit
/// `grant_type`. Die Client-Zugangsdaten kommen entweder im HTTP-Basic-Header
/// oder im Body (`client_secret_basic` bzw. `client_secret_post`), damit jede
/// gängige OAuth2-Bibliothek in ihrer Standard-Konfiguration anbinden kann.
#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    /// Optional angefragte Scopes (leerzeichengetrennt). Muss eine Teilmenge
    /// der Mandanten-Scopes sein und verengt das ausgestellte Token auf genau
    /// diese Rechte (Least Privilege je Token). Fehlt der Parameter, traegt
    /// das Token die vollen Mandanten-Rechte.
    scope: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    /// Die tatsaechlich gewaehrten Scopes (leerzeichengetrennt, RFC 6749).
    scope: String,
}

/// OAuth2-Fehlerantwort (`{error, error_description}`, RFC 6749 Abschnitt
/// 5.2), getrennt vom `{code, message}`-Schema der uebrigen Routen, damit
/// Standard-OAuth2-Clients die Fehler maschinell verstehen. Bei
/// `invalid_client` gehoert ein `WWW-Authenticate: Basic` dazu.
fn oauth_error(status: StatusCode, error: &'static str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response();
    if error == "invalid_client" {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Basic realm=\"integrations\""),
        );
    }
    response
}

/// Client-Zugangsdaten aus dem HTTP-Basic-Header lesen (RFC 6749 Abschnitt
/// 2.3.1). `None`, wenn kein oder ein unlesbarer Basic-Header vorliegt.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = raw.strip_prefix("Basic ")?.trim();
    let decoded = String::from_utf8(BASE64.decode(encoded).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// `POST /integrations/token`: standardkonformer OAuth2-Client-Credentials-
/// Grant. Unbekannte Client-ID, falsches Secret und gesperrter Mandant
/// antworten identisch (`invalid_client`, 401), damit die Antwort nichts
/// ueber existierende Mandanten verraet.
async fn token(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenForm>,
) -> Response {
    if req.grant_type != "client_credentials" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Nur grant_type=client_credentials wird unterstuetzt",
        );
    }
    // Zugangsdaten bevorzugt aus dem HTTP-Basic-Header, sonst aus dem Body.
    let (client_id, client_secret) = match basic_credentials(&headers) {
        Some(pair) => pair,
        None => match (req.client_id, req.client_secret) {
            (Some(id), Some(secret)) => (id, secret),
            _ => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client_id und client_secret fehlen (HTTP-Basic oder im Body)",
                )
            }
        },
    };

    let found = match st.store.find_by_client_id(&client_id).await {
        Ok(found) => found,
        Err(error) => {
            tracing::error!(%error, "Mandanten-Suche fehlgeschlagen");
            return internal();
        }
    };
    // Argon2 ist bewusst teuer: nicht auf dem Request-Thread rechnen.
    let verified = match &found {
        Some((_, secret_hash)) => {
            let secret = client_secret.clone();
            let hash = secret_hash.clone();
            tokio::task::spawn_blocking(move || auth::verify_secret(&secret, &hash))
                .await
                .unwrap_or(false)
        }
        None => false,
    };
    let tenant = match (found, verified) {
        (Some((tenant, _)), true) if !tenant.disabled => tenant,
        _ => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client-ID oder Secret ist falsch",
            )
        }
    };

    // Angefragte Scopes muessen eine Teilmenge der Mandanten-Rechte sein.
    // Ein leerer oder fehlender scope-Parameter bedeutet "gib die vollen
    // Mandanten-Rechte" (RFC 6749 3.3: scope ist optional); ein angefragter,
    // engerer Satz verengt das Token auf genau diese Rechte (Least Privilege).
    let granted: Vec<String> = match req.scope.as_deref() {
        Some(requested) if requested.split_whitespace().next().is_some() => {
            let asked: Vec<String> = requested.split_whitespace().map(String::from).collect();
            if let Some(unknown) = asked.iter().find(|s| !tenant.has_scope(s)) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    &format!("Scope '{unknown}' liegt nicht beim Mandanten"),
                );
            }
            asked
        }
        _ => tenant.scopes.clone(),
    };

    let access_token = auth::new_tenant_token();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
        + TOKEN_TTL_SECS;
    if let Err(error) = st
        .store
        .save_token(
            &auth::token_hash(&access_token),
            &tenant.id,
            &granted,
            expires_at,
        )
        .await
    {
        tracing::error!(%error, "Token-Ablage fehlgeschlagen");
        return internal();
    }
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: TOKEN_TTL_SECS,
            scope: granted.join(" "),
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct NotifyRequest {
    handle: String,
    title: String,
}

#[derive(Serialize)]
struct NotifyResponse {
    /// Zielgeräte des Kontos (gültige Gerätemenge laut identity).
    devices: u32,
    /// Davon gerade verbunden; nur informativ, nicht verbundene Geräte
    /// verpassen den Hinweis (Hinweis-Semantik, Stand lebt im Projekt).
    connected: u32,
}

/// `POST /integrations/{tenant}/notify`: markierte Maschinen-
/// Benachrichtigung an alle Geräte eines Nutzers (F070).
async fn notify(
    State(st): State<AppState>,
    Path(path_tenant): Path<String>,
    headers: HeaderMap,
    Json(req): Json<NotifyRequest>,
) -> Response {
    let tenant = match authenticate_tenant(&st, &headers, &path_tenant).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if let Some(denied) = authorize(&st, &tenant, SCOPE_NOTIFY) {
        return denied;
    }
    let title = req.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_title",
            format!("Titel: 1 bis {MAX_TITLE_CHARS} Zeichen"),
        );
    }
    let account = match st.identity.account_devices(&req.handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown_user",
                format!("Nutzer '{}' ist unbekannt", req.handle),
            )
        }
        Err(error) => {
            tracing::error!(%error, "Nutzer-Aufloesung fehlgeschlagen");
            return internal();
        }
    };
    let device_ids: Vec<String> = account.devices.iter().map(|d| d.id.clone()).collect();
    if device_ids.is_empty() {
        // Konto ohne gültige Geräte: nichts zuzustellen, aber kein Fehler.
        return (
            StatusCode::OK,
            Json(NotifyResponse {
                devices: 0,
                connected: 0,
            }),
        )
            .into_response();
    }
    // Das Event, wie es der Client sieht: markiert als Maschinen-
    // Benachrichtigung, mit Mandant und Titel, sonst nichts.
    let event = json!({
        "event": "integration.notification",
        "tenant": tenant.name,
        "title": title,
    });
    match st.realtime.push_event(&device_ids, event).await {
        Ok(connected) => (
            StatusCode::OK,
            Json(NotifyResponse {
                devices: device_ids.len() as u32,
                connected,
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "Event-Zustellung fehlgeschlagen");
            internal()
        }
    }
}

#[derive(Serialize)]
struct PresenceResponse {
    handle: String,
    /// true, sobald irgendein Gerät des Kontos verbunden ist. Mehr
    /// Auflösung (welches Gerät, seit wann) gibt die API bewusst nicht
    /// her: Präsenz ist schon so ein Metadaten-Zugeständnis.
    online: bool,
}

/// `GET /integrations/{tenant}/presence/{handle}`: Online-Status (F080).
/// [ANNAHME: Die Freigabe je Nutzer ("soweit der Nutzer es erlaubt")
/// braucht Nutzer-Einstellungen, die es noch nicht gibt; bis dahin ist
/// Präsenz für Mandanten pauschal sichtbar. Die Einstellungs-Etappe
/// ergänzt das Opt-out.]
async fn presence(
    State(st): State<AppState>,
    Path((path_tenant, handle)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authenticate_tenant(&st, &headers, &path_tenant).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if let Some(denied) = authorize(&st, &tenant, SCOPE_PRESENCE) {
        return denied;
    }
    let account = match st.identity.account_devices(&handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "unknown_user",
                format!("Nutzer '{handle}' ist unbekannt"),
            )
        }
        Err(error) => {
            tracing::error!(%error, "Nutzer-Aufloesung fehlgeschlagen");
            return internal();
        }
    };
    let device_ids: Vec<String> = account.devices.iter().map(|d| d.id.clone()).collect();
    let online = if device_ids.is_empty() {
        false
    } else {
        match st.realtime.query_presence(&device_ids).await {
            Ok(online_ids) => !online_ids.is_empty(),
            Err(error) => {
                tracing::error!(%error, "Praesenz-Abfrage fehlgeschlagen");
                return internal();
            }
        }
    };
    (StatusCode::OK, Json(PresenceResponse { handle, online })).into_response()
}

/// Guard der internen Anlage-Route (Digest-Vergleich wie überall).
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
struct CreateTenantRequest {
    name: String,
    scopes: Vec<String>,
    rate_limit: Option<u32>,
}

#[derive(Serialize)]
struct CreateTenantResponse {
    id: String,
    client_id: String,
    /// Das Klartext-Secret, genau einmal sichtbar. Danach existiert nur
    /// noch der Argon2id-Hash; verloren heißt neu anlegen.
    client_secret: String,
}

/// Mandanten-Name: klein, URL-tauglich, eindeutig lesbar.
fn valid_tenant_name(name: &str) -> bool {
    (3..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// `POST /internal/tenants`: legt einen Mandanten an (Betriebs-Route).
async fn create_tenant(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTenantRequest>,
) -> Response {
    if let Some(denied) = internal_denied(&st, &headers) {
        return denied;
    }
    if !valid_tenant_name(&req.name) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Name: 3 bis 64 Zeichen aus a-z, 0-9 und '-', nicht am Rand",
        );
    }
    if req.scopes.is_empty()
        || !req
            .scopes
            .iter()
            .all(|s| KNOWN_SCOPES.contains(&s.as_str()))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_scopes",
            format!("Scopes: nicht leer, erlaubt sind {KNOWN_SCOPES:?}"),
        );
    }
    let rate_limit = req.rate_limit.unwrap_or(60);
    if rate_limit == 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_rate_limit",
            "rate_limit muss mindestens 1 sein",
        );
    }

    let client_secret = auth::new_client_secret();
    let secret_for_hash = client_secret.clone();
    let secret_hash =
        match tokio::task::spawn_blocking(move || auth::hash_secret(&secret_for_hash)).await {
            Ok(Ok(hash)) => hash,
            _ => return internal(),
        };
    let tenant = NewTenant {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name.clone(),
        // Client-ID = Name: lesbar und zu Keycloak-Konventionen passend;
        // das Feld bleibt getrennt, falls die OIDC-Anbindung eigene IDs
        // vergibt (domain.rs).
        client_id: req.name.clone(),
        secret_hash,
        scopes: req.scopes,
        rate_limit,
    };
    let id = tenant.id.clone();
    match st.store.create(tenant).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(CreateTenantResponse {
                id,
                client_id: req.name,
                client_secret,
            }),
        )
            .into_response(),
        Err(StoreError::NameTaken) => api_error(
            StatusCode::CONFLICT,
            "name_taken",
            "Name ist schon vergeben",
        ),
        Err(error) => {
            tracing::error!(%error, "Mandanten-Anlage fehlgeschlagen");
            internal()
        }
    }
}
