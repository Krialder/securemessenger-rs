//! HTTP-Schicht des Identitäts-Dienstes: Zustand, Router und Handler.
//!
//! Fehler gehen einheitlich als JSON mit `code` und `message` raus, wie in
//! dokumentation/schnittstellen.md festgelegt. Die Passwort-Arbeit läuft in
//! `spawn_blocking`, weil Argon2id bewusst teuer ist und sonst die
//! async-Worker blockieren würde.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::credential;
use crate::domain::{Account, Device};
use crate::kt_notify::{KtNotifier, NoopKtNotifier};
use crate::provision::{ProvisionRelay, PutError};
use crate::session::{
    InMemorySessionStore, RefreshError, SessionConfig, SessionIdentity, SessionStore,
};
use crate::store::{AccountStore, InMemoryStore, StoreError};
use common::rate::RateLimiter;

/// Login-Versuche je Handle und Minute: bremst Credential-Stuffing gegen
/// ein einzelnes Konto, ohne legitime Tipper auszusperren.
/// [ANNAHME: 10/min; das Pflichtenheft fordert strenge Limits auf Login
/// und Registrierung, nennt aber keine Zahlen.]
const LOGIN_RATE_LIMIT: u32 = 10;
/// Registrierungen je Handle und Minute. Der Schlüssel ist das Handle,
/// nicht die IP: hinter dem Ingress ist die Quell-IP nicht belastbar,
/// IP-Limits gehören an die Edge. [ANNAHME: 5/min.]
const REGISTER_RATE_LIMIT: u32 = 5;
/// Discovery-Runden je Abrufer und Minute. Die harte Bremse gegen
/// Enumeration: ohne Kenntnis des Handles ist jeder Wert nutzlos, und
/// mehr als eine Handvoll Auflösungen pro Minute braucht kein legitimer
/// Client. [ANNAHME: 20/min; die Spec fordert striktes Limit, nennt keine
/// Zahl.]
const DISCOVERY_RATE_LIMIT: u32 = 20;
/// Anzeigename-Abrufe je Abrufer und Minute. Großzügig, weil die Clients
/// beim App-Start je Kontakt einmal fragen und beim Chat-Öffnen auffrischen;
/// nur eine Bremse gegen missbräuchliches Reihum-Abfragen. [ANNAHME: 120/min.]
const PROFILE_RATE_LIMIT: u32 = 120;

/// Geteilter Zustand aller Handler.
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn AccountStore>,
    /// Session-Familien mit Access-/Refresh-Rotation (F020), siehe session.rs.
    sessions: Arc<dyn SessionStore>,
    session_config: SessionConfig,
    /// Hash, gegen den bei unbekanntem Handle geprüft wird, damit die
    /// Antwortzeit nicht verrät, ob ein Konto existiert.
    dummy_hash: Arc<str>,
    /// SHA-256 des Shared Secrets für /internal-Routen. Ohne Wert sind die
    /// Routen abgeschaltet (404). Als Hash gehalten, damit der Vergleich
    /// über Digests läuft und kein Klartext-Secret im Speicher liegt.
    internal_token_hash: Option<Arc<str>>,
    /// Rate-Limits der heißen Pfade (Login, Registrierung), je Handle.
    limiter: Arc<RateLimiter>,
    /// Meldet Schlüsseländerungen ans KT-Verzeichnis (F120); Noop, wenn
    /// kein kt-Dienst konfiguriert ist.
    kt: Arc<dyn KtNotifier>,
    /// OPRF-Schlüssel für Contact Discovery (specs/contact-discovery.md);
    /// ohne Wert sind die Discovery-Routen abgeschaltet.
    discovery_oprf: Option<Arc<oprf::ServerKey>>,
    /// Proof-of-Work-Schwierigkeit (führende Nullbits) bei der
    /// Registrierung; 0 = aus (specs/sealed-sender-und-abuse.md).
    pow_difficulty: u32,
    /// Aussteller der Sealed-Sender-Zertifikate; ohne Wert sind die
    /// Sealed-Sender-Routen abgeschaltet (specs/sealed-sender-und-abuse.md).
    sealed_sender: Option<Arc<sealed_cert::Issuer>>,
    /// Flüchtiger Relay für die QR-Kopplung: transportiert den unter einem
    /// Geheimnis verschlüsselten Kopplungs-Antrag vom neuen zum
    /// freischaltenden Gerät (provision.rs). Sieht nie Klartext.
    provision: Arc<ProvisionRelay>,
}

impl AppState {
    /// Zustand mit In-Memory-Ablage und Standard-Laufzeiten. Rechnet einmalig
    /// den Dummy-Hash und gehört deshalb in den Programmstart, nicht in den
    /// Request-Pfad.
    pub fn new_in_memory() -> Self {
        Self::with_session_config(SessionConfig::default())
    }

    /// Wie `new_in_memory`, aber mit eigenen Token-Laufzeiten (für Tests).
    pub fn with_session_config(session_config: SessionConfig) -> Self {
        Self::with_stores(
            Arc::new(InMemoryStore::default()),
            Arc::new(InMemorySessionStore::new(session_config)),
            session_config,
        )
    }

    /// Zustand mit beliebigen Ablagen; der Produktionspfad reicht hier die
    /// PostgreSQL-Stores hinein (main.rs).
    pub fn with_stores(
        store: Arc<dyn AccountStore>,
        sessions: Arc<dyn SessionStore>,
        session_config: SessionConfig,
    ) -> Self {
        let dummy = auth::hash_password(&auth::new_session_token())
            .expect("Argon2id mit Default-Parametern hasht fehlerfrei");
        Self {
            store,
            sessions,
            session_config,
            dummy_hash: Arc::from(dummy),
            internal_token_hash: None,
            limiter: Arc::new(RateLimiter::default()),
            kt: Arc::new(NoopKtNotifier),
            discovery_oprf: None,
            pow_difficulty: 0,
            sealed_sender: None,
            provision: Arc::new(ProvisionRelay::default()),
        }
    }

    /// Schaltet die Sealed-Sender-Zertifikatsausgabe frei (main.rs, wenn
    /// SEALED_SENDER_TRUST_ROOT konfiguriert ist).
    pub fn with_sealed_sender(mut self, issuer: Arc<sealed_cert::Issuer>) -> Self {
        self.sealed_sender = Some(issuer);
        self
    }

    /// Setzt die Proof-of-Work-Schwierigkeit der Registrierung (führende
    /// Nullbits); 0 lässt die Bremse aus (main.rs, aus POW_DIFFICULTY).
    pub fn with_pow_difficulty(mut self, bits: u32) -> Self {
        self.pow_difficulty = bits;
        self
    }

    /// Hängt den KT-Melder ein (main.rs, wenn KT_URL konfiguriert ist).
    pub fn with_kt_notifier(mut self, notifier: Arc<dyn KtNotifier>) -> Self {
        self.kt = notifier;
        self
    }

    /// Schaltet Contact Discovery mit dem Server-OPRF-Schlüssel frei
    /// (main.rs, wenn CDS_OPRF_KEY konfiguriert ist).
    pub fn with_discovery_oprf(mut self, key: Arc<oprf::ServerKey>) -> Self {
        self.discovery_oprf = Some(key);
        self
    }

    /// Schaltet die /internal-Routen mit einem Shared Secret frei
    /// (Dienst-zu-Dienst, z. B. directory).
    pub fn with_internal_token(mut self, token: &str) -> Self {
        self.internal_token_hash = Some(Arc::from(auth::token_hash(token)));
        self
    }
}

/// Baut den vollständigen Router des Dienstes.
///
/// `POST /accounts` legt Konto und erstes Gerät zusammen an, `/devices`
/// verwaltet die Gerätemenge (F030/F040, schnittstellen.md).
pub fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/", get(|| async { "SecureMessenger identity service" }))
        .route(
            "/accounts",
            post(register)
                .delete(delete_account)
                .patch(change_display_name),
        )
        .route("/accounts/undelete", post(undelete_account))
        .route("/accounts/rotate-identity", post(rotate_identity))
        // Anzeigename eines bekannten Kontos (F010): jeder Angemeldete darf
        // das Profil eines Handles lesen, um es bei seinen Kontakten
        // anzuzeigen. Nach den festen /accounts/*-Routen eingehängt, damit
        // 'undelete'/'rotate-identity' nicht als Handle missgedeutet werden.
        .route("/accounts/{handle}", get(account_profile))
        .route("/pow", get(pow_info))
        .route("/sessions", post(login).delete(logout))
        .route("/sessions/refresh", post(refresh))
        .route("/sessions/password", post(change_password))
        .route("/devices", get(list_devices).post(add_device))
        .route("/devices/{id}", delete(remove_device))
        // QR-Kopplung: das neue Gerät legt seinen verschlüsselten Antrag ab
        // (POST), das freischaltende holt ihn (GET). Beide ohne Token: das
        // neue Gerät hat noch keins, und der Relay-Inhalt ist für ihn ohnehin
        // opak. Immer eingehängt (kein Config-Gate), weil es reiner,
        // zustandsloser Transport ist. Ein enger Body-Deckel (8 KiB) nur auf
        // dem POST (die einzige Route mit Body), damit ein riesiger Request
        // den Speicher nicht am Feld-Deckel vorbei füllt; die Feld-Grenzen in
        // provision.rs sind die zweite Verteidigungslinie. Massenhaftes
        // Kanal-Squatting bremst ein IP-Rate-Limit am Ingress (wie bei
        // Login/Registrierung, deren Handle-Limit hier mangels Konto nicht
        // greift); der QR-Weg fällt bei vollem Relay ohnehin sichtbar auf den
        // manuellen Antrag zurück.
        .route(
            "/provision",
            post(provision_put).layer(axum::extract::DefaultBodyLimit::max(8 * 1024)),
        )
        .route("/provision/{channel}", get(provision_get));
    // Contact Discovery nur bei konfiguriertem OPRF-Schlüssel: sonst
    // existieren die Routen nicht (echtes 404 statt einer Antwort ohne
    // Verschleierung).
    if state.discovery_oprf.is_some() {
        router = router
            .route("/discovery/evaluate", post(discovery_evaluate))
            .route("/discovery/lookup", post(discovery_lookup));
    }
    // Sealed Sender nur bei konfiguriertem Trust Root: der Anker (GET,
    // öffentlich) und die Zertifikatsausgabe (Bearer) hängen zusammen.
    if state.sealed_sender.is_some() {
        router = router
            .route("/sealed-sender", get(sealed_sender_info))
            .route("/sender-certificate", get(sender_certificate));
    }
    // Dienst-zu-Dienst (nicht öffentlich, Shared Secret): Introspektion
    // von Access-Tokens und die Gerätemenge eines Kontos. So bleibt die
    // Session-Ablage privat beim identity-Dienst, statt dass andere
    // Dienste in seine Datenbank greifen. Ohne konfiguriertes Secret werden
    // die Routen gar nicht erst eingehängt: jede Anfrage darauf ist ein
    // sauberes 404, auch für Extractor-Fehler wie kaputtes JSON.
    if state.internal_token_hash.is_some() {
        router = router
            .route("/internal/introspect", post(introspect))
            .route(
                "/internal/accounts/{handle}/devices",
                get(internal_account_devices),
            );
    }
    router
        .layer(axum::middleware::from_fn(common::metrics::track))
        .merge(common::ops_router())
        .with_state(state)
}

#[derive(Deserialize)]
struct RegisterRequest {
    handle: String,
    display_name: Option<String>,
    password: String,
    /// Öffentlicher Konto-Identitätsschlüssel (Ed25519, Base64). Der Client
    /// erzeugt das Schlüsselpaar, der private Teil verlässt ihn nie.
    identity_key: String,
    /// Das erste Gerät; ein Konto ohne Gerät gibt es nicht.
    device: DeviceRequest,
    /// Proof-of-Work-nonce, wenn der Dienst eine Bremse verlangt
    /// (`GET /pow` nennt die Schwierigkeit).
    #[serde(default)]
    pow_nonce: Option<u64>,
}

#[derive(Serialize)]
struct PowInfo {
    /// Geforderte führende Nullbits; 0 heißt: keine Bremse.
    difficulty: u32,
}

/// `GET /pow`: die aktuelle Proof-of-Work-Schwierigkeit, damit der Client
/// vor der Registrierung den passenden nonce sucht.
async fn pow_info(State(st): State<AppState>) -> Response {
    (
        StatusCode::OK,
        Json(PowInfo {
            difficulty: st.pow_difficulty,
        }),
    )
        .into_response()
}

/// Gültigkeit eines Absender-Zertifikats: ein Tag. Kurz genug, dass ein
/// revoziertes Gerät zeitnah herausfällt (es bekommt schlicht kein neues
/// Zertifikat mehr), lang genug, dass Clients nicht pro Nachricht anfragen.
/// [ANNAHME: 24 Stunden, der Startwert aus offene-fragen.md.]
const SENDER_CERTIFICATE_TTL_MILLIS: u64 = 24 * 60 * 60 * 1000;

#[derive(Serialize)]
struct SealedSenderInfo {
    /// Öffentlicher Trust Root (Base64, 33 Bytes), gegen den Clients die
    /// Zertifikatskette beim Entsiegeln prüfen.
    trust_root: String,
}

/// `GET /sealed-sender`: der öffentliche Trust Root. Unauthentifiziert,
/// denn er ist per Definition öffentlich; ein Client, der dem Server hier
/// nicht traut, verankert ihn stattdessen über SM_SEALED_TRUST_ROOT lokal
/// (Bootstrapping-Problem wie beim KT-Signaturschlüssel, gleiche Antwort).
async fn sealed_sender_info(State(st): State<AppState>) -> Response {
    // Die Route existiert nur mit konfiguriertem Aussteller (app()).
    let Some(issuer) = st.sealed_sender.as_ref() else {
        return internal();
    };
    (
        StatusCode::OK,
        Json(SealedSenderInfo {
            trust_root: BASE64.encode(issuer.trust_root_public()),
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct SenderCertificateQuery {
    /// Protokoll-Gerätenummer des Absenders (ProtocolAddress-Teil). Der
    /// Client nennt sie, weil nur er sie kennt; die Sicherheit hängt nicht
    /// daran, sondern am Identitätsschlüssel, den der Dienst selbst aus
    /// seiner Registrierung nimmt.
    #[serde(default = "default_protocol_device")]
    device: u32,
}

fn default_protocol_device() -> u32 {
    1
}

#[derive(Serialize)]
struct SenderCertificateResponse {
    /// Serialisiertes SenderCertificate (Base64), unverändert für
    /// `sealed_sender_encrypt` bestimmt.
    certificate: String,
    /// Ablauf in Unix-Millisekunden, damit der Client rechtzeitig neu holt.
    expires_at_millis: u64,
}

/// `GET /sender-certificate`: stellt dem authentifizierten Gerät ein
/// kurzlebiges Absender-Zertifikat aus. Der Identitätsschlüssel im
/// Zertifikat kommt aus der eigenen Registrierung des Geräts, nie aus dem
/// Request: ein Konto kann sich so kein Zertifikat für einen fremden
/// Schlüssel erschleichen.
async fn sender_certificate(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SenderCertificateQuery>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    let Some(issuer) = st.sealed_sender.as_ref() else {
        return internal();
    };
    let devices = match st.store.devices(&who.handle).await {
        Ok(devices) => devices,
        Err(error) => return store_failure(error),
    };
    // Revozierte Geräte fallen hier heraus: sie behalten ihr letztes
    // Zertifikat höchstens bis zu dessen Ablauf (TTL), danach ist Schluss.
    let Some(device) = devices.iter().find(|d| d.id == who.device_id && !d.revoked) else {
        return api_error(
            StatusCode::FORBIDDEN,
            "unknown_device",
            "Gerät ist nicht (mehr) Teil der gültigen Gerätemenge",
        );
    };
    let Ok(identity_key) = BASE64.decode(&device.public_key) else {
        tracing::error!(handle = %who.handle, "registrierter Geräteschlüssel ist kein Base64");
        return internal();
    };
    let expires_at_millis = now_unix() * 1000 + SENDER_CERTIFICATE_TTL_MILLIS;
    match issuer.issue(&who.handle, query.device, &identity_key, expires_at_millis) {
        Ok(certificate) => (
            StatusCode::OK,
            Json(SenderCertificateResponse {
                certificate: BASE64.encode(certificate),
                expires_at_millis,
            }),
        )
            .into_response(),
        Err(error) => {
            // Kein Serverfehler: das Gerät hat bei der Registrierung keinen
            // libsignal-Identitätsschlüssel hinterlegt (33 Bytes mit
            // Typ-Präfix), damit kann kein Zertifikat entstehen.
            tracing::warn!(%error, handle = %who.handle, "Absender-Zertifikat nicht ausstellbar");
            api_error(
                StatusCode::BAD_REQUEST,
                "device_key_unsupported",
                "der registrierte Geräteschlüssel ist kein libsignal-Identitätsschlüssel",
            )
        }
    }
}

/// Ein Gerät, wie der Client es anmeldet. Das Credential ist die Signatur
/// des Konto-Identitätsschlüssels über das Format aus credential.rs.
#[derive(Deserialize)]
struct DeviceRequest {
    /// Client-erzeugte ID, z. B. eine UUID. Pro Konto eindeutig, für immer.
    id: String,
    name: Option<String>,
    /// Öffentlicher Geräteschlüssel (Ed25519, Base64).
    public_key: String,
    /// Ablauf des Credentials, Unix-Sekunden. Der Client wählt die Dauer.
    not_after: u64,
    /// Signatur (Base64) des Konto-Identitätsschlüssels.
    credential: String,
}

#[derive(Serialize)]
struct AccountResponse {
    handle: String,
    display_name: String,
    /// Bestätigt die registrierte Geräte-ID; bei einem Mehr-Feld-POST soll
    /// der Client sehen, was der Server wirklich angelegt hat.
    device_id: String,
    /// Die vom Server vergebene libsignal-Gerätenummer des ersten Geräts
    /// (immer 1); der Client übernimmt sie als seinen ProtocolAddress-Teil.
    protocol_device_id: u16,
}

/// Antwort auf `POST /devices`: bestätigt die Geräte-ID und nennt die
/// vergebene Gerätenummer, die der Client als seinen ProtocolAddress-Teil
/// braucht (er kann sie nicht selbst wählen, der Server hält sie eindeutig).
#[derive(Serialize)]
struct AddDeviceResponse {
    device_id: String,
    protocol_device_id: u16,
}

#[derive(Serialize)]
struct DeviceResponse {
    id: String,
    name: String,
    public_key: String,
    not_after: u64,
    /// Die libsignal-Gerätenummer (ProtocolAddress-Teil), damit ein Client
    /// nach Verlust des lokalen Zustands seine eigene Nummer wiederfindet.
    protocol_device_id: u16,
}

#[derive(Deserialize)]
struct LoginRequest {
    handle: String,
    password: String,
    /// Sessions sind gerätegebunden: das Gerät muss registriert und nicht
    /// revoziert sein.
    device_id: String,
}

/// Passwortwechsel des angemeldeten Kontos: das alte Passwort belegt, dass
/// der Aufrufer es kennt (ein gestohlenes Token allein soll das Passwort
/// nicht tauschen können), das neue ersetzt es.
#[derive(Deserialize)]
struct PasswordChangeRequest {
    current_password: String,
    new_password: String,
}

/// Konto-Löschung vormerken: das Passwort bestätigt, dass es der Besitzer
/// ist (ein gestohlenes Token allein soll das Konto nicht löschen können).
#[derive(Deserialize)]
struct DeleteAccountRequest {
    password: String,
}

/// Neuer Anzeigename (F010: getrennt vom Handle, jederzeit änderbar).
#[derive(Deserialize)]
struct DisplayNameRequest {
    display_name: String,
}

/// Rotation des Konto-Wurzelschlüssels (ADR-0010). Der neue öffentliche
/// Wurzelschlüssel, das vom ALTEN Schlüssel signierte Rotations-Zertifikat
/// und je aktuellem Gerät ein mit dem NEUEN Schlüssel signiertes Credential.
#[derive(Deserialize)]
struct RotateIdentityRequest {
    new_identity_key: String,
    rotation_signature: String,
    devices: Vec<RotateDeviceCredential>,
}

#[derive(Deserialize)]
struct RotateDeviceCredential {
    id: String,
    credential: String,
    /// Frischer Ablauf des neu signierten Credentials, Unix-Sekunden
    /// (ADR-0010). Die Rotation ist zugleich die Erneuerung: ein sonst
    /// abgelaufenes, aber nicht revoziertes Gerät würde die Rotation sonst
    /// dauerhaft blockieren.
    not_after: u64,
}

/// Antwort auf die Änderung: der gespeicherte (getrimmte) Name, damit der
/// Client die kanonische Form übernimmt statt seiner Roh-Eingabe.
#[derive(Serialize)]
struct DisplayNameResponse {
    display_name: String,
}

/// Öffentliches Kontakt-Profil (Handle plus Anzeigename), das ein
/// angemeldeter Nutzer zu einem bekannten Handle abfragt, um es bei seinen
/// Kontakten anzuzeigen. Bewusst minimal: nur was zum Anzeigen nötig ist,
/// keine Geräte, kein Schlüssel (die holt der Krypto-Pfad getrennt).
#[derive(Serialize)]
struct ProfileResponse {
    handle: String,
    display_name: String,
}

/// Antwort auf die vorgemerkte Löschung: der Ablauf der Widerrufsfrist als
/// Unix-Sekunden, damit der Client die Frist anzeigen und das Widerrufen
/// anbieten kann.
#[derive(Serialize)]
struct DeletionScheduledResponse {
    deletion_pending_until: u64,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

/// Antwort auf Login und Refresh. Feldnamen nach OAuth-2.0-Konvention
/// (access_token, refresh_token, token_type, expires_in), damit Clients beim
/// späteren OIDC-Anschluss (Pflichtenheft 5.2) keine zweite Form lernen.
#[derive(Serialize)]
struct SessionResponse {
    access_token: String,
    refresh_token: String,
    token_type: &'static str,
    /// Sekunden bis zum Ablauf des Access-Tokens.
    expires_in: u64,
    /// Bei einer vorgemerkten Löschung der Ablauf der Widerrufsfrist
    /// (Unix-Sekunden); fehlt bei einem aktiven Konto. So sieht der Client
    /// direkt nach dem Login, dass eine Löschung läuft, und kann sie anbieten
    /// zu widerrufen.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion_pending_until: Option<u64>,
    /// Anzeigename des Kontos (F010), damit der Client ihn nach der
    /// Anmeldung zeigen und zum Ändern vorbelegen kann. Fehlt auf dem
    /// Refresh-Pfad (der prüft nur das Token); der Client behält dann
    /// seinen letzten Stand.
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

/// Einheitliches Fehlerformat nach schnittstellen.md.
#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ApiError { code, message })).into_response()
}

fn internal() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Interner Fehler",
    )
}

/// Backend-Fehler der Ablage: loggen und 500. Nie in ein 401/404 übersetzen,
/// sonst sieht ein Datenbank-Ausfall wie "gibt es nicht" aus und Clients
/// räumen lokalen Zustand ab.
fn store_failure(error: StoreError) -> Response {
    tracing::error!(?error, "Ablage-Fehler");
    internal()
}

/// Prüft ein Passwort gegen einen Hash auf dem Blocking-Pool (Argon2id ist
/// bewusst teuer). Ein abgebrochener Task (Panik im Verifizierer) ist ein
/// interner Fehler und wird als 500 zurückgegeben, NICHT still als „Passwort
/// falsch" (401): sonst sähe ein Absturz am Login wie ein Anmeldefehler aus.
/// Gleiche Behandlung wie in register/change_password.
async fn verify_password_blocking(password: String, hash: String) -> Result<bool, Response> {
    tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash))
        .await
        .map_err(|error| {
            tracing::error!(%error, "spawn_blocking bei der Passwortprüfung abgebrochen");
            internal()
        })
}

/// Meldet die aktuelle Schlüsselmenge eines Kontos ans KT-Verzeichnis,
/// fire-and-forget im Hintergrund: die Antwort an den Client wartet nie
/// auf kt, und ein kt-Ausfall wird nur geloggt (kt_notify.rs).
fn notify_kt(st: &AppState, handle: &str) {
    let store = st.store.clone();
    let kt = st.kt.clone();
    let handle = handle.to_string();
    tokio::spawn(async move {
        let account = match store.get(&handle).await {
            Ok(Some(account)) => account,
            _ => return,
        };
        let devices = match store.devices(&handle).await {
            Ok(devices) => devices,
            Err(_) => return,
        };
        let view = common::identity_client::AccountDevices {
            id: account.id,
            handle: handle.clone(),
            identity_key: account.identity_key,
            devices: devices
                .into_iter()
                .filter(|d| !d.revoked)
                .map(|d| common::identity_client::DeviceInfo {
                    id: d.id,
                    public_key: d.public_key,
                    not_after: d.not_after,
                })
                .collect(),
        };
        let commitment = common::kt::account_commitment(&view);
        kt.key_set_changed(&handle, &commitment).await;
    });
}

/// Hex-Darstellung des OPRF-Werts: der Discovery-Index-Schlüssel. Hex
/// statt Base64, damit er unverändert als Text-Primärschlüssel taugt.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Trägt ein frisch angelegtes Konto in den Discovery-Index ein, wenn
/// Discovery konfiguriert ist. Der Server rechnet `PRF_k(handle)` selbst
/// (er kennt seine Handles ohnehin) und legt das Konto darunter ab.
/// Fehler werden nur geloggt: ein Konto entsteht auch dann, wenn der
/// Index-Eintrag scheitert (Discovery ist nachrangig, nicht Teil der
/// Registrierungs-Zusage).
async fn index_discovery(st: &AppState, record: crate::store::DiscoveryRecord) {
    let Some(oprf) = &st.discovery_oprf else {
        return;
    };
    let prf = match oprf.prf(record.handle.as_bytes()) {
        Ok(prf) => prf,
        Err(error) => {
            tracing::error!(%error, "OPRF-Berechnung für Discovery fehlgeschlagen");
            return;
        }
    };
    if let Err(error) = st.store.index_discovery(&hex(&prf), record).await {
        tracing::error!(?error, "Discovery-Index-Eintrag fehlgeschlagen");
    }
}

#[derive(Deserialize)]
struct DiscoveryEvaluateRequest {
    /// Das geblendete Element (Base64), aus `oprf::blind`.
    blinded: String,
}

#[derive(Serialize)]
struct DiscoveryEvaluateResponse {
    /// Die Server-Auswertung (Base64), die der Client entblendet.
    evaluation: String,
}

/// `POST /discovery/evaluate`: die Server-Runde der OPRF. Der Server sieht
/// nur das geblendete Element, nie den Handle. Rate-limitiert je Abrufer,
/// weil jede Runde eine Rate-Einheit gegen Enumeration ist.
async fn discovery_evaluate(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DiscoveryEvaluateRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    if let Err(retry_after) = st
        .limiter
        .check(&format!("discovery:{}", who.handle), DISCOVERY_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    let Some(oprf) = &st.discovery_oprf else {
        return internal();
    };
    let blinded = match BASE64.decode(&req.blinded) {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_blinded",
                "blinded ist kein gültiges Base64",
            )
        }
    };
    match oprf.evaluate(&blinded) {
        Ok(evaluation) => (
            StatusCode::OK,
            Json(DiscoveryEvaluateResponse {
                evaluation: BASE64.encode(evaluation),
            }),
        )
            .into_response(),
        Err(error) => {
            // Ein ungültiges geblendetes Element ist ein Client-Fehler,
            // kein Server-Fehler; die Bibliothek unterscheidet das nicht,
            // deshalb 400 mit knapper Meldung.
            tracing::debug!(%error, "OPRF-Auswertung abgelehnt");
            api_error(
                StatusCode::BAD_REQUEST,
                "invalid_blinded",
                "blinded ist kein gültiges OPRF-Element",
            )
        }
    }
}

#[derive(Deserialize)]
struct DiscoveryLookupRequest {
    /// Der entblendete OPRF-Wert `PRF_k(handle)` (Hex).
    prf: String,
}

#[derive(Serialize)]
struct DiscoveryLookupResponse {
    handle: String,
    /// Interne Konto-Adresse (recipient_id).
    id: String,
    /// Konto-Identitätsschlüssel, damit der Client direkt gegen KT prüfen kann.
    identity_key: String,
}

/// `POST /discovery/lookup`: schlägt ein Konto über seinen OPRF-Wert nach.
/// Der Client kannte den Handle (er hat ihn selbst geblendet); der Server
/// lernt aus dem Wert nicht den Klartext. 404, wenn kein Konto darunter
/// steht. Rate-limitiert wie die Auswertung.
async fn discovery_lookup(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DiscoveryLookupRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    if let Err(retry_after) = st
        .limiter
        .check(&format!("discovery:{}", who.handle), DISCOVERY_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    match st.store.discovery_lookup(&req.prf).await {
        Ok(Some(record)) => (
            StatusCode::OK,
            Json(DiscoveryLookupResponse {
                handle: record.handle,
                id: record.id,
                identity_key: record.identity_key,
            }),
        )
            .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Kein Konto unter diesem Wert",
        ),
        Err(error) => store_failure(error),
    }
}

async fn register(State(st): State<AppState>, Json(req): Json<RegisterRequest>) -> Response {
    if let Err(message) = validate_handle(&req.handle) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_handle", message);
    }
    // Limit vor der teuren Arbeit (Argon2, Signaturprüfung); der
    // Schlüssel trägt einen Präfix, damit Login-Versuche auf dasselbe
    // Handle ein eigenes Fenster haben.
    if let Err(retry_after) = st
        .limiter
        .check(&format!("register:{}", req.handle), REGISTER_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    // Proof-of-Work-Bremse (Sybil-Widerstand): vor der teuren Arbeit prüfen.
    // Ohne konfigurierte Schwierigkeit ist sie aus, dann ist kein nonce nötig.
    if st.pow_difficulty > 0 {
        match req.pow_nonce {
            Some(nonce) if pow::verify(&req.handle, nonce, st.pow_difficulty) => {}
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "pow_required",
                    "Registrierung braucht einen gültigen Proof-of-Work (Schwierigkeit unter GET /pow)",
                )
            }
        }
    }
    if let Err(message) = validate_password(&req.password) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_password", message);
    }
    if let Err(message) = validate_device_id(&req.device.id) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_device", message);
    }
    // Früh geprüft wie Handle und Passwort (vor Argon2); ohne eigenen
    // Namen gilt der Handle.
    let display_name = match normalize_display_name(req.display_name.as_deref()) {
        Ok(Some(name)) => name,
        Ok(None) => req.handle.clone(),
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_display_name", message),
    };
    // Früher Duplikat-Check, damit ein vergebenes Handle keinen teuren
    // Argon2-Lauf kostet. Verbindlich bleibt der atomare create() darunter.
    match st.store.get(&req.handle).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return api_error(
                StatusCode::CONFLICT,
                "handle_taken",
                "Handle ist bereits vergeben",
            )
        }
        Err(error) => return store_failure(error),
    }
    // Credential vor dem Argon2-Lauf prüfen: Signaturverifikation ist
    // billig, und ein kaputtes Gerät soll den teuren Hash gar nicht auslösen.
    if let Err(error) = credential::verify_device_credential(
        &req.identity_key,
        &req.handle,
        &req.device.id,
        &req.device.public_key,
        req.device.not_after,
        &req.device.credential,
        now_unix(),
    ) {
        return credential_error_response(error);
    }
    let password = req.password;
    let password_hash =
        match tokio::task::spawn_blocking(move || auth::hash_password(&password)).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(error)) => {
                tracing::error!(%error, "Argon2-Hashing fehlgeschlagen");
                return internal();
            }
            Err(error) => {
                tracing::error!(%error, "spawn_blocking abgebrochen");
                return internal();
            }
        };
    let response = AccountResponse {
        handle: req.handle.clone(),
        display_name: display_name.clone(),
        device_id: req.device.id.clone(),
        // Das erste Gerät ist immer Nummer 1 (die Ablage vergibt sie so).
        protocol_device_id: 1,
    };
    let account = Account {
        id: uuid::Uuid::new_v4().to_string(),
        handle: req.handle,
        display_name,
        password_hash,
        identity_key: req.identity_key,
        deletion_pending_until: None,
    };
    // Für den Discovery-Index vor dem Verschieben festhalten.
    let discovery_record = crate::store::DiscoveryRecord {
        handle: account.handle.clone(),
        id: account.id.clone(),
        identity_key: account.identity_key.clone(),
    };
    match st
        .store
        .create(account, device_from_request(req.device))
        .await
    {
        Ok(()) => {
            // Neues Konto = neue Schlüsselmenge im Verzeichnis.
            notify_kt(&st, &response.handle);
            index_discovery(&st, discovery_record).await;
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(StoreError::HandleTaken) => api_error(
            StatusCode::CONFLICT,
            "handle_taken",
            "Handle ist bereits vergeben",
        ),
        Err(StoreError::DeviceIdTaken) => api_error(
            StatusCode::CONFLICT,
            "device_id_taken",
            "Geräte-ID ist bereits vergeben",
        ),
        Err(error) => store_failure(error),
    }
}

fn device_from_request(req: DeviceRequest) -> Device {
    Device {
        id: req.id,
        // Fallback statt Pflichtfeld: der Name ist rein informativ.
        name: req
            .name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "Gerät".to_string()),
        public_key: req.public_key,
        credential: req.credential,
        not_after: req.not_after,
        revoked: false,
        // 0 = noch nicht vergeben; die Ablage setzt die Nummer (1 beim
        // ersten Gerät, sonst max + 1).
        protocol_device_id: 0,
    }
}

/// Übersetzt Credential-Fehler in API-Antworten. Alle Varianten sind 400 mit
/// demselben Code; die genaue Ursache steht nur im Log, damit die API keine
/// Prüfreihenfolge verrät.
fn credential_error_response(error: credential::CredentialError) -> Response {
    tracing::debug!(?error, "Geräte-Credential abgelehnt");
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_credential",
        "Geräte-Credential ist ungültig oder abgelaufen",
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit liegt nach 1970")
        .as_secs()
}

async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    // Limit je Handle vor der Passwortarbeit: bremst Durchprobieren gegen
    // ein Konto, bevor es Argon2-Zeit kostet.
    if let Err(retry_after) = st
        .limiter
        .check(&format!("login:{}", req.handle), LOGIN_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    // Auch bei unbekanntem Handle wird gegen einen Dummy-Hash geprüft,
    // damit die Antwortzeit keine Konto-Existenz verrät.
    let (stored_hash, account_exists, deletion_pending_until, display_name) =
        match st.store.get(&req.handle).await {
            Ok(Some(account)) => (
                account.password_hash,
                true,
                account.deletion_pending_until,
                Some(account.display_name),
            ),
            Ok(None) => (st.dummy_hash.to_string(), false, None, None),
            Err(error) => return store_failure(error),
        };
    let password = req.password;
    let password_ok = match verify_password_blocking(password, stored_hash).await {
        Ok(ok) => ok,
        Err(response) => return response,
    };
    // Geräteprüfung nach der Passwortarbeit und mit derselben generischen
    // Antwort: wer das Passwort nicht kennt, erfährt auch nichts über die
    // Gerätemenge.
    let device_ok = match st.store.get_device(&req.handle, &req.device_id).await {
        Ok(device) => device.is_some_and(|d| !d.revoked),
        Err(error) => return store_failure(error),
    };
    if !password_ok || !account_exists || !device_ok {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Handle, Passwort oder Gerät ist ungültig",
        );
    }
    let (mut response, access_hash, refresh_hash) = new_token_pair(&st);
    response.deletion_pending_until = deletion_pending_until;
    response.display_name = display_name;
    let created = st
        .sessions
        .create(
            SessionIdentity {
                handle: req.handle,
                device_id: req.device_id,
            },
            access_hash,
            refresh_hash,
        )
        .await;
    if let Err(error) = created {
        tracing::error!(%error, "Session anlegen fehlgeschlagen");
        return internal();
    }
    (StatusCode::OK, Json(response)).into_response()
}

/// Baut ein frisches Token-Paar samt Antwort. Der Klartext geht genau einmal
/// an den Client, gespeichert werden nur die Hashes.
fn new_token_pair(st: &AppState) -> (SessionResponse, String, String) {
    let access_token = auth::new_session_token();
    let refresh_token = auth::new_session_token();
    let access_hash = auth::token_hash(&access_token);
    let refresh_hash = auth::token_hash(&refresh_token);
    let response = SessionResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: st.session_config.access_ttl.as_secs(),
        deletion_pending_until: None,
        display_name: None,
    };
    (response, access_hash, refresh_hash)
}

/// `POST /sessions/refresh`: rotiert das Token-Paar. Ein wiederverwendetes
/// (schon rotiertes) Refresh-Token widerruft die ganze Familie; nach außen
/// bleibt die Antwort trotzdem das generische 401, damit ein Angreifer nicht
/// erfährt, dass er aufgeflogen ist. Der Vorfall steht im Log.
async fn refresh(State(st): State<AppState>, Json(req): Json<RefreshRequest>) -> Response {
    let (response, access_hash, refresh_hash) = new_token_pair(&st);
    match st
        .sessions
        .refresh(
            &auth::token_hash(&req.refresh_token),
            access_hash,
            refresh_hash,
        )
        .await
    {
        Ok(_identity) => (StatusCode::OK, Json(response)).into_response(),
        Err(RefreshError::Backend(error)) => {
            tracing::error!(%error, "Refresh: Ablage-Fehler");
            internal()
        }
        Err(error) => {
            if error == RefreshError::ReuseDetected {
                tracing::warn!(
                    "rotiertes Refresh-Token erneut vorgelegt, Session-Familie widerrufen"
                );
            }
            api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_refresh_token",
                "Refresh-Token ist ungültig oder abgelaufen",
            )
        }
    }
}

/// `POST /sessions/password`: ändert das Konto-Passwort. Bearer-
/// authentifiziert, aber das ALTE Passwort muss zusätzlich stimmen: ein
/// gestohlenes Access-Token allein soll das Passwort nicht tauschen können
/// (sonst sperrte ein Dieb den Besitzer aus). Nach dem Wechsel werden die
/// Sessions ALLER ANDEREN Geräte widerrufen, damit ein Angreifer mit einem
/// alten Token auf einem anderen Gerät ausgesperrt wird; das anfragende
/// Gerät behält seine Session. Der Client verschlüsselt danach seine lokale
/// Ablage unter dem neuen Passwort neu (keystore), sonst scheiterte die
/// nächste Anmeldung.
async fn change_password(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordChangeRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    // Bremst das Durchprobieren des alten Passworts (ein Angreifer mit
    // gestohlenem Token, aber ohne Passwort) je Handle.
    if let Err(retry_after) = st
        .limiter
        .check(&format!("passwd:{}", who.handle), LOGIN_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    let account = match st.store.get(&who.handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            tracing::error!(handle = %who.handle, "Session ohne zugehöriges Konto");
            return internal();
        }
        Err(error) => return store_failure(error),
    };
    if let Err(message) = validate_password(&req.new_password) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_password", message);
    }
    // Altes Passwort prüfen und neues hashen laufen auf einem Blocking-Thread
    // (Argon2 ist bewusst teuer).
    let current = req.current_password;
    let new = req.new_password;
    let stored = account.password_hash;
    let hashed = tokio::task::spawn_blocking(move || {
        if !auth::verify_password(&current, &stored) {
            return None;
        }
        auth::hash_password(&new).ok()
    })
    .await;
    let new_hash = match hashed {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Das aktuelle Passwort ist falsch",
            )
        }
        Err(error) => {
            tracing::error!(%error, "spawn_blocking beim Passwortwechsel abgebrochen");
            return internal();
        }
    };
    // Zuerst alle ANDEREN Geräte abmelden, DANN das Passwort setzen: so gilt
    // "204 heißt: Passwort gewechselt UND alle anderen Sessions widerrufen".
    // Scheitert der Widerruf (Ablage-Fehler), bricht der Wechsel ab, bevor
    // das Passwort geändert ist; die anderen Geräte melden sich dann mit dem
    // (unveränderten) alten Passwort neu an. Die Gegenreihenfolge (erst
    // Passwort, dann Widerruf) ließe bei einem Fehler ein fremdes Gerät mit
    // altem Token bis zu 30 Tage angemeldet, während der Nutzer Erfolg sieht.
    // Das anfragende Gerät (who.device_id) bleibt verschont.
    let devices = match st.store.devices(&who.handle).await {
        Ok(devices) => devices,
        Err(error) => return store_failure(error),
    };
    for device in devices
        .iter()
        .filter(|d| d.id != who.device_id && !d.revoked)
    {
        if let Err(error) = st.sessions.revoke_device(&who.handle, &device.id).await {
            tracing::error!(%error, device = %device.id, "Session vor Passwortwechsel nicht widerrufen");
            return internal();
        }
    }
    if let Err(error) = st.store.set_password_hash(&who.handle, &new_hash).await {
        return store_failure(error);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Widerrufsfrist der Konto-Löschung: 30 Tage (NF030 nennt keine Zahl).
/// Über `ACCOUNT_DELETION_GRACE_SECS` überschreibbar, damit der Betrieb (und
/// ein Test) eine andere Frist wählen kann; ein leerer oder unparsbarer Wert
/// fällt still auf die Vorgabe zurück.
const DELETION_GRACE_SECS_DEFAULT: u64 = 30 * 24 * 60 * 60;

fn deletion_grace_secs() -> u64 {
    std::env::var("ACCOUNT_DELETION_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DELETION_GRACE_SECS_DEFAULT)
}

/// `DELETE /accounts`: merkt die Löschung des angemeldeten Kontos vor (NF030,
/// Löschung mit Widerrufsfrist). Bearer-authentifiziert, aber das Passwort
/// muss zusätzlich stimmen: ein gestohlenes Access-Token allein soll ein
/// Konto nicht löschen können. Das Konto bleibt während der Frist voll
/// nutzbar und die Löschung widerrufbar (`POST /accounts/undelete`); erst der
/// Purge nach Ablauf entfernt Konto, Geräte, Sessions und Discovery-Eintrag
/// (Crypto-Shredding: der Konto-Identitätsschlüssel und die Credentials
/// verschwinden, die E2E-Schlüssel lagen ohnehin nie beim Server).
async fn delete_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    // Wie beim Passwortwechsel: das Durchprobieren des Passworts (Angreifer
    // mit Token, ohne Passwort) je Handle bremsen.
    if let Err(retry_after) = st
        .limiter
        .check(&format!("delete:{}", who.handle), LOGIN_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    let account = match st.store.get(&who.handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            tracing::error!(handle = %who.handle, "Session ohne zugehöriges Konto");
            return internal();
        }
        Err(error) => return store_failure(error),
    };
    let password = req.password;
    let stored = account.password_hash;
    let password_ok = match verify_password_blocking(password, stored).await {
        Ok(ok) => ok,
        Err(response) => return response,
    };
    if !password_ok {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Das Passwort ist falsch",
        );
    }
    let deletion_at = now_unix() + deletion_grace_secs();
    match st.store.schedule_deletion(&who.handle, deletion_at).await {
        Ok(()) => (
            StatusCode::OK,
            Json(DeletionScheduledResponse {
                deletion_pending_until: deletion_at,
            }),
        )
            .into_response(),
        Err(error) => store_failure(error),
    }
}

/// `PATCH /accounts`: ändert den Anzeigenamen des angemeldeten Kontos
/// (F010). Nur das Token nötig, anders als Löschung und Passwortwechsel:
/// die Änderung ist umkehrbar und zerstört nichts, eine Passwort-Hürde
/// wäre Reibung ohne Sicherheitsgewinn. Kein eigenes Rate-Limit: ein
/// UPDATE ohne teure Arbeit, und der Angemeldete ändert nur sich selbst.
async fn change_display_name(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisplayNameRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    let name = match normalize_display_name(Some(&req.display_name)) {
        Ok(Some(name)) => name,
        Ok(None) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_display_name",
                "Anzeigename darf nicht leer sein",
            )
        }
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "invalid_display_name", message),
    };
    match st.store.set_display_name(&who.handle, &name).await {
        Ok(()) => (
            StatusCode::OK,
            Json(DisplayNameResponse { display_name: name }),
        )
            .into_response(),
        Err(error) => store_failure(error),
    }
}

/// `GET /accounts/{handle}`: das öffentliche Profil (Handle plus
/// Anzeigename) eines bekannten Kontos. Bearer nötig (kein anonymes
/// Verzeichnis-Grasen), aber jeder Angemeldete darf jedes Handle abfragen,
/// wie beim Bündel-Abruf: die Clients zeigen den Anzeigenamen ihrer
/// Kontakte an und frischen ihn bei Bedarf auf. Ehrliche Grenze: der
/// Anzeigename ist Server-Datum, nicht Ende-zu-Ende und nicht im
/// KT-Commitment; der Handle bleibt die kryptografische Identität. Ein
/// vorgemerkt gelöschtes Konto bleibt bis zum Purge normal abfragbar (es ist
/// in der Widerrufsfrist voll nutzbar).
async fn account_profile(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(handle): axum::extract::Path<String>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    if let Err(retry_after) = st
        .limiter
        .check(&format!("profile:{}", who.handle), PROFILE_RATE_LIMIT)
    {
        return common::rate::too_many_requests(retry_after);
    }
    match st.store.get(&handle).await {
        Ok(Some(account)) => (
            StatusCode::OK,
            Json(ProfileResponse {
                handle: account.handle,
                display_name: account.display_name,
            }),
        )
            .into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "Kein solches Konto"),
        Err(error) => store_failure(error),
    }
}

/// `POST /accounts/rotate-identity`: rotiert den Konto-Wurzelschlüssel
/// (ADR-0010). Bearer-authentifiziert; die eigentliche Autorisierung ist
/// die Kontinuitätssignatur des ALTEN Wurzelschlüssels über den neuen.
/// Alle aktuellen (nicht revozierten) Geräte müssen mit einem neu
/// signierten Credential kommen, sonst zeigte die Kette nach der Rotation
/// nicht mehr auf sie. Nach dem atomaren Ersetzen geht ein frisches
/// KT-Commitment (der auditierbare Vermerk der Rotation).
async fn rotate_identity(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RotateIdentityRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    let account = match st.store.get(&who.handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            tracing::error!(handle = %who.handle, "Session ohne zugehöriges Konto");
            return internal();
        }
        Err(error) => return store_failure(error),
    };
    // Kontinuität: das Zertifikat muss der ALTE (gespeicherte) Schlüssel
    // signiert haben, sonst ist die Rotation nicht autorisiert. Eigener
    // Fehlercode `invalid_continuity` (getrennt vom Geräte-Credential-
    // Fehler): ein Client, der eine unterbrochene Rotation wiederaufnimmt,
    // liest daran ab, dass der Dienst den neuen Schlüssel bereits übernommen
    // hat, und übernimmt ihn lokal (ADR-0010, Wiederaufnahme).
    if credential::verify_rotation_cert(
        &account.identity_key,
        &who.handle,
        &req.new_identity_key,
        &req.rotation_signature,
    )
    .is_err()
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_continuity",
            "Kontinuitätssignatur passt nicht zum aktuellen Wurzelschlüssel",
        );
    }
    // Die aktuellen, gültigen Geräte samt ihrer opaken Schlüssel laden:
    // gegen sie prüft der NEUE Schlüssel die neuen Credentials, und ihre
    // Menge muss vollständig abgedeckt sein. Der Ablauf (`not_after`) kommt
    // jetzt aus der Anfrage: die Rotation erneuert das Credential, statt den
    // alten (womöglich abgelaufenen) Ablauf beizubehalten.
    let current: Vec<Device> = match st.store.devices(&who.handle).await {
        Ok(devices) => devices.into_iter().filter(|d| !d.revoked).collect(),
        Err(error) => return store_failure(error),
    };
    let provided: std::collections::HashMap<&str, &RotateDeviceCredential> =
        req.devices.iter().map(|d| (d.id.as_str(), d)).collect();
    let now = now_unix();
    for device in &current {
        let Some(entry) = provided.get(device.id.as_str()) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "incomplete_rotation",
                "Für jedes aktuelle Gerät muss ein neu signiertes Credential mitkommen",
            );
        };
        if let Err(error) = credential::verify_device_credential(
            &req.new_identity_key,
            &who.handle,
            &device.id,
            &device.public_key,
            entry.not_after,
            &entry.credential,
            now,
        ) {
            return credential_error_response(error);
        }
    }
    let device_credentials: Vec<(String, String, u64)> = current
        .iter()
        .map(|d| {
            let entry = provided[d.id.as_str()];
            (d.id.clone(), entry.credential.clone(), entry.not_after)
        })
        .collect();
    match st
        .store
        .rotate_identity(
            &who.handle,
            &account.identity_key,
            &req.new_identity_key,
            &device_credentials,
        )
        .await
    {
        Ok(()) => {
            notify_kt(&st, &who.handle);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(StoreError::ConcurrentUpdate) => concurrent_update_response(),
        Err(error) => store_failure(error),
    }
}

/// 409 für einen parallelen Schreibkonflikt auf dem Konto (ADR-0010): eine
/// überlappende Rotation oder Geräte-Freischaltung hat den Zustand unter der
/// Prüfung verändert. Der Client holt frischen Zustand und setzt neu an; so
/// entsteht kein halb rotiertes Konto.
fn concurrent_update_response() -> Response {
    api_error(
        StatusCode::CONFLICT,
        "concurrent_update",
        "Konto wurde parallel geändert; mit frischem Zustand erneut versuchen",
    )
}

/// `POST /accounts/undelete`: widerruft eine vorgemerkte Löschung innerhalb
/// der Frist (Bearer, kein Passwort nötig: wer angemeldet ist, darf die
/// eigene Löschung stoppen). Idempotent.
async fn undelete_account(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    match st.store.cancel_deletion(&who.handle).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_failure(error),
    }
}

async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = bearer_token(&headers) {
        // Widerruft die ganze Familie, auch das Refresh-Token: nach einem
        // Logout darf sich die Session nicht wieder erneuern lassen.
        if let Err(error) = st.sessions.revoke_by_access(&auth::token_hash(token)).await {
            // Ein Backend-Fehler heißt: nicht widerrufen. Das darf nicht wie
            // Erfolg aussehen, der Client würde sein Token verwerfen und die
            // Session lebte weiter.
            tracing::error!(%error, "Logout: Ablage-Fehler");
            return internal();
        }
    }
    // Immer 204, damit die Antwort nicht verrät, ob das Token gültig war.
    StatusCode::NO_CONTENT.into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Auflösung des Bearer-Tokens zur Session-Identität. Als Hilfsfunktion
/// statt Extractor: drei Aufrufer, und so bleibt sichtbar, dass die Prüfung
/// am Handler-Anfang steht. Äußeres Result ist ein Backend-Ausfall (500),
/// inneres None ein unbekanntes Token (401).
async fn authenticate(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<Option<SessionIdentity>, String> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    st.sessions.authenticate(&auth::token_hash(token)).await
}

fn invalid_token() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Access-Token ist ungültig oder abgelaufen",
    )
}

/// Entfaltet den Backend-Fehlerfall der Session-Prüfung. Kein
/// `Result<_, Response>`-Helfer, weil die Response als Err-Variante zu groß
/// wäre (clippy: result_large_err); die Handler matchen selbst.
fn session_failure(error: String) -> Response {
    tracing::error!(%error, "Session-Prüfung: Ablage-Fehler");
    internal()
}

/// `GET /devices`: die gültige Gerätemenge des eigenen Kontos. Revozierte
/// Geräte fehlen; ihre Historie wird erst mit Key Transparency ein
/// API-Thema.
async fn list_devices(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    let devices = match st.store.devices(&who.handle).await {
        Ok(devices) => devices,
        Err(error) => return store_failure(error),
    };
    let devices: Vec<DeviceResponse> = devices
        .into_iter()
        .filter(|d| !d.revoked)
        .map(|d| DeviceResponse {
            id: d.id,
            name: d.name,
            public_key: d.public_key,
            not_after: d.not_after,
            protocol_device_id: d.protocol_device_id,
        })
        .collect();
    (StatusCode::OK, Json(devices)).into_response()
}

/// `POST /devices`: schaltet ein weiteres Gerät frei. Der Aufrufer ist ein
/// bereits registriertes Gerät mit gültiger Session; das Credential des
/// neuen Geräts hat der Konto-Identitätsschlüssel clientseitig signiert
/// (QR-/Bestätigungs-Flow läuft zwischen den Geräten, ohne Server).
async fn add_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceRequest>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    if let Err(message) = validate_device_id(&req.id) {
        return api_error(StatusCode::BAD_REQUEST, "invalid_device", message);
    }
    let account = match st.store.get(&who.handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            // Session ohne Konto kann nur durch einen Programmierfehler entstehen.
            tracing::error!(handle = %who.handle, "Session ohne zugehöriges Konto");
            return internal();
        }
        Err(error) => return store_failure(error),
    };
    if let Err(error) = credential::verify_device_credential(
        &account.identity_key,
        &who.handle,
        &req.id,
        &req.public_key,
        req.not_after,
        &req.credential,
        now_unix(),
    ) {
        return credential_error_response(error);
    }
    let device_id = req.id.clone();
    match st
        .store
        .add_device(&who.handle, device_from_request(req), &account.identity_key)
        .await
    {
        Ok(protocol_device_id) => {
            // Gerät dazu = neue Schlüsselmenge im Verzeichnis.
            notify_kt(&st, &who.handle);
            (
                StatusCode::CREATED,
                Json(AddDeviceResponse {
                    device_id,
                    protocol_device_id,
                }),
            )
                .into_response()
        }
        Err(StoreError::ConcurrentUpdate) => concurrent_update_response(),
        Err(StoreError::DeviceIdTaken) => api_error(
            StatusCode::CONFLICT,
            "device_id_taken",
            "Geräte-ID ist bereits vergeben",
        ),
        Err(StoreError::TooManyDevices) => api_error(
            StatusCode::CONFLICT,
            "too_many_devices",
            "Das Konto hat die Höchstzahl an Geräten erreicht",
        ),
        Err(error) => store_failure(error),
    }
}

/// `DELETE /devices/{id}`: nimmt ein Gerät aus der gültigen Menge und
/// widerruft dessen Sessions. Das anfragende Gerät kann sich nicht selbst
/// entfernen, damit niemand das letzte Gerät löscht und sich aussperrt;
/// Entfernen läuft immer über ein anderes Gerät.
///
/// Das Neuschlüsseln betroffener Gruppen (schnittstellen.md) folgt mit der
/// MLS-Anbindung; serverseitig ist die Revocation der auslösende Eintrag.
async fn remove_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    let who = match authenticate(&st, &headers).await {
        Ok(Some(identity)) => identity,
        Ok(None) => return invalid_token(),
        Err(error) => return session_failure(error),
    };
    if who.device_id == device_id {
        return api_error(
            StatusCode::CONFLICT,
            "own_device",
            "Das eigene Gerät lässt sich nicht entfernen",
        );
    }
    match st.store.revoke_device(&who.handle, &device_id).await {
        Ok(()) => {
            // Erst die Ablage, dann die Sessions: taucht dazwischen ein
            // Request des Geräts auf, scheitert er spätestens an der
            // nächsten Rotation; umgekehrt könnte ein frischer Login das
            // Fenster wieder öffnen.
            if let Err(error) = st.sessions.revoke_device(&who.handle, &device_id).await {
                // Gerät ist revoziert, aber alte Sessions leben noch bis zum
                // Ablauf: dem Aufrufer als Fehler melden, damit er es erneut
                // versucht, statt sich in Sicherheit zu wiegen.
                tracing::error!(%error, "Sessions des Geräts nicht widerrufen");
                return internal();
            }
            // Revocation = neue (kleinere) Schlüsselmenge im Verzeichnis;
            // für Kontakte wird der stille Weiterbetrieb des Geräts damit
            // entdeckbar.
            notify_kt(&st, &who.handle);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(StoreError::DeviceNotFound) => api_error(
            StatusCode::NOT_FOUND,
            "device_not_found",
            "Gerät ist unbekannt oder bereits entfernt",
        ),
        Err(error) => store_failure(error),
    }
}

/// Was das neue Gerät ablegt (`POST /provision`): die aus dem Geheimnis
/// abgeleitete Kanal-ID und der darunter verschlüsselte Antrag. Der Dienst
/// prüft nichts am Inhalt, er hält nur die opaken Bytes.
#[derive(Deserialize)]
struct ProvisionPutRequest {
    channel: String,
    nonce: String,
    ciphertext: String,
}

/// Was das freischaltende Gerät holt (`GET /provision/{channel}`).
#[derive(Serialize)]
struct ProvisionGetResponse {
    nonce: String,
    ciphertext: String,
}

/// `POST /provision`: legt einen verschlüsselten Kopplungs-Antrag unter
/// seiner Kanal-ID ab (QR-Kopplung, specs/geraete-identitaet.md). Tokenlos:
/// das neue Gerät ist noch nicht registriert, und der Inhalt ist für den
/// Dienst opak. Erster gewinnt: ein belegter Kanal wird abgewiesen, statt
/// still überschrieben (so fällt ein Vorpreschen auf).
async fn provision_put(
    State(st): State<AppState>,
    Json(req): Json<ProvisionPutRequest>,
) -> Response {
    match st.provision.put(&req.channel, req.nonce, req.ciphertext) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(PutError::InvalidChannel) => api_error(
            StatusCode::BAD_REQUEST,
            "invalid_channel",
            "Kanal-ID hat nicht das erwartete Format",
        ),
        Err(PutError::TooLarge) => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "der verschlüsselte Antrag ist zu groß",
        ),
        Err(PutError::ChannelTaken) => api_error(
            StatusCode::CONFLICT,
            "channel_taken",
            "dieser Kopplungs-Kanal ist bereits belegt",
        ),
        Err(PutError::Full) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay_full",
            "der Kopplungs-Relay ist vorübergehend voll",
        ),
    }
}

/// `GET /provision/{channel}`: holt den abgelegten Antrag. `None` (nie
/// abgelegt oder verfallen) ist ein 404 ohne weitere Auskunft.
async fn provision_get(State(st): State<AppState>, Path(channel): Path<String>) -> Response {
    match st.provision.get(&channel) {
        Some((nonce, ciphertext)) => (
            StatusCode::OK,
            Json(ProvisionGetResponse { nonce, ciphertext }),
        )
            .into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "channel_not_found",
            "kein Kopplungs-Antrag unter dieser Kanal-ID",
        ),
    }
}

/// Vorläufige Handle-Regel: 3 bis 32 Zeichen aus a-z, 0-9 sowie `_ . -`,
/// Beginn mit Buchstabe oder Ziffer. Die endgültige Policy hängt an Contact
/// Discovery und Key Transparency (dokumentation/specs/) und darf diese
/// Regel nur weiter einschränken, nicht lockern, sonst brechen Alt-Handles.
fn validate_handle(handle: &str) -> Result<(), &'static str> {
    let length = handle.chars().count();
    if !(3..=32).contains(&length) {
        return Err("Handle braucht 3 bis 32 Zeichen");
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
    {
        return Err("erlaubt sind a-z, 0-9 sowie _ . -");
    }
    if !handle
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err("Handle beginnt mit Buchstabe oder Ziffer");
    }
    Ok(())
}

/// Bidi-Steuerzeichen (LRM/RLM, LRE bis RLO samt PDF, LRI bis PDI): sie
/// drehen die Leserichtung benachbarten Texts um und machen Namen
/// spoofing-fähig („gnp.exe"-Muster), sobald eine spätere Etappe
/// Anzeigenamen anderen Nutzern zeigt. An der Schreibstelle abgewiesen,
/// weil Bestandsdaten nachträglich zu bereinigen teurer wäre.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Unsichtbare Format-Zeichen (Zero-Width-Familie, Soft Hyphen, Word
/// Joiner, BOM). Einzeln bleiben sie erlaubt, denn ZWJ/ZWNJ sind in
/// Emoji-Sequenzen und persischen wie indischen Namen legitim; nur ein
/// Name, der ausschließlich aus solchen Zeichen besteht, sähe leer aus.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' | '\u{180E}' | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

/// Anzeigename-Regel (F010): getrimmt 1 bis 64 Zeichen, keine Steuer-,
/// Zeilentrenner- oder Bidi-Zeichen, mindestens ein sichtbares Zeichen.
/// `Ok(None)` heißt: kein eigener Name angegeben (leer oder nur Weißraum),
/// der Aufrufer wählt dann seinen Rückfall (bei der Registrierung der
/// Handle). Der Deckel hält Anzeigen und Logs frei von Blob-Namen; anders
/// als beim Handle bleibt der Zeichenvorrat offen (Namen tragen Umlaute,
/// Leerzeichen, fremde Schriften).
fn normalize_display_name(input: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(trimmed) = input.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if trimmed.chars().count() > 64 {
        return Err("Anzeigename ist auf 64 Zeichen begrenzt");
    }
    // U+2028/U+2029 sind Zeilentrenner (Zl/Zp, nicht `is_control`), die
    // Anzeigen und Logs genauso brechen wie Steuerzeichen.
    if trimmed
        .chars()
        .any(|c| c.is_control() || is_bidi_control(c) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err("Anzeigename darf keine Steuer- oder Richtungszeichen enthalten");
    }
    // Ein Name nur aus unsichtbaren Zeichen (Zero-Width-Space und
    // Verwandte) erfüllte formal „nicht leer", sähe aber leer aus; der
    // Fehlertext des Endpunkts verspricht das Gegenteil.
    if !trimmed
        .chars()
        .any(|c| !c.is_whitespace() && !is_invisible_format(c))
    {
        return Err("Anzeigename braucht mindestens ein sichtbares Zeichen");
    }
    Ok(Some(trimmed.to_string()))
}

/// Längenregel statt Kompositionsregeln (NIST-Linie): mindestens 12 Zeichen,
/// nach oben auf 128 begrenzt, damit der Argon2-Aufwand gedeckelt bleibt.
fn validate_password(password: &str) -> Result<(), &'static str> {
    let length = password.chars().count();
    if length < 12 {
        return Err("Passwort braucht mindestens 12 Zeichen");
    }
    if length > 128 {
        return Err("Passwort ist auf 128 Zeichen begrenzt");
    }
    Ok(())
}

/// Geräte-IDs sind client-erzeugte UUIDs in kanonischer Kleinschreibung
/// (datenmodell.md: `devices.id UUID PRIMARY KEY`). Strikt kanonisch, weil
/// die ID Teil der signierten Credential-Nachricht ist: zwei Schreibweisen
/// derselben UUID wären zwei verschiedene Signaturen für dieselbe Identität.
fn validate_device_id(id: &str) -> Result<(), &'static str> {
    match uuid::Uuid::try_parse(id) {
        // to_string liefert die kanonische Form; Abgleich lehnt
        // Großschreibung, urn:-Präfix und Braced-Formen ab.
        Ok(parsed) if parsed.to_string() == id => Ok(()),
        _ => Err("Geräte-ID muss eine UUID in kanonischer Form sein"),
    }
}

/// Prüft das Shared Secret der /internal-Routen. Ohne konfiguriertes Token
/// existieren die Routen nach außen nicht (404 statt 401), damit ein
/// öffentlich erreichbarer Dienst ohne Secret keine interne Fläche zeigt.
/// Vergleich über SHA-256-Digests: konstante Zeit, kein Klartext im State.
/// `Some(response)` ist die Ablehnung; `None` heißt autorisiert.
fn internal_denied(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = &st.internal_token_hash else {
        return Some(StatusCode::NOT_FOUND.into_response());
    };
    let presented = headers
        .get("x-internal-token")
        .and_then(|v| v.to_str().ok());
    match presented {
        Some(token) if auth::token_hash(token) == **expected => None,
        _ => Some(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_internal_token",
            "Internes Token fehlt oder ist ungültig",
        )),
    }
}

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
}

/// Antwort im Zuschnitt von RFC 7662: `active` plus Identität nur bei
/// gültigem Token. Ungültig und abgelaufen sind nicht unterscheidbar.
#[derive(Serialize)]
struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

/// `POST /internal/introspect`: löst ein Access-Token zur Session-Identität
/// auf. Für Dienste wie directory, die Bearer-Tokens prüfen müssen, ohne
/// die Session-Ablage zu kennen.
async fn introspect(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IntrospectRequest>,
) -> Response {
    if let Some(response) = internal_denied(&st, &headers) {
        return response;
    }
    match st
        .sessions
        .authenticate(&auth::token_hash(&req.token))
        .await
    {
        Ok(identity) => {
            let (handle, device_id) = match identity {
                Some(who) => (Some(who.handle), Some(who.device_id)),
                None => (None, None),
            };
            (
                StatusCode::OK,
                Json(IntrospectResponse {
                    active: handle.is_some(),
                    handle,
                    device_id,
                }),
            )
                .into_response()
        }
        Err(error) => session_failure(error),
    }
}

#[derive(Serialize)]
struct InternalDeviceResponse {
    id: String,
    public_key: String,
    not_after: u64,
}

#[derive(Serialize)]
struct InternalAccountResponse {
    /// Server-erzeugte Konto-UUID: interne Adresse für andere Dienste
    /// (z. B. recipient_id in der Zustellung).
    id: String,
    handle: String,
    /// Öffentlicher Konto-Identitätsschlüssel (Base64), Teil des
    /// Prekey-Bündels beim Sitzungsaufbau.
    identity_key: String,
    devices: Vec<InternalDeviceResponse>,
}

/// `GET /internal/accounts/{handle}/devices`: Konto-Identitätsschlüssel und
/// die gültige (nicht revozierte) Gerätemenge. Grundlage der Prekey-Bündel
/// im directory-Dienst.
async fn internal_account_devices(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Response {
    if let Some(response) = internal_denied(&st, &headers) {
        return response;
    }
    let account = match st.store.get(&handle).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Konto ist unbekannt",
            )
        }
        Err(error) => return store_failure(error),
    };
    let devices = match st.store.devices(&handle).await {
        Ok(devices) => devices,
        Err(error) => return store_failure(error),
    };
    let devices = devices
        .into_iter()
        .filter(|d| !d.revoked)
        .map(|d| InternalDeviceResponse {
            id: d.id,
            public_key: d.public_key,
            not_after: d.not_after,
        })
        .collect();
    (
        StatusCode::OK,
        Json(InternalAccountResponse {
            id: account.id,
            handle: account.handle,
            identity_key: account.identity_key,
            devices,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_regeln() {
        assert!(validate_handle("alice").is_ok());
        assert!(validate_handle("a1.b-c_d").is_ok());
        assert!(validate_handle("ab").is_err()); // zu kurz
        assert!(validate_handle("Alice").is_err()); // Großbuchstabe
        assert!(validate_handle("-alice").is_err()); // falscher Beginn
        assert!(validate_handle("al ice").is_err()); // Leerzeichen
        assert!(validate_handle(&"x".repeat(33)).is_err()); // zu lang
    }

    #[test]
    fn passwort_regeln() {
        assert!(validate_password("zwölf-zeichen-lang").is_ok());
        assert!(validate_password("elf-zeichen").is_err());
        assert!(validate_password(&"p".repeat(129)).is_err());
    }

    #[test]
    fn geraete_id_regeln() {
        assert!(validate_device_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_device_id("").is_err());
        assert!(validate_device_id("laptop-1").is_err()); // keine UUID
        assert!(validate_device_id("550E8400-E29B-41D4-A716-446655440000").is_err()); // nicht kanonisch
        assert!(validate_device_id("urn:uuid:550e8400-e29b-41d4-a716-446655440000").is_err());
    }
}
