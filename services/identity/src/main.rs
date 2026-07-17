//! Einstiegspunkt: baut den Router aus identity::api und startet den Server.

use std::sync::Arc;

use common::{config::ServiceConfig, telemetry};
use identity::api::{app, AppState};
use identity::pg;
use identity::session::SessionConfig;

/// Obergrenze fuer beide Token-Laufzeiten: 10 Jahre. Faengt die klassische
/// Millisekunden-Verwechslung (30 Tage als 2592000000 waeren 82 Jahre) und
/// bleibt weit unter dem Punkt, an dem die Unix-Sekunden-Arithmetik der
/// Ablage kippen koennte.
const TTL_MAX_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Liest eine Token-Laufzeit aus der Umgebung. Fehlt die Variable (oder ist
/// sie leer), gilt die Vorgabe; ist sie gesetzt, aber kein brauchbarer Wert
/// (unparsbar, 0, jenseits von zehn Jahren), bricht der Start ab. Der
/// Unterschied ist Absicht: eine fehlende Variable ist der Normalfall, ein
/// gesetzter-aber-kaputter Wert ist eine Fehlkonfiguration, und ein Dienst,
/// der sie still verwirft, liefe mit anderen Laufzeiten als der Betreiber
/// glaubt (etwa 30 Tage Refresh statt der beabsichtigten Verkuerzung).
/// Gleiches Muster wie bei den uebrigen Pflicht-Secrets in dieser Datei.
fn ttl_from_env(name: &str, default: std::time::Duration) -> std::time::Duration {
    let Ok(raw) = std::env::var(name) else {
        return default;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return default;
    }
    let secs: u64 = raw
        .parse()
        .unwrap_or_else(|_| panic!("{name} ist keine Ganzzahl in Sekunden: '{raw}'"));
    assert!(secs > 0, "{name} muss groesser als 0 sein");
    assert!(
        secs <= TTL_MAX_SECS,
        "{name} ist groesser als 10 Jahre ({secs} s); Sekunden statt Millisekunden angeben"
    );
    std::time::Duration::from_secs(secs)
}

/// Token-Laufzeiten aus der Umgebung, sonst die Vorgaben (15 min Access,
/// 30 Tage Refresh). ACCESS_TTL_SECS und REFRESH_TTL_SECS erlauben einer
/// Betriebsumgebung eine andere Wahl, ohne dass ein Client dafuer gebaut
/// werden muss; in der Entwicklung macht ein kurzer Access-Wert die
/// Token-Erneuerung des Clients binnen Sekunden statt Minuten pruefbar.
fn session_config_from_env() -> SessionConfig {
    let default = SessionConfig::default();
    let config = SessionConfig {
        access_ttl: ttl_from_env("ACCESS_TTL_SECS", default.access_ttl),
        refresh_ttl: ttl_from_env("REFRESH_TTL_SECS", default.refresh_ttl),
    };
    if config.access_ttl != default.access_ttl {
        tracing::info!(
            access_ttl_secs = config.access_ttl.as_secs(),
            "Access-Token-Laufzeit aus Umgebung"
        );
    }
    if config.refresh_ttl != default.refresh_ttl {
        tracing::info!(
            refresh_ttl_secs = config.refresh_ttl.as_secs(),
            "Refresh-Token-Laufzeit aus Umgebung"
        );
    }
    config
}

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("identity");
    common::require_in_production(&cfg.database_url, "DATABASE_URL");
    common::require_in_production(&cfg.internal_token, "INTERNAL_TOKEN");

    // Mit DATABASE_URL persistiert der Dienst in PostgreSQL, ohne läuft er
    // mit prozesslokaler Ablage (Entwicklung, Tests). Schlägt Verbindung
    // oder Migration fehl, bricht der Start ab: ein Dienst, der still ohne
    // Persistenz anläuft, wäre in Produktion ein Datenverlust.
    let state = match &cfg.database_url {
        Some(url) => {
            let pool = pg::connect_and_migrate(url)
                .await
                .expect("PostgreSQL erreichbar und migrierbar");
            let session_config = session_config_from_env();
            tracing::info!("Persistenz: PostgreSQL");
            AppState::with_stores(
                Arc::new(pg::PgAccountStore::new(pool.clone())),
                Arc::new(pg::PgSessionStore::new(pool, session_config)),
                session_config,
            )
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, Daten nur im Prozessspeicher");
            // Die TTL-Variablen gelten auch hier: gerade der Modus ohne
            // Datenbank ist der Entwicklungsfall, fuer den ein kurzer
            // Access-Wert gedacht ist; ein Knopf, der je nach Persistenz
            // still ins Leere griffe, wuerde Fehlkonfiguration verschleiern.
            AppState::with_session_config(session_config_from_env())
        }
    };

    // Mit INTERNAL_TOKEN stehen die /internal-Routen (Introspektion,
    // Gerätemenge) für andere Dienste bereit, ohne bleiben sie 404.
    let state = match &cfg.internal_token {
        Some(token) => {
            tracing::info!("interne Routen freigeschaltet");
            state.with_internal_token(token)
        }
        None => state,
    };

    // Mit KT_URL meldet identity jede Schlüsseländerung ans
    // KT-Verzeichnis (F120); das Shared Secret ist dasselbe wie überall.
    let state = match (std::env::var("KT_URL").ok(), &cfg.internal_token) {
        (Some(kt_url), Some(token)) if !kt_url.is_empty() => {
            tracing::info!(%kt_url, "KT-Meldungen aktiv");
            state.with_kt_notifier(Arc::new(identity::kt_notify::HttpKtNotifier::new(
                &kt_url, token,
            )))
        }
        (Some(_), None) => {
            tracing::warn!("KT_URL gesetzt, aber INTERNAL_TOKEN fehlt; KT-Meldungen bleiben aus");
            state
        }
        _ => state,
    };

    // Mit CDS_OPRF_KEY (Base64-Seed, 32 Byte) steht Contact Discovery
    // bereit; ohne bleiben die /discovery-Routen 404. Ein flüchtiger
    // Schlüssel waere nach einem Neustart nicht mehr zum vorhandenen
    // Discovery-Index passend, deshalb hier Pflicht-Secret statt Default.
    let state = match std::env::var("CDS_OPRF_KEY").ok().filter(|s| !s.is_empty()) {
        Some(seed_b64) => {
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine as _;
            let seed = BASE64
                .decode(&seed_b64)
                .expect("CDS_OPRF_KEY ist gültiges Base64");
            let key =
                oprf::ServerKey::from_seed(&seed).expect("CDS_OPRF_KEY ergibt OPRF-Schlüssel");
            tracing::info!("Contact Discovery aktiv");
            state.with_discovery_oprf(Arc::new(key))
        }
        None => state,
    };

    // Mit POW_DIFFICULTY (fuehrende Nullbits) verlangt die Registrierung
    // einen Proof-of-Work als Sybil-Bremse; 0 oder ungesetzt = aus.
    let state = match std::env::var("POW_DIFFICULTY")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|bits| *bits > 0)
    {
        Some(bits) => {
            tracing::info!(bits, "Proof-of-Work bei der Registrierung aktiv");
            state.with_pow_difficulty(bits)
        }
        None => state,
    };

    // Mit SEALED_SENDER_TRUST_ROOT (Base64, 32 Byte) stellt der Dienst
    // Sealed-Sender-Zertifikate aus; ohne bleiben die Routen 404. Der
    // Serverschlüssel entsteht bei jedem Start frisch und wird vom Trust
    // Root signiert; nur der Trust Root muss stabil bleiben, weil er der
    // Anker in den Clients ist (crates/sealed-cert).
    let state = match std::env::var("SEALED_SENDER_TRUST_ROOT")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(seed_b64) => {
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine as _;
            let seed = BASE64
                .decode(seed_b64.trim())
                .expect("SEALED_SENDER_TRUST_ROOT ist gültiges Base64");
            let issuer = sealed_cert::Issuer::from_seed(&seed)
                .expect("SEALED_SENDER_TRUST_ROOT ergibt einen 32-Byte-Schlüssel");
            tracing::info!("Sealed-Sender-Zertifikatsausgabe aktiv");
            state.with_sealed_sender(Arc::new(issuer))
        }
        None => state,
    };

    let router = app(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .expect("Bind-Adresse belegbar");

    tracing::info!(
        service = %cfg.service_name,
        addr = %cfg.bind_addr,
        "Dienst gestartet"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(common::shutdown_signal())
        .await
        .expect("Server läuft");
}
