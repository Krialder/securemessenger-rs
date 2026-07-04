//! Einstiegspunkt: baut den Router aus identity::api und startet den Server.

use std::sync::Arc;

use common::{config::ServiceConfig, telemetry};
use identity::api::{app, AppState};
use identity::pg;
use identity::session::SessionConfig;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("identity");

    // Mit DATABASE_URL persistiert der Dienst in PostgreSQL, ohne läuft er
    // mit prozesslokaler Ablage (Entwicklung, Tests). Schlägt Verbindung
    // oder Migration fehl, bricht der Start ab: ein Dienst, der still ohne
    // Persistenz anläuft, wäre in Produktion ein Datenverlust.
    let state = match &cfg.database_url {
        Some(url) => {
            let pool = pg::connect_and_migrate(url)
                .await
                .expect("PostgreSQL erreichbar und migrierbar");
            let session_config = SessionConfig::default();
            tracing::info!("Persistenz: PostgreSQL");
            AppState::with_stores(
                Arc::new(pg::PgAccountStore::new(pool.clone())),
                Arc::new(pg::PgSessionStore::new(pool, session_config)),
                session_config,
            )
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, Daten nur im Prozessspeicher");
            AppState::new_in_memory()
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

    let router = app(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .expect("Bind-Adresse belegbar");

    tracing::info!(
        service = %cfg.service_name,
        addr = %cfg.bind_addr,
        "Dienst gestartet"
    );

    axum::serve(listener, router).await.expect("Server läuft");
}
