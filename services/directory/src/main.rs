//! Einstiegspunkt: baut den Router aus directory::api und startet den Server.

use std::sync::Arc;

use common::identity_client::HttpIdentityGateway;
use common::{config::ServiceConfig, telemetry};
use directory::api::{app, AppState};
use directory::pg;
use directory::store::InMemoryPrekeyStore;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("directory");

    // Ohne identity-Anbindung kann der Dienst keine Tokens prüfen und
    // keine Gerätemengen auflösen: harter Startfehler statt eines Dienstes,
    // der jede Anfrage mit 500 beantwortet.
    let identity_url = cfg
        .identity_url
        .as_deref()
        .expect("IDENTITY_URL ist Pflicht (Basis-URL des identity-Dienstes)");
    let internal_token = cfg
        .internal_token
        .as_deref()
        .expect("INTERNAL_TOKEN ist Pflicht (Shared Secret der internen identity-Routen)");
    let identity = Arc::new(HttpIdentityGateway::new(identity_url, internal_token));

    let state = match &cfg.database_url {
        Some(url) => {
            let pool = pg::connect_and_migrate(url)
                .await
                .expect("PostgreSQL erreichbar und migrierbar");
            tracing::info!("Persistenz: PostgreSQL");
            AppState::new(Arc::new(pg::PgPrekeyStore::new(pool)), identity)
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, Prekeys nur im Prozessspeicher");
            AppState::new(Arc::new(InMemoryPrekeyStore::default()), identity)
        }
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
