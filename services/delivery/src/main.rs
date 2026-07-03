//! Einstiegspunkt: baut den Router aus delivery::api und startet den Server.

use std::sync::Arc;

use common::identity_client::HttpIdentityGateway;
use common::{config::ServiceConfig, telemetry};
use delivery::api::{app, AppState};
use delivery::pg;
use delivery::store::InMemoryMessageStore;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("delivery");

    // Ohne identity-Anbindung kann der Dienst keine Tokens prüfen und
    // keine Empfänger auflösen: harter Startfehler statt eines Dienstes,
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
            AppState::new(Arc::new(pg::PgMessageStore::new(pool)), identity)
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, Nachrichten nur im Prozessspeicher");
            AppState::new(Arc::new(InMemoryMessageStore::default()), identity)
        }
    }
    // Dasselbe Shared Secret in beide Richtungen: delivery weist sich
    // damit bei identity aus und schaltet seine eigenen /internal-Routen
    // (Events, Präsenz) für integrations frei.
    .with_internal_token(internal_token);

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
