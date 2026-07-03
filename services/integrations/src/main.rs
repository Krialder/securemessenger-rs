//! Einstiegspunkt: baut den Router aus integrations::api und startet den Server.

use std::sync::Arc;

use common::identity_client::HttpIdentityGateway;
use common::{config::ServiceConfig, telemetry};
use integrations::api::{app, AppState};
use integrations::pg;
use integrations::realtime_client::HttpRealtimeGateway;
use integrations::store::InMemoryTenantStore;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("integrations");

    // Ohne die Nachbardienste kann der Dienst weder Nutzer auflösen noch
    // Events zustellen: harter Startfehler statt eines Dienstes, der jede
    // Anfrage mit 500 beantwortet.
    let identity_url = cfg
        .identity_url
        .as_deref()
        .expect("IDENTITY_URL ist Pflicht (Basis-URL des identity-Dienstes)");
    let delivery_url = cfg
        .delivery_url
        .as_deref()
        .expect("DELIVERY_URL ist Pflicht (Basis-URL des delivery-Dienstes)");
    let internal_token = cfg
        .internal_token
        .as_deref()
        .expect("INTERNAL_TOKEN ist Pflicht (Shared Secret der internen Routen)");
    let identity = Arc::new(HttpIdentityGateway::new(identity_url, internal_token));
    let realtime = Arc::new(HttpRealtimeGateway::new(delivery_url, internal_token));

    let state = match &cfg.database_url {
        Some(url) => {
            let pool = pg::connect_and_migrate(url)
                .await
                .expect("PostgreSQL erreichbar und migrierbar");
            tracing::info!("Persistenz: PostgreSQL");
            AppState::new(Arc::new(pg::PgTenantStore::new(pool)), identity, realtime)
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, Mandanten nur im Prozessspeicher");
            AppState::new(Arc::new(InMemoryTenantStore::default()), identity, realtime)
        }
    }
    // Dasselbe Shared Secret in beide Richtungen: integrations weist
    // sich bei identity/delivery aus und schaltet seine eigene
    // Mandanten-Anlage-Route frei.
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
