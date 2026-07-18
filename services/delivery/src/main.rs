//! Einstiegspunkt: baut den Router aus delivery::api und startet den Server.

use std::sync::Arc;

use common::identity_client::HttpIdentityGateway;
use common::{config::ServiceConfig, telemetry};
use delivery::api::{app, AppState};
use delivery::integrations_client::HttpIntegrationsGateway;
use delivery::pg;
use delivery::push::{VapidKeys, VapidPushSender};
use delivery::store::InMemoryMessageStore;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("delivery");
    common::require_in_production(&cfg.database_url, "DATABASE_URL");

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
            AppState::new(Arc::new(pg::PgMessageStore::new(pool.clone())), identity)
                .with_group_store(Arc::new(pg::PgGroupStore::new(pool)))
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

    // Optional: Präsenz-Änderungen an integrations melden (Webhooks). Ohne
    // INTEGRATIONS_URL bleibt es beim Noop, der Chat-Kern hängt nicht daran.
    let state = match cfg.integrations_url.as_deref() {
        Some(url) => {
            tracing::info!(%url, "Präsenz-Webhooks an integrations aktiv");
            state.with_integrations(Arc::new(HttpIntegrationsGateway::new(url, internal_token)))
        }
        None => state,
    };

    // Optional: Web-Push (VAPID). Ohne VAPID_PRIVATE_KEY bleibt es beim Noop
    // (Push aus). Ein GESETZTER, aber kaputter Schlüssel ist ein
    // Betriebsfehler und bricht den Start ab statt still Push abzuschalten.
    let state = match std::env::var("VAPID_PRIVATE_KEY")
        .ok()
        .filter(|key| !key.is_empty())
    {
        Some(private_key) => {
            let keys = VapidKeys::from_private_base64(&private_key)
                .expect("VAPID_PRIVATE_KEY ist ein gültiger base64url-P-256-Schlüssel");
            let subject = std::env::var("VAPID_SUBJECT")
                .unwrap_or_else(|_| "mailto:admin@securemessenger.local".to_string());
            tracing::info!("Web-Push (VAPID) aktiv");
            state.with_push(Arc::new(VapidPushSender::new(keys, &subject)))
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
