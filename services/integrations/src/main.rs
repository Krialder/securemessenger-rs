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
    common::require_in_production(&cfg.database_url, "DATABASE_URL");

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

    // Webhook-Signierpaar: aus dem Betriebs-Seed, sonst ephemer (dann
    // ändert sich der öffentliche Schlüssel über Neustarts, Empfänger
    // müssten ihn neu holen). Ein kaputter Seed bricht den Start ab, statt
    // still ephemer zu werden.
    let webhook_signer = match std::env::var("INTEGRATIONS_WEBHOOK_SIGNING_KEY") {
        Ok(seed) if !seed.is_empty() => Arc::new(
            integrations::webhook::WebhookSigner::from_seed_b64(&seed)
                .expect("INTEGRATIONS_WEBHOOK_SIGNING_KEY ist ein gültiger Base64-32-Byte-Seed"),
        ),
        _ => {
            tracing::warn!(
                "INTEGRATIONS_WEBHOOK_SIGNING_KEY nicht gesetzt, ephemerer Webhook-Schlüssel"
            );
            Arc::new(integrations::webhook::WebhookSigner::ephemeral())
        }
    };

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
    .with_internal_token(internal_token)
    .with_webhook_signer(webhook_signer)
    // SSRF-Schutz standardmäßig an; nur der lokale Lauf erlaubt
    // Webhook-Ziele auf localhost (INTEGRATIONS_ALLOW_PRIVATE_WEBHOOKS=1).
    .allow_private_webhooks(
        std::env::var("INTEGRATIONS_ALLOW_PRIVATE_WEBHOOKS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    );

    // Outbox-Worker starten, bevor der State in den Router wandert: er liefert
    // die von /internal/presence-event eingereihten Webhooks mit Wiederholung.
    state.spawn_outbox_worker();

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
