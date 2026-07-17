//! Einstiegspunkt: baut Verzeichnis und Router, startet den
//! Epochen-Publisher und den Server.

use std::sync::Arc;
use std::time::Duration;

use common::{config::ServiceConfig, telemetry};
use kt::api::{app, AppState};
use kt::directory::KtDirectory;
use kt::keys::{RootSigner, SecretVrf};
use kt::pg;
use kt::store::{InMemoryKtStore, KtStore};

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("kt");
    common::require_in_production(&cfg.database_url, "DATABASE_URL");
    common::require_in_production(&cfg.internal_token, "INTERNAL_TOKEN");

    // Schlüssel aus Secrets; ohne Konfiguration flüchtige Dev-Schlüssel
    // mit deutlicher Warnung (Wurzeln überleben dann keinen Neustart).
    let signer = match std::env::var("KT_SIGNING_KEY") {
        Ok(seed) if !seed.is_empty() => {
            RootSigner::from_seed_b64(&seed).expect("KT_SIGNING_KEY gültig (Base64, 32 Byte)")
        }
        _ => {
            // Ein flüchtiger KT-Signaturschlüssel bricht die Transparenz-
            // Garantie über Neustarts: im Produktionsbetrieb harter Fehler.
            if common::production_mode() {
                panic!("KT_SIGNING_KEY ist im Produktionsbetrieb (SM_ENV=production) Pflicht");
            }
            tracing::warn!(
                "KT_SIGNING_KEY nicht gesetzt, flüchtiger Signaturschlüssel (nur Entwicklung)"
            );
            RootSigner::ephemeral()
        }
    };
    let vrf = match std::env::var("KT_VRF_KEY") {
        Ok(seed) if !seed.is_empty() => {
            SecretVrf::from_seed_b64(&seed).expect("KT_VRF_KEY gültig (Base64, 32 Byte)")
        }
        _ => {
            if common::production_mode() {
                panic!("KT_VRF_KEY ist im Produktionsbetrieb (SM_ENV=production) Pflicht");
            }
            tracing::warn!("KT_VRF_KEY nicht gesetzt, flüchtiger VRF-Schlüssel (nur Entwicklung)");
            SecretVrf::ephemeral()
        }
    };

    let store: Arc<dyn KtStore> = match &cfg.database_url {
        Some(url) => {
            let pool = pg::connect_and_migrate(url)
                .await
                .expect("PostgreSQL erreichbar und migrierbar");
            tracing::info!("Persistenz: PostgreSQL");
            Arc::new(pg::PgKtStore::new(pool))
        }
        None => {
            tracing::warn!("DATABASE_URL nicht gesetzt, KT-Log nur im Prozessspeicher");
            Arc::new(InMemoryKtStore::default())
        }
    };

    // Wiederaufbau aus dem Log; ein Integritätsbruch ist ein harter
    // Startfehler (directory.rs).
    let directory = Arc::new(
        KtDirectory::rebuild(store.as_ref(), vrf, signer)
            .await
            .expect("KT-Verzeichnis aus dem Log wiederaufbaubar"),
    );
    tracing::info!(
        root_signing_key = %directory.signer().public_key_b64(),
        "KT-Verzeichnis bereit"
    );

    // Epochen-Publisher: bündelt wartende Updates periodisch zu einer
    // Epoche. [ANNAHME: 1 Stunde, Spec-Zielbereich 1 bis 6 Stunden;
    // KT_EPOCH_SECONDS übersteuert für Entwicklung und Tests.]
    let epoch_seconds = std::env::var("KT_EPOCH_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    {
        let store = store.clone();
        let directory = directory.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(epoch_seconds.max(1)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match directory.publish_pending(store.as_ref()).await {
                    Ok(Some(record)) => {
                        tracing::info!(epoch = record.epoch, "KT-Epoche veröffentlicht");
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(%error, "Epochen-Veröffentlichung fehlgeschlagen");
                    }
                }
            }
        });
    }

    let mut state = AppState::new(store, directory);
    if let Some(internal_token) = cfg.internal_token.as_deref() {
        state = state.with_internal_token(internal_token);
    } else {
        tracing::warn!("INTERNAL_TOKEN nicht gesetzt, /internal/updates bleibt aus");
    }

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
