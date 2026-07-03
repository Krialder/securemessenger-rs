//! Einstiegspunkt: baut den Router aus media::api und startet den Server.

use std::sync::Arc;

use common::identity_client::HttpIdentityGateway;
use common::{config::ServiceConfig, telemetry};
use media::api::{app, AppState};
use object_store::aws::AmazonS3Builder;
use object_store::memory::InMemory;
use object_store::ObjectStore;

#[tokio::main]
async fn main() {
    telemetry::init();
    let cfg = ServiceConfig::from_env("media");

    let identity_url = cfg
        .identity_url
        .as_deref()
        .expect("IDENTITY_URL ist Pflicht (Basis-URL des identity-Dienstes)");
    let internal_token = cfg
        .internal_token
        .as_deref()
        .expect("INTERNAL_TOKEN ist Pflicht (Shared Secret der internen identity-Routen)");
    let identity = Arc::new(HttpIdentityGateway::new(identity_url, internal_token));

    // Objektspeicher: S3/MinIO, wenn konfiguriert (NF120), sonst
    // In-Memory mit Warnung - gleiches Muster wie DATABASE_URL bei den
    // anderen Diensten. Schlägt die S3-Konfiguration fehl, bricht der
    // Start ab, statt still ohne Persistenz zu laufen.
    let store: Arc<dyn ObjectStore> = match std::env::var("MEDIA_S3_BUCKET") {
        Ok(bucket) if !bucket.is_empty() => {
            let endpoint = std::env::var("MEDIA_S3_ENDPOINT")
                .expect("MEDIA_S3_ENDPOINT ist Pflicht, wenn MEDIA_S3_BUCKET gesetzt ist");
            let s3 = AmazonS3Builder::from_env()
                .with_bucket_name(&bucket)
                .with_endpoint(&endpoint)
                // MinIO im Cluster spricht intern HTTP; TLS terminiert
                // die Edge (betrieb.md).
                .with_allow_http(true)
                .build()
                .expect("S3/MinIO-Konfiguration gültig");
            tracing::info!(%bucket, %endpoint, "Blob-Ablage: S3/MinIO");
            Arc::new(s3)
        }
        _ => {
            tracing::warn!("MEDIA_S3_BUCKET nicht gesetzt, Blobs nur im Prozessspeicher");
            Arc::new(InMemory::new())
        }
    };

    let state = AppState::new(store, identity);
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
