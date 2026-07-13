//! Gemeinsame Bausteine für die SecureMessenger-Dienste.
//!
//! Bewusst ohne Nachrichten-Kryptografie: die lebt im Client-Core (libsignal,
//! OpenMLS), das Backend hält und verteilt Chiffretext
//! (dokumentation/architektur.md).

use axum::http::header;
use axum::response::IntoResponse;
use axum::{routing::get, Router};

pub mod identity_client;
pub mod kt;
pub mod metrics;
pub mod rate;

pub mod telemetry {
    //! Strukturiertes Logging nach stdout, niemals mit Nachrichteninhalt (NF100).
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    /// Initialisiert das globale Tracing-Subsystem mit JSON-Logs nach stdout.
    /// Das Log-Level kommt aus `RUST_LOG`, Default `info`.
    pub fn init() {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    }
}

pub mod config {
    //! Konfiguration aus Umgebungsvariablen, keine Secrets im Code.
    use std::net::SocketAddr;

    /// Basis-Konfiguration, die jeder Dienst teilt.
    #[derive(Debug, Clone)]
    pub struct ServiceConfig {
        /// Adresse, auf der der HTTP-Server lauscht.
        pub bind_addr: SocketAddr,
        /// Dienstname, nur für Logs und Metriken.
        pub service_name: String,
        /// PostgreSQL-Verbindung. Ohne `DATABASE_URL` startet ein Dienst mit
        /// prozesslokaler Ablage: lokal entwickeln ohne Infrastruktur,
        /// im Cluster ist die Variable per Deployment gesetzt.
        pub database_url: Option<String>,
        /// Shared Secret für Dienst-zu-Dienst-Aufrufe (`INTERNAL_TOKEN`).
        /// identity schaltet damit seine /internal-Routen frei, andere
        /// Dienste weisen sich damit aus. Ohne Wert bleiben interne Routen
        /// aus; im Cluster kommt das Secret aus einem Kubernetes-Secret.
        pub internal_token: Option<String>,
        /// Basis-URL des identity-Dienstes (`IDENTITY_URL`) für Dienste,
        /// die Tokens introspektieren oder Gerätelisten brauchen.
        pub identity_url: Option<String>,
        /// Basis-URL des delivery-Dienstes (`DELIVERY_URL`) für Dienste,
        /// die Echtzeit-Events auslösen oder Präsenz abfragen (integrations).
        pub delivery_url: Option<String>,
        /// Basis-URL des integrations-Dienstes (`INTEGRATIONS_URL`); delivery
        /// meldet dorthin Präsenz-Änderungen für die Webhooks. Optional: ohne
        /// Wert läuft delivery ohne die Webhook-Anbindung.
        pub integrations_url: Option<String>,
    }

    impl ServiceConfig {
        /// Liest die Konfiguration aus der Umgebung.
        /// `BIND_ADDR` Default `0.0.0.0:8080`, `SERVICE_NAME` Default `default_name`.
        pub fn from_env(default_name: &str) -> Self {
            let bind_addr = std::env::var("BIND_ADDR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| "0.0.0.0:8080".parse().expect("gültige Default-Adresse"));
            let service_name =
                std::env::var("SERVICE_NAME").unwrap_or_else(|_| default_name.to_string());
            let non_empty = |name: &str| std::env::var(name).ok().filter(|s| !s.is_empty());
            Self {
                bind_addr,
                service_name,
                database_url: non_empty("DATABASE_URL"),
                internal_token: non_empty("INTERNAL_TOKEN"),
                identity_url: non_empty("IDENTITY_URL"),
                delivery_url: non_empty("DELIVERY_URL"),
                integrations_url: non_empty("INTEGRATIONS_URL"),
            }
        }
    }
}

/// Betriebs-Endpunkte, die jeder Dienst braucht: `/live` und `/ready` als
/// Kubernetes-Probes (NF100) sowie `/metrics` im Prometheus-Textformat.
/// Generisch über den State, damit sich der Router in jeden Dienst-Router
/// mergen lässt; die Handler selbst brauchen keinen State.
pub fn ops_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/live", get(|| async { "ok" }))
        .route("/ready", get(|| async { "ok" }))
        .route("/metrics", get(serve_metrics))
}

/// SLI-Metriken der prozessweiten Registry (siehe metrics-Modul); gefüllt
/// von der track-Middleware, die jeder Dienst einhängt.
async fn serve_metrics() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics::render(),
    )
}
