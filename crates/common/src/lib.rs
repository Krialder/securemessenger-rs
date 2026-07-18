//! Gemeinsame Bausteine für die SecureMessenger-Dienste.
//!
//! Bewusst ohne Nachrichten-Kryptografie: die lebt im Client-Core (libsignal,
//! OpenMLS), das Backend hält und verteilt Chiffretext
//! (dokumentation/architektur.md).

use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::get, Router};

/// Prozessweite Bereitschaft fuer die `/ready`-Probe. Startet als bereit und
/// wird beim Shutdown auf `false` gesetzt, damit Kubernetes den drainenden
/// Pod aus der Rotation nimmt, bevor der Server die letzten Anfragen auslaufen
/// laesst (sonst laufen noch neue Anfragen in einen sterbenden Pod).
static READY: AtomicBool = AtomicBool::new(true);

/// Setzt die Bereitschaft, die `/ready` meldet.
pub fn set_ready(ready: bool) {
    READY.store(ready, Ordering::Relaxed);
}

pub mod identity_client;
pub mod kt;
pub mod metrics;
pub mod rate;
pub mod ssrf;

pub mod http {
    //! Geteilter HTTP-Client fuer Dienst-zu-Dienst-Aufrufe.
    //!
    //! Immer mit Timeouts: ein verbundener, aber nicht antwortender
    //! Nachbardienst (etwa identity auf dem Auth-Heisspfad) wuerde sonst jede
    //! Anfrage unbegrenzt blockieren und Tasks samt DB-Pool erschoepfen, ein
    //! Kaskadenausfall. reqwest hat von sich aus KEINEN Request-Timeout.
    use std::time::Duration;

    /// reqwest-Client mit Verbindungs- und Gesamt-Timeout fuer interne Aufrufe.
    pub fn internal_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest-Client baubar")
    }
}

/// Ein Future, das aufloest, wenn der Prozess enden soll: SIGTERM (Unix, so
/// stoppt Kubernetes einen Pod) oder Ctrl-C. Fuer
/// `axum::serve(...).with_graceful_shutdown(...)`, damit laufende Anfragen und
/// WebSockets beim Rollout/Drain sauber auslaufen statt hart abzubrechen.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    // Erst unbereit melden (Kubernetes nimmt den Pod aus der Rotation), dann
    // laesst axum::serve die laufenden Anfragen auslaufen.
    set_ready(false);
    tracing::info!("Shutdown-Signal empfangen, fahre geordnet herunter");
    // Im Produktionsbetrieb kurz warten, damit Kubernetes die Unbereitschaft
    // sieht und keine neuen Anfragen mehr schickt, BEVOR der Server aufhoert
    // anzunehmen (sonst liefen sie in einen sterbenden Pod). Im
    // Entwicklungsbetrieb kein Warten, damit Ctrl-C sofort greift.
    if production_mode() {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Laeuft der Dienst im Produktionsbetrieb (`SM_ENV=production`)? Dann sind
/// Persistenz und Secrets Pflicht; fehlen sie, bricht der Start ab, statt
/// still auf In-Memory oder ephemere Schluessel auszuweichen (ein
/// Datenverlust- und Sicherheitsrisiko). Ohne den Schalter bleibt der
/// bequeme Entwicklungsbetrieb (Ausweichen mit Warnung).
pub fn production_mode() -> bool {
    std::env::var("SM_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// Bricht mit klarer Meldung ab, wenn im Produktionsbetrieb ein Pflicht-
/// Konfigurationswert fehlt. Im Entwicklungsbetrieb tut sie nichts.
pub fn require_in_production<T>(value: &Option<T>, name: &str) {
    if production_mode() && value.is_none() {
        panic!("{name} ist im Produktionsbetrieb (SM_ENV=production) Pflicht, fehlt aber");
    }
}

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
        // /live: lebt der Prozess ueberhaupt? (statisch ok, korrekt fuer
        // Liveness.) /ready: nimmt der Pod neue Anfragen an? Waehrend des
        // Shutdowns 503, damit Kubernetes ihn aus der Rotation nimmt.
        .route("/live", get(|| async { "ok" }))
        .route("/ready", get(ready_probe))
        .route("/metrics", get(serve_metrics))
}

async fn ready_probe() -> impl IntoResponse {
    if READY.load(Ordering::Relaxed) {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "shutting down")
    }
}

/// SLI-Metriken der prozessweiten Registry (siehe metrics-Modul); gefüllt
/// von der track-Middleware, die jeder Dienst einhängt.
async fn serve_metrics() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics::render(),
    )
}

#[cfg(test)]
mod tests {
    use super::{production_mode, require_in_production};

    #[test]
    fn require_in_production_only_bricht_im_produktionsbetrieb_ab() {
        // Ohne Produktionsschalter: kein Abbruch, auch bei fehlendem Wert.
        std::env::remove_var("SM_ENV");
        assert!(!production_mode());
        require_in_production::<String>(&None, "TEST_WERT");

        // Mit Schalter: ein fehlender Pflichtwert bricht den Start ab.
        std::env::set_var("SM_ENV", "production");
        assert!(production_mode());
        let abgebrochen =
            std::panic::catch_unwind(|| require_in_production::<String>(&None, "TEST_WERT"))
                .is_err();
        assert!(
            abgebrochen,
            "fehlender Wert muss im Produktionsbetrieb abbrechen"
        );
        // Ein gesetzter Wert ist auch im Produktionsbetrieb in Ordnung.
        require_in_production(&Some("da".to_string()), "TEST_WERT");
        std::env::remove_var("SM_ENV");
    }
}
