//! SLI-Metriken im Prometheus-Format (betrieb.md "Beobachtbarkeit").
//!
//! Zwei Messgrößen speisen die SLO-Auswertung: Anfragen je Route und
//! Status (Verfügbarkeit) und ein Latenz-Histogramm je Route (p95/p99
//! rechnet Prometheus aus den Buckets). Bewusst handgeschrieben statt
//! über ein Metrik-Framework: zwei Instrumente, feste Buckets, keine
//! weitere Abhängigkeit. Die Route ist das axum-Routenmuster
//! (MatchedPath), nie der rohe Pfad - sonst explodiert die Kardinalität
//! mit jedem Handle in der URL.
//!
//! Die Registry ist prozessweit (LazyLock): jeder Dienst hat genau
//! eine, die Middleware schreibt, der /metrics-Endpunkt liest.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

/// Bucket-Grenzen in Sekunden. Feinauflösung unten (API-Ziel p95 < 2 s,
/// Zustellpfad p95 < 500 ms), oben offen über +Inf.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Default)]
struct RouteLatency {
    /// Kumulative Zähler je Bucket (Prometheus-Histogramm-Semantik
    /// entsteht erst beim Rendern; hier zählt jeder Bucket exakt).
    buckets: [u64; BUCKETS.len()],
    sum: f64,
    count: u64,
}

#[derive(Default)]
pub struct Registry {
    /// (Methode, Route, Status) -> Anzahl.
    requests: Mutex<HashMap<(String, String, u16), u64>>,
    /// Route -> Latenzverteilung.
    latency: Mutex<HashMap<String, RouteLatency>>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::default);

impl Registry {
    fn record(&self, method: &str, route: &str, status: u16, seconds: f64) {
        {
            let mut requests = self.requests.lock().expect("Metrik-Lock nicht vergiftet");
            *requests
                .entry((method.to_string(), route.to_string(), status))
                .or_insert(0) += 1;
        }
        let mut latency = self.latency.lock().expect("Metrik-Lock nicht vergiftet");
        let entry = latency.entry(route.to_string()).or_default();
        for (i, bound) in BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                entry.buckets[i] += 1;
            }
        }
        entry.sum += seconds;
        entry.count += 1;
    }

    fn render(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str(
            "# HELP process_up 1 wenn der Dienst laeuft\n# TYPE process_up gauge\nprocess_up 1\n",
        );

        out.push_str("# HELP http_requests_total Anfragen je Methode, Route und Status\n# TYPE http_requests_total counter\n");
        let requests = self.requests.lock().expect("Metrik-Lock nicht vergiftet");
        let mut lines: Vec<String> = requests
            .iter()
            .map(|((method, route, status), count)| {
                format!(
                    "http_requests_total{{method=\"{method}\",route=\"{route}\",status=\"{status}\"}} {count}\n"
                )
            })
            .collect();
        drop(requests);
        // Sortiert, damit die Ausgabe deterministisch ist (Tests, Diffs).
        lines.sort();
        for line in lines {
            out.push_str(&line);
        }

        out.push_str("# HELP http_request_duration_seconds Antwortzeit je Route\n# TYPE http_request_duration_seconds histogram\n");
        let latency = self.latency.lock().expect("Metrik-Lock nicht vergiftet");
        let mut routes: Vec<&String> = latency.keys().collect();
        routes.sort();
        for route in routes {
            let entry = &latency[route];
            for (i, bound) in BUCKETS.iter().enumerate() {
                out.push_str(&format!(
                    "http_request_duration_seconds_bucket{{route=\"{route}\",le=\"{bound}\"}} {}\n",
                    entry.buckets[i]
                ));
            }
            out.push_str(&format!(
                "http_request_duration_seconds_bucket{{route=\"{route}\",le=\"+Inf\"}} {}\n",
                entry.count
            ));
            out.push_str(&format!(
                "http_request_duration_seconds_sum{{route=\"{route}\"}} {}\n",
                entry.sum
            ));
            out.push_str(&format!(
                "http_request_duration_seconds_count{{route=\"{route}\"}} {}\n",
                entry.count
            ));
        }
        out
    }
}

/// axum-Middleware: misst jede Anfrage. Einhängen mit
/// `.layer(axum::middleware::from_fn(common::metrics::track))`.
pub async fn track(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    // Das Routenmuster, nicht der rohe Pfad (Kardinalität). Anfragen
    // ohne Match (404) laufen unter "unmatched".
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let start = Instant::now();
    let response = next.run(request).await;
    REGISTRY.record(
        &method,
        &route,
        response.status().as_u16(),
        start.elapsed().as_secs_f64(),
    );
    response
}

/// Prometheus-Textformat für den /metrics-Endpunkt.
pub fn render() -> String {
    REGISTRY.render()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders_prometheus_format() {
        REGISTRY.record("GET", "/messages", 200, 0.03);
        REGISTRY.record("GET", "/messages", 200, 0.7);
        REGISTRY.record("POST", "/messages", 500, 0.001);

        let text = render();
        assert!(text.contains("process_up 1"));
        assert!(text
            .contains("http_requests_total{method=\"GET\",route=\"/messages\",status=\"200\"} 2"));
        assert!(text
            .contains("http_requests_total{method=\"POST\",route=\"/messages\",status=\"500\"} 1"));
        // 0.03 liegt in le=0.05, 0.7 erst in le=1: der 0.05er-Bucket
        // zaehlt mindestens einen, der +Inf-Bucket alle drei... genauer:
        // je Route; /messages hat 3 Messungen.
        assert!(text
            .contains("http_request_duration_seconds_bucket{route=\"/messages\",le=\"+Inf\"} 3"));
        assert!(text.contains("http_request_duration_seconds_count{route=\"/messages\"} 3"));
    }
}
