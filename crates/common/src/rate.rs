//! Rate-Limit je Schlüssel: festes Minutenfenster (Pflichtenheft 6.4).
//!
//! Streng auf den heißen Pfaden: Login, Registrierung, die
//! Schlüssel-Endpunkte und die Integrations-API. Der Schlüssel ist,
//! was der Aufrufer nicht frei wechseln kann: das Handle beim Login,
//! die aufgelöste Identität bei authentifizierten Endpunkten, der
//! Mandant bei der Integrations-API. Bei Überschreitung antwortet der
//! Dienst 429 mit `Retry-After`.
//!
//! [ANNAHME: In-Prozess-Zähler statt der Redis-Zähler aus dem
//! Pflichtenheft; Redis kommt mit der Edge-Etappe in den Stack. Bei
//! mehreren Repliken gilt das Limit je Replik, also großzügiger als
//! konfiguriert - für den Schutzzweck reicht das vorerst. IP-basierte
//! Limits gehören an die Edge, hinter dem Ingress ist die Quell-IP
//! ohne vertrauenswürdige Header nicht belastbar.]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Einheitliche 429-Antwort mit `Retry-After` (Pflichtenheft 6.4), im
/// Fehlerformat der Dienste (`code`, `message`).
pub fn too_many_requests(retry_after_secs: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after_secs.to_string())],
        Json(serde_json::json!({
            "code": "rate_limited",
            "message": "Rate-Limit erreicht, bitte später erneut versuchen",
        })),
    )
        .into_response()
}

/// Zähler je Schlüssel im aktuellen Minutenfenster.
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
    /// Verbucht eine Anfrage. Ok = durchlassen; Err trägt die Sekunden
    /// bis zum nächsten Fenster (für den Retry-After-Header).
    pub fn check(&self, key: &str, limit: u32) -> Result<(), u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Systemzeit nach 1970")
            .as_secs();
        let minute = now / 60;
        let mut windows = self.windows.lock().expect("Rate-Lock nicht vergiftet");
        let entry = windows.entry(key.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            // Neues Fenster: alter Zähler ist bedeutungslos. Alte
            // Einträge bleiben liegen; ein Eintrag je Schlüssel hält
            // die Map klein genug.
            *entry = (minute, 0);
        }
        if entry.1 >= limit {
            return Err(60 - (now % 60));
        }
        entry.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_enforced_per_key() {
        let limiter = RateLimiter::default();
        for _ in 0..3 {
            assert!(limiter.check("k1", 3).is_ok());
        }
        let retry = limiter.check("k1", 3).unwrap_err();
        assert!((1..=60).contains(&retry));
        // Anderer Schlüssel hat sein eigenes Fenster.
        assert!(limiter.check("k2", 3).is_ok());
    }
}
