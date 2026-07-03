//! In-Prozess-Fanout für Echtzeit-Ereignisse (schnittstellen.md
//! "Echtzeit-Events").
//!
//! Über den WebSocket gehen nur Hinweise und minimale, markierte
//! Maschinen-Benachrichtigungen, nie Chat-Inhalte: den Chiffretext holt
//! der Client selbst über GET /messages. Ein verlorenes Ereignis ist
//! deshalb verschmerzbar, die Abholung ist die Wahrheit.
//!
//! [ANNAHME: Fanout prozesslokal über einen broadcast-Kanal. Bei mehreren
//! Repliken sieht ein Socket nur Ereignisse seiner eigenen Replik; die
//! NATS-Queue aus architektur.md kommt mit der Skalierungs-Etappe.]

use tokio::sync::broadcast;

/// Ein Ereignis für genau ein Gerät. Jede Verbindung filtert auf ihr
/// eigenes Gerät, so erfährt niemand etwas über fremde Zustellungen.
#[derive(Clone, Debug)]
pub enum HubEvent {
    /// Für dieses Gerät liegt eine Hülle bereit; Inhalt kommt per Pull.
    MessageWaiting { device_id: String },
    /// Markierte Maschinen-Benachrichtigung eines Fremdprojekts (F070),
    /// bereits als fertiges Event-JSON serialisiert. Minimaler Inhalt:
    /// die Details holt der Nutzer im Fremdprojekt (pflichtenheft.md 5.2).
    Notification {
        device_id: String,
        event_json: String,
    },
}

impl HubEvent {
    pub fn device_id(&self) -> &str {
        match self {
            HubEvent::MessageWaiting { device_id } => device_id,
            HubEvent::Notification { device_id, .. } => device_id,
        }
    }
}

/// Nabe zwischen den Auslösern (POST /messages, interne Event-Route) und
/// den WebSocket-Verbindungen.
#[derive(Clone)]
pub struct RealtimeHub {
    tx: broadcast::Sender<HubEvent>,
}

impl RealtimeHub {
    pub fn new() -> Self {
        // Kapazität großzügig: Empfänger, die trotzdem hinterherhinken,
        // bekommen Lagged und schicken dann einen unbedingten
        // message.waiting-Hinweis (siehe api.rs), verlieren also nichts
        // Verbindliches.
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    /// Meldet: für dieses Gerät liegt etwas bereit. Ohne Empfänger ist
    /// das kein Fehler, dann holt das Gerät beim nächsten Verbinden ab.
    pub fn notify(&self, device_id: &str) {
        let _ = self.tx.send(HubEvent::MessageWaiting {
            device_id: device_id.to_string(),
        });
    }

    /// Verteilt ein fertig serialisiertes Ereignis an ein Gerät. Ist das
    /// Gerät nicht verbunden, verfällt es: Benachrichtigungen sind
    /// Hinweise, keine Zustellpflicht (der Stand lebt im Fremdprojekt).
    pub fn publish(&self, event: HubEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.tx.subscribe()
    }
}

impl Default for RealtimeHub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribers_receive_only_after_subscribing() {
        let hub = RealtimeHub::new();
        hub.notify("dev-vorher");

        let mut rx = hub.subscribe();
        hub.notify("dev-1");
        hub.publish(HubEvent::Notification {
            device_id: "dev-2".to_string(),
            event_json: r#"{"event":"integration.notification"}"#.to_string(),
        });

        assert_eq!(rx.recv().await.unwrap().device_id(), "dev-1");
        let second = rx.recv().await.unwrap();
        assert_eq!(second.device_id(), "dev-2");
        match second {
            HubEvent::Notification { event_json, .. } => {
                assert!(event_json.contains("integration.notification"));
            }
            other => panic!("unerwartetes Ereignis: {other:?}"),
        }
    }
}
