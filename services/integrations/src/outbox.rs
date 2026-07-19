//! Hintergrund-Worker der Webhook-Outbox.
//!
//! `presence_event` reiht Zustellungen nur in die Outbox ein; hier werden sie
//! geholt und gesendet. Jeder Versuch wird mit FRISCHEM Zeitstempel neu
//! signiert (der Körper mit stabiler id/created_at bleibt gleich), damit ein
//! Empfänger mit Replay-Fenster einen späten Wiederholversuch nicht als zu
//! alt abweist. Der nächste Versuch ist beim Claim schon eingeplant
//! (Backoff), ein Fehler hält die anderen Zustellungen nicht auf.

use std::sync::Arc;
use std::time::Duration;

use crate::store::TenantStore;
use crate::webhook::{Delivery, WebhookSender, WebhookSigner};

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}

/// Ein Durchlauf: bis zu `limit` fällige Zustellungen holen, senden,
/// Erfolg/Fehler vermerken. Liefert die Zahl der erfolgreich zugestellten.
/// Der Worker-Loop ruft nur dies auf, damit die Logik testbar bleibt.
pub async fn drain_once(
    store: &Arc<dyn TenantStore>,
    signer: &Arc<WebhookSigner>,
    sender: &Arc<dyn WebhookSender>,
    limit: usize,
) -> usize {
    let due = match store.claim_due_deliveries(limit).await {
        Ok(due) => due,
        Err(error) => {
            tracing::error!(%error, "Outbox-Claim fehlgeschlagen");
            return 0;
        }
    };
    let mut delivered = 0usize;
    for row in due {
        let timestamp = now_epoch();
        let signature = signer.sign(timestamp, &row.body);
        let delivery = Delivery {
            url: row.url,
            event: row.event_type,
            delivery_id: row.id.clone(),
            timestamp,
            signature,
            body: row.body,
        };
        match sender.deliver(delivery).await {
            Ok(()) => {
                if let Err(error) = store.mark_delivery_done(&row.id).await {
                    tracing::error!(%error, id = %row.id, "Outbox: Erledigung nicht speicherbar");
                } else {
                    delivered += 1;
                }
            }
            Err(error) => {
                // Der nächste Versuch ist beim Claim schon eingeplant; hier
                // nur den Fehler vermerken (best effort).
                let _ = store.mark_delivery_error(&row.id, &error).await;
                tracing::warn!(
                    id = %row.id,
                    attempt = row.attempts,
                    %error,
                    "Webhook-Zustellung fehlgeschlagen, Wiederholung eingeplant"
                );
            }
        }
    }
    delivered
}

/// Startet den Dauer-Worker: pollt die Outbox in kurzem Takt und liefert
/// fällige Zustellungen aus. Best effort, läuft neben dem HTTP-Server.
pub fn spawn_worker(
    store: Arc<dyn TenantStore>,
    signer: Arc<WebhookSigner>,
    sender: Arc<dyn WebhookSender>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            drain_once(&store, &signer, &sender, 100).await;
        }
    });
}
