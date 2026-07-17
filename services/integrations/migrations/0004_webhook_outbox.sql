-- Dauerhafte Webhook-Outbox: statt Best-Effort-Zustellung schreibt der
-- Dienst jede faellige Zustellung hierher, ein Hintergrund-Worker liefert
-- sie mit exponentiellem Backoff (mindestens einmal). Ein kurz nicht
-- erreichbarer Empfaenger verliert damit kein Ereignis mehr.
--
-- Gespeichert wird der fertige Envelope-KOERPER (mit stabiler id und
-- created_at), NICHT die Signatur: der Worker signiert jeden Versuch mit
-- frischem Zeitstempel neu, damit ein Empfaenger mit Replay-Fenster einen
-- spaeten Wiederholversuch nicht faelschlich als zu alt abweist. Die url
-- ist ein Schnappschuss der Anlage: ein bereits eingereihtes Ereignis wird
-- auch dann noch zugestellt, wenn der Endpunkt danach entfernt wird.
CREATE TABLE integration_webhook_outbox (
    id              UUID PRIMARY KEY,          -- zugleich die Envelope-id (Dedup)
    url             TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    body            BYTEA NOT NULL,            -- der JSON-Koerper (unsigniert; je Versuch neu signiert)
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ,              -- gesetzt = erledigt
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT
);

-- Faellige, noch nicht zugestellte Zeilen schnell finden (Teil-Index; mehrere
-- Repliken teilen sich die Outbox ueber FOR UPDATE SKIP LOCKED beim Claim).
CREATE INDEX idx_outbox_due
    ON integration_webhook_outbox (next_attempt_at)
    WHERE delivered_at IS NULL;
