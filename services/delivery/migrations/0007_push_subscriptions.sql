-- Web-Push-Abos (F1): je Gerät genau ein Browser-Abo, damit der Dienst eine
-- INHALTLOSE Aufweck-Benachrichtigung schicken kann, wenn eine Nachricht
-- eintrifft, während das Gerät keinen WebSocket hält (Browser geschlossen).
-- Der Push trägt nie Inhalt: der Client holt die Hülle wie sonst per Pull.
-- endpoint/p256dh/auth sind die Browser-Abo-Daten (RFC 8291); p256dh/auth
-- werden für den inhaltslosen Push nicht gebraucht, aber mitgespeichert,
-- falls später ein verschlüsselter Payload dazukommt.
CREATE TABLE push_subscriptions (
    device_id  TEXT PRIMARY KEY,
    endpoint   TEXT NOT NULL,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
