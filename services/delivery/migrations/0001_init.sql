-- Grundschema des Zustelldienstes, nach dokumentation/datenmodell.md
-- (Abschnitt "Nachrichten"). Eigene Datenbank: Dienste greifen nie in
-- fremde Schemata (architektur.md); recipient_id und device_id sind
-- logische Referenzen auf den identity-Dienst, ohne Fremdschlüssel.

-- Für den Server eine Blackbox mit Zustelladresse: die Hülle trägt
-- Sealed-Sender-Kopf plus Chiffretext, einen Absender speichert der
-- Dienst nie. Partitioniert nach Monat, alte Partitionen fallen per
-- Retention weg; die Partitionen legt der Dienst beim Schreiben an
-- (pg.rs), nicht die Migration, weil sie von der Laufzeit abhängen.
CREATE TABLE messages (
    -- Client-erzeugt, eine UUID je Hülle (je Zielgerät). Macht Retries
    -- deduplizierbar, siehe message_dedupe.
    id           UUID NOT NULL,
    recipient_id UUID NOT NULL,
    device_id    UUID NOT NULL,
    envelope     BYTEA NOT NULL,
    -- Commitment fürs Abuse-Reporting. Bis zur Sealed-Sender-Etappe darf
    -- es leer sein, die Spalte bleibt aber NOT NULL, damit die Semantik
    -- "immer vorhanden, notfalls leer" eindeutig ist.
    franking_tag BYTEA NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

-- Posteingang eines Geräts, Abholreihenfolge = Eingangsreihenfolge.
CREATE INDEX idx_messages_inbox ON messages (device_id, received_at);

-- Der Primärschlüssel der partitionierten Tabelle muss den Partitions-
-- schlüssel enthalten und kann die Hüllen-ID deshalb nicht allein global
-- erzwingen. Diese Tabelle tut es: INSERT ... ON CONFLICT DO NOTHING
-- macht POST /messages idempotent. Zeilen überleben das Abräumen der
-- Nachricht (sonst würde ein später Retry erneut zustellen) und werden
-- per Retention mit den Partitionen entsorgt.
CREATE TABLE message_dedupe (
    id          UUID PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
