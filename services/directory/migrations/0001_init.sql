-- Prekey-Pool des Schlüssel-Verzeichnisses, nach dokumentation/datenmodell.md.
-- device_id ist eine logische Referenz: die devices-Tabelle gehört dem
-- identity-Dienst (eigene Datenbank je Dienst), Gültigkeit eines Geräts
-- prüft directory über die interne identity-API, nie per Fremdschlüssel.

CREATE TABLE prekeys (
    id         UUID PRIMARY KEY,
    device_id  UUID NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('signed', 'one_time', 'pq_signed', 'pq_one_time')),
    -- Opaker öffentlicher Schlüssel samt Signatur-Material, wie der Client
    -- ihn hochlädt. Der Server interpretiert ihn nicht (Krypto im Client-Core).
    key        BYTEA NOT NULL,
    -- Einmal-Prekeys: TRUE = konsumiert. Signierte Prekeys: TRUE = durch
    -- Rotation ersetzt. Zeilen bleiben stehen, Aufräumen ist ein späterer
    -- Wartungsjob, kein Korrektheitsthema.
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pool eines Geräts, ungenutzte zuerst, mit SKIP LOCKED beim Ziehen.
CREATE INDEX idx_prekeys_pool ON prekeys (device_id, kind) WHERE used = FALSE;
