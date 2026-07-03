-- Key Transparency (F120): PostgreSQL ist die Quelle der Wahrheit fuer
-- das Update-Log und die signierten Wurzeln. Der Merkle-Baum (AZKS aus
-- akd) ist ein Derivat: er wird beim Start deterministisch aus dem
-- Update-Log wiederaufgebaut und gegen die gespeicherten Wurzeln
-- geprueft (Integritaetsbruch = harter Startfehler). So braucht akd
-- keinen eigenen persistenten Storage-Adapter, und die append-only
-- Historie liegt trotzdem dauerhaft und pruefbar in der Datenbank.

-- Ein Eintrag je Schluesselaenderung: welches Handle zeigt ab welcher
-- Epoche auf welches Schluessel-Commitment. Angefuegt, nie geaendert.
CREATE TABLE kt_updates (
    seq         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    handle      TEXT NOT NULL,
    -- Commitment auf die Geraete-/Schluesselmenge des Kontos (opak,
    -- berechnet vom identity-Dienst; kt interpretiert es nie).
    value       BYTEA NOT NULL,
    -- NULL = wartet auf die naechste Epoche; sonst die Epoche, in der
    -- das Update veroeffentlicht wurde.
    epoch       BIGINT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_kt_updates_pending ON kt_updates (seq) WHERE epoch IS NULL;
CREATE INDEX idx_kt_updates_epoch ON kt_updates (epoch);

-- Die signierten Wurzeln (STH) je Epoche: der append-only Log, den
-- Clients und Auditoren pruefen. Angefuegt, nie geaendert.
CREATE TABLE kt_epochs (
    epoch        BIGINT PRIMARY KEY,
    root_hash    BYTEA NOT NULL,
    -- Ed25519-Signatur ueber das kanonische STH-Format (signer.rs).
    signature    BYTEA NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
