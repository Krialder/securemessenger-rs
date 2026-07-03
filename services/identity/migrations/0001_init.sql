-- Grundschema des identity-Dienstes, nach dokumentation/datenmodell.md
-- (Abschnitte "Konten und Geräte" und "Sitzungen").

CREATE TABLE accounts (
    id                     UUID PRIMARY KEY,
    handle                 TEXT UNIQUE NOT NULL,
    display_name           TEXT NOT NULL,
    -- Argon2id im PHC-Format (auth.rs).
    password_hash          TEXT NOT NULL,
    -- Öffentlicher Konto-Identitätsschlüssel (Ed25519), die Wurzel der
    -- Geräte-Credentials. Der private Teil liegt nie beim Server.
    identity_key           BYTEA NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'active',  -- active | locked | deletion_pending
    deletion_pending_until TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id              UUID PRIMARY KEY,
    account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    -- Öffentlicher Geräteschlüssel (Ed25519).
    identity_key    BYTEA NOT NULL,
    -- Vom Konto-Identitätsschlüssel signiertes Geräte-Credential.
    credential_blob BYTEA NOT NULL,
    -- Ablauf des Credentials als Unix-Sekunden; BIGINT statt TIMESTAMPTZ,
    -- weil der Wert Teil der signierten Credential-Nachricht ist und
    -- verlustfrei so zurückgegeben werden muss, wie der Client ihn signierte.
    not_after       BIGINT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    -- Gesetzt = aus der gültigen Menge entfernt. Die Zeile bleibt erhalten,
    -- damit die Geräte-ID gesperrt bleibt (Credential-Replay-Schutz).
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_devices_account ON devices (account_id) WHERE revoked_at IS NULL;

-- Session-Familien (F020): ein Gerät eines Nutzers über Rotationen hinweg.
-- Es liegen nur SHA-256-Hashes der Tokens, nie Klartext. Ablaufzeiten als
-- Unix-Sekunden (BIGINT): die Fachlogik rechnet in Sekunden-TTLs, und so
-- bleiben In-Memory- und PostgreSQL-Semantik identisch vergleichbar.
CREATE TABLE session_families (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id         UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    access_hash        TEXT UNIQUE NOT NULL,
    access_expires_at  BIGINT NOT NULL,
    refresh_hash       TEXT UNIQUE NOT NULL,
    refresh_expires_at BIGINT NOT NULL
);

CREATE INDEX idx_session_families_device ON session_families (account_id, device_id);

-- Rotierte Refresh-Hashes: führen ein wiederverwendetes Token zur Familie
-- zurück (Reuse-Erkennung, RFC 9700). Fällt mit der Familie (CASCADE).
CREATE TABLE used_refresh_hashes (
    refresh_hash TEXT PRIMARY KEY,
    family_id    BIGINT NOT NULL REFERENCES session_families(id) ON DELETE CASCADE
);
