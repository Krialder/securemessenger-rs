-- Mandanten der Integrations-API (F100, pflichtenheft.md Abschnitt 7).
-- Jedes Fremdprojekt ist ein Mandant mit eigenem Client-Secret und eigenem
-- Rate-Limit; ein kompromittiertes Projekt-Token bleibt auf seinen
-- Mandanten begrenzt. Das Secret liegt nur als Argon2id-PHC-String hier,
-- nie im Klartext (NF040).
CREATE TABLE integration_tenants (
    id             UUID PRIMARY KEY,
    name           TEXT UNIQUE NOT NULL,           -- z. B. 'azubi-os'
    oidc_client_id TEXT UNIQUE NOT NULL,
    secret_hash    TEXT NOT NULL,                  -- Argon2id-PHC-String
    scopes         TEXT[] NOT NULL DEFAULT '{}',   -- 'notify', 'presence'
    webhook_url    TEXT,
    rate_limit     INTEGER NOT NULL DEFAULT 60,    -- Anfragen pro Minute
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at    TIMESTAMPTZ                     -- gesetzt = Mandant gesperrt
);

-- Kurzlebige Mandanten-Tokens (Client-Credentials-Zuschnitt): das
-- Fremdprojekt tauscht client_id plus Secret gegen ein Token und ruft
-- damit die API. Nur der SHA-256-Digest liegt hier; ein Auszug der
-- Ablage liefert keine gueltigen Tokens. Abgelaufene Zeilen raeumt der
-- Dienst beim naechsten Token-Tausch weg.
CREATE TABLE integration_tokens (
    token_hash  TEXT PRIMARY KEY,                  -- SHA-256 hex
    tenant_id   UUID NOT NULL REFERENCES integration_tenants (id),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_integration_tokens_expiry ON integration_tokens (expires_at);
