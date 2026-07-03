# Datenmodell

Was der Server speichert. Die Blöcke sind nah an dem, was wir wirklich anlegen, mit Indizes, Partitionierung und den Sperren, die der Sitzungsaufbau braucht. Klartext, private Schlüssel und der entschlüsselte Verlauf kommen nie hierher.

Geshardet wird nach Konto-ID, jeder Dienst hält sein eigenes Schema. Das KT-Verzeichnis ist zusätzlich ein Merkle-Speicher (siehe [specs/key-transparency.md](specs/key-transparency.md)).

## Konten und Geräte

```sql
CREATE TABLE accounts (
    id                     UUID PRIMARY KEY,
    handle                 TEXT UNIQUE NOT NULL,
    display_name           TEXT,
    password_hash          TEXT NOT NULL,   -- Argon2id (PHC-String)
    identity_key           BYTEA NOT NULL,  -- öffentlicher Konto-Identitätsschlüssel (Ed25519)
    status                 TEXT NOT NULL DEFAULT 'active',  -- active | locked | deletion_pending
    deletion_pending_until TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id              UUID PRIMARY KEY,
    account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name            TEXT,
    identity_key    BYTEA NOT NULL,        -- öffentlicher Geräteschlüssel: die serialisierte libsignal-Identität, serverseitig opak (ADR-0009)
    credential_blob BYTEA NOT NULL,        -- vom Konto-Identitätsschlüssel signiertes Geräte-Credential
    not_after       BIGINT NOT NULL,       -- Ablauf des Credentials, Unix-Sekunden
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_devices_account ON devices (account_id) WHERE revoked_at IS NULL;
```

Geräte-IDs erzeugt der Client (UUID v4, kanonische Form). Sie sind global eindeutig, nicht nur je Konto: die ID steckt in der signierten Credential-Nachricht, und eine nach Revocation wiedervergebene ID würde alte Signaturen wieder gültig machen. Revozierte Geräte werden deshalb markiert (`revoked_at`), nie gelöscht.

## Sitzungen

Serverseitige Session-Familien für den API-Zugriff (Access- und Refresh-Token, Rotation mit Reuse-Erkennung nach RFC 9700). Tokens selbst liegen nie hier, nur ihre SHA-256-Hashes: ein Datenbank-Leak gibt keine gültigen Tokens her. Das ist Transportschicht-Zustand und unabhängig von den E2EE-Sitzungen der Clients.

```sql
CREATE TABLE session_families (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id         UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    access_hash        TEXT UNIQUE NOT NULL,   -- SHA-256 des Access-Tokens
    access_expires_at  BIGINT NOT NULL,        -- Unix-Sekunden
    refresh_hash       TEXT UNIQUE NOT NULL,   -- SHA-256 des aktuellen Refresh-Tokens
    refresh_expires_at BIGINT NOT NULL
);

-- Rotierte Refresh-Hashes je Familie: taucht einer davon wieder auf, ist das
-- Token-Diebstahl oder ein Client-Fehler, und die ganze Familie wird widerrufen.
CREATE TABLE used_refresh_hashes (
    refresh_hash TEXT PRIMARY KEY,
    family_id    BIGINT NOT NULL REFERENCES session_families(id) ON DELETE CASCADE
);

CREATE INDEX idx_session_families_device ON session_families (account_id, device_id);
```

## Prekeys

Pro Gerät ein Pool, klassisch und post-quantum. Wichtig ist die atomare Konsumierung: Zwei gleichzeitige Sitzungsaufbauten dürfen nicht denselben Einmal-Prekey ziehen. Das löst `SELECT ... FOR UPDATE SKIP LOCKED`.

Die Tabelle gehört dem Schlüssel-Verzeichnis (directory-Dienst) und liegt in dessen eigener Datenbank. `device_id` ist deshalb eine logische Referenz ohne Fremdschlüssel: die `devices`-Tabelle gehört dem identity-Dienst, Dienste greifen nie in fremde Datenbanken (siehe [architektur.md](architektur.md)). Konsumierte und rotierte Prekeys bleiben als `used = TRUE` stehen; Aufräumen ist ein späterer Wartungsjob.

```sql
CREATE TABLE prekeys (
    id         UUID PRIMARY KEY,   -- client-erzeugt, global eindeutig
    device_id  UUID NOT NULL,      -- logische Referenz auf identity/devices
    kind       TEXT NOT NULL,      -- signed | one_time | pq_signed | pq_one_time
    key        BYTEA NOT NULL,     -- opaker Blob, Server interpretiert nie
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pool eines Geräts, ungenutzte zuerst, mit SKIP LOCKED beim Ziehen.
CREATE INDEX idx_prekeys_pool ON prekeys (device_id, kind) WHERE used = FALSE;
```

Zielwerte: rund 100 Einmal-Prekeys je Typ und Gerät, Nachfüllen ab 20 verbleibenden, signierte Prekeys wöchentlich rotiert.

## Key Transparency

Der kt-Dienst hält zwei angefügte, nie geänderte Tabellen in seiner eigenen Datenbank. PostgreSQL ist die Quelle der Wahrheit; der Merkle-Baum (AZKS aus akd) ist ein Derivat, das beim Start deterministisch aus dem Update-Log wiederaufgebaut und gegen die gespeicherten Wurzeln geprüft wird (ein Integritätsbruch ist ein harter Startfehler). `kt_updates` ist das Änderungs-Log: je Schlüsseländerung ein Eintrag, welches Handle ab welcher Epoche auf welches Commitment zeigt. Das Commitment berechnet der identity-Dienst (smktc.v1, SHA-256 über Identitätsschlüssel und sortierte Gerätemenge), kt interpretiert es nie. `kt_epochs` ist der append-only Log der signierten Wurzeln (STH), den Clients und Auditoren prüfen.

```sql
CREATE TABLE kt_updates (
    seq         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    handle      TEXT NOT NULL,
    value       BYTEA NOT NULL,        -- opakes Konto-Commitment (vom identity-Dienst)
    epoch       BIGINT,                -- NULL = wartet auf die nächste Epoche
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE kt_epochs (
    epoch        BIGINT PRIMARY KEY,
    root_hash    BYTEA NOT NULL,
    signature    BYTEA NOT NULL,       -- Ed25519 über das kanonische STH-Format
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Nachrichten

Für den Server eine Blackbox mit Zustelladresse. Die `id` ist client-erzeugt und macht `POST /messages` idempotent; jede Hülle adressiert genau ein Gerät, für Multi-Device-Fan-out legt der Client pro Zielgerät eine eigene Hülle an. Die Tabelle gehört dem delivery-Dienst und liegt in dessen eigener Datenbank; `recipient_id` (Konto-UUID) und `device_id` sind logische Referenzen ohne Fremdschlüssel, aufgelöst über die interne identity-API. Die Tabelle ist nach Monat partitioniert (`PARTITION BY RANGE (received_at)`), alte Partitionen fallen per Retention weg; der Dienst legt Monatspartitionen beim Schreiben selbst an (Advisory Lock gegen Rennen paralleler Writer).

```sql
CREATE TABLE messages (
    id            UUID NOT NULL,        -- client-erzeugt, dedupliziert Retries
    recipient_id  UUID NOT NULL,
    device_id     UUID NOT NULL,
    envelope      BYTEA NOT NULL,       -- Sealed-Sender-Hülle + Chiffretext
    franking_tag  BYTEA NOT NULL,       -- Commitment fürs Abuse-Reporting
    received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at  TIMESTAMPTZ,
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

CREATE INDEX idx_messages_inbox ON messages (device_id, received_at);
```

Der Primärschlüssel enthält den Partitionsschlüssel und kann die `id` deshalb nicht global eindeutig halten. Das übernimmt eine kleine Dedupe-Tabelle: ein `INSERT ... ON CONFLICT DO NOTHING` pro Hülle erkennt Wiederholungen auch dann noch, wenn die Hülle längst zugestellt und gelöscht ist - sonst würde ein später Retry sie erneut zustellen. Aufgeräumt wird sie mit der Retention zusammen mit den Partitionen.

```sql
CREATE TABLE message_dedupe (
    id           UUID PRIMARY KEY,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## Franking-Log

Damit der Server eine gemeldete Nachricht verifizieren kann, muss er sein eigenes Franking-Commitment aufbewahren, ohne den Inhalt zu kennen. Sonst lässt sich eine Meldung nicht prüfen.

```sql
CREATE TABLE franking_log (
    message_id   UUID NOT NULL,
    commitment   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id)
);
```

## Gruppen-Zustellung

Der Server kann Gruppennachrichten nicht lesen, muss sie aber zustellen, und kennt dafür die Geräte einer Gruppe. Das ist der Metadaten-Punkt aus der [sicherheit.md](sicherheit.md).

```sql
CREATE TABLE group_devices (
    group_id  UUID NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);
```

Der kryptografische Gruppenzustand lebt als TreeKEM-Zustand in den Clients. Der Server hält ihn nicht.

## Mandanten der Integrations-API

Fremdprojekte (F100) sind Mandanten des integrations-Dienstes und leben in dessen eigener Datenbank. Das Client-Secret liegt nur als Argon2id-Hash vor und wird dem Betreiber genau einmal bei der Anlage gezeigt; ein kompromittiertes Projekt-Token bleibt auf seinen Mandanten und dessen Scopes begrenzt.

```sql
CREATE TABLE integration_tenants (
    id             UUID PRIMARY KEY,
    name           TEXT UNIQUE NOT NULL,           -- z. B. 'azubi-os'
    oidc_client_id TEXT UNIQUE NOT NULL,
    secret_hash    TEXT NOT NULL,                  -- Argon2id-PHC-String
    scopes         TEXT[] NOT NULL DEFAULT '{}',   -- 'notify', 'presence'
    webhook_url    TEXT,
    rate_limit     INTEGER NOT NULL DEFAULT 60,    -- Anfragen pro Minute
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at    TIMESTAMPTZ
);
```

Mandanten tauschen client_id plus Secret gegen ein kurzlebiges Token (Client-Credentials-Zuschnitt); abgelegt wird nur der SHA-256-Digest, abgelaufene Zeilen räumt der nächste Token-Tausch weg.

```sql
CREATE TABLE integration_tokens (
    token_hash  TEXT PRIMARY KEY,                  -- SHA-256 hex
    tenant_id   UUID NOT NULL REFERENCES integration_tenants (id),
    expires_at  TIMESTAMPTZ NOT NULL
);
```

## Was auf dem Gerät bleibt

Nur lokal und verschlüsselt: private Schlüssel, der Ratchet- und MLS-Zustand, der entschlüsselte Cache, die Einstellungen. Auf einem gesperrten Gerät ist der Bestand ohne Geräte-Keystore oder Passphrase nutzlos.
