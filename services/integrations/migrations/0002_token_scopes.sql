-- Least Privilege je Token (F100): ein Fremdprojekt kann ein Token bewusst
-- enger ausstellen als die vollen Mandanten-Rechte (OAuth2 scope-Parameter,
-- RFC 6749 3.3). Bisher trug jedes Token pauschal alle Mandanten-Scopes;
-- jetzt hält das Token seine eigene, ausgestellte Teilmenge.
--
-- Vorgabe leeres Array nur fuer den Migrationsmoment; api.rs stellt beim
-- Token-Tausch immer mindestens einen Scope aus (sonst waere das Token
-- nutzlos). Kein Backfill noetig: bestehende Tokens sind kurzlebig (1h) und
-- ohnehin bald abgelaufen.
ALTER TABLE integration_tokens
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT '{}';
