-- Gruppen-Name, -Einstellungen und -Rollen (Paket B). Der Server war fuer
-- Gruppen bisher rein zustellend; jetzt setzt er auch die Rechte-Matrix
-- durch (owner/admin/member). Das ist Server-Durchsetzung wie bei
-- Matrix/Telegram, nicht Ende-zu-Ende verifizierbar (siehe groups.rs).

-- Name (server-sichtbares Metadatum, damit die Einladung ihn zeigen kann)
-- und Einstellungen (als JSON-Text: invite_policy, announcement,
-- info_policy). Bestandsgruppen bekommen leere Vorgaben.
ALTER TABLE groups ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN settings TEXT NOT NULL
    DEFAULT '{"invite_policy":"all","announcement":false,"info_policy":"admins"}';

-- Rolle je Mitglied (Handle). Genau ein owner je Gruppe (durch die Logik in
-- groups.rs, nicht durch ein DB-Constraint, weil die Uebergabe zwei Zeilen
-- in einem Schritt aendert). Faellt mit der Gruppe (ON DELETE CASCADE).
CREATE TABLE group_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    handle   TEXT NOT NULL,
    role     TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    PRIMARY KEY (group_id, handle)
);
