-- Gruppen-Zustellung (MLS Delivery Service, datenmodell.md
-- "Gruppen-Zustellung"). Der Server haelt den kryptografischen
-- Gruppenzustand nicht; er haelt nur, was er fuers Zustellen braucht: die
-- aktuelle Epoche je Gruppe (fuer die Serialisierung konkurrierender
-- Commits) und die Mitglieds-Geraeteliste (fuers Fan-out).

CREATE TABLE groups (
    id    UUID PRIMARY KEY,          -- client-erzeugt
    epoch BIGINT NOT NULL DEFAULT 0  -- fortlaufend, Commit erhoeht um 1
);

-- Die Mitglieds-Geraete. device_id ist eine logische Referenz auf die
-- Geraete beim identity-Dienst (eigene Datenbank, kein Fremdschluessel),
-- wie recipient_id/device_id bei den Nachrichten.
CREATE TABLE group_devices (
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    PRIMARY KEY (group_id, device_id)
);
