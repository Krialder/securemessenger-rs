-- Kleine, kontoweit eindeutige libsignal-Gerätenummer je Gerät (Multi-
-- Device). Sie ist der Geräteteil der ProtocolAddress: zwei Geräte eines
-- Kontos brauchen verschiedene Nummern, damit ein Absender getrennte
-- Sitzungen zu ihnen halten kann. Der Server vergibt sie monoton (max + 1
-- je Konto, revozierte Nummern werden nicht wiederverwendet).
--
-- Bestandsdaten: jedes vorhandene Konto hat genau ein Gerät (Registrierung
-- legt Konto und erstes Gerät zusammen an, weitere Geräte gab es bisher
-- nicht), also ist die Vorgabe 1 für alle Altzeilen korrekt. SMALLINT deckt
-- den Bereich 1..255 mehr als ab.
ALTER TABLE devices
    ADD COLUMN protocol_device_id SMALLINT NOT NULL DEFAULT 1;

-- Innerhalb eines Kontos ist die Nummer eindeutig (über alle Geräte, auch
-- revozierte, weil ihre Nummern gesperrt bleiben). Ein Partial-Index wäre
-- falsch: gerade die revozierten müssen mitsperren.
CREATE UNIQUE INDEX devices_account_protocol_id_unique
    ON devices (account_id, protocol_device_id);
