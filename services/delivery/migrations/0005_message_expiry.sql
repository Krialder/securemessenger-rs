-- Disappearing Messages (specs/sealed-sender-und-abuse.md): der Absender
-- kann festlegen, dass eine unabgeholte Huelle nach einem Zeitpunkt
-- verschwindet. Der Server sieht nur den Zeitpunkt (Unix-Sekunden), nie den
-- Inhalt; abgeholt wird eine abgelaufene Huelle nicht mehr. Die eigentliche
-- Vergaenglichkeit auf dem Empfaengergeraet regelt der Client.
--
-- NULL = kein Ablauf (Default), damit bestehende Zeilen unveraendert bleiben.
ALTER TABLE messages ADD COLUMN expires_at BIGINT;

-- Der Posteingang filtert nach Ablauf; ein Teilindex haelt die Abfrage
-- guenstig, ohne die abgelaufenen Zeilen mitzuschleppen.
CREATE INDEX idx_messages_expiry ON messages (device_id, expires_at)
    WHERE expires_at IS NOT NULL;
