-- Discovery-Index fuer Contact Discovery (specs/contact-discovery.md).
-- Der Client blendet den gesuchten Handle, der Server wertet die OPRF aus,
-- der Client entblendet zu PRF_k(handle) und schlaegt darueber nach. Diese
-- Tabelle haelt den Index: PRF-Wert (Hex) auf Konto-Referenz. Der Eintrag
-- entsteht bei der Registrierung; der Server berechnet PRF_k(handle) selbst
-- (er kennt seine Handles ohnehin).
--
-- prf ist der Primaerschluessel: ein PRF-Wert gehoert zu genau einem Handle
-- (die OPRF ist eine Funktion). identity_key wird mitgefuehrt, damit der
-- Client nach der Aufloesung direkt gegen Key Transparency pruefen kann.
CREATE TABLE discovery (
    prf          TEXT PRIMARY KEY,
    account_id   UUID NOT NULL,
    handle       TEXT NOT NULL,
    identity_key TEXT NOT NULL
);
