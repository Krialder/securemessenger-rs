-- Legt beim ERSTEN Start des postgres-Containers eine Datenbank je Dienst an
-- (eigene Datenbank, damit sich die sqlx-Migrationstabellen nicht in die Quere
-- kommen, ENTWICKLUNG.md). Nur einmalig ausgefuehrt: das offizielle
-- postgres-Image spielt /docker-entrypoint-initdb.d ausschliesslich bei
-- leerem Datenverzeichnis ein. Spaetere Aenderungen brauchen ein frisches
-- Volume (docker compose down -v).
CREATE DATABASE identity;
CREATE DATABASE directory;
CREATE DATABASE delivery;
CREATE DATABASE kt;
CREATE DATABASE integrations;
