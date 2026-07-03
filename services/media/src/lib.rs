//! Medien-Dienst (F180): verschlüsselte Blobs im Objektspeicher.
//!
//! Der Client verschlüsselt die Datei, lädt den Blob hoch und bekommt
//! eine Referenz; der Schlüssel reist in der Nachricht, nie über diesen
//! Dienst (schnittstellen.md "Medien"). Der Server sieht nur Chiffretext
//! ohne Dateinamen, ohne Typ, ohne Metadaten - eine Referenz ist eine
//! Capability: wer sie und den Schlüssel hat, hat die Datei.
//!
//! Ablage über object_store: S3/MinIO im Betrieb (NF120), In-Memory ohne
//! Konfiguration. Keine eigene Datenbank: der Objektspeicher ist die
//! einzige Ablage, die Referenz ist der Objektname.

pub mod api;
