//! Integrations-Dienst: die Basis-Dienste für Fremdprojekte (F070, F080,
//! F100; pflichtenheft.md 5.2).
//!
//! Fremdprojekte wie AzubiOS sind Mandanten mit eigenem Client-Secret,
//! eigenen Scopes und eigenem Rate-Limit. Sie lösen markierte Maschinen-
//! Benachrichtigungen aus (kein Ende-zu-Ende-Chat: der Absender ist ein
//! Server) und fragen Präsenz ab. Der Dienst hält eine eigene Datenbank
//! (Mandanten und Tokens) und spricht identity (Nutzer-Auflösung) und
//! delivery (Events, Präsenz) nur über deren interne Routen an.

pub mod api;
pub mod auth;
pub mod domain;
pub mod outbox;
pub mod pg;
pub mod realtime_client;
pub mod store;
pub mod webhook;
