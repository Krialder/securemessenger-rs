//! Identitäts- und Auth-Dienst (Fundament, Phase 1).
//!
//! Bibliotheksteil, damit Integrationstests die HTTP-Schicht direkt testen
//! können. Enthält bewusst keine Nachrichten-Kryptografie: die lebt im
//! Client-Core (libsignal, OpenMLS). Hier gibt es nur Login-Schutz über
//! geprüfte Bibliotheken: Argon2id für Passwörter, SHA-256 für Token-Hashes.

pub mod api;
pub mod auth;
pub mod credential;
pub mod domain;
pub mod kt_notify;
pub mod pg;
pub mod provision;
pub mod session;
pub mod store;
