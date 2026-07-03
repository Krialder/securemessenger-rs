//! Schlüssel-Verzeichnis (F110): Prekey-Pools der Geräte, klassisch und
//! post-quantum.
//!
//! Eigener Dienst mit eigener Datenbank (architektur.md); Tokens und
//! Gerätemengen kommen über die interne identity-API. Der Server versteht
//! die Schlüssel nicht, er verwaltet Vorrat und atomare Konsumierung -
//! die Kryptografie dazu lebt im Client-Core. Sender-Credentials für
//! Sealed Sender folgen mit der zugehörigen Etappe.

pub mod api;
pub mod domain;
pub mod pg;
pub mod store;
