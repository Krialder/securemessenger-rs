//! Zustelldienst (F050): nimmt Chiffretext an, legt ihn ab, stellt zu
//! (store-and-forward bis zur Bestätigung durch das Zielgerät) und hält
//! die Echtzeit-Verbindung für Hinweise (architektur.md "Zustellung"
//! und "Echtzeit & Presence").
//!
//! Eigener Dienst mit eigener Datenbank. Bearer-Tokens prüft er über die
//! interne identity-API, Inhalte bleiben Blackbox: Hüllen und
//! Franking-Tags sind opake Blobs, einen Absender speichert der Dienst
//! nie. Die Nachrichten-Kryptografie lebt im Client-Core.

pub mod api;
pub mod domain;
pub mod hub;
pub mod pg;
pub mod store;
