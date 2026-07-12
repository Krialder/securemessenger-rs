//! client-app: Protokoll-Orchestrierung der SecureMessenger-Clients.
//!
//! Diese Schicht sitzt zwischen dem Krypto-Kern (`client-core`) und den
//! konkreten Clients (`clients/cli`, `clients/web`). Sie spricht die
//! Backend-Dienste über HTTP an und baut auf denselben gepinnten
//! Krypto-Bibliotheken auf. Sie enthält selbst keine Nachrichten-Kryptografie;
//! die lebt im Krypto-Kern, der Server sieht nur Chiffretext
//! (dokumentation/architektur.md).
//!
//! Plattform-neutral: die Bibliothek baut nativ (CLI, FFI) und nach
//! `wasm32-unknown-unknown` (Browser, siehe GOAL.md Meilenstein 0). Deshalb
//! keine Laufzeit-Annahmen (kein eigenes `tokio`), nur `async` und ein
//! HTTP-Client, den es auf beiden Zielen gibt.
//!
//! Umfang aktuell: Konto-Layer (Registrierung, Login, Session-Rotation,
//! Logout gegen identity), Nachrichten-Layer (Prekey-Veröffentlichung und
//! Bündel-Abruf gegen directory, Hüllen-Umlauf gegen delivery, Wire-Framing),
//! die persistente Protokoll-Ablage hinter dem Storage-Trait und die
//! KT-Selbstprüfung (kt-Modul). Offen: WebSocket-Hinweiskanal.

pub mod account;
pub mod delivery;
pub mod directory;
pub mod discovery;
pub mod error;
pub mod franking;
pub mod grouptext;
mod http;
pub mod identity;
pub mod kt;
pub mod prekeys;
pub mod protocol_store;
pub mod storage;
pub mod sync;
pub mod wire;

pub use error::ClientError;
pub use identity::{Account, IdentityClient, NewAccount, Session};
