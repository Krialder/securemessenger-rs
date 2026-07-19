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
//! Passwortwechsel, Konto-Löschung, Anzeigename, Wurzelschlüssel-Rotation,
//! Geräte-Kopplung gegen identity), Nachrichten-Layer (Prekey-Veröffentlichung
//! und Bündel-Abruf gegen directory, Hüllen-Umlauf gegen delivery samt
//! WebSocket-Hinweiskanal, Wire-Framing), Sealed Sender, Contact Discovery,
//! Message Franking und Blockieren, MLS-Gruppen (grouptext), Multi-Device-
//! Self-Sync, die KT-Selbstprüfung (kt-Modul) und die persistente Protokoll-
//! Ablage hinter dem Storage-Trait.

pub mod account;
pub mod backup;
pub mod call;
pub mod datachan;
pub mod delivery;
pub mod directory;
pub mod discovery;
pub mod error;
pub mod franking;
pub mod grouptext;
mod http;
pub mod identity;
pub mod kt;
pub mod msg;
pub mod policy;
pub mod prekeys;
pub mod protocol_store;
pub mod storage;
pub mod store_keys;
pub mod sync;
pub mod wire;

pub use error::ClientError;
pub use identity::{Account, IdentityClient, NewAccount, Session};
