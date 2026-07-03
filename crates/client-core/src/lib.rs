//! Der gemeinsame Krypto-Kern der Clients (ADR-0005).
//!
//! Hier und nur hier lebt die Nachrichten-Kryptografie: PQXDH, Double
//! Ratchet und SPQR aus libsignal, Gruppen (RFC 9420) aus OpenMLS. Der
//! Kern läuft auf den Geräten (nativ über FFI, im Web als WebAssembly);
//! kein Backend-Dienst hängt von diesem Crate ab, der Server sieht nur
//! Chiffretext (dokumentation/architektur.md).
//!
//! Beide Bibliotheken sind auf einen Release-Commit gepinnt
//! (specs/krypto-kern.md "Version-Pins"): libsignal v0.96.4, OpenMLS
//! v0.8.1. Die heiklen Konstruktionen - die Hybrid-Bindung von PQXDH,
//! die SPQR-Mischung im Ratchet - kommen unverändert aus libsignal;
//! dieses Crate orchestriert nur die Bibliotheken und legt die
//! Plattform-Festlegungen (Cipher-Suite, KEM-Typ) an genau einer Stelle
//! fest. Eigene Krypto-Konstruktionen sind hier verboten.
//!
//! Die FFI- und WASM-Schichten folgen mit der Client-Etappe; die
//! Integrations-Beweise liegen als Tests in tests/.

pub mod group;
pub mod onetoone;

// Re-Exports, damit Client-Code die gepinnten Bibliotheken über den Kern
// bezieht und nicht versehentlich eine zweite, anders gepinnte Version
// in den Dependency-Graph zieht.
pub use libsignal_protocol;
pub use openmls;
pub use openmls_basic_credential;
pub use openmls_rust_crypto;
