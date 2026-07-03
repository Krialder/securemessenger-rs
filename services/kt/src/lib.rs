//! Key-Transparency-Dienst (F120, specs/key-transparency.md).
//!
//! Eine verifiable map (Handle -> Schlüssel-Commitment) auf einem
//! Merkle-Baum, gestützt auf einen append-only Log signierter Wurzeln.
//! Die Konstruktion kommt vollständig aus akd (Metas KT-Bibliothek,
//! exakt gepinnt); dieser Dienst orchestriert: Update-Log und Wurzeln
//! in PostgreSQL (Quelle der Wahrheit), der Baum als deterministisch
//! wiederaufgebautes Derivat, Epochen-Veröffentlichung, Beweis-Endpunkte.
//!
//! Per Spec hält dieser Dienst private Schlüssel (VRF und
//! Wurzel-Signatur) - die dokumentierte Ausnahme von der "Backend
//! verifiziert nur"-Regel. Nachrichten-Krypto bleibt im Client-Core.

pub mod api;
pub mod directory;
pub mod keys;
pub mod pg;
pub mod store;
