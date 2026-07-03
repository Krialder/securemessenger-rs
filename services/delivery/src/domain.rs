//! Fachmodell der Zustellung. Für den Server ist eine Nachricht eine
//! Blackbox mit Zustelladresse (datenmodell.md): Hülle und Franking-Tag
//! sind opake Blobs (Base64), einen Absender gibt es im Modell nicht.

/// Eine anzunehmende Hülle: ein Chiffretext für genau ein Zielgerät.
/// Die `id` erzeugt der Client je Hülle; sie macht Retries idempotent.
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub id: String,
    /// Konto-UUID des Empfängers (aufgelöst über identity, nie vom Client).
    pub recipient_id: String,
    pub device_id: String,
    /// Sealed-Sender-Hülle plus Chiffretext, Base64.
    pub envelope: String,
    /// Franking-Commitment, Base64. Leer bis zur Sealed-Sender-Etappe.
    pub franking_tag: Option<String>,
}

/// Eine wartende Hülle beim Abholen. `received_at` in Unix-Sekunden.
#[derive(Debug, Clone)]
pub struct WaitingMessage {
    pub id: String,
    pub envelope: String,
    pub franking_tag: Option<String>,
    pub received_at: u64,
}

/// Ergebnis eines Batch-Uploads: Duplikate sind kein Fehler, sondern der
/// Beweis, dass ein Retry idempotent ankam.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreOutcome {
    pub accepted: u64,
    pub duplicates: u64,
}
