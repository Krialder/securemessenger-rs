//! Fachmodell des Schlüssel-Verzeichnisses: Prekeys und ihre Typen.
//!
//! Ein Prekey ist hier ein opaker Blob. Was drinsteckt (Kurve, KEM,
//! Signatur des Geräteschlüssels), prüft der Client-Core beim
//! Sitzungsaufbau; der Server verwaltet nur Vorrat und Konsumierung
//! (dokumentation/datenmodell.md, Abschnitt Prekeys).

use std::fmt;

/// Die vier Pool-Typen aus dem Datenmodell: klassisch und post-quantum,
/// jeweils signiert (rotierend, mehrfach lesbar) und einmalig (konsumiert).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrekeyKind {
    Signed,
    OneTime,
    PqSigned,
    PqOneTime,
}

impl PrekeyKind {
    /// Signierte Prekeys werden beim Abruf gelesen, Einmal-Prekeys
    /// konsumiert; an dieser Eigenschaft hängt die gesamte Pool-Logik.
    pub fn is_one_time(self) -> bool {
        matches!(self, PrekeyKind::OneTime | PrekeyKind::PqOneTime)
    }

    /// Stabile Zeichenform, identisch mit dem CHECK-Constraint der Tabelle.
    pub fn as_str(self) -> &'static str {
        match self {
            PrekeyKind::Signed => "signed",
            PrekeyKind::OneTime => "one_time",
            PrekeyKind::PqSigned => "pq_signed",
            PrekeyKind::PqOneTime => "pq_one_time",
        }
    }
}

impl fmt::Display for PrekeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ein hochgeladener Prekey: client-erzeugte ID plus opaker Schlüssel-Blob
/// (Base64 an der API, BYTEA in der Ablage).
#[derive(Debug, Clone)]
pub struct Prekey {
    pub id: String,
    pub key: String,
}

/// Das Bündel eines Geräts für den Sitzungsaufbau: signierte Prekeys werden
/// gelesen, die Einmal-Prekeys sind beim Zusammenstellen konsumiert worden.
/// Leere Felder heißen: Pool leer bzw. noch nichts hochgeladen; der
/// Client-Core entscheidet, ob ihm das für PQXDH reicht (sicherheit.md:
/// Rückfall auf den Signed Prekey schwächt die PQ-Eigenschaften).
#[derive(Debug, Clone, Default)]
pub struct DeviceBundle {
    pub signed: Option<Prekey>,
    pub pq_signed: Option<Prekey>,
    pub one_time: Option<Prekey>,
    pub pq_one_time: Option<Prekey>,
}

/// Verbleibende Einmal-Prekeys eines Geräts; der Client füllt ab 20 nach
/// (Zielwerte aus datenmodell.md).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolCounts {
    pub one_time: u64,
    pub pq_one_time: u64,
}
