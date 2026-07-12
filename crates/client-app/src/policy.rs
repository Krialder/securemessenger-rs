//! Gemeinsame Betriebs- und Protokoll-Konstanten der Clients.
//!
//! Werte, die CLI und Web-Client identisch halten müssen. Einmal hier, statt
//! in jedem Client eine eigene Kopie zu pflegen (die auseinanderdriften
//! kann, was die Bestandsaufnahme als Risiko markiert hat).

/// Gültigkeitsdauer eines Geräte-Credentials in Sekunden (ein Jahr). Der
/// Client wählt die Dauer, der Dienst prüft nur (geraete-identitaet.md).
pub const CREDENTIAL_TTL_SECONDS: u64 = 60 * 60 * 24 * 365;

/// Zielbestand ungenutzter MLS-KeyPackages je Gerät: der Client legt nur bis
/// zu diesem Stand nach, damit der Verzeichnis-Pool klein bleibt und der
/// serverseitige Deckel im Normalbetrieb nie greift.
pub const MLS_KEY_PACKAGE_TARGET: u64 = 8;

/// Höchstzahl gleichzeitig offener (noch nicht angenommener) Gruppen-
/// Einladungen. Deckel gegen das Fluten der Einladungsliste (DoS-Bremse).
pub const MAX_PENDING_INVITES: usize = 16;

/// Höchstzahl gepufferter Vor-Annahme-Hüllen je Einladung. Der Roster kommt
/// zuerst; der Deckel verhindert, dass ein Einladender die Ablage vor einer
/// Ablehnung mit beliebig vielen Hüllen füllt.
pub const INVITE_BUFFER_MAX: usize = 32;
