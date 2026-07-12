//! Gemeinsame Namen der lokalen Schlüssel-Werte-Ablage der Clients.
//!
//! CLI und Web-Client legen ihren Zustand unter denselben Schlüsseln ab.
//! Früher hielt jeder Client eigene Kopien dieser Konstanten; drifteten sie
//! auseinander, läge der Zustand plötzlich unter verschiedenen Namen und ein
//! Client fände den des anderen nicht wieder. Hier stehen sie einmal, damit
//! beide Clients garantiert dasselbe Ablage-Layout benutzen.

/// Exportierter MLS-Mitgliedszustand (Signierschlüssel plus Provider).
pub const MLS_STATE_KEY: &str = "mls/state";
/// Lokale Gruppenliste (Zustell-ID plus Anzeigename je Gruppe).
pub const GROUPS_INDEX_KEY: &str = "groups/index";
/// Liste der offenen, noch nicht angenommenen Einladungen (Gruppen-IDs).
pub const INVITES_INDEX_KEY: &str = "invites/index";
/// Nächste zu vergebende Prekey-ID (Zähler).
pub const COUNTER_KEY: &str = "counter/next_prekey_id";
/// Gecachte eigene Gerätemenge für den Self-Sync.
pub const OWN_DEVICES_KEY: &str = "sync/own_devices";

/// Der Geräte-Roster einer Gruppe (Zielgeräte je Handle).
pub fn roster_key(group_id: &str) -> String {
    format!("group/{group_id}/roster")
}

/// Der vorgemerkte Welcome-Blob einer noch nicht angenommenen Einladung.
pub fn invite_key(group_id: &str) -> String {
    format!("group/{group_id}/invite")
}

/// Der gepufferte Vor-Annahme-Verkehr einer Einladung (Base64-JSON-Liste).
pub fn invite_buffer_key(group_id: &str) -> String {
    format!("group/{group_id}/buffer")
}
