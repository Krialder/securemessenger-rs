//! Fachmodell der Integrations-API: Mandanten und ihre Rechte (F100).

/// Recht, Benachrichtigungen auszulösen (F070).
pub const SCOPE_NOTIFY: &str = "notify";
/// Recht, Präsenz abzufragen (F080).
pub const SCOPE_PRESENCE: &str = "presence";

/// Alle bekannten Scopes; die Mandanten-Anlage weist alles andere ab,
/// damit Tippfehler nicht als "nie greifendes Recht" durchrutschen.
pub const KNOWN_SCOPES: [&str; 2] = [SCOPE_NOTIFY, SCOPE_PRESENCE];

/// Ein Fremdprojekt als Mandant. Das Client-Secret taucht hier nie auf,
/// es existiert nur als Argon2id-Hash in der Ablage.
#[derive(Debug, Clone)]
pub struct Tenant {
    /// Server-erzeugte UUID (kanonische Form).
    pub id: String,
    /// Sprechender, eindeutiger Name, z. B. "azubi-os". Steht auch im
    /// Pfad der API (/integrations/{tenant}/...) und markiert die
    /// Benachrichtigungen beim Nutzer als Maschinen-Hinweis.
    pub name: String,
    /// OAuth2-Client-ID; heute gleich dem Namen, bleibt aber eigenes
    /// Feld, damit eine spätere Keycloak-Anbindung (F060) die IDs
    /// unabhängig vom Namen vergeben kann.
    pub client_id: String,
    /// Gewährte Rechte, Teilmenge von KNOWN_SCOPES.
    pub scopes: Vec<String>,
    /// Anfragen pro Minute (F100); durchgesetzt in rate.rs.
    pub rate_limit: u32,
    /// Gesperrte Mandanten behalten ihre Daten, bekommen aber weder
    /// Tokens noch API-Zugriff.
    pub disabled: bool,
}

impl Tenant {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}
