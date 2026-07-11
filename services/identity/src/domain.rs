//! Fachmodell für Konten und Geräte. Bewusst ohne Kryptografie: der
//! Passwort-Hash entsteht über die geprüfte argon2-Bibliothek (auth.rs),
//! die Credential-Prüfung liegt in credential.rs.

use std::fmt;

/// Ein Konto, identifiziert über ein eindeutiges Handle (F010).
/// Der Anzeigename ist davon getrennt und änderbar.
///
/// Absichtlich nicht serialisierbar, damit der Passwort-Hash nie versehentlich
/// in einer API-Antwort landet. Antworten bauen eigene Response-Typen.
#[derive(Clone)]
pub struct Account {
    /// Server-erzeugte Konto-UUID (kanonische Form). Interne Adresse für
    /// andere Dienste (z. B. recipient_id in der Zustellung); die öffentliche
    /// Adresse bleibt das Handle.
    pub id: String,
    pub handle: String,
    pub display_name: String,
    /// Argon2id-Hash des Passworts im PHC-Format.
    pub password_hash: String,
    /// Öffentlicher Konto-Identitätsschlüssel (Ed25519, Base64). Die Wurzel
    /// der Geräte-Credentials; der private Teil liegt nie beim Server
    /// (specs/geraete-identitaet.md).
    pub identity_key: String,
    /// Ist eine Löschung vorgemerkt, steht hier der Ablauf der Widerrufsfrist
    /// als Unix-Sekunden (NF030: Löschung mit Widerrufsfrist). `None` bei
    /// einem aktiven Konto. Bis zu diesem Zeitpunkt kann der Nutzer die
    /// Löschung widerrufen; danach entfernt der Purge das Konto und mit ihm
    /// die Schlüssel (Crypto-Shredding).
    pub deletion_pending_until: Option<u64>,
}

// Debug von Hand, damit der Hash nicht in Logs oder Fehlermeldungen leakt.
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("handle", &self.handle)
            .field("display_name", &self.display_name)
            .field("password_hash", &"<geschwärzt>")
            .field("identity_key", &self.identity_key)
            .finish()
    }
}

/// Ein Gerät eines Kontos (F030/F040). Die Zugehörigkeit beweist das vom
/// Konto-Identitätsschlüssel signierte Credential, nicht der Server.
#[derive(Clone, Debug)]
pub struct Device {
    /// Client-erzeugte UUID in kanonischer Form (datenmodell.md). Global
    /// eindeutig und nach Revocation für immer belegt, sonst wäre das alte
    /// Credential für ein neues Gerät mit derselben ID wiederverwendbar
    /// (Replay).
    pub id: String,
    /// Anzeigename, z. B. "Laptop". Rein informativ.
    pub name: String,
    /// Öffentlicher Geräteschlüssel (Ed25519, Base64).
    pub public_key: String,
    /// Signatur des Konto-Identitätsschlüssels über das Credential
    /// (Base64, Format in credential.rs).
    pub credential: String,
    /// Ablauf des Credentials als Unix-Sekunden. Der Client wählt die
    /// Gültigkeitsdauer, der Server lehnt Abgelaufenes ab (Spec lässt die
    /// Dauer offen).
    pub not_after: u64,
    /// Revoziert = aus der gültigen Menge entfernt. Eintrag bleibt wegen
    /// der ID-Sperre erhalten.
    pub revoked: bool,
    /// Kleine, kontoweit eindeutige libsignal-Gerätenummer (1..255), vom
    /// Server bei der Anlage vergeben. Sie ist der Geräteteil der
    /// ProtocolAddress: zwei Geräte eines Kontos brauchen verschiedene
    /// Nummern, damit ein Absender getrennte Sitzungen zu ihnen hält. Der
    /// Server vergibt sie monoton (max + 1, revozierte Nummern werden nicht
    /// wiederverwendet), weil eine wiederbenutzte Nummer eine gecachte
    /// Sitzung zum alten Gerät stillschweigend auf das neue umleiten würde.
    /// `0` ist der Platzhalter vor der Vergabe (die Ablage setzt den Wert).
    pub protocol_device_id: u16,
}

/// Obergrenze der Gerätenummer: die libsignal-`DeviceId` und die
/// Bündel-Blobs führen sie als ein Byte (client-app `device_id_from_u32`),
/// mehr als 255 Geräte je Konto sind ohnehin absurd.
pub const MAX_PROTOCOL_DEVICE_ID: u16 = 255;
