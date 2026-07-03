//! Fehlertyp der Client-Bibliothek.
//!
//! Bewusst grob: der Client zeigt dem Nutzer eine verständliche Meldung, die
//! Feindiagnose (welches Feld, welcher Prüfschritt) bleibt bei den Diensten
//! und deren Logs. Die Dienste antworten einheitlich als JSON mit `code` und
//! `message` (dokumentation/schnittstellen.md); `Api` trägt beides weiter,
//! damit ein Aufrufer maschinell auf `code` reagieren kann.

use std::fmt;

#[derive(Debug)]
pub enum ClientError {
    /// Transportfehler unterhalb von HTTP (Verbindung, DNS, TLS).
    Transport(String),
    /// Der Dienst antwortete mit einem Fehlerstatus. `code` ist der
    /// API-Fehlercode, soweit die Antwort einen Textkörper hatte.
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// Die Antwort ließ sich nicht wie erwartet lesen (Deserialisierung).
    Decode(String),
    /// Fehler aus dem Krypto-Kern oder beim (De-)Serialisieren von
    /// Protokoll-Material (Bündel, Hüllen).
    Protocol(String),
    /// Die Key-Transparency-Prüfung ist fehlgeschlagen: das Verzeichnis
    /// enthält nicht das, was dieser Client veröffentlicht hat, oder der
    /// Beweis verifiziert nicht. Eigene Variante, weil das der Alarmfall
    /// der Spec ist (stiller Schlüsseltausch) und Clients ihn anders
    /// anzeigen müssen als einen gewöhnlichen Dienstfehler.
    KeyTransparency(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Transport(detail) => write!(f, "Transportfehler: {detail}"),
            ClientError::Api {
                status,
                code,
                message,
            } => write!(f, "Dienstfehler {status} ({code}): {message}"),
            ClientError::Decode(detail) => write!(f, "Antwort nicht lesbar: {detail}"),
            ClientError::Protocol(detail) => write!(f, "Protokollfehler: {detail}"),
            ClientError::KeyTransparency(detail) => {
                write!(f, "Key-Transparency-Alarm: {detail}")
            }
        }
    }
}

impl std::error::Error for ClientError {}
