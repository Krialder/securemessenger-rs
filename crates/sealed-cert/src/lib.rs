//! Ausstellung der Sealed-Sender-Zertifikate
//! (specs/sealed-sender-und-abuse.md).
//!
//! Sealed Sender braucht eine Aussage, der der Empfänger trauen kann: "der
//! Server hat diesen Absender authentifiziert, und das ist sein
//! Identitätsschlüssel". Signal löst das über eine zweistufige
//! Zertifikatskette: Ein Trust Root (langlebig, sein öffentlicher Teil ist
//! im Client verankert) signiert ein Server-Zertifikat, dessen Schlüssel
//! wiederum die kurzlebigen Absender-Zertifikate signiert. Die Empfänger
//! prüfen beim Entsiegeln nur gegen den Trust Root; die Kette steckt im
//! Zertifikat selbst.
//!
//! Genau diese Zweistufigkeit macht die Infrastruktur austauschbar: Der
//! Serverschlüssel entsteht hier bei jedem Start frisch und wird vom Trust
//! Root signiert. Er kann also rotieren, auf mehrere Instanzen verteilt
//! oder später durch eine anonyme Credential-Quelle (zkgroup) ersetzt
//! werden, ohne dass ein Client einen neuen Anker lernt. Das Format ist
//! libsignals eigenes Protobuf (`ServerCertificate`, `SenderCertificate`),
//! kein Eigenbau; dieses Crate hält nur die Ausstellung an einer Stelle.
//!
//! [ANNAHME: Der Absender-Name im Zertifikat ist das Handle (Signal nimmt
//! dort die Konto-UUID); die Protokolladressen dieses Systems laufen über
//! Handles, und der Empfänger ordnet die Sitzung über genau diesen Namen
//! zu. Das Zertifikat verrät dem Empfänger den Absender, das soll es: nur
//! der Server soll ihn nicht mehr sehen.]

use libsignal_protocol::{
    DeviceId, KeyPair, PrivateKey, PublicKey, SenderCertificate, ServerCertificate,
};

/// Fehler der Ausstellung; als String gehalten, weil die Aufrufer (der
/// identity-Dienst) daraus ohnehin nur eine Log-Zeile und ein 500 machen.
#[derive(Debug)]
pub struct IssueError(pub String);

impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IssueError {}

fn map_err<E: std::fmt::Display>(context: &str) -> impl Fn(E) -> IssueError + '_ {
    move |error| IssueError(format!("{context}: {error}"))
}

/// Länge des Trust-Root-Geheimnisses: ein X25519-Skalar.
pub const TRUST_ROOT_SEED_LEN: usize = 32;

/// Die Schlüssel-ID des Server-Zertifikats. Der Wert ist frei, solange er
/// nicht in libsignals Revocation-Liste steht (0xDEADC357 ist revoziert).
const SERVER_KEY_ID: u32 = 1;

/// Der Aussteller: hält den Trust Root und ein beim Bau frisch erzeugtes,
/// vom Trust Root signiertes Server-Zertifikat.
pub struct Issuer {
    server_key: PrivateKey,
    server_certificate: ServerCertificate,
    trust_root_public: PublicKey,
}

impl Issuer {
    /// Baut den Aussteller aus dem Trust-Root-Geheimnis (32 Bytes, aus der
    /// Konfiguration). Der Serverschlüssel entsteht dabei frisch: Er muss
    /// Neustarts nicht überleben, weil jedes Absender-Zertifikat seine
    /// Signaturkette vollständig mitträgt.
    pub fn from_seed(seed: &[u8]) -> Result<Self, IssueError> {
        if seed.len() != TRUST_ROOT_SEED_LEN {
            return Err(IssueError(format!(
                "Trust-Root-Geheimnis muss {TRUST_ROOT_SEED_LEN} Bytes haben, hat {}",
                seed.len()
            )));
        }
        let trust_root = PrivateKey::deserialize(seed).map_err(map_err("Trust Root unlesbar"))?;
        let trust_root_public = trust_root
            .public_key()
            .map_err(map_err("Trust-Root-Public"))?;

        let mut rng = rand::rng();
        let server_pair = KeyPair::generate(&mut rng);
        let server_certificate =
            ServerCertificate::new(SERVER_KEY_ID, server_pair.public_key, &trust_root, &mut rng)
                .map_err(map_err("Server-Zertifikat"))?;

        Ok(Self {
            server_key: server_pair.private_key,
            server_certificate,
            trust_root_public,
        })
    }

    /// Der öffentliche Trust Root (33 Bytes, serialisiert), den Clients zum
    /// Prüfen brauchen. Er ist der eine Anker, der stabil bleiben muss.
    pub fn trust_root_public(&self) -> Vec<u8> {
        self.trust_root_public.serialize().into_vec()
    }

    /// Stellt ein Absender-Zertifikat aus: Handle, Protokoll-Gerätenummer
    /// und der registrierte Identitätsschlüssel (33 Bytes, serialisiert)
    /// des authentifizierten Geräts, gültig bis `expires_at_millis`
    /// (Unix-Millisekunden). Zurück kommt das serialisierte Zertifikat,
    /// das der Client unverändert an `sealed_sender_encrypt` gibt.
    pub fn issue(
        &self,
        handle: &str,
        protocol_device_id: u32,
        identity_key: &[u8],
        expires_at_millis: u64,
    ) -> Result<Vec<u8>, IssueError> {
        let key = PublicKey::deserialize(identity_key)
            .map_err(map_err("Identitätsschlüssel unlesbar"))?;
        let device_id: DeviceId = u8::try_from(protocol_device_id)
            .ok()
            .and_then(|id| DeviceId::new(id).ok())
            .ok_or_else(|| {
                IssueError(format!(
                    "Protokoll-Gerätenummer {protocol_device_id} liegt außerhalb des gültigen Bereichs"
                ))
            })?;
        let mut rng = rand::rng();
        let certificate = SenderCertificate::new(
            handle.to_string(),
            None,
            key,
            device_id,
            libsignal_protocol::Timestamp::from_epoch_millis(expires_at_millis),
            self.server_certificate.clone(),
            &self.server_key,
            &mut rng,
        )
        .map_err(map_err("Absender-Zertifikat"))?;
        Ok(certificate
            .serialized()
            .map_err(map_err("Serialisierung"))?
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::Timestamp;

    fn identity_key_bytes() -> Vec<u8> {
        let mut rng = rand::rng();
        KeyPair::generate(&mut rng)
            .public_key
            .serialize()
            .into_vec()
    }

    #[test]
    fn issued_certificate_validates_against_trust_root() {
        let issuer = Issuer::from_seed(&[7u8; 32]).unwrap();
        let cert_bytes = issuer
            .issue("alice", 1, &identity_key_bytes(), 10_000)
            .unwrap();

        let cert = SenderCertificate::deserialize(&cert_bytes).unwrap();
        let trust_root = PublicKey::deserialize(&issuer.trust_root_public()).unwrap();
        // Vor dem Ablauf gültig, danach nicht mehr: die Gültigkeit hängt
        // an der Signaturkette UND am Zeitpunkt.
        assert!(cert
            .validate(&trust_root, Timestamp::from_epoch_millis(9_999))
            .unwrap());
        assert!(!cert
            .validate(&trust_root, Timestamp::from_epoch_millis(10_001))
            .unwrap());
        assert_eq!(cert.sender_uuid().unwrap(), "alice");
    }

    #[test]
    fn foreign_trust_root_rejects_certificate() {
        let issuer = Issuer::from_seed(&[7u8; 32]).unwrap();
        let other = Issuer::from_seed(&[8u8; 32]).unwrap();
        let cert_bytes = issuer
            .issue("alice", 1, &identity_key_bytes(), 10_000)
            .unwrap();
        let cert = SenderCertificate::deserialize(&cert_bytes).unwrap();
        let foreign_root = PublicKey::deserialize(&other.trust_root_public()).unwrap();
        assert!(!cert
            .validate(&foreign_root, Timestamp::from_epoch_millis(1))
            .unwrap());
    }

    #[test]
    fn seed_length_is_enforced() {
        assert!(Issuer::from_seed(&[1u8; 16]).is_err());
    }
}
