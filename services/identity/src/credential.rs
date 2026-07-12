//! Prüfung von Geräte-Credentials (specs/geraete-identitaet.md).
//!
//! Der Konto-Identitätsschlüssel (Ed25519) signiert clientseitig ein
//! Credential, das Geräteschlüssel, Geräte-ID und Gültigkeit an das Konto
//! bindet. Der Server verifiziert nur; er besitzt keine privaten Schlüssel.
//!
//! [ANNAHME: Die Spec lässt das Credential-Format offen. Bis zur Festlegung
//! gilt das hier definierte Format "smdc.v1" (SecureMessenger Device
//! Credential). Es ist versioniert, damit ein späterer Wechsel ohne
//! Mehrdeutigkeit möglich ist.]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};

/// Warum die Credential-Prüfung fehlschlug. Die API übersetzt alle Varianten
/// in denselben generischen Fehler; die Unterscheidung dient Logs und Tests.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// Schlüssel oder Signatur sind kein gültiges Base64 oder haben die
    /// falsche Länge (Ed25519: 32 Byte Schlüssel, 64 Byte Signatur).
    Malformed,
    /// Die Signatur passt nicht zum Konto-Identitätsschlüssel.
    BadSignature,
    /// `not_after` liegt nicht in der Zukunft.
    Expired,
}

/// Die zu signierende Nachricht. Newline-getrennt und mit Versionspräfix:
/// eindeutig, solange kein Feld ein Newline enthält. Das stellen die
/// API-Validierungen sicher (Handle-Alphabet, Geräte-ID-Alphabet, Base64,
/// Dezimalzahl). Längenpräfixe oder CBOR wären robuster, aber für ein als
/// Annahme markiertes Übergangsformat unnötiger Aufwand.
pub fn credential_message(
    handle: &str,
    device_id: &str,
    device_public_key_b64: &str,
    not_after: u64,
) -> String {
    format!("smdc.v1\n{handle}\n{device_id}\n{device_public_key_b64}\n{not_after}")
}

/// Prüft ein Geräte-Credential gegen den Konto-Identitätsschlüssel.
///
/// `now` kommt vom Aufrufer, damit Tests den Ablauf deterministisch prüfen
/// können (gleiche Überlegung wie bei der Session-Ablage).
pub fn verify_device_credential(
    identity_key_b64: &str,
    handle: &str,
    device_id: &str,
    device_public_key_b64: &str,
    not_after: u64,
    signature_b64: &str,
    now: u64,
) -> Result<(), CredentialError> {
    // Ablauf zuerst: billig, und ein abgelaufenes Credential soll auch mit
    // gültiger Signatur nicht als "nur abgelaufen light" durchrutschen.
    if not_after <= now {
        return Err(CredentialError::Expired);
    }
    // Obergrenze: die Ablage speichert Unix-Sekunden als BIGINT (i64,
    // datenmodell.md). Werte darüber sind kein reales Ablaufdatum.
    if not_after > i64::MAX as u64 {
        return Err(CredentialError::Malformed);
    }

    let identity_key = decode_verifying_key(identity_key_b64)?;
    // Der Geräteschlüssel ist die serialisierte libsignal-Identität des
    // Geräts (ADR-0009) und für den Server opak: er speichert und verteilt
    // sie nur, benutzt sie nie. Geprüft wird deshalb Form und Länge, nicht
    // die Kurve; die kryptografische Prüfung geschieht im Client beim
    // Verarbeiten des Prekey-Bündels. Die Längengrenze hält offensichtlichen
    // Müll aus der Ablage (libsignal-Identitäten sind 33 Bytes, Ed25519 32).
    decode_opaque_key(device_public_key_b64)?;

    let signature_bytes: [u8; 64] = BASE64
        .decode(signature_b64)
        .map_err(|_| CredentialError::Malformed)?
        .try_into()
        .map_err(|_| CredentialError::Malformed)?;
    let signature = Signature::from_bytes(&signature_bytes);

    let message = credential_message(handle, device_id, device_public_key_b64, not_after);
    // verify_strict statt verify: lehnt Schlüssel/Signaturen mit
    // Small-Order-Komponenten ab und schließt damit Malleability-Spielräume,
    // die bei Standard-Ed25519-Verify offen bleiben.
    identity_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| CredentialError::BadSignature)
}

/// Die zu signierende Rotations-Botschaft (ADR-0010). Byte-gleich zur
/// Client-Seite (client-app::account::rotation_message).
pub fn rotation_message(handle: &str, new_identity_key_b64: &str) -> String {
    format!("smrot.v1\n{handle}\n{new_identity_key_b64}")
}

/// Prüft das Rotations-Zertifikat gegen den ALTEN Konto-Wurzelschlüssel
/// (ADR-0010): nur wer den alten Schlüssel hält, kann die Kontinuität
/// belegen. Der neue Schlüssel muss zudem ein wohlgeformter Ed25519-Punkt
/// sein (er verifiziert danach die neuen Geräte-Credentials).
pub fn verify_rotation_cert(
    old_identity_key_b64: &str,
    handle: &str,
    new_identity_key_b64: &str,
    signature_b64: &str,
) -> Result<(), CredentialError> {
    // Der neue Schlüssel muss ein gültiger Ed25519-Punkt sein, sonst könnte
    // ein Konto in einen Zustand rotieren, in dem keine Signatur mehr prüft.
    decode_verifying_key(new_identity_key_b64)?;
    let old_key = decode_verifying_key(old_identity_key_b64)?;
    let signature_bytes: [u8; 64] = BASE64
        .decode(signature_b64)
        .map_err(|_| CredentialError::Malformed)?
        .try_into()
        .map_err(|_| CredentialError::Malformed)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = rotation_message(handle, new_identity_key_b64);
    old_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| CredentialError::BadSignature)
}

/// Dekodiert den Base64-Ed25519-Konto-Wurzelschlüssel; nur er verifiziert
/// serverseitig Signaturen.
fn decode_verifying_key(key_b64: &str) -> Result<VerifyingKey, CredentialError> {
    let bytes: [u8; 32] = BASE64
        .decode(key_b64)
        .map_err(|_| CredentialError::Malformed)?
        .try_into()
        .map_err(|_| CredentialError::Malformed)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CredentialError::Malformed)
}

/// Obergrenze für opake Geräteschlüssel in Bytes. Großzügig über den realen
/// Formaten (33 Bytes libsignal, 32 Bytes Ed25519), aber klein genug, dass
/// niemand Datenblöcke als "Schlüssel" ablegt.
const MAX_DEVICE_KEY_BYTES: usize = 128;

/// Prüft einen opaken Geräteschlüssel (ADR-0009): gültiges Base64, nicht
/// leer, längenbegrenzt. Keine Kurvenprüfung, der Server interpretiert den
/// Schlüssel nicht.
fn decode_opaque_key(key_b64: &str) -> Result<(), CredentialError> {
    match BASE64.decode(key_b64) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_DEVICE_KEY_BYTES => Ok(()),
        _ => Err(CredentialError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Baut ein signiertes Credential, wie es sonst der Client erzeugt.
    fn sign(
        key: &SigningKey,
        handle: &str,
        device_id: &str,
        device_key_b64: &str,
        not_after: u64,
    ) -> String {
        let message = credential_message(handle, device_id, device_key_b64, not_after);
        BASE64.encode(key.sign(message.as_bytes()).to_bytes())
    }

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn accepts_valid_credential() {
        let identity = test_key(1);
        let device_key_b64 = BASE64.encode(test_key(2).verifying_key().to_bytes());
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());
        let sig = sign(&identity, "alice", "dev-1", &device_key_b64, 1000);

        let result = verify_device_credential(
            &identity_b64,
            "alice",
            "dev-1",
            &device_key_b64,
            1000,
            &sig,
            999,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_expired_credential() {
        let identity = test_key(1);
        let device_key_b64 = BASE64.encode(test_key(2).verifying_key().to_bytes());
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());
        let sig = sign(&identity, "alice", "dev-1", &device_key_b64, 1000);

        // not_after == now zählt als abgelaufen, gleiche Semantik wie bei
        // Session-Tokens (deterministisch mit Laufzeit 0 testbar).
        let result = verify_device_credential(
            &identity_b64,
            "alice",
            "dev-1",
            &device_key_b64,
            1000,
            &sig,
            1000,
        );
        assert_eq!(result, Err(CredentialError::Expired));
    }

    #[test]
    fn rejects_signature_from_wrong_key() {
        let identity = test_key(1);
        let attacker = test_key(9);
        let device_key_b64 = BASE64.encode(test_key(2).verifying_key().to_bytes());
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());
        let sig = sign(&attacker, "alice", "dev-1", &device_key_b64, 1000);

        let result = verify_device_credential(
            &identity_b64,
            "alice",
            "dev-1",
            &device_key_b64,
            1000,
            &sig,
            1,
        );
        assert_eq!(result, Err(CredentialError::BadSignature));
    }

    #[test]
    fn rejects_tampered_fields() {
        let identity = test_key(1);
        let device_key_b64 = BASE64.encode(test_key(2).verifying_key().to_bytes());
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());
        let sig = sign(&identity, "alice", "dev-1", &device_key_b64, 1000);

        // Signiert wurde dev-1; jedes abweichende Feld muss die Prüfung
        // scheitern lassen, sonst bindet das Credential nichts.
        let result = verify_device_credential(
            &identity_b64,
            "alice",
            "dev-2",
            &device_key_b64,
            1000,
            &sig,
            1,
        );
        assert_eq!(result, Err(CredentialError::BadSignature));
    }

    #[test]
    fn rejects_malformed_input() {
        let result = verify_device_credential("kein base64!", "a", "d", "x", 10, "sig", 1);
        assert_eq!(result, Err(CredentialError::Malformed));
    }

    /// Geräteschlüssel sind opak (ADR-0009): eine serialisierte
    /// libsignal-Identität (33 Bytes, Typ-Präfix 0x05) muss durchgehen,
    /// obwohl sie kein Ed25519-Punkt ist.
    #[test]
    fn accepts_libsignal_identity_as_device_key() {
        let identity = test_key(1);
        let mut libsignal_key = vec![0x05u8];
        libsignal_key.extend_from_slice(&[7u8; 32]);
        let device_key_b64 = BASE64.encode(&libsignal_key);
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());
        let sig = sign(&identity, "alice", "dev-1", &device_key_b64, 1000);

        let result = verify_device_credential(
            &identity_b64,
            "alice",
            "dev-1",
            &device_key_b64,
            1000,
            &sig,
            1,
        );
        assert_eq!(result, Ok(()));
    }

    /// Opak heißt nicht grenzenlos: leere und überlange Schlüssel bleiben
    /// draußen.
    #[test]
    fn rejects_empty_and_oversized_device_keys() {
        let identity = test_key(1);
        let identity_b64 = BASE64.encode(identity.verifying_key().to_bytes());

        for bad_key in [BASE64.encode([]), BASE64.encode([1u8; 129])] {
            let sig = sign(&identity, "alice", "dev-1", &bad_key, 1000);
            let result =
                verify_device_credential(&identity_b64, "alice", "dev-1", &bad_key, 1000, &sig, 1);
            assert_eq!(result, Err(CredentialError::Malformed));
        }
    }
}
