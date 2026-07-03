//! Das Schlüssel-Commitment eines Kontos: der Wert, der im
//! KT-Verzeichnis unter dem Handle steht (specs/key-transparency.md).
//!
//! Liegt in common, weil identity es berechnet und meldet, kt es nur
//! speichert und Clients es später lokal nachrechnen (Selbstprüfung).
//! Ein SHA-256 über die kanonische Serialisierung von
//! Identitätsschlüssel und gültiger Gerätemenge.
//! [ANNAHME: eigenes, minimales Format "smktc.v1"; die Spec lässt das
//! Commitment-Schema offen ("Commitment-Schema für mehrere Geräte pro
//! Konto" steht dort als offener Punkt). Es ist bewusst nur ein Hash:
//! die Schlüssel selbst liefert das Schlüssel-Verzeichnis (directory),
//! KT beweist deren Unverändertheit.]

use crate::identity_client::AccountDevices;
use sha2::{Digest, Sha256};

/// Kanonisch: Domain-Präfix, Identitätsschlüssel, dann jedes gültige
/// Gerät sortiert nach ID mit Feldtrennern. Sortierung macht das
/// Commitment unabhängig von der Reihenfolge der identity-Antwort.
pub fn account_commitment(account: &AccountDevices) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"smktc.v1");
    hasher.update(account.identity_key.as_bytes());
    hasher.update([0x00]);
    let mut devices: Vec<_> = account.devices.iter().collect();
    devices.sort_by(|a, b| a.id.cmp(&b.id));
    for device in devices {
        hasher.update(device.id.as_bytes());
        hasher.update([0x00]);
        hasher.update(device.public_key.as_bytes());
        hasher.update([0x00]);
        hasher.update(device.not_after.to_be_bytes());
        hasher.update([0x01]);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_client::DeviceInfo;

    fn device(id: &str, key: &str) -> DeviceInfo {
        DeviceInfo {
            id: id.to_string(),
            public_key: key.to_string(),
            not_after: 4102444800,
        }
    }

    #[test]
    fn commitment_is_order_independent_and_key_sensitive() {
        let a = AccountDevices {
            id: "acc".to_string(),
            handle: "alice".to_string(),
            identity_key: "aWQ=".to_string(),
            devices: vec![device("dev-1", "a2V5MQ=="), device("dev-2", "a2V5Mg==")],
        };
        let mut b = a.clone();
        b.devices.reverse();
        assert_eq!(
            account_commitment(&a),
            account_commitment(&b),
            "Gerätereihenfolge darf das Commitment nicht ändern"
        );

        let mut c = a.clone();
        c.devices[0].public_key = "YW5kZXJlcg==".to_string();
        assert_ne!(
            account_commitment(&a),
            account_commitment(&c),
            "Schlüsseltausch muss das Commitment ändern"
        );

        let mut d = a.clone();
        d.devices.push(device("dev-3", "a2V5Mw=="));
        assert_ne!(
            account_commitment(&a),
            account_commitment(&d),
            "Rogue-Gerät muss das Commitment ändern"
        );
    }
}
