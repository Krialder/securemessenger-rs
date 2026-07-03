//! Das Schlüssel-Commitment eines Kontos: der Wert, der im
//! KT-Verzeichnis unter dem Handle steht (specs/key-transparency.md).
//!
//! Die kanonischen Bytes rechnet `kt-format` (eine Quelle für Server und
//! Clients, auch wasm32); hier lebt nur der Adapter von der
//! identity-Antwortform (`AccountDevices`) auf dieses Format. identity
//! berechnet und meldet das Commitment, Clients rechnen es zur
//! Selbstprüfung nach.

use crate::identity_client::AccountDevices;
use kt_format::CommitmentDevice;

/// SHA-256 über Identitätsschlüssel und gültige Gerätemenge, Format
/// `smktc.v1` (Details und Begründung in `kt_format::account_commitment`).
pub fn account_commitment(account: &AccountDevices) -> Vec<u8> {
    let devices: Vec<CommitmentDevice<'_>> = account
        .devices
        .iter()
        .map(|d| CommitmentDevice {
            id: &d.id,
            public_key: &d.public_key,
            not_after: d.not_after,
        })
        .collect();
    kt_format::account_commitment(&account.identity_key, &devices)
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

    /// Der Adapter darf die kanonischen Bytes nicht verändern: dieselben
    /// Eingaben müssen dasselbe Commitment ergeben wie kt-format direkt.
    #[test]
    fn adapter_matches_canonical_format() {
        let account = AccountDevices {
            id: "acc".to_string(),
            handle: "alice".to_string(),
            identity_key: "aWQ=".to_string(),
            devices: vec![device("dev-1", "a2V5MQ=="), device("dev-2", "a2V5Mg==")],
        };
        let direct = kt_format::account_commitment(
            "aWQ=",
            &[
                kt_format::CommitmentDevice {
                    id: "dev-1",
                    public_key: "a2V5MQ==",
                    not_after: 4102444800,
                },
                kt_format::CommitmentDevice {
                    id: "dev-2",
                    public_key: "a2V5Mg==",
                    not_after: 4102444800,
                },
            ],
        );
        assert_eq!(account_commitment(&account), direct);
    }

    #[test]
    fn commitment_reacts_to_key_and_device_changes() {
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
    }
}
