//! Kanonische Byte-Formate der Key Transparency, geteilt zwischen Server
//! und Clients (specs/key-transparency.md).
//!
//! Drei Festlegungen leben hier an genau einer Stelle, weil beide Seiten
//! dieselben Bytes rechnen müssen und eine stille Abweichung die
//! Selbstprüfung wertlos machen würde:
//!
//! - das Konto-Commitment `smktc.v1` (identity berechnet und meldet es,
//!   Clients rechnen es zur Selbstprüfung nach),
//! - die signierte Wurzelnachricht `smkt.v1` (kt signiert sie, Clients
//!   und Auditoren prüfen die Signatur),
//! - hinter dem Feature `verify` die akd-Konfiguration mit dem
//!   Domain-Label der Plattform (kt baut den Baum damit, Clients
//!   verifizieren Beweise nur mit exakt derselben Konfiguration).

use sha2::{Digest, Sha256};

/// Ein Gerät, wie es ins Commitment eingeht: die Felder, die identity
/// über `GET /devices` beziehungsweise die interne Konto-API liefert.
pub struct CommitmentDevice<'a> {
    /// Client-erzeugte Geräte-ID (kanonische UUID).
    pub id: &'a str,
    /// Öffentlicher Geräteschlüssel als Base64 (opak nach ADR-0009).
    pub public_key: &'a str,
    /// Ablauf des Geräte-Credentials in Unix-Sekunden.
    pub not_after: u64,
}

/// Das Konto-Commitment `smktc.v1`: SHA-256 über Identitätsschlüssel und
/// gültige Gerätemenge. [ANNAHME: eigenes, minimales Format; die Spec
/// lässt das Commitment-Schema offen. Es ist bewusst nur ein Hash: die
/// Schlüssel selbst liefert das Schlüssel-Verzeichnis, KT beweist deren
/// Unverändertheit.]
///
/// Kanonisch: Domain-Präfix, Identitätsschlüssel, dann jedes Gerät
/// sortiert nach ID mit Feldtrennern. Die Sortierung passiert hier, damit
/// das Commitment unabhängig von der Reihenfolge der Server-Antwort ist.
pub fn account_commitment(identity_key: &str, devices: &[CommitmentDevice<'_>]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"smktc.v1");
    hasher.update(identity_key.as_bytes());
    hasher.update([0x00]);
    let mut sorted: Vec<&CommitmentDevice<'_>> = devices.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(b.id));
    for device in sorted {
        hasher.update(device.id.as_bytes());
        hasher.update([0x00]);
        hasher.update(device.public_key.as_bytes());
        hasher.update([0x00]);
        hasher.update(device.not_after.to_be_bytes());
        hasher.update([0x01]);
    }
    hasher.finalize().to_vec()
}

/// Die kanonischen Bytes der signierten Wurzel (STH). [ANNAHME: eigenes,
/// minimales Format mit Domain-Präfix "smkt.v1"; die Spec legt keins
/// fest. Es enthält genau das, was ein Prüfer braucht: Epoche und
/// Wurzel-Hash.]
pub fn root_message(epoch: u64, root_hash: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(7 + 8 + root_hash.len());
    message.extend_from_slice(b"smkt.v1");
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(root_hash);
    message
}

/// Die akd-Konfiguration der Plattform. [ANNAHME: ExperimentalConfiguration
/// mit eigenem Domain-Label; sie ist die von akd empfohlene aktuelle
/// Konfiguration. WhatsAppV1 bliebe die Alternative, wenn Interop mit
/// deren Auditoren nötig würde.] Beweise verifizieren nur mit exakt
/// dieser Konfiguration, deshalb liegt sie hier und nicht im kt-Dienst.
#[cfg(feature = "verify")]
#[derive(Clone)]
pub struct SmDomainLabel;

#[cfg(feature = "verify")]
impl akd::DomainLabel for SmDomainLabel {
    fn domain_label() -> &'static [u8] {
        b"securemessenger-kt-v1"
    }
}

#[cfg(feature = "verify")]
pub type KtConfiguration = akd::ExperimentalConfiguration<SmDomainLabel>;

#[cfg(test)]
mod tests {
    use super::*;

    fn device<'a>(id: &'a str, key: &'a str) -> CommitmentDevice<'a> {
        CommitmentDevice {
            id,
            public_key: key,
            not_after: 4102444800,
        }
    }

    #[test]
    fn commitment_is_order_independent_and_key_sensitive() {
        let devices = [device("dev-1", "a2V5MQ=="), device("dev-2", "a2V5Mg==")];
        let reversed = [device("dev-2", "a2V5Mg=="), device("dev-1", "a2V5MQ==")];
        assert_eq!(
            account_commitment("aWQ=", &devices),
            account_commitment("aWQ=", &reversed),
            "Gerätereihenfolge darf das Commitment nicht ändern"
        );

        let swapped = [device("dev-1", "YW5kZXJlcg=="), device("dev-2", "a2V5Mg==")];
        assert_ne!(
            account_commitment("aWQ=", &devices),
            account_commitment("aWQ=", &swapped),
            "Schlüsseltausch muss das Commitment ändern"
        );

        let extra = [
            device("dev-1", "a2V5MQ=="),
            device("dev-2", "a2V5Mg=="),
            device("dev-3", "a2V5Mw=="),
        ];
        assert_ne!(
            account_commitment("aWQ=", &devices),
            account_commitment("aWQ=", &extra),
            "Rogue-Gerät muss das Commitment ändern"
        );
    }

    #[test]
    fn root_message_is_epoch_and_root_bound() {
        let root = [42u8; 32];
        assert_eq!(&root_message(3, &root)[..7], b"smkt.v1");
        assert_ne!(root_message(3, &root), root_message(4, &root));
        assert_ne!(root_message(3, &root), root_message(3, &[7u8; 32]));
    }
}
