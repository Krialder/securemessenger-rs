//! Client des Key-Transparency-Dienstes (services/kt) und die
//! Selbstprüfung der eigenen Schlüsselhistorie.
//!
//! Die Selbstprüfung ist der primäre Hebel der Spec
//! (specs/key-transparency.md "Selbstprüfung durch den Client"): der
//! Client weiß, welche Schlüssel er veröffentlicht hat, holt den
//! Inklusionsbeweis zu seinem Handle und prüft, dass im Verzeichnis genau
//! das Commitment steht, das er lokal aus Identitätsschlüssel und
//! Gerätemenge nachrechnet. Schiebt der Server einen fremden Schlüssel
//! oder ein fremdes Gerät ein, ändert sich das Commitment, und die
//! Prüfung schlägt Alarm (`ClientError::KeyTransparency`).
//!
//! Geprüft wird in vier Schritten, jeder für sich notwendig:
//! 1. Wurzelsignatur: die Epoche ist vom kt-Dienst signiert (Ed25519,
//!    Format `smkt.v1` aus kt-format).
//! 2. Wurzelbindung: der Beweis gehört zu genau dieser signierten Wurzel.
//! 3. Inklusionsbeweis: akd verifiziert Label und Wert gegen die Wurzel
//!    (VRF-Schlüssel des Dienstes, geteilte `KtConfiguration`).
//! 4. Commitment-Vergleich: der bewiesene Wert ist byte-gleich mit dem
//!    lokal nachgerechneten `smktc.v1`-Commitment.
//!
//! [ANNAHME: Das Bootstrapping des Wurzel-Signaturschlüssels ist in der
//! Spec offen. Ohne übergebenen Pin gilt Trust-on-first-use über
//! `GET /kt/info`; Aufrufer, die den Schlüssel kennen (Konfiguration,
//! früherer Lauf), übergeben ihn und ein Tausch fällt auf.]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use kt_format::{account_commitment, root_message, CommitmentDevice, KtConfiguration};
use serde::Deserialize;

use crate::error::ClientError;
use crate::http::{parse_json, transport};
use crate::identity::DeviceView;

/// Client des Key-Transparency-Dienstes. Hält Basis-URL und einen
/// wiederverwendbaren HTTP-Client, wie die übrigen Dienst-Clients.
#[derive(Clone)]
pub struct KtClient {
    base_url: String,
    http: reqwest::Client,
}

/// Antwort von `GET /kt/info`: der Einstieg für Clients.
#[derive(Deserialize, Debug, Clone)]
pub struct KtInfo {
    /// Öffentlicher Wurzel-Signaturschlüssel (Ed25519, Base64); das, was
    /// Clients pinnen.
    pub root_signing_key: String,
    /// Öffentlicher VRF-Schlüssel für die Label-Verifikation (Base64).
    pub vrf_public_key: String,
    /// Jüngste veröffentlichte Epoche; `None`, solange keine existiert.
    pub latest_epoch: Option<u64>,
}

/// Antwort von `GET /kt/proof/{handle}`: Inklusionsbeweis zur jüngsten
/// Epoche. Beweis-Bytes sind bincode-serialisiertes akd-Material, Base64.
#[derive(Deserialize, Debug, Clone)]
pub struct InclusionProof {
    pub epoch: u64,
    pub root_hash: String,
    pub proof: String,
}

/// Antwort von `GET /kt/epoch/{n}`: eine signierte Wurzel (STH).
#[derive(Deserialize, Debug, Clone)]
pub struct SignedRoot {
    pub epoch: u64,
    pub root_hash: String,
    pub signature: String,
}

/// Ergebnis einer bestandenen Selbstprüfung: gegen welche Epoche geprüft
/// wurde und die wievielte Version des eigenen Eintrags dort steht.
#[derive(Debug, Clone, Copy)]
pub struct SelfCheck {
    pub epoch: u64,
    pub version: u64,
}

impl KtClient {
    /// Baut einen Client für die gegebene Basis-URL; ein abschließender
    /// Schrägstrich wird entfernt, wie bei den übrigen Dienst-Clients.
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            http: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `GET /kt/info`: Schlüssel und jüngste Epoche des Dienstes.
    pub async fn info(&self) -> Result<KtInfo, ClientError> {
        let response = self
            .http
            .get(self.url("/kt/info"))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /kt/proof/{handle}`: Inklusionsbeweis zur jüngsten Epoche.
    pub async fn proof(&self, handle: &str) -> Result<InclusionProof, ClientError> {
        let response = self
            .http
            .get(self.url(&format!("/kt/proof/{handle}")))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /kt/epoch/{n}`: die signierte Wurzel einer Epoche.
    pub async fn signed_root(&self, epoch: u64) -> Result<SignedRoot, ClientError> {
        let response = self
            .http
            .get(self.url(&format!("/kt/epoch/{epoch}")))
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// Die Selbstprüfung: steht im Verzeichnis exakt das Commitment, das
    /// sich aus dem eigenen Identitätsschlüssel und der eigenen
    /// Gerätemenge (`GET /devices` beim identity-Dienst) ergibt?
    ///
    /// `pinned_root_key` ist der gepinnte Wurzel-Signaturschlüssel
    /// (Base64) aus Konfiguration oder einem früheren Lauf; ohne ihn gilt
    /// Trust-on-first-use auf `GET /kt/info`. Jeder Fehlschlag der vier
    /// Prüfschritte kommt als `ClientError::KeyTransparency` zurück und
    /// ist als Alarm zu behandeln, nicht als Ausfall.
    pub async fn verify_self(
        &self,
        handle: &str,
        identity_key_b64: &str,
        devices: &[DeviceView],
        pinned_root_key: Option<&str>,
    ) -> Result<SelfCheck, ClientError> {
        let info = self.info().await?;
        let signing_key_b64 = match pinned_root_key {
            Some(pinned) if pinned != info.root_signing_key => {
                return Err(ClientError::KeyTransparency(
                    "Wurzel-Signaturschlüssel des Dienstes weicht vom gepinnten ab".to_string(),
                ));
            }
            Some(pinned) => pinned,
            None => &info.root_signing_key,
        };

        let proof = self.proof(handle).await?;
        let signed = self.signed_root(proof.epoch).await?;

        // Schritt 2 zuerst prüfbar: Beweis und signierte Wurzel müssen
        // dieselbe Wurzel meinen, sonst signiert die Signatur etwas anderes,
        // als der Beweis beweist.
        if signed.root_hash != proof.root_hash {
            return Err(ClientError::KeyTransparency(format!(
                "Wurzel des Beweises passt nicht zur signierten Epoche {}",
                proof.epoch
            )));
        }

        // Schritt 1: Ed25519-Signatur über die kanonische Wurzelnachricht.
        let verifying_key = decode_verifying_key(signing_key_b64)?;
        let root_hash = decode_b64(&signed.root_hash, "root_hash")?;
        let signature_bytes = decode_b64(&signed.signature, "signature")?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| ClientError::Decode(format!("Wurzelsignatur: {error}")))?;
        verifying_key
            .verify(&root_message(signed.epoch, &root_hash), &signature)
            .map_err(|_| {
                ClientError::KeyTransparency(format!(
                    "Wurzelsignatur der Epoche {} verifiziert nicht",
                    signed.epoch
                ))
            })?;

        // Schritt 3: der akd-Inklusionsbeweis gegen die signierte Wurzel.
        let vrf_public = decode_b64(&info.vrf_public_key, "vrf_public_key")?;
        let proof_bytes = decode_b64(&proof.proof, "proof")?;
        let lookup: akd::LookupProof = bincode::deserialize(&proof_bytes)
            .map_err(|error| ClientError::Decode(format!("Inklusionsbeweis: {error}")))?;
        let root_hash: [u8; 32] = root_hash
            .try_into()
            .map_err(|_| ClientError::Decode("Wurzel-Hash hat nicht 32 Byte".to_string()))?;
        let result = akd::client::lookup_verify::<KtConfiguration>(
            &vrf_public,
            root_hash,
            proof.epoch,
            akd::AkdLabel::from(handle),
            lookup,
        )
        .map_err(|error| {
            ClientError::KeyTransparency(format!("Inklusionsbeweis verifiziert nicht: {error}"))
        })?;

        // Schritt 4: der bewiesene Wert muss dem lokal nachgerechneten
        // Commitment entsprechen. Genau hier fällt der untergeschobene
        // Schlüssel oder das Rogue-Gerät auf.
        let commitment_devices: Vec<CommitmentDevice<'_>> = devices
            .iter()
            .map(|d| CommitmentDevice {
                id: &d.id,
                public_key: &d.public_key,
                not_after: d.not_after,
            })
            .collect();
        let expected = account_commitment(identity_key_b64, &commitment_devices);
        if result.value.0 != expected {
            return Err(ClientError::KeyTransparency(
                "Verzeichnis-Eintrag weicht von den eigenen veröffentlichten Schlüsseln ab \
                 (möglicher stiller Schlüssel- oder Gerätetausch)"
                    .to_string(),
            ));
        }

        Ok(SelfCheck {
            epoch: proof.epoch,
            version: result.version,
        })
    }
}

fn decode_b64(value: &str, field: &str) -> Result<Vec<u8>, ClientError> {
    BASE64
        .decode(value)
        .map_err(|error| ClientError::Decode(format!("{field}: {error}")))
}

fn decode_verifying_key(b64: &str) -> Result<VerifyingKey, ClientError> {
    let bytes: [u8; 32] = decode_b64(b64, "root_signing_key")?
        .try_into()
        .map_err(|_| ClientError::Decode("Wurzelschlüssel hat nicht 32 Byte".to_string()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| ClientError::Decode(format!("Wurzelschlüssel: {error}")))
}
