//! Client des Schlüssel-Verzeichnisses (services/directory).
//!
//! `POST /keys/prekeys` veröffentlicht die eigenen Blobs (welches Gerät,
//! bestimmt das Bearer-Token), `GET /keys/{handle}` holt die Bündel aller
//! gültigen Geräte eines Kontos und konsumiert dabei Einmal-Prekeys. Die
//! Request- und Response-Formen spiegeln services/directory/src/api.rs.

use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::http::{parse_json, transport};
use crate::prekeys::{DeviceBundleJson, DirectoryPrekey, PrekeyPublication};

#[derive(Clone)]
pub struct DirectoryClient {
    base_url: String,
    http: reqwest::Client,
}

/// Restbestände der Einmal-Pools nach einem Upload beziehungsweise auf
/// Abfrage; der Client füllt nach, wenn sie unter 20 fallen
/// (datenmodell.md).
#[derive(Deserialize, Debug, Clone)]
pub struct PrekeyCounts {
    pub one_time: u64,
    pub pq_one_time: u64,
}

/// Antwort von `GET /keys/{handle}`: Konto-Identitätsschlüssel plus ein
/// Bündel je gültigem Gerät.
#[derive(Deserialize, Debug, Clone)]
pub struct AccountBundles {
    pub handle: String,
    /// Öffentlicher Konto-Wurzelschlüssel (Ed25519, Base64).
    pub identity_key: String,
    pub devices: Vec<DeviceBundleJson>,
}

/// Ein MLS-KeyPackage eines Geräts (Antwort von `GET /keys/{handle}/mls`).
/// Der `key_package`-Blob ist das serialisierte OpenMLS-KeyPackage,
/// opak für den Server.
#[derive(Deserialize, Debug, Clone)]
pub struct MlsKeyPackageEntry {
    pub device_id: String,
    pub key_package: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MlsKeyPackages {
    pub handle: String,
    pub devices: Vec<MlsKeyPackageEntry>,
}

#[derive(Serialize)]
struct UploadRequest<'a> {
    signed_prekey: &'a DirectoryPrekey,
    pq_signed_prekey: &'a DirectoryPrekey,
    one_time_prekeys: &'a [DirectoryPrekey],
}

#[derive(Serialize)]
struct MlsUploadRequest<'a> {
    mls_key_packages: &'a [DirectoryPrekey],
}

impl DirectoryClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// `POST /keys/prekeys`: veröffentlicht ein frisches Bündel (rotiert die
    /// signierten Prekeys, füllt die Einmal-Pools nach).
    pub async fn publish(
        &self,
        access_token: &str,
        publication: &PrekeyPublication,
    ) -> Result<PrekeyCounts, ClientError> {
        let body = UploadRequest {
            signed_prekey: &publication.signed_prekey,
            pq_signed_prekey: &publication.pq_signed_prekey,
            one_time_prekeys: &publication.one_time_prekeys,
        };
        let response = self
            .http
            .post(format!("{}/keys/prekeys", self.base_url))
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /keys/{handle}`: die Prekey-Bündel aller gültigen Geräte des
    /// Kontos. Konsumiert je Gerät einen Einmal-Prekey pro Typ.
    pub async fn bundles(
        &self,
        access_token: &str,
        handle: &str,
    ) -> Result<AccountBundles, ClientError> {
        let response = self
            .http
            .get(format!("{}/keys/{handle}", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /keys/prekeys` mit MLS-KeyPackages: füllt den KeyPackage-Pool
    /// des eigenen Geräts (Gruppen-Beitritte konsumieren je eins).
    pub async fn publish_mls_key_packages(
        &self,
        access_token: &str,
        packages: &[DirectoryPrekey],
    ) -> Result<(), ClientError> {
        let response = self
            .http
            .post(format!("{}/keys/prekeys", self.base_url))
            .bearer_auth(access_token)
            .json(&MlsUploadRequest {
                mls_key_packages: packages,
            })
            .send()
            .await
            .map_err(transport)?;
        crate::http::expect_success(response).await
    }

    /// `GET /keys/{handle}/mls`: je gültigem Gerät ein MLS-KeyPackage,
    /// konsumiert. Geräte ohne freies Paket fehlen in der Antwort.
    pub async fn mls_key_packages(
        &self,
        access_token: &str,
        handle: &str,
    ) -> Result<MlsKeyPackages, ClientError> {
        let response = self
            .http
            .get(format!("{}/keys/{handle}/mls", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }
}
