//! Client des Identitäts-Dienstes (services/identity).
//!
//! Deckt den Konto-Layer ab: Registrierung (Konto plus erstes Gerät), Login
//! mit Gerätebindung, Rotation des Token-Paars und Logout. Die Request- und
//! Response-Formen spiegeln services/identity/src/api.rs; Feldnamen und
//! Status-Codes folgen dokumentation/schnittstellen.md.

use serde::{Deserialize, Serialize};

use crate::account::{build_device_credential, IdentityKeypair};
use crate::error::ClientError;
use crate::http::{expect_success, parse_json, transport};

/// Client des Identitäts-Dienstes. Hält die Basis-URL und einen
/// wiederverwendbaren HTTP-Client (Verbindungspool, ein DNS-/TLS-Aufbau).
#[derive(Clone)]
pub struct IdentityClient {
    base_url: String,
    http: reqwest::Client,
}

/// Alles, was eine Registrierung braucht. Den öffentlichen Kontoschlüssel
/// und das Geräte-Credential leitet `register` ab; der private
/// Wurzelschlüssel bleibt beim Aufrufer.
pub struct NewAccount<'a> {
    pub handle: &'a str,
    pub display_name: Option<&'a str>,
    pub password: &'a str,
    /// Konto-Wurzelschlüssel (Ed25519); signiert das Geräte-Credential.
    pub account_key: &'a IdentityKeypair,
    /// Öffentlicher Schlüssel des ersten Geräts als Base64. Nach ADR-0009
    /// ist das die serialisierte libsignal-Identität des Geräts
    /// (`client_core::onetoone::Device::identity_public`); der Server
    /// behandelt sie als opake Bytes.
    pub device_public_key: &'a str,
    /// Client-erzeugte Geräte-ID, kanonische UUID.
    pub device_id: &'a str,
    /// Ablauf des Credentials in Unix-Sekunden; der Client wählt die Dauer.
    pub not_after: u64,
}

/// Bestätigtes Konto nach der Registrierung (Antwort von `POST /accounts`).
#[derive(Deserialize, Debug, Clone)]
pub struct Account {
    pub handle: String,
    pub display_name: String,
    pub device_id: String,
    /// Die vom Server vergebene libsignal-Gerätenummer des ersten Geräts
    /// (immer 1). Der Client übernimmt sie als seinen ProtocolAddress-Teil.
    /// `default` für den Fall eines älteren Servers ohne das Feld: dann ist
    /// die alte Konstante 1 die richtige Annahme.
    #[serde(default = "device_id_one")]
    pub protocol_device_id: u16,
}

fn device_id_one() -> u16 {
    1
}

/// Ein Gerät der eigenen Gerätemenge (Antwort von `GET /devices`).
/// Trägt alle Zutaten des KT-Commitments (id, public_key, not_after),
/// damit die Selbstprüfung es direkt nachrechnen kann.
#[derive(Deserialize, Debug, Clone)]
pub struct DeviceView {
    pub id: String,
    pub name: Option<String>,
    pub public_key: String,
    pub not_after: u64,
    /// Die libsignal-Gerätenummer; `default` 0, falls ein älterer Server
    /// sie nicht mitführt (dann ist die Nummer aus der Menge nicht bekannt).
    #[serde(default)]
    pub protocol_device_id: u16,
}

/// Was eine Geräte-Freischaltung braucht (Parameter von `add_device`). Der
/// Konto-Wurzelschlüssel signiert das Credential des neuen Geräts; der
/// Server prüft die Signatur gegen den Konto-Identitätsschlüssel.
pub struct DeviceEnrollment<'a> {
    pub account_key: &'a IdentityKeypair,
    pub handle: &'a str,
    /// Öffentlicher Schlüssel des neuen Geräts (libsignal-Identität, Base64).
    pub device_public_key: &'a str,
    /// Client-erzeugte Geräte-ID, kanonische UUID.
    pub device_id: &'a str,
    pub name: Option<&'a str>,
    pub not_after: u64,
}

/// Ergebnis einer Freischaltung (Antwort von `POST /devices`): die
/// bestätigte Geräte-ID und die vom Server vergebene Protokollnummer, die
/// das neue Gerät als seinen ProtocolAddress-Teil übernimmt.
#[derive(Deserialize, Debug, Clone)]
pub struct AddDeviceOutcome {
    pub device_id: String,
    pub protocol_device_id: u16,
}

/// Ein Token-Paar mit Laufzeit (Antwort von Login und Refresh). Feldnamen nach
/// OAuth-2.0-Konvention, wie der Dienst sie liefert.
#[derive(Deserialize, Debug, Clone)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Sekunden bis zum Ablauf des Access-Tokens.
    pub expires_in: u64,
    /// Bei einer vorgemerkten Konto-Löschung der Ablauf der Widerrufsfrist
    /// (Unix-Sekunden); `None` bei einem aktiven Konto. Der Client zeigt
    /// damit direkt nach dem Login, dass eine Löschung läuft.
    #[serde(default)]
    pub deletion_pending_until: Option<u64>,
    /// Anzeigename des Kontos (F010); `None` auf dem Refresh-Pfad und bei
    /// älteren Diensten, der Client behält dann seinen letzten Stand.
    #[serde(default)]
    pub display_name: Option<String>,
}

impl IdentityClient {
    /// Baut einen Client für die gegebene Basis-URL (z. B.
    /// `http://127.0.0.1:8080`). Ein abschließender Schrägstrich wird
    /// entfernt, damit die Pfadanhänge sauber zusammensetzen.
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

    /// `GET /pow`: die geforderte Proof-of-Work-Schwierigkeit (führende
    /// Nullbits) der Registrierung; 0 heißt: keine Bremse.
    pub async fn pow_difficulty(&self) -> Result<u32, ClientError> {
        let response = self
            .http
            .get(self.url("/pow"))
            .send()
            .await
            .map_err(transport)?;
        let info: PowInfo = parse_json(response).await?;
        Ok(info.difficulty)
    }

    /// `GET /sealed-sender`: der öffentliche Trust Root der
    /// Sealed-Sender-Zertifikatskette (33 Bytes), `None` wenn der Dienst
    /// keine Zertifikate ausstellt (Route existiert dann nicht). Wer dem
    /// Server diesen Anker nicht abnehmen will, verankert ihn lokal; das
    /// ist dasselbe Bootstrapping-Problem wie beim KT-Signaturschlüssel.
    pub async fn sealed_sender_trust_root(&self) -> Result<Option<Vec<u8>>, ClientError> {
        let response = self
            .http
            .get(self.url("/sealed-sender"))
            .send()
            .await
            .map_err(transport)?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let info: SealedSenderInfo = parse_json(response).await?;
        use base64::Engine as _;
        let trust_root = base64::engine::general_purpose::STANDARD
            .decode(&info.trust_root)
            .map_err(|_| ClientError::Protocol("Trust Root ist kein Base64".to_string()))?;
        Ok(Some(trust_root))
    }

    /// `GET /sender-certificate`: ein kurzlebiges Absender-Zertifikat für
    /// das eigene Gerät (Bearer). Die Bytes gehen unverändert an
    /// `Device::seal_message`; `expires_at_millis` sagt dem Client, wann
    /// er neu holen muss.
    pub async fn sender_certificate(
        &self,
        access_token: &str,
        protocol_device_id: u32,
    ) -> Result<SenderCertificate, ClientError> {
        let response = self
            .http
            .get(self.url(&format!("/sender-certificate?device={protocol_device_id}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        let raw: SenderCertificateJson = parse_json(response).await?;
        use base64::Engine as _;
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(&raw.certificate)
            .map_err(|_| ClientError::Protocol("Zertifikat ist kein Base64".to_string()))?;
        Ok(SenderCertificate {
            certificate,
            expires_at_millis: raw.expires_at_millis,
        })
    }

    /// `POST /accounts`: legt Konto und erstes Gerät an. Erzeugt die
    /// öffentlichen Schlüssel und das signierte Geräte-Credential aus den
    /// übergebenen Schlüsselpaaren. Verlangt der Dienst einen Proof-of-Work
    /// (Sybil-Bremse), löst der Client ihn vorher selbst.
    pub async fn register(&self, account: &NewAccount<'_>) -> Result<Account, ClientError> {
        let identity_key = account.account_key.public_b64();
        let device_public = account.device_public_key.to_string();
        let credential = build_device_credential(
            account.account_key,
            account.handle,
            account.device_id,
            &device_public,
            account.not_after,
        );
        // Nur bei aktiver Bremse rechnen; solve blockiert kurz und läuft
        // deshalb auf einem Blocking-Thread, damit die async-Worker frei
        // bleiben. Auf wasm gibt es kein spawn_blocking, dort direkt
        // (die Schwierigkeit ist im Referenzbetrieb klein).
        let difficulty = self.pow_difficulty().await?;
        let pow_nonce = if difficulty > 0 {
            Some(solve_pow(account.handle, difficulty).await?)
        } else {
            None
        };
        let body = RegisterRequest {
            handle: account.handle,
            display_name: account.display_name,
            password: account.password,
            identity_key: &identity_key,
            device: DeviceRequest {
                id: account.device_id,
                name: None,
                public_key: &device_public,
                not_after: account.not_after,
                credential: &credential,
            },
            pow_nonce,
        };
        let response = self
            .http
            .post(self.url("/accounts"))
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /sessions`: meldet ein registriertes Gerät an und liefert ein
    /// frisches Token-Paar.
    pub async fn login(
        &self,
        handle: &str,
        password: &str,
        device_id: &str,
    ) -> Result<Session, ClientError> {
        let body = LoginRequest {
            handle,
            password,
            device_id,
        };
        let response = self
            .http
            .post(self.url("/sessions"))
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /sessions/refresh`: rotiert das Token-Paar. Ein erneut
    /// vorgelegtes, bereits rotiertes Refresh-Token widerruft serverseitig die
    /// ganze Familie und kommt hier als `401` zurück.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session, ClientError> {
        let body = RefreshRequest { refresh_token };
        let response = self
            .http
            .post(self.url("/sessions/refresh"))
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `GET /devices`: die gültige Gerätemenge des eigenen Kontos.
    /// Revozierte Geräte fehlen; genau diese Menge geht ins
    /// KT-Commitment ein (Selbstprüfung, `crate::kt`).
    pub async fn devices(&self, access_token: &str) -> Result<Vec<DeviceView>, ClientError> {
        let response = self
            .http
            .get(self.url("/devices"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `POST /devices`: schaltet ein weiteres Gerät fürs eigene Konto frei.
    /// Der Aufrufer ist ein bereits angemeldetes Gerät (Bearer); das
    /// Credential des neuen Geräts signiert der Konto-Wurzelschlüssel
    /// clientseitig, der Server prüft es gegen den Konto-Identitätsschlüssel
    /// (geraete-identitaet.md). Liefert die vom Server vergebene
    /// Protokollnummer, die das neue Gerät als seine libsignal-Gerätenummer
    /// übernimmt.
    pub async fn add_device(
        &self,
        access_token: &str,
        enroll: &DeviceEnrollment<'_>,
    ) -> Result<AddDeviceOutcome, ClientError> {
        let credential = build_device_credential(
            enroll.account_key,
            enroll.handle,
            enroll.device_id,
            enroll.device_public_key,
            enroll.not_after,
        );
        let body = DeviceRequest {
            id: enroll.device_id,
            name: enroll.name,
            public_key: enroll.device_public_key,
            not_after: enroll.not_after,
            credential: &credential,
        };
        let response = self
            .http
            .post(self.url("/devices"))
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        parse_json(response).await
    }

    /// `DELETE /devices/{id}`: nimmt ein Gerät aus der gültigen Menge
    /// (Revocation). Ein Gerät kann sich nicht selbst entfernen (der Server
    /// antwortet dann `409`), damit man sich nicht aussperrt.
    pub async fn remove_device(
        &self,
        access_token: &str,
        device_id: &str,
    ) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(self.url(&format!("/devices/{device_id}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `POST /sessions/password`: ändert das Konto-Passwort. Bearer, plus das
    /// alte Passwort zur Bestätigung. Nach Erfolg sind die Sessions aller
    /// anderen Geräte widerrufen; der Aufrufer muss seine lokale, unter dem
    /// Passwort verschlüsselte Ablage neu versiegeln (das liegt beim Client,
    /// nicht beim Dienst). `401` (`invalid_credentials`) heißt: altes
    /// Passwort falsch.
    pub async fn change_password(
        &self,
        access_token: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        let body = PasswordChangeBody {
            current_password,
            new_password,
        };
        let response = self
            .http
            .post(self.url("/sessions/password"))
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `DELETE /accounts`: merkt die Löschung des eigenen Kontos vor (NF030,
    /// Widerrufsfrist). Bearer plus Passwort zur Bestätigung. Liefert den
    /// Ablauf der Frist (Unix-Sekunden); bis dahin ist die Löschung mit
    /// `undelete_account` widerrufbar. `401` heißt: Passwort falsch.
    pub async fn delete_account(
        &self,
        access_token: &str,
        password: &str,
    ) -> Result<u64, ClientError> {
        let response = self
            .http
            .delete(self.url("/accounts"))
            .bearer_auth(access_token)
            .json(&DeleteAccountBody { password })
            .send()
            .await
            .map_err(transport)?;
        let scheduled: DeletionScheduled = parse_json(response).await?;
        Ok(scheduled.deletion_pending_until)
    }

    /// `POST /accounts/undelete`: widerruft eine vorgemerkte Löschung
    /// innerhalb der Frist (Bearer, kein Passwort nötig).
    pub async fn undelete_account(&self, access_token: &str) -> Result<(), ClientError> {
        let response = self
            .http
            .post(self.url("/accounts/undelete"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `PATCH /accounts`: ändert den Anzeigenamen (F010, getrennt vom
    /// Handle, jederzeit änderbar; Bearer genügt). Liefert den vom Server
    /// gespeicherten (getrimmten) Namen zurück, damit der Aufrufer die
    /// kanonische Form übernimmt.
    pub async fn set_display_name(
        &self,
        access_token: &str,
        display_name: &str,
    ) -> Result<String, ClientError> {
        let response = self
            .http
            .patch(self.url("/accounts"))
            .bearer_auth(access_token)
            .json(&DisplayNameBody { display_name })
            .send()
            .await
            .map_err(transport)?;
        let renamed: DisplayNamed = parse_json(response).await?;
        Ok(renamed.display_name)
    }

    /// `POST /provision`: legt einen verschlüsselten Kopplungs-Antrag unter
    /// seiner Kanal-ID im Relay ab (QR-Kopplung). Tokenlos, weil das neue
    /// Gerät noch nicht registriert ist und der Inhalt für den Dienst opak
    /// bleibt. `409` (Kanal belegt) kommt als `ClientError::Api` zurück.
    pub async fn provision_put(
        &self,
        channel: &str,
        nonce: &str,
        ciphertext: &str,
    ) -> Result<(), ClientError> {
        let body = ProvisionPutBody {
            channel,
            nonce,
            ciphertext,
        };
        let response = self
            .http
            .post(self.url("/provision"))
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }

    /// `GET /provision/{channel}`: holt den abgelegten Antrag (Nonce,
    /// Chiffretext). `Ok(None)` bei `404`, also wenn nichts abgelegt oder der
    /// Kanal verfallen ist; nur echte Fehler werden zum `ClientError`.
    pub async fn provision_get(
        &self,
        channel: &str,
    ) -> Result<Option<(String, String)>, ClientError> {
        let response = self
            .http
            .get(self.url(&format!("/provision/{channel}")))
            .send()
            .await
            .map_err(transport)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let fetched: ProvisionFetched = parse_json(response).await?;
        Ok(Some((fetched.nonce, fetched.ciphertext)))
    }

    /// `DELETE /sessions`: meldet ab und widerruft die ganze Session-Familie.
    /// Der Dienst antwortet immer `204`, auch bei unbekanntem Token, damit die
    /// Antwort nichts über dessen Gültigkeit verrät.
    pub async fn logout(&self, access_token: &str) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(self.url("/sessions"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;
        expect_success(response).await
    }
}

#[derive(Serialize)]
struct DeleteAccountBody<'a> {
    password: &'a str,
}

#[derive(Deserialize)]
struct DeletionScheduled {
    deletion_pending_until: u64,
}

#[derive(Serialize)]
struct DisplayNameBody<'a> {
    display_name: &'a str,
}

#[derive(Deserialize)]
struct DisplayNamed {
    display_name: String,
}

#[derive(Serialize)]
struct PasswordChangeBody<'a> {
    current_password: &'a str,
    new_password: &'a str,
}

#[derive(Serialize)]
struct ProvisionPutBody<'a> {
    channel: &'a str,
    nonce: &'a str,
    ciphertext: &'a str,
}

#[derive(Deserialize)]
struct ProvisionFetched {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct DeviceRequest<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    public_key: &'a str,
    not_after: u64,
    credential: &'a str,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    handle: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    password: &'a str,
    identity_key: &'a str,
    device: DeviceRequest<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_nonce: Option<u64>,
}

#[derive(Deserialize)]
struct PowInfo {
    difficulty: u32,
}

#[derive(Deserialize)]
struct SealedSenderInfo {
    trust_root: String,
}

#[derive(Deserialize)]
struct SenderCertificateJson {
    certificate: String,
    expires_at_millis: u64,
}

/// Ein Absender-Zertifikat samt Ablauf, wie es der Dienst ausstellt.
/// Die Bytes sind das serialisierte libsignal-`SenderCertificate`.
#[derive(Debug, Clone)]
pub struct SenderCertificate {
    pub certificate: Vec<u8>,
    pub expires_at_millis: u64,
}

/// Löst den Proof-of-Work fürs Registrieren. Läuft inline (die Bibliothek
/// setzt keine Laufzeit voraus); bei Referenz-Schwierigkeit ist die Suche
/// kurz. Auf teuren Schwierigkeiten würde ein Aufrufer sie auf einen
/// eigenen Thread legen. `async` bleibt der Einheitlichkeit halber.
async fn solve_pow(handle: &str, difficulty: u32) -> Result<u64, ClientError> {
    pow::solve(handle, difficulty)
        .ok_or_else(|| ClientError::Protocol("kein Proof-of-Work-nonce gefunden".to_string()))
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    handle: &'a str,
    password: &'a str,
    device_id: &'a str,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}
