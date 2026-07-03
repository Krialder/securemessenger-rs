//! Headless-Referenzclient (`sm`): treibt die client-app-Bibliothek über die
//! Kommandozeile und macht den Protokollfluss sichtbar, bevor der Web-Client
//! dieselben Bausteine nutzt.
//!
//! Zwei lokale Dateien: das Profil (Handle, Konto-Seed, Geräte-ID, Tokens)
//! und die Zustands-Ablage (libsignal-Identität, Sitzungen, Prekeys,
//! Kontakte) hinter dem Storage-Trait aus client-app. Sitzungen überleben
//! damit Prozessgrenzen: `sm send` und `sm recv` setzen den Ratchet dort
//! fort, wo der letzte Aufruf endete.
//!
//! [ANNAHME: Beide Dateien sind unverschlüsseltes JSON, eine
//! Entwickler-Bequemlichkeit; wer sie hat, hat die Identität. Die
//! verschlüsselte Geräte-Ablage (Keystore) ist eine eigene Etappe.]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::delivery::{DeliveryClient, OutgoingEnvelope};
use client_app::directory::DirectoryClient;
use client_app::prekeys::{
    bundle_from_directory, device_id_from_u32, publication_from_bundle, PROTOCOL_DEVICE_ID,
};
use client_app::protocol_store::{has_own_identity, store_own_identity, PersistentProtocolStore};
use client_app::storage::{FileStorage, KeyValueStorage as _};
use client_app::{wire, IdentityClient, NewAccount};
use client_core::libsignal_protocol::ProtocolAddress;
use client_core::onetoone::Device;
use serde::{Deserialize, Serialize};

/// Standard-Adressen der Dienste im lokalen Betrieb (alle binden per
/// Default auf 8080; directory und delivery laufen lokal über BIND_ADDR
/// auf eigenen Ports, siehe ENTWICKLUNG.md).
const DEFAULT_IDENTITY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_DIRECTORY_URL: &str = "http://127.0.0.1:8081";
const DEFAULT_DELIVERY_URL: &str = "http://127.0.0.1:8082";
/// Gültigkeit des Geräte-Credentials: ein Jahr. Der Client wählt die Dauer
/// (specs/geraete-identitaet.md), der Server lehnt nur Abgelaufenes ab.
const CREDENTIAL_TTL_SECONDS: u64 = 60 * 60 * 24 * 365;
/// Storage-Schlüssel des Prekey-ID-Zählers (client-core `next_prekey_id`).
const COUNTER_KEY: &str = "counter/next_prekey_id";

/// Das lokal abgelegte Client-Profil. Der Konto-Seed ist der private
/// Wurzelschlüssel; wer diese Datei hat, hat das Konto.
#[derive(Serialize, Deserialize, Default)]
struct Profile {
    handle: String,
    /// Seed des Ed25519-Konto-Wurzelschlüssels (Base64).
    account_seed: String,
    /// Server-seitige Geräte-ID (UUID).
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// Ein bekannter Kontakt: die Geräte, an die zugestellt wird, samt der
/// Protokoll-Gerätenummer aus dem Bündel-Blob.
#[derive(Serialize, Deserialize, Clone)]
struct ContactDevice {
    server_device_id: String,
    protocol_device_id: u32,
}

type SharedStorage = Rc<RefCell<FileStorage>>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Fehler: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("help") {
        "register" => register(&args[1..]).await,
        "login" => login(&args[1..]).await,
        "logout" => logout().await,
        "whoami" => whoami(),
        "publish-keys" => publish_keys().await,
        "send" => send(&args[1..]).await,
        "recv" => recv().await,
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            Err(format!("unbekannter Befehl: {other}"))
        }
    }
}

/// `sm register <handle> <passwort>`: erzeugt Konto-Wurzelschlüssel und
/// libsignal-Geräte-Identität, registriert das Konto und legt Profil plus
/// Zustands-Ablage an.
async fn register(args: &[String]) -> Result<(), String> {
    let [handle, password] = args else {
        return Err("Aufruf: sm register <handle> <passwort>".to_string());
    };

    let account_key = IdentityKeypair::generate();
    // libsignal-Registration-IDs sind 14 Bit (1..16380).
    let registration_id = rand::Rng::random_range(&mut rand::rng(), 1u32..16380);
    let mut keygen = Device::new(handle, 1, registration_id).map_err(|e| e.to_string())?;
    let device_public = BASE64.encode(keygen.identity_public().await.map_err(|e| e.to_string())?);
    let identity_bytes = keygen
        .identity_keypair_bytes()
        .await
        .map_err(|e| e.to_string())?;
    let device_id = uuid::Uuid::new_v4().to_string();
    let not_after = now_unix() + CREDENTIAL_TTL_SECONDS;

    let client = IdentityClient::new(identity_url());
    let account = client
        .register(&NewAccount {
            handle: handle.as_str(),
            display_name: None,
            password: password.as_str(),
            account_key: &account_key,
            device_public_key: &device_public,
            device_id: &device_id,
            not_after,
        })
        .await
        .map_err(|error| error.to_string())?;

    // Erst nach erfolgreicher Registrierung lokal verankern.
    let storage = open_storage()?;
    store_own_identity(&storage, &identity_bytes, registration_id).map_err(|e| e.to_string())?;
    save_profile(&Profile {
        handle: account.handle.clone(),
        account_seed: BASE64.encode(account_key.to_seed()),
        device_id: account.device_id.clone(),
        access_token: None,
        refresh_token: None,
    })?;

    println!(
        "Registriert: {} (Gerät {})",
        account.handle, account.device_id
    );
    Ok(())
}

/// `sm login <passwort>`: meldet das Gerät aus dem Profil an und speichert
/// das Token-Paar. Das Passwort wird nie abgelegt.
async fn login(args: &[String]) -> Result<(), String> {
    let [password] = args else {
        return Err("Aufruf: sm login <passwort>".to_string());
    };
    let mut profile = load_profile()?;

    let client = IdentityClient::new(identity_url());
    let session = client
        .login(&profile.handle, password, &profile.device_id)
        .await
        .map_err(|error| error.to_string())?;

    profile.access_token = Some(session.access_token);
    profile.refresh_token = Some(session.refresh_token);
    save_profile(&profile)?;

    println!(
        "Angemeldet als {} (Token läuft in {}s ab)",
        profile.handle, session.expires_in
    );
    Ok(())
}

/// `sm logout`: meldet die aktive Session ab und verwirft die Tokens.
async fn logout() -> Result<(), String> {
    let mut profile = load_profile()?;
    let Some(access) = profile.access_token.clone() else {
        return Err("Kein aktives Token. Zuerst 'sm login'.".to_string());
    };

    IdentityClient::new(identity_url())
        .logout(&access)
        .await
        .map_err(|error| error.to_string())?;

    profile.access_token = None;
    profile.refresh_token = None;
    save_profile(&profile)?;

    println!("Abgemeldet.");
    Ok(())
}

/// `sm whoami`: zeigt Handle, Geräte-ID und Anmeldestatus des Profils.
fn whoami() -> Result<(), String> {
    let profile = load_profile()?;
    let state = if profile.access_token.is_some() {
        "angemeldet"
    } else {
        "abgemeldet"
    };
    println!("Handle: {}", profile.handle);
    println!("Gerät:  {}", profile.device_id);
    println!("Status: {state}");
    Ok(())
}

/// `sm publish-keys`: erzeugt einen frischen Prekey-Satz und veröffentlicht
/// ihn im Schlüssel-Verzeichnis. Ohne veröffentlichte Prekeys kann niemand
/// eine Sitzung zu diesem Gerät aufbauen.
async fn publish_keys() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, storage) = open_device(&profile)?;

    let bundle = device
        .publish_prekey_bundle()
        .await
        .map_err(|e| e.to_string())?;
    let publication = publication_from_bundle(&bundle).map_err(|e| e.to_string())?;
    let counts = DirectoryClient::new(directory_url())
        .publish(&token, &publication)
        .await
        .map_err(|e| e.to_string())?;
    save_counter(&storage, device.next_prekey_id())?;

    println!(
        "Prekeys veröffentlicht (Einmal-Vorrat: {} klassisch, {} PQ)",
        counts.one_time, counts.pq_one_time
    );
    Ok(())
}

/// `sm send <handle> <text>`: baut bei Bedarf die Sitzung auf (Bündel-Abruf,
/// PQXDH) und stellt die Ende-zu-Ende verschlüsselte Nachricht über die
/// Zustellung an alle Geräte des Kontakts zu.
async fn send(args: &[String]) -> Result<(), String> {
    let [recipient, text] = args else {
        return Err("Aufruf: sm send <handle> <text>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, storage) = open_device(&profile)?;

    // Kontakt auflösen: bekannt aus der Ablage, sonst Bündel holen und
    // Sitzungen aufbauen (konsumiert Einmal-Prekeys des Gegenübers).
    let contact_key = format!("contact/{recipient}");
    let devices: Vec<ContactDevice> = match storage
        .borrow()
        .get(&contact_key)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("Kontakt unlesbar: {e}"))?
        }
        None => Vec::new(),
    };
    let devices = if devices.is_empty() {
        let bundles = DirectoryClient::new(directory_url())
            .bundles(&token, recipient)
            .await
            .map_err(|e| e.to_string())?;
        if bundles.devices.is_empty() {
            return Err(format!("'{recipient}' hat keine gültigen Geräte"));
        }
        let mut contact = Vec::with_capacity(bundles.devices.len());
        for bundle_json in &bundles.devices {
            let (bundle, protocol_device_id) =
                bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
            let address = ProtocolAddress::new(
                recipient.to_string(),
                device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
            );
            device
                .establish_session(&address, &bundle)
                .await
                .map_err(|e| format!("Sitzungsaufbau: {e}"))?;
            contact.push(ContactDevice {
                server_device_id: bundle_json.device_id.clone(),
                protocol_device_id,
            });
        }
        let json = serde_json::to_vec(&contact).map_err(|e| e.to_string())?;
        storage
            .borrow_mut()
            .put(&contact_key, &json)
            .map_err(|e| e.to_string())?;
        contact
    } else {
        devices
    };

    let mut envelopes = Vec::with_capacity(devices.len());
    for target in &devices {
        let address = ProtocolAddress::new(
            recipient.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let message = device
            .encrypt(&address, text.as_bytes())
            .await
            .map_err(|e| format!("Verschlüsselung: {e}"))?;
        let envelope =
            wire::seal(&profile.handle, PROTOCOL_DEVICE_ID, &message).map_err(|e| e.to_string())?;
        envelopes.push(OutgoingEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: recipient.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
        });
    }

    let outcome = DeliveryClient::new(delivery_url())
        .submit(&token, &envelopes)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "Zugestellt an {} Gerät(e) ({} angenommen, {} Duplikate)",
        devices.len(),
        outcome.accepted,
        outcome.duplicates
    );
    Ok(())
}

/// `sm recv`: holt wartende Hüllen ab, entschlüsselt sie und bestätigt sie
/// (erst das Ack räumt sie serverseitig weg).
async fn recv() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, _storage) = open_device(&profile)?;

    let delivery = DeliveryClient::new(delivery_url());
    let waiting = delivery.fetch(&token).await.map_err(|e| e.to_string())?;
    if waiting.is_empty() {
        println!("Keine neuen Nachrichten.");
        return Ok(());
    }

    let mut acked = Vec::with_capacity(waiting.len());
    for message in &waiting {
        let opened = match wire::open(&message.envelope) {
            Ok(opened) => opened,
            Err(error) => {
                // Unlesbare Hülle: melden, aber nicht bestätigen, damit sie
                // für eine spätere Client-Version erhalten bleibt.
                eprintln!("Hülle {} übersprungen: {error}", message.id);
                continue;
            }
        };
        let address = ProtocolAddress::new(
            opened.from.clone(),
            device_id_from_u32(opened.from_device).map_err(|e| e.to_string())?,
        );
        match device.decrypt(&address, &opened.message).await {
            Ok(plaintext) => {
                println!("[{}] {}", opened.from, String::from_utf8_lossy(&plaintext));
                acked.push(message.id.clone());
            }
            Err(error) => {
                eprintln!("Hülle {} nicht entschlüsselbar: {error}", message.id);
                // Auch nicht entschlüsselbare Hüllen bestätigen: ein
                // erneuter Abruf würde am selben Fehler scheitern (Ratchet
                // kennt den Schlüssel nicht mehr), die Hülle bliebe für
                // immer liegen.
                acked.push(message.id.clone());
            }
        }
    }
    if !acked.is_empty() {
        delivery
            .ack(&token, &acked)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn print_usage() {
    eprintln!(
        "sm - SecureMessenger Referenzclient\n\
         \n\
         Befehle:\n\
         \x20 register <handle> <passwort>   Konto und erstes Gerät anlegen\n\
         \x20 login <passwort>               Gerät anmelden, Token speichern\n\
         \x20 logout                         Session abmelden\n\
         \x20 whoami                         Profil anzeigen\n\
         \x20 publish-keys                   Prekey-Satz im Verzeichnis veröffentlichen\n\
         \x20 send <handle> <text>           E2EE-Nachricht senden (baut Sitzung bei Bedarf auf)\n\
         \x20 recv                           wartende Nachrichten abholen und entschlüsseln\n\
         \x20 help                           diese Hilfe\n\
         \n\
         Umgebung:\n\
         \x20 SM_IDENTITY_URL    identity-Dienst (Vorgabe {DEFAULT_IDENTITY_URL})\n\
         \x20 SM_DIRECTORY_URL   directory-Dienst (Vorgabe {DEFAULT_DIRECTORY_URL})\n\
         \x20 SM_DELIVERY_URL    delivery-Dienst (Vorgabe {DEFAULT_DELIVERY_URL})\n\
         \x20 SM_PROFILE         Profildatei (Vorgabe sm-profile.json)\n\
         \x20 SM_STATE           Zustands-Ablage (Vorgabe sm-state.json)"
    );
}

fn identity_url() -> String {
    std::env::var("SM_IDENTITY_URL").unwrap_or_else(|_| DEFAULT_IDENTITY_URL.to_string())
}

fn directory_url() -> String {
    std::env::var("SM_DIRECTORY_URL").unwrap_or_else(|_| DEFAULT_DIRECTORY_URL.to_string())
}

fn delivery_url() -> String {
    std::env::var("SM_DELIVERY_URL").unwrap_or_else(|_| DEFAULT_DELIVERY_URL.to_string())
}

fn profile_path() -> String {
    std::env::var("SM_PROFILE").unwrap_or_else(|_| "sm-profile.json".to_string())
}

fn state_path() -> String {
    std::env::var("SM_STATE").unwrap_or_else(|_| "sm-state.json".to_string())
}

fn load_profile() -> Result<Profile, String> {
    let path = profile_path();
    let data = std::fs::read(&path)
        .map_err(|_| format!("Kein Profil unter {path}. Zuerst 'sm register' ausführen."))?;
    serde_json::from_slice(&data).map_err(|error| format!("Profil unlesbar: {error}"))
}

fn save_profile(profile: &Profile) -> Result<(), String> {
    let path = profile_path();
    let data = serde_json::to_vec_pretty(profile).map_err(|error| error.to_string())?;
    std::fs::write(&path, data).map_err(|error| format!("Profil nicht schreibbar: {error}"))
}

fn access_token(profile: &Profile) -> Result<String, String> {
    profile
        .access_token
        .clone()
        .ok_or_else(|| "Kein aktives Token. Zuerst 'sm login'.".to_string())
}

fn open_storage() -> Result<SharedStorage, String> {
    Ok(Rc::new(RefCell::new(FileStorage::open(state_path())?)))
}

/// Öffnet die Zustands-Ablage und baut das Gerät darüber; der
/// Prekey-Zähler kommt aus der Ablage, damit IDs nie doppelt vergeben
/// werden.
fn open_device(
    profile: &Profile,
) -> Result<(Device<PersistentProtocolStore<FileStorage>>, SharedStorage), String> {
    let storage = open_storage()?;
    if !has_own_identity(&storage).map_err(|e| e.to_string())? {
        return Err(format!(
            "Keine Geräte-Identität unter {}. Zuerst 'sm register'.",
            state_path()
        ));
    }
    let next_prekey_id = match storage
        .borrow()
        .get(COUNTER_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => u32::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| "Prekey-Zähler hat die falsche Länge".to_string())?,
        ),
        None => 1,
    };
    let device = Device::with_store(
        &profile.handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        next_prekey_id,
    )
    .map_err(|e| e.to_string())?;
    Ok((device, storage))
}

fn save_counter(storage: &SharedStorage, next_prekey_id: u32) -> Result<(), String> {
    storage
        .borrow_mut()
        .put(COUNTER_KEY, &next_prekey_id.to_be_bytes())
        .map_err(|e| e.to_string())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Systemzeit nach 1970")
        .as_secs()
}
