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
//! [ANNAHME: Ohne `SM_PASSPHRASE` liegen beide Dateien als Klartext-JSON
//! vor, eine Entwickler-Bequemlichkeit; wer sie hat, hat die Identität.
//! Mit gesetzter `SM_PASSPHRASE` verschlüsselt der keystore-Tresor beide
//! (Konto-Seed, Tokens, Sitzungen, Kontakte), und der blosse Besitz der
//! Dateien genügt nicht mehr. Die Passphrase kommt über die Umgebung wie
//! die übrigen Geheimnisse des Projekts; ein echter Desktop-Client nähme
//! den OS-Keyring, das ist die nächste Stufe.]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::{build_device_credential, build_rotation_cert, IdentityKeypair};
use client_app::delivery::{
    parse_ws_event, ws_auth_frame, DeliveryClient, GroupOutgoing, OutgoingEnvelope, WsEvent,
};
use client_app::directory::DirectoryClient;
use client_app::grouptext::{self, GroupPayload, RosterDevice};
use client_app::identity::{DeviceEnrollment, RotateDeviceCredential};
use client_app::prekeys::{
    bundle_from_directory, device_id_from_u32, new_uuid, publication_from_bundle, DirectoryPrekey,
};
use client_app::protocol_store::{has_own_identity, store_own_identity, PersistentProtocolStore};
use client_app::storage::{FileStorage, KeyValueStorage as _};
use client_app::{wire, IdentityClient, NewAccount};
use client_core::group::{GroupInbound, GroupMember, GroupSession};
use client_core::libsignal_protocol::ProtocolAddress;
use client_core::onetoone::Device;
use futures_util::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

/// Standard-Adressen der Dienste im lokalen Betrieb (alle binden per
/// Default auf 8080; directory und delivery laufen lokal über BIND_ADDR
/// auf eigenen Ports, siehe ENTWICKLUNG.md).
const DEFAULT_IDENTITY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_DIRECTORY_URL: &str = "http://127.0.0.1:8081";
const DEFAULT_DELIVERY_URL: &str = "http://127.0.0.1:8082";
const DEFAULT_KT_URL: &str = "http://127.0.0.1:8083";
/// Gültigkeit des Geräte-Credentials: ein Jahr. Der Client wählt die Dauer
/// (specs/geraete-identitaet.md), der Server lehnt nur Abgelaufenes ab.
const CREDENTIAL_TTL_SECONDS: u64 = 60 * 60 * 24 * 365;
/// Storage-Schlüssel des Prekey-ID-Zählers (client-core `next_prekey_id`).
const COUNTER_KEY: &str = "counter/next_prekey_id";
/// Storage-Schlüssel des persistenten MLS-Zustands (smmls.v1-Blob mit
/// Signierschlüssel, KeyPackage-Privatteilen und allen Gruppenzuständen;
/// EIN Mitglied je Gerät für alle Gruppen). Liegt wie alles andere hinter
/// dem keystore, wenn SM_PASSPHRASE gesetzt ist.
const MLS_STATE_KEY: &str = "mls/state";
/// Storage-Schlüssel der lokalen Gruppenliste (`sm groups`).
const GROUPS_INDEX_KEY: &str = "groups/index";
/// Storage-Schlüssel der Liste offener Einladungen (Gruppen-IDs, deren
/// Welcome vorgemerkt, aber noch nicht angenommen ist).
const INVITES_INDEX_KEY: &str = "invites/index";
/// Höchstzahl gleichzeitig offener Einladungen. Weil `is_welcome` nur das
/// Wire-Format prüft (nicht, dass der Welcome wirklich an uns adressiert
/// ist) und keinen KeyPackage-Verbrauch auslöst, könnte sonst jeder
/// Authentifizierte die Ablage mit beliebig vielen Welcome-Blobs fluten.
/// Ist der Deckel erreicht, werden neue Einladungen verworfen, bis der
/// Nutzer bestehende annimmt oder ablehnt.
const MAX_PENDING_INVITES: usize = 16;
/// Höchstzahl gepufferter Hüllen je offener Einladung (gegen das Fluten
/// der Ablage vor einer Ablehnung; der Roster kommt als erste Hülle).
const INVITE_BUFFER_MAX: usize = 32;
/// Zielbestand ungenutzter MLS-KeyPackages im Verzeichnis. Der Client
/// legt nur bis hierher nach (nicht bei jeder Anmeldung feste vier),
/// damit der Pool nicht wächst und der server-seitige Deckel
/// (`MAX_MLS_KEY_PACKAGES`) nie greift.
const MLS_KEY_PACKAGE_TARGET: u64 = 8;

/// Das lokal abgelegte Client-Profil. Der Konto-Seed ist der private
/// Wurzelschlüssel; wer diese Datei hat, hat das Konto.
#[derive(Serialize, Deserialize, Default)]
struct Profile {
    handle: String,
    /// Seed des Ed25519-Konto-Wurzelschlüssels (Base64). Leer auf einem
    /// gekoppelten Zweitgerät: das hält nur seine eigene Geräte-Identität,
    /// nicht den Konto-Wurzelschlüssel (der bleibt auf dem Erstgerät). Ein
    /// Zweitgerät kann darum senden und empfangen, aber keine weiteren
    /// Geräte freischalten und keine KT-Selbstprüfung fahren.
    #[serde(default)]
    account_seed: String,
    /// Seed eines noch nicht bestätigten neuen Wurzelschlüssels (Base64),
    /// während einer laufenden Rotation (ADR-0010). Er wird VOR dem
    /// Serveraufruf abgelegt und nach dem bestätigten Erfolg nach
    /// `account_seed` befördert und geleert. Bricht der Aufruf zwischen
    /// Server-Commit und lokalem Ablegen ab, hält das Gerät hier den neuen
    /// Schlüssel und kann die Rotation beim nächsten Lauf abschließen; ohne
    /// diese Ablage wäre der neue Schlüssel verloren und das Konto ausgesperrt.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pending_account_seed: String,
    /// Server-seitige Geräte-ID (UUID).
    device_id: String,
    /// Die vom Server vergebene libsignal-Gerätenummer (ProtocolAddress-Teil).
    /// Vorgabe 1 für Altprofile aus der Ein-Gerät-Zeit.
    #[serde(default = "one_u16")]
    protocol_device_id: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

fn one_u16() -> u16 {
    1
}

/// Der offene Kopplungs-Antrag, den ein Zweitgerät ausgibt und ein Erstgerät
/// freischaltet: die Geräte-ID und der öffentliche Geräteschlüssel des neuen
/// Geräts. Als eine Base64-Zeile kodiert, damit sie sich wie ein QR-Code in
/// einem Stück übertragen lässt (der QR-/Relay-Kanal automatisiert genau
/// diese Übergabe später).
#[derive(Serialize, Deserialize)]
struct LinkRequest {
    device_id: String,
    device_public_key: String,
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
        "passwd" => passwd(&args[1..]).await,
        "whoami" => whoami(),
        "link" => link(&args[1..]).await,
        "approve" => approve(&args[1..]).await,
        "link-finish" => link_finish(&args[1..]).await,
        "devices" => devices().await,
        "unlink" => unlink(&args[1..]).await,
        "delete-account" => delete_account(&args[1..]).await,
        "undelete" => undelete().await,
        "rename" => rename(&args[1..]).await,
        "rotate-key" => rotate_key().await,
        "publish-keys" => publish_keys().await,
        "group-create" => group_create(&args[1..]).await,
        "groups" => groups_list(),
        "group-send" => group_send(&args[1..]).await,
        "group-remove" => group_remove(&args[1..]).await,
        "group-leave" => group_leave(&args[1..]).await,
        "invites" => invites_list(),
        "group-accept" => group_accept(&args[1..]).await,
        "group-decline" => group_decline(&args[1..]),
        "send" => send(&args[1..]).await,
        "recv" => recv().await,
        "listen" => listen(&args[1..]).await,
        "verify" => verify().await,
        "audit" => audit(&args[1..]).await,
        "keycheck" => keycheck(&args[1..]).await,
        "report" => report(&args[1..]).await,
        "block" => block(&args[1..]).await,
        "unblock" => unblock(&args[1..]).await,
        "blocks" => blocks().await,
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
        pending_account_seed: String::new(),
        device_id: account.device_id.clone(),
        // Das erste Gerät ist Nummer 1 (der Server bestätigt es).
        protocol_device_id: account.protocol_device_id,
        access_token: None,
        refresh_token: None,
    })?;

    println!(
        "Registriert: {} (Gerät {}, Nummer {})",
        account.handle, account.device_id, account.protocol_device_id
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

    // Den Self-Sync-Cache der eigenen Geräte leeren: ein seit der letzten
    // Anmeldung neu gekoppeltes Gerät wird so beim nächsten Senden
    // aufgelöst (sonst bekäme es keine Kopien). Best effort.
    if let Ok(storage) = open_storage() {
        let _ = storage.borrow_mut().remove("sync/own_devices");
    }

    println!(
        "Angemeldet als {} (Token läuft in {}s ab)",
        profile.handle, session.expires_in
    );
    Ok(())
}

/// `sm passwd <altes> <neues>`: ändert das Konto-Passwort. Der Dienst prüft
/// das alte Passwort und meldet danach alle ANDEREN Geräte ab; dieses Gerät
/// behält seine Session. Anders als der Web-Client verschlüsselt das CLI die
/// lokale Ablage nicht unter dem Konto-Passwort, sondern unter der separaten
/// SM_PASSPHRASE, deshalb ist hier keine Neuversiegelung nötig.
async fn passwd(args: &[String]) -> Result<(), String> {
    let [current, new] = args else {
        return Err("Aufruf: sm passwd <altes-passwort> <neues-passwort>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    IdentityClient::new(identity_url())
        .change_password(&token, current, new)
        .await
        .map_err(|e| e.to_string())?;
    println!("Passwort geändert. Andere Geräte sind abgemeldet.");
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
    let directory = DirectoryClient::new(directory_url());
    let counts = directory
        .publish(&token, &publication)
        .await
        .map_err(|e| e.to_string())?;
    save_counter(&storage, device.next_prekey_id())?;

    // Dazu MLS-KeyPackages, damit andere dieses Konto in Gruppen einladen
    // können (das Verzeichnis konsumiert je Einladung eines). Nur bis zum
    // Zielbestand nachlegen (der Restbestand steht in der Upload-Antwort):
    // so wächst der Pool nicht bei jeder Anmeldung, und der server-seitige
    // Deckel wird nie erreicht. Die Privatteile wandern erst gesichert in
    // den persistenten MLS-Zustand, dann wird veröffentlicht (sonst wäre
    // ein Welcome auf ein KeyPackage möglich, dessen Privatteil fehlt).
    let published_mls = if counts.mls_key_package < MLS_KEY_PACKAGE_TARGET {
        let member = load_or_new_member(&storage, &profile.handle)?;
        let needed = (MLS_KEY_PACKAGE_TARGET - counts.mls_key_package) as usize;
        let mut packages = Vec::with_capacity(needed);
        for _ in 0..needed {
            packages.push(DirectoryPrekey {
                id: new_uuid(),
                key: BASE64.encode(member.key_package_blob()?),
            });
        }
        save_member_state(&storage, &member.export_state()?)?;
        directory
            .publish_mls_key_packages(&token, &packages)
            .await
            .map_err(|e| e.to_string())?;
        packages.len()
    } else {
        0
    };

    println!(
        "Prekeys veröffentlicht (Einmal-Vorrat: {} klassisch, {} PQ; {} MLS-KeyPackages nachgelegt)",
        counts.one_time, counts.pq_one_time, published_mls
    );
    Ok(())
}

/// `sm send <handle> <text> [--ttl <sekunden>] [--sealed]`: baut bei Bedarf
/// die Sitzung auf (Bündel-Abruf, PQXDH) und stellt die Ende-zu-Ende
/// verschlüsselte Nachricht über die Zustellung an alle Geräte des Kontakts
/// zu. Mit `--ttl` verschwindet eine unabgeholte Hülle nach der Frist
/// (Disappearing Messages); mit `--sealed` geht sie als Sealed-Sender-Hülle
/// ohne Absender-Klartext und ohne Token an die Zustellung.
async fn send(args: &[String]) -> Result<(), String> {
    let usage = "Aufruf: sm send <handle> <text> [--ttl <sekunden>] [--sealed]";
    let [recipient, text, flags @ ..] = args else {
        return Err(usage.to_string());
    };
    let mut ttl: Option<u64> = None;
    let mut sealed = false;
    let mut rest = flags.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--ttl" => {
                let seconds = rest.next().ok_or("--ttl braucht eine Zahl in Sekunden")?;
                ttl = Some(
                    seconds
                        .parse()
                        .map_err(|_| "--ttl braucht eine Zahl in Sekunden".to_string())?,
                );
            }
            "--sealed" => sealed = true,
            other => return Err(format!("unbekanntes Argument: {other}\n{usage}")),
        }
    }
    let expires_at = ttl.map(|seconds| now_unix() + seconds);
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

    // Einmal je Nachricht franken: derselbe Franking-Schlüssel und dasselbe
    // Commitment für alle Zielgeräte, damit der Empfänger jede Kopie melden
    // kann (specs/sealed-sender-und-abuse.md). Der Schlüssel reist im
    // verschlüsselten Payload, das Commitment als Franking-Tag. Das gilt
    // auch versiegelt: das Tag identifiziert niemanden.
    let franked = client_app::franking::frank(text.as_bytes());
    let franking_tag = BASE64.encode(&franked.commitment);
    // Für --sealed einmal das Absender-Zertifikat besorgen (gecacht).
    let certificate = if sealed {
        Some(
            sender_certificate_cached(&token, u32::from(profile.protocol_device_id), &storage)
                .await?,
        )
    } else {
        None
    };
    let mut envelopes = Vec::with_capacity(devices.len());
    for target in &devices {
        let address = ProtocolAddress::new(
            recipient.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let envelope = match &certificate {
            // Versiegelt: der Absender steht nur mitverschlüsselt in der
            // Hülle (Zertifikat), das Framing trägt kein from-Feld.
            Some(certificate) => {
                let blob = device
                    .seal_message(&address, certificate, &franked.payload)
                    .await
                    .map_err(|e| format!("Versiegeln: {e}"))?;
                wire::seal_sealed(&blob).map_err(|e| e.to_string())?
            }
            None => {
                let message = device
                    .encrypt(&address, &franked.payload)
                    .await
                    .map_err(|e| format!("Verschlüsselung: {e}"))?;
                wire::seal(
                    &profile.handle,
                    u32::from(profile.protocol_device_id),
                    &message,
                )
                .map_err(|e| e.to_string())?
            }
        };
        envelopes.push(OutgoingEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: recipient.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
            franking_tag: Some(franking_tag.clone()),
            expires_at,
        });
    }

    // Self-Sync: dieselbe Nachricht als Kopie an die eigenen Zweitgeräte,
    // damit der gesendete Text auch dort im Verlauf steht. Best effort:
    // scheitert das, ist die Nachricht beim Empfänger trotzdem raus.
    match build_sync_envelopes(
        &mut device,
        &storage,
        &token,
        &profile.handle,
        u32::from(profile.protocol_device_id),
        certificate.as_deref(),
        recipient,
        text,
        expires_at,
    )
    .await
    {
        Ok(mut sync) => envelopes.append(&mut sync),
        Err(error) => eprintln!("Self-Sync übersprungen: {error}"),
    }

    let delivery = DeliveryClient::new(delivery_url());
    let outcome = if sealed {
        // Absichtlich ohne Token: ein Bearer würde den Absender gegenüber
        // der Zustellung identifizieren.
        delivery.submit_sealed(&envelopes).await
    } else {
        delivery.submit(&token, &envelopes).await
    }
    .map_err(|e| e.to_string())?;
    println!(
        "Zugestellt an {} Gerät(e) ({} angenommen, {} Duplikate{})",
        devices.len(),
        outcome.accepted,
        outcome.duplicates,
        if sealed { ", versiegelt" } else { "" }
    );
    Ok(())
}

/// Löst die eigenen ANDEREN Geräte auf (für den Self-Sync) und baut je Gerät
/// eine Kopie-Hülle. Die Geräteliste wird wie ein Kontakt gecacht
/// (`sync/own_devices`); der Schlüssel-vorhanden-heißt-aufgelöst-Trick
/// unterscheidet „keine Zweitgeräte" (leer gespeichert) von „noch nicht
/// aufgelöst" (Schlüssel fehlt), sodass ein Ein-Gerät-Konto nicht bei jedem
/// Senden erneut auflöst und Prekeys verbraucht. Nach dem Koppeln eines
/// neuen Geräts wird der Cache geleert (approve und die nächste Anmeldung).
// Die Argumente sind alle unabhängig nötig (Gerät, Ablage, Token, eigene
// Identität, Sealed-Zertifikat, Ziel-Nachricht); ein Sammel-Struct für einen
// einzigen Aufrufer wäre nur Zeremonie.
#[allow(clippy::too_many_arguments)]
async fn build_sync_envelopes(
    device: &mut Device<PersistentProtocolStore<FileStorage>>,
    storage: &SharedStorage,
    token: &str,
    handle: &str,
    own_protocol_id: u32,
    certificate: Option<&[u8]>,
    peer: &str,
    text: &str,
    expires_at: Option<u64>,
) -> Result<Vec<OutgoingEnvelope>, String> {
    const OWN_KEY: &str = "sync/own_devices";
    let cached = storage.borrow().get(OWN_KEY).map_err(|e| e.to_string())?;
    let siblings: Vec<ContactDevice> = match cached {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("Eigene Geräte unlesbar: {e}"))?
        }
        None => {
            let bundles = DirectoryClient::new(directory_url())
                .bundles(token, handle)
                .await
                .map_err(|e| e.to_string())?;
            let mut siblings = Vec::new();
            for bundle_json in &bundles.devices {
                let (bundle, protocol_device_id) =
                    bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
                if protocol_device_id == own_protocol_id {
                    continue; // das eigene Gerät bekommt keine Kopie
                }
                let address = ProtocolAddress::new(
                    handle.to_string(),
                    device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
                );
                device
                    .establish_session(&address, &bundle)
                    .await
                    .map_err(|e| format!("Sitzungsaufbau (eigenes Gerät): {e}"))?;
                siblings.push(ContactDevice {
                    server_device_id: bundle_json.device_id.clone(),
                    protocol_device_id,
                });
            }
            let json = serde_json::to_vec(&siblings).map_err(|e| e.to_string())?;
            storage
                .borrow_mut()
                .put(OWN_KEY, &json)
                .map_err(|e| e.to_string())?;
            siblings
        }
    };
    if siblings.is_empty() {
        return Ok(Vec::new());
    }
    let payload = client_app::sync::encode(peer, text);
    let mut out = Vec::with_capacity(siblings.len());
    for sib in &siblings {
        let address = ProtocolAddress::new(
            handle.to_string(),
            device_id_from_u32(sib.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let envelope = match certificate {
            Some(cert) => {
                let blob = device
                    .seal_message(&address, cert, &payload)
                    .await
                    .map_err(|e| format!("Versiegeln (Sync): {e}"))?;
                wire::seal_sealed(&blob).map_err(|e| e.to_string())?
            }
            None => {
                let message = device
                    .encrypt(&address, &payload)
                    .await
                    .map_err(|e| format!("Verschlüsselung (Sync): {e}"))?;
                wire::seal(handle, own_protocol_id, &message).map_err(|e| e.to_string())?
            }
        };
        out.push(OutgoingEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: handle.to_string(),
            device_id: sib.server_device_id.clone(),
            envelope,
            franking_tag: None,
            expires_at,
        });
    }
    Ok(out)
}

/// Holt das Sealed-Sender-Zertifikat des eigenen Geräts, mit Cache in der
/// Ablage (`sealed/certificate`): erst wenn es fehlt oder in unter fünf
/// Minuten abläuft, fragt der Client den identity-Dienst neu.
async fn sender_certificate_cached(
    token: &str,
    protocol_device_id: u32,
    storage: &SharedStorage,
) -> Result<Vec<u8>, String> {
    const KEY: &str = "sealed/certificate";
    if let Some(bytes) = storage.borrow().get(KEY).map_err(|e| e.to_string())? {
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            let fresh_until = (now_unix() + 300) * 1000;
            if record["expires_at_millis"].as_u64().unwrap_or(0) > fresh_until {
                if let Some(cert) = record["certificate"]
                    .as_str()
                    .and_then(|b64| BASE64.decode(b64).ok())
                {
                    return Ok(cert);
                }
            }
        }
    }
    let issued = IdentityClient::new(identity_url())
        .sender_certificate(token, protocol_device_id)
        .await
        .map_err(|e| format!("Absender-Zertifikat: {e}"))?;
    let record = serde_json::json!({
        "certificate": BASE64.encode(&issued.certificate),
        "expires_at_millis": issued.expires_at_millis,
    });
    storage
        .borrow_mut()
        .put(
            KEY,
            &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    Ok(issued.certificate)
}

/// Der Trust Root zum Entsiegeln, mit Cache in der Ablage
/// (`sealed/trust_root`). Der erste Abruf vertraut dem identity-Dienst
/// (Trust-on-first-use wie beim KT-Signaturschlüssel); danach ist der
/// Anker lokal gepinnt, ein später ausgetauschter Root fällt auf, weil
/// jedes Entsiegeln scheitert.
async fn sealed_trust_root_cached(storage: &SharedStorage) -> Result<Vec<u8>, String> {
    const KEY: &str = "sealed/trust_root";
    if let Some(root) = storage.borrow().get(KEY).map_err(|e| e.to_string())? {
        return Ok(root);
    }
    let root = IdentityClient::new(identity_url())
        .sealed_sender_trust_root()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("der identity-Dienst stellt keine Sealed-Sender-Zertifikate aus")?;
    storage
        .borrow_mut()
        .put(KEY, &root)
        .map_err(|e| e.to_string())?;
    Ok(root)
}

/// `sm recv`: holt wartende Hüllen ab, entschlüsselt sie und bestätigt sie
/// (erst das Ack räumt sie serverseitig weg).
async fn recv() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, storage) = open_device(&profile)?;

    let delivery = DeliveryClient::new(delivery_url());
    if drain_waiting(&delivery, &token, &mut device, &storage).await? == 0 {
        println!("Keine neuen Nachrichten.");
    }
    Ok(())
}

/// Legt Franking-Schlüssel und Klartext einer empfangenen Nachricht ab,
/// damit `sm report` sie später aufdecken kann. Schlüssel: `franking/{id}`.
fn remember_franking(
    storage: &SharedStorage,
    message_id: &str,
    opened: &client_app::franking::OpenedMessage,
) -> Result<(), String> {
    let record = serde_json::json!({
        "key": BASE64.encode(&opened.franking_key),
        "message": BASE64.encode(&opened.message),
    });
    let json = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    storage
        .borrow_mut()
        .put(&format!("franking/{message_id}"), &json)
        .map_err(|e| e.to_string())
}

/// Gibt einen entschlüsselten Payload aus und legt das Franking-Material
/// fürs spätere Melden ab (`sm report`). Der Payload ist gefrankt (K_f
/// vorangestellt); ältere, ungefrankte Nachrichten fallen auf die rohe
/// Anzeige zurück.
///
/// Ist der Absender das eigene Handle, ist es eine Self-Sync-Kopie einer
/// selbst gesendeten Nachricht (ein anderes eigenes Gerät hat sie
/// verschickt): dann steht im Payload nicht die Nachricht, sondern der
/// Sync-Datensatz (Empfänger und Text), und die Zeile wird als ausgehend
/// gezeigt.
fn print_and_remember(
    storage: &SharedStorage,
    message_id: &str,
    from: &str,
    payload: &[u8],
    own_handle: &str,
) -> Result<(), String> {
    if from == own_handle {
        match client_app::sync::decode(payload) {
            Ok(client_app::sync::Synced::Message { peer, text }) => {
                println!("[-> {peer}] {text}  (auf anderem Gerät gesendet)")
            }
            // Das CLI hält keinen persistenten Verlauf, deshalb ist ein
            // Verlaufs-Nachzug hier nur eine kurze Ausgabe (der Web-Client
            // spielt ihn in seine Ablage ein).
            Ok(client_app::sync::Synced::History { peer, lines }) => println!(
                "[Verlaufs-Nachzug zu {peer}: {} Zeile(n) von einem anderen Gerät]",
                lines.len()
            ),
            Err(error) => eprintln!("Sync-Hülle {message_id} unlesbar: {error}"),
        }
        return Ok(());
    }
    match client_app::franking::unfrank(payload) {
        Ok(opened_msg) => {
            println!(
                "[{}] {}",
                from,
                String::from_utf8_lossy(&opened_msg.message)
            );
            // Die Melde-ID auf stderr, damit die Nachrichtenzeile (stdout)
            // schlicht bleibt: `sm report <id>`.
            eprintln!("  (Melde-ID: {message_id})");
            remember_franking(storage, message_id, &opened_msg)
        }
        Err(_) => {
            println!("[{}] {}", from, String::from_utf8_lossy(payload));
            Ok(())
        }
    }
}

/// Der Abhol-Durchlauf von `recv` und `listen`: wartende Hüllen holen,
/// entschlüsseln, ausgeben und bestätigen. Liefert, wie viele Hüllen
/// verarbeitet (bestätigt) wurden.
async fn drain_waiting(
    delivery: &DeliveryClient,
    token: &str,
    device: &mut Device<PersistentProtocolStore<FileStorage>>,
    storage: &SharedStorage,
) -> Result<usize, String> {
    let waiting = delivery.fetch(token).await.map_err(|e| e.to_string())?;
    // Das eigene Handle für die Self-Sync-Erkennung (Absender == ich).
    let own_handle = device.address().name().to_string();
    let mut acked = Vec::with_capacity(waiting.len());
    for message in &waiting {
        // Sealed-Sender-Hüllen zuerst: sie tragen keinen Absender im
        // Framing, der kommt erst aus der geprüften Zertifikatskette.
        if matches!(wire::classify(&message.envelope), wire::Framed::Sealed) {
            let blob = match wire::open_sealed(&message.envelope) {
                Ok(blob) => blob,
                Err(error) => {
                    eprintln!("Hülle {} übersprungen: {error}", message.id);
                    continue;
                }
            };
            let trust_root = sealed_trust_root_cached(storage).await?;
            match device.unseal_message(&trust_root, &blob).await {
                Ok(unsealed) => {
                    print_and_remember(
                        storage,
                        &message.id,
                        &unsealed.sender,
                        &unsealed.plaintext,
                        &own_handle,
                    )?;
                    acked.push(message.id.clone());
                }
                Err(error) => {
                    eprintln!("Hülle {} nicht entsiegelbar: {error}", message.id);
                    // Bestätigen wie unten: ein erneuter Abruf scheitert
                    // am selben Fehler.
                    acked.push(message.id.clone());
                }
            }
            continue;
        }
        // Gruppen-Hüllen (smgrp.v1): MLS verarbeiten statt Double Ratchet.
        if matches!(wire::classify(&message.envelope), wire::Framed::Group) {
            let opened = match wire::open_group(&message.envelope) {
                Ok(opened) => opened,
                Err(error) => {
                    eprintln!("Gruppen-Hülle {} übersprungen: {error}", message.id);
                    continue;
                }
            };
            match handle_group_envelope(storage, &own_handle, &opened.group_id, &opened.blob) {
                // Auch fehlgeschlagene Verarbeitung bestätigen: ein
                // erneuter Abruf scheiterte am selben Fehler (MLS-Zustand
                // kennt die Epoche bzw. den Schlüssel nicht mehr).
                Ok(()) => acked.push(message.id.clone()),
                Err(error) => {
                    eprintln!("Gruppen-Hülle {} nicht verarbeitbar: {error}", message.id);
                    acked.push(message.id.clone());
                }
            }
            continue;
        }
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
            Ok(payload) => {
                print_and_remember(storage, &message.id, &opened.from, &payload, &own_handle)?;
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
            .ack(token, &acked)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(acked.len())
}

/// `sm listen [--once]`: hält den Hinweiskanal offen und holt nach jedem
/// `message.waiting`-Hinweis ab wie `recv`. Direkt nach dem Verbinden wird
/// einmal abgeholt, weil Hinweise nur künftige Einreichungen ankündigen
/// (schnittstellen.md: nach jedem Verbinden abholen). `--once` beendet
/// nach dem ersten Durchlauf mit Nachrichten; das macht den Befehl im
/// Prozess-je-Befehl-Test beweisbar.
async fn listen(args: &[String]) -> Result<(), String> {
    let once = match args.first().map(String::as_str) {
        Some("--once") => true,
        Some(other) => return Err(format!("unbekanntes Argument: {other}")),
        None => false,
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, storage) = open_device(&profile)?;
    let delivery = DeliveryClient::new(delivery_url());

    let (mut socket, _) = tokio_tungstenite::connect_async(delivery.ws_url())
        .await
        .map_err(|e| format!("Hinweiskanal nicht erreichbar: {e}"))?;
    socket
        .send(Message::Text(ws_auth_frame(&token).into()))
        .await
        .map_err(|e| format!("Auth-Frame nicht gesendet: {e}"))?;

    // Was schon wartet, kündigt kein Hinweis mehr an.
    if drain_waiting(&delivery, &token, &mut device, &storage).await? > 0 && once {
        return Ok(());
    }

    eprintln!("Verbunden, warte auf Hinweise (Strg+C beendet).");
    while let Some(frame) = socket.next().await {
        let frame = frame.map_err(|e| format!("Hinweiskanal gestört: {e}"))?;
        match frame {
            Message::Text(text) => match parse_ws_event(text.as_str()) {
                Some(WsEvent::MessageWaiting) => {
                    if drain_waiting(&delivery, &token, &mut device, &storage).await? > 0 && once {
                        return Ok(());
                    }
                }
                Some(WsEvent::Notification { tenant, title }) => {
                    println!("[Benachrichtigung von {tenant}] {title}");
                }
                Some(WsEvent::Other { event }) => {
                    eprintln!("Unbekanntes Event ignoriert: {event}");
                }
                None => eprintln!("Frame ohne event-Feld ignoriert"),
            },
            // Close 4401 heißt: Token abgelaufen oder ungültig.
            Message::Close(reason) => {
                return Err(match reason {
                    Some(frame) => {
                        format!("Server hat geschlossen: {} {}", frame.code, frame.reason)
                    }
                    None => "Server hat geschlossen".to_string(),
                });
            }
            // Ping/Pong beantwortet tungstenite selbst, Binärframes sendet
            // der Kanal nicht (schnittstellen.md).
            _ => {}
        }
    }
    Err("Verbindung beendet".to_string())
}

/// `sm keycheck <handle>`: holt die Bündel eines Kontakts frisch und
/// vergleicht deren Geräteschlüssel mit den lokal gespeicherten. Ein
/// geänderter Schlüssel wird deutlich gemeldet (specs/key-transparency.md,
/// sichtbare Warnung bei Schlüsselwechsel); vorher unbekannte Geräte sind
/// Erstkontakt (Trust-on-first-use).
async fn keycheck(args: &[String]) -> Result<(), String> {
    let [handle] = args else {
        return Err("Aufruf: sm keycheck <handle>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (mut device, _storage) = open_device(&profile)?;

    let bundles = DirectoryClient::new(directory_url())
        .bundles(&token, handle)
        .await
        .map_err(|e| e.to_string())?;
    if bundles.devices.is_empty() {
        println!("'{handle}' hat keine gültigen Geräte.");
        return Ok(());
    }

    let mut changed = false;
    for bundle_json in &bundles.devices {
        let (_bundle, protocol_device_id) =
            bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
        let address = ProtocolAddress::new(
            handle.to_string(),
            device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
        );
        let incoming = BASE64
            .decode(&bundle_json.identity_key)
            .map_err(|e| format!("Bündel-Schlüssel kein Base64: {e}"))?;
        match device
            .stored_identity(&address)
            .await
            .map_err(|e| e.to_string())?
        {
            None => println!(
                "Gerät {}: Erstkontakt (noch keine Sitzung).",
                bundle_json.device_id
            ),
            Some(stored) if stored == incoming => {
                println!("Gerät {}: Schlüssel unverändert.", bundle_json.device_id)
            }
            Some(_) => {
                changed = true;
                println!(
                    "Gerät {}: SCHLÜSSEL GEÄNDERT. Vor dem Weiterschreiben die Sicherheitsnummer neu abgleichen.",
                    bundle_json.device_id
                );
            }
        }
    }
    if changed {
        return Err("Mindestens ein Geräteschlüssel hat sich geändert.".to_string());
    }
    Ok(())
}

/// `sm audit <from> <to>`: prüft als Gelegenheits-Auditor, ob das
/// KT-Log zwischen zwei Epochen append-only ist (specs/key-transparency.md,
/// Konsistenzbeweis). Braucht keine Anmeldung; die signierten Wurzeln und
/// der Beweis sind öffentlich.
async fn audit(args: &[String]) -> Result<(), String> {
    let [from, to] = args else {
        return Err("Aufruf: sm audit <von-epoche> <bis-epoche>".to_string());
    };
    let from: u64 = from
        .parse()
        .map_err(|_| "von-epoche ist keine Zahl".to_string())?;
    let to: u64 = to
        .parse()
        .map_err(|_| "bis-epoche ist keine Zahl".to_string())?;
    match client_app::kt::KtClient::new(kt_url())
        .verify_consistency(from, to, None)
        .await
    {
        Ok(()) => {
            println!("Log ist zwischen Epoche {from} und {to} append-only (konsistent).");
            Ok(())
        }
        Err(client_app::ClientError::KeyTransparency(detail)) => {
            Err(format!("KT-KONSISTENZ-ALARM: {detail}"))
        }
        Err(other) => Err(format!("Konsistenzprüfung nicht möglich: {other}")),
    }
}

/// `sm report <message_id>`: meldet eine empfangene Nachricht. Deckt den
/// beim Empfang abgelegten Franking-Schlüssel und Klartext auf; der Server
/// prüft, ob sie das aufbewahrte Commitment öffnen (beweisbar echt).
async fn report(args: &[String]) -> Result<(), String> {
    let [message_id] = args else {
        return Err("Aufruf: sm report <message_id>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let (_device, storage) = open_device(&profile)?;

    let bytes = storage
        .borrow()
        .get(&format!("franking/{message_id}"))
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Kein Franking-Material zu {message_id} (erst empfangen)"))?;
    let record: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Franking-Ablage unlesbar: {e}"))?;
    let key = BASE64
        .decode(record["key"].as_str().unwrap_or_default())
        .map_err(|e| e.to_string())?;
    let message = BASE64
        .decode(record["message"].as_str().unwrap_or_default())
        .map_err(|e| e.to_string())?;

    let verified = DeliveryClient::new(delivery_url())
        .report(&token, message_id, &message, &key)
        .await
        .map_err(|e| e.to_string())?;
    if verified {
        println!("Meldung verifiziert: die Nachricht wurde nachweislich so gesendet.");
    } else {
        println!("Meldung NICHT verifiziert: das Commitment öffnet nicht.");
    }
    Ok(())
}

/// `sm block <handle>`: blockiert ein Handle; danach werden dessen
/// Nachrichten still verworfen.
async fn block(args: &[String]) -> Result<(), String> {
    let [handle] = args else {
        return Err("Aufruf: sm block <handle>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    DeliveryClient::new(delivery_url())
        .block(&token, handle)
        .await
        .map_err(|e| e.to_string())?;
    println!("{handle} blockiert.");
    Ok(())
}

/// `sm unblock <handle>`: hebt eine Blockierung auf.
async fn unblock(args: &[String]) -> Result<(), String> {
    let [handle] = args else {
        return Err("Aufruf: sm unblock <handle>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    DeliveryClient::new(delivery_url())
        .unblock(&token, handle)
        .await
        .map_err(|e| e.to_string())?;
    println!("{handle} entblockt.");
    Ok(())
}

/// `sm blocks`: zeigt die eigene Blockliste.
async fn blocks() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let blocked = DeliveryClient::new(delivery_url())
        .blocks(&token)
        .await
        .map_err(|e| e.to_string())?;
    if blocked.is_empty() {
        println!("Keine blockierten Handles.");
    } else {
        for handle in blocked {
            println!("{handle}");
        }
    }
    Ok(())
}

/// `sm link <handle> <passwort>`: beginnt die Kopplung auf einem NEUEN,
/// leeren Gerät. Erzeugt die Geräte-Identität, legt ein vorläufiges Profil
/// an (noch ohne Nummer, ohne Token) und gibt den Kopplungs-Antrag als eine
/// Base64-Zeile aus. Diese Zeile wird auf dem Erstgerät mit `sm approve`
/// freigeschaltet; danach schließt `sm link-finish` die Kopplung ab. Der
/// Konto-Wurzelschlüssel bleibt auf dem Erstgerät: dieses Gerät wird ein
/// gekoppeltes Zweitgerät, das senden und empfangen kann.
async fn link(args: &[String]) -> Result<(), String> {
    let [handle, _password] = args else {
        return Err("Aufruf: sm link <handle> <passwort>".to_string());
    };
    let storage = open_storage()?;
    if has_own_identity(&storage).map_err(|e| e.to_string())? {
        return Err(format!(
            "Unter {} liegt schon eine Geräte-Identität. Kopplung braucht ein leeres Profil (SM_STATE auf einen neuen Pfad setzen).",
            state_path()
        ));
    }
    // Frische Geräte-Identität. Die Protokollnummer steht erst nach der
    // Freischaltung fest; für die Schlüsselerzeugung ist sie belanglos (der
    // Identitätsschlüssel hängt nicht an der Adresse), deshalb hier 1.
    let registration_id = rand::Rng::random_range(&mut rand::rng(), 1u32..16380);
    let mut keygen = Device::new(handle, 1, registration_id).map_err(|e| e.to_string())?;
    let device_public = BASE64.encode(keygen.identity_public().await.map_err(|e| e.to_string())?);
    let identity_bytes = keygen
        .identity_keypair_bytes()
        .await
        .map_err(|e| e.to_string())?;
    let device_id = uuid::Uuid::new_v4().to_string();

    store_own_identity(&storage, &identity_bytes, registration_id).map_err(|e| e.to_string())?;
    save_profile(&Profile {
        handle: handle.clone(),
        // Kein Konto-Wurzelschlüssel auf dem Zweitgerät.
        account_seed: String::new(),
        pending_account_seed: String::new(),
        device_id: device_id.clone(),
        // 0 = noch nicht freigeschaltet; link-finish setzt die echte Nummer.
        protocol_device_id: 0,
        access_token: None,
        refresh_token: None,
    })?;

    let request = LinkRequest {
        device_id,
        device_public_key: device_public,
    };
    let payload = BASE64.encode(serde_json::to_vec(&request).map_err(|e| e.to_string())?);
    println!("Kopplung begonnen. Auf dem Erstgerät ausführen:");
    println!("  sm approve {payload}");
    println!("Danach hier abschließen: sm link-finish {handle} <passwort>");
    Ok(())
}

/// `sm approve <antrag>`: schaltet auf dem ERSTGERÄT (mit Konto-Wurzel-
/// schlüssel und aktiver Anmeldung) ein neues Gerät frei. Signiert dessen
/// Credential mit dem Konto-Schlüssel und ruft `POST /devices`; der Server
/// vergibt die Gerätenummer. Ohne Wurzelschlüssel (also auf einem
/// Zweitgerät) geht das nicht.
async fn approve(args: &[String]) -> Result<(), String> {
    let [payload] = args else {
        return Err("Aufruf: sm approve <antrag>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    if profile.account_seed.is_empty() {
        return Err(
            "Dieses Gerät hat keinen Konto-Wurzelschlüssel (Zweitgerät). Freischalten nur auf dem Erstgerät.".to_string(),
        );
    }
    let seed: [u8; 32] = BASE64
        .decode(&profile.account_seed)
        .map_err(|e| format!("Konto-Seed unlesbar: {e}"))?
        .try_into()
        .map_err(|_| "Konto-Seed hat die falsche Länge".to_string())?;
    let account_key = IdentityKeypair::from_seed(&seed);

    let request: LinkRequest = serde_json::from_slice(
        &BASE64
            .decode(payload)
            .map_err(|_| "Antrag ist kein Base64".to_string())?,
    )
    .map_err(|e| format!("Antrag unlesbar: {e}"))?;

    let not_after = now_unix() + CREDENTIAL_TTL_SECONDS;
    let outcome = IdentityClient::new(identity_url())
        .add_device(
            &token,
            &DeviceEnrollment {
                account_key: &account_key,
                handle: &profile.handle,
                device_public_key: &request.device_public_key,
                device_id: &request.device_id,
                name: None,
                not_after,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    // Der Self-Sync-Cache dieses Geräts ist jetzt veraltet (ein Geschwister
    // kam dazu); leeren, damit die nächste gesendete Nachricht auch an das
    // neue Gerät synchronisiert. Best effort.
    if let Ok(storage) = open_storage() {
        let _ = storage.borrow_mut().remove("sync/own_devices");
    }

    println!(
        "Gerät {} freigeschaltet (Nummer {}). Auf dem neuen Gerät 'sm link-finish' ausführen.",
        outcome.device_id, outcome.protocol_device_id
    );
    Ok(())
}

/// `sm link-finish <handle> <passwort>`: schließt die Kopplung auf dem
/// Zweitgerät ab, nachdem das Erstgerät `sm approve` ausgeführt hat. Meldet
/// sich an (jetzt möglich, das Gerät ist freigeschaltet), liest die vom
/// Server vergebene Nummer aus der eigenen Gerätemenge, verankert sie im
/// Profil und veröffentlicht die Prekeys, damit Absender an dieses Gerät
/// zustellen können.
async fn link_finish(args: &[String]) -> Result<(), String> {
    let [handle, password] = args else {
        return Err("Aufruf: sm link-finish <handle> <passwort>".to_string());
    };
    let mut profile = load_profile()?;
    if handle != &profile.handle {
        return Err(format!(
            "Profil gehört zu '{}', nicht zu '{handle}'.",
            profile.handle
        ));
    }

    let client = IdentityClient::new(identity_url());
    let session = client
        .login(&profile.handle, password, &profile.device_id)
        .await
        .map_err(|e| e.to_string())?;
    let access = session.access_token.clone();
    profile.access_token = Some(session.access_token);
    profile.refresh_token = Some(session.refresh_token);

    // Die eigene Nummer aus der Gerätemenge holen (der Server hat sie bei
    // der Freischaltung vergeben).
    let devices = client.devices(&access).await.map_err(|e| e.to_string())?;
    let mine = devices.iter().find(|d| d.id == profile.device_id).ok_or(
        "Dieses Gerät steht nicht in der Gerätemenge. Zuerst 'sm approve' auf dem Erstgerät.",
    )?;
    if mine.protocol_device_id == 0 {
        return Err("Der Server hat keine Gerätenummer geliefert (zu alter Server?).".to_string());
    }
    profile.protocol_device_id = mine.protocol_device_id;
    save_profile(&profile)?;

    // Prekeys veröffentlichen, sonst kann niemand an dieses Gerät zustellen.
    let (mut device, storage) = open_device(&profile)?;
    let bundle = device
        .publish_prekey_bundle()
        .await
        .map_err(|e| e.to_string())?;
    let publication = publication_from_bundle(&bundle).map_err(|e| e.to_string())?;
    DirectoryClient::new(directory_url())
        .publish(&access, &publication)
        .await
        .map_err(|e| e.to_string())?;
    save_counter(&storage, device.next_prekey_id())?;

    println!(
        "Gekoppelt als Gerät {} (Nummer {}). Empfängt ab jetzt eigene Kopien.",
        profile.device_id, profile.protocol_device_id
    );
    Ok(())
}

/// `sm devices`: listet die gültige Gerätemenge des eigenen Kontos mit ihren
/// Nummern (das eigene Gerät markiert).
async fn devices() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let list = IdentityClient::new(identity_url())
        .devices(&token)
        .await
        .map_err(|e| e.to_string())?;
    if list.is_empty() {
        println!("Keine Geräte.");
        return Ok(());
    }
    for d in &list {
        let mine = if d.id == profile.device_id {
            " (dieses Gerät)"
        } else {
            ""
        };
        let name = d.name.as_deref().unwrap_or("Gerät");
        println!(
            "Nummer {}: {} [{}]{}",
            d.protocol_device_id, name, d.id, mine
        );
    }
    Ok(())
}

/// `sm unlink <geräte-id>`: entfernt ein Gerät aus der gültigen Menge
/// (Revocation). Das eigene Gerät kann sich nicht selbst entfernen (der
/// Server lehnt das ab, damit man sich nicht aussperrt).
async fn unlink(args: &[String]) -> Result<(), String> {
    let [device_id] = args else {
        return Err("Aufruf: sm unlink <geräte-id>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    IdentityClient::new(identity_url())
        .remove_device(&token, device_id)
        .await
        .map_err(|e| e.to_string())?;
    println!("Gerät {device_id} entfernt.");
    Ok(())
}

/// `sm delete-account <passwort>`: merkt die Löschung des eigenen Kontos vor
/// (NF030, Widerrufsfrist). Das Passwort bestätigt, dass es der Besitzer ist.
/// Bis zum Ablauf der Frist ist die Löschung mit `sm undelete` widerrufbar;
/// danach entfernt der Server-Purge Konto und Schlüssel. Die CLI versiegelt
/// nichts neu: ihre Ablage liegt unter der separaten SM_PASSPHRASE, nicht
/// unter dem Konto-Passwort.
async fn delete_account(args: &[String]) -> Result<(), String> {
    let [password] = args else {
        return Err("Aufruf: sm delete-account <passwort>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let until = IdentityClient::new(identity_url())
        .delete_account(&token, password)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "Löschung vorgemerkt. Widerrufsfrist läuft bis Unix-Zeit {until}. \
         Widerrufen mit 'sm undelete'."
    );
    Ok(())
}

/// `sm undelete`: widerruft eine vorgemerkte Konto-Löschung innerhalb der
/// Frist.
async fn undelete() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    IdentityClient::new(identity_url())
        .undelete_account(&token)
        .await
        .map_err(|e| e.to_string())?;
    println!("Löschung widerrufen. Das Konto bleibt bestehen.");
    Ok(())
}

/// `sm rename <anzeigename>`: ändert den Anzeigenamen des Kontos (F010,
/// getrennt vom Handle; der Handle bleibt). Mehrere Argumente werden mit
/// Leerzeichen verbunden, damit Namen mit Leerzeichen ohne Shell-Quoting
/// funktionieren. Der Server trimmt und bestätigt die gespeicherte Form.
async fn rename(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Aufruf: sm rename <anzeigename>".to_string());
    }
    let name = args.join(" ");
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let stored = IdentityClient::new(identity_url())
        .set_display_name(&token, &name)
        .await
        .map_err(|e| e.to_string())?;
    println!("Anzeigename geändert: {stored}");
    Ok(())
}

/// `sm rotate-key`: rotiert den Konto-Wurzelschlüssel (ADR-0010). Nur auf
/// dem Erstgerät (das den Wurzel-Seed hält). Zieht ein neues Wurzelpaar,
/// signiert mit dem ALTEN Schlüssel das Rotations-Zertifikat (Kontinuität),
/// signiert jedes aktuelle Gerät mit dem NEUEN Schlüssel neu (und erneuert
/// dabei dessen Ablauf) und reicht beides atomar ein. Der Dienst schiebt
/// danach ein frisches KT-Commitment, in dem die Rotation sichtbar wird.
///
/// Absturzsicher: der neue Seed wird VOR dem Serveraufruf als `pending`
/// abgelegt und erst nach dem bestätigten Erfolg nach `account_seed`
/// befördert. Bricht der Lauf zwischen Server-Commit und lokalem Ablegen ab,
/// hält das Gerät den neuen Schlüssel weiter und schließt die Rotation beim
/// nächsten Aufruf ab, statt ausgesperrt zu sein.
async fn rotate_key() -> Result<(), String> {
    let mut profile = load_profile()?;
    let token = access_token(&profile)?;
    if profile.account_seed.is_empty() {
        return Err(
            "Dieses Gerät hat keinen Konto-Wurzelschlüssel (Zweitgerät). Rotieren nur auf dem \
             Erstgerät."
                .to_string(),
        );
    }
    let old_account = IdentityKeypair::from_seed(&decode_seed(&profile.account_seed)?);

    // Liegt ein pending seed, ist eine frühere Rotation unterbrochen worden:
    // dann diese abschließen (Zielschlüssel ist der pending), keine neue
    // starten. Sonst ein frisches Wurzelpaar ziehen und VOR dem Serveraufruf
    // ablegen, damit ein Absturz danach den neuen Schlüssel nicht verliert.
    let resuming = !profile.pending_account_seed.is_empty();
    let new_account = if resuming {
        IdentityKeypair::from_seed(&decode_seed(&profile.pending_account_seed)?)
    } else {
        let account = IdentityKeypair::generate();
        profile.pending_account_seed = BASE64.encode(account.to_seed());
        save_profile(&profile)?;
        account
    };
    let new_identity_key = new_account.public_b64();
    let rotation_signature = build_rotation_cert(&old_account, &profile.handle, &new_identity_key);

    // Jedes aktuelle, nicht revozierte Gerät mit dem NEUEN Schlüssel neu
    // signieren und dabei den Ablauf erneuern (der Dienst prüft gegen genau
    // diese Gerätemenge und speichert den frischen not_after).
    let not_after = now_unix() + CREDENTIAL_TTL_SECONDS;
    let client = IdentityClient::new(identity_url());
    let devices = client.devices(&token).await.map_err(|e| e.to_string())?;
    let device_creds: Vec<RotateDeviceCredential> = devices
        .iter()
        .map(|device| RotateDeviceCredential {
            id: device.id.clone(),
            credential: build_device_credential(
                &new_account,
                &profile.handle,
                &device.id,
                &device.public_key,
                not_after,
            ),
            not_after,
        })
        .collect();

    match client
        .rotate_identity(&token, &new_identity_key, &rotation_signature, &device_creds)
        .await
    {
        Ok(()) => {
            promote_pending_seed(&mut profile, &new_account)?;
            println!(
                "Wurzelschlüssel rotiert ({} Gerät(e) neu signiert). Kontakte sehen einen \
                 Schlüsselwechsel; die Sicherheitsnummer über einen zweiten Kanal neu abgleichen.",
                device_creds.len()
            );
            Ok(())
        }
        // Wiederaufnahme: der Dienst hat den pending-Schlüssel bei einem
        // früheren, nur lokal nicht bestätigten Lauf schon übernommen. Die
        // Kontinuitätssignatur des ALTEN Schlüssels passt deshalb nicht mehr
        // (invalid_continuity). Da der einzige andere Schlüssel, den dieses
        // Gerät je erzeugte, der pending ist, muss der Dienst auf ihm stehen:
        // ihn lokal übernehmen und die Rotation so abschließen.
        Err(client_app::ClientError::Api { code, .. })
            if resuming && code == "invalid_continuity" =>
        {
            promote_pending_seed(&mut profile, &new_account)?;
            println!(
                "Frühere Rotation abgeschlossen: der Dienst hielt den neuen Wurzelschlüssel \
                 bereits, das Gerät hat ihn jetzt übernommen."
            );
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Dekodiert einen Base64-Seed (32 Byte) eines Wurzelschlüssels.
fn decode_seed(seed_b64: &str) -> Result<[u8; 32], String> {
    BASE64
        .decode(seed_b64)
        .map_err(|e| format!("Konto-Seed unlesbar: {e}"))?
        .try_into()
        .map_err(|_| "Konto-Seed hat die falsche Länge".to_string())
}

/// Befördert den bestätigten neuen Wurzelschlüssel nach `account_seed` und
/// leert `pending_account_seed`. Erst nach dem Servererfolg aufgerufen.
fn promote_pending_seed(profile: &mut Profile, new_account: &IdentityKeypair) -> Result<(), String> {
    profile.account_seed = BASE64.encode(new_account.to_seed());
    profile.pending_account_seed = String::new();
    save_profile(profile)
}

/// Ein Eintrag der lokalen Gruppenliste: die Zustell-ID plus die
/// Mitglieder-Handles (aus dem MLS-Ratchet-Tree bzw. der Gründung).
#[derive(Serialize, Deserialize)]
struct GroupEntry {
    id: String,
    members: Vec<String>,
}

fn roster_key(group_id: &str) -> String {
    format!("group/{group_id}/roster")
}

/// Lädt das MLS-Mitglied aus der Ablage oder legt ein frisches an und
/// persistiert es sofort (die KeyPackage-Privatteile müssen jeden
/// Prozesswechsel überleben, sonst wäre ein späterer Welcome wertlos).
fn load_or_new_member(storage: &SharedStorage, handle: &str) -> Result<GroupMember, String> {
    let existing = storage
        .borrow()
        .get(MLS_STATE_KEY)
        .map_err(|e| e.to_string())?;
    match existing {
        Some(state) => GroupMember::restore(handle.as_bytes(), &state),
        None => {
            let member = GroupMember::new(handle.as_bytes())?;
            save_member_state(storage, &member.export_state()?)?;
            Ok(member)
        }
    }
}

fn save_member_state(storage: &SharedStorage, state: &[u8]) -> Result<(), String> {
    storage
        .borrow_mut()
        .put(MLS_STATE_KEY, state)
        .map_err(|e| e.to_string())
}

fn load_group_index(storage: &SharedStorage) -> Result<Vec<GroupEntry>, String> {
    let raw = storage
        .borrow()
        .get(GROUPS_INDEX_KEY)
        .map_err(|e| e.to_string())?;
    match raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

fn save_group_index(storage: &SharedStorage, index: &[GroupEntry]) -> Result<(), String> {
    let bytes = serde_json::to_vec(index).map_err(|e| e.to_string())?;
    storage
        .borrow_mut()
        .put(GROUPS_INDEX_KEY, &bytes)
        .map_err(|e| e.to_string())
}

/// Merkt eine Gruppe in der lokalen Liste vor (ersetzt einen bestehenden
/// Eintrag derselben ID, etwa nach einer Mitglieder-Änderung).
fn remember_group(storage: &SharedStorage, entry: GroupEntry) -> Result<(), String> {
    let mut index = load_group_index(storage)?;
    index.retain(|g| g.id != entry.id);
    index.push(entry);
    save_group_index(storage, &index)
}

fn invite_key(group_id: &str) -> String {
    format!("group/{group_id}/invite")
}

fn load_invites(storage: &SharedStorage) -> Result<Vec<String>, String> {
    let raw = storage
        .borrow()
        .get(INVITES_INDEX_KEY)
        .map_err(|e| e.to_string())?;
    match raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

fn save_invites(storage: &SharedStorage, invites: &[String]) -> Result<(), String> {
    let bytes = serde_json::to_vec(invites).map_err(|e| e.to_string())?;
    storage
        .borrow_mut()
        .put(INVITES_INDEX_KEY, &bytes)
        .map_err(|e| e.to_string())
}

/// Merkt eine Einladung vor: legt den Welcome-Blob ab und trägt die
/// Gruppen-ID in die Einladungsliste ein (doppelte werden ignoriert). Der
/// Welcome wird bewusst NICHT verarbeitet, sonst wäre das eingeladene
/// KeyPackage schon für eine noch nicht angenommene (oder Spam-)
/// Einladung verbraucht.
fn remember_invite(
    storage: &SharedStorage,
    group_id: &str,
    welcome_blob: &[u8],
) -> Result<bool, String> {
    let mut invites = load_invites(storage)?;
    if invites.iter().any(|id| id == group_id) {
        return Ok(false);
    }
    // Deckel gegen das Fluten der Einladungsliste (siehe MAX_PENDING_INVITES).
    if invites.len() >= MAX_PENDING_INVITES {
        return Ok(false);
    }
    storage
        .borrow_mut()
        .put(&invite_key(group_id), welcome_blob)
        .map_err(|e| e.to_string())?;
    invites.push(group_id.to_string());
    save_invites(storage, &invites)?;
    Ok(true)
}

/// Entfernt eine vorgemerkte Einladung samt gepuffertem Verkehr (nach
/// Annahme oder Ablehnung).
fn forget_invite(storage: &SharedStorage, group_id: &str) -> Result<(), String> {
    let mut invites = load_invites(storage)?;
    invites.retain(|id| id != group_id);
    save_invites(storage, &invites)?;
    let _ = storage.borrow_mut().remove(&invite_key(group_id));
    let _ = storage.borrow_mut().remove(&invite_buffer_key(group_id));
    Ok(())
}

fn invite_buffer_key(group_id: &str) -> String {
    format!("group/{group_id}/buffer")
}

/// Puffert eine Gruppen-Hülle, die vor der Annahme einer Einladung
/// eintrifft (etwa der Geräte-Roster, den der Gründer gleich nach der
/// Gründung schickt). Ohne den Puffer ginge sie verloren, weil eine noch
/// nicht beigetretene Gruppe sie nicht verarbeiten kann; bei der Annahme
/// werden die gepufferten Hüllen der Reihe nach nachgespielt. Als Base64
/// abgelegt (die Ablage hält Bytes; eine JSON-Liste ist so lesbar).
fn buffer_invite_blob(storage: &SharedStorage, group_id: &str, blob: &[u8]) -> Result<(), String> {
    let key = invite_buffer_key(group_id);
    let mut buffered: Vec<String> = match storage.borrow().get(&key).map_err(|e| e.to_string())? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    // Puffer deckeln: das Wichtige (der Roster) kommt zuerst; ein
    // gedeckelter Puffer verhindert, dass ein Einladender die Ablage vor
    // der Ablehnung mit beliebig vielen Hüllen füllt.
    if buffered.len() >= INVITE_BUFFER_MAX {
        return Ok(());
    }
    buffered.push(BASE64.encode(blob));
    let bytes = serde_json::to_vec(&buffered).map_err(|e| e.to_string())?;
    storage
        .borrow_mut()
        .put(&key, &bytes)
        .map_err(|e| e.to_string())
}

fn load_invite_buffer(storage: &SharedStorage, group_id: &str) -> Result<Vec<Vec<u8>>, String> {
    let raw = storage
        .borrow()
        .get(&invite_buffer_key(group_id))
        .map_err(|e| e.to_string())?;
    let encoded: Vec<String> = match raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    encoded
        .iter()
        .map(|s| BASE64.decode(s).map_err(|e| e.to_string()))
        .collect()
}

fn save_roster(
    storage: &SharedStorage,
    group_id: &str,
    devices: &[RosterDevice],
) -> Result<(), String> {
    let bytes = serde_json::to_vec(devices).map_err(|e| e.to_string())?;
    storage
        .borrow_mut()
        .put(&roster_key(group_id), &bytes)
        .map_err(|e| e.to_string())
}

fn load_roster(storage: &SharedStorage, group_id: &str) -> Result<Vec<RosterDevice>, String> {
    let raw = storage
        .borrow()
        .get(&roster_key(group_id))
        .map_err(|e| e.to_string())?;
    match raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
        None => Err(
            "Geräte-Roster dieser Gruppe fehlt noch; 'sm recv' holt ihn (der Gründer schickt ihn \
             als erste Gruppen-Nachricht)."
                .to_string(),
        ),
    }
}

/// `sm group-create <mitglied> [<mitglied>...]`: gründet eine MLS-Gruppe
/// mit sich selbst plus den genannten Handles. Die Eingeladenen brauchen
/// veröffentlichte MLS-KeyPackages (`sm publish-keys`). Ablauf wie in
/// specs/mls-delivery-service.md: Gruppe beim Zustelldienst anlegen
/// (Epoche 0), KeyPackages je Gerät der Eingeladenen aus dem Verzeichnis
/// holen (konsumiert je eins), ein Commit lädt alle ein (Epoche 1), die
/// Welcome-Hüllen gehen an die eingeladenen Geräte, und der Geräte-Roster
/// folgt als erste Anwendungsnachricht (Ende-zu-Ende, wie alles).
async fn group_create(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Aufruf: sm group-create <mitglied> [<mitglied>...]".to_string());
    }
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let mut invitees: Vec<String> = Vec::new();
    for handle in args {
        if handle != &profile.handle && !invitees.contains(handle) {
            invitees.push(handle.clone());
        }
    }
    if invitees.is_empty() {
        return Err("Eine Gruppe braucht mindestens ein anderes Mitglied.".to_string());
    }
    let mut members = vec![profile.handle.clone()];
    members.extend(invitees.iter().cloned());

    // Zuerst die KeyPackages holen: scheitert ein Eingeladener (nichts
    // veröffentlicht), ist noch nichts angelegt worden.
    let directory = DirectoryClient::new(directory_url());
    let mut invite_blobs = Vec::new();
    let mut roster = Vec::new();
    for handle in &invitees {
        let packages = directory
            .mls_key_packages(&token, handle)
            .await
            .map_err(|e| e.to_string())?;
        if packages.devices.is_empty() {
            return Err(format!(
                "{handle} hat kein MLS-KeyPackage veröffentlicht; dort 'sm publish-keys' ausführen."
            ));
        }
        for entry in packages.devices {
            invite_blobs.push(
                BASE64
                    .decode(&entry.key_package)
                    .map_err(|e| format!("KeyPackage von {handle} unlesbar: {e}"))?,
            );
            roster.push(RosterDevice {
                handle: handle.clone(),
                device_id: entry.device_id,
            });
        }
    }

    // Auch die EIGENEN anderen Geräte einladen (Multi-Device): jedes ist
    // ein eigenes MLS-Leaf. Das gründende Gerät selbst (own device_id)
    // fällt heraus (es ist schon Leaf 0). Wer nur ein Gerät hat, fügt hier
    // nichts hinzu. Die eigenen Geräte bekommen wie jedes Mitglied eine
    // Einladung, die dort anzunehmen ist.
    let own_packages = directory
        .mls_key_packages(&token, &profile.handle)
        .await
        .map_err(|e| e.to_string())?;
    for entry in own_packages.devices {
        if entry.device_id == profile.device_id {
            continue;
        }
        invite_blobs.push(
            BASE64
                .decode(&entry.key_package)
                .map_err(|e| format!("eigenes KeyPackage unlesbar: {e}"))?,
        );
        roster.push(RosterDevice {
            handle: profile.handle.clone(),
            device_id: entry.device_id,
        });
    }

    // Der Roster führt ALLE Mitglieds-Geräte einschließlich des eigenen:
    // Beigetretene adressieren daraus auch den Gründer. Die Fanouts unten
    // filtern nur das eigene Gerät heraus (sein Leaf kann die eigene
    // Nachricht nicht entschlüsseln).
    roster.push(RosterDevice {
        handle: profile.handle.clone(),
        device_id: profile.device_id.clone(),
    });

    let delivery = DeliveryClient::new(delivery_url());
    let group_id = new_uuid();
    let created = delivery
        .create_group(&token, &group_id, &members)
        .await
        .map_err(|e| e.to_string())?;

    let storage = open_storage()?;
    let member = load_or_new_member(&storage, &profile.handle)?;
    let mut session = GroupSession::create(member, group_id.as_bytes())?;
    let outcome = session.add_members(&invite_blobs)?;

    let welcome_fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(&group_id, &outcome.welcome)
                    .map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    // Erst senden, dann anwenden: nimmt der Dienst den Commit nicht an,
    // wird der vorgemerkte Zustand gar nicht erst abgelegt (die Gruppe
    // ist beim Dienst dann angelegt, aber ohne Mitglieder-Commit, und ein
    // neuer Versuch kann sie überschreiben). Der Handshake ist signierter
    // Klartext, ein verworfener Commit hinterlässt kein Schlüsselmaterial.
    delivery
        .group_commit(&token, &group_id, 0, &members, &welcome_fanout)
        .await
        .map_err(|e| e.to_string())?;
    session.merge_pending()?;
    save_member_state(&storage, &session.export_state()?)?;

    // Der Geräte-Roster als erste Anwendungsnachricht: Beigetretene
    // erfahren daraus, an welche Geräte sie ihre Hüllen adressieren
    // (der Zustelldienst hat bewusst keine GET-Route dafür).
    let roster_blob = session.create_message(&grouptext::encode_roster(&roster))?;
    // Auch das Erzeugen rückt den Sende-Ratchet vor: Zustand sichern,
    // BEVOR der Chiffretext das Gerät verlässt (sonst nutzte ein
    // Wiederanlauf dieselbe Ratchet-Position erneut).
    save_member_state(&storage, &session.export_state()?)?;
    let roster_fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(&group_id, &roster_blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    delivery
        .group_messages(&token, &group_id, &roster_fanout)
        .await
        .map_err(|e| e.to_string())?;

    save_roster(&storage, &group_id, &roster)?;
    remember_group(
        &storage,
        GroupEntry {
            id: group_id.clone(),
            members: members.clone(),
        },
    )?;
    println!(
        "Gruppe {group_id} angelegt: {} ({} Gerät(e) beim Dienst)",
        members.join(", "),
        created.devices
    );
    Ok(())
}

/// `sm groups`: die lokale Gruppenliste (Zustell-ID plus Mitglieder).
fn groups_list() -> Result<(), String> {
    let storage = open_storage()?;
    let index = load_group_index(&storage)?;
    if index.is_empty() {
        println!("Keine Gruppen. Mit 'sm group-create <mitglied>...' die erste gründen.");
        return Ok(());
    }
    for entry in index {
        println!("{}  {}", entry.id, entry.members.join(", "));
    }
    Ok(())
}

/// `sm group-send <gruppen-id> <text>`: verschlüsselt den Text mit MLS an
/// die Gruppe und stellt ihn an alle Geräte des lokalen Rosters zu.
async fn group_send(args: &[String]) -> Result<(), String> {
    let [group_id, text] = args else {
        return Err("Aufruf: sm group-send <gruppen-id> <text>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let storage = open_storage()?;
    let member = load_or_new_member(&storage, &profile.handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err(format!(
            "Gruppe {group_id} ist in der lokalen Ablage unbekannt ('sm groups' zeigt die eigenen)."
        ));
    };
    let roster = load_roster(&storage, group_id)?;
    let blob = session.create_message(&grouptext::encode_text(text))?;
    // Zustand sichern, BEVOR der Chiffretext das Gerät verlässt (siehe
    // group_create: sonst Ratchet-Wiederverwendung nach einem Abbruch).
    save_member_state(&storage, &session.export_state()?)?;
    let fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    let sent = delivery_client()
        .group_messages(&token, group_id, &fanout)
        .await
        .map_err(|e| e.to_string())?;
    println!("An die Gruppe gesendet ({} Gerät(e))", sent.accepted);
    Ok(())
}

fn delivery_client() -> DeliveryClient {
    DeliveryClient::new(delivery_url())
}

/// `sm group-remove <gruppen-id> <handle>`: entfernt ein Mitglied mit
/// MLS-Neuschlüsseln. Der Remove-Commit schaltet die Gruppe in eine neue
/// Epoche, die dem Entfernten verschlossen bleibt; das ist die Antwort
/// auf ein kompromittiertes oder revoziertes Gerät eines Mitglieds. Der
/// Commit geht auch an die Geräte des Entfernten, damit sein Client die
/// Entfernung erkennt und lokal aufräumt; danach bekommt die Rest-Gruppe
/// einen frischen Roster.
async fn group_remove(args: &[String]) -> Result<(), String> {
    let [group_id, handle] = args else {
        return Err("Aufruf: sm group-remove <gruppen-id> <handle>".to_string());
    };
    let profile = load_profile()?;
    if handle == &profile.handle {
        return Err(
            "Sich selbst entfernen geht nicht (RFC 9420 verbietet den Commit der eigenen \
             Entfernung); zum Austreten 'sm group-leave' nutzen."
                .to_string(),
        );
    }
    let token = access_token(&profile)?;
    let storage = open_storage()?;
    let member = load_or_new_member(&storage, &profile.handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err(format!(
            "Gruppe {group_id} ist in der lokalen Ablage unbekannt."
        ));
    };
    let old_roster = load_roster(&storage, group_id)?;
    // Die Server-Epoche läuft mit der MLS-Epoche im Gleichschritt (jeder
    // Commit geht über den Dienst); der CAS-Vertrag verlangt die aktuelle.
    let from_epoch = session.epoch();
    // Die verbleibende Mitgliederliste (der Server ersetzt damit seine
    // Gerätemenge): die aktuellen Identitäten ohne den Entfernten. Vor
    // merge_pending trägt member_identities noch alle.
    let members: Vec<String> = unique_handles(session.member_identities())
        .into_iter()
        .filter(|m| m != handle)
        .collect();
    // Commit bauen (nur VORGEMERKT, nicht angewandt, nicht gesichert).
    let commit = session.remove_members(&[handle.as_bytes().to_vec()])?;

    // Der Commit geht an ALLE bisherigen Geräte außer den eigenen, auch
    // an die des Entfernten (Erkennen + Aufräumen).
    let commit_fanout: Vec<GroupOutgoing> = fanout_targets(&old_roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &commit).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    // Senden, dann anwenden. Lehnt der Dienst ab (409, ein anderes
    // Mitglied war schneller) oder scheitert der Versand, wird NICHTS
    // gesichert: der lokale Zustand bleibt bei Epoche N (kein Fork), und
    // ein 'sm recv' wendet den Gewinner-Commit an. Würde man vorher
    // anwenden und ablegen, läge die eigene Epoche für immer neben der
    // Dienst-Wahrheit.
    delivery_client()
        .group_commit(&token, group_id, from_epoch, &members, &commit_fanout)
        .await
        .map_err(|e| {
            format!("{e} (bei stale_epoch: 'sm recv' holt den Stand nach, dann erneut entfernen)")
        })?;
    session.merge_pending()?;
    save_member_state(&storage, &session.export_state()?)?;

    // Den frischen Roster (ohne den Entfernten) SOFORT lokal ablegen:
    // scheitert die Roster-Nachricht unten, sind die Empfänger trotzdem
    // selbst-heilend (sie filtern beim Verarbeiten des Commits die Geräte
    // ausgeschiedener Handles heraus), und der eigene Roster stimmt schon.
    let new_roster: Vec<RosterDevice> = old_roster
        .into_iter()
        .filter(|device| &device.handle != handle)
        .collect();
    save_roster(&storage, group_id, &new_roster)?;
    remember_group(
        &storage,
        GroupEntry {
            id: group_id.clone(),
            members: members.clone(),
        },
    )?;
    println!(
        "{handle} entfernt; die Gruppe ist neu geschlüsselt ({} Mitglieder: {})",
        members.len(),
        members.join(", ")
    );

    // Frischer Roster an die Rest-Gruppe (best effort, siehe oben).
    let roster_blob = session.create_message(&grouptext::encode_roster(&new_roster))?;
    save_member_state(&storage, &session.export_state()?)?;
    let roster_fanout: Vec<GroupOutgoing> = fanout_targets(&new_roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &roster_blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    if !roster_fanout.is_empty() {
        if let Err(error) = delivery_client()
            .group_messages(&token, group_id, &roster_fanout)
            .await
        {
            eprintln!(
                "  (Roster-Nachricht nicht zugestellt: {error}; die Empfänger heilen den \
                 Roster beim Verarbeiten des Entfernungs-Commits selbst.)"
            );
        }
    }
    Ok(())
}

/// `sm group-leave <gruppen-id>`: verlässt die Gruppe lokal. Schickt den
/// Verbliebenen eine Ansage und löscht dann den eigenen Gruppenzustand
/// samt lokaler Einträge. Kryptografisch entfernt bleibt man erst, wenn
/// ein verbleibendes Mitglied den Remove-Commit setzt (`group-remove`),
/// denn RFC 9420 verbietet den Commit der eigenen Entfernung; die Ansage
/// fordert genau dazu auf.
async fn group_leave(args: &[String]) -> Result<(), String> {
    let [group_id] = args else {
        return Err("Aufruf: sm group-leave <gruppen-id>".to_string());
    };
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let storage = open_storage()?;
    let member = load_or_new_member(&storage, &profile.handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err(format!(
            "Gruppe {group_id} ist in der lokalen Ablage unbekannt."
        ));
    };
    let roster = load_roster(&storage, group_id)?;
    let blob = session.create_message(&grouptext::encode_leave())?;
    save_member_state(&storage, &session.export_state()?)?;
    let fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &profile.device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    if !fanout.is_empty() {
        delivery_client()
            .group_messages(&token, group_id, &fanout)
            .await
            .map_err(|e| e.to_string())?;
    }
    let member = session.forget()?;
    save_member_state(&storage, &member.export_state()?)?;
    let mut index = load_group_index(&storage)?;
    index.retain(|g| &g.id != group_id);
    save_group_index(&storage, &index)?;
    let _ = storage.borrow_mut().remove(&roster_key(group_id));
    println!(
        "Gruppe verlassen und lokal vergessen. Kryptografisch entfernt dich erst der \
         Remove-Commit eines verbleibenden Mitglieds ('sm group-remove {group_id} {}').",
        profile.handle
    );
    Ok(())
}

/// `sm invites`: die offenen Einladungen (Gruppen-IDs, deren Welcome
/// vorgemerkt, aber noch nicht angenommen ist).
fn invites_list() -> Result<(), String> {
    let storage = open_storage()?;
    let invites = load_invites(&storage)?;
    if invites.is_empty() {
        println!("Keine offenen Einladungen.");
        return Ok(());
    }
    for id in invites {
        println!("{id}  (annehmen: 'sm group-accept {id}')");
    }
    Ok(())
}

/// `sm group-accept <gruppen-id>`: nimmt eine vorgemerkte Einladung an,
/// tritt also jetzt erst der Gruppe bei (verarbeitet den Welcome, was das
/// eingeladene KeyPackage verbraucht). Die Mitgliederliste kommt aus dem
/// Ratchet-Tree; der Geräte-Roster folgt mit dem nächsten `sm recv`.
async fn group_accept(args: &[String]) -> Result<(), String> {
    let [group_id] = args else {
        return Err("Aufruf: sm group-accept <gruppen-id>".to_string());
    };
    let profile = load_profile()?;
    let storage = open_storage()?;
    let welcome = storage
        .borrow()
        .get(&invite_key(group_id))
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Keine offene Einladung zu Gruppe {group_id} ('sm invites')."))?;
    let member = load_or_new_member(&storage, &profile.handle)?;
    let mut session = GroupSession::join_group(member, &welcome)
        .map_err(|e| format!("Beitritt scheitert: {e}"))?;
    save_member_state(&storage, &session.export_state()?)?;

    // Vor der Annahme eingetroffenen Verkehr nachspielen: der Geräte-Roster
    // (zum Senden nötig), Gesprächs-Texte (sonst verloren, der Server hat
    // seine Kopie beim Puffern schon verworfen) und fremde Commits. Der
    // Reihe nach; eine einzelne unlesbare Hülle darf den Beitritt nicht
    // scheitern lassen. Ein Commit, der uns schon wieder ENTFERNT, macht
    // die Einladung wertlos: dann aufräumen statt eine tote Gruppe anlegen.
    let mut roster_devices = None;
    let mut pending_texts: Vec<(String, String)> = Vec::new();
    let mut removed_before_join = false;
    for buffered in load_invite_buffer(&storage, group_id)? {
        match session.process(&buffered) {
            Ok(GroupInbound::Application(application)) => {
                let sender = String::from_utf8_lossy(&application.sender_identity).to_string();
                match grouptext::decode(&application.plaintext) {
                    Ok(GroupPayload::Roster { devices }) => roster_devices = Some(devices),
                    Ok(GroupPayload::Text { text }) => pending_texts.push((sender, text)),
                    Ok(GroupPayload::Leave) | Err(_) => {}
                }
            }
            Ok(GroupInbound::RemovedSelf) => {
                removed_before_join = true;
                break;
            }
            Ok(GroupInbound::Updated) => {}
            Err(error) => eprintln!("[gruppe {group_id}] gepufferte Hülle übersprungen: {error}"),
        }
    }

    if removed_before_join {
        let member = session.forget()?;
        save_member_state(&storage, &member.export_state()?)?;
        forget_invite(&storage, group_id)?;
        return Err(format!(
            "Die Einladung zu Gruppe {group_id} ist nicht mehr gültig (du wurdest inzwischen \
             wieder entfernt). Sie wurde verworfen."
        ));
    }

    save_member_state(&storage, &session.export_state()?)?;
    if let Some(devices) = roster_devices {
        save_roster(&storage, group_id, &devices)?;
    }

    let members = unique_handles(session.member_identities());
    remember_group(
        &storage,
        GroupEntry {
            id: group_id.clone(),
            members: members.clone(),
        },
    )?;
    forget_invite(&storage, group_id)?;
    let roster_note = if load_roster(&storage, group_id).is_ok() {
        "Der Geräte-Roster ist da, du kannst senden."
    } else {
        "Den Geräte-Roster holt der nächste 'sm recv'."
    };
    println!(
        "Einladung angenommen, Gruppe {group_id} beigetreten ({} Mitglieder: {}). {roster_note}",
        members.len(),
        members.join(", ")
    );
    // Vor der Annahme gesendete Gesprächs-Texte zeigen (der Reihe nach).
    for (sender, text) in pending_texts {
        println!("[gruppe {group_id}] {sender}: {text}");
    }
    Ok(())
}

/// `sm group-decline <gruppen-id>`: lehnt eine vorgemerkte Einladung ab.
/// Der Welcome wird verworfen, KEIN KeyPackage verbraucht. Kryptografisch
/// bleibt man in der Gerätemenge des Einladenden, liest aber nichts; ein
/// späterer Wunsch beizutreten braucht eine neue Einladung.
fn group_decline(args: &[String]) -> Result<(), String> {
    let [group_id] = args else {
        return Err("Aufruf: sm group-decline <gruppen-id>".to_string());
    };
    let storage = open_storage()?;
    if !load_invites(&storage)?.iter().any(|id| id == group_id) {
        return Err(format!("Keine offene Einladung zu Gruppe {group_id}."));
    }
    forget_invite(&storage, group_id)?;
    println!("Einladung zu Gruppe {group_id} abgelehnt.");
    Ok(())
}

/// Die eindeutigen Handles aus einer Leaf-Identitätsliste
/// (`member_identities`): ein Multi-Device-Mitglied hat mehrere Leaves mit
/// demselben Handle, für die Mitglieder-Anzeige und den `members`-Parameter
/// (Handles, die der Dienst zu Geräten auflöst) zählt jeder Handle einmal.
fn unique_handles(identities: Vec<Vec<u8>>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    identities
        .into_iter()
        .map(|id| String::from_utf8_lossy(&id).to_string())
        .filter(|handle| seen.insert(handle.clone()))
        .collect()
}

/// Die Zustell-Ziele aus einem Roster: alle Geräte AUSSER dem eigenen. Es
/// wird nach der eigenen GERÄTE-ID gefiltert, nicht nach dem Handle:
/// eigene Zweitgeräte sind eigene MLS-Leaves und sollen die Nachricht
/// bekommen (Multi-Device), nur das sendende Gerät selbst nicht (sein Leaf
/// kann die eigene Nachricht nicht entschlüsseln).
fn fanout_targets<'a>(
    roster: &'a [RosterDevice],
    own_device_id: &'a str,
) -> impl Iterator<Item = &'a RosterDevice> {
    roster
        .iter()
        .filter(move |device| device.device_id != own_device_id)
}

/// Verarbeitet eine eingehende Gruppen-Hülle: bekannte Gruppe -> MLS
/// verarbeiten (Text ausgeben, Roster übernehmen, fremde Commits
/// anwenden); unbekannte Gruppe -> der Blob muss ein Welcome sein, also
/// beitreten und die Gruppe lokal vormerken. Der MLS-Zustand wird nach
/// JEDER Verarbeitung gesichert (der Ratchet ist weitergelaufen).
fn handle_group_envelope(
    storage: &SharedStorage,
    own_handle: &str,
    group_id: &str,
    blob: &[u8],
) -> Result<(), String> {
    let member = load_or_new_member(storage, own_handle)?;
    match GroupSession::load(member, group_id.as_bytes())? {
        Some(mut session) => {
            let inbound = session.process(blob)?;
            match inbound {
                GroupInbound::Application(application) => {
                    save_member_state(storage, &session.export_state()?)?;
                    let sender = String::from_utf8_lossy(&application.sender_identity).to_string();
                    match grouptext::decode(&application.plaintext).map_err(|e| e.to_string())? {
                        GroupPayload::Text { text } => {
                            println!("[gruppe {group_id}] {sender}: {text}");
                        }
                        GroupPayload::Roster { devices } => {
                            save_roster(storage, group_id, &devices)?;
                            println!(
                                "[gruppe {group_id}] Geräte-Roster von {sender} übernommen ({} Gerät(e))",
                                devices.len()
                            );
                        }
                        GroupPayload::Leave => {
                            println!(
                                "[gruppe {group_id}] {sender} verlässt die Gruppe. Kryptografisch \
                                 entfernt erst 'sm group-remove {group_id} {sender}'."
                            );
                        }
                    }
                }
                // Fremder Commit: die Mitgliederliste kann sich geändert
                // haben, den lokalen Eintrag nachführen.
                GroupInbound::Updated => {
                    save_member_state(storage, &session.export_state()?)?;
                    let members = unique_handles(session.member_identities());
                    // Roster selbst-heilen: Geräte ausgeschiedener Handles
                    // fallen heraus, auch wenn die neue Roster-Nachricht
                    // (die der Committer separat schickt) nie ankommt. Sonst
                    // adressierte ein späterer Versand ein Gerät außerhalb
                    // der Gruppen-Gerätemenge, und der Dienst wiese den
                    // ganzen Stapel ab (404 unknown_device).
                    if let Ok(roster) = load_roster(storage, group_id) {
                        let pruned: Vec<RosterDevice> = roster
                            .into_iter()
                            .filter(|device| members.iter().any(|m| m == &device.handle))
                            .collect();
                        save_roster(storage, group_id, &pruned)?;
                    }
                    remember_group(
                        storage,
                        GroupEntry {
                            id: group_id.to_string(),
                            members: members.clone(),
                        },
                    )?;
                    println!(
                        "[gruppe {group_id}] Gruppen-Update angewandt ({} Mitglieder: {})",
                        members.len(),
                        members.join(", ")
                    );
                }
                // Der Commit hat DIESES Mitglied entfernt: Zustand und
                // lokale Einträge aufräumen; die neue Epoche ist ohnehin
                // unlesbar (MLS-Neuschlüsseln), und genau das ist der Zweck.
                GroupInbound::RemovedSelf => {
                    let member = session.forget()?;
                    save_member_state(storage, &member.export_state()?)?;
                    let mut index = load_group_index(storage)?;
                    index.retain(|g| g.id != group_id);
                    save_group_index(storage, &index)?;
                    let _ = storage.borrow_mut().remove(&roster_key(group_id));
                    println!(
                        "[gruppe {group_id}] Du wurdest aus der Gruppe entfernt; der lokale \
                         Zustand ist gelöscht."
                    );
                }
            }
            Ok(())
        }
        None => {
            // Unbekannte Gruppe: eine Welcome-Nachricht ist eine EINLADUNG,
            // die nur vorgemerkt wird (kein automatischer Beitritt, sonst
            // könnte jeder Authentifizierte ein Gerät in seine Gruppe
            // ziehen und Nachrichten aufzwingen). Der Welcome wird bewusst
            // nicht verarbeitet, damit eine abgelehnte oder Spam-Einladung
            // kein KeyPackage kostet. Ein Nicht-Welcome-Blob (Anwendung
            // oder Commit einer Gruppe, in der wir nicht sind) wird
            // verworfen (der Aufrufer bestätigt ihn).
            if GroupSession::is_welcome(blob) {
                if remember_invite(storage, group_id, blob)? {
                    println!(
                        "[einladung] Du wurdest zu Gruppe {group_id} eingeladen. Annehmen mit \
                         'sm group-accept {group_id}', ablehnen mit 'sm group-decline {group_id}'."
                    );
                }
            } else if load_invites(storage)?.iter().any(|id| id == group_id) {
                // Verkehr, der vor der Annahme eintrifft (etwa der Roster):
                // puffern, damit er beim Beitritt nachgespielt werden kann.
                buffer_invite_blob(storage, group_id, blob)?;
            } else {
                eprintln!(
                    "[gruppe {group_id}] Nachricht einer Gruppe, in der du nicht bist, verworfen."
                );
            }
            Ok(())
        }
    }
}

/// `sm verify`: die KT-Selbstprüfung des eigenen Kontos
/// (specs/key-transparency.md). Rechnet das Commitment aus Konto-Schlüssel
/// und eigener Gerätemenge nach und verifiziert den Inklusionsbeweis gegen
/// die signierte Wurzel. Ein Alarm ist ein Sicherheitssignal (möglicher
/// stiller Schlüsseltausch), kein gewöhnlicher Fehler.
async fn verify() -> Result<(), String> {
    let profile = load_profile()?;
    let token = access_token(&profile)?;
    let seed: [u8; 32] = BASE64
        .decode(&profile.account_seed)
        .map_err(|e| format!("Konto-Seed unlesbar: {e}"))?
        .try_into()
        .map_err(|_| "Konto-Seed hat die falsche Länge".to_string())?;
    let account = IdentityKeypair::from_seed(&seed);
    let devices = IdentityClient::new(identity_url())
        .devices(&token)
        .await
        .map_err(|e| format!("Gerätemenge nicht abrufbar: {e}"))?;
    match client_app::kt::KtClient::new(kt_url())
        .verify_self(&profile.handle, &account.public_b64(), &devices, None)
        .await
    {
        Ok(check) => {
            println!(
                "KT-Eintrag stimmt: Epoche {}, Version {} ({} Gerät(e) im Commitment)",
                check.epoch,
                check.version,
                devices.len()
            );
            Ok(())
        }
        Err(client_app::ClientError::KeyTransparency(detail)) => Err(format!("KT-ALARM: {detail}")),
        Err(other) => Err(format!("KT-Prüfung nicht möglich: {other}")),
    }
}

fn print_usage() {
    eprintln!(
        "sm - SecureMessenger Referenzclient\n\
         \n\
         Befehle:\n\
         \x20 register <handle> <passwort>   Konto und erstes Gerät anlegen\n\
         \x20 login <passwort>               Gerät anmelden, Token speichern\n\
         \x20 logout                         Session abmelden\n\
         \x20 passwd <altes> <neues>         Konto-Passwort aendern (meldet andere Geraete ab)\n\
         \x20 whoami                         Profil anzeigen\n\
         \x20 link <handle> <passwort>       neues Zweitgeraet koppeln: Antrag ausgeben\n\
         \x20 approve <antrag>               Zweitgeraet freischalten (nur Erstgeraet)\n\
         \x20 link-finish <handle> <passwort>  Kopplung auf dem Zweitgeraet abschliessen\n\
         \x20 devices                        eigene Geraetemenge mit Nummern anzeigen\n\
         \x20 unlink <geraete-id>            ein Geraet entfernen (Revocation)\n\
         \x20 delete-account <passwort>     Konto-Loeschung vormerken (Widerrufsfrist)\n\
         \x20 undelete                      vorgemerkte Loeschung widerrufen\n\
         \x20 rename <anzeigename>          Anzeigename aendern (Handle bleibt)\n\
         \x20 rotate-key                    Konto-Wurzelschluessel rotieren (nur Erstgeraet)\n\
         \x20 publish-keys                   Prekey-Satz + MLS-KeyPackages veroeffentlichen\n\
         \x20 group-create <mitglied>...     MLS-Gruppe mit sich + den Handles gruenden\n\
         \x20 groups                         lokale Gruppenliste (ID + Mitglieder)\n\
         \x20 group-send <id> <text>         E2EE-Gruppennachricht senden\n\
         \x20 group-remove <id> <handle>     Mitglied entfernen (MLS-Neuschluesseln)\n\
         \x20 group-leave <id>               Gruppe verlassen (lokal + Ansage)\n\
         \x20 invites                        offene Gruppen-Einladungen anzeigen\n\
         \x20 group-accept <id>              Einladung annehmen (beitreten)\n\
         \x20 group-decline <id>             Einladung ablehnen\n\
         \x20 send <handle> <text> [--ttl s] [--sealed]  E2EE senden (--ttl: verschwindet; --sealed: ohne Absender-Klartext)\n\
         \x20 recv                           wartende Nachrichten abholen und entschlüsseln\n\
         \x20 listen [--once]                Hinweiskanal halten und bei Hinweisen abholen\n\
         \x20 verify                         eigenen KT-Eintrag pruefen (Selbstpruefung)\n\
         \x20 audit <von> <bis>              KT-Log-Konsistenz zwischen zwei Epochen pruefen\n\
         \x20 keycheck <handle>              Geraeteschluessel eines Kontakts auf Aenderung pruefen\n\
         \x20 report <message_id>            empfangene Nachricht melden (Franking aufdecken)\n\
         \x20 block <handle>                 Absender blockieren\n\
         \x20 unblock <handle>               Blockierung aufheben\n\
         \x20 blocks                         eigene Blockliste anzeigen\n\
         \x20 help                           diese Hilfe\n\
         \n\
         Umgebung:\n\
         \x20 SM_IDENTITY_URL    identity-Dienst (Vorgabe {DEFAULT_IDENTITY_URL})\n\
         \x20 SM_DIRECTORY_URL   directory-Dienst (Vorgabe {DEFAULT_DIRECTORY_URL})\n\
         \x20 SM_DELIVERY_URL    delivery-Dienst (Vorgabe {DEFAULT_DELIVERY_URL})\n\
         \x20 SM_KT_URL          kt-Dienst (Vorgabe {DEFAULT_KT_URL})\n\
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

fn kt_url() -> String {
    std::env::var("SM_KT_URL").unwrap_or_else(|_| DEFAULT_KT_URL.to_string())
}

fn profile_path() -> String {
    std::env::var("SM_PROFILE").unwrap_or_else(|_| "sm-profile.json".to_string())
}

fn state_path() -> String {
    std::env::var("SM_STATE").unwrap_or_else(|_| "sm-state.json".to_string())
}

/// Lädt das Profil. Mit gesetzter Passphrase wird eine verschlüsselte
/// Datei entsiegelt; eine ältere Klartext-Datei wird noch gelesen (und
/// beim nächsten Speichern verschlüsselt). Ohne Passphrase eine
/// verschlüsselte Datei zu öffnen, scheitert klar.
fn load_profile() -> Result<Profile, String> {
    let path = profile_path();
    let data = std::fs::read(&path)
        .map_err(|_| format!("Kein Profil unter {path}. Zuerst 'sm register' ausführen."))?;
    let json = match passphrase() {
        Some(pp) if keystore::is_sealed(&data) => {
            keystore::Sealer::unlock(&pp, &data)
                .map_err(|e| format!("Profil: {e}"))?
                .1
        }
        None if keystore::is_sealed(&data) => {
            return Err("Profil ist verschlüsselt; SM_PASSPHRASE setzen.".to_string())
        }
        // Passphrase gesetzt, Datei noch Klartext (Migration), oder gar
        // keine Passphrase und Klartext-Datei: unverändert lesen.
        _ => data,
    };
    serde_json::from_slice(&json).map_err(|error| format!("Profil unlesbar: {error}"))
}

/// Speichert das Profil. Mit Passphrase im keystore-Envelope (der
/// Konto-Seed und die Tokens liegen dann nicht mehr im Klartext), sonst als
/// Klartext-JSON.
fn save_profile(profile: &Profile) -> Result<(), String> {
    let path = profile_path();
    let json = serde_json::to_vec_pretty(profile).map_err(|error| error.to_string())?;
    let data = match passphrase() {
        Some(pp) => keystore::Sealer::create(&pp).seal(&json),
        None => json,
    };
    std::fs::write(&path, data).map_err(|error| format!("Profil nicht schreibbar: {error}"))
}

fn access_token(profile: &Profile) -> Result<String, String> {
    profile
        .access_token
        .clone()
        .ok_or_else(|| "Kein aktives Token. Zuerst 'sm login'.".to_string())
}

/// Die Ablage-Passphrase aus der Umgebung. Ist `SM_PASSPHRASE` gesetzt,
/// laufen Profil und Zustand verschlüsselt (keystore); ohne bleibt es
/// Klartext, damit Tests und der schnelle lokale Betrieb ohne Vorbereitung
/// funktionieren. [ANNAHME: Passphrase über die Umgebung wie die übrigen
/// Geheimnisse des Projekts (KT-Schlüssel, OPRF-Schlüssel); ein echter
/// Desktop-Client nähme den OS-Keyring, das ist eine eigene Etappe.]
fn passphrase() -> Option<String> {
    std::env::var("SM_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty())
}

fn open_storage() -> Result<SharedStorage, String> {
    let storage = match passphrase() {
        Some(pp) => FileStorage::open_encrypted(state_path(), &pp)?,
        None => FileStorage::open(state_path())?,
    };
    Ok(Rc::new(RefCell::new(storage)))
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
    let protocol_device_id = u8::try_from(profile.protocol_device_id)
        .map_err(|_| format!("Gerätenummer {} über 255", profile.protocol_device_id))?;
    let device = Device::with_store(
        &profile.handle,
        protocol_device_id,
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
