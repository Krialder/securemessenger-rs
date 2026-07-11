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
use client_app::account::IdentityKeypair;
use client_app::delivery::{
    parse_ws_event, ws_auth_frame, DeliveryClient, OutgoingEnvelope, WsEvent,
};
use client_app::directory::DirectoryClient;
use client_app::identity::DeviceEnrollment;
use client_app::prekeys::{bundle_from_directory, device_id_from_u32, publication_from_bundle};
use client_app::protocol_store::{has_own_identity, store_own_identity, PersistentProtocolStore};
use client_app::storage::{FileStorage, KeyValueStorage as _};
use client_app::{wire, IdentityClient, NewAccount};
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
        "whoami" => whoami(),
        "link" => link(&args[1..]).await,
        "approve" => approve(&args[1..]).await,
        "link-finish" => link_finish(&args[1..]).await,
        "devices" => devices().await,
        "unlink" => unlink(&args[1..]).await,
        "publish-keys" => publish_keys().await,
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
         \x20 whoami                         Profil anzeigen\n\
         \x20 link <handle> <passwort>       neues Zweitgeraet koppeln: Antrag ausgeben\n\
         \x20 approve <antrag>               Zweitgeraet freischalten (nur Erstgeraet)\n\
         \x20 link-finish <handle> <passwort>  Kopplung auf dem Zweitgeraet abschliessen\n\
         \x20 devices                        eigene Geraetemenge mit Nummern anzeigen\n\
         \x20 unlink <geraete-id>            ein Geraet entfernen (Revocation)\n\
         \x20 publish-keys                   Prekey-Satz im Verzeichnis veröffentlichen\n\
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
