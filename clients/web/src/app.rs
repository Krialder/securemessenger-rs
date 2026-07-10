//! Web-Client (Leptos, CSR): Oberfläche und Ablaufsteuerung.
//!
//! Die Schichten darunter bleiben unangetastet: `client-core` trägt die
//! Krypto, `client-app` das Protokoll (HTTP, Blobs, Framing, Ablage).
//! Der Zustand liegt persistent in IndexedDB (storage.rs): Geräte-Identität,
//! Sitzungen, Prekey-Zähler, Kontakte und das Profil überleben das Neuladen,
//! dieselben Ablage-Schlüssel wie beim CLI (contact/..., counter/...), damit
//! die Formate nicht auseinanderlaufen.
//!
//! [ANNAHME: Tokens werden nicht persistiert; nach einem Neuladen meldet
//! sich der Nutzer mit dem Passwort neu an. Das ist bewusst: ein
//! dauerhaft gespeichertes Token im unverschlüsselten Browser-Storage
//! wäre ein größeres Diebstahlsziel als die erneute Eingabe wert ist.
//! Ein Konto je Browser-Profil; ein zweites Konto braucht ein anderes
//! Browser-Profil. Abruf per Knopf; der gloo-net-Hinweiskanal folgt als
//! nächster Schnitt. Der Web-Client ist laut sicherheit.md das
//! kryptografisch schwächste Glied (kein OS-Keystore, XSS-Fläche); die
//! Oberfläche sagt das sichtbar an, statt es zu kaschieren.]

use std::cell::RefCell;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::delivery::{
    parse_ws_event, ws_auth_frame, DeliveryClient, OutgoingEnvelope, WsEvent,
};
use client_app::directory::DirectoryClient;
use client_app::kt::KtClient;
use client_app::prekeys::{
    bundle_from_directory, device_id_from_u32, new_uuid, publication_from_bundle,
    PROTOCOL_DEVICE_ID,
};
use client_app::protocol_store::{store_own_identity, PersistentProtocolStore};
use client_app::storage::KeyValueStorage as _;
use client_app::{wire, ClientError, IdentityClient, NewAccount};
use client_core::libsignal_protocol::{IdentityKeyPair, ProtocolAddress};
use client_core::onetoone::Device;
use futures_util::{SinkExt as _, StreamExt as _};
use gloo_net::websocket::{futures::WebSocket, Message as WsMessage};
use leptos::prelude::*;
use leptos::task::spawn_local;
use send_wrapper::SendWrapper;
use serde::{Deserialize, Serialize};

use crate::storage::BrowserStorage;

/// Gültigkeit des Geräte-Credentials: ein Jahr, wie beim CLI.
const CREDENTIAL_TTL_SECONDS: u64 = 60 * 60 * 24 * 365;
/// Ablage-Schlüssel, identisch zum CLI (Zähler) bzw. web-eigen (Profil).
const COUNTER_KEY: &str = "counter/next_prekey_id";
const PROFILE_KEY: &str = "profile/v1";
/// Index aller Unterhaltungen (jüngste zuerst) samt Auszug und
/// Ungelesen-Zahl. Ein eigener Schlüssel, weil der Storage-Trait bewusst
/// kein Auflisten kennt (die persistenten Backends bräuchten sonst
/// Prefix-Scans). Die Verläufe selbst liegen je Kontakt getrennt.
const CHATS_INDEX_KEY: &str = "chats/index";
/// Höchstens so viele Nachrichten je Unterhaltung in der Ablage; ältere
/// fallen vorn heraus. Ein Referenzclient braucht keinen unbegrenzten
/// Verlauf, und die Ablage schreibt bei jeder Änderung den Wert neu.
const HISTORY_LIMIT: usize = 200;

fn history_key(peer: &str) -> String {
    format!("history/{peer}")
}

/// Eine Zeile im Verlauf: Absender-Handle, Klartext, Zeitstempel
/// (Unix-Sekunden). Der eigene Handle markiert ausgehende Nachrichten.
#[derive(Serialize, Deserialize, Clone)]
struct StoredLine {
    from: String,
    text: String,
    at: u64,
}

/// Die Zusammenfassung einer Unterhaltung für die Seitenleiste: mit wem,
/// der letzte Auszug und wie viele ungelesen sind.
#[derive(Serialize, Deserialize, Clone)]
struct ChatSummary {
    peer: String,
    snippet: String,
    unread: u32,
}

fn load_summaries(storage: &SharedStorage) -> Vec<ChatSummary> {
    storage
        .borrow()
        .get(CHATS_INDEX_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_summaries(storage: &SharedStorage, summaries: &[ChatSummary]) {
    if let Ok(json) = serde_json::to_vec(summaries) {
        let _ = storage.borrow_mut().put(CHATS_INDEX_KEY, &json);
    }
}

fn load_history(storage: &SharedStorage, peer: &str) -> Vec<StoredLine> {
    storage
        .borrow()
        .get(&history_key(peer))
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Hängt eine Zeile an die Anzeige-Liste an und hält sie auf dieselbe
/// Obergrenze wie die Ablage (`save_history`); sonst wüchse das reaktive
/// Signal unbegrenzt und spränge nach einem Neuladen auf die gekappten 200
/// zurück (sichtbar inkonsistent zur Ablage).
fn push_capped(list: &mut Vec<StoredLine>, line: StoredLine) {
    list.push(line);
    if list.len() > HISTORY_LIMIT {
        let excess = list.len() - HISTORY_LIMIT;
        list.drain(0..excess);
    }
}

fn save_history(storage: &SharedStorage, peer: &str, history: &[StoredLine]) {
    let capped = if history.len() > HISTORY_LIMIT {
        &history[history.len() - HISTORY_LIMIT..]
    } else {
        history
    };
    if let Ok(json) = serde_json::to_vec(capped) {
        let _ = storage.borrow_mut().put(&history_key(peer), &json);
    }
}

/// Legt eine Nachricht in Verlauf und Zusammenfassung ab und liefert die
/// neue, nach Aktualität sortierte Liste zurück. `bump_unread` zählt eine
/// eingehende Nachricht als ungelesen, solange der Chat nicht offen ist.
fn record_message(
    storage: &SharedStorage,
    peer: &str,
    line: StoredLine,
    bump_unread: bool,
) -> Vec<ChatSummary> {
    let mut history = load_history(storage, peer);
    let snippet = line.text.clone();
    history.push(line);
    save_history(storage, peer, &history);

    let mut summaries = load_summaries(storage);
    if let Some(pos) = summaries.iter().position(|s| s.peer == peer) {
        let mut summary = summaries.remove(pos);
        summary.snippet = snippet;
        if bump_unread {
            summary.unread += 1;
        }
        summaries.insert(0, summary);
    } else {
        summaries.insert(
            0,
            ChatSummary {
                peer: peer.to_string(),
                snippet,
                unread: u32::from(bump_unread),
            },
        );
    }
    save_summaries(storage, &summaries);
    summaries
}

/// Stellt sicher, dass eine (auch leere) Unterhaltung im Index steht,
/// damit ein neu begonnener Chat sofort in der Liste auftaucht.
fn ensure_chat(storage: &SharedStorage, peer: &str) -> Vec<ChatSummary> {
    let mut summaries = load_summaries(storage);
    if !summaries.iter().any(|s| s.peer == peer) {
        summaries.insert(
            0,
            ChatSummary {
                peer: peer.to_string(),
                snippet: String::new(),
                unread: 0,
            },
        );
        save_summaries(storage, &summaries);
    }
    summaries
}

/// Setzt die Ungelesen-Zahl einer Unterhaltung auf null (Chat geöffnet).
fn mark_read(storage: &SharedStorage, peer: &str) -> Vec<ChatSummary> {
    let mut summaries = load_summaries(storage);
    if let Some(summary) = summaries.iter_mut().find(|s| s.peer == peer) {
        summary.unread = 0;
        save_summaries(storage, &summaries);
    }
    summaries
}

/// Die Initiale für den Avatar: der erste Buchstabe des Handles, groß.
fn avatar_initial(handle: &str) -> String {
    handle
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Wählt eine der sechs kontrastgeprüften Avatar-Farben stabil aus dem
/// Handle (gleicher Kontakt, gleiche Farbe).
fn avatar_style(handle: &str) -> String {
    let sum: u32 = handle.bytes().map(u32::from).sum();
    format!("background-color: var(--sm-avatar-{})", sum % 6 + 1)
}

/// Formatiert einen Unix-Zeitstempel als lokale Uhrzeit (HH:MM) über die
/// JavaScript-Uhr des Browsers.
fn format_time(at: u64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((at as f64) * 1000.0));
    format!("{:02}:{:02}", date.get_hours(), date.get_minutes())
}

type SharedStorage = Rc<RefCell<BrowserStorage>>;
type WebDevice = Device<PersistentProtocolStore<BrowserStorage>>;

/// Das persistente Profil: was der Client nach einem Neuladen braucht,
/// um sich wieder anzumelden. Der Konto-Seed bleibt für spätere
/// Geräte-Credentials erhalten (wer die Ablage hat, hat das Konto,
/// wie beim CLI-Profil).
#[derive(Serialize, Deserialize, Clone)]
struct Profile {
    handle: String,
    account_seed: String,
    device_id: String,
}

/// Ein bekanntes Kontakt-Gerät, Format identisch zum CLI
/// (`contact/{handle}` in der Ablage).
#[derive(Serialize, Deserialize, Clone)]
struct ContactDevice {
    server_device_id: String,
    protocol_device_id: u32,
}

/// Der lebende Client-Zustand hinter der Oberfläche. In einem
/// `Rc<RefCell<...>>`, weil das Gerät nicht klonbar ist und die
/// Leptos-Handler es teilen; der `busy`-Riegel in der UI verhindert, dass
/// zwei Abläufe gleichzeitig hineingreifen. Der `SendWrapper` darum herum
/// überbrückt die Send-Anforderung des Leptos-Renderers im eindrähtigen
/// Browser.
struct Core {
    device: WebDevice,
    handle: String,
    token: String,
    storage: SharedStorage,
}

type SharedCore = SendWrapper<Rc<RefCell<Option<Core>>>>;
type SharedBoot = SendWrapper<Rc<RefCell<Option<SharedStorage>>>>;

fn origin() -> String {
    web_sys::window()
        .expect("Browser-Fenster")
        .location()
        .origin()
        .expect("Origin")
}

/// Die Dienste liegen hinter same-origin-Pfaden (/api/...), die der
/// trunk-Dev-Server beziehungsweise der Ingress auf die Dienste abbildet.
fn identity_url() -> String {
    format!("{}/api/identity", origin())
}

fn directory_url() -> String {
    format!("{}/api/directory", origin())
}

fn delivery_url() -> String {
    format!("{}/api/delivery", origin())
}

fn kt_url() -> String {
    format!("{}/api/kt", origin())
}

/// Die 60 Ziffern der Sicherheitsnummer in Fünfergruppen, wie Signal sie
/// zeigt; am Stück wäre sie nicht abgleichbar.
fn group_safety_number(number: &str) -> String {
    number
        .as_bytes()
        .chunks(5)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Die gespeicherte Modus-Wahl aus localStorage; ohne Wahl "system"
/// (dann entscheidet die CSS-Media-Query nach der OS-Präferenz). Das
/// gleiche Schlüsselwort wie im FOUC-Guard in index.html.
fn stored_theme() -> String {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("sm-theme").ok().flatten())
        .unwrap_or_else(|| "system".to_string())
}

/// Setzt den Modus: data-theme am Wurzelelement (die CSS-Ebene 2 schaltet
/// darüber um) und speichert die Wahl. Nur auf ausdrückliche Nutzeraktion,
/// damit "system" nicht ungefragt zu einer festen Wahl wird.
fn apply_theme(choice: &str) {
    if let Some(window) = web_sys::window() {
        if let Some(root) = window.document().and_then(|d| d.document_element()) {
            let _ = root.set_attribute("data-theme", choice);
        }
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.set_item("sm-theme", choice);
        }
    }
}

fn load_profile(storage: &SharedStorage) -> Option<Profile> {
    let bytes = storage.borrow().get(PROFILE_KEY).ok()??;
    serde_json::from_slice(&bytes).ok()
}

fn save_profile(storage: &SharedStorage, profile: &Profile) -> Result<(), String> {
    let json = serde_json::to_vec(profile).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(PROFILE_KEY, &json)
}

fn load_counter(storage: &SharedStorage) -> Result<u32, String> {
    match storage.borrow().get(COUNTER_KEY)? {
        Some(bytes) => {
            Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
                "Prekey-Zähler hat die falsche Länge".to_string()
            })?))
        }
        None => Ok(1),
    }
}

fn save_counter(storage: &SharedStorage, next_prekey_id: u32) -> Result<(), String> {
    storage
        .borrow_mut()
        .put(COUNTER_KEY, &next_prekey_id.to_be_bytes())
}

/// Konto anlegen: Schlüssel erzeugen, registrieren, anmelden, Prekeys
/// veröffentlichen, Profil und Zähler verankern. Ein Schritt aus
/// Nutzersicht, weil ein frisch angelegtes Konto ohne veröffentlichte
/// Prekeys nicht erreichbar wäre.
async fn onboard(storage: SharedStorage, handle: String, password: String) -> Result<Core, String> {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    // libsignal-Registration-IDs sind 14 Bit (1..16380).
    let registration_id = rand::Rng::random_range(&mut rng, 1u32..16380);

    store_own_identity(&storage, &identity.serialize(), registration_id)
        .map_err(|e| e.to_string())?;
    let mut device = Device::with_store(
        &handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        1,
    )
    .map_err(|e| e.to_string())?;
    let device_public = BASE64.encode(device.identity_public().await.map_err(|e| e.to_string())?);

    let account_key = IdentityKeypair::generate();
    let device_id = new_uuid();
    let identity_client = IdentityClient::new(identity_url());
    identity_client
        .register(&NewAccount {
            handle: &handle,
            display_name: None,
            password: &password,
            account_key: &account_key,
            device_public_key: &device_public,
            device_id: &device_id,
            not_after: now_unix() + CREDENTIAL_TTL_SECONDS,
        })
        .await
        .map_err(|e| e.to_string())?;
    let session = identity_client
        .login(&handle, &password, &device_id)
        .await
        .map_err(|e| e.to_string())?;

    let bundle = device
        .publish_prekey_bundle()
        .await
        .map_err(|e| e.to_string())?;
    let publication = publication_from_bundle(&bundle).map_err(|e| e.to_string())?;
    DirectoryClient::new(directory_url())
        .publish(&session.access_token, &publication)
        .await
        .map_err(|e| e.to_string())?;
    save_counter(&storage, device.next_prekey_id())?;
    save_profile(
        &storage,
        &Profile {
            handle: handle.clone(),
            account_seed: BASE64.encode(account_key.to_seed()),
            device_id,
        },
    )?;

    Ok(Core {
        device,
        handle,
        token: session.access_token,
        storage,
    })
}

/// Anmeldung nach einem Neuladen: das Profil kommt aus der Ablage, die
/// Geräte-Identität und alle Sitzungen liegen schon im Protokoll-Store;
/// nur das Passwort muss der Nutzer neu eingeben (Tokens werden bewusst
/// nicht persistiert, siehe Modulkopf).
async fn login(storage: SharedStorage, password: String) -> Result<Core, String> {
    let profile = load_profile(&storage).ok_or_else(|| "Kein Profil in der Ablage".to_string())?;
    let session = IdentityClient::new(identity_url())
        .login(&profile.handle, &password, &profile.device_id)
        .await
        .map_err(|e| e.to_string())?;
    let next_prekey_id = load_counter(&storage)?;
    let device = Device::with_store(
        &profile.handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        next_prekey_id,
    )
    .map_err(|e| e.to_string())?;
    Ok(Core {
        device,
        handle: profile.handle,
        token: session.access_token,
        storage,
    })
}

/// Sendet eine Nachricht; baut beim ersten Kontakt die PQXDH-Sitzungen aus
/// den Verzeichnis-Bündeln auf und merkt sich die Geräte des Kontakts in
/// der Ablage (gleicher Fluss und gleiches Format wie im CLI).
async fn send_message(
    core: &mut Core,
    peer: &str,
    text: &str,
    expires_at: Option<u64>,
) -> Result<(), String> {
    let contact_key = format!("contact/{peer}");
    let known: Vec<ContactDevice> = match core
        .storage
        .borrow()
        .get(&contact_key)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("Kontakt unlesbar: {e}"))?
        }
        None => Vec::new(),
    };
    let devices = if known.is_empty() {
        let bundles = DirectoryClient::new(directory_url())
            .bundles(&core.token, peer)
            .await
            .map_err(|e| e.to_string())?;
        if bundles.devices.is_empty() {
            return Err(format!("'{peer}' hat keine gültigen Geräte"));
        }
        let mut contact = Vec::with_capacity(bundles.devices.len());
        for bundle_json in &bundles.devices {
            let (bundle, protocol_device_id) =
                bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
            let address = ProtocolAddress::new(
                peer.to_string(),
                device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
            );
            core.device
                .establish_session(&address, &bundle)
                .await
                .map_err(|e| format!("Sitzungsaufbau: {e}"))?;
            contact.push(ContactDevice {
                server_device_id: bundle_json.device_id.clone(),
                protocol_device_id,
            });
        }
        let json = serde_json::to_vec(&contact).map_err(|e| e.to_string())?;
        core.storage
            .borrow_mut()
            .put(&contact_key, &json)
            .map_err(|e| e.to_string())?;
        contact
    } else {
        known
    };

    // Einmal je Nachricht franken (specs/sealed-sender-und-abuse.md): der
    // Franking-Schlüssel reist im verschlüsselten Payload, das Commitment
    // als Tag an der Hülle. Dieselben Werte für alle Zielgeräte.
    let franked = client_app::franking::frank(text.as_bytes());
    let franking_tag = BASE64.encode(&franked.commitment);
    let mut envelopes = Vec::new();
    for target in &devices {
        let address = ProtocolAddress::new(
            peer.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let message = core
            .device
            .encrypt(&address, &franked.payload)
            .await
            .map_err(|e| format!("Verschlüsselung: {e}"))?;
        let envelope =
            wire::seal(&core.handle, PROTOCOL_DEVICE_ID, &message).map_err(|e| e.to_string())?;
        envelopes.push(OutgoingEnvelope {
            id: new_uuid(),
            recipient: peer.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
            franking_tag: Some(franking_tag.clone()),
            expires_at,
        });
    }
    DeliveryClient::new(delivery_url())
        .submit(&core.token, &envelopes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Holt wartende Hüllen ab, entschlüsselt und bestätigt sie; liefert
/// (Absender, Klartext) je Nachricht.
async fn fetch_messages(core: &mut Core) -> Result<Vec<(String, String)>, String> {
    let delivery = DeliveryClient::new(delivery_url());
    let waiting = delivery
        .fetch(&core.token)
        .await
        .map_err(|e| e.to_string())?;
    let mut received = Vec::new();
    let mut acked = Vec::new();
    for message in &waiting {
        let opened = match wire::open(&message.envelope) {
            Ok(opened) => opened,
            Err(error) => {
                // Unlesbare Hülle: stehen lassen (siehe CLI-Begründung).
                leptos::logging::warn!("Hülle {} übersprungen: {error}", message.id);
                continue;
            }
        };
        let address = ProtocolAddress::new(
            opened.from.clone(),
            device_id_from_u32(opened.from_device).map_err(|e| e.to_string())?,
        );
        match core.device.decrypt(&address, &opened.message).await {
            Ok(payload) => {
                // Payload ist gefrankt (K_f vorangestellt); entrahmen, sonst
                // roh anzeigen (ältere, ungefrankte Nachrichten).
                let text = match client_app::franking::unfrank(&payload) {
                    Ok(opened_msg) => String::from_utf8_lossy(&opened_msg.message).to_string(),
                    Err(_) => String::from_utf8_lossy(&payload).to_string(),
                };
                received.push((opened.from.clone(), text));
                acked.push(message.id.clone());
            }
            Err(error) => {
                leptos::logging::warn!("Hülle {} nicht entschlüsselbar: {error}", message.id);
                // Bestätigen trotzdem, sonst bleibt sie für immer liegen
                // (der Ratchet kennt den Schlüssel nicht mehr).
                acked.push(message.id.clone());
            }
        }
    }
    if !acked.is_empty() {
        delivery
            .ack(&core.token, &acked)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(received)
}

/// Hält den Hinweiskanal offen: die Browser-Seite des Vertrags aus
/// `client_app::delivery`. Die Schleife fasst den Client-Zustand nie an,
/// sie zählt nur das Hinweis-Signal hoch; den Abruf stößt ein Effect an,
/// sobald die Oberfläche frei ist (kein RefCell-Borrow über await).
/// Maschinen-Benachrichtigungen (integrations-Dienst) laufen in eine
/// eigene Liste, getrennt vom Krypto-Status und vom E2E-Chat.
fn start_hint_channel(
    token: String,
    set_hints: WriteSignal<u64>,
    set_status: WriteSignal<String>,
    set_notifications: WriteSignal<Vec<String>>,
    set_connected: WriteSignal<bool>,
) {
    spawn_local(async move {
        let url = client_app::delivery::ws_url(&delivery_url());
        let mut socket = match WebSocket::open(&url) {
            Ok(socket) => socket,
            Err(error) => {
                set_connected.set(false);
                set_status.set(format!("Echtzeit-Kanal nicht erreichbar: {error}"));
                return;
            }
        };
        if let Err(error) = socket.send(WsMessage::Text(ws_auth_frame(&token))).await {
            set_connected.set(false);
            set_status.set(format!("Echtzeit-Kanal: Auth nicht gesendet: {error}"));
            return;
        }
        // Auth gesendet, der Kanal steht bis zum Schliessen oder Fehler.
        set_connected.set(true);
        while let Some(frame) = socket.next().await {
            match frame {
                Ok(WsMessage::Text(text)) => match parse_ws_event(&text) {
                    Some(WsEvent::MessageWaiting) => set_hints.update(|n| *n += 1),
                    Some(WsEvent::Notification { tenant, title }) => {
                        set_notifications.update(|list| list.push(format!("{tenant}: {title}")));
                    }
                    // Unbekannte und unlesbare Frames bewusst still: neue
                    // Server-Events dürfen alte Clients nicht stören.
                    Some(WsEvent::Other { .. }) | None => {}
                },
                Ok(WsMessage::Bytes(_)) => {}
                Err(error) => {
                    set_connected.set(false);
                    set_status.set(format!("Echtzeit-Kanal gestört: {error}"));
                    return;
                }
            }
        }
        // [ANNAHME: kein automatischer Wiederverbinder, wie beim CLI; der
        // Abruf-Knopf bleibt als Rückfallebene sichtbar.]
        set_connected.set(false);
        set_status.set("Echtzeit-Kanal geschlossen; Abrufen weiter per Knopf.".to_string());
    });
}

/// Die KT-Selbstprüfung für das eigene Konto (kt-Modul in client-app):
/// Commitment aus Konto-Schlüssel und eigener Gerätemenge nachrechnen,
/// Beweis gegen die signierte Wurzel verifizieren. Alarm (`true` im
/// Fehler-Tupel) und gewöhnlicher Fehler werden getrennt gemeldet, weil
/// nur ersterer ein Sicherheitssignal ist; ein kt-Ausfall ist keiner.
async fn kt_self_check(core: &Core) -> Result<String, (bool, String)> {
    let profile =
        load_profile(&core.storage).ok_or((false, "Kein Profil in der Ablage".to_string()))?;
    let seed: [u8; 32] = BASE64
        .decode(&profile.account_seed)
        .map_err(|e| (false, format!("Konto-Seed unlesbar: {e}")))?
        .try_into()
        .map_err(|_| (false, "Konto-Seed hat die falsche Länge".to_string()))?;
    let account = IdentityKeypair::from_seed(&seed);
    let devices = IdentityClient::new(identity_url())
        .devices(&core.token)
        .await
        .map_err(|e| (false, format!("Gerätemenge nicht abrufbar: {e}")))?;
    match KtClient::new(kt_url())
        .verify_self(&core.handle, &account.public_b64(), &devices, None)
        .await
    {
        Ok(check) => Ok(format!(
            "Eigener KT-Eintrag stimmt (Epoche {}, Version {}).",
            check.epoch, check.version
        )),
        Err(ClientError::KeyTransparency(detail)) => Err((true, format!("KT-ALARM: {detail}"))),
        Err(other) => Err((false, format!("KT-Prüfung nicht möglich: {other}"))),
    }
}

/// Startzustand der Oberfläche, Ergebnis der Ablage-Hydration.
#[derive(Clone, PartialEq)]
enum Boot {
    /// IndexedDB wird noch gelesen.
    Loading,
    /// Keine Identität in der Ablage: Registrierungs-Formular.
    Fresh,
    /// Profil vorhanden: Anmelde-Formular für dieses Handle.
    Known(String),
    /// Ablage nicht nutzbar (etwa privates Fenster ohne IndexedDB).
    Broken(String),
}

#[component]
fn App() -> impl IntoView {
    let core: SharedCore = SendWrapper::new(Rc::new(RefCell::new(None)));
    // Die hydratisierte Ablage, bis Login/Registrierung sie in den Core
    // übernehmen; getrennt vom Core, weil sie vor der Anmeldung existiert.
    let boot_storage: SharedBoot = SendWrapper::new(Rc::new(RefCell::new(None)));
    let (boot, set_boot) = signal(Boot::Loading);
    let (logged_in, set_logged_in) = signal(false);
    let (status, set_status) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (me, set_me) = signal(String::new());
    let (handle_input, set_handle_input) = signal(String::new());
    let (password_input, set_password_input) = signal(String::new());
    let (text_input, set_text_input) = signal(String::new());
    // Die Unterhaltungen der Seitenleiste (jüngste zuerst) und der offene
    // Chat. Der Verlauf des offenen Chats liegt in `messages`.
    let (chats, set_chats) = signal(Vec::<ChatSummary>::new());
    let (selected, set_selected) = signal(Option::<String>::None);
    // Der Verlauf des offenen Chats; beim Wechsel aus der Ablage geladen.
    let (messages, set_messages) = signal(Vec::<StoredLine>::new());
    // Frist-Auswahl des Composers in Sekunden (0 = aus); setzt expires_at.
    let (ttl_choice, set_ttl_choice) = signal(0u64);
    // "Neuer Chat": ob das Handle-Feld offen ist und sein Inhalt.
    let (new_chat_open, set_new_chat_open) = signal(false);
    let (new_chat_input, set_new_chat_input) = signal(String::new());
    // Ob die Sicherheitsnummer im Thread aufgeklappt ist.
    let (safety_open, set_safety_open) = signal(false);
    // Bleibender Verbindungszustand des Echtzeit-Kanals (Chat-Kopf).
    let (connected, set_connected) = signal(false);
    // Zähler der message.waiting-Hinweise vom Echtzeit-Kanal; der Effect
    // weiter unten holt ab, sobald die Oberfläche frei ist.
    let (hints, set_hints) = signal(0u64);
    let handled_hints = StoredValue::new(0u64);
    // (Kontakt, gruppierte Nummer) der zuletzt gezeigten Sicherheitsnummer.
    let (safety_info, set_safety_info) = signal(Option::<(String, String)>::None);
    // Ergebnis der KT-Selbstprüfung: (bestanden, Meldung).
    let (kt_info, set_kt_info) = signal(Option::<(bool, String)>::None);
    // Maschinen-Benachrichtigungen vom integrations-Dienst, getrennt vom
    // Krypto-Status und vom E2E-Chat (design-system.md, Status-Trennung).
    let (notifications, set_notifications) = signal(Vec::<String>::new());
    // Gewählter Darstellungs-Modus (system/hell/dunkel/midnight); der
    // FOUC-Guard in index.html hat ihn beim Laden schon angewandt.
    let (theme, set_theme) = signal(stored_theme());
    // Fokusziel beim Chat-Wechsel: der Kontaktname im Chat-Kopf (SC 2.4.3).
    let chat_name_ref = NodeRef::<leptos::html::H2>::new();

    // Die Ablage des aktiven Cores, für die synchronen Listen-Handler
    // (Auswahl, Neuer Chat) außerhalb der async-Abläufe.
    let current_storage = {
        let core = core.clone();
        move || core.borrow().as_ref().map(|c| c.storage.clone())
    };

    // Hydration: einmal beim Start die Ablage öffnen und entscheiden,
    // welches Formular gezeigt wird.
    {
        let boot_storage = boot_storage.clone();
        spawn_local(async move {
            match BrowserStorage::open().await {
                Ok(storage) => {
                    let storage: SharedStorage = Rc::new(RefCell::new(storage));
                    let known = load_profile(&storage).map(|p| p.handle);
                    *boot_storage.borrow_mut() = Some(storage);
                    set_boot.set(match known {
                        Some(handle) => Boot::Known(handle),
                        None => Boot::Fresh,
                    });
                }
                Err(error) => set_boot.set(Boot::Broken(error)),
            }
        });
    }

    let on_register = {
        let core = core.clone();
        let boot_storage = boot_storage.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = boot_storage.borrow().clone() else {
                set_status.set("Ablage noch nicht bereit.".to_string());
                return;
            };
            let handle = handle_input.get_untracked();
            let password = password_input.get_untracked();
            if handle.is_empty() || password.is_empty() {
                set_status.set("Handle und Passwort angeben.".to_string());
                return;
            }
            set_busy.set(true);
            set_status.set("Konto wird angelegt ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                match onboard(storage, handle.clone(), password).await {
                    Ok(new_core) => {
                        start_hint_channel(
                            new_core.token.clone(),
                            set_hints,
                            set_status,
                            set_notifications,
                            set_connected,
                        );
                        let storage = new_core.storage.clone();
                        *core.borrow_mut() = Some(new_core);
                        set_chats.set(load_summaries(&storage));
                        set_me.set(handle);
                        set_logged_in.set(true);
                        set_status.set("Bereit.".to_string());
                    }
                    Err(error) => set_status.set(format!("Fehlgeschlagen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    let on_login = {
        let core = core.clone();
        let boot_storage = boot_storage.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = boot_storage.borrow().clone() else {
                set_status.set("Ablage noch nicht bereit.".to_string());
                return;
            };
            let password = password_input.get_untracked();
            if password.is_empty() {
                set_status.set("Passwort angeben.".to_string());
                return;
            }
            set_busy.set(true);
            set_status.set("Anmeldung ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                match login(storage, password).await {
                    Ok(new_core) => {
                        start_hint_channel(
                            new_core.token.clone(),
                            set_hints,
                            set_status,
                            set_notifications,
                            set_connected,
                        );
                        set_me.set(new_core.handle.clone());
                        let storage = new_core.storage.clone();
                        *core.borrow_mut() = Some(new_core);
                        set_chats.set(load_summaries(&storage));
                        set_logged_in.set(true);
                        set_status.set("Bereit; Sitzungen aus der Ablage geladen.".to_string());
                        // Was schon wartet, kündigt kein Hinweis mehr an:
                        // einmal initial abholen (wie sm listen).
                        set_hints.update(|n| *n += 1);
                    }
                    Err(error) => set_status.set(format!("Anmeldung fehlgeschlagen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Der Sende-Ablauf, geteilt zwischen Knopf und Enter-Taste im Textfeld.
    // Sendet an den offenen Chat und legt die Nachricht in dessen Verlauf ab.
    let run_send = SendWrapper::new(Rc::new({
        let core = core.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                set_status.set("Zuerst links einen Chat wählen.".to_string());
                return;
            };
            let text = text_input.get_untracked();
            if text.is_empty() {
                set_status.set("Text angeben.".to_string());
                return;
            }
            let ttl = ttl_choice.get_untracked();
            let expires_at = (ttl > 0).then(|| now_unix() + ttl);
            set_busy.set(true);
            set_status.set("Wird gesendet ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                // Den Core für die Dauer der Operation herausnehmen statt
                // den RefCell-Borrow über await zu halten (clippy
                // await_holding_refcell_ref): ein zweiter Task sähe sonst
                // einen Panic statt eines sauberen "beschäftigt".
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let storage = active.storage.clone();
                        let who = active.handle.clone();
                        let result = send_message(&mut active, &peer, &text, expires_at).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(()) => {
                                let line = StoredLine {
                                    from: who,
                                    text: text.clone(),
                                    at: now_unix(),
                                };
                                let summaries =
                                    record_message(&storage, &peer, line.clone(), false);
                                set_chats.set(summaries);
                                // Anzeige und Composer nur berühren, wenn der
                                // Chat noch offen ist: der Nutzer kann während
                                // des Sendens gewechselt und einen neuen
                                // Entwurf getippt haben, der nicht verloren
                                // gehen darf.
                                if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                                    set_messages.update(|list| push_capped(list, line));
                                    set_text_input.set(String::new());
                                }
                                set_status.set(String::new());
                            }
                            Err(error) => set_status.set(format!("Senden fehlgeschlagen: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    }));

    let on_send = {
        let run_send = run_send.clone();
        move |_| run_send()
    };
    let on_message_key = {
        let run_send = run_send.clone();
        move |ev: web_sys::KeyboardEvent| {
            // Enter sendet, Umschalt-Enter bleibt für einen Zeilenumbruch frei.
            if ev.key() == "Enter" && !ev.shift_key() {
                ev.prevent_default();
                run_send();
            }
        }
    };

    // Der Abhol-Ablauf, geteilt zwischen Knopf und Hinweis-Effect.
    let run_fetch = SendWrapper::new(Rc::new({
        let core = core.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            let core = core.clone();
            spawn_local(async move {
                // Herausnehmen statt Borrow über await halten, wie beim
                // Senden (clippy await_holding_refcell_ref).
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let storage = active.storage.clone();
                        let result = fetch_messages(&mut active).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(received) if received.is_empty() => {
                                set_status.set("Keine neuen Nachrichten.".to_string());
                            }
                            Ok(received) => {
                                let open = selected.get_untracked();
                                let mut summaries = None;
                                for (sender, text) in received {
                                    let for_open = open.as_deref() == Some(sender.as_str());
                                    let line = StoredLine {
                                        from: sender.clone(),
                                        text,
                                        at: now_unix(),
                                    };
                                    // Nur eine noch nicht offene Unterhaltung
                                    // zählt ungelesen hoch.
                                    summaries = Some(record_message(
                                        &storage,
                                        &sender,
                                        line.clone(),
                                        !for_open,
                                    ));
                                    if for_open {
                                        set_messages.update(|list| push_capped(list, line));
                                    }
                                }
                                if let Some(summaries) = summaries {
                                    set_chats.set(summaries);
                                }
                                set_status.set(String::new());
                            }
                            Err(error) => set_status.set(format!("Abruf fehlgeschlagen: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    }));

    let on_fetch = {
        let run_fetch = run_fetch.clone();
        move |_| run_fetch()
    };

    // Holt nach jedem Hinweis ab, sobald die Oberfläche frei ist: der
    // Effect läuft erneut, wenn busy zurück auf false kippt, und sieht
    // dann noch unbehandelte Hinweise. Verpasst wird so keiner.
    {
        let run_fetch = run_fetch.clone();
        Effect::new(move |_| {
            let pending = hints.get();
            let currently_busy = busy.get();
            if logged_in.get() && !currently_busy && pending > handled_hints.get_value() {
                handled_hints.set_value(pending);
                run_fetch();
            }
        });
    }

    // Blendet die Sicherheitsnummer des offenen Chats ein oder aus. Beim
    // Öffnen wird sie für den ausgewählten Kontakt berechnet.
    let on_safety = {
        let core = core.clone();
        move |_| {
            if safety_open.get_untracked() {
                set_safety_open.set(false);
                return;
            }
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            set_busy.set(true);
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let result = match device_id_from_u32(PROTOCOL_DEVICE_ID) {
                            Ok(id) => {
                                let address = ProtocolAddress::new(peer.clone(), id);
                                active
                                    .device
                                    .safety_number(&address)
                                    .await
                                    .map_err(|e| e.to_string())
                            }
                            Err(error) => Err(error.to_string()),
                        };
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(Some(number)) => {
                                set_safety_info.set(Some((peer, group_safety_number(&number))));
                                set_safety_open.set(true);
                                set_status.set(String::new());
                            }
                            Ok(None) => {
                                set_safety_info.set(None);
                                set_safety_open.set(true);
                            }
                            Err(error) => set_status.set(format!("Sicherheitsnummer: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    };

    // Einen Chat öffnen: Verlauf laden, ungelesen zurücksetzen, auswählen.
    let open_chat = {
        let current_storage = current_storage.clone();
        move |peer: String| {
            let Some(storage) = current_storage() else {
                return;
            };
            set_messages.set(load_history(&storage, &peer));
            set_chats.set(mark_read(&storage, &peer));
            set_safety_open.set(false);
            set_safety_info.set(None);
            set_selected.set(Some(peer));
        }
    };

    let on_back = move |_| {
        set_selected.set(None);
        set_safety_open.set(false);
    };

    // "Neuer Chat" bestätigen: Handle in die Liste aufnehmen und öffnen.
    let on_new_chat_confirm = {
        let open_chat = open_chat.clone();
        let current_storage = current_storage.clone();
        move || {
            let peer = new_chat_input.get_untracked().trim().to_string();
            if peer.is_empty() {
                return;
            }
            if let Some(storage) = current_storage() {
                set_chats.set(ensure_chat(&storage, &peer));
            }
            set_new_chat_input.set(String::new());
            set_new_chat_open.set(false);
            open_chat(peer);
        }
    };

    // Fokus-Mitführung beim Chat-Wechsel (SC 2.4.3): der Kontaktname im
    // Chat-Kopf. Erst nach dem Render, sonst zeigt der NodeRef ins Leere.
    Effect::new(move |_| {
        if selected.get().is_some() {
            let name_ref = chat_name_ref;
            request_animation_frame(move || {
                if let Some(el) = name_ref.get_untracked() {
                    let _ = el.focus();
                }
            });
        }
    });

    let on_kt_check = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            set_kt_info.set(None);
            set_status.set("Key-Transparency-Prüfung ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                match taken {
                    Some(active) => {
                        let result = kt_self_check(&active).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(message) => {
                                set_kt_info.set(Some((true, message)));
                                set_status.set(String::new());
                            }
                            // Der Alarm bleibt als rote Zeile stehen; ein
                            // gewöhnlicher Fehler ist nur Status.
                            Err((true, message)) => {
                                set_kt_info.set(Some((false, message)));
                                set_status.set(String::new());
                            }
                            Err((false, message)) => set_status.set(message),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    };

    view! {
        <div class="sm-app" class=("has-selection", move || selected.get().is_some())>
            <header class="sm-header" role="banner">
                <h1>"SecureMessenger"</h1>
                {move || {
                    logged_in
                        .get()
                        .then(|| {
                            view! {
                                <span class="sm-identity">"Angemeldet als " <strong>{me}</strong></span>
                            }
                        })
                }}
                <div class="sm-theme-switch">
                    <label for="sm-theme-select">"Darstellung"</label>
                    <select
                        id="sm-theme-select"
                        prop:value=theme
                        on:change=move |ev| {
                            let choice = event_target_value(&ev);
                            apply_theme(&choice);
                            set_theme.set(choice);
                        }
                    >
                        <option value="system">"System"</option>
                        <option value="hell">"Hell"</option>
                        <option value="dunkel">"Dunkel"</option>
                        <option value="midnight">"Mitternacht"</option>
                    </select>
                </div>
            </header>

            {move || {
                if logged_in.get() {
                    let open_chat_list = open_chat.clone();
                    let confirm_click = on_new_chat_confirm.clone();
                    let confirm_key = on_new_chat_confirm.clone();
                    // Frische Klone der Thread-Handler: die innere, auf `selected`
                    // reagierende Closure besitzt eigene Kopien, die äußere
                    // Closure behält ihre Originale für den nächsten Lauf.
                    // `on_back` fängt nur Copy-Signale ein und ist selbst Copy,
                    // braucht also keinen Klon.
                    let on_safety = on_safety.clone();
                    let on_send = on_send.clone();
                    let on_fetch = on_fetch.clone();
                    let on_message_key = on_message_key.clone();
                    view! {
                        <div class="sm-shell">
                            <nav class="sm-sidebar" aria-label="Konversationen">
                                <div class="sm-sidebar-head">
                                    <h2>"Chats"</h2>
                                    <button
                                        type="button"
                                        class="sm-primary"
                                        on:click=move |_| {
                                            set_new_chat_open.update(|open| *open = !*open)
                                        }
                                    >
                                        "Neuer Chat"
                                    </button>
                                </div>
                                {move || {
                                    new_chat_open
                                        .get()
                                        .then(|| {
                                            let confirm_click = confirm_click.clone();
                                            let confirm_key = confirm_key.clone();
                                            view! {
                                                <div class="sm-sidebar-head">
                                                    <div class="sm-field">
                                                        <label for="sm-newchat">"Handle des Kontakts"</label>
                                                        <input
                                                            id="sm-newchat"
                                                            prop:value=new_chat_input
                                                            on:input=move |ev| {
                                                                set_new_chat_input
                                                                    .set(event_target_value(&ev))
                                                            }
                                                            on:keydown=move |ev: web_sys::KeyboardEvent| {
                                                                if ev.key() == "Enter" {
                                                                    ev.prevent_default();
                                                                    (confirm_key)();
                                                                }
                                                            }
                                                        />
                                                    </div>
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=move |_| (confirm_click)()
                                                    >
                                                        "Öffnen"
                                                    </button>
                                                </div>
                                            }
                                        })
                                }}
                                <ul class="sm-convos">
                                    {move || {
                                        let sel = selected.get();
                                        let list = chats.get();
                                        if list.is_empty() {
                                            view! {
                                                <li class="sm-empty">
                                                    <p>
                                                        "Noch keine Unterhaltungen. Mit "
                                                        "'Neuer Chat' die erste beginnen."
                                                    </p>
                                                </li>
                                            }
                                                .into_any()
                                        } else {
                                            let open_chat_list = open_chat_list.clone();
                                            list.into_iter()
                                                .map(|chat| {
                                                    let peer = chat.peer.clone();
                                                    let is_sel = sel.as_deref() == Some(peer.as_str());
                                                    let has_unread = chat.unread > 0;
                                                    let unread = chat.unread;
                                                    let open = open_chat_list.clone();
                                                    let click_peer = peer.clone();
                                                    view! {
                                                        <li>
                                                            <button
                                                                type="button"
                                                                class="sm-convo"
                                                                class=("sm-has-unread", has_unread)
                                                                aria-current=if is_sel { "true" } else { "false" }
                                                                on:click=move |_| open(click_peer.clone())
                                                            >
                                                                <span
                                                                    class="sm-avatar"
                                                                    aria-hidden="true"
                                                                    style=avatar_style(&peer)
                                                                >
                                                                    {avatar_initial(&peer)}
                                                                </span>
                                                                <span class="sm-convo-name">
                                                                    {peer.clone()}
                                                                </span>
                                                                <span class="sm-convo-snippet">
                                                                    {chat.snippet.clone()}
                                                                </span>
                                                                {has_unread
                                                                    .then(|| {
                                                                        view! {
                                                                            <span
                                                                                class="sm-unread"
                                                                                aria-label=format!(
                                                                                    "{unread} ungelesene Nachrichten",
                                                                                )
                                                                            >
                                                                                {unread}
                                                                            </span>
                                                                        }
                                                                    })}
                                                            </button>
                                                        </li>
                                                    }
                                                })
                                                .collect_view()
                                                .into_any()
                                        }
                                    }}
                                </ul>
                                <div class="sm-sidebar-foot">
                                    <button
                                        type="button"
                                        class="sm-secondary"
                                        on:click=on_kt_check.clone()
                                        disabled=busy
                                    >
                                        "Schlüssel prüfen (KT)"
                                    </button>
                                    {move || {
                                        kt_info
                                            .get()
                                            .map(|(ok, message)| {
                                                if ok {
                                                    view! { <p class="sm-note sm-ok">{message}</p> }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <p class="sm-note sm-warn" role="alert">
                                                            {message}
                                                        </p>
                                                    }
                                                        .into_any()
                                                }
                                            })
                                    }}
                                    <p class="sm-caution">
                                        "Geräte-Identität, Sitzungen und Kontakte liegen "
                                        "unverschlüsselt in IndexedDB dieses Browser-Profils. Der "
                                        "Browser ist das kryptografisch schwächste Glied der "
                                        "Plattform (sicherheit.md)."
                                    </p>
                                </div>
                            </nav>

                            <main class="sm-thread" aria-label="Unterhaltung">
                                {move || {
                                    match selected.get() {
                                        None => {
                                            view! {
                                                <div class="sm-empty">
                                                    <p>
                                                        "Links eine Unterhaltung wählen oder mit "
                                                        "'Neuer Chat' eine neue beginnen. Alle "
                                                        "Nachrichten sind Ende-zu-Ende verschlüsselt."
                                                    </p>
                                                </div>
                                            }
                                                .into_any()
                                        }
                                        Some(peer) => {
                                            view! {
                                                <div class="sm-chat-head">
                                                    <button
                                                        type="button"
                                                        class="sm-back sm-secondary"
                                                        aria-label="Zurück zur Liste"
                                                        on:click=on_back
                                                    >
                                                        "Zurück"
                                                    </button>
                                                    <h2
                                                        class="sm-chat-name"
                                                        tabindex="-1"
                                                        node_ref=chat_name_ref
                                                    >
                                                        {peer.clone()}
                                                    </h2>
                                                    {move || {
                                                        if connected.get() {
                                                            view! {
                                                                <span class="sm-conn sm-on">
                                                                    <span aria-hidden="true">"●"</span>
                                                                    "Verbunden"
                                                                </span>
                                                            }
                                                                .into_any()
                                                        } else {
                                                            view! {
                                                                <span class="sm-conn sm-off">
                                                                    <span aria-hidden="true">"○"</span>
                                                                    "Getrennt, Abrufen weiter per Knopf."
                                                                </span>
                                                            }
                                                                .into_any()
                                                        }
                                                    }}
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=on_safety.clone()
                                                        disabled=busy
                                                    >
                                                        "Sicherheitsnummer"
                                                    </button>
                                                </div>

                                                {move || {
                                                    safety_open
                                                        .get()
                                                        .then(|| {
                                                            match safety_info.get() {
                                                                Some((contact, number)) => {
                                                                    view! {
                                                                        <div
                                                                            class="sm-safety"
                                                                            role="group"
                                                                            aria-label="Sicherheitsnummer"
                                                                        >
                                                                            <p>
                                                                                "Diese Nummer über einen zweiten Kanal mit "
                                                                                <strong>{contact}</strong>
                                                                                " vergleichen. Stimmt sie, ist die Verbindung "
                                                                                "nicht umgeleitet."
                                                                            </p>
                                                                            <p class="sm-fingerprint">{number}</p>
                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                }
                                                                None => {
                                                                    view! {
                                                                        <div class="sm-safety">
                                                                            <p>
                                                                                "Die Sicherheitsnummer entsteht mit der "
                                                                                "ersten gesendeten oder empfangenen Nachricht."
                                                                            </p>
                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                }
                                                            }
                                                        })
                                                }}

                                                <ul
                                                    class="sm-log"
                                                    role="log"
                                                    aria-label="Nachrichtenverlauf"
                                                    aria-live="polite"
                                                    aria-relevant="additions"
                                                    aria-atomic="false"
                                                >
                                                    {move || {
                                                        let own = me.get();
                                                        let msgs = messages.get();
                                                        if msgs.is_empty() {
                                                            view! {
                                                                <li class="sm-status">
                                                                    "Ende-zu-Ende verschlüsselt. Vor der ersten "
                                                                    "Nachricht die Sicherheitsnummer vergleichen, "
                                                                    "damit die Verbindung nicht umgeleitet ist."
                                                                </li>
                                                            }
                                                                .into_any()
                                                        } else {
                                                            msgs.into_iter()
                                                                .map(|line| {
                                                                    let class = if line.from == own {
                                                                        "sm-msg sm-mine"
                                                                    } else {
                                                                        "sm-msg"
                                                                    };
                                                                    view! {
                                                                        <li class=class>
                                                                            <span class="sm-msg-from">{line.from}</span>
                                                                            <span class="sm-msg-text">{line.text}</span>
                                                                            <span class="sm-msg-time">
                                                                                {format_time(line.at)}
                                                                            </span>
                                                                        </li>
                                                                    }
                                                                })
                                                                .collect_view()
                                                                .into_any()
                                                        }
                                                    }}
                                                </ul>

                                                <div class="sm-composer">
                                                    <div class="sm-field">
                                                        <label for="sm-msg">"Nachricht (Enter sendet)"</label>
                                                        <input
                                                            id="sm-msg"
                                                            prop:value=text_input
                                                            on:input=move |ev| {
                                                                set_text_input.set(event_target_value(&ev))
                                                            }
                                                            on:keydown=on_message_key.clone()
                                                        />
                                                    </div>
                                                    <div class="sm-field">
                                                        <label for="sm-ttl">"Frist"</label>
                                                        <select
                                                            id="sm-ttl"
                                                            class="sm-ttl"
                                                            prop:value=move || ttl_choice.get().to_string()
                                                            on:change=move |ev| {
                                                                let secs = event_target_value(&ev)
                                                                    .parse::<u64>()
                                                                    .unwrap_or(0);
                                                                set_ttl_choice.set(secs);
                                                            }
                                                        >
                                                            <option value="0">"Aus"</option>
                                                            <option value="300">"5 Minuten"</option>
                                                            <option value="3600">"1 Stunde"</option>
                                                            <option value="86400">"1 Tag"</option>
                                                            <option value="604800">"1 Woche"</option>
                                                        </select>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        class="sm-primary"
                                                        on:click=on_send.clone()
                                                        disabled=busy
                                                    >
                                                        "Senden"
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=on_fetch.clone()
                                                        disabled=busy
                                                    >
                                                        "Abrufen"
                                                    </button>
                                                </div>
                                            }
                                                .into_any()
                                        }
                                    }
                                }}
                                <p class="sm-status" role="status" aria-live="polite">{status}</p>
                            </main>
                        </div>

                        {move || {
                            let items = notifications.get();
                            (!items.is_empty())
                                .then(|| {
                                    view! {
                                        <aside
                                            class="sm-notify"
                                            role="complementary"
                                            aria-label="Benachrichtigungen"
                                            aria-live="polite"
                                        >
                                            <h2>"Benachrichtigungen"</h2>
                                            <ul>
                                                {items
                                                    .into_iter()
                                                    .map(|n| view! { <li>{n}</li> })
                                                    .collect_view()}
                                            </ul>
                                        </aside>
                                    }
                                })
                        }}
                    }
                        .into_any()
                } else {
                    view! {
                        <main class="sm-main">
                            {match boot.get() {
                                    Boot::Loading => {
                                        view! { <p class="sm-status">"Ablage wird geladen ..."</p> }
                                            .into_any()
                                    }
                                    Boot::Broken(error) => {
                                        view! {
                                            <p class="sm-note sm-warn" role="alert">
                                                {format!(
                                                    "Ablage nicht verfügbar: {error}. Ohne IndexedDB (z. B. \
                                                     privates Fenster) kann dieser Client keine Identität \
                                                     halten.",
                                                )}
                                            </p>
                                        }
                                            .into_any()
                                    }
                                    Boot::Known(handle) => {
                                        view! {
                                            <section class="sm-card" aria-label="Anmelden">
                                                <h2>
                                                    {format!("Konto '{handle}' auf diesem Gerät gefunden")}
                                                </h2>
                                                <div class="sm-field">
                                                    <label for="sm-pass">"Passwort"</label>
                                                    <input
                                                        id="sm-pass"
                                                        type="password"
                                                        prop:value=password_input
                                                        on:input=move |ev| {
                                                            set_password_input.set(event_target_value(&ev))
                                                        }
                                                    />
                                                </div>
                                                <div class="sm-row">
                                                    <button
                                                        type="button"
                                                        class="sm-primary"
                                                        on:click=on_login.clone()
                                                        disabled=busy
                                                    >
                                                        "Anmelden"
                                                    </button>
                                                </div>
                                            </section>
                                        }
                                            .into_any()
                                    }
                                    Boot::Fresh => {
                                        view! {
                                            <section class="sm-card" aria-label="Konto anlegen">
                                                <h2>"Konto anlegen"</h2>
                                                <p class="sm-status">
                                                    "Registrierung, Anmeldung und Prekey-Veröffentlichung "
                                                    "in einem Schritt."
                                                </p>
                                                <div class="sm-field">
                                                    <label for="sm-handle">"Handle (a-z, 0-9, _ . -)"</label>
                                                    <input
                                                        id="sm-handle"
                                                        prop:value=handle_input
                                                        on:input=move |ev| {
                                                            set_handle_input.set(event_target_value(&ev))
                                                        }
                                                    />
                                                </div>
                                                <div class="sm-field">
                                                    <label for="sm-newpass">
                                                        "Passwort (mindestens 12 Zeichen)"
                                                    </label>
                                                    <input
                                                        id="sm-newpass"
                                                        type="password"
                                                        prop:value=password_input
                                                        on:input=move |ev| {
                                                            set_password_input.set(event_target_value(&ev))
                                                        }
                                                    />
                                                </div>
                                                <div class="sm-row">
                                                    <button
                                                        type="button"
                                                        class="sm-primary"
                                                        on:click=on_register.clone()
                                                        disabled=busy
                                                    >
                                                        "Konto anlegen"
                                                    </button>
                                                </div>
                                            </section>
                                        }
                                            .into_any()
                                    }
                                }
                            }
                            <p class="sm-status" role="status" aria-live="polite">{status}</p>
                        </main>
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

/// Startet die App: Panic-Ausgaben in die Browser-Konsole, dann mounten.
pub fn run() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
