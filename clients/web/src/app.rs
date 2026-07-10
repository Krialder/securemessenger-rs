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
//! Browser-Profil. Der Empfang läuft in Echtzeit über den
//! gloo-net-Hinweiskanal (mit Wiederverbindung nach Abbruch), der
//! Abruf-Knopf bleibt als Rückfallebene. Die IndexedDB-Ablage ist mit dem
//! Login-Passwort verschlüsselt (keystore, storage.rs); ein verschlüsseltes
//! Konto ist beim Start ein eigener Boot-Zustand (`Locked`), weil der
//! Handle vor dem Entsperren im gesealten Blob steckt. Der Web-Client
//! bleibt laut sicherheit.md das kryptografisch schwächste Glied (kein
//! OS-Keystore, XSS-Fläche, Schlüssel im Speicher während der Sitzung); die
//! Oberfläche sagt das sichtbar an, statt es zu kaschieren.]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

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
use futures_util::future::{select, Either};
use futures_util::{SinkExt as _, StreamExt as _};
use gloo_net::websocket::{futures::WebSocket, Message as WsMessage, WebSocketError};
use gloo_timers::future::sleep;
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
/// `report_id` ist die Zustell-ID einer empfangenen, gefrankten Nachricht:
/// der Schlüssel zum Franking-Material in der Ablage (`franking/<id>`) und
/// damit die Voraussetzung fürs Melden. Eigene und ältere, ungefrankte
/// Zeilen haben keine; `serde(default)` hält alte Verläufe lesbar.
#[derive(Serialize, Deserialize, Clone)]
struct StoredLine {
    from: String,
    text: String,
    at: u64,
    #[serde(default)]
    report_id: Option<String>,
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
    storage: SharedStorage,
}

/// Was eine erfolgreiche An- oder Neuanmeldung liefert: das Gerät und das
/// frische Token-Paar samt Laufzeit. Der Zugriffstoken wandert in ein
/// app-weites Signal (damit WS-Kanal und Anfragen immer den aktuellen
/// nutzen), der Refresh-Token in die Rotation.
struct Onboarded {
    core: Core,
    access_token: String,
    refresh_token: String,
    expires_in: u64,
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
async fn onboard(
    storage: SharedStorage,
    handle: String,
    password: String,
) -> Result<Onboarded, String> {
    // Ab dem ersten Schreibvorgang verschlüsseln: bei der Registrierung
    // steht das Passwort durch die eigene Wahl fest, es gibt keine
    // vorhandenen Daten, die ein falsches Passwort gefährden könnte.
    storage.borrow_mut().adopt_passphrase(&password);
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

    Ok(Onboarded {
        core: Core {
            device,
            handle,
            storage,
        },
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
    })
}

/// Anmeldung nach einem Neuladen: das Profil kommt aus der Ablage, die
/// Geräte-Identität und alle Sitzungen liegen schon im Protokoll-Store;
/// nur das Passwort muss der Nutzer neu eingeben (Tokens werden bewusst
/// nicht persistiert, siehe Modulkopf).
async fn login(storage: SharedStorage, password: String) -> Result<Onboarded, String> {
    // Eine verschlüsselte Ablage zuerst entsperren; ein falsches Passwort
    // scheitert hier, noch vor dem Server. Bei Klartext oder frisch ist das
    // ein No-op.
    storage
        .borrow_mut()
        .unlock(&password)
        .map_err(|e| format!("Ablage nicht entsperrbar: {e}"))?;
    let profile = load_profile(&storage).ok_or_else(|| "Kein Profil in der Ablage".to_string())?;
    let session = IdentityClient::new(identity_url())
        .login(&profile.handle, &password, &profile.device_id)
        .await
        .map_err(|e| e.to_string())?;
    // Nach der Server-Bestätigung eine noch unverschlüsselte Ablage
    // (Migration einer alten Klartext-Ablage) verschlüsseln; bei einer schon
    // entsperrten gesealten Ablage ist das ein No-op.
    storage.borrow_mut().adopt_passphrase(&password);
    let next_prekey_id = load_counter(&storage)?;
    let device = Device::with_store(
        &profile.handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        next_prekey_id,
    )
    .map_err(|e| e.to_string())?;
    Ok(Onboarded {
        core: Core {
            device,
            handle: profile.handle,
            storage,
        },
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
    })
}

/// Wartezeit bis zur nächsten Erneuerung: 60 s vor dem Ablauf, aber nie
/// länger als die halbe Laufzeit (sonst wäre ein kurzes Entwicklungs-Token
/// schon vor der ersten Erneuerung tot) und mindestens 1 s gegen eine enge
/// Schleife bei absurden Laufzeiten.
fn refresh_wait(expires_in: u64) -> u64 {
    expires_in.saturating_sub(60).max(expires_in / 2).max(1)
}

/// Erneuert das Zugriffstoken vor dem Ablauf und rotiert dabei den
/// Refresh-Token, damit lange Sitzungen nicht nach 15 Minuten stillstehen.
/// Läuft als eigene Schleife: schlafen bis kurz vor Ablauf, erneuern, das
/// app-weite Token-Signal aktualisieren (WS-Kanal und Anfragen lesen es),
/// wiederholen. Die Token-Epoche beendet die Schleife bei Abmeldung oder
/// Konto-Wechsel. Fehler beim Erneuern sind nach Art getrennt: einen
/// Transportfehler (Netz weg, Standby, Dienst kurz nicht da) wiederholt die
/// Schleife mit Backoff, der Refresh-Token gilt ja weiter und die Sitzung
/// heilt nach der Netz-Rückkehr von selbst; ein 401 (Session widerrufen
/// oder Reuse erkannt) ist endgültig, dann endet die Schleife mit
/// sichtbarer Meldung statt still, damit die Neuanmeldung nicht erst am
/// nächsten gescheiterten Senden auffällt.
fn start_token_refresh(
    epoch: StoredValue<u64>,
    my_epoch: u64,
    refresh_token: StoredValue<String>,
    set_token: WriteSignal<String>,
    set_status: WriteSignal<String>,
    expires_in: u64,
) {
    spawn_local(async move {
        let mut wait = refresh_wait(expires_in);
        let mut backoff = 1u64;
        loop {
            sleep(Duration::from_secs(wait)).await;
            if epoch.get_value() != my_epoch {
                return;
            }
            let current = refresh_token.get_value();
            match IdentityClient::new(identity_url()).refresh(&current).await {
                Ok(session) => {
                    if epoch.get_value() != my_epoch {
                        // Abmeldung während des Roundtrips: der Logout hat
                        // das ALTE Token widerrufen, das der Server beim
                        // Rotieren aber schon entwertet hatte (No-op). Das
                        // frische Paar darf die Abmeldung nicht überleben,
                        // deshalb hier widerrufen statt es nur zu verwerfen.
                        let _ = IdentityClient::new(identity_url())
                            .logout(&session.access_token)
                            .await;
                        return;
                    }
                    set_token.set(session.access_token);
                    refresh_token.set_value(session.refresh_token);
                    wait = refresh_wait(session.expires_in);
                    backoff = 1;
                }
                // 401: der Dienst kennt den Refresh-Token nicht mehr
                // (widerrufen oder Reuse erkannt). Endgültig; 5xx und
                // andere Status fallen bewusst in den Wiederholungs-Arm,
                // ein kurzer Datenbank-Ausfall darf die Sitzung nicht
                // beenden.
                Err(ClientError::Api { status: 401, .. }) => {
                    set_status.set(
                        "Sitzung abgelaufen: Erneuerung abgelehnt, bitte neu anmelden.".to_string(),
                    );
                    return;
                }
                Err(_) => {
                    wait = backoff;
                    backoff = (backoff * 2).min(30);
                }
            }
        }
    });
}

/// Sendet eine Nachricht; baut beim ersten Kontakt die PQXDH-Sitzungen aus
/// den Verzeichnis-Bündeln auf und merkt sich die Geräte des Kontakts in
/// der Ablage (gleicher Fluss und gleiches Format wie im CLI).
///
/// `sealed` versiegelt die Nachricht (Sealed Sender): der Absender steht
/// nur mitverschlüsselt in der Hülle (Zertifikat), das Framing trägt kein
/// from-Feld, und die Zustellung läuft absichtlich ohne Token, weil ein
/// Bearer den Absender gegenüber dem Dienst identifizieren würde.
///
/// Nimmt das Token als Signal statt als Wert: zwischen Bündel-Abruf und
/// Zustellung kann die Erneuerung rotieren, und der Dienst entwertet das
/// alte Token dabei sofort. Jeder Request liest deshalb unmittelbar vorher
/// den aktuellen Stand.
async fn send_message(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    text: &str,
    expires_at: Option<u64>,
    sealed: bool,
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
            .bundles(&token.get_untracked(), peer)
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
    // Für versiegelten Versand einmal das Absender-Zertifikat besorgen
    // (gecacht in der Ablage, siehe sender_certificate_cached).
    let certificate = if sealed {
        Some(sender_certificate_cached(token, &core.storage).await?)
    } else {
        None
    };
    let mut envelopes = Vec::new();
    for target in &devices {
        let address = ProtocolAddress::new(
            peer.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let envelope = match &certificate {
            Some(certificate) => {
                let blob = core
                    .device
                    .seal_message(&address, certificate, &franked.payload)
                    .await
                    .map_err(|e| format!("Versiegeln: {e}"))?;
                wire::seal_sealed(&blob).map_err(|e| e.to_string())?
            }
            None => {
                let message = core
                    .device
                    .encrypt(&address, &franked.payload)
                    .await
                    .map_err(|e| format!("Verschlüsselung: {e}"))?;
                wire::seal(&core.handle, PROTOCOL_DEVICE_ID, &message).map_err(|e| e.to_string())?
            }
        };
        envelopes.push(OutgoingEnvelope {
            id: new_uuid(),
            recipient: peer.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
            franking_tag: Some(franking_tag.clone()),
            expires_at,
        });
    }
    let delivery = DeliveryClient::new(delivery_url());
    if sealed {
        delivery
            .submit_sealed(&envelopes)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        delivery
            .submit(&token.get_untracked(), &envelopes)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Der Trust Root zum Entsiegeln, gepinnt in der Ablage
/// (`sealed/trust_root`): der erste Abruf vertraut dem identity-Dienst
/// (Trust-on-first-use wie beim KT-Schlüssel und im CLI), danach liegt der
/// Anker lokal fest. Ein später ausgetauschter Root fällt auf, weil jedes
/// Entsiegeln scheitert.
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

/// Das Sealed-Sender-Zertifikat des eigenen Geräts, gecacht in der Ablage
/// (`sealed/certificate`): erst wenn es fehlt oder in unter fünf Minuten
/// abläuft, stellt der identity-Dienst ein frisches aus (wie im CLI; das
/// Zertifikat gilt 24 h, ein Abruf je Nachricht wäre Verschwendung).
async fn sender_certificate_cached(
    token: ReadSignal<String>,
    storage: &SharedStorage,
) -> Result<Vec<u8>, String> {
    const KEY: &str = "sealed/certificate";
    let cached = storage.borrow().get(KEY).map_err(|e| e.to_string())?;
    if let Some(bytes) = cached {
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
        .sender_certificate(&token.get_untracked(), PROTOCOL_DEVICE_ID)
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

/// Entrahmt einen entschlüsselten Payload (K_f vorangestellt, Message
/// Franking), legt das Melde-Material ab (`franking/<id>`, Format wie im
/// CLI) und liefert (Klartext, Melde-ID). Ältere, ungefrankte Nachrichten
/// fallen auf die rohe Anzeige zurück, ohne Melde-ID; schlägt das Ablegen
/// fehl, bleibt die Nachricht lesbar, nur das Melden fällt für sie aus.
fn open_payload(
    storage: &SharedStorage,
    message_id: &str,
    payload: &[u8],
) -> (String, Option<String>) {
    match client_app::franking::unfrank(payload) {
        Ok(opened) => {
            let record = serde_json::json!({
                "key": BASE64.encode(&opened.franking_key),
                "message": BASE64.encode(&opened.message),
            });
            let stored = serde_json::to_vec(&record)
                .map_err(|e| e.to_string())
                .and_then(|json| {
                    storage
                        .borrow_mut()
                        .put(&format!("franking/{message_id}"), &json)
                });
            let report_id = match stored {
                Ok(()) => Some(message_id.to_string()),
                Err(error) => {
                    leptos::logging::warn!(
                        "Franking-Material zu {message_id} nicht abgelegt: {error}"
                    );
                    None
                }
            };
            (
                String::from_utf8_lossy(&opened.message).to_string(),
                report_id,
            )
        }
        Err(_) => (String::from_utf8_lossy(payload).to_string(), None),
    }
}

/// Holt wartende Hüllen ab, entschlüsselt und bestätigt sie; liefert
/// (Absender, Klartext, Melde-ID) je Nachricht. Die Melde-ID ist gesetzt,
/// wenn Franking-Material fürs Melden abgelegt wurde. Token als Signal aus
/// demselben Grund wie bei `send_message`: zwischen fetch und ack liegt die
/// Entschlüsselung, in der die Erneuerung rotieren kann.
async fn fetch_messages(
    core: &mut Core,
    token: ReadSignal<String>,
) -> Result<Vec<(String, String, Option<String>)>, String> {
    let delivery = DeliveryClient::new(delivery_url());
    let waiting = delivery
        .fetch(&token.get_untracked())
        .await
        .map_err(|e| e.to_string())?;
    let mut received = Vec::new();
    let mut acked = Vec::new();
    for message in &waiting {
        // Sealed-Sender-Hüllen zuerst: sie tragen keinen Absender im
        // Framing, der kommt erst aus der geprüften Zertifikatskette
        // (wire::classify unterscheidet die Framings eindeutig).
        if matches!(wire::classify(&message.envelope), wire::Framed::Sealed) {
            let blob = match wire::open_sealed(&message.envelope) {
                Ok(blob) => blob,
                Err(error) => {
                    leptos::logging::warn!("Hülle {} übersprungen: {error}", message.id);
                    continue;
                }
            };
            let trust_root = sealed_trust_root_cached(&core.storage).await?;
            match core.device.unseal_message(&trust_root, &blob).await {
                Ok(unsealed) => {
                    let (text, report_id) =
                        open_payload(&core.storage, &message.id, &unsealed.plaintext);
                    received.push((unsealed.sender.clone(), text, report_id));
                    acked.push(message.id.clone());
                }
                Err(error) => {
                    leptos::logging::warn!("Hülle {} nicht entsiegelbar: {error}", message.id);
                    // Bestätigen wie unten: ein erneuter Abruf scheitert am
                    // selben Fehler, die Hülle bliebe für immer liegen.
                    acked.push(message.id.clone());
                }
            }
            continue;
        }
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
                let (text, report_id) = open_payload(&core.storage, &message.id, &payload);
                received.push((opened.from.clone(), text, report_id));
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
        // Ein Fehler beim Bestätigen darf die Nachrichten nicht verwerfen:
        // die Entschlüsselung hat den Ratchet schon fortgeschaltet, beim
        // nächsten Abruf wären dieselben Hüllen unlesbar und die Inhalte
        // endgültig verloren. Also nur warnen; die unbestätigten Hüllen
        // räumt der nächste Abruf über den Unlesbar-Pfad oben ab.
        if let Err(error) = delivery.ack(&token.get_untracked(), &acked).await {
            leptos::logging::warn!(
                "Bestätigen von {} Hüllen fehlgeschlagen: {error}",
                acked.len()
            );
        }
    }
    Ok(received)
}

/// Hält den Hinweiskanal offen und verbindet nach einem Abbruch neu: die
/// Browser-Seite des Vertrags aus `client_app::delivery`. Die Schleife
/// fasst den Client-Zustand nie an, sie zählt nur das Hinweis-Signal hoch;
/// den Abruf stößt ein Effect an, sobald die Oberfläche frei ist (kein
/// RefCell-Borrow über await). Maschinen-Benachrichtigungen
/// (integrations-Dienst) laufen in eine eigene Liste, getrennt vom
/// Krypto-Status und vom E2E-Chat.
///
/// `my_epoch` ist die Kanal-Epoche beim Start; `epoch` die aktuelle. Ein
/// Abmelden oder eine neue Anmeldung erhöht die Epoche und lässt diese
/// Schleife beim nächsten Prüfpunkt sauber enden, damit kein toter Kanal
/// mit altem Token weiterläuft (sonst gäbe es nach dem Konto-Wechsel zwei
/// konkurrierende Schleifen).
fn start_hint_channel(
    token: ReadSignal<String>,
    epoch: StoredValue<u64>,
    my_epoch: u64,
    set_hints: WriteSignal<u64>,
    set_status: WriteSignal<String>,
    set_notifications: WriteSignal<Vec<String>>,
    set_connected: WriteSignal<bool>,
) {
    spawn_local(async move {
        // Wartezeit zwischen Versuchen; nach jeder erfolgreichen Verbindung
        // zurück auf 1s, gedeckelt bei 30s, damit ein toter Server nicht
        // dauerhaft angehämmert wird.
        let mut backoff = 1u64;
        // Aufeinanderfolgende Auth-Abweisungen (Server-Close 4401). Eine
        // einzelne kann ein harmloses Rennen mit der Token-Erneuerung sein
        // (der Reconnect las das Signal, bevor die Rotation es fortschrieb),
        // die zweite in Folge heißt: das Token ist wirklich tot, weiter zu
        // hämmern wäre sinnlos.
        let mut auth_rejected = 0u32;
        loop {
            if epoch.get_value() != my_epoch {
                return;
            }
            let url = client_app::delivery::ws_url(&delivery_url());
            let opened = WebSocket::open(&url);
            let mut socket = match opened {
                Ok(socket) => socket,
                Err(error) => {
                    set_connected.set(false);
                    set_status.set(format!("Echtzeit-Kanal nicht erreichbar: {error}"));
                    sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
                    continue;
                }
            };
            // Das jeweils aktuelle Token lesen: nach einer Token-Erneuerung
            // (start_token_refresh) verbindet ein Reconnect mit dem frischen.
            let auth = ws_auth_frame(&token.get_untracked());
            if let Err(error) = socket.send(WsMessage::Text(auth)).await {
                set_connected.set(false);
                set_status.set(format!("Echtzeit-Kanal: Auth nicht gesendet: {error}"));
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                continue;
            }
            // Verbunden. Backoff zurücksetzen und einmal abholen, damit
            // während der Trennung eingegangene Nachrichten nicht fehlen
            // (der Hinweis dafür kam ja über den geschlossenen Kanal nicht).
            set_connected.set(true);
            set_status.set(String::new());
            backoff = 1;
            set_hints.update(|n| *n += 1);
            loop {
                // Höchstens 5 s auf das nächste Frame warten: ein stiller,
                // offener Socket würde sonst unbegrenzt parken und der
                // Epochen-Check nie laufen. Die Abmeldung könnte den Kanal
                // dann nicht beenden, das Gerät bliebe serverseitig als
                // online gemeldet und nach einer Neuanmeldung liefen zwei
                // Kanäle parallel.
                let frame = match select(socket.next(), sleep(Duration::from_secs(5))).await {
                    Either::Left((frame, _)) => frame,
                    Either::Right(((), _)) => {
                        if epoch.get_value() != my_epoch {
                            // Der Socket fällt hier aus dem Scope und wird
                            // damit geschlossen.
                            return;
                        }
                        // Verbindung lebt seit 5 s: die Auth war gültig.
                        auth_rejected = 0;
                        continue;
                    }
                };
                let Some(frame) = frame else {
                    // Stream zu Ende: neu verbinden (äußere Schleife).
                    break;
                };
                if epoch.get_value() != my_epoch {
                    return;
                }
                match frame {
                    Ok(WsMessage::Text(text)) => {
                        auth_rejected = 0;
                        match parse_ws_event(&text) {
                            Some(WsEvent::MessageWaiting) => set_hints.update(|n| *n += 1),
                            Some(WsEvent::Notification { tenant, title }) => {
                                set_notifications
                                    .update(|list| list.push(format!("{tenant}: {title}")));
                            }
                            // Unbekannte und unlesbare Frames bewusst still:
                            // neue Server-Events dürfen alte Clients nicht
                            // stören.
                            Some(WsEvent::Other { .. }) | None => {}
                        }
                    }
                    Ok(WsMessage::Bytes(_)) => {}
                    // Der Dienst hat die Auth abgewiesen (eigener Close-Code
                    // 4401, siehe delivery). Beim zweiten Mal in Folge ist
                    // das Token endgültig tot: sichtbar machen und aufhören,
                    // statt alle 30 s mit demselben toten Token anzuklopfen.
                    Err(WebSocketError::ConnectionClose(event)) if event.code == 4401 => {
                        auth_rejected += 1;
                        if auth_rejected >= 2 {
                            set_connected.set(false);
                            set_status.set(
                                "Echtzeit-Kanal: Sitzung ungültig, bitte neu anmelden.".to_string(),
                            );
                            return;
                        }
                        break;
                    }
                    // Fehler: innere Schleife verlassen und neu verbinden.
                    Err(_) => break,
                }
            }
            // Kanal zu (Server-Close oder Fehler): getrennt melden und, wenn
            // die Schleife noch aktuell ist, mit Backoff neu verbinden.
            if epoch.get_value() != my_epoch {
                return;
            }
            set_connected.set(false);
            set_status.set("Echtzeit-Kanal getrennt, neuer Verbindungsversuch ...".to_string());
            sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
}

/// Prüft die Geräteschlüssel eines Kontakts gegen das Verzeichnis, wie
/// `sm keycheck` im CLI: der beim ersten Kontakt gespeicherte
/// Identitätsschlüssel (TOFU) wird mit dem frischen Bündel verglichen.
/// Weicht er ab, hat der Kontakt (oder ein Angreifer über den Server) den
/// Schlüssel getauscht; dann ist `false` im Ergebnis der Alarmfall, analog
/// zur KT-Prüfung. Ein Gerät ohne gespeicherte Sitzung ist kein Alarm: bei
/// unbekanntem Kontakt der Erstkontakt, bei bekanntem ein neues Gerät, das
/// erst die nächste Sitzung pinnt.
async fn key_check(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
) -> Result<(bool, String), String> {
    let bundles = DirectoryClient::new(directory_url())
        .bundles(&token.get_untracked(), peer)
        .await
        .map_err(|e| e.to_string())?;
    if bundles.devices.is_empty() {
        return Err(format!("'{peer}' hat keine gültigen Geräte."));
    }
    let mut unchanged = 0usize;
    let mut fresh = 0usize;
    let mut changed: Vec<String> = Vec::new();
    for bundle_json in &bundles.devices {
        let (_bundle, protocol_device_id) =
            bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
        let address = ProtocolAddress::new(
            peer.to_string(),
            device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
        );
        let incoming = BASE64
            .decode(&bundle_json.identity_key)
            .map_err(|e| format!("Bündel-Schlüssel kein Base64: {e}"))?;
        match core
            .device
            .stored_identity(&address)
            .await
            .map_err(|e| e.to_string())?
        {
            None => fresh += 1,
            Some(stored) if stored == incoming => unchanged += 1,
            // Gekürzte Geräte-ID: lesbar in der Statuszeile, eindeutig
            // genug zum Wiederfinden in der Geräteliste.
            Some(_) => changed.push(bundle_json.device_id.chars().take(8).collect()),
        }
    }
    if !changed.is_empty() {
        return Ok((
            false,
            format!(
                "SCHLÜSSEL GEÄNDERT (Gerät {}): Vor dem Weiterschreiben die \
                 Sicherheitsnummer über einen zweiten Kanal neu abgleichen.",
                changed.join(", ")
            ),
        ));
    }
    let message = match (unchanged, fresh) {
        (0, f) => format!("Noch keine Sitzung ({f} Gerät(e)): der Schlüssel wird beim ersten Senden gespeichert (Erstkontakt)."),
        (u, 0) => format!("Geräteschlüssel unverändert ({u} Gerät(e))."),
        (u, f) => format!("{u} Geräteschlüssel unverändert, {f} neue(s) Gerät(e) ohne bisherige Sitzung."),
    };
    Ok((true, message))
}

/// Die KT-Selbstprüfung für das eigene Konto (kt-Modul in client-app):
/// Commitment aus Konto-Schlüssel und eigener Gerätemenge nachrechnen,
/// Beweis gegen die signierte Wurzel verifizieren. Alarm (`true` im
/// Fehler-Tupel) und gewöhnlicher Fehler werden getrennt gemeldet, weil
/// nur ersterer ein Sicherheitssignal ist; ein kt-Ausfall ist keiner.
async fn kt_self_check(core: &Core, token: &str) -> Result<String, (bool, String)> {
    let profile =
        load_profile(&core.storage).ok_or((false, "Kein Profil in der Ablage".to_string()))?;
    let seed: [u8; 32] = BASE64
        .decode(&profile.account_seed)
        .map_err(|e| (false, format!("Konto-Seed unlesbar: {e}")))?
        .try_into()
        .map_err(|_| (false, "Konto-Seed hat die falsche Länge".to_string()))?;
    let account = IdentityKeypair::from_seed(&seed);
    let devices = IdentityClient::new(identity_url())
        .devices(token)
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
    /// Klartext-Profil vorhanden (Migration): Anmeldung für dieses Handle.
    Known(String),
    /// Verschlüsselte Ablage: Anmeldung nötig, aber der Handle ist vor dem
    /// Passwort unbekannt (der ganze Blob ist gesealt).
    Locked,
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
    // Versiegelt senden (Sealed Sender): der Dienst sieht den Absender
    // nicht mehr im Klartext. Bewusst eine Wahl je Sitzung, kein Zwang:
    // der Empfang braucht eine bestehende Sitzung, Erstkontakt bleibt
    // deshalb unversiegelt sinnvoll.
    let (sealed_choice, set_sealed_choice) = signal(false);
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
    // Ergebnis der Schlüsselwechsel-Prüfung des offenen Chats:
    // (kein Wechsel, Meldung). Beim Chat-Wechsel zurückgesetzt, die Aussage
    // gilt nur für den geprüften Kontakt.
    let (key_info, set_key_info) = signal(Option::<(bool, String)>::None);
    // Ob der offene Kontakt auf der eigenen Blockliste steht. `None`, bis
    // die Liste nach dem Chat-Öffnen vom Dienst geladen ist; der Knopf
    // erscheint erst dann, damit er nie den falschen Zustand anbietet.
    let (blocked, set_blocked) = signal(Option::<bool>::None);
    // Maschinen-Benachrichtigungen vom integrations-Dienst, getrennt vom
    // Krypto-Status und vom E2E-Chat (design-system.md, Status-Trennung).
    let (notifications, set_notifications) = signal(Vec::<String>::new());
    // Gewählter Darstellungs-Modus (system/hell/dunkel/midnight); der
    // FOUC-Guard in index.html hat ihn beim Laden schon angewandt.
    let (theme, set_theme) = signal(stored_theme());
    // Fokusziel beim Chat-Wechsel: der Kontaktname im Chat-Kopf (SC 2.4.3).
    let chat_name_ref = NodeRef::<leptos::html::H2>::new();
    // Der Verlauf-Container, für den Auto-Scroll ans Ende bei neuen
    // Nachrichten und beim Öffnen eines Chats.
    let log_ref = NodeRef::<leptos::html::Ul>::new();
    // Epoche des Echtzeit-Kanals: erhöht sich bei Anmeldung, Registrierung
    // und Abmeldung; eine laufende Kanal-Schleife endet, sobald ihre Epoche
    // veraltet ist (siehe start_hint_channel).
    let channel_epoch = StoredValue::new(0u64);

    // Das Zugriffstoken der Sitzung als Signal, damit alle Abläufe (Senden,
    // Abholen, KT-Prüfung, Reconnect des Hinweiskanals) beim Zugriff das
    // jeweils aktuelle Token lesen; die Token-Erneuerung schreibt es fort.
    // Das Refresh-Token liegt daneben (nicht reaktiv, es steuert keine
    // Anzeige), die Epoche beendet die Erneuerungsschleife bei Abmeldung.
    let (access_token, set_access_token) = signal(String::new());
    let refresh_token = StoredValue::new(String::new());
    let token_epoch = StoredValue::new(0u64);

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
                    // Verschlüsselte Ablage: der Handle ist erst nach dem
                    // Entsperren lesbar (Locked). Klartext (Migration) oder
                    // frisch: wie bisher entscheiden.
                    let boot = {
                        let s = storage.borrow();
                        if !s.has_state() {
                            Boot::Fresh
                        } else if s.is_locked() {
                            Boot::Locked
                        } else {
                            match load_profile(&storage).map(|p| p.handle) {
                                Some(handle) => Boot::Known(handle),
                                None => Boot::Fresh,
                            }
                        }
                    };
                    *boot_storage.borrow_mut() = Some(storage);
                    set_boot.set(boot);
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
                    Ok(onboarded) => {
                        let Onboarded {
                            core: new_core,
                            access_token: at,
                            refresh_token: rt,
                            expires_in,
                        } = onboarded;
                        // Token in die App-Signale übernehmen und die
                        // Erneuerung starten, bevor der Core aktiv wird.
                        set_access_token.set(at);
                        refresh_token.set_value(rt);
                        token_epoch.update_value(|e| *e += 1);
                        start_token_refresh(
                            token_epoch,
                            token_epoch.get_value(),
                            refresh_token,
                            set_access_token,
                            set_status,
                            expires_in,
                        );
                        channel_epoch.update_value(|e| *e += 1);
                        start_hint_channel(
                            access_token,
                            channel_epoch,
                            channel_epoch.get_value(),
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
                    Ok(onboarded) => {
                        let Onboarded {
                            core: new_core,
                            access_token: at,
                            refresh_token: rt,
                            expires_in,
                        } = onboarded;
                        set_access_token.set(at);
                        refresh_token.set_value(rt);
                        token_epoch.update_value(|e| *e += 1);
                        start_token_refresh(
                            token_epoch,
                            token_epoch.get_value(),
                            refresh_token,
                            set_access_token,
                            set_status,
                            expires_in,
                        );
                        channel_epoch.update_value(|e| *e += 1);
                        start_hint_channel(
                            access_token,
                            channel_epoch,
                            channel_epoch.get_value(),
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

    // Abmelden: die Session beim Dienst best-effort widerrufen, den lebenden
    // Zustand verwerfen und zur Anmeldemaske zurückkehren. Die Ablage
    // (Identität, Sitzungen, Kontakte, Verläufe) bleibt, damit man sich mit
    // dem Passwort wieder anmelden kann; nur die flüchtige Session endet.
    let on_logout = {
        let core = core.clone();
        let boot_storage = boot_storage.clone();
        move |_| {
            // Die Kanal-Schleife und die Token-Erneuerung veralten lassen
            // (kein toter Kanal mit altem Token, keine Erneuerung nach der
            // Abmeldung) und den Verbindungszustand zurücksetzen.
            channel_epoch.update_value(|e| *e += 1);
            token_epoch.update_value(|e| *e += 1);
            set_connected.set(false);
            let token = access_token.get_untracked();
            set_access_token.set(String::new());
            refresh_token.set_value(String::new());
            if let Some(active) = core.borrow_mut().take() {
                let handle = active.handle.clone();
                *boot_storage.borrow_mut() = Some(active.storage.clone());
                // Best effort: das Token beim Dienst widerrufen. Ein Fehler
                // hier ist unkritisch, lokal ist die Session schon beendet.
                spawn_local(async move {
                    let _ = IdentityClient::new(identity_url()).logout(&token).await;
                });
                set_boot.set(Boot::Known(handle));
            }
            set_logged_in.set(false);
            set_selected.set(None);
            set_messages.set(Vec::new());
            set_chats.set(Vec::new());
            set_new_chat_open.set(false);
            set_safety_open.set(false);
            set_safety_info.set(None);
            set_kt_info.set(None);
            set_key_info.set(None);
            set_blocked.set(None);
            set_notifications.set(Vec::new());
            set_password_input.set(String::new());
            set_text_input.set(String::new());
            set_status.set("Abgemeldet.".to_string());
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
            let sealed = sealed_choice.get_untracked();
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
                        let result = send_message(
                            &mut active,
                            access_token,
                            &peer,
                            &text,
                            expires_at,
                            sealed,
                        )
                        .await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(()) => {
                                let line = StoredLine {
                                    from: who,
                                    text: text.clone(),
                                    at: now_unix(),
                                    report_id: None,
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
                        let result = fetch_messages(&mut active, access_token).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(received) if received.is_empty() => {
                                set_status.set("Keine neuen Nachrichten.".to_string());
                            }
                            Ok(received) => {
                                let open = selected.get_untracked();
                                let mut summaries = None;
                                for (sender, text, report_id) in received {
                                    let for_open = open.as_deref() == Some(sender.as_str());
                                    let line = StoredLine {
                                        from: sender.clone(),
                                        text,
                                        at: now_unix(),
                                        report_id,
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

    // Prüft die Geräteschlüssel des offenen Chats gegen das Verzeichnis
    // (Schlüsselwechsel-Warnung, siehe key_check).
    let on_key_check = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            set_busy.set(true);
            set_key_info.set(None);
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let result = key_check(&mut active, access_token, &peer).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(info) => {
                                // Nur anzeigen, wenn der Chat noch offen ist:
                                // die Aussage gehört zu genau diesem Kontakt.
                                if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                                    set_key_info.set(Some(info));
                                }
                                set_status.set(String::new());
                            }
                            Err(error) => set_status.set(format!("Schlüssel-Prüfung: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    };

    // Blockiert den offenen Kontakt oder hebt die Blockierung auf. Der
    // Dienst verwirft Nachrichten blockierter Absender serverseitig und
    // still (der Absender erfährt nichts); der Knopf erscheint erst, wenn
    // der geladene Zustand bekannt ist, damit er nie falsch beschriftet
    // ist. Fängt nur Copy-Signale ein und ist selbst Copy.
    let on_block = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(peer) = selected.get_untracked() else {
            return;
        };
        let Some(is_blocked) = blocked.get_untracked() else {
            return;
        };
        set_busy.set(true);
        spawn_local(async move {
            let delivery = DeliveryClient::new(delivery_url());
            let token = access_token.get_untracked();
            let result = if is_blocked {
                delivery.unblock(&token, &peer).await
            } else {
                delivery.block(&token, &peer).await
            };
            match result {
                Ok(()) => {
                    if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                        set_blocked.set(Some(!is_blocked));
                    }
                    set_status.set(if is_blocked {
                        format!("{peer} ist nicht mehr blockiert.")
                    } else {
                        format!(
                            "{peer} ist blockiert; neue Nachrichten dieses Handles \
                             verwirft der Dienst still."
                        )
                    });
                }
                Err(error) => set_status.set(format!("Blockieren: {error}")),
            }
            set_busy.set(false);
        });
    };

    // Meldet eine empfangene Nachricht beim Dienst (Message Franking):
    // K_f und Klartext aus der Ablage öffnen das beim Senden aufbewahrte
    // Commitment, der Dienst prüft es nach und antwortet, ob die Nachricht
    // nachweislich so gesendet wurde (specs/sealed-sender-und-abuse.md).
    let run_report = SendWrapper::new(Rc::new({
        let current_storage = current_storage.clone();
        move |report_id: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            let record = storage
                .borrow()
                .get(&format!("franking/{report_id}"))
                .ok()
                .flatten();
            let Some(bytes) = record else {
                set_status.set("Kein Franking-Material zu dieser Nachricht.".to_string());
                return;
            };
            let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    set_status.set(format!("Franking-Ablage unlesbar: {error}"));
                    return;
                }
            };
            let decoded = BASE64
                .decode(parsed["key"].as_str().unwrap_or_default())
                .and_then(|key| {
                    BASE64
                        .decode(parsed["message"].as_str().unwrap_or_default())
                        .map(|message| (key, message))
                });
            let Ok((key, message)) = decoded else {
                set_status.set("Franking-Ablage unlesbar: kein Base64.".to_string());
                return;
            };
            set_busy.set(true);
            spawn_local(async move {
                let result = DeliveryClient::new(delivery_url())
                    .report(&access_token.get_untracked(), &report_id, &message, &key)
                    .await;
                match result {
                    Ok(true) => set_status.set(
                        "Meldung bestätigt: die Nachricht wurde nachweislich so gesendet."
                            .to_string(),
                    ),
                    Ok(false) => set_status
                        .set("Meldung NICHT bestätigt: das Commitment öffnet nicht.".to_string()),
                    Err(error) => set_status.set(format!("Melden: {error}")),
                }
                set_busy.set(false);
            });
        }
    }));

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
            set_key_info.set(None);
            set_blocked.set(None);
            set_selected.set(Some(peer.clone()));
            // Blockier-Zustand des Kontakts nachladen; das Ergebnis zählt
            // nur, wenn der Chat beim Eintreffen noch offen ist.
            spawn_local(async move {
                if let Ok(list) = DeliveryClient::new(delivery_url())
                    .blocks(&access_token.get_untracked())
                    .await
                {
                    if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                        set_blocked.set(Some(list.iter().any(|h| h == &peer)));
                    }
                }
            });
        }
    };

    let on_back = move |_| {
        set_selected.set(None);
        set_safety_open.set(false);
        set_key_info.set(None);
        set_blocked.set(None);
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

    // Auto-Scroll ans Ende des Verlaufs: läuft neu bei jeder Änderung von
    // `messages` (neue Nachricht, Chat gewechselt) und scrollt nach dem
    // Render ganz nach unten, damit die neueste Nachricht sichtbar ist.
    Effect::new(move |_| {
        // Abhängigkeit anmelden, ohne den Wert zu brauchen.
        let _ = messages.get();
        let log_ref = log_ref;
        request_animation_frame(move || {
            if let Some(el) = log_ref.get_untracked() {
                el.set_scroll_top(el.scroll_height());
            }
        });
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
                        let token = access_token.get_untracked();
                        let result = kt_self_check(&active, &token).await;
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
                {
                    let on_logout = on_logout.clone();
                    move || {
                        let on_logout = on_logout.clone();
                        logged_in
                            .get()
                            .then(|| {
                                view! {
                                    <span class="sm-identity">
                                        "Angemeldet als " <strong>{me}</strong>
                                    </span>
                                    <button
                                        type="button"
                                        class="sm-secondary sm-logout"
                                        on:click=on_logout
                                    >
                                        "Abmelden"
                                    </button>
                                }
                            })
                    }
                }
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
                    let on_key_check = on_key_check.clone();
                    let run_report = run_report.clone();
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
                                        "Geräte-Identität, Sitzungen und Kontakte liegen mit dem "
                                        "Passwort verschlüsselt in IndexedDB (Argon2id plus "
                                        "ChaCha20-Poly1305). Solange die App offen ist, hält sie den "
                                        "Schlüssel im Speicher; der Browser bleibt laut sicherheit.md "
                                        "das schwächste Glied (kein OS-Keystore, XSS-Fläche)."
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
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=on_key_check.clone()
                                                        disabled=busy
                                                    >
                                                        "Schlüssel prüfen"
                                                    </button>
                                                    {move || {
                                                        blocked
                                                            .get()
                                                            .map(|is_blocked| {
                                                                view! {
                                                                    <button
                                                                        type="button"
                                                                        class="sm-secondary"
                                                                        on:click=on_block
                                                                        disabled=busy
                                                                    >
                                                                        {if is_blocked {
                                                                            "Blockierung aufheben"
                                                                        } else {
                                                                            "Blockieren"
                                                                        }}
                                                                    </button>
                                                                }
                                                            })
                                                    }}
                                                </div>

                                                {move || {
                                                    key_info
                                                        .get()
                                                        .map(|(ok, message)| {
                                                            if ok {
                                                                view! {
                                                                    <p class="sm-note sm-ok">
                                                                        <span aria-hidden="true">"✓ "</span>
                                                                        {message}
                                                                    </p>
                                                                }
                                                                    .into_any()
                                                            } else {
                                                                view! {
                                                                    <p class="sm-note sm-warn" role="alert">
                                                                        <span aria-hidden="true">"⚠ "</span>
                                                                        {message}
                                                                    </p>
                                                                }
                                                                    .into_any()
                                                            }
                                                        })
                                                }}

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
                                                    node_ref=log_ref
                                                    role="log"
                                                    aria-label="Nachrichtenverlauf"
                                                    aria-live="polite"
                                                    aria-relevant="additions"
                                                    aria-atomic="false"
                                                >
                                                    {
                                                        let run_report = run_report.clone();
                                                        move || {
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
                                                                        let mine = line.from == own;
                                                                        let class = if mine {
                                                                            "sm-msg sm-mine"
                                                                        } else {
                                                                            "sm-msg"
                                                                        };
                                                                        // Melden nur für empfangene Nachrichten
                                                                        // mit abgelegtem Franking-Material.
                                                                        let report_id = if mine {
                                                                            None
                                                                        } else {
                                                                            line.report_id.clone()
                                                                        };
                                                                        let report_click = run_report.clone();
                                                                        view! {
                                                                            <li class=class>
                                                                                <span class="sm-msg-from">{line.from}</span>
                                                                                <span class="sm-msg-text">{line.text}</span>
                                                                                <span class="sm-msg-time">
                                                                                    {format_time(line.at)}
                                                                                </span>
                                                                                {report_id
                                                                                    .map(|id| {
                                                                                        view! {
                                                                                            <button
                                                                                                type="button"
                                                                                                class="sm-msg-report"
                                                                                                title="Nachricht beim Dienst melden (Message Franking)"
                                                                                                on:click=move |_| report_click(
                                                                                                    id.clone(),
                                                                                                )
                                                                                                disabled=busy
                                                                                            >
                                                                                                "Melden"
                                                                                            </button>
                                                                                        }
                                                                                    })}
                                                                            </li>
                                                                        }
                                                                    })
                                                                    .collect_view()
                                                                    .into_any()
                                                            }
                                                        }
                                                    }
                                                </ul>

                                                <div class="sm-composer">
                                                    <div class="sm-field">
                                                        <label for="sm-msg">
                                                            "Nachricht (Enter sendet, Umschalt-Enter neue Zeile)"
                                                        </label>
                                                        <textarea
                                                            id="sm-msg"
                                                            class="sm-composer-input"
                                                            rows="1"
                                                            prop:value=text_input
                                                            on:input=move |ev| {
                                                                set_text_input.set(event_target_value(&ev))
                                                            }
                                                            on:keydown=on_message_key.clone()
                                                        ></textarea>
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
                                                    <label class="sm-sealed-toggle">
                                                        <input
                                                            type="checkbox"
                                                            prop:checked=sealed_choice
                                                            on:change=move |ev| {
                                                                set_sealed_choice
                                                                    .set(event_target_checked(&ev));
                                                            }
                                                        />
                                                        "Versiegelt (Server sieht den Absender nicht)"
                                                    </label>
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
                                    Boot::Locked => {
                                        view! {
                                            <section class="sm-card" aria-label="Anmelden">
                                                <h2>"Verschlüsseltes Konto auf diesem Gerät"</h2>
                                                <p class="sm-status">
                                                    "Die Ablage ist mit dem Passwort verschlüsselt. "
                                                    "Zum Entsperren das Passwort eingeben."
                                                </p>
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
                                                        "Entsperren und anmelden"
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
