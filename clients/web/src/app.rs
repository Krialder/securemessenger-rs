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
async fn send_message(core: &mut Core, peer: &str, text: &str) -> Result<(), String> {
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
            // Disappearing-Messages-TTL folgt mit einem eigenen UI-Schnitt.
            expires_at: None,
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
) {
    spawn_local(async move {
        let url = client_app::delivery::ws_url(&delivery_url());
        let mut socket = match WebSocket::open(&url) {
            Ok(socket) => socket,
            Err(error) => {
                set_status.set(format!("Echtzeit-Kanal nicht erreichbar: {error}"));
                return;
            }
        };
        if let Err(error) = socket.send(WsMessage::Text(ws_auth_frame(&token))).await {
            set_status.set(format!("Echtzeit-Kanal: Auth nicht gesendet: {error}"));
            return;
        }
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
                    set_status.set(format!("Echtzeit-Kanal gestört: {error}"));
                    return;
                }
            }
        }
        // [ANNAHME: kein automatischer Wiederverbinder, wie beim CLI; der
        // Abruf-Knopf bleibt als Rückfallebene sichtbar.]
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
    let (peer_input, set_peer_input) = signal(String::new());
    let (text_input, set_text_input) = signal(String::new());
    // (Absender, Text); der eigene Handle markiert ausgehende Nachrichten.
    let (messages, set_messages) = signal(Vec::<(String, String)>::new());
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
                        );
                        *core.borrow_mut() = Some(new_core);
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
                        );
                        set_me.set(new_core.handle.clone());
                        *core.borrow_mut() = Some(new_core);
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
    let run_send = SendWrapper::new(Rc::new({
        let core = core.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            let peer = peer_input.get_untracked();
            let text = text_input.get_untracked();
            if peer.is_empty() || text.is_empty() {
                set_status.set("Empfänger und Text angeben.".to_string());
                return;
            }
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
                        let result = send_message(&mut active, &peer, &text).await;
                        let who = active.handle.clone();
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(()) => {
                                set_messages.update(|list| list.push((who, text)));
                                set_text_input.set(String::new());
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
                        let result = fetch_messages(&mut active).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(received) if received.is_empty() => {
                                set_status.set("Keine neuen Nachrichten.".to_string());
                            }
                            Ok(received) => {
                                set_messages.update(|list| list.extend(received));
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

    let on_safety = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let peer = peer_input.get_untracked();
            if peer.is_empty() {
                set_status.set("Empfänger-Handle angeben.".to_string());
                return;
            }
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
                                set_status.set(String::new());
                            }
                            Ok(None) => set_status.set(format!(
                                "Noch keine Sitzung mit '{peer}': erst eine Nachricht \
                                 senden oder empfangen."
                            )),
                            Err(error) => set_status.set(format!("Sicherheitsnummer: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    };

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
        <div class="sm-app">
            <header class="sm-header">
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

            <main class="sm-main">
                <p class="sm-caution">
                    "Geräte-Identität, Sitzungen und Kontakte liegen unverschlüsselt in "
                    "IndexedDB dieses Browser-Profils. Der Browser ist das kryptografisch "
                    "schwächste Glied der Plattform (sicherheit.md)."
                </p>

                {move || {
                    let items = notifications.get();
                    (!items.is_empty())
                        .then(|| {
                            view! {
                                <section
                                    class="sm-notify"
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
                                </section>
                            }
                        })
                }}

                {move || {
                    if logged_in.get() {
                        view! {
                            <section class="sm-card" aria-label="Nachricht verfassen">
                                <div class="sm-field">
                                    <label for="sm-peer">"Empfänger-Handle"</label>
                                    <input
                                        id="sm-peer"
                                        prop:value=peer_input
                                        on:input=move |ev| set_peer_input.set(event_target_value(&ev))
                                    />
                                </div>
                                <div class="sm-field">
                                    <label for="sm-msg">"Nachricht (Enter sendet)"</label>
                                    <input
                                        id="sm-msg"
                                        prop:value=text_input
                                        on:input=move |ev| set_text_input.set(event_target_value(&ev))
                                        on:keydown=on_message_key.clone()
                                    />
                                </div>
                                <div class="sm-row">
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
                            </section>

                            <section class="sm-card" aria-label="Schlüssel prüfen">
                                <h2>"Schlüssel prüfen"</h2>
                                <div class="sm-row">
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
                                        on:click=on_kt_check.clone()
                                        disabled=busy
                                    >
                                        "Schlüssel prüfen (KT)"
                                    </button>
                                </div>
                                {move || {
                                    safety_info
                                        .get()
                                        .map(|(peer, number)| {
                                            view! {
                                                <div>
                                                    <p>
                                                        <strong>
                                                            {format!("Sicherheitsnummer mit {peer}")}
                                                        </strong>
                                                        " – über einen zweiten Kanal abgleichen:"
                                                    </p>
                                                    <p class="sm-fingerprint">{number}</p>
                                                </div>
                                            }
                                        })
                                }}
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
                            </section>

                            <ul
                                class="sm-log"
                                role="log"
                                aria-label="Nachrichtenverlauf"
                                aria-live="polite"
                            >
                                {move || {
                                    let own = me.get();
                                    messages
                                        .get()
                                        .into_iter()
                                        .map(|(who, text)| {
                                            let class = if who == own {
                                                "sm-msg sm-mine"
                                            } else {
                                                "sm-msg"
                                            };
                                            view! {
                                                <li class=class>
                                                    <span class="sm-msg-from">{who}</span>
                                                    <span class="sm-msg-text">{text}</span>
                                                </li>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </ul>
                        }
                            .into_any()
                    } else {
                        match boot.get() {
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
                }}

                <p class="sm-status" role="status" aria-live="polite">
                    {status}
                </p>
            </main>
        </div>
    }
}

/// Startet die App: Panic-Ausgaben in die Browser-Konsole, dann mounten.
pub fn run() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
