//! Die Leptos-Oberfläche des Web-Clients: nur Darstellung und
//! Ablaufsteuerung.
//!
//! Die Schichten darunter bleiben unangetastet: `client-core` trägt die
//! Krypto, `client-app` das Protokoll (HTTP, Blobs, Framing, Ablage). Hier
//! wird beides mit einer bewusst schlichten Oberfläche verdrahtet:
//! Konto anlegen, Nachricht senden, Nachrichten abrufen.
//!
//! [ANNAHME: Die Ablage ist In-Memory und lebt nur so lange wie der Tab;
//! ein Neuladen der Seite verliert Sitzungen und Geräte-Identität
//! (IndexedDB-Anbindung ist die nächste Etappe, storage.rs). Abruf per
//! Knopf statt WebSocket-Hinweis; der Hinweiskanal folgt. Der Web-Client
//! ist laut sicherheit.md das kryptografisch schwächste Glied (kein
//! OS-Keystore, XSS-Fläche); die Oberfläche sagt das sichtbar an, statt es
//! zu kaschieren.]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use client_app::account::IdentityKeypair;
use client_app::delivery::{DeliveryClient, OutgoingEnvelope};
use client_app::directory::DirectoryClient;
use client_app::prekeys::{
    bundle_from_directory, device_id_from_u32, new_uuid, publication_from_bundle,
    PROTOCOL_DEVICE_ID,
};
use client_app::protocol_store::{store_own_identity, PersistentProtocolStore};
use client_app::storage::InMemoryStorage;
use client_app::{wire, IdentityClient, NewAccount};
use client_core::libsignal_protocol::{IdentityKeyPair, ProtocolAddress};
use client_core::onetoone::Device;
use leptos::prelude::*;
use leptos::task::spawn_local;
use send_wrapper::SendWrapper;

/// Gültigkeit des Geräte-Credentials: ein Jahr, wie beim CLI.
const CREDENTIAL_TTL_SECONDS: u64 = 60 * 60 * 24 * 365;

type WebDevice = Device<PersistentProtocolStore<InMemoryStorage>>;

/// Ein bekannter Kontakt: Zustell-Adresse und Protokoll-Gerätenummer.
struct Contact {
    server_device_id: String,
    protocol_device_id: u32,
}

/// Der lebende Client-Zustand hinter der Oberfläche. In einem
/// `Rc<RefCell<...>>`, weil das Gerät nicht klonbar ist und die
/// Leptos-Handler es teilen; der `busy`-Riegel in der UI verhindert, dass
/// zwei Abläufe gleichzeitig hineingreifen. Der `SendWrapper` darum herum
/// stillt die Send-Anforderung des Leptos-Renderers: der Browser ist
/// eindrähtig, ein Zugriff aus einem fremden Thread (der hier nie
/// vorkommt) würde kontrolliert panicken statt still Daten zu zerreißen.
struct Core {
    device: WebDevice,
    handle: String,
    token: String,
    contacts: HashMap<String, Vec<Contact>>,
}

type SharedCore = SendWrapper<Rc<RefCell<Option<Core>>>>;

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

fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Konto anlegen: Schlüssel erzeugen, registrieren, anmelden, Prekeys
/// veröffentlichen. Ein Schritt aus Nutzersicht, weil ein frisch angelegtes
/// Konto ohne veröffentlichte Prekeys nicht erreichbar wäre.
async fn onboard(handle: String, password: String) -> Result<Core, String> {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let registration_id = rand::Rng::random_range(&mut rng, 1u32..16380);

    let storage = Rc::new(RefCell::new(InMemoryStorage::default()));
    store_own_identity(&storage, &identity.serialize(), registration_id)
        .map_err(|e| e.to_string())?;
    let mut device = Device::with_store(&handle, 1, PersistentProtocolStore::open(storage), 1)
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

    Ok(Core {
        device,
        handle,
        token: session.access_token,
        contacts: HashMap::new(),
    })
}

/// Sendet eine Nachricht; baut beim ersten Kontakt die PQXDH-Sitzungen aus
/// den Verzeichnis-Bündeln auf (gleicher Fluss wie im CLI).
async fn send_message(core: &mut Core, peer: &str, text: &str) -> Result<(), String> {
    if !core.contacts.contains_key(peer) {
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
            contact.push(Contact {
                server_device_id: bundle_json.device_id.clone(),
                protocol_device_id,
            });
        }
        core.contacts.insert(peer.to_string(), contact);
    }

    let mut envelopes = Vec::new();
    for target in &core.contacts[peer] {
        let address = ProtocolAddress::new(
            peer.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let message = core
            .device
            .encrypt(&address, text.as_bytes())
            .await
            .map_err(|e| format!("Verschlüsselung: {e}"))?;
        let envelope =
            wire::seal(&core.handle, PROTOCOL_DEVICE_ID, &message).map_err(|e| e.to_string())?;
        envelopes.push(OutgoingEnvelope {
            id: new_uuid(),
            recipient: peer.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
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
            Ok(plaintext) => {
                received.push((
                    opened.from.clone(),
                    String::from_utf8_lossy(&plaintext).to_string(),
                ));
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

#[component]
fn App() -> impl IntoView {
    let core: SharedCore = SendWrapper::new(Rc::new(RefCell::new(None)));
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

    let on_register = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
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
                match onboard(handle.clone(), password).await {
                    Ok(new_core) => {
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

    let on_send = {
        let core = core.clone();
        move |_| {
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
                let mut guard = core.borrow_mut();
                match guard.as_mut() {
                    Some(core) => match send_message(core, &peer, &text).await {
                        Ok(()) => {
                            let who = core.handle.clone();
                            set_messages.update(|list| list.push((who, text)));
                            set_text_input.set(String::new());
                            set_status.set(String::new());
                        }
                        Err(error) => set_status.set(format!("Senden fehlgeschlagen: {error}")),
                    },
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                drop(guard);
                set_busy.set(false);
            });
        }
    };

    let on_fetch = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            let core = core.clone();
            spawn_local(async move {
                let mut guard = core.borrow_mut();
                match guard.as_mut() {
                    Some(core) => match fetch_messages(core).await {
                        Ok(received) if received.is_empty() => {
                            set_status.set("Keine neuen Nachrichten.".to_string());
                        }
                        Ok(received) => {
                            set_messages.update(|list| list.extend(received));
                            set_status.set(String::new());
                        }
                        Err(error) => set_status.set(format!("Abruf fehlgeschlagen: {error}")),
                    },
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                drop(guard);
                set_busy.set(false);
            });
        }
    };

    view! {
        <main>
            <h1>"SecureMessenger"</h1>
            <p class="warnung">
                "Web-Client ohne dauerhafte Ablage: ein Neuladen der Seite verwirft "
                "Geräte-Identität und Sitzungen (IndexedDB folgt). Der Browser ist "
                "das kryptografisch schwächste Glied der Plattform (sicherheit.md)."
            </p>
            {move || {
                if logged_in.get() {
                    view! {
                        <p>"Angemeldet als " <strong>{me}</strong></p>
                        <div class="zeile">
                            <input
                                prop:value=peer_input
                                on:input=move |ev| set_peer_input.set(event_target_value(&ev))
                                placeholder="Empfänger-Handle"
                            />
                        </div>
                        <div class="zeile">
                            <input
                                prop:value=text_input
                                on:input=move |ev| set_text_input.set(event_target_value(&ev))
                                placeholder="Nachricht"
                            />
                            <button on:click=on_send.clone() disabled=busy>"Senden"</button>
                            <button on:click=on_fetch.clone() disabled=busy>"Abrufen"</button>
                        </div>
                        <ul class="chat">
                            {move || {
                                let own = me.get();
                                messages
                                    .get()
                                    .into_iter()
                                    .map(|(who, text)| {
                                        let eigene = who == own;
                                        view! {
                                            <li class:eigene=eigene>
                                                <strong>{format!("[{who}] ")}</strong>
                                                {text}
                                            </li>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </ul>
                    }
                        .into_any()
                } else {
                    view! {
                        <p>"Konto anlegen (Registrierung, Anmeldung und Prekey-Veröffentlichung in einem Schritt):"</p>
                        <div class="zeile">
                            <input
                                prop:value=handle_input
                                on:input=move |ev| set_handle_input.set(event_target_value(&ev))
                                placeholder="Handle (a-z, 0-9, _ . -)"
                            />
                        </div>
                        <div class="zeile">
                            <input
                                type="password"
                                prop:value=password_input
                                on:input=move |ev| set_password_input.set(event_target_value(&ev))
                                placeholder="Passwort (mindestens 12 Zeichen)"
                            />
                            <button on:click=on_register.clone() disabled=busy>"Konto anlegen"</button>
                        </div>
                    }
                        .into_any()
                }
            }}
            <p class="status">{status}</p>
        </main>
    }
}

/// Startet die App: Panic-Ausgaben in die Browser-Konsole, dann mounten.
pub fn run() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
