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
use client_app::account::{
    build_device_credential, build_rotation_cert, decode_seed, IdentityKeypair,
};
use client_app::delivery::{
    parse_ws_event, ws_auth_frame, DeliveryClient, GroupMemberInfo, GroupMetaInfo, GroupOutgoing,
    GroupRole, OutgoingEnvelope, WsEvent,
};
use client_app::directory::DirectoryClient;
use client_app::grouptext::{self, GroupPayload, RosterDevice};
use client_app::identity::{DeviceEnrollment, RotateDeviceCredential};
use client_app::kt::KtClient;
use client_app::policy::{
    CREDENTIAL_TTL_SECONDS, INVITE_BUFFER_MAX, MAX_PENDING_INVITES, MLS_KEY_PACKAGE_TARGET,
};
use client_app::prekeys::{
    bundle_from_directory, device_id_from_u32, new_uuid, publication_from_bundle, DirectoryPrekey,
    PROTOCOL_DEVICE_ID,
};
use client_app::protocol_store::{store_own_identity, PersistentProtocolStore};
use client_app::storage::KeyValueStorage as _;
use client_app::store_keys::{
    invite_buffer_key, invite_key, roster_key, COUNTER_KEY, GROUPS_INDEX_KEY, INVITES_INDEX_KEY,
    MLS_STATE_KEY, OWN_DEVICES_KEY,
};
use client_app::{wire, ClientError, IdentityClient, NewAccount};
use client_core::group::{GroupInbound, GroupMember, GroupSession};
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

/// Web-eigener Ablage-Schlüssel des Profils (die geteilten Schlüssel und
/// Betriebskonstanten kommen aus client-app::store_keys/policy).
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
    /// Die vom Absender vergebene Nachrichten-ID (`smmsg`/`smgpl`). Sie
    /// verbindet eine Zeile mit späteren Bearbeitungen/Löschungen. Alte
    /// Verläufe und History-Nachzüge ohne ID sind nicht bearbeitbar.
    #[serde(default)]
    id: String,
    /// Wahr, wenn der Absender den Text nachträglich bearbeitet hat; die
    /// Oberfläche zeigt dann „bearbeitet".
    #[serde(default)]
    edited: bool,
    /// Wahr, wenn der Absender die Nachricht bei allen gelöscht hat; die
    /// Zeile bleibt als Grabstein stehen.
    #[serde(default)]
    deleted: bool,
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

/// Ablage der Kontakt-Anzeigenamen (Handle -> Anzeigename) als ein Blob. Der
/// Anzeigename ist Server-Datum (nicht Ende-zu-Ende); er wird beim App-Start
/// und Chat-Öffnen aufgefrischt. Der Handle bleibt daneben die
/// kryptografische Identität und wird in der Oberfläche mit angezeigt.
const CONTACT_NAMES_KEY: &str = "contacts/names";

fn load_contact_names(storage: &SharedStorage) -> std::collections::HashMap<String, String> {
    storage
        .borrow()
        .get(CONTACT_NAMES_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_contact_names(storage: &SharedStorage, names: &std::collections::HashMap<String, String>) {
    if let Ok(json) = serde_json::to_vec(names) {
        let _ = storage.borrow_mut().put(CONTACT_NAMES_KEY, &json);
    }
}

/// Holt für die gegebenen 1:1-Kontakte den aktuellen Anzeigenamen vom
/// identity-Dienst und aktualisiert Signal und Ablage. Best effort: bei
/// Fehler oder unbekanntem Handle bleibt der letzte Stand (ein Ausfall darf
/// einen Namen nicht löschen). Gruppen (`grp:`) und der eigene Handle werden
/// übersprungen.
fn refresh_contact_names(
    peers: Vec<String>,
    own: &str,
    token: String,
    storage: SharedStorage,
    set_contact_names: WriteSignal<std::collections::HashMap<String, String>>,
) {
    if token.is_empty() {
        return;
    }
    for peer in peers {
        if peer.starts_with("grp:") || peer.is_empty() || peer == own {
            continue;
        }
        let token = token.clone();
        let storage = storage.clone();
        spawn_local(async move {
            if let Ok(Some(name)) = IdentityClient::new(identity_url())
                .account_name(&token, &peer)
                .await
            {
                set_contact_names.update(|map| {
                    let changed = map.get(&peer) != Some(&name);
                    if changed {
                        map.insert(peer.clone(), name);
                        save_contact_names(&storage, map);
                    }
                });
            }
        });
    }
}

/// Ablage-Schlüssel der Einstellung "versiegelt senden als Vorgabe". Ein
/// Byte (0/1), damit die Wahl über Neuladen und Neuanmeldung erhalten
/// bleibt; sie liegt im selben verschlüsselten Zustandsblob wie der Rest.
const SEALED_DEFAULT_KEY: &str = "settings/sealed_default";

fn load_sealed_default(storage: &SharedStorage) -> bool {
    storage
        .borrow()
        .get(SEALED_DEFAULT_KEY)
        .ok()
        .flatten()
        .is_some_and(|bytes| bytes.first() == Some(&1))
}

fn save_sealed_default(storage: &SharedStorage, on: bool) {
    let _ = storage
        .borrow_mut()
        .put(SEALED_DEFAULT_KEY, &[u8::from(on)]);
}

/// Ablage-Schlüssel der Einstellung „Live-Tippen im Anruf" (Paket E): während
/// eines Anrufs sieht der Gesprächspartner den Entwurf in Echtzeit. Ein Byte
/// (0/1), bleibt über Neuladen erhalten.
const LIVE_TYPING_KEY: &str = "settings/live_typing";

fn load_live_typing(storage: &SharedStorage) -> bool {
    storage
        .borrow()
        .get(LIVE_TYPING_KEY)
        .ok()
        .flatten()
        .is_some_and(|bytes| bytes.first() == Some(&1))
}

fn save_live_typing(storage: &SharedStorage, on: bool) {
    let _ = storage.borrow_mut().put(LIVE_TYPING_KEY, &[u8::from(on)]);
}

/// Ob Web-Push (Benachrichtigungen bei geschlossenem Browser) für dieses
/// Gerät eingeschaltet ist. Persistiert, damit die App das Abo beim Start
/// still auffrischen kann (der Push-Endpoint des Browsers kann rotieren).
const PUSH_ON_KEY: &str = "settings/push_on";

fn load_push_on(storage: &SharedStorage) -> bool {
    storage
        .borrow()
        .get(PUSH_ON_KEY)
        .ok()
        .flatten()
        .is_some_and(|bytes| bytes.first() == Some(&1))
}

fn save_push_on(storage: &SharedStorage, on: bool) {
    let _ = storage.borrow_mut().put(PUSH_ON_KEY, &[u8::from(on)]);
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
    // Ein Grabstein hat leeren Text; die Seitenleiste zeigt dann einen
    // lesbaren Platzhalter statt einer leeren Zeile (wie apply_event).
    let snippet = if line.deleted {
        "(Nachricht gelöscht)".to_string()
    } else {
        line.text.clone()
    };
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

/// Wendet eine empfangene Bearbeitung oder Löschung auf den Verlauf eines
/// Chats an: die Zeile mit der Ziel-ID bekommt neuen Text (und die Marke
/// „bearbeitet") bzw. wird zum Grabstein. Nur Zeilen DES ABSENDERS des
/// Ereignisses sind betroffen (`event_from`): niemand kann fremde Nachrichten
/// bearbeiten oder löschen, auch nicht mit geratener ID (die 1:1-ID ist das
/// nicht erratbare Franking-Commitment). Ein Grabstein bleibt Grabstein (ein
/// nachlaufendes Edit weckt ihn nicht wieder).
///
/// Regel fürs Melden: die Zeile beweist stets den ZULETZT lesbaren Inhalt.
/// Bei einer Bearbeitung folgt die Melde-ID dem neuen Text (`edit_report_id`);
/// bei einer Löschung bleibt die alte Melde-ID, damit ein Absender Missbrauch
/// nicht durch Nachträgliches Löschen tilgen kann (der letzte gezeigte Inhalt
/// bleibt meldbar).
/// [ANNAHME: Jede so gemeldete Fassung ist ein echter, beweisbarer Versand;
/// eine bewusst überschriebene FRÜHERE Fassung ist danach nicht mehr mit
/// einem Klick meldbar (ihr Franking-Material liegt aber weiter lokal unter
/// `franking/<zustell-id>`, eine spätere Versions-Melde-Oberfläche könnte es
/// erreichen). Das deckt sich mit der offenen Frage in
/// specs/sealed-sender-und-abuse.md: welche Fassung eine bearbeitete
/// Nachricht belegt, ist eine Politik-Entscheidung, keine
/// Krypto-Eigenschaft.]
///
/// Aktualisiert den Seitenleisten-Auszug, falls die letzte Zeile betroffen
/// war, und liefert die neue Liste; ohne Treffer ändert sich nichts.
fn apply_event(
    storage: &SharedStorage,
    peer: &str,
    event_from: &str,
    target: &str,
    new_text: Option<&str>,
    edit_report_id: Option<String>,
) -> Option<Vec<ChatSummary>> {
    if target.is_empty() {
        return None;
    }
    let mut history = load_history(storage, peer);
    let line = history
        .iter_mut()
        .find(|l| l.id == target && l.from == event_from && !l.deleted)?;
    match new_text {
        Some(text) => {
            line.text = text.to_string();
            line.edited = true;
            // Die Meldbarkeit folgt dem gezeigten (neuen) Text; ohne
            // Melde-Material (Selbst-Edit, Gruppe) bleibt sie unverändert.
            if edit_report_id.is_some() {
                line.report_id = edit_report_id;
            }
        }
        None => {
            line.text = String::new();
            line.deleted = true;
            // report_id bleibt: der letzte gezeigte Inhalt bleibt meldbar.
        }
    }
    save_history(storage, peer, &history);

    // Der Auszug in der Seitenleiste zeigt die letzte Zeile; war GENAU die
    // (nach ID und Autor) die betroffene, zieht er nach.
    let last_changed = history
        .last()
        .is_some_and(|l| l.id == target && l.from == event_from);
    let mut summaries = load_summaries(storage);
    if last_changed {
        if let Some(summary) = summaries.iter_mut().find(|s| s.peer == peer) {
            summary.snippet = match new_text {
                Some(text) => text.to_string(),
                None => "(Nachricht gelöscht)".to_string(),
            };
            save_summaries(storage, &summaries);
        }
    }
    Some(summaries)
}

/// Entfernt eine Zeile nur LOKAL aus dem Verlauf („für mich löschen"): kein
/// Ereignis reist über die Leitung, andere Geräte und der Empfänger behalten
/// ihre Kopie. Aktualisiert den Seitenleisten-Auszug und liefert die neue
/// Liste.
fn remove_line_local(storage: &SharedStorage, peer: &str, target: &str) -> Vec<ChatSummary> {
    let mut history = load_history(storage, peer);
    history.retain(|l| l.id.is_empty() || l.id != target);
    save_history(storage, peer, &history);

    let snippet = history.last().map(|l| l.text.clone()).unwrap_or_default();
    let mut summaries = load_summaries(storage);
    if let Some(summary) = summaries.iter_mut().find(|s| s.peer == peer) {
        summary.snippet = snippet;
        save_summaries(storage, &summaries);
    }
    summaries
}

/// Spielt einen nachgelieferten Verlauf (Koppeln) in die Ablage ein: die
/// Zeilen werden mit dem lokalen Verlauf des Chats zusammengeführt, nach
/// Zeit sortiert und auf `HISTORY_LIMIT` gekappt. Duplikate (dieselbe Zeile
/// aus Live-Empfang und Nachzug) fallen über (Absender, Text, Zeit) heraus,
/// sodass ein doppelter Nachzug oder eine Überschneidung mit schon
/// vorhandenen Zeilen nichts verdoppelt. Aktualisiert die Seitenleiste und
/// liefert die neue Liste; der Nachzug zählt nie ungelesen.
fn merge_history(
    storage: &SharedStorage,
    peer: &str,
    incoming: &[client_app::sync::HistLine],
) -> Vec<ChatSummary> {
    let mut history = load_history(storage, peer);
    for hl in incoming {
        let dup = history
            .iter()
            .any(|l| l.from == hl.from && l.text == hl.text && l.at == hl.at);
        if !dup {
            history.push(StoredLine {
                from: hl.from.clone(),
                text: hl.text.clone(),
                at: hl.at,
                report_id: None,
                // Der Verlaufs-Nachzug trägt keine Nachrichten-IDs; diese
                // Zeilen sind nachträglich nicht bearbeitbar (siehe HistLine).
                id: String::new(),
                edited: false,
                deleted: false,
            });
        }
    }
    history.sort_by_key(|l| l.at);
    save_history(storage, peer, &history);

    let snippet = history.last().map(|l| l.text.clone()).unwrap_or_default();
    let mut summaries = load_summaries(storage);
    if let Some(pos) = summaries.iter().position(|s| s.peer == peer) {
        let mut summary = summaries.remove(pos);
        summary.snippet = snippet;
        summaries.insert(0, summary);
    } else {
        summaries.insert(
            0,
            ChatSummary {
                peer: peer.to_string(),
                snippet,
                unread: 0,
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

/// Chat-Schlüssel einer Gruppe in Verlauf und Chatliste: `grp:<uuid>`.
/// Handles kennen keinen Doppelpunkt (Handle-Regel des identity-Dienstes),
/// der Präfix kollidiert also nie mit einem Kontakt-Chat.
const GROUP_CHAT_PREFIX: &str = "grp:";
// Die geteilten Ablage-Schlüssel (MLS_STATE_KEY, GROUPS_INDEX_KEY,
// INVITES_INDEX_KEY, COUNTER_KEY, roster_key/invite_key/invite_buffer_key)
// und Betriebskonstanten (CREDENTIAL_TTL_SECONDS, MLS_KEY_PACKAGE_TARGET,
// MAX_PENDING_INVITES, INVITE_BUFFER_MAX) kommen jetzt aus client-app
// (store_keys, policy), damit CLI und Web nicht auseinanderdriften.

fn load_invites(storage: &SharedStorage) -> Vec<String> {
    storage
        .borrow()
        .get(INVITES_INDEX_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_invites(storage: &SharedStorage, invites: &[String]) -> Result<(), String> {
    let bytes = serde_json::to_vec(invites).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(INVITES_INDEX_KEY, &bytes)
}

/// Merkt eine Einladung vor (Welcome-Blob ablegen, ID in die Liste),
/// ohne den Welcome zu verarbeiten. Liefert `true`, wenn sie neu ist.
fn invite_meta_key(group_id: &str) -> String {
    format!("invite-meta/{group_id}")
}

/// Anzeigetext einer Einladung aus Name und Einlader.
fn invite_banner_text(name: &str, inviter: &str) -> String {
    match (name.is_empty(), inviter.is_empty()) {
        (false, false) => format!("Einladung in „{name}“ von {inviter}"),
        (false, true) => format!("Einladung in „{name}“"),
        (true, false) => format!("Einladung in eine Gruppe von {inviter}"),
        (true, true) => "Einladung in eine Gruppe".to_string(),
    }
}

/// Liest die Einladungs-Metadaten (Name, Einlader) eines vorgemerkten
/// Beitritts; leere Strings, wenn nichts bekannt ist.
fn load_invite_meta(storage: &SharedStorage, group_id: &str) -> (String, String) {
    storage
        .borrow()
        .get(&invite_meta_key(group_id))
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .map(|m| {
            (
                m["name"].as_str().unwrap_or("").to_string(),
                m["inviter"].as_str().unwrap_or("").to_string(),
            )
        })
        .unwrap_or_default()
}

fn remember_invite(
    storage: &SharedStorage,
    group_id: &str,
    welcome_blob: &[u8],
    name: Option<&str>,
    inviter: Option<&str>,
) -> Result<bool, String> {
    let mut invites = load_invites(storage);
    if invites.iter().any(|id| id == group_id) {
        return Ok(false);
    }
    // Deckel gegen das Fluten (siehe MAX_PENDING_INVITES).
    if invites.len() >= MAX_PENDING_INVITES {
        return Ok(false);
    }
    storage
        .borrow_mut()
        .put(&invite_key(group_id), welcome_blob)?;
    let meta = serde_json::json!({
        "name": name.unwrap_or(""),
        "inviter": inviter.unwrap_or(""),
    });
    if let Ok(bytes) = serde_json::to_vec(&meta) {
        let _ = storage.borrow_mut().put(&invite_meta_key(group_id), &bytes);
    }
    invites.push(group_id.to_string());
    save_invites(storage, &invites)?;
    Ok(true)
}

/// Verwirft eine Einladung samt gepuffertem Verkehr (Annahme/Ablehnung).
fn forget_invite(storage: &SharedStorage, group_id: &str) -> Result<(), String> {
    let mut invites = load_invites(storage);
    invites.retain(|id| id != group_id);
    save_invites(storage, &invites)?;
    let _ = storage.borrow_mut().remove(&invite_key(group_id));
    let _ = storage.borrow_mut().remove(&invite_buffer_key(group_id));
    let _ = storage.borrow_mut().remove(&invite_meta_key(group_id));
    Ok(())
}

/// Puffert eine vor der Annahme eintreffende Gruppen-Hülle (etwa den
/// Roster), damit sie beim Beitritt nachgespielt werden kann. Base64 in
/// einer JSON-Liste.
fn buffer_invite_blob(storage: &SharedStorage, group_id: &str, blob: &[u8]) -> Result<(), String> {
    let key = invite_buffer_key(group_id);
    let mut buffered: Vec<String> = storage
        .borrow()
        .get(&key)?
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    // Puffer deckeln (der Roster kommt zuerst): kein Fluten der Ablage vor
    // einer Ablehnung.
    if buffered.len() >= INVITE_BUFFER_MAX {
        return Ok(());
    }
    buffered.push(BASE64.encode(blob));
    let bytes = serde_json::to_vec(&buffered).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(&key, &bytes)
}

fn load_invite_buffer(storage: &SharedStorage, group_id: &str) -> Result<Vec<Vec<u8>>, String> {
    let encoded: Vec<String> = storage
        .borrow()
        .get(&invite_buffer_key(group_id))?
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    encoded
        .iter()
        .map(|s| BASE64.decode(s).map_err(|e| e.to_string()))
        .collect()
}

fn group_chat_key(group_id: &str) -> String {
    format!("{GROUP_CHAT_PREFIX}{group_id}")
}

fn group_id_of(chat_key: &str) -> Option<&str> {
    chat_key.strip_prefix(GROUP_CHAT_PREFIX)
}

/// Zustand einer Gruppe in der lokalen Liste. `Active` ist der Normalfall
/// (der Client trägt lebenden MLS-Zustand); `Removed`/`Left` sind
/// Grabsteine: der MLS-Zustand ist gelöscht, der Chat-Verlauf bleibt
/// lesbar, aber Senden und Mitglieder-Aktionen sind aus. Als Grabstein
/// bleibt der Eintrag in der Liste, damit der Anzeigename samt Zusatz
/// „(entfernt)"/„(verlassen)" auch nach einem Neuladen erhalten ist
/// (sonst zeigte die Liste den nackten `grp:<uuid>`-Schlüssel).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
enum GroupStatus {
    #[default]
    Active,
    Removed,
    Left,
}

/// Ein Eintrag der lokalen Gruppenliste. Das `members`/`id`-Format ist
/// identisch zum CLI; `status` ergänzt der Web-Client (serde-Default
/// `active`, damit CLI-geschriebene Einträge ohne Feld lesbar bleiben).
#[derive(Serialize, Deserialize, Clone)]
struct GroupEntry {
    id: String,
    members: Vec<String>,
    #[serde(default)]
    status: GroupStatus,
}

/// Lädt das MLS-Mitglied aus der Ablage oder legt ein frisches an und
/// persistiert es sofort (die KeyPackage-Privatteile müssen jedes
/// Neuladen überleben, sonst wäre ein späterer Welcome wertlos).
fn load_or_new_member(storage: &SharedStorage, handle: &str) -> Result<GroupMember, String> {
    let existing = storage.borrow().get(MLS_STATE_KEY)?;
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
    storage.borrow_mut().put(MLS_STATE_KEY, state)
}

fn load_group_index(storage: &SharedStorage) -> Vec<GroupEntry> {
    storage
        .borrow()
        .get(GROUPS_INDEX_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Merkt eine Gruppe in der lokalen Liste vor (ersetzt einen bestehenden
/// Eintrag derselben ID).
fn remember_group(storage: &SharedStorage, entry: GroupEntry) -> Result<(), String> {
    let mut index = load_group_index(storage);
    index.retain(|g| g.id != entry.id);
    index.push(entry);
    let bytes = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(GROUPS_INDEX_KEY, &bytes)
}

/// Setzt eine Gruppe auf einen Grabstein-Zustand (entfernt/verlassen): der
/// Eintrag bleibt in der Liste (der Anzeigename samt Zusatz überlebt so das
/// Neuladen), die Mitglieder bleiben fürs Label erhalten, der Status
/// schaltet die Aktionen ab. Der MLS-Zustand und der Roster sind zu diesem
/// Zeitpunkt schon gelöscht (`forget`).
fn tombstone_group(
    storage: &SharedStorage,
    group_id: &str,
    status: GroupStatus,
) -> Result<(), String> {
    let mut index = load_group_index(storage);
    if let Some(entry) = index.iter_mut().find(|g| g.id == group_id) {
        entry.status = status;
    }
    let bytes = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(GROUPS_INDEX_KEY, &bytes)?;
    let _ = storage.borrow_mut().remove(&roster_key(group_id));
    Ok(())
}

fn save_roster(
    storage: &SharedStorage,
    group_id: &str,
    devices: &[RosterDevice],
) -> Result<(), String> {
    let bytes = serde_json::to_vec(devices).map_err(|e| e.to_string())?;
    storage.borrow_mut().put(&roster_key(group_id), &bytes)
}

fn load_roster(storage: &SharedStorage, group_id: &str) -> Result<Vec<RosterDevice>, String> {
    match storage.borrow().get(&roster_key(group_id))? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
        None => Err(
            "Geräte-Roster dieser Gruppe fehlt noch (der Gründer schickt ihn als erste \
             Gruppen-Nachricht; ein Abruf holt ihn)."
                .to_string(),
        ),
    }
}

/// Der Anzeigename einer Gruppe: die anderen Mitglieder, damit die Zeile
/// wie ein Gespräch liest („Gruppe: bert, carl").
fn group_label(members: &[String], own: &str) -> String {
    let others: Vec<&str> = members
        .iter()
        .filter(|m| m.as_str() != own)
        .map(String::as_str)
        .collect();
    if others.is_empty() {
        "Gruppe (nur ich)".to_string()
    } else {
        format!("Gruppe: {}", others.join(", "))
    }
}

/// Anzeige-Zustand eines Gruppen-Chats: der Listen-Name, die Mitglieder
/// (für die Mitgliederliste im Chat-Kopf) und ob die Gruppe vergessen ist
/// (Grabstein: kein MLS-Zustand mehr, Senden und Mitglieder-Aktionen aus).
#[derive(Clone)]
struct GroupUi {
    label: String,
    members: Vec<String>,
    forgotten: bool,
}

/// Baut den Anzeige-Zustand aus einem Gruppen-Eintrag: bei einem
/// Grabstein trägt das Label den Zusatz, und `forgotten` schaltet die
/// Aktionen ab.
fn group_ui(entry: &GroupEntry, own: &str) -> GroupUi {
    let base = group_label(&entry.members, own);
    let (label, forgotten) = match entry.status {
        GroupStatus::Active => (base, false),
        GroupStatus::Removed => (format!("{base} (entfernt)"), true),
        GroupStatus::Left => (format!("{base} (verlassen)"), true),
    };
    GroupUi {
        label,
        members: entry.members.clone(),
        forgotten,
    }
}

/// Alle Gruppen-Anzeigezustände aus der Ablage, für Chatliste und
/// Chat-Kopf (Schlüssel ist der `grp:`-Chat-Schlüssel).
fn load_group_labels(
    storage: &SharedStorage,
    own: &str,
) -> std::collections::HashMap<String, GroupUi> {
    load_group_index(storage)
        .iter()
        .map(|entry| (group_chat_key(&entry.id), group_ui(entry, own)))
        .collect()
}

/// Die Zustell-Ziele aus einem Roster: alle Geräte AUSSER dem eigenen. Es
/// wird nach der eigenen GERÄTE-ID gefiltert, nicht nach dem Handle: eigene
/// Zweitgeräte sind eigene MLS-Leaves und sollen die Nachricht bekommen
/// (Multi-Device), nur das sendende Gerät selbst nicht.
fn fanout_targets<'a>(
    roster: &'a [RosterDevice],
    own_device_id: &'a str,
) -> impl Iterator<Item = &'a RosterDevice> {
    roster
        .iter()
        .filter(move |device| device.device_id != own_device_id)
}

/// Die eindeutigen Handles aus einer Leaf-Identitätsliste
/// (`member_identities`): ein Multi-Device-Mitglied hat mehrere Leaves mit
/// demselben Handle, für Anzeige und `members`-Parameter zählt jeder einmal.
fn unique_handles(identities: Vec<Vec<u8>>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    identities
        .into_iter()
        .map(|id| String::from_utf8_lossy(&id).to_string())
        .filter(|handle| seen.insert(handle.clone()))
        .collect()
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

/// Formatiert einen Unix-Zeitstempel als lokales Datum (TT.MM.JJJJ) über die
/// JavaScript-Uhr des Browsers; für die Anzeige der Löschfrist.
fn format_date(at: u64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((at as f64) * 1000.0));
    format!(
        "{:02}.{:02}.{}",
        date.get_date(),
        date.get_month() + 1,
        date.get_full_year()
    )
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
    /// Konto-Wurzelschlüssel (Base64-Seed). Leer auf einem gekoppelten
    /// Zweitgerät (der Browser als Zweitgerät hält nur seine Geräte-Identität,
    /// nicht den Konto-Schlüssel; er kann senden und empfangen, aber keine
    /// weiteren Geräte freischalten).
    #[serde(default)]
    account_seed: String,
    /// Seed eines noch nicht bestätigten neuen Wurzelschlüssels (Base64),
    /// während einer laufenden Rotation (ADR-0010). VOR dem Serveraufruf
    /// abgelegt, nach dem bestätigten Erfolg nach `account_seed` befördert
    /// und geleert. Bricht der Aufruf zwischen Server-Commit und lokalem
    /// Ablegen ab, hält der Browser hier den neuen Schlüssel und schließt die
    /// Rotation beim nächsten Versuch ab, statt ausgesperrt zu sein.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pending_account_seed: String,
    device_id: String,
    /// Die vom Server vergebene libsignal-Gerätenummer (ProtocolAddress-Teil).
    /// Vorgabe 1 für Altprofile aus der Ein-Gerät-Zeit.
    #[serde(default = "one_u16")]
    protocol_device_id: u16,
}

fn one_u16() -> u16 {
    1
}

/// Ein bekanntes Kontakt-Gerät, Format identisch zum CLI
/// (`contact/{handle}` in der Ablage).
#[derive(Serialize, Deserialize, Clone)]
struct ContactDevice {
    server_device_id: String,
    protocol_device_id: u32,
}

/// Der Kopplungs-Antrag eines neuen Geräts, Format identisch zum CLI
/// (`sm link` gibt genau diese Base64-Zeile aus): Geräte-ID und
/// öffentlicher Geräteschlüssel. Der Web-Client als Erstgerät schaltet ihn
/// mit `approve` frei.
#[derive(Serialize, Deserialize)]
struct LinkRequest {
    device_id: String,
    device_public_key: String,
}

/// Eine Zeile der Geräteverwaltung: was die Oberfläche je Gerät zeigt.
#[derive(Clone)]
struct DeviceRow {
    id: String,
    name: String,
    protocol_device_id: u16,
    is_own: bool,
}

/// Was ein Abruf je Hülle liefert: eine gewöhnliche eingehende Nachricht,
/// eine Self-Sync-Kopie einer selbst (auf einem anderen Gerät) gesendeten
/// Nachricht (als ausgehend in den Verlauf), oder ein Verlaufs-Nachzug eines
/// anderen eigenen Geräts beim Koppeln (mehrere Zeilen für einen Chat).
enum Incoming {
    Message {
        from: String,
        text: String,
        report_id: Option<String>,
        /// Die Nachrichten-ID (Franking-Commitment; leer bei einer
        /// ungefrankten Alt-Nachricht, dann nicht bearbeitbar).
        id: String,
    },
    Synced {
        peer: String,
        text: String,
        id: String,
    },
    SyncedHistory {
        peer: String,
        lines: Vec<client_app::sync::HistLine>,
    },
    /// Ein 1:1-Anruf-Signal (Offer/Answer/ICE/Hangup) des Peers (F2). Reist
    /// verschlüsselt wie eine Nachricht, landet aber nicht im Verlauf, sondern
    /// bei der Anruf-Steuerung.
    Call {
        peer: String,
        signal: client_app::call::Signal,
    },
    /// Eine MLS-Gruppennachricht; der Absender kommt aus der von MLS
    /// geprüften Credential, nicht aus der Transport-Hülle.
    Group {
        group_id: String,
        from: String,
        text: String,
        id: String,
    },
    /// Eine Bearbeitung: die Zeile mit `target` im Chat `chat_peer` (ein
    /// Handle oder `grp:<id>`) bekommt neuen Text. Vereint 1:1, Gruppe und
    /// Self-Sync, weil die Anwendung überall dieselbe ist. `from` ist der
    /// Urheber des Ereignisses (1:1: der Absender; Gruppe: die MLS-geprüfte
    /// Credential; Self-Sync: das eigene Handle): nur SEINE Zeilen darf das
    /// Ereignis treffen. `report_id` ist das Melde-Material der Bearbeitung
    /// (deckt den NEUEN Text), damit eine bearbeitete Zeile weiter meldbar
    /// bleibt und nicht den alten Text beweist.
    Edit {
        chat_peer: String,
        from: String,
        target: String,
        text: String,
        report_id: Option<String>,
    },
    /// Eine Löschung bei allen: die Zeile mit `target` im Chat `chat_peer`
    /// wird zum Grabstein. `from` wie bei `Edit`.
    Delete {
        chat_peer: String,
        from: String,
        target: String,
    },
    /// Ein fremder Commit hat die Mitgliederliste geändert (Entfernung
    /// durch ein anderes Mitglied); Label nachführen.
    GroupUpdated {
        group_id: String,
        members: Vec<String>,
    },
    /// Ein fremder Commit hat DIESES Mitglied entfernt; der lokale
    /// Zustand ist schon aufgeräumt, die UI sagt es an.
    GroupRemovedSelf { group_id: String },
    /// Eine Einladung in eine Gruppe (Welcome vorgemerkt, noch nicht
    /// beigetreten); die UI bietet Annehmen/Ablehnen an. Name und Einlader
    /// (vom Einladenden bezeugt) fürs Banner.
    GroupInvite {
        group_id: String,
        name: String,
        inviter: String,
    },
}

/// Übersetzt ein entschlüsseltes Self-Sync-Ergebnis in einen `Incoming`.
/// `own` ist das eigene Handle (Urheber der Ereignisse aus dem Self-Sync).
/// `sealed` sagt, ob die Hülle versiegelt ankam: ein Änderungsereignis
/// (Bearbeitung/Löschung) wird NUR aus einer versiegelten Hülle angewandt,
/// weil nur dann das Zertifikat den Absender bindet; eine unversiegelte
/// Absenderadresse ist fälschbar und würde das Umschreiben/Löschen des
/// eigenen Verlaufs durch einen Dritten erlauben. Liefert `None`, wenn nichts
/// anzuwenden ist (unversiegeltes, also unglaubwürdiges Ereignis).
fn incoming_from_sync(
    own: &str,
    sealed: bool,
    synced: client_app::sync::Synced,
) -> Option<Incoming> {
    match synced {
        client_app::sync::Synced::Message { peer, text, id } => {
            Some(Incoming::Synced { peer, text, id })
        }
        client_app::sync::Synced::History { peer, lines } => {
            Some(Incoming::SyncedHistory { peer, lines })
        }
        // Ein auf einem anderen eigenen Gerät ausgelöstes Änderungsereignis.
        client_app::sync::Synced::Event { peer, event } => {
            if !sealed {
                leptos::logging::warn!(
                    "Unversiegelte Self-Sync-Änderung verworfen (nicht authentisch)."
                );
                return None;
            }
            match client_app::msg::decode(&event) {
                // Ein Text käme hier nur aus einem Alt-Payload; als
                // ausgehende Zeile ohne ID deuten.
                client_app::msg::Msg::Text { text } => Some(Incoming::Synced {
                    peer,
                    text,
                    id: String::new(),
                }),
                client_app::msg::Msg::Edit { target, text } => Some(Incoming::Edit {
                    chat_peer: peer,
                    from: own.to_string(),
                    target,
                    text,
                    // Die eigene Bearbeitung ist nicht zu melden (kein
                    // fremder Missbrauch); report_id bleibt leer.
                    report_id: None,
                }),
                client_app::msg::Msg::Delete { target } => Some(Incoming::Delete {
                    chat_peer: peer,
                    from: own.to_string(),
                    target,
                }),
            }
        }
    }
}

/// Übersetzt eine entschlüsselte 1:1-`smmsg`-Deutung in einen `Incoming`. Der
/// Chat ist der Absender (`from`); ein Text bekommt seine Nachrichten-ID aus
/// dem Franking-Commitment (`id`), eine Bearbeitung/Löschung trifft die Zeile
/// mit der Ziel-ID.
///
/// `sealed` sagt, ob die Hülle versiegelt ankam. Eine Bearbeitung/Löschung
/// wird NUR aus einer versiegelten Hülle angewandt: echte Änderungen gehen
/// immer versiegelt (`edit_message`/`delete_message`), und nur dann bindet
/// das Zertifikat den Absender. Eine unversiegelte Hülle trägt die
/// Absenderadresse im Klartext (fälschbar, Trust-on-first-use); ohne diese
/// Schranke könnte ein Dritter (etwa ein neugieriger Dienst, der das
/// Commitment als Franking-Tag kennt) ein Löschen/Umschreiben einer echten
/// Nachricht unter dem Handle des Absenders unterschieben. Ein Text bleibt
/// auch unversiegelt zulässig (das war schon immer so; eine gefälschte
/// EINGEHENDE Zeile ist die Alt-Eigenschaft des unversiegelten Kanals, das
/// NEUE Risiko ist nur das Verändern bestehenden Verlaufs). Liefert `None`,
/// wenn ein unversiegeltes Änderungsereignis verworfen wird.
fn incoming_from_msg(
    from: String,
    msg: client_app::msg::Msg,
    report_id: Option<String>,
    id: String,
    sealed: bool,
) -> Option<Incoming> {
    match msg {
        client_app::msg::Msg::Text { text } => Some(Incoming::Message {
            from,
            text,
            report_id,
            id,
        }),
        client_app::msg::Msg::Edit { target, text } if sealed => Some(Incoming::Edit {
            chat_peer: from.clone(),
            from,
            target,
            text,
            report_id,
        }),
        client_app::msg::Msg::Delete { target } if sealed => Some(Incoming::Delete {
            chat_peer: from.clone(),
            from,
            target,
        }),
        client_app::msg::Msg::Edit { .. } | client_app::msg::Msg::Delete { .. } => {
            leptos::logging::warn!("Unversiegelte 1:1-Änderung verworfen (nicht authentisch).");
            None
        }
    }
}

/// Verarbeitet eine eingehende Gruppen-Hülle, wie im CLI: bekannte Gruppe
/// heißt MLS `process` (Text anzeigen, Roster übernehmen, fremde Commits
/// anwenden), unbekannte heißt Welcome-Beitritt. Der MLS-Zustand wird
/// nach JEDER Verarbeitung gesichert (der Ratchet ist weitergelaufen);
/// ein Abbruch davor läuft beim nächsten Abruf auf denselben Zustand auf.
fn handle_group_envelope(
    storage: &SharedStorage,
    own_handle: &str,
    group_id: &str,
    blob: &[u8],
    invite_name: Option<&str>,
    invite_inviter: Option<&str>,
) -> Result<Option<Incoming>, String> {
    let member = load_or_new_member(storage, own_handle)?;
    match GroupSession::load(member, group_id.as_bytes())? {
        Some(mut session) => {
            let inbound = session.process(blob)?;
            match inbound {
                GroupInbound::Application(application) => {
                    save_member_state(storage, &session.export_state()?)?;
                    let sender = String::from_utf8_lossy(&application.sender_identity).to_string();
                    match grouptext::decode(&application.plaintext).map_err(|e| e.to_string())? {
                        GroupPayload::Text { id, text } => Ok(Some(Incoming::Group {
                            group_id: group_id.to_string(),
                            from: sender,
                            text,
                            id,
                        })),
                        GroupPayload::Edit { target, text } => Ok(Some(Incoming::Edit {
                            chat_peer: group_chat_key(group_id),
                            from: sender,
                            target,
                            text,
                            // Gruppen-Hüllen tragen kein Franking; nichts zu
                            // melden.
                            report_id: None,
                        })),
                        GroupPayload::Delete { target } => Ok(Some(Incoming::Delete {
                            chat_peer: group_chat_key(group_id),
                            from: sender,
                            target,
                        })),
                        GroupPayload::Roster { devices } => {
                            save_roster(storage, group_id, &devices)?;
                            Ok(None)
                        }
                        // Die Ansage erscheint als Zeile im Gruppen-Chat;
                        // das kryptografische Entfernen bleibt Sache eines
                        // verbleibenden Mitglieds.
                        GroupPayload::Leave => Ok(Some(Incoming::Group {
                            group_id: group_id.to_string(),
                            from: sender,
                            text: "(verlässt die Gruppe)".to_string(),
                            id: String::new(),
                        })),
                    }
                }
                // Fremder Commit: Mitgliederliste nachführen (der Eintrag
                // speist die Anzeigenamen), sonst nichts anzuzeigen.
                GroupInbound::Updated => {
                    save_member_state(storage, &session.export_state()?)?;
                    let members = unique_handles(session.member_identities());
                    // Roster selbst-heilen: Geräte ausgeschiedener Handles
                    // fallen heraus, auch wenn die neue Roster-Nachricht nie
                    // ankommt (sonst wiese der Dienst einen späteren Versand
                    // wegen unknown_device wholesale ab).
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
                            status: GroupStatus::Active,
                        },
                    )?;
                    Ok(Some(Incoming::GroupUpdated {
                        group_id: group_id.to_string(),
                        members,
                    }))
                }
                // Der Commit hat DIESES Mitglied entfernt: Zustand löschen,
                // die Gruppe als Grabstein markieren (der Verlauf und der
                // Anzeigename samt „(entfernt)" überleben ein Neuladen).
                GroupInbound::RemovedSelf => {
                    let member = session.forget()?;
                    save_member_state(storage, &member.export_state()?)?;
                    tombstone_group(storage, group_id, GroupStatus::Removed)?;
                    Ok(Some(Incoming::GroupRemovedSelf {
                        group_id: group_id.to_string(),
                    }))
                }
            }
        }
        None => {
            // Unbekannte Gruppe: ein Welcome ist eine EINLADUNG, die nur
            // vorgemerkt wird (kein automatischer Beitritt; sonst könnte
            // jeder Authentifizierte ein Gerät in seine Gruppe ziehen). Der
            // Welcome wird nicht verarbeitet, damit eine abgelehnte oder
            // Spam-Einladung kein KeyPackage kostet. Verkehr, der vor der
            // Annahme eintrifft (etwa der Roster), wird gepuffert.
            if GroupSession::is_welcome(blob) {
                if remember_invite(storage, group_id, blob, invite_name, invite_inviter)? {
                    Ok(Some(Incoming::GroupInvite {
                        group_id: group_id.to_string(),
                        name: invite_name.unwrap_or("").to_string(),
                        inviter: invite_inviter.unwrap_or("").to_string(),
                    }))
                } else {
                    Ok(None)
                }
            } else if load_invites(storage).iter().any(|id| id == group_id) {
                buffer_invite_blob(storage, group_id, blob)?;
                Ok(None)
            } else {
                // Nachricht einer Gruppe, in der wir nicht sind: verwerfen.
                Ok(None)
            }
        }
    }
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
    /// Bei einer vorgemerkten Konto-Löschung der Ablauf der Widerrufsfrist
    /// (Unix-Sekunden), aus der Login-Antwort; `None` bei einem aktiven
    /// Konto. Nur der `login`-Weg kann ihn tragen (der Server meldet ihn bei
    /// der Anmeldung); Registrierung und Kopplung setzen `None`.
    deletion_pending_until: Option<u64>,
    /// Anzeigename des Kontos (F010) aus der Login-Antwort, zum Anzeigen
    /// und Vorbelegen in den Einstellungen. Alle drei Wege (Registrierung,
    /// Anmeldung, Kopplung) enden in einem Login und tragen ihn.
    display_name: Option<String>,
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

/// Rendert Daten als QR-Code zu einem Inline-SVG (dunkle Module auf weißem
/// Grund, mit Ruhezone). Selbst gezeichnet aus der Modul-Matrix, damit keine
/// Fremd-Ressource nötig ist und die Content-Security-Policy nichts laden
/// muss. Schwarz auf Weiß unabhängig vom Modus: QR-Leser erwarten dunkel auf
/// hell, ein invertierter Code scheitert bei manchen Scannern.
fn qr_svg(data: &str) -> Option<String> {
    use qrcode::types::Color;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes()).ok()?;
    let width = code.width();
    let quiet = 4usize;
    let size = width + 2 * quiet;
    let colors = code.to_colors();
    let mut rects = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                rects.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"1\" height=\"1\"/>",
                    x + quiet,
                    y + quiet
                ));
            }
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         width=\"100%\" height=\"100%\" shape-rendering=\"crispEdges\" \
         role=\"img\" aria-label=\"QR-Code des Kopplungs-Codes\">\
         <rect width=\"{size}\" height=\"{size}\" fill=\"#ffffff\"/>\
         <g fill=\"#000000\">{rects}</g></svg>"
    ))
}

/// Löst die Freischalt-Eingabe zu einem Kopplungs-Antrag auf: ist die Eingabe
/// ein Kopplungs-Code (ein 32-Byte-Geheimnis aus dem QR), wird der Antrag
/// über den Relay geholt und entschlüsselt; sonst ist die Eingabe schon der
/// Antrag als Text (der manuelle Weg). Ein Geheimnis ist am festen Format
/// eindeutig erkennbar (genau 32 Byte Base64), ein Antrag ist länger.
async fn resolve_link_input(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let Ok(secret) = provisioning::Secret::from_b64(trimmed) else {
        // Kein Geheimnis: die Eingabe ist der Antrag selbst.
        return Ok(trimmed.to_string());
    };
    let channel = secret.channel_id();
    let (nonce, ciphertext) = IdentityClient::new(identity_url())
        .provision_get(&channel)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            "Kein Kopplungs-Antrag unter diesem Code (abgelaufen oder falsch abgetippt)."
                .to_string()
        })?;
    let plaintext = provisioning::open(&secret, &nonce, &ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(plaintext).map_err(|e| format!("Antrag unlesbar: {e}"))
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

/// Bietet Bytes als Datei-Download an: ein Blob, eine Objekt-URL und ein
/// programmatisch geklickter Anker. Rein clientseitig, nichts verlässt den
/// Browser (die Sicherung ist ohnehin schon verschlüsselt).
fn download_file(filename: &str, bytes: &[u8]) -> Result<(), String> {
    use wasm_bindgen::JsCast as _;
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)
        .map_err(|_| "Blob nicht erzeugbar".to_string())?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|_| "Objekt-URL nicht erzeugbar".to_string())?;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("kein Dokument")?;
    let anchor = document
        .create_element("a")
        .map_err(|_| "Anker nicht erzeugbar".to_string())?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "kein Anker-Element".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    anchor.click();
    // Die Objekt-URL erst NACH einem kurzen Tick freigeben: manche Browser
    // brechen den gerade angestoßenen Download ab, wenn die URL im selben
    // synchronen Ablauf schon wieder ungültig ist.
    spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(1_000).await;
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    Ok(())
}

/// Liest die Bytes einer im Datei-Feld gewählten Datei (asynchron über die
/// File-API des Browsers).
async fn read_file_bytes(file: &web_sys::File) -> Result<Vec<u8>, String> {
    let buffer = wasm_bindgen_futures::JsFuture::from(file.array_buffer())
        .await
        .map_err(|_| "Datei nicht lesbar".to_string())?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

/// Konto anlegen: Schlüssel erzeugen, registrieren, anmelden, Prekeys
/// veröffentlichen, Profil und Zähler verankern. Ein Schritt aus
/// Nutzersicht, weil ein frisch angelegtes Konto ohne veröffentlichte
/// Prekeys nicht erreichbar wäre.
async fn onboard(
    storage: SharedStorage,
    handle: String,
    password: String,
    display_name: Option<String>,
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
            display_name: display_name.as_deref(),
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
    // MLS-KeyPackages fürs Eingeladen-werden in Gruppen, wie beim CLI.
    top_up_mls_key_packages(&storage, &session.access_token, &handle).await?;
    save_profile(
        &storage,
        &Profile {
            handle: handle.clone(),
            account_seed: BASE64.encode(account_key.to_seed()),
            pending_account_seed: String::new(),
            device_id,
            // Das erste Gerät ist immer Nummer 1 (der Server bestätigt es).
            protocol_device_id: 1,
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
        // Frisch registriert bzw. gekoppelt: keine Löschung vorgemerkt.
        deletion_pending_until: None,
        display_name: session.display_name,
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
    // Den Self-Sync-Cache leeren: ein seit der letzten Anmeldung von einem
    // anderen Gerät gekoppeltes (oder entferntes) Gerät wird so beim nächsten
    // Senden neu aufgelöst.
    let _ = storage.borrow_mut().remove(OWN_DEVICES_KEY);
    // Den MLS-KeyPackage-Vorrat auffüllen (das Verzeichnis konsumiert je
    // Gruppen-Einladung eines); best effort, eine Anmeldung soll daran
    // nicht scheitern.
    if let Err(error) =
        top_up_mls_key_packages(&storage, &session.access_token, &profile.handle).await
    {
        leptos::logging::warn!("MLS-KeyPackages nachlegen: {error}");
    }
    let next_prekey_id = load_counter(&storage)?;
    let protocol_device_id = u8::try_from(profile.protocol_device_id)
        .map_err(|_| format!("Gerätenummer {} über 255", profile.protocol_device_id))?;
    let device = Device::with_store(
        &profile.handle,
        protocol_device_id,
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
        // Nur die Anmeldung erfährt vom Server, ob eine Löschung läuft.
        deletion_pending_until: session.deletion_pending_until,
        display_name: session.display_name,
    })
}

/// Beginnt die Kopplung dieses Browsers als ZWEITGERÄT (Gegenstück zu
/// `sm link`): erzeugt eine frische Geräte-Identität, legt ein vorläufiges
/// Profil an (kein Konto-Wurzelschlüssel, Nummer 0 = noch nicht
/// freigeschaltet) und liefert den Kopplungs-Antrag als eine Base64-Zeile.
/// Der wird auf dem Erstgerät freigeschaltet, danach schließt `link_finish`
/// ab. Bewusst noch unverschlüsselt: das Passwort ist erst nach der
/// Server-Anmeldung bestätigt (wie bei `login`), und in diesem Zustand liegt
/// nur die frische, noch nicht autorisierte Geräte-Identität in der Ablage,
/// keine Nachrichten.
/// Ergebnis von `link_start`: der Kopplungs-Antrag als Text (immer, der
/// manuelle Weg) und, falls das Ablegen beim Relay klappte, das Geheimnis
/// für den QR-Code (der bequeme Weg).
struct LinkStarted {
    payload: String,
    secret: Option<String>,
}

async fn link_start(storage: SharedStorage, handle: String) -> Result<LinkStarted, String> {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let registration_id = rand::Rng::random_range(&mut rng, 1u32..16380);
    store_own_identity(&storage, &identity.serialize(), registration_id)
        .map_err(|e| e.to_string())?;
    // Die Nummer steht erst nach dem Freischalten fest; für die
    // Schlüsselerzeugung ist sie belanglos (der Identitätsschlüssel hängt
    // nicht an der Adresse), deshalb hier 1.
    let mut device = Device::with_store(
        &handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        1,
    )
    .map_err(|e| e.to_string())?;
    let device_public = BASE64.encode(device.identity_public().await.map_err(|e| e.to_string())?);
    let device_id = new_uuid();
    save_profile(
        &storage,
        &Profile {
            handle,
            account_seed: String::new(),
            pending_account_seed: String::new(),
            device_id: device_id.clone(),
            protocol_device_id: 0,
        },
    )?;
    let request = LinkRequest {
        device_id,
        device_public_key: device_public,
    };
    let payload = BASE64.encode(serde_json::to_vec(&request).map_err(|e| e.to_string())?);

    // Für die QR-Kopplung den Antrag zusätzlich unter einem frischen
    // Geheimnis verschlüsseln und beim Relay ablegen. Das Geheimnis geht in
    // den QR-Code; der Relay sieht nur Chiffretext (provisioning-Crate).
    // Scheitert das Ablegen (Netz, Kanal-Kollision), bleibt der manuelle Weg
    // (Antrag als Text kopieren), deshalb kein harter Fehler.
    let secret = provisioning::Secret::generate();
    let sealed = provisioning::seal(&secret, payload.as_bytes());
    let relay_ok = IdentityClient::new(identity_url())
        .provision_put(
            &sealed.channel_id,
            &sealed.nonce_b64,
            &sealed.ciphertext_b64,
        )
        .await
        .is_ok();

    Ok(LinkStarted {
        payload,
        secret: relay_ok.then(|| secret.to_b64()),
    })
}

/// Rekonstruiert den Kopplungs-Antrag aus einem angefangenen (Nummer 0)
/// Profil, damit ein Neuladen mitten in der Kopplung sie fortsetzen kann.
async fn pending_link_payload(storage: &SharedStorage) -> Option<String> {
    let profile = load_profile(storage)?;
    if profile.protocol_device_id != 0 {
        return None;
    }
    let mut device = Device::with_store(
        &profile.handle,
        1,
        PersistentProtocolStore::open(storage.clone()),
        1,
    )
    .ok()?;
    let device_public = BASE64.encode(device.identity_public().await.ok()?);
    let request = LinkRequest {
        device_id: profile.device_id,
        device_public_key: device_public,
    };
    Some(BASE64.encode(serde_json::to_vec(&request).ok()?))
}

/// Schließt die Kopplung ab, nachdem das Erstgerät den Antrag freigeschaltet
/// hat (Gegenstück zu `sm link-finish`): meldet sich an (jetzt möglich, das
/// Gerät ist freigeschaltet), liest die vom Server vergebene Nummer aus der
/// eigenen Gerätemenge, verankert sie im Profil, verschlüsselt die Ablage
/// unter dem bestätigten Passwort und veröffentlicht die Prekeys.
async fn link_finish(storage: SharedStorage, password: String) -> Result<Onboarded, String> {
    let profile = load_profile(&storage).ok_or_else(|| "Kein Profil in der Ablage".to_string())?;
    let identity_client = IdentityClient::new(identity_url());
    let session = identity_client
        .login(&profile.handle, &password, &profile.device_id)
        .await
        .map_err(|e| e.to_string())?;
    // Die eigene Nummer aus der Gerätemenge holen (der Server hat sie beim
    // Freischalten vergeben).
    let devices = identity_client
        .devices(&session.access_token)
        .await
        .map_err(|e| e.to_string())?;
    let mine = devices.iter().find(|d| d.id == profile.device_id).ok_or_else(|| {
        "Dieses Gerät steht noch nicht in der Gerätemenge. Zuerst auf dem Erstgerät freischalten."
            .to_string()
    })?;
    if mine.protocol_device_id == 0 {
        return Err("Der Server hat keine Gerätenummer geliefert (zu alter Server?).".to_string());
    }
    let protocol_device_id = mine.protocol_device_id;
    // Jetzt ist das Passwort server-bestätigt: die Ablage verschlüsseln.
    storage.borrow_mut().adopt_passphrase(&password);
    save_profile(
        &storage,
        &Profile {
            handle: profile.handle.clone(),
            account_seed: String::new(),
            pending_account_seed: String::new(),
            device_id: profile.device_id.clone(),
            protocol_device_id,
        },
    )?;

    let next_prekey_id = load_counter(&storage)?;
    let number = u8::try_from(protocol_device_id)
        .map_err(|_| format!("Gerätenummer {protocol_device_id} über 255"))?;
    let mut device = Device::with_store(
        &profile.handle,
        number,
        PersistentProtocolStore::open(storage.clone()),
        next_prekey_id,
    )
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
    // MLS-KeyPackages fürs Eingeladen-werden in Gruppen, wie beim CLI.
    top_up_mls_key_packages(&storage, &session.access_token, &profile.handle).await?;

    Ok(Onboarded {
        core: Core {
            device,
            handle: profile.handle,
            storage,
        },
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
        // Frisch registriert bzw. gekoppelt: keine Löschung vorgemerkt.
        deletion_pending_until: None,
        display_name: session.display_name,
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

/// Die eigene libsignal-Gerätenummer aus der Geräteadresse (der
/// ProtocolAddress-Teil). Sie stimmt mit der server-vergebenen Nummer aus
/// dem Profil überein (onboard/login/link bauen das Gerät damit) und ist
/// beim Senden die eine Quelle: das Erstgerät nutzt 1, ein gekoppeltes
/// Zweitgerät seine zugewiesene Nummer.
fn own_device_number(core: &Core) -> u32 {
    u32::from(core.device.address().device_id())
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
/// Wie die Self-Sync-Kopie einer 1:1-Zustellung aussieht: eine gewöhnliche
/// Nachricht (Text + ID) oder ein Änderungsereignis (rohe smmsg-Bytes).
enum SelfCopy<'a> {
    Text { text: &'a str },
    Event { event: &'a [u8] },
}

async fn deliver_1to1(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    plaintext: &[u8],
    sealed: bool,
    self_copy: SelfCopy<'_>,
    expires_at: Option<u64>,
) -> Result<String, String> {
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
    // Franking-Schlüssel reist im verschlüsselten Payload, das Commitment als
    // Tag an der Hülle und ist zugleich die stabile Nachrichten-ID.
    let franked = client_app::franking::frank(plaintext);
    let franking_tag = BASE64.encode(&franked.commitment);
    let id = client_app::franking::commitment_id(&franked.commitment);
    // Sealed braucht das Absender-Zertifikat (gecacht); dasselbe deckt die
    // Self-Sync-Kopie ab.
    let certificate = if sealed {
        let number = own_device_number(core);
        Some(sender_certificate_cached(token, number, &core.storage).await?)
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
                wire::seal(&core.handle, own_device_number(core), &message)
                    .map_err(|e| e.to_string())?
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
    // Self-Sync: die Kopie an die eigenen Zweitgeräte. Ein Text reist als
    // gewöhnliche Nachricht mit seiner ID; ein Änderungsereignis als
    // versiegeltes smmsg (nur so vertraut die Empfangsseite dem Ereignis).
    // Best effort: scheitert das, ist die Nachricht beim Empfänger trotzdem
    // raus.
    let self_payload = match self_copy {
        SelfCopy::Text { text } => client_app::sync::encode(peer, text, &id),
        SelfCopy::Event { event } => client_app::sync::encode_event(peer, event),
    };
    match build_sync_envelopes(
        core,
        token,
        certificate.as_deref(),
        &self_payload,
        expires_at,
    )
    .await
    {
        Ok(mut sync) => envelopes.append(&mut sync),
        Err(error) => leptos::logging::warn!("Self-Sync übersprungen: {error}"),
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
    Ok(id)
}

/// Löst die Geräte eines Kontakts auf (aus dem Cache oder per Bündel-Abruf
/// samt Sitzungsaufbau) und cacht sie. Geteilt von der Nachrichten- und der
/// Anruf-Signalisierung.
async fn resolve_peer_devices(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
) -> Result<Vec<ContactDevice>, String> {
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
    if !known.is_empty() {
        return Ok(known);
    }
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
    Ok(contact)
}

/// Sendet ein Anruf-Signal (F2) an alle Geräte des Peers: Ende-zu-Ende über
/// den Ratchet verschlüsselt, aber NICHT gefrankt (flüchtige Steuerung, keine
/// meldbare Nachricht) und ohne Self-Sync. Kurze Frist, weil ein Signal an ein
/// abwesendes Gerät wertlos ist.
async fn send_call_signal(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    signal: &client_app::call::Signal,
) -> Result<(), String> {
    let devices = resolve_peer_devices(core, token, peer).await?;
    let plaintext = signal.encode();
    let expires_at = Some(now_unix() + 120);
    let mut envelopes = Vec::with_capacity(devices.len());
    for target in &devices {
        let address = ProtocolAddress::new(
            peer.to_string(),
            device_id_from_u32(target.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let message = core
            .device
            .encrypt(&address, &plaintext)
            .await
            .map_err(|e| format!("Signal-Verschlüsselung: {e}"))?;
        let envelope = wire::seal(&core.handle, own_device_number(core), &message)
            .map_err(|e| e.to_string())?;
        envelopes.push(OutgoingEnvelope {
            id: new_uuid(),
            recipient: peer.to_string(),
            device_id: target.server_device_id.clone(),
            envelope,
            franking_tag: None,
            expires_at,
        });
    }
    DeliveryClient::new(delivery_url())
        .submit(&token.get_untracked(), &envelopes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Baut den Signal-Sink für eine `CallSession`: jedes ausgehende Signal wird
/// verschlüsselt an den Peer gesendet. Nimmt den Core kurz aus dem RefCell
/// (wie run_send), damit kein Borrow über das await gehalten wird; überlappt
/// ein Signal mit einer anderen Core-Operation, geht es verloren (ICE hat
/// Redundanz, dokumentierte Grenze der Referenz-Umsetzung).
fn call_sink(core: SharedCore, token: ReadSignal<String>, peer: String) -> crate::call::SignalSink {
    Rc::new(move |signal: client_app::call::Signal| {
        let core = core.clone();
        let peer = peer.clone();
        spawn_local(async move {
            let taken = core.borrow_mut().take();
            if let Some(mut active) = taken {
                if let Err(error) = send_call_signal(&mut active, token, &peer, &signal).await {
                    leptos::logging::warn!("Anruf-Signal nicht gesendet: {error}");
                }
                *core.borrow_mut() = Some(active);
            } else {
                leptos::logging::warn!("Anruf-Signal übersprungen (Core gerade belegt)");
            }
        })
    })
}

/// Sendet eine neue 1:1-Nachricht (roher Text) und liefert ihre ID (das
/// Franking-Commitment) zurück, damit die eigene Verlaufszeile sie trägt und
/// ein späteres Bearbeiten/Löschen sie trifft.
async fn send_message(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    text: &str,
    expires_at: Option<u64>,
    sealed: bool,
) -> Result<String, String> {
    deliver_1to1(
        core,
        token,
        peer,
        text.as_bytes(),
        sealed,
        SelfCopy::Text { text },
        expires_at,
    )
    .await
}

/// Bearbeitet eine früher gesendete 1:1-Nachricht bei allen. Reist IMMER
/// versiegelt: so bindet das Zertifikat den Absender, und die Empfangsseite
/// vertraut der Self-Sync-Kopie (eine unversiegelte, fälschbare Absender-
/// adresse würde das Umschreiben fremder Verläufe erlauben).
async fn edit_message(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    target: &str,
    text: &str,
) -> Result<(), String> {
    let event = client_app::msg::encode_edit(target, text);
    deliver_1to1(
        core,
        token,
        peer,
        &event,
        true,
        SelfCopy::Event { event: &event },
        None,
    )
    .await?;
    Ok(())
}

/// Löscht eine früher gesendete 1:1-Nachricht bei allen (immer versiegelt,
/// siehe `edit_message`); die Empfangsseite ersetzt sie durch einen
/// Grabstein.
async fn delete_message(
    core: &mut Core,
    token: ReadSignal<String>,
    peer: &str,
    target: &str,
) -> Result<(), String> {
    let event = client_app::msg::encode_delete(target);
    deliver_1to1(
        core,
        token,
        peer,
        &event,
        true,
        SelfCopy::Event { event: &event },
        None,
    )
    .await?;
    Ok(())
}

/// Löst die eigenen ANDEREN Geräte auf und baut je Gerät eine
/// Self-Sync-Kopie (Gegenstück zur CLI). Die Geräteliste wird gecacht
/// (`sync/own_devices`); Schlüssel-vorhanden heißt aufgelöst (auch leer =
/// keine Zweitgeräte), damit ein Ein-Gerät-Konto nicht bei jedem Senden
/// erneut auflöst und Prekeys verbraucht. Das eigene Gerät (Erst- oder
/// gekoppeltes Zweitgerät) fällt über `own_device_number` heraus. Der Cache
/// wird bei der Anmeldung geleert, damit ein neu gekoppeltes Gerät auftaucht.
///
/// Löst die eigenen ANDEREN Geräte auf und baut je Gerät eine Sitzung, mit
/// Cache in der Ablage (`sync/own_devices`): Schlüssel-vorhanden heißt
/// aufgelöst (auch leer = keine Zweitgeräte), damit ein Ein-Gerät-Konto
/// nicht bei jedem Senden erneut auflöst und Prekeys verbraucht. Das eigene
/// Gerät fällt über `own_device_number` heraus. Der Cache wird nach
/// Freischalten und bei der Anmeldung geleert, damit ein neu gekoppeltes
/// Gerät auftaucht. Geteilt von Self-Sync und Verlaufs-Nachzug.
async fn own_siblings(
    core: &mut Core,
    token: ReadSignal<String>,
) -> Result<Vec<ContactDevice>, String> {
    let cached = core
        .storage
        .borrow()
        .get(OWN_DEVICES_KEY)
        .map_err(|e| e.to_string())?;
    if let Some(bytes) = cached {
        return serde_json::from_slice(&bytes).map_err(|e| format!("Eigene Geräte unlesbar: {e}"));
    }
    let bundles = DirectoryClient::new(directory_url())
        .bundles(&token.get_untracked(), &core.handle)
        .await
        .map_err(|e| e.to_string())?;
    let mut siblings = Vec::new();
    for bundle_json in &bundles.devices {
        let (bundle, protocol_device_id) =
            bundle_from_directory(bundle_json).map_err(|e| e.to_string())?;
        if protocol_device_id == own_device_number(core) {
            continue; // das eigene Gerät bekommt keine Kopie
        }
        let address = ProtocolAddress::new(
            core.handle.clone(),
            device_id_from_u32(protocol_device_id).map_err(|e| e.to_string())?,
        );
        core.device
            .establish_session(&address, &bundle)
            .await
            .map_err(|e| format!("Sitzungsaufbau (eigenes Gerät): {e}"))?;
        siblings.push(ContactDevice {
            server_device_id: bundle_json.device_id.clone(),
            protocol_device_id,
        });
    }
    let json = serde_json::to_vec(&siblings).map_err(|e| e.to_string())?;
    core.storage
        .borrow_mut()
        .put(OWN_DEVICES_KEY, &json)
        .map_err(|e| e.to_string())?;
    Ok(siblings)
}

async fn build_sync_envelopes(
    core: &mut Core,
    token: ReadSignal<String>,
    certificate: Option<&[u8]>,
    payload: &[u8],
    expires_at: Option<u64>,
) -> Result<Vec<OutgoingEnvelope>, String> {
    let siblings = own_siblings(core, token).await?;
    if siblings.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(siblings.len());
    for sib in &siblings {
        let address = ProtocolAddress::new(
            core.handle.clone(),
            device_id_from_u32(sib.protocol_device_id).map_err(|e| e.to_string())?,
        );
        let envelope = match certificate {
            Some(cert) => {
                let blob = core
                    .device
                    .seal_message(&address, cert, payload)
                    .await
                    .map_err(|e| format!("Versiegeln (Sync): {e}"))?;
                wire::seal_sealed(&blob).map_err(|e| e.to_string())?
            }
            None => {
                let message = core
                    .device
                    .encrypt(&address, payload)
                    .await
                    .map_err(|e| format!("Verschlüsselung (Sync): {e}"))?;
                wire::seal(&core.handle, own_device_number(core), &message)
                    .map_err(|e| e.to_string())?
            }
        };
        out.push(OutgoingEnvelope {
            id: new_uuid(),
            recipient: core.handle.clone(),
            device_id: sib.server_device_id.clone(),
            envelope,
            franking_tag: None,
            expires_at,
        });
    }
    Ok(out)
}

/// Die jüngsten Verlaufszeilen, die als ein `smsync.v1`-history-Payload
/// unter das Hüllen-Größenlimit der Zustellung passen (64 KiB je Hülle; hier
/// mit Sicherheitsmarge auf 48 KiB Klartext gedeckelt, weil Verschlüsselung
/// und Base64 noch zulegen). Bei sehr langen Chats fehlen die ältesten
/// Zeilen; das ist die ehrliche Grenze eines einzelnen Nachzugs.
fn cap_history_lines(
    peer: &str,
    lines: &[client_app::sync::HistLine],
) -> Vec<client_app::sync::HistLine> {
    const MAX_PLAINTEXT: usize = 48 * 1024;
    let mut start = 0;
    while start < lines.len() {
        let slice = &lines[start..];
        if client_app::sync::encode_history(peer, slice).len() <= MAX_PLAINTEXT {
            return slice.to_vec();
        }
        start += 1;
    }
    Vec::new()
}

/// Liefert den gespeicherten Verlauf an frisch gekoppelte eigene Geräte
/// (Verlaufs-Nachzug): je Chat eine `history`-Sync-Hülle an jedes
/// Geschwister-Gerät, das den Verlauf noch nicht bekam (Marker
/// `sync/history_sent/<geräte-id>` gegen Doppel-Lieferung). Nur der
/// Web-Client hält überhaupt einen Verlauf, deshalb ist dies der Web->Web-
/// Weg; ein Empfänger ohne persistenten Verlauf (CLI) behandelt die Hülle
/// gutartig. Liefert die Zahl der belieferten neuen Geräte.
async fn push_history(core: &mut Core, token: ReadSignal<String>) -> Result<usize, String> {
    let siblings = own_siblings(core, token).await?;
    if siblings.is_empty() {
        return Ok(0);
    }
    // Chats mit nicht-leerem Verlauf einsammeln (peer + Zeilen).
    let chats: Vec<(String, Vec<client_app::sync::HistLine>)> = load_summaries(&core.storage)
        .iter()
        .filter_map(|s| {
            let hist = load_history(&core.storage, &s.peer);
            if hist.is_empty() {
                return None;
            }
            // Bei allen gelöschte Zeilen NICHT nachliefern: der Nachzug trägt
            // keine Grabstein-Marke (HistLine hat nur from/text/at), sie
            // kämen sonst als leere Zeilen an. Ein frisch gekoppeltes Gerät
            // sieht schon gelöschte Nachrichten schlicht nicht.
            let lines: Vec<_> = hist
                .iter()
                .filter(|l| !l.deleted)
                .map(|l| client_app::sync::HistLine {
                    from: l.from.clone(),
                    text: l.text.clone(),
                    at: l.at,
                })
                .collect();
            if lines.is_empty() {
                return None;
            }
            Some((s.peer.clone(), lines))
        })
        .collect();
    if chats.is_empty() {
        return Ok(0);
    }

    let mut envelopes = Vec::new();
    let mut markers = Vec::new();
    for sib in &siblings {
        let marker = format!("sync/history_sent/{}", sib.server_device_id);
        let already = core
            .storage
            .borrow()
            .get(&marker)
            .map_err(|e| e.to_string())?
            .is_some();
        if already {
            continue;
        }
        markers.push(marker);
        let address = ProtocolAddress::new(
            core.handle.clone(),
            device_id_from_u32(sib.protocol_device_id).map_err(|e| e.to_string())?,
        );
        for (peer, lines) in &chats {
            let capped = cap_history_lines(peer, lines);
            if capped.is_empty() {
                continue;
            }
            let payload = client_app::sync::encode_history(peer, &capped);
            let message = core
                .device
                .encrypt(&address, &payload)
                .await
                .map_err(|e| format!("Verschlüsselung (Verlauf): {e}"))?;
            let envelope = wire::seal(&core.handle, own_device_number(core), &message)
                .map_err(|e| e.to_string())?;
            envelopes.push(OutgoingEnvelope {
                id: new_uuid(),
                recipient: core.handle.clone(),
                device_id: sib.server_device_id.clone(),
                envelope,
                franking_tag: None,
                expires_at: None,
            });
        }
    }
    if envelopes.is_empty() {
        return Ok(0);
    }
    // In Batches (delivery deckelt bei 100 Hüllen je Aufruf) zustellen.
    let delivery = DeliveryClient::new(delivery_url());
    for chunk in envelopes.chunks(100) {
        delivery
            .submit(&token.get_untracked(), chunk)
            .await
            .map_err(|e| e.to_string())?;
    }
    // Erst nach erfolgreicher Zustellung merken, sonst wird ein
    // fehlgeschlagener Nachzug beim nächsten Versuch wiederholt.
    for marker in &markers {
        let _ = core.storage.borrow_mut().put(marker, &[1u8]);
    }
    Ok(markers.len())
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
    protocol_device_id: u32,
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
        .sender_certificate(&token.get_untracked(), protocol_device_id)
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
/// CLI) und liefert (smmsg-Deutung, Melde-ID, Nachrichten-ID). Die
/// Nachrichten-ID ist das Franking-Commitment (Basis fürs Bearbeiten/Löschen)
/// und leer bei einer ungefrankten Alt-Nachricht; schlägt das Ablegen fehl,
/// bleibt die Nachricht lesbar, nur das Melden fällt für sie aus.
fn open_payload(
    storage: &SharedStorage,
    message_id: &str,
    payload: &[u8],
) -> (client_app::msg::Msg, Option<String>, String) {
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
            let id = client_app::franking::message_id(&opened.franking_key, &opened.message);
            (client_app::msg::decode(&opened.message), report_id, id)
        }
        // Ungefrankt (Alt-Nachricht): roher Text, keine Melde-/Nachrichten-ID.
        Err(_) => (client_app::msg::decode(payload), None, String::new()),
    }
}

/// Holt wartende Hüllen ab, entschlüsselt und bestätigt sie; liefert je
/// Hülle ein `Incoming` (gewöhnliche Nachricht oder Self-Sync-Kopie). Eine
/// Hülle, deren Absender das eigene Handle ist, ist eine Self-Sync-Kopie
/// (man schreibt sich nie selbst im normalen Fluss). Token als Signal aus
/// demselben Grund wie bei `send_message`: zwischen fetch und ack liegt die
/// Entschlüsselung, in der die Erneuerung rotieren kann.
/// Legt MLS-KeyPackages im Verzeichnis nach, damit dieses Konto in Gruppen
/// eingeladen werden kann, aber nur bis zum Zielbestand (der Restbestand
/// kommt aus `counts`): so wächst der Pool nicht bei jeder Anmeldung, und
/// der server-seitige Deckel wird nie erreicht. Die Privatteile werden VOR
/// der Veröffentlichung gesichert; sonst wäre ein Welcome auf ein
/// KeyPackage möglich, dessen Privatteil nie gespeichert wurde.
async fn top_up_mls_key_packages(
    storage: &SharedStorage,
    token: &str,
    handle: &str,
) -> Result<(), String> {
    let directory = DirectoryClient::new(directory_url());
    let counts = directory.counts(token).await.map_err(|e| e.to_string())?;
    if counts.mls_key_package >= MLS_KEY_PACKAGE_TARGET {
        return Ok(());
    }
    let member = load_or_new_member(storage, handle)?;
    let needed = (MLS_KEY_PACKAGE_TARGET - counts.mls_key_package) as usize;
    let mut packages = Vec::with_capacity(needed);
    for _ in 0..needed {
        packages.push(DirectoryPrekey {
            id: new_uuid(),
            key: BASE64.encode(member.key_package_blob()?),
        });
    }
    save_member_state(storage, &member.export_state()?)?;
    directory
        .publish_mls_key_packages(token, &packages)
        .await
        .map_err(|e| e.to_string())
}

/// Gründet eine MLS-Gruppe mit den genannten Handles, wie das CLI:
/// Gruppe beim Zustelldienst anlegen (Epoche 0), je Gerät der
/// Eingeladenen ein KeyPackage aus dem Verzeichnis (konsumiert je eins),
/// ein Commit lädt alle ein (Epoche 1), die Welcome-Hüllen gehen an die
/// eingeladenen Geräte und der Geräte-Roster folgt als erste
/// Anwendungsnachricht. Liefert die Zustell-Gruppen-ID.
async fn create_group_web(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    name: &str,
    invitees: &[String],
) -> Result<String, String> {
    let profile = load_profile(storage).ok_or("Kein Profil in der Ablage")?;
    let own_device_id = profile.device_id.clone();
    let mut members = vec![own_handle.to_string()];
    members.extend(invitees.iter().cloned());

    // Zuerst die KeyPackages: scheitert ein Eingeladener, ist noch nichts
    // angelegt worden.
    let directory = DirectoryClient::new(directory_url());
    let mut invite_blobs = Vec::new();
    let mut roster = Vec::new();
    for handle in invitees {
        let packages = directory
            .mls_key_packages(token, handle)
            .await
            .map_err(|e| e.to_string())?;
        if packages.devices.is_empty() {
            return Err(format!(
                "{handle} hat kein MLS-KeyPackage veröffentlicht (dort einmal neu anmelden oder \
                 'sm publish-keys' ausführen)."
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
    // ein eigenes MLS-Leaf; das gründende Gerät selbst fällt heraus.
    let own_packages = directory
        .mls_key_packages(token, own_handle)
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
            handle: own_handle.to_string(),
            device_id: entry.device_id,
        });
    }
    // Der Roster führt ALLE Mitglieds-Geräte einschließlich des eigenen:
    // Beigetretene adressieren daraus auch den Gründer.
    roster.push(RosterDevice {
        handle: own_handle.to_string(),
        device_id: profile.device_id.clone(),
    });

    let delivery = DeliveryClient::new(delivery_url());
    let group_id = new_uuid();
    delivery
        .create_group(token, &group_id, name, &members)
        .await
        .map_err(|e| e.to_string())?;

    let member = load_or_new_member(storage, own_handle)?;
    let mut session = GroupSession::create(member, group_id.as_bytes())?;
    let outcome = session.add_members(&invite_blobs)?;

    // Die Welcome-Hülle trägt Name und Einlader für die Einladungs-Anzeige.
    let welcome_fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group_invite(&group_id, &outcome.welcome, name, own_handle)
                    .map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    // Erst senden, dann anwenden: nimmt der Dienst den Commit nicht an,
    // wird der vorgemerkte Zustand nicht abgelegt (siehe die Begründung
    // in client-core::group::add_members). Der Handshake ist signierter
    // Klartext, ein verworfener Commit hinterlässt kein Schlüsselmaterial.
    delivery
        .group_commit(token, &group_id, 0, &members, &welcome_fanout)
        .await
        .map_err(|e| e.to_string())?;
    session.merge_pending()?;
    save_member_state(storage, &session.export_state()?)?;

    let roster_blob = session.create_message(&grouptext::encode_roster(&roster))?;
    // Auch das Erzeugen rückt den Sende-Ratchet vor: sichern, BEVOR der
    // Chiffretext das Gerät verlässt.
    save_member_state(storage, &session.export_state()?)?;
    let roster_fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(&group_id, &roster_blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    delivery
        .group_messages(token, &group_id, &roster_fanout)
        .await
        .map_err(|e| e.to_string())?;

    save_roster(storage, &group_id, &roster)?;
    remember_group(
        storage,
        GroupEntry {
            id: group_id.clone(),
            members,
            status: GroupStatus::Active,
        },
    )?;
    Ok(group_id)
}

/// Verschlüsselt einen `smgpl`-Payload (Text, Bearbeitung oder Löschung)
/// durch die MLS-Sitzung und fächert ihn an alle Roster-Geräte außer den
/// eigenen. Der Zustand wird VOR dem Versand gesichert (sonst nutzte ein
/// Neuladen dieselbe Ratchet-Position erneut). Gemeinsamer Kern von
/// send/edit/delete in Gruppen.
async fn send_group_payload(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
    payload: &[u8],
) -> Result<(), String> {
    let own_device_id = load_profile(storage)
        .map(|p| p.device_id)
        .ok_or("Kein Profil in der Ablage")?;
    let member = load_or_new_member(storage, own_handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err("Diese Gruppe ist in der lokalen Ablage unbekannt.".to_string());
    };
    let roster = load_roster(storage, group_id)?;
    let blob = session.create_message(payload)?;
    save_member_state(storage, &session.export_state()?)?;
    let fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    DeliveryClient::new(delivery_url())
        .group_messages(token, group_id, &fanout)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Sendet einen Text in eine Gruppe und liefert dessen neue Nachrichten-ID
/// (für die eigene Verlaufszeile, damit ein späteres Bearbeiten/Löschen sie
/// trifft).
async fn send_group_message(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
    text: &str,
) -> Result<String, String> {
    let id = new_uuid();
    send_group_payload(
        storage,
        token,
        own_handle,
        group_id,
        &grouptext::encode_text(&id, text),
    )
    .await?;
    Ok(id)
}

/// Bearbeitet eine früher gesendete Gruppennachricht bei allen.
async fn edit_group_message(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
    target: &str,
    text: &str,
) -> Result<(), String> {
    send_group_payload(
        storage,
        token,
        own_handle,
        group_id,
        &grouptext::encode_edit(target, text),
    )
    .await
}

/// Löscht eine früher gesendete Gruppennachricht bei allen.
async fn delete_group_message(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
    target: &str,
) -> Result<(), String> {
    send_group_payload(
        storage,
        token,
        own_handle,
        group_id,
        &grouptext::encode_delete(target),
    )
    .await
}

/// Entfernt ein Mitglied mit MLS-Neuschlüsseln (wie `sm group-remove`):
/// der Remove-Commit schaltet die Gruppe in eine neue Epoche, die dem
/// Entfernten verschlossen bleibt; er geht auch an dessen Geräte, damit
/// der Client dort aufräumt. Danach bekommt die Rest-Gruppe einen
/// frischen Roster. Liefert die neue Mitgliederliste.
async fn remove_group_member(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
    handle: &str,
) -> Result<Vec<String>, String> {
    let own_device_id = load_profile(storage)
        .map(|p| p.device_id)
        .ok_or("Kein Profil in der Ablage")?;
    let member = load_or_new_member(storage, own_handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err("Diese Gruppe ist in der lokalen Ablage unbekannt.".to_string());
    };
    let old_roster = load_roster(storage, group_id)?;
    let from_epoch = session.epoch();
    // Verbleibende Mitglieder (der Server ersetzt damit die Gerätemenge):
    // die aktuellen Identitäten ohne den Entfernten. Vor merge_pending
    // trägt member_identities noch alle.
    let members: Vec<String> = unique_handles(session.member_identities())
        .into_iter()
        .filter(|m| m != handle)
        .collect();
    let commit = session.remove_members(&[handle.as_bytes().to_vec()])?;

    let delivery = DeliveryClient::new(delivery_url());
    let commit_fanout: Vec<GroupOutgoing> = fanout_targets(&old_roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &commit).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    // Senden, dann anwenden. Bei 409 oder Versandfehler wird nichts
    // gesichert: der lokale Zustand bleibt bei Epoche N (kein Fork), ein
    // Abruf wendet den Gewinner-Commit an.
    delivery
        .group_commit(token, group_id, from_epoch, &members, &commit_fanout)
        .await
        .map_err(|e| format!("{e} (bei stale_epoch: erst abrufen, dann erneut entfernen)"))?;
    session.merge_pending()?;
    save_member_state(storage, &session.export_state()?)?;

    // Den frischen Roster SOFORT lokal ablegen: scheitert die
    // Roster-Nachricht unten, heilen die Empfänger den Roster beim
    // Verarbeiten des Commits selbst, und der eigene stimmt schon.
    let new_roster: Vec<RosterDevice> = old_roster
        .into_iter()
        .filter(|device| device.handle != handle)
        .collect();
    save_roster(storage, group_id, &new_roster)?;
    remember_group(
        storage,
        GroupEntry {
            id: group_id.to_string(),
            members: members.clone(),
            status: GroupStatus::Active,
        },
    )?;

    let roster_blob = session.create_message(&grouptext::encode_roster(&new_roster))?;
    save_member_state(storage, &session.export_state()?)?;
    let roster_fanout: Vec<GroupOutgoing> = fanout_targets(&new_roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &roster_blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    if !roster_fanout.is_empty() {
        // Best effort: die Empfänger heilen den Roster ohnehin selbst.
        if let Err(error) = delivery
            .group_messages(token, group_id, &roster_fanout)
            .await
        {
            leptos::logging::warn!("Roster-Nachricht nach Entfernung nicht zugestellt: {error}");
        }
    }
    Ok(members)
}

/// Nimmt eine vorgemerkte Einladung an (wie `sm group-accept`): tritt der
/// Gruppe bei (verarbeitet den Welcome, verbraucht das KeyPackage) und
/// spielt den vor der Annahme gepufferten Verkehr nach (vor allem den
/// Geräte-Roster). Liefert die Mitgliederliste. Kein Netzwerk nötig: die
/// Gruppe ist beim Dienst schon angelegt.
fn accept_invite(
    storage: &SharedStorage,
    own_handle: &str,
    group_id: &str,
) -> Result<Vec<String>, String> {
    let welcome = storage
        .borrow()
        .get(&invite_key(group_id))?
        .ok_or_else(|| "Keine offene Einladung zu dieser Gruppe.".to_string())?;
    let member = load_or_new_member(storage, own_handle)?;
    let mut session = GroupSession::join_group(member, &welcome)
        .map_err(|e| format!("Beitritt scheitert: {e}"))?;
    save_member_state(storage, &session.export_state()?)?;

    // Gepufferten Verkehr nachspielen: Roster (zum Senden nötig),
    // Gesprächs-Texte (sonst verloren) und fremde Commits. Ein Commit, der
    // uns schon wieder entfernt, macht die Einladung wertlos. Auch vor dem
    // Beitritt eingetroffene Bearbeitungen/Löschungen werden schon HIER auf
    // die gepufferten Texte angewandt (nach ID und Absender), damit eine vor
    // dem Beitritt bei allen gelöschte Nachricht nicht als Grabstein-loser
    // Text wieder auftaucht.
    let mut roster_devices = None;
    let mut pending: Vec<StoredLine> = Vec::new();
    let mut removed_before_join = false;
    for buffered in load_invite_buffer(storage, group_id)? {
        match session.process(&buffered) {
            Ok(GroupInbound::Application(application)) => {
                let sender = String::from_utf8_lossy(&application.sender_identity).to_string();
                match grouptext::decode(&application.plaintext) {
                    Ok(GroupPayload::Roster { devices }) => roster_devices = Some(devices),
                    Ok(GroupPayload::Text { id, text }) => pending.push(StoredLine {
                        from: sender,
                        text,
                        at: now_unix(),
                        report_id: None,
                        id,
                        edited: false,
                        deleted: false,
                    }),
                    Ok(GroupPayload::Edit { target, text }) => {
                        if let Some(line) = pending
                            .iter_mut()
                            .find(|l| l.id == target && l.from == sender && !l.deleted)
                        {
                            line.text = text;
                            line.edited = true;
                        }
                    }
                    Ok(GroupPayload::Delete { target }) => {
                        if let Some(line) = pending
                            .iter_mut()
                            .find(|l| l.id == target && l.from == sender && !l.deleted)
                        {
                            line.text = String::new();
                            line.deleted = true;
                        }
                    }
                    Ok(GroupPayload::Leave) | Err(_) => {}
                }
            }
            Ok(GroupInbound::RemovedSelf) => {
                removed_before_join = true;
                break;
            }
            Ok(GroupInbound::Updated) => {}
            Err(error) => leptos::logging::warn!("gepufferte Hülle übersprungen: {error}"),
        }
    }

    if removed_before_join {
        let member = session.forget()?;
        save_member_state(storage, &member.export_state()?)?;
        forget_invite(storage, group_id)?;
        return Err(
            "Die Einladung ist nicht mehr gültig (du wurdest inzwischen wieder entfernt)."
                .to_string(),
        );
    }

    save_member_state(storage, &session.export_state()?)?;
    if let Some(devices) = roster_devices {
        save_roster(storage, group_id, &devices)?;
    }
    // Vor der Annahme gesendete Zeilen in den Verlauf legen (der Reihe nach),
    // damit sie im Chat erscheinen statt verloren zu gehen; Bearbeitungen und
    // Löschungen sind oben schon eingearbeitet.
    let chat_key = group_chat_key(group_id);
    for line in pending {
        record_message(storage, &chat_key, line, false);
    }

    let members = unique_handles(session.member_identities());
    remember_group(
        storage,
        GroupEntry {
            id: group_id.to_string(),
            members: members.clone(),
            status: GroupStatus::Active,
        },
    )?;
    forget_invite(storage, group_id)?;
    Ok(members)
}

/// Verlässt die Gruppe lokal (wie `sm group-leave`): Ansage an die
/// Verbliebenen, dann eigenen Zustand samt Einträgen löschen. Der Verlauf
/// des Chats bleibt in der Ablage; kryptografisch entfernt einen erst der
/// Remove-Commit eines verbleibenden Mitglieds.
async fn leave_group_web(
    storage: &SharedStorage,
    token: &str,
    own_handle: &str,
    group_id: &str,
) -> Result<(), String> {
    let own_device_id = load_profile(storage)
        .map(|p| p.device_id)
        .ok_or("Kein Profil in der Ablage")?;
    let member = load_or_new_member(storage, own_handle)?;
    let Some(mut session) = GroupSession::load(member, group_id.as_bytes())? else {
        return Err("Diese Gruppe ist in der lokalen Ablage unbekannt.".to_string());
    };
    let roster = load_roster(storage, group_id)?;
    let blob = session.create_message(&grouptext::encode_leave())?;
    save_member_state(storage, &session.export_state()?)?;
    let fanout: Vec<GroupOutgoing> = fanout_targets(&roster, &own_device_id)
        .map(|device| {
            Ok(GroupOutgoing {
                id: new_uuid(),
                device_id: device.device_id.clone(),
                envelope: wire::seal_group(group_id, &blob).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<_, String>>()?;
    if !fanout.is_empty() {
        DeliveryClient::new(delivery_url())
            .group_messages(token, group_id, &fanout)
            .await
            .map_err(|e| e.to_string())?;
    }
    let member = session.forget()?;
    save_member_state(storage, &member.export_state()?)?;
    // Grabstein statt Löschen: der Chat-Verlauf und der Anzeigename samt
    // „(verlassen)" bleiben nach einem Neuladen erhalten.
    tombstone_group(storage, group_id, GroupStatus::Left)?;
    Ok(())
}

async fn fetch_messages(
    core: &mut Core,
    token: ReadSignal<String>,
) -> Result<Vec<Incoming>, String> {
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
                    if unsealed.sender == core.handle {
                        // sealed=true: die Absenderidentität ist zertifikats-
                        // geprüft, ein Self-Sync-Änderungsereignis ist hier
                        // authentisch.
                        match client_app::sync::decode(&unsealed.plaintext) {
                            Ok(synced) => {
                                received.extend(incoming_from_sync(&core.handle, true, synced))
                            }
                            Err(error) => {
                                leptos::logging::warn!(
                                    "Sync-Hülle {} unlesbar: {error}",
                                    message.id
                                )
                            }
                        }
                    } else {
                        // sealed=true: die Absenderidentität ist zertifikats-
                        // geprüft, eine Änderung ist hier authentisch.
                        let (msg, report_id, id) =
                            open_payload(&core.storage, &message.id, &unsealed.plaintext);
                        received.extend(incoming_from_msg(
                            unsealed.sender.clone(),
                            msg,
                            report_id,
                            id,
                            true,
                        ));
                    }
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
        // Gruppen-Hüllen (smgrp.v1): MLS verarbeiten statt Double Ratchet.
        if matches!(wire::classify(&message.envelope), wire::Framed::Group) {
            let opened = match wire::open_group(&message.envelope) {
                Ok(opened) => opened,
                Err(error) => {
                    leptos::logging::warn!("Gruppen-Hülle {} übersprungen: {error}", message.id);
                    continue;
                }
            };
            match handle_group_envelope(
                &core.storage,
                &core.handle,
                &opened.group_id,
                &opened.blob,
                opened.name.as_deref(),
                opened.inviter.as_deref(),
            ) {
                Ok(Some(incoming)) => received.push(incoming),
                Ok(None) => {}
                // Auch fehlgeschlagene Verarbeitung bestätigen (unten):
                // ein erneuter Abruf scheiterte am selben Fehler.
                Err(error) => leptos::logging::warn!(
                    "Gruppen-Hülle {} nicht verarbeitbar: {error}",
                    message.id
                ),
            }
            acked.push(message.id.clone());
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
                if opened.from == core.handle {
                    // sealed=false: unversiegelt, die Absenderadresse ist
                    // Klartext und fälschbar; ein Self-Sync-Änderungsereignis
                    // daraus verwirft incoming_from_sync.
                    match client_app::sync::decode(&payload) {
                        Ok(synced) => {
                            received.extend(incoming_from_sync(&core.handle, false, synced))
                        }
                        Err(error) => {
                            leptos::logging::warn!("Sync-Hülle {} unlesbar: {error}", message.id)
                        }
                    }
                } else if client_app::call::is_signal(&payload) {
                    // Ein Anruf-Signal (F2): nicht in den Chat, sondern an die
                    // Anruf-Steuerung. Reist ungefrankt, deshalb VOR
                    // open_payload erkannt.
                    match client_app::call::decode(&payload) {
                        Ok(signal) => received.push(Incoming::Call {
                            peer: opened.from.clone(),
                            signal,
                        }),
                        Err(error) => {
                            leptos::logging::warn!("Anruf-Signal {} unlesbar: {error}", message.id)
                        }
                    }
                } else {
                    // sealed=false: unversiegelt, die Absenderadresse ist
                    // Klartext und fälschbar; ein Änderungsereignis daraus
                    // verwirft incoming_from_msg (nur Text ist zulässig).
                    let (msg, report_id, id) = open_payload(&core.storage, &message.id, &payload);
                    received.extend(incoming_from_msg(
                        opened.from.clone(),
                        msg,
                        report_id,
                        id,
                        false,
                    ));
                }
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

/// Lädt die eigene Gerätemenge (`GET /devices`) und formt sie in
/// Anzeige-Zeilen; das eigene Gerät wird über die Profil-Geräte-ID markiert.
async fn load_device_rows(storage: &SharedStorage, token: &str) -> Result<Vec<DeviceRow>, String> {
    let own_id = load_profile(storage)
        .map(|p| p.device_id)
        .unwrap_or_default();
    let list = IdentityClient::new(identity_url())
        .devices(token)
        .await
        .map_err(|e| e.to_string())?;
    Ok(list
        .into_iter()
        .map(|d| DeviceRow {
            is_own: d.id == own_id,
            name: d.name.unwrap_or_else(|| "Gerät".to_string()),
            protocol_device_id: d.protocol_device_id,
            id: d.id,
        })
        .collect())
}

/// Schaltet ein neues Gerät frei (`sm approve`-Gegenstück im Web): decodiert
/// den Kopplungs-Antrag, signiert dessen Credential mit dem Konto-Wurzel-
/// schlüssel aus dem Profil und ruft `add_device`. Ohne Wurzelschlüssel
/// (ein gekoppeltes Zweitgerät wäre so eins) geht das nicht.
async fn approve_device(storage: &SharedStorage, token: &str, input: &str) -> Result<u16, String> {
    let profile = load_profile(storage).ok_or("Kein Profil in der Ablage".to_string())?;
    if profile.account_seed.is_empty() {
        return Err(
            "Dieses Gerät hat keinen Konto-Wurzelschlüssel; Freischalten nur auf dem Erstgerät."
                .to_string(),
        );
    }
    // Die Eingabe kann ein QR-/Relay-Code oder der Antrag als Text sein.
    let payload = resolve_link_input(input).await?;
    let payload = payload.as_str();
    let seed: [u8; 32] = BASE64
        .decode(&profile.account_seed)
        .map_err(|e| format!("Konto-Seed unlesbar: {e}"))?
        .try_into()
        .map_err(|_| "Konto-Seed hat die falsche Länge".to_string())?;
    let account_key = IdentityKeypair::from_seed(&seed);
    let request: LinkRequest = serde_json::from_slice(
        &BASE64
            .decode(payload.trim())
            .map_err(|_| "Antrag ist kein Base64".to_string())?,
    )
    .map_err(|e| format!("Antrag unlesbar: {e}"))?;
    let outcome = IdentityClient::new(identity_url())
        .add_device(
            token,
            &DeviceEnrollment {
                account_key: &account_key,
                handle: &profile.handle,
                device_public_key: &request.device_public_key,
                device_id: &request.device_id,
                name: None,
                not_after: now_unix() + CREDENTIAL_TTL_SECONDS,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    // Der Self-Sync-Cache dieses Geräts ist jetzt veraltet (ein Geschwister
    // kam dazu); leeren, damit die nächste gesendete Nachricht auch an das
    // neue Gerät synchronisiert.
    let _ = storage.borrow_mut().remove(OWN_DEVICES_KEY);
    Ok(outcome.protocol_device_id)
}

/// Rotiert den Konto-Wurzelschlüssel (ADR-0010, `sm rotate-key`-Gegenstück
/// im Web). Nur auf einem Erstgerät mit Wurzel-Seed. Signiert das
/// Rotations-Zertifikat mit dem ALTEN Schlüssel, jedes Gerät mit dem NEUEN,
/// reicht beides ein und legt erst nach dem Erfolg den neuen Seed ab.
/// Liefert die Zahl der neu signierten Geräte.
/// Rotiert den Konto-Wurzelschlüssel (ADR-0010), Browser-Fassung des
/// CLI-Ablaufs. Absturzsicher: der neue Seed wird VOR dem Serveraufruf als
/// `pending` in IndexedDB abgelegt und erst nach dem bestätigten Erfolg nach
/// `account_seed` befördert; eine unterbrochene Rotation wird beim nächsten
/// Versuch abgeschlossen (siehe rotate_key in der CLI). Jedes Gerät wird mit
/// dem neuen Schlüssel neu signiert und sein Ablauf erneuert.
async fn rotate_key_web(storage: &SharedStorage, token: &str) -> Result<usize, String> {
    let mut profile = load_profile(storage).ok_or("Kein Profil in der Ablage")?;
    if profile.account_seed.is_empty() {
        return Err(
            "Dieses Gerät hat keinen Konto-Wurzelschlüssel; Rotieren nur auf dem Erstgerät."
                .to_string(),
        );
    }
    let old_account = IdentityKeypair::from_seed(&decode_seed(&profile.account_seed)?);

    // Liegt ein pending seed, eine frühere Rotation abschließen statt eine
    // neue starten. Sonst ein frisches Wurzelpaar ziehen und VOR dem
    // Serveraufruf ablegen, damit ein Absturz danach den Schlüssel nicht
    // verliert.
    let resuming = !profile.pending_account_seed.is_empty();
    let new_account = if resuming {
        IdentityKeypair::from_seed(&decode_seed(&profile.pending_account_seed)?)
    } else {
        let account = IdentityKeypair::generate();
        profile.pending_account_seed = BASE64.encode(account.to_seed());
        save_profile(storage, &profile)?;
        account
    };
    let new_identity_key = new_account.public_b64();
    let rotation_signature = build_rotation_cert(&old_account, &profile.handle, &new_identity_key);

    let not_after = now_unix() + CREDENTIAL_TTL_SECONDS;
    let client = IdentityClient::new(identity_url());
    let devices = client.devices(token).await.map_err(|e| e.to_string())?;
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
        .rotate_identity(token, &new_identity_key, &rotation_signature, &device_creds)
        .await
    {
        Ok(()) => {
            promote_pending_seed_web(storage, &mut profile, &new_account)?;
            Ok(device_creds.len())
        }
        // Wiederaufnahme: der Dienst hat den pending-Schlüssel schon
        // übernommen (die Kontinuitätssignatur des alten passt nicht mehr).
        // Ihn lokal übernehmen und so die Rotation abschließen.
        Err(client_app::ClientError::Api { code, .. })
            if resuming && code == "invalid_continuity" =>
        {
            promote_pending_seed_web(storage, &mut profile, &new_account)?;
            Ok(device_creds.len())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Befördert den bestätigten neuen Wurzelschlüssel nach `account_seed` und
/// leert `pending_account_seed`. Erst nach dem Servererfolg aufgerufen.
fn promote_pending_seed_web(
    storage: &SharedStorage,
    profile: &mut Profile,
    new_account: &IdentityKeypair,
) -> Result<(), String> {
    profile.account_seed = BASE64.encode(new_account.to_seed());
    profile.pending_account_seed = String::new();
    save_profile(storage, profile)
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
    /// Eine begonnene Kopplung dieses Browsers als Zweitgerät (Profil liegt,
    /// aber die Nummer ist 0 = noch nicht freigeschaltet). Trägt den
    /// Kopplungs-Antrag zum Anzeigen und, falls das Ablegen beim Relay klappte,
    /// das Geheimnis für den QR-Code. Nach dem Freischalten auf dem Erstgerät
    /// schließt der Nutzer hier ab. `secret` ist `None` nach einem Neuladen
    /// mitten in der Kopplung (das Geheimnis ist flüchtig, nur der Antrag
    /// liegt): dann bleibt der manuelle Weg.
    Linking {
        payload: String,
        secret: Option<String>,
    },
    /// Ablage nicht nutzbar (etwa privates Fenster ohne IndexedDB).
    Broken(String),
}

/// Zustand der Anruf-Oberfläche (F2). Die eigentliche Verbindung hält ein
/// `call::CallSession` daneben; dieses Signal steuert nur die Anzeige.
#[derive(Clone, PartialEq)]
enum CallUi {
    /// Kein Anruf.
    Idle,
    /// Anruf gestartet, wartet auf Annahme des Peers.
    Outgoing { peer: String, call_id: String },
    /// Ein eingehender Anruf klingelt; das Offer wartet bis zur Annahme.
    Incoming {
        peer: String,
        call_id: String,
        sdp: String,
    },
    /// Verbunden.
    Active {
        peer: String,
        call_id: String,
        muted: bool,
    },
}

impl CallUi {
    /// Der Peer des aktuellen Anrufs (für die Signal-Zuordnung).
    fn peer(&self) -> Option<&str> {
        match self {
            CallUi::Idle => None,
            CallUi::Outgoing { peer, .. }
            | CallUi::Incoming { peer, .. }
            | CallUi::Active { peer, .. } => Some(peer),
        }
    }

    /// Die Kennung des aktuellen Anrufs (zum Abgleich später/doppelt
    /// eintreffender Signale mit dem RICHTIGEN Anruf).
    fn call_id(&self) -> Option<&str> {
        match self {
            CallUi::Idle => None,
            CallUi::Outgoing { call_id, .. }
            | CallUi::Incoming { call_id, .. }
            | CallUi::Active { call_id, .. } => Some(call_id),
        }
    }
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
    // Sicherungs-Passwörter: getrennt vom Konto-Passwort (die Sicherung
    // verlässt das Gerät). Eines fürs Erstellen (Einstellungen), eines fürs
    // Einspielen (Boot-Bildschirm).
    let (backup_export_pw, set_backup_export_pw) = signal(String::new());
    let (backup_import_pw, set_backup_import_pw) = signal(String::new());
    // Anzeigename fürs Registrierungs-Formular (F010, optional): trägt
    // Groß-/Kleinschreibung und Leerzeichen (Vor- und Nachname), anders als
    // der technische Handle; leer heißt Rückfall auf den Handle.
    let (reg_name_input, set_reg_name_input) = signal(String::new());
    let (text_input, set_text_input) = signal(String::new());
    // Bearbeiten-Modus des Composers: die Nachrichten-ID der eigenen Zeile,
    // deren Text gerade ersetzt wird (None = normale neue Nachricht). Beim
    // Senden geht dann ein smmsg-Edit statt eines Texts raus.
    let (editing, set_editing) = signal(Option::<String>::None);
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
    // Mitglieder-Eingabe fürs Gründen einer Gruppe (im Neuer-Chat-Panel).
    let (group_input, set_group_input) = signal(String::new());
    // Gruppenname beim Gründen (optional).
    let (group_name_input, set_group_name_input) = signal(String::new());
    // Anzeigenamen der Gruppen-Chats (Schlüssel `grp:<id>` -> „Gruppe: ...");
    // aus der Ablage geladen und bei Gründung/Beitritt fortgeschrieben.
    let (group_labels, set_group_labels) =
        signal(std::collections::HashMap::<String, GroupUi>::new());
    // Anzeigenamen der 1:1-Kontakte (Handle -> Name), aus der Ablage geladen
    // und beim App-Start und Chat-Öffnen aufgefrischt.
    let (contact_names, set_contact_names) =
        signal(std::collections::HashMap::<String, String>::new());
    // Offene Gruppen-Einladungen (Gruppen-IDs, Welcome vorgemerkt, noch
    // nicht beigetreten); als Banner mit Annehmen/Ablehnen in der
    // Seitenleiste. Aus der Ablage geladen, damit sie ein Neuladen
    // überleben.
    let (invites, set_invites) = signal(Vec::<String>::new());
    // Anzeigetext je Einladung (group_id -> "Name von X"); reaktiv fürs Banner.
    let (invite_labels, set_invite_labels) =
        signal(std::collections::HashMap::<String, String>::new());
    // Verwaltungssicht (Name, Rollen, Einstellungen) der GEÖFFNETEN Gruppe;
    // beim Öffnen vom Dienst geholt, für die Rollen-Anzeige und -Aktionen.
    let (group_meta, set_group_meta) = signal(Option::<GroupMetaInfo>::None);
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
    // Geräteverwaltung: die geladene Gerätemenge und der eingefügte
    // Kopplungs-Antrag eines neuen Geräts (in der Einstellungen-Ansicht).
    let (device_rows, set_device_rows) = signal(Vec::<DeviceRow>::new());
    let (link_input, set_link_input) = signal(String::new());
    // Ob die Einstellungen-Ansicht offen ist (statt des Chat-Threads im
    // Haupt-Bereich). Beim Öffnen laufen die Nachlader (Geräte, Blockliste).
    let (settings_open, set_settings_open) = signal(false);
    // "Versiegelt senden als Vorgabe": persistierte Startwahl des
    // Composer-Sealed-Hakens für neue Sitzungen (Einstellungen).
    let (sealed_default, set_sealed_default) = signal(false);
    // Web-Push (Benachrichtigungen bei geschlossenem Browser) für dieses
    // Gerät ein/aus; aus der Ablage geladen (Einstellungen).
    let (push_on, set_push_on) = signal(false);
    // 1:1-Anruf (F2): der reaktive Anzeige-Zustand und die lebende
    // WebRTC-Verbindung daneben (nicht reaktiv, hält Browser-Ressourcen).
    let (call_ui, set_call_ui) = signal(CallUi::Idle);
    let call_session: SendWrapper<Rc<RefCell<Option<Rc<crate::call::CallSession>>>>> =
        SendWrapper::new(Rc::new(RefCell::new(None)));
    // Antwort-/ICE-Signale, die eintreffen, BEVOR die Session steht (die
    // Klingel-/Aufbauphase des Angerufenen): gepuffert und beim Session-Start
    // nachgespielt, sonst gingen die früh getrickelten ICE-Kandidaten verloren
    // und der Anruf hätte keinen Ton.
    let call_pending: SendWrapper<Rc<RefCell<Vec<client_app::call::Signal>>>> =
        SendWrapper::new(Rc::new(RefCell::new(Vec::new())));
    // Live-Tippen (Paket E): ob es eingeschaltet ist (Einstellung, persistiert)
    // und der zuletzt empfangene Entwurf des Gesprächspartners (nur während
    // eines Anrufs; None = keine Vorschau).
    let (live_typing, set_live_typing) = signal(false);
    let (peer_typing, set_peer_typing) = signal(Option::<String>::None);
    // Der Anruf-Partner, an den zuletzt ein Live-Tipp-Entwurf ging (oder None,
    // wenn gerade nicht geteilt wird). Damit ein Verlassen des Chats dem
    // Partner ein leeres Update schickt (Vorschau weg) und ein Betreten NICHT
    // gleich den vorhandenen Puffer streamt.
    let call_share_target = StoredValue::new(Option::<String>::None);
    // Ob gerade live geteilt wird (Anruf-Partner offen + eingeschaltet); für
    // die steigende Flanke, an der der Composer geleert wird.
    let call_was_sharing = StoredValue::new(false);
    // Die globale Blockliste (alle blockierten Handles) für die
    // Einstellungen-Ansicht; `None`, solange nicht geladen.
    let (block_list, set_block_list) = signal(Option::<Vec<String>>::None);
    // Passwortwechsel (Einstellungen, Konto): altes und neues Passwort samt
    // Wiederholung. Nach Erfolg werden alle Felder geleert.
    let (pw_current, set_pw_current) = signal(String::new());
    let (pw_new, set_pw_new) = signal(String::new());
    let (pw_confirm, set_pw_confirm) = signal(String::new());
    // Ablauf der Widerrufsfrist einer vorgemerkten Konto-Löschung
    // (Unix-Sekunden); `None` = aktives Konto. Aus der Login-Antwort gesetzt.
    let (deletion_pending, set_deletion_pending) = signal(Option::<u64>::None);
    // Passwort-Bestätigung im Lösch-Formular (die Löschung ist zerstörend,
    // deshalb ein bewusster Schritt statt eines Ein-Klick-Knopfes).
    let (delete_pw, set_delete_pw) = signal(String::new());
    // Eingabefeld für den Anzeigenamen (F010, Einstellungen); die
    // Login-Antwort belegt es mit dem aktuellen Namen vor, damit der Nutzer
    // den Stand sieht und ändert statt blind zu tippen.
    let (name_input, set_name_input) = signal(String::new());
    // Maschinen-Benachrichtigungen vom integrations-Dienst, getrennt vom
    // Krypto-Status und vom E2E-Chat (design-system.md, Status-Trennung).
    let (notifications, set_notifications) = signal(Vec::<String>::new());
    // Gewählter Darstellungs-Modus (system/hell/dunkel/midnight); der
    // FOUC-Guard in index.html hat ihn beim Laden schon angewandt.
    let (theme, set_theme) = signal(stored_theme());
    // Fokusziel beim Chat-Wechsel: der Kontaktname im Chat-Kopf (SC 2.4.3).
    let chat_name_ref = NodeRef::<leptos::html::H2>::new();
    // Das Datei-Feld für den Sicherungs-Import. Nur ein Ref, obwohl es in
    // zwei Boot-Zweigen (Fresh und Locked) steht: die Zweige sind exklusiv,
    // gebunden wird das gerade gerenderte Feld.
    let backup_file_ref = NodeRef::<leptos::html::Input>::new();
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
                    // Kurze Borrows, keiner über ein await gehalten.
                    let boot = if !storage.borrow().has_state() {
                        Boot::Fresh
                    } else if storage.borrow().is_locked() {
                        Boot::Locked
                    } else {
                        match load_profile(&storage) {
                            // Nummer 0 = eine begonnene Kopplung; den Antrag
                            // rekonstruieren und die Kopplung fortsetzen.
                            Some(p) if p.protocol_device_id == 0 => {
                                match pending_link_payload(&storage).await {
                                    // Nach einem Neuladen ist das QR-Geheimnis
                                    // weg (flüchtig); nur der manuelle Weg bleibt.
                                    Some(payload) => Boot::Linking {
                                        payload,
                                        secret: None,
                                    },
                                    None => Boot::Known(p.handle),
                                }
                            }
                            Some(p) => Boot::Known(p.handle),
                            None => Boot::Fresh,
                        }
                    };
                    *boot_storage.borrow_mut() = Some(storage);
                    set_boot.set(boot);
                }
                Err(error) => set_boot.set(Boot::Broken(error)),
            }
        });
    }

    // Eine erfolgreiche An-/Neu-/Kopplungs-Anmeldung in den lebenden Zustand
    // heben: Token übernehmen, Erneuerung und Hinweiskanal starten, Core
    // aktiv setzen, Chats und Sealed-Vorgabe laden, angemeldet melden. Eine
    // Quelle für alle drei Wege (Registrierung, Anmeldung, Kopplung).
    let activate_session = {
        let core = core.clone();
        SendWrapper::new(Rc::new(move |onboarded: Onboarded| {
            let Onboarded {
                core: new_core,
                access_token: at,
                refresh_token: rt,
                expires_in,
                deletion_pending_until,
                display_name,
            } = onboarded;
            set_deletion_pending.set(deletion_pending_until);
            // Das Eingabefeld mit dem aktuellen Namen vorbelegen; ohne
            // Antwort-Feld (älterer Dienst) bleibt es leer.
            set_name_input.set(display_name.unwrap_or_default());
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
            set_me.set(new_core.handle.clone());
            set_group_labels.set(load_group_labels(&storage, &new_core.handle));
            let pending = load_invites(&storage);
            set_invite_labels.set(
                pending
                    .iter()
                    .map(|id| {
                        let (n, inv) = load_invite_meta(&storage, id);
                        (id.clone(), invite_banner_text(&n, &inv))
                    })
                    .collect(),
            );
            set_invites.set(pending);
            let summaries = load_summaries(&storage);
            // Kontakt-Anzeigenamen aus der Ablage übernehmen und beim Start
            // für alle 1:1-Kontakte auffrischen (automatische Übernahme einer
            // Namensänderung eines Kontakts).
            set_contact_names.set(load_contact_names(&storage));
            refresh_contact_names(
                summaries.iter().map(|c| c.peer.clone()).collect(),
                &new_core.handle,
                access_token.get_untracked(),
                storage.clone(),
                set_contact_names,
            );
            *core.borrow_mut() = Some(new_core);
            set_chats.set(summaries);
            let sealed = load_sealed_default(&storage);
            set_sealed_default.set(sealed);
            set_sealed_choice.set(sealed);
            set_live_typing.set(load_live_typing(&storage));
            let push_enabled = load_push_on(&storage);
            set_push_on.set(push_enabled);
            set_logged_in.set(true);
            // Ein aktives Push-Abo beim Start still auffrischen: der Endpoint
            // des Browsers kann rotieren, sonst bliebe Push danach lautlos
            // aus (das Abo beim Dienst zeigte ins Leere). Best effort, ohne
            // neuen Erlaubnis-Dialog (bei erteilter Erlaubnis liefert der
            // Browser sofort).
            if push_enabled {
                let token = access_token.get_untracked();
                spawn_local(async move {
                    if let Err(error) =
                        crate::push::enable(&DeliveryClient::new(delivery_url()), &token).await
                    {
                        leptos::logging::warn!("Push-Abo nicht aufgefrischt: {error}");
                    }
                });
            }
        }))
    };

    let on_register = {
        let boot_storage = boot_storage.clone();
        let activate_session = activate_session.clone();
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
            // Optionaler Anzeigename; nur Weißraum zählt als nicht angegeben
            // (der Server trimmt ebenso und fällt dann auf den Handle zurück).
            let display_name = Some(reg_name_input.get_untracked().trim().to_string())
                .filter(|name| !name.is_empty());
            if handle.is_empty() || password.is_empty() {
                set_status.set("Handle und Passwort angeben.".to_string());
                return;
            }
            set_busy.set(true);
            set_status.set("Konto wird angelegt ...".to_string());
            let activate_session = activate_session.clone();
            spawn_local(async move {
                match onboard(storage, handle.clone(), password, display_name).await {
                    Ok(onboarded) => {
                        activate_session(onboarded);
                        set_status.set("Bereit.".to_string());
                    }
                    Err(error) => set_status.set(format!("Fehlgeschlagen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    let on_login = {
        let boot_storage = boot_storage.clone();
        let activate_session = activate_session.clone();
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
            let activate_session = activate_session.clone();
            spawn_local(async move {
                match login(storage, password).await {
                    Ok(onboarded) => {
                        activate_session(onboarded);
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

    // Kopplung beginnen: diesen Browser als Zweitgerät eines bestehenden
    // Kontos anmelden. Erzeugt die Geräte-Identität und zeigt den Antrag.
    let on_link_start = {
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
            if handle.is_empty() {
                set_status.set("Handle des bestehenden Kontos angeben.".to_string());
                return;
            }
            set_busy.set(true);
            set_status.set("Kopplung wird vorbereitet ...".to_string());
            spawn_local(async move {
                match link_start(storage, handle).await {
                    Ok(started) => {
                        // Konnte der Antrag nicht beim Relay abgelegt werden
                        // (Netz, Kanal voll), gibt es keinen QR-Code; dann den
                        // manuellen Weg ansagen, statt ihn kommentarlos
                        // anzubieten.
                        let hint = if started.secret.is_none() {
                            "Kein QR-Code (Relay nicht erreichbar). Den Antrag als Text übertragen."
                        } else {
                            ""
                        };
                        set_boot.set(Boot::Linking {
                            payload: started.payload,
                            secret: started.secret,
                        });
                        set_status.set(hint.to_string());
                    }
                    Err(error) => set_status.set(format!("Kopplung fehlgeschlagen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Kopplung abschließen: nachdem das Erstgerät den Antrag freigeschaltet
    // hat, anmelden und die Prekeys veröffentlichen (siehe link_finish).
    let on_link_finish = {
        let boot_storage = boot_storage.clone();
        let activate_session = activate_session.clone();
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
                set_status.set("Passwort des Kontos angeben.".to_string());
                return;
            }
            set_busy.set(true);
            set_status.set("Kopplung wird abgeschlossen ...".to_string());
            let activate_session = activate_session.clone();
            spawn_local(async move {
                match link_finish(storage, password).await {
                    Ok(onboarded) => {
                        activate_session(onboarded);
                        // Den Linking-Bootzustand (samt dem darin gehaltenen
                        // Kopplungs-Geheimnis) fallen lassen: er wird nach der
                        // Anmeldung nicht mehr angezeigt, und das Geheimnis
                        // soll nicht die ganze Sitzung im Speicher bleiben.
                        set_boot.set(Boot::Loading);
                        set_status.set("Gekoppelt. Empfängt ab jetzt eigene Kopien.".to_string());
                        set_hints.update(|n| *n += 1);
                    }
                    Err(error) => set_status.set(format!("Abschluss fehlgeschlagen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Kopplung abbrechen: das vorläufige Profil verwerfen, zurück zur Wahl.
    let on_link_cancel = {
        let boot_storage = boot_storage.clone();
        move |_| {
            if let Some(storage) = boot_storage.borrow().clone() {
                let _ = storage.borrow_mut().remove(PROFILE_KEY);
            }
            set_status.set(String::new());
            set_boot.set(Boot::Fresh);
        }
    };

    // Sicherung erstellen (Einstellungen, angemeldet): den gesamten Zustand
    // unter einem Sicherungs-Passwort versiegeln und als Datei herunterladen.
    let on_backup_export = {
        let current_storage = current_storage.clone();
        move |_| {
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            // Die Mindestlänge prüft backup::seal zentral (auch fürs CLI);
            // hier wird nur die Fehlermeldung gezeigt.
            let bytes = match storage
                .borrow()
                .export_backup(&backup_export_pw.get_untracked())
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    set_status.set(error);
                    return;
                }
            };
            match download_file("securemessenger-sicherung.smbak", &bytes) {
                Ok(()) => {
                    set_backup_export_pw.set(String::new());
                    set_status.set(
                        "Sicherung heruntergeladen. Getrennt vom Gerät und sicher aufbewahren; \
                         das Passwort ist der einzige Schlüssel dazu."
                            .to_string(),
                    );
                }
                Err(error) => set_status.set(format!("Download fehlgeschlagen: {error}")),
            }
        }
    };

    // Sicherung einspielen (Boot-Bildschirm): die gewählte Datei mit dem
    // Sicherungs-Passwort entschlüsseln, den Zustand laden und zur Anmeldung
    // des wiederhergestellten Handles wechseln (das Konto-Passwort versiegelt
    // die Ablage dann wieder lokal).
    let on_backup_import = SendWrapper::new(Rc::new({
        let boot_storage = boot_storage.clone();
        move |_: ()| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = boot_storage.borrow().clone() else {
                set_status.set("Ablage noch nicht bereit.".to_string());
                return;
            };
            let pw = backup_import_pw.get_untracked();
            if pw.is_empty() {
                set_status.set("Sicherungs-Passwort angeben.".to_string());
                return;
            }
            let file = backup_file_ref
                .get_untracked()
                .and_then(|input| input.files())
                .and_then(|files| files.get(0));
            let Some(file) = file else {
                set_status.set("Zuerst eine Sicherungsdatei wählen.".to_string());
                return;
            };
            // Liegt schon ein (verschlüsseltes) Konto auf diesem Gerät (Locked),
            // ersetzt der Import es unwiderruflich. Das darf nicht still
            // geschehen: erst bestätigen lassen.
            if storage.borrow().is_locked() {
                let confirmed = web_sys::window()
                    .and_then(|w| {
                        w.confirm_with_message(
                            "Auf diesem Gerät liegt bereits ein verschlüsseltes Konto. \
                             Der Import ersetzt es endgültig. Fortfahren?",
                        )
                        .ok()
                    })
                    .unwrap_or(false);
                if !confirmed {
                    set_status.set("Import abgebrochen.".to_string());
                    return;
                }
            }
            set_busy.set(true);
            set_status.set("Sicherung wird eingespielt ...".to_string());
            spawn_local(async move {
                match read_file_bytes(&file).await {
                    Ok(bytes) => {
                        let result = storage.borrow_mut().import_backup(&bytes, &pw, PROFILE_KEY);
                        match result {
                            Ok(()) => match load_profile(&storage) {
                                Some(profile) => {
                                    set_backup_import_pw.set(String::new());
                                    set_status.set(
                                        "Sicherung eingespielt. Jetzt mit dem Konto-Passwort \
                                         anmelden."
                                            .to_string(),
                                    );
                                    set_boot.set(Boot::Known(profile.handle));
                                }
                                None => {
                                    set_status.set("Die Sicherung enthält kein Konto.".to_string())
                                }
                            },
                            Err(error) => set_status.set(format!("Import fehlgeschlagen: {error}")),
                        }
                    }
                    Err(error) => set_status.set(format!("Datei nicht lesbar: {error}")),
                }
                set_busy.set(false);
            });
        }
    }));

    // Die Import-Karte erscheint in ZWEI Boot-Zweigen (Fresh und Locked); als
    // wiederverwendbarer Bausatz statt doppeltem Markup. Der Klon je Aufruf
    // hält den Handler-Rc; die beiden Zweige sind exklusiv, das Datei-Feld
    // bindet also nur einmal.
    let import_card = {
        let on_backup_import = on_backup_import.clone();
        move || {
            let on_backup_import = on_backup_import.clone();
            view! {
                <section class="sm-card" aria-label="Sicherung einspielen">
                    <h2>"Aus einer Sicherung wiederherstellen"</h2>
                    <p class="sm-status">
                        "Eine früher erstellte Sicherungsdatei (.smbak) einspielen: Gerät, "
                        "Sitzungen und Verlauf kommen zurück. Danach mit dem Konto-Passwort "
                        "anmelden."
                    </p>
                    <div class="sm-field">
                        <label for="sm-backup-file">"Sicherungsdatei (.smbak)"</label>
                        <input id="sm-backup-file" type="file" node_ref=backup_file_ref />
                    </div>
                    <div class="sm-field">
                        <label for="sm-backup-pw">"Sicherungs-Passwort"</label>
                        <input
                            id="sm-backup-pw"
                            type="password"
                            prop:value=backup_import_pw
                            on:input=move |ev| {
                                set_backup_import_pw.set(event_target_value(&ev))
                            }
                        />
                    </div>
                    <div class="sm-row">
                        <button
                            type="button"
                            class="sm-secondary"
                            on:click=move |_| on_backup_import(())
                            disabled=busy
                        >
                            "Sicherung einspielen"
                        </button>
                    </div>
                </section>
            }
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
            set_deletion_pending.set(None);
            set_name_input.set(String::new());
            set_group_labels.set(std::collections::HashMap::new());
            set_invites.set(Vec::new());
            set_group_input.set(String::new());
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
            set_settings_open.set(false);
            set_device_rows.set(Vec::new());
            set_block_list.set(None);
            set_sealed_default.set(false);
            set_push_on.set(false);
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
                        // Bearbeiten-Modus: statt einer neuen Nachricht geht
                        // ein Edit auf die gemerkte ID raus; lokal wird
                        // dieselbe Regel angewandt wie bei einem empfangenen
                        // Edit (eine Quelle der Wahrheit, apply_event).
                        if let Some(target) = editing.get_untracked() {
                            let result = if let Some(group_id) =
                                group_id_of(&peer).map(str::to_string)
                            {
                                edit_group_message(
                                    &storage,
                                    &access_token.get_untracked(),
                                    &who,
                                    &group_id,
                                    &target,
                                    &text,
                                )
                                .await
                            } else {
                                edit_message(&mut active, access_token, &peer, &target, &text).await
                            };
                            *core.borrow_mut() = Some(active);
                            match result {
                                Ok(()) => {
                                    // Eigenes Edit: kein fremdes Melde-Material
                                    // (None); die eigene Zeile behält ihre.
                                    if let Some(s) = apply_event(
                                        &storage,
                                        &peer,
                                        &who,
                                        &target,
                                        Some(&text),
                                        None,
                                    ) {
                                        set_chats.set(s);
                                    }
                                    if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                                        set_messages.set(load_history(&storage, &peer));
                                        set_text_input.set(String::new());
                                    }
                                    set_editing.set(None);
                                    set_status.set(String::new());
                                }
                                Err(error) => {
                                    set_status.set(format!("Bearbeiten fehlgeschlagen: {error}"))
                                }
                            }
                            set_busy.set(false);
                            return;
                        }
                        // Gruppen-Chats gehen über den MLS-Pfad; Frist und
                        // Sealed sind 1:1-Mechanik (der Gruppen-Fanout kennt
                        // kein expires_at, und Sealed versteckt den Absender
                        // vor dem Dienst, was MLS-Hüllen ohnehin tun).
                        let result = if let Some(group_id) = group_id_of(&peer).map(str::to_string)
                        {
                            // In eine vergessene Gruppe (entfernt/verlassen)
                            // führt kein Senden mehr: klar sagen statt den
                            // generischen "unbekannt"-Fehler.
                            if group_labels
                                .get_untracked()
                                .get(&peer)
                                .is_some_and(|ui| ui.forgotten)
                            {
                                Err("Du bist nicht mehr in dieser Gruppe (entfernt oder \
                                     verlassen); der Verlauf bleibt lesbar."
                                    .to_string())
                            } else {
                                send_group_message(
                                    &storage,
                                    &access_token.get_untracked(),
                                    &who,
                                    &group_id,
                                    &text,
                                )
                                .await
                            }
                        } else {
                            send_message(
                                &mut active,
                                access_token,
                                &peer,
                                &text,
                                expires_at,
                                sealed,
                            )
                            .await
                        };
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(id) => {
                                let line = StoredLine {
                                    from: who,
                                    text: text.clone(),
                                    at: now_unix(),
                                    report_id: None,
                                    id,
                                    edited: false,
                                    deleted: false,
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

    // Ein eingehendes Anruf-Signal des Peers verarbeiten (aus dem Abholweg).
    // Alle Zweige gleichen die call_id des Signals gegen den LAUFENDEN Anruf
    // ab, damit ein spätes/doppeltes Signal eines alten Anrufs einen neuen
    // nicht stört.
    let apply_call_signal = SendWrapper::new(Rc::new({
        let core = core.clone();
        let call_session = call_session.clone();
        let call_pending = call_pending.clone();
        move |peer: String, signal: client_app::call::Signal| {
            use client_app::call::Signal;
            // Ob das Signal zum gerade laufenden/klingelnden Anruf gehört.
            let current = call_ui.get_untracked();
            let matches_current = current.peer() == Some(peer.as_str())
                && current.call_id() == Some(signal.call_id());
            // Einem Anrufer, dessen Offer wir nicht annehmen können, ein
            // Hangup zurückgeben (besetzt/Glare-Verlierer).
            let busy_reply = {
                let core = core.clone();
                move |call_id: String, reason: &'static str, peer: String| {
                    spawn_local(async move {
                        let taken = core.borrow_mut().take();
                        if let Some(mut active) = taken {
                            let _ = send_call_signal(
                                &mut active,
                                access_token,
                                &peer,
                                &Signal::Hangup {
                                    call_id,
                                    reason: reason.to_string(),
                                },
                            )
                            .await;
                            *core.borrow_mut() = Some(active);
                        }
                    });
                }
            };
            match signal {
                Signal::Offer { call_id, sdp } => match current {
                    CallUi::Idle => {
                        set_call_ui.set(CallUi::Incoming {
                            peer: peer.clone(),
                            call_id,
                            sdp,
                        });
                        set_status.set(format!("{peer} ruft an ..."));
                    }
                    // Glare: ich rufe gerade DENSELBEN Peer an und bekomme sein
                    // Offer. Deterministischer Tie-Break über die Handles: der
                    // lexikografisch kleinere Handle bleibt Anrufer, der
                    // größere gibt seinen Versuch auf und nimmt das Offer an.
                    CallUi::Outgoing {
                        peer: my_peer,
                        call_id: my_call,
                    } if my_peer == peer => {
                        let own = me.get_untracked();
                        if own < peer {
                            // Ich bleibe Anrufer: das fremde Offer verwerfen
                            // (der Peer nimmt meins an).
                            busy_reply(call_id, "glare", peer.clone());
                        } else {
                            // Ich gebe auf: meinen Versuch schließen und das
                            // Offer annehmen (Incoming), damit einer gewinnt.
                            busy_reply(my_call, "glare", peer.clone());
                            if let Some(session) = call_session.borrow_mut().take() {
                                session.close();
                            }
                            call_pending.borrow_mut().clear();
                            set_call_ui.set(CallUi::Incoming {
                                peer: peer.clone(),
                                call_id,
                                sdp,
                            });
                            set_status.set(format!("{peer} ruft an ..."));
                        }
                    }
                    // Sonst besetzt.
                    _ => busy_reply(call_id, "besetzt", peer.clone()),
                },
                Signal::Answer { .. } | Signal::Ice { .. } => {
                    if !matches_current {
                        return; // Signal eines fremden/alten Anrufs.
                    }
                    let is_answer = matches!(signal, Signal::Answer { .. });
                    let current_session = call_session.borrow().as_ref().cloned();
                    if let Some(session) = current_session {
                        spawn_local(async move {
                            let _ = session.on_signal(signal).await;
                        });
                    } else {
                        // Die Session steht noch nicht (Klingel-/Aufbauphase):
                        // puffern und beim Session-Start nachspielen.
                        call_pending.borrow_mut().push(signal);
                    }
                    if is_answer {
                        if let CallUi::Outgoing { peer, call_id } = call_ui.get_untracked() {
                            set_call_ui.set(CallUi::Active {
                                peer,
                                call_id,
                                muted: false,
                            });
                            set_status.set(String::new());
                        }
                    }
                }
                Signal::Hangup { .. } => {
                    if matches_current {
                        if let Some(session) = call_session.borrow_mut().take() {
                            session.close();
                        }
                        call_pending.borrow_mut().clear();
                        set_call_ui.set(CallUi::Idle);
                        set_status.set(format!("{peer} hat aufgelegt."));
                    }
                }
            }
        }
    }));

    // Der Abhol-Ablauf, geteilt zwischen Knopf und Hinweis-Effect.
    let run_fetch = SendWrapper::new(Rc::new({
        let core = core.clone();
        let apply_call_signal = apply_call_signal.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            let core = core.clone();
            // Je Aufruf einen eigenen Klon des Anruf-Signal-Handlers, damit die
            // äußere Closure Fn bleibt (der async-Block zieht ihn hinein).
            let apply_call_signal = apply_call_signal.clone();
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
                                let own = me.get_untracked();
                                let mut summaries = None;
                                for item in received {
                                    // Ein Anruf-Signal (F2) geht nicht in den
                                    // Chat, sondern an die Anruf-Steuerung.
                                    if let Incoming::Call { peer, signal } = item {
                                        apply_call_signal(peer, signal);
                                        continue;
                                    }
                                    // Ein Verlaufs-Nachzug (Koppeln) bringt
                                    // mehrere Zeilen für einen Chat; sie werden
                                    // in die Ablage gemischt statt einzeln
                                    // angehängt.
                                    if let Incoming::SyncedHistory { peer, lines } = item {
                                        summaries = Some(merge_history(&storage, &peer, &lines));
                                        if open.as_deref() == Some(peer.as_str()) {
                                            set_messages.set(load_history(&storage, &peer));
                                        }
                                        continue;
                                    }
                                    // Eine geänderte Mitgliederliste führt nur
                                    // den Anzeigenamen nach.
                                    if let Incoming::GroupUpdated { group_id, members } = item {
                                        let key = group_chat_key(&group_id);
                                        set_group_labels.update(|labels| {
                                            labels.insert(
                                                key,
                                                GroupUi {
                                                    label: group_label(&members, &own),
                                                    members,
                                                    forgotten: false,
                                                },
                                            );
                                        });
                                        continue;
                                    }
                                    // Selbst entfernt: der Verlauf bleibt
                                    // stehen, der Name sagt den Zustand an,
                                    // die Aktionen sind aus (forgotten).
                                    if let Incoming::GroupRemovedSelf { group_id } = item {
                                        let key = group_chat_key(&group_id);
                                        set_group_labels.update(|labels| {
                                            if let Some(ui) = labels.get_mut(&key) {
                                                if !ui.forgotten {
                                                    ui.label = format!("{} (entfernt)", ui.label);
                                                }
                                                ui.forgotten = true;
                                            }
                                        });
                                        set_status.set(
                                            "Du wurdest aus einer Gruppe entfernt; der Verlauf \
                                             bleibt lesbar, senden geht nicht mehr."
                                                .to_string(),
                                        );
                                        continue;
                                    }
                                    // Eine Einladung: in die Banner-Liste, der
                                    // Nutzer entscheidet (Welcome ist schon
                                    // vorgemerkt, kein Beitritt).
                                    if let Incoming::GroupInvite {
                                        group_id,
                                        name,
                                        inviter,
                                    } = item
                                    {
                                        set_invite_labels.update(|m| {
                                            m.insert(
                                                group_id.clone(),
                                                invite_banner_text(&name, &inviter),
                                            );
                                        });
                                        set_invites.update(|list| {
                                            if !list.contains(&group_id) {
                                                list.push(group_id);
                                            }
                                        });
                                        set_status.set(
                                            "Du wurdest in eine Gruppe eingeladen (siehe links)."
                                                .to_string(),
                                        );
                                        continue;
                                    }
                                    // Eine Bearbeitung oder Löschung trifft
                                    // eine BESTEHENDE Zeile statt eine neue
                                    // anzuhängen; ohne Treffer (unbekannte
                                    // ID) passiert nichts.
                                    if let Incoming::Edit {
                                        chat_peer,
                                        from,
                                        target,
                                        text,
                                        report_id,
                                    } = &item
                                    {
                                        if let Some(s) = apply_event(
                                            &storage,
                                            chat_peer,
                                            from,
                                            target,
                                            Some(text),
                                            report_id.clone(),
                                        ) {
                                            summaries = Some(s);
                                            if open.as_deref() == Some(chat_peer.as_str()) {
                                                set_messages.set(load_history(&storage, chat_peer));
                                            }
                                        }
                                        continue;
                                    }
                                    if let Incoming::Delete {
                                        chat_peer,
                                        from,
                                        target,
                                    } = &item
                                    {
                                        if let Some(s) = apply_event(
                                            &storage, chat_peer, from, target, None, None,
                                        ) {
                                            summaries = Some(s);
                                            if open.as_deref() == Some(chat_peer.as_str()) {
                                                set_messages.set(load_history(&storage, chat_peer));
                                            }
                                        }
                                        continue;
                                    }
                                    // Ausgehend (Self-Sync) gehört in den Chat
                                    // mit dem Empfänger und zählt nie ungelesen;
                                    // eingehend zählt ungelesen, wenn der Chat
                                    // nicht offen ist.
                                    let (chat_peer, line, outgoing) = match item {
                                        Incoming::Message {
                                            from,
                                            text,
                                            report_id,
                                            id,
                                        } => (
                                            from.clone(),
                                            StoredLine {
                                                from,
                                                text,
                                                at: now_unix(),
                                                report_id,
                                                id,
                                                edited: false,
                                                deleted: false,
                                            },
                                            false,
                                        ),
                                        Incoming::Synced { peer, text, id } => (
                                            peer,
                                            StoredLine {
                                                from: own.clone(),
                                                text,
                                                at: now_unix(),
                                                report_id: None,
                                                id,
                                                edited: false,
                                                deleted: false,
                                            },
                                            true,
                                        ),
                                        // Gruppennachricht: in den Gruppen-Chat,
                                        // der Absender kommt aus der von MLS
                                        // geprüften Credential (kein Melden:
                                        // Gruppen-Hüllen tragen kein Franking).
                                        Incoming::Group {
                                            group_id,
                                            from,
                                            text,
                                            id,
                                        } => (
                                            group_chat_key(&group_id),
                                            StoredLine {
                                                from,
                                                text,
                                                at: now_unix(),
                                                report_id: None,
                                                id,
                                                edited: false,
                                                deleted: false,
                                            },
                                            false,
                                        ),
                                        // History, Gruppen-Ereignisse und
                                        // Edit/Delete/Call sind oben behandelt.
                                        Incoming::SyncedHistory { .. }
                                        | Incoming::GroupUpdated { .. }
                                        | Incoming::GroupRemovedSelf { .. }
                                        | Incoming::GroupInvite { .. }
                                        | Incoming::Edit { .. }
                                        | Incoming::Delete { .. }
                                        | Incoming::Call { .. } => unreachable!(),
                                    };
                                    let for_open = open.as_deref() == Some(chat_peer.as_str());
                                    let bump = !outgoing && !for_open;
                                    summaries = Some(record_message(
                                        &storage,
                                        &chat_peer,
                                        line.clone(),
                                        bump,
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

    // Startet den Bearbeiten-Modus: Composer mit dem alten Text füllen, die
    // Ziel-ID merken; das Senden geht dann als Edit raus (siehe run_send).
    let on_edit_start = move |(target, old_text): (String, String)| {
        set_editing.set(Some(target));
        set_text_input.set(old_text);
    };
    let on_edit_cancel = move |_| {
        set_editing.set(None);
        set_text_input.set(String::new());
    };

    // Löscht eine eigene Nachricht BEI ALLEN: das Delete-Ereignis reist an
    // alle Geräte (Empfänger und eigene), lokal wird dieselbe Grabstein-Regel
    // angewandt wie bei einem empfangenen Delete.
    let run_delete_all = SendWrapper::new(Rc::new({
        let core = core.clone();
        move |target: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            set_busy.set(true);
            set_status.set("Wird gelöscht ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let storage = active.storage.clone();
                        let who = active.handle.clone();
                        let result = if let Some(group_id) = group_id_of(&peer).map(str::to_string)
                        {
                            delete_group_message(
                                &storage,
                                &access_token.get_untracked(),
                                &who,
                                &group_id,
                                &target,
                            )
                            .await
                        } else {
                            delete_message(&mut active, access_token, &peer, &target).await
                        };
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(()) => {
                                if let Some(s) =
                                    apply_event(&storage, &peer, &who, &target, None, None)
                                {
                                    set_chats.set(s);
                                }
                                if selected.get_untracked().as_deref() == Some(peer.as_str()) {
                                    set_messages.set(load_history(&storage, &peer));
                                }
                                set_status.set(String::new());
                            }
                            Err(error) => {
                                set_status.set(format!("Löschen fehlgeschlagen: {error}"))
                            }
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    }));

    // Löscht eine Zeile nur für mich: rein lokal, nichts reist.
    let on_delete_local = {
        let current_storage = current_storage.clone();
        move |target: String| {
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            let Some(storage) = current_storage() else {
                return;
            };
            set_chats.set(remove_line_local(&storage, &peer, &target));
            set_messages.set(load_history(&storage, &peer));
        }
    };

    // --- 1:1-Anrufe (F2) ---
    // Holt die TURN-Zugangsdaten und baut eine CallSession; None, wenn Anrufe
    // aus sind oder etwas scheitert (dann meldet der Aufrufer und geht auf
    // Idle zurück).
    let new_call_session = {
        let core = core.clone();
        move |call_id: String, peer: String| {
            let core = core.clone();
            async move {
                let creds = DeliveryClient::new(delivery_url())
                    .turn_credentials(&access_token.get_untracked())
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "Anrufe sind auf diesem Server nicht aktiv.".to_string())?;
                let sink = call_sink(core.clone(), access_token, peer.clone());
                crate::call::CallSession::new(&call_id, &creds, sink)
            }
        }
    };

    // Ein Hangup an den Peer schicken, ohne dass eine Session existiert
    // (Ablehnen, Abbruch während des Klingelns, Annehmen-Fehler).
    let hangup_peer = {
        let core = core.clone();
        move |peer: String, call_id: String, reason: &'static str| {
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                if let Some(mut active) = taken {
                    let _ = send_call_signal(
                        &mut active,
                        access_token,
                        &peer,
                        &client_app::call::Signal::Hangup {
                            call_id,
                            reason: reason.to_string(),
                        },
                    )
                    .await;
                    *core.borrow_mut() = Some(active);
                }
            });
        }
    };

    // Nach dem Aufbau: die Session ablegen, aber nur, wenn der Anruf noch
    // derselbe ist (sonst wurde er inzwischen abgebrochen -> Session schließen,
    // Mikrofon freigeben). Verdrahtet on_closed (gescheiterte Verbindung räumt
    // auf) und spielt die während des Aufbaus gepufferten Signale nach.
    let finalize_call = {
        let call_session = call_session.clone();
        let call_pending = call_pending.clone();
        move |call_id: String, session: Rc<crate::call::CallSession>| {
            if call_ui.get_untracked().call_id() != Some(call_id.as_str()) {
                session.close();
                call_pending.borrow_mut().clear();
                return;
            }
            let closed_session = call_session.clone();
            let closed_id = call_id.clone();
            session.set_on_closed(Rc::new(move || {
                if call_ui.get_untracked().call_id() == Some(closed_id.as_str()) {
                    if let Some(s) = closed_session.borrow_mut().take() {
                        s.close();
                    }
                    set_call_ui.set(CallUi::Idle);
                    set_status.set("Anruf beendet.".to_string());
                }
            }));
            // Live-Tippen (Paket E): der Entwurf des Gesprächspartners kommt
            // über den Datenkanal; leerer Text blendet die Vorschau aus.
            session.set_on_data(Rc::new(move |msg| {
                if let Some(client_app::datachan::DataEvent::Typing { text }) =
                    client_app::datachan::decode(&msg)
                {
                    set_peer_typing.set((!text.is_empty()).then_some(text));
                }
            }));
            let pending: Vec<_> = call_pending.borrow_mut().drain(..).collect();
            for signal in pending {
                let session = session.clone();
                spawn_local(async move {
                    let _ = session.on_signal(signal).await;
                });
            }
            *call_session.borrow_mut() = Some(session);
        }
    };

    // Endet der Anruf (Idle), die Tipp-Vorschau des Partners ausblenden, egal
    // über welchen Weg (Auflegen, Ablehnung, Timeout, Verbindungsabbruch).
    Effect::new(move |_| {
        if matches!(call_ui.get(), CallUi::Idle) {
            set_peer_typing.set(None);
        }
    });

    // Beim BEGINN des Teilens (steigende Flanke von „eingeschaltet + Anruf mit
    // dem offenen Chat") den Composer leeren. So streamt nie ein Entwurf mit,
    // der vorher für einen ANDEREN Chat getippt und beim Wechsel mitgenommen
    // wurde (der globale Entwurf bleibt sonst über Chats erhalten). Nach dem
    // Leeren enthält der Puffer nur noch Text, der HIER im Teilen entsteht;
    // auch ein Stumm-Umschalten (das den Effekt erneut auslöst) kann dann
    // nichts Fremdes mehr senden. Ein normaler Chatwechsel ohne Anruf leert
    // nichts (die Flanke steigt nur mit laufendem Anruf).
    Effect::new(move |_| {
        let sharing = live_typing.get()
            && matches!(
                call_ui.get(),
                CallUi::Active { ref peer, .. }
                    if selected.get().as_deref() == Some(peer.as_str())
            );
        if sharing && !call_was_sharing.get_value() {
            set_text_input.set(String::new());
        }
        call_was_sharing.set_value(sharing);
    });

    // Live-Tippen: den Entwurf über den Datenkanal streamen, solange
    // eingeschaltet UND mit dem offenen Chat gerade ein Anruf läuft. Der Effekt
    // hört auf ALLE vier Bedingungen (Entwurf, Auswahl, Anrufzustand, Schalter),
    // damit ein Wechsel des Kontexts sofort greift:
    // - Innerhalb desselben Teil-Kontexts (gleicher Anruf-Partner offen): den
    //   aktuellen Entwurf senden.
    // - Verlässt man den Kontext (anderer Chat, Anruf-Ende, Schalter aus): dem
    //   Partner EINMAL ein leeres Update schicken, damit seine Vorschau nicht
    //   auf dem zuletzt geteilten Text stehen bleibt.
    // - Betritt man den Kontext neu: NICHT den schon im Feld liegenden Puffer
    //   streamen (der könnte für einen anderen Chat gedacht gewesen sein);
    //   erst der nächste Tastendruck teilt. open_chat leert das Feld bei
    //   eingeschaltetem Live-Tippen ohnehin, sodass kein Fremd-Entwurf bleibt.
    Effect::new({
        let call_session = call_session.clone();
        move |_| {
            let text = text_input.get();
            let selected_now = selected.get();
            let ui = call_ui.get();
            let on = live_typing.get();
            let target = match &ui {
                CallUi::Active { peer, .. }
                    if on && selected_now.as_deref() == Some(peer.as_str()) =>
                {
                    Some(peer.clone())
                }
                _ => None,
            };
            let previous = call_share_target.get_value();
            if let Some(session) = call_session.borrow().as_ref() {
                match (&previous, &target) {
                    // Gleicher Anruf-Partner offen: den Entwurf teilen.
                    (Some(prev), Some(cur)) if prev == cur => {
                        session.send_data(&client_app::datachan::encode_typing(&text));
                    }
                    // Kontext verlassen ODER frisch betreten: Vorschau des
                    // Partners zurücksetzen, aber den vorhandenen Puffer nicht
                    // gleich streamen.
                    (Some(_), _) | (None, Some(_)) => {
                        session.send_data(&client_app::datachan::encode_typing(""));
                    }
                    (None, None) => {}
                }
            }
            call_share_target.set_value(target);
        }
    });

    // Anruf starten (aus dem Chat-Kopf).
    let on_call_start = SendWrapper::new(Rc::new({
        let new_call_session = new_call_session.clone();
        let finalize_call = finalize_call.clone();
        let hangup_peer = hangup_peer.clone();
        let call_session = call_session.clone();
        let call_pending = call_pending.clone();
        move |peer: String| {
            if !matches!(call_ui.get_untracked(), CallUi::Idle) {
                set_status.set("Es läuft schon ein Anruf.".to_string());
                return;
            }
            let call_id = new_uuid();
            set_call_ui.set(CallUi::Outgoing {
                peer: peer.clone(),
                call_id: call_id.clone(),
            });
            set_status.set("Anruf wird aufgebaut ...".to_string());
            let build = new_call_session(call_id.clone(), peer.clone());
            let finalize_call = finalize_call.clone();
            let hangup_peer = hangup_peer.clone();
            let call_session = call_session.clone();
            let call_pending = call_pending.clone();
            spawn_local(async move {
                match build.await {
                    Ok(session) => {
                        if let Err(error) = session.start().await {
                            set_status.set(format!("Anruf fehlgeschlagen: {error}"));
                            session.close();
                            call_pending.borrow_mut().clear();
                            if call_ui.get_untracked().call_id() == Some(call_id.as_str()) {
                                hangup_peer(peer, call_id, "fehler");
                                set_call_ui.set(CallUi::Idle);
                            }
                            return;
                        }
                        finalize_call(call_id.clone(), session);
                        // Klingelt der Anruf zu lange, selbst auflegen (Mikrofon
                        // und Verbindung nicht endlos offen lassen).
                        gloo_timers::future::TimeoutFuture::new(45_000).await;
                        if matches!(call_ui.get_untracked(), CallUi::Outgoing { call_id: ref c, .. } if c == &call_id)
                        {
                            // Die abgelegte Session schließen (sonst bliebe das
                            // Mikrofon offen); sie schickt dabei selbst das
                            // Hangup. Steht sie ausnahmsweise nicht, das Hangup
                            // direkt geben.
                            if let Some(session) = call_session.borrow_mut().take() {
                                session.hangup("keine-antwort");
                            } else {
                                hangup_peer(peer, call_id, "keine-antwort");
                            }
                            call_pending.borrow_mut().clear();
                            set_call_ui.set(CallUi::Idle);
                            set_status.set("Keine Antwort.".to_string());
                        }
                    }
                    Err(error) => {
                        set_status.set(error);
                        call_pending.borrow_mut().clear();
                        if call_ui.get_untracked().call_id() == Some(call_id.as_str()) {
                            set_call_ui.set(CallUi::Idle);
                        }
                    }
                }
            });
        }
    }));

    // Eingehenden Anruf annehmen.
    let on_call_accept = SendWrapper::new(Rc::new({
        let new_call_session = new_call_session.clone();
        let finalize_call = finalize_call.clone();
        let hangup_peer = hangup_peer.clone();
        let call_pending = call_pending.clone();
        move |_: ()| {
            let CallUi::Incoming { peer, call_id, sdp } = call_ui.get_untracked() else {
                return;
            };
            set_call_ui.set(CallUi::Active {
                peer: peer.clone(),
                call_id: call_id.clone(),
                muted: false,
            });
            set_status.set(String::new());
            let build = new_call_session(call_id.clone(), peer.clone());
            let finalize_call = finalize_call.clone();
            let hangup_peer = hangup_peer.clone();
            let call_pending = call_pending.clone();
            spawn_local(async move {
                let failed = match build.await {
                    Ok(session) => match session.accept(&sdp).await {
                        Ok(()) => {
                            finalize_call(call_id.clone(), session);
                            None
                        }
                        Err(error) => {
                            session.close();
                            Some(format!("Annehmen fehlgeschlagen: {error}"))
                        }
                    },
                    Err(error) => Some(error),
                };
                if let Some(message) = failed {
                    set_status.set(message);
                    call_pending.borrow_mut().clear();
                    // Dem Anrufer Bescheid geben, sonst klingelt er weiter.
                    if call_ui.get_untracked().call_id() == Some(call_id.as_str()) {
                        hangup_peer(peer, call_id, "fehler");
                        set_call_ui.set(CallUi::Idle);
                    }
                }
            });
        }
    }));

    // Eingehenden Anruf ablehnen: dem Anrufer ein Hangup schicken (ohne
    // Session, das Offer war nur vorgemerkt).
    let on_call_reject = SendWrapper::new(Rc::new({
        let hangup_peer = hangup_peer.clone();
        let call_pending = call_pending.clone();
        move |_: ()| {
            let CallUi::Incoming { peer, call_id, .. } = call_ui.get_untracked() else {
                return;
            };
            set_call_ui.set(CallUi::Idle);
            set_status.set(String::new());
            call_pending.borrow_mut().clear();
            hangup_peer(peer, call_id, "abgelehnt");
        }
    }));

    // Auflegen (aus dem Anruf-Balken): steht schon eine Session, schickt sie
    // selbst das Hangup und schließt; steht sie noch nicht (Klingeln/Aufbau),
    // das Hangup direkt an den Peer geben, damit sein Klingeln endet.
    let on_call_hangup = SendWrapper::new(Rc::new({
        let call_session = call_session.clone();
        let call_pending = call_pending.clone();
        let hangup_peer = hangup_peer.clone();
        move |_: ()| {
            let current = call_ui.get_untracked();
            if let Some(session) = call_session.borrow_mut().take() {
                session.hangup("aufgelegt");
            } else if let (Some(peer), Some(call_id)) = (current.peer(), current.call_id()) {
                hangup_peer(peer.to_string(), call_id.to_string(), "aufgelegt");
            }
            call_pending.borrow_mut().clear();
            set_call_ui.set(CallUi::Idle);
            set_status.set(String::new());
        }
    }));

    // Mikrofon stumm/frei.
    let on_call_mute = SendWrapper::new(Rc::new({
        let call_session = call_session.clone();
        move |_: ()| {
            if let Some(session) = call_session.borrow().as_ref() {
                let muted = session.toggle_mute();
                if let CallUi::Active { peer, call_id, .. } = call_ui.get_untracked() {
                    set_call_ui.set(CallUi::Active {
                        peer,
                        call_id,
                        muted,
                    });
                }
            }
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
            // Ein angefangenes Bearbeiten gehört zum vorigen Chat; beim
            // Wechsel verwerfen. Der vorbefüllte Composer-Text (die alte
            // Nachricht) muss MIT weg, sonst schickte ein Enter im neuen Chat
            // ihn als neue Nachricht dorthin (Textleck über Chats). Nur der
            // Bearbeiten-Entwurf wird geleert, ein selbst getippter Entwurf
            // ohne Bearbeiten-Modus bleibt erhalten. (Das Leeren fürs
            // Live-Tippen erledigt der share-Effekt, sobald man in den
            // Anruf-Chat wechselt, damit hier keine Entwürfe ohne Anruf fallen.)
            if editing.get_untracked().is_some() {
                set_text_input.set(String::new());
            }
            set_editing.set(None);
            set_safety_info.set(None);
            set_key_info.set(None);
            set_blocked.set(None);
            // Einen Chat zu öffnen verlässt die Einstellungen-Ansicht.
            set_settings_open.set(false);
            // Den Anzeigenamen des Kontakts frisch holen (eine Änderung des
            // Kontakts kommt so beim Öffnen automatisch an).
            refresh_contact_names(
                vec![peer.clone()],
                &me.get_untracked(),
                access_token.get_untracked(),
                storage.clone(),
                set_contact_names,
            );
            set_selected.set(Some(peer.clone()));
            // Bei einer Gruppe die Verwaltungssicht (Name, Rollen,
            // Einstellungen) frisch holen; bei einem 1:1-Chat gibt es keine.
            set_group_meta.set(None);
            if let Some(group_id) = group_id_of(&peer) {
                let group_id = group_id.to_string();
                let peer_for_meta = peer.clone();
                spawn_local(async move {
                    if let Ok(meta) = DeliveryClient::new(delivery_url())
                        .group_meta(&access_token.get_untracked(), &group_id)
                        .await
                    {
                        // Den Server-Namen in die Chatliste/den Kopf übernehmen
                        // (statt der abgeleiteten Mitglieder-Liste).
                        if !meta.name.is_empty() {
                            let key = peer_for_meta.clone();
                            let name = meta.name.clone();
                            set_group_labels.update(|labels| {
                                if let Some(ui) = labels.get_mut(&key) {
                                    if !ui.forgotten {
                                        ui.label = name;
                                    }
                                }
                            });
                        }
                        if selected.get_untracked().as_deref() == Some(peer_for_meta.as_str()) {
                            set_group_meta.set(Some(meta));
                        }
                    }
                });
            }
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

    // Gruppe gründen (im Neuer-Chat-Panel): die Mitglieder-Handles aus dem
    // Feld (Komma oder Leerzeichen), dann der volle Gründungs-Ablauf
    // (create_group_web); der neue Gruppen-Chat öffnet sich direkt.
    let on_create_group = {
        let open_chat = open_chat.clone();
        let current_storage = current_storage.clone();
        move || {
            if busy.get_untracked() {
                return;
            }
            let own = me.get_untracked();
            let mut invitees: Vec<String> = Vec::new();
            for raw in group_input
                .get_untracked()
                .split([',', ' '])
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if raw != own && !invitees.iter().any(|h| h == raw) {
                    invitees.push(raw.to_string());
                }
            }
            if invitees.is_empty() {
                set_status.set("Mitglieder-Handles angeben (mit Komma getrennt).".to_string());
                return;
            }
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            let group_name = group_name_input.get_untracked().trim().to_string();
            set_busy.set(true);
            set_status.set("Gruppe wird gegründet ...".to_string());
            let open_chat = open_chat.clone();
            spawn_local(async move {
                let result = create_group_web(
                    &storage,
                    &access_token.get_untracked(),
                    &own,
                    &group_name,
                    &invitees,
                )
                .await;
                match result {
                    Ok(group_id) => {
                        let key = group_chat_key(&group_id);
                        let mut members = vec![own.clone()];
                        members.extend(invitees);
                        // Der eingegebene Name gewinnt; sonst die Mitglieder.
                        let label = if group_name.is_empty() {
                            group_label(&members, &own)
                        } else {
                            group_name.clone()
                        };
                        set_group_labels.update(|labels| {
                            labels.insert(
                                key.clone(),
                                GroupUi {
                                    label,
                                    members: members.clone(),
                                    forgotten: false,
                                },
                            );
                        });
                        set_chats.set(ensure_chat(&storage, &key));
                        set_group_input.set(String::new());
                        set_group_name_input.set(String::new());
                        set_new_chat_open.set(false);
                        set_status.set("Gruppe gegründet.".to_string());
                        open_chat(key);
                    }
                    Err(error) => set_status.set(format!("Gruppe gründen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Mitglied aus der OFFENEN Gruppe entfernen (MLS-Neuschlüsseln): die
    // neue Epoche bleibt dem Entfernten verschlossen; danach frischer
    // Roster an die Rest-Gruppe.
    let on_group_remove = {
        let current_storage = current_storage.clone();
        SendWrapper::new(Rc::new(move |handle: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            let Some(group_id) = group_id_of(&peer).map(str::to_string) else {
                return;
            };
            let Some(storage) = current_storage() else {
                return;
            };
            let own = me.get_untracked();
            set_busy.set(true);
            spawn_local(async move {
                let result = remove_group_member(
                    &storage,
                    &access_token.get_untracked(),
                    &own,
                    &group_id,
                    &handle,
                )
                .await;
                match result {
                    Ok(members) => {
                        set_group_labels.update(|labels| {
                            labels.insert(
                                group_chat_key(&group_id),
                                GroupUi {
                                    label: group_label(&members, &own),
                                    members,
                                    forgotten: false,
                                },
                            );
                        });
                        set_status.set(format!(
                            "{handle} entfernt; die Gruppe ist neu geschlüsselt."
                        ));
                    }
                    Err(error) => set_status.set(format!("Entfernen: {error}")),
                }
                set_busy.set(false);
            });
        }))
    };

    // Die offene Gruppe verlassen: Ansage an die anderen, dann lokal
    // vergessen (der Verlauf bleibt); kryptografisch entfernt einen erst
    // der Remove-Commit eines verbleibenden Mitglieds.
    let on_group_leave = {
        let current_storage = current_storage.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let Some(peer) = selected.get_untracked() else {
                return;
            };
            let Some(group_id) = group_id_of(&peer).map(str::to_string) else {
                return;
            };
            let Some(storage) = current_storage() else {
                return;
            };
            let own = me.get_untracked();
            set_busy.set(true);
            spawn_local(async move {
                let result =
                    leave_group_web(&storage, &access_token.get_untracked(), &own, &group_id).await;
                match result {
                    Ok(()) => {
                        let key = group_chat_key(&group_id);
                        set_group_labels.update(|labels| {
                            if let Some(ui) = labels.get_mut(&key) {
                                if !ui.forgotten {
                                    ui.label = format!("{} (verlassen)", ui.label);
                                }
                                ui.forgotten = true;
                            }
                        });
                        set_status.set(
                            "Gruppe verlassen. Kryptografisch entfernt dich erst ein \
                             verbleibendes Mitglied über dessen Mitgliederliste."
                                .to_string(),
                        );
                    }
                    Err(error) => set_status.set(format!("Verlassen: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Rolle eines Mitglieds ändern (befördern/degradieren). Server-Aktion
    // ohne MLS-Änderung; danach die Verwaltungssicht auffrischen.
    let on_group_role = {
        move |(target, role): (String, GroupRole)| {
            if busy.get_untracked() {
                return;
            }
            let Some(group_id) = selected
                .get_untracked()
                .and_then(|p| group_id_of(&p).map(str::to_string))
            else {
                return;
            };
            set_busy.set(true);
            spawn_local(async move {
                match DeliveryClient::new(delivery_url())
                    .group_set_role(&access_token.get_untracked(), &group_id, &target, role)
                    .await
                {
                    Ok(meta) => {
                        set_group_meta.set(Some(meta));
                        set_status.set(format!("Rolle von {target} geändert."));
                    }
                    Err(error) => set_status.set(format!("Rolle ändern: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Besitz an ein Mitglied übergeben (nur der Owner).
    let on_group_transfer = {
        move |target: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(group_id) = selected
                .get_untracked()
                .and_then(|p| group_id_of(&p).map(str::to_string))
            else {
                return;
            };
            set_busy.set(true);
            spawn_local(async move {
                match DeliveryClient::new(delivery_url())
                    .group_transfer(&access_token.get_untracked(), &group_id, &target)
                    .await
                {
                    Ok(meta) => {
                        set_group_meta.set(Some(meta));
                        set_status.set(format!("Besitz an {target} übergeben."));
                    }
                    Err(error) => set_status.set(format!("Übergabe: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Announcement-Modus umschalten (nur Staff). Holt die aktuellen
    // Einstellungen und kippt das Feld.
    let on_group_announce = {
        move |on: bool| {
            if busy.get_untracked() {
                return;
            }
            let Some(group_id) = selected
                .get_untracked()
                .and_then(|p| group_id_of(&p).map(str::to_string))
            else {
                return;
            };
            let Some(mut settings) = group_meta.get_untracked().map(|m| m.settings) else {
                return;
            };
            settings.announcement = on;
            set_busy.set(true);
            spawn_local(async move {
                match DeliveryClient::new(delivery_url())
                    .group_update_info(
                        &access_token.get_untracked(),
                        &group_id,
                        None,
                        Some(settings),
                    )
                    .await
                {
                    Ok(meta) => {
                        set_group_meta.set(Some(meta));
                        set_status.set("Einstellung gespeichert.".to_string());
                    }
                    Err(error) => set_status.set(format!("Einstellung: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Eine Einladung annehmen: jetzt erst der Beitritt (verarbeitet den
    // Welcome), der gepufferte Roster wird nachgespielt, der Gruppen-Chat
    // öffnet sich. Kein Netzwerk nötig (die Gruppe ist beim Dienst schon
    // angelegt).
    let on_invite_accept = {
        let open_chat = open_chat.clone();
        let current_storage = current_storage.clone();
        SendWrapper::new(Rc::new(move |group_id: String| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = current_storage() else {
                return;
            };
            let own = me.get_untracked();
            let open_chat = open_chat.clone();
            set_busy.set(true);
            spawn_local(async move {
                match accept_invite(&storage, &own, &group_id) {
                    Ok(members) => {
                        let key = group_chat_key(&group_id);
                        set_group_labels.update(|labels| {
                            labels.insert(
                                key.clone(),
                                GroupUi {
                                    label: group_label(&members, &own),
                                    members,
                                    forgotten: false,
                                },
                            );
                        });
                        set_invites.update(|list| list.retain(|id| id != &group_id));
                        set_chats.set(ensure_chat(&storage, &key));
                        set_status.set("Einladung angenommen.".to_string());
                        open_chat(key);
                    }
                    Err(error) => {
                        // Auch die „schon wieder entfernt"-Ablehnung hat die
                        // Einladung in der Ablage verworfen: die Banner-Liste
                        // aus der Ablage nachziehen.
                        set_invites.set(load_invites(&storage));
                        set_status.set(format!("Annehmen: {error}"));
                    }
                }
                set_busy.set(false);
            });
        }))
    };

    // Eine Einladung ablehnen: den Welcome verwerfen (kein KeyPackage
    // verbraucht), aus der Banner-Liste nehmen.
    let on_invite_decline = {
        let current_storage = current_storage.clone();
        SendWrapper::new(Rc::new(move |group_id: String| {
            let Some(storage) = current_storage() else {
                return;
            };
            if let Err(error) = forget_invite(&storage, &group_id) {
                set_status.set(format!("Ablehnen: {error}"));
                return;
            }
            set_invites.update(|list| list.retain(|id| id != &group_id));
            set_status.set("Einladung abgelehnt.".to_string());
        }))
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

    // Verlauf an frisch gekoppelte eigene Geräte nachliefern (siehe
    // push_history). Vom Nutzer ausgelöst, wenn das neue Gerät bereit ist.
    let on_push_history = {
        let core = core.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            set_status.set("Verlauf wird an neue Geräte gesendet ...".to_string());
            let core = core.clone();
            spawn_local(async move {
                let taken = core.borrow_mut().take();
                match taken {
                    Some(mut active) => {
                        let result = push_history(&mut active, access_token).await;
                        *core.borrow_mut() = Some(active);
                        match result {
                            Ok(0) => set_status
                                .set("Kein neues Gerät oder kein Verlauf zu senden.".to_string()),
                            Ok(n) => {
                                set_status.set(format!("Verlauf an {n} neue(s) Gerät(e) gesendet."))
                            }
                            Err(error) => set_status.set(format!("Verlauf senden: {error}")),
                        }
                    }
                    None => set_status.set("Nicht angemeldet.".to_string()),
                }
                set_busy.set(false);
            });
        }
    };

    // Passwortwechsel (Einstellungen, Konto): altes Passwort prüfen lassen,
    // neues setzen, danach die lokale Ablage unter dem neuen Passwort neu
    // versiegeln (sonst scheitert die nächste Anmeldung am Entsperren). Der
    // Dienst meldet die anderen Geräte ab; dieses Gerät behält seine Session.
    let on_change_password = {
        let current_storage = current_storage.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let current = pw_current.get_untracked();
            let new = pw_new.get_untracked();
            let confirm = pw_confirm.get_untracked();
            if current.is_empty() || new.is_empty() {
                set_status.set("Aktuelles und neues Passwort angeben.".to_string());
                return;
            }
            if new.chars().count() < 12 {
                set_status.set("Das neue Passwort braucht mindestens 12 Zeichen.".to_string());
                return;
            }
            if new.chars().count() > 128 {
                set_status.set("Das neue Passwort ist auf 128 Zeichen begrenzt.".to_string());
                return;
            }
            if new != confirm {
                set_status.set(
                    "Die Wiederholung stimmt nicht mit dem neuen Passwort überein.".to_string(),
                );
                return;
            }
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            set_busy.set(true);
            set_status.set("Passwort wird geändert ...".to_string());
            spawn_local(async move {
                let result = IdentityClient::new(identity_url())
                    .change_password(&access_token.get_untracked(), &current, &new)
                    .await;
                match result {
                    Ok(()) => {
                        // Erst nach der Server-Bestätigung neu versiegeln:
                        // scheitert der Wechsel, bleibt die Ablage unter dem
                        // alten Passwort stimmig. Das Versiegeln (synchron,
                        // Borrow sofort freigegeben) vom Schreiben trennen und
                        // das Schreiben abwarten, damit ein fehlgeschlagener
                        // IndexedDB-Schreibvorgang nicht still bleibt (sonst
                        // stünde der Dienst auf dem neuen, die Ablage auf dem
                        // alten Passwort, und die nächste Anmeldung sperrte
                        // sich aus).
                        let stored = storage.borrow_mut().reseal_prepare(&new);
                        match crate::storage::write_state(stored).await {
                            Ok(()) => {
                                set_pw_current.set(String::new());
                                set_pw_new.set(String::new());
                                set_pw_confirm.set(String::new());
                                set_status.set(
                                    "Passwort geändert. Andere Geräte sind abgemeldet.".to_string(),
                                );
                            }
                            Err(error) => set_status.set(format!(
                                "Passwort beim Dienst geändert, aber die lokale Ablage nicht neu \
                                 verschlüsselt ({error}). Bitte neu laden und mit dem NEUEN Passwort \
                                 anmelden; gelingt das nicht, ist eine Neukopplung nötig."
                            )),
                        }
                    }
                    // Transportfehler ist mehrdeutig: der Server kann den
                    // Wechsel schon vollzogen haben, während die Antwort verloren
                    // ging. Nicht als reinen Fehlschlag melden, damit der Nutzer
                    // beim nächsten Anmelden das neue Passwort probiert.
                    Err(ClientError::Transport(detail)) => set_status.set(format!(
                        "Ungewiss, ob der Wechsel durchlief ({detail}). Beim nächsten Anmelden \
                         zuerst das NEUE Passwort versuchen."
                    )),
                    Err(error) => set_status.set(format!("Passwortwechsel: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Konto-Löschung vormerken (NF030, Widerrufsfrist): das Passwort
    // bestätigt den Besitzer. Fängt nur Copy-Signale ein.
    let on_delete_account = move |_| {
        if busy.get_untracked() {
            return;
        }
        let password = delete_pw.get_untracked();
        if password.is_empty() {
            set_status.set("Zum Löschen das Passwort eingeben.".to_string());
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let result = IdentityClient::new(identity_url())
                .delete_account(&access_token.get_untracked(), &password)
                .await;
            match result {
                Ok(until) => {
                    set_deletion_pending.set(Some(until));
                    set_delete_pw.set(String::new());
                    set_status.set(
                        "Löschung vorgemerkt. Bis zum Ablauf der Frist widerrufbar.".to_string(),
                    );
                }
                Err(error) => set_status.set(format!("Löschen: {error}")),
            }
            set_busy.set(false);
        });
    };

    // Vorgemerkte Löschung widerrufen.
    let on_undelete = move |_| {
        if busy.get_untracked() {
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let result = IdentityClient::new(identity_url())
                .undelete_account(&access_token.get_untracked())
                .await;
            match result {
                Ok(()) => {
                    set_deletion_pending.set(None);
                    set_status.set("Löschung widerrufen. Das Konto bleibt.".to_string());
                }
                Err(error) => set_status.set(format!("Widerrufen: {error}")),
            }
            set_busy.set(false);
        });
    };

    // Anzeigename ändern (F010): der Server trimmt und bestätigt die
    // gespeicherte Form, das Feld übernimmt sie (kanonischer Stand statt
    // Roh-Eingabe). Fängt nur Copy-Signale ein.
    let on_rename = move |_| {
        if busy.get_untracked() {
            return;
        }
        let name = name_input.get_untracked();
        if name.trim().is_empty() {
            set_status.set("Anzeigename darf nicht leer sein.".to_string());
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let result = IdentityClient::new(identity_url())
                .set_display_name(&access_token.get_untracked(), &name)
                .await;
            match result {
                Ok(stored) => {
                    set_name_input.set(stored);
                    set_status.set("Anzeigename geändert.".to_string());
                }
                Err(error) => set_status.set(format!("Anzeigename: {error}")),
            }
            set_busy.set(false);
        });
    };

    // Wurzelschlüssel rotieren (ADR-0010): nur auf einem Erstgerät mit
    // Wurzel-Seed. Kontakte sehen danach einen Schlüsselwechsel.
    let on_rotate_key = {
        let current_storage = current_storage.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            set_busy.set(true);
            spawn_local(async move {
                match rotate_key_web(&storage, &access_token.get_untracked()).await {
                    Ok(count) => set_status.set(format!(
                        "Wurzelschlüssel rotiert ({count} Gerät(e) neu signiert). Kontakte sehen \
                         einen Schlüsselwechsel; die Sicherheitsnummer über einen zweiten Kanal \
                         neu abgleichen."
                    )),
                    Err(error) => set_status.set(format!("Rotieren: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Geteilter Nachlade-Ablauf der Gerätemenge, von mehreren Handlern
    // genutzt (Öffnen, Freischalten, Entfernen).
    let refresh_devices = {
        let current_storage = current_storage.clone();
        SendWrapper::new(Rc::new(move || {
            let Some(storage) = current_storage() else {
                return;
            };
            spawn_local(async move {
                match load_device_rows(&storage, &access_token.get_untracked()).await {
                    Ok(rows) => set_device_rows.set(rows),
                    Err(error) => set_status.set(format!("Geräte laden: {error}")),
                }
            });
        }))
    };

    // Die globale Blockliste (Einstellungen) frisch vom Dienst laden.
    let refresh_block_list = SendWrapper::new(Rc::new(move || {
        spawn_local(async move {
            match DeliveryClient::new(delivery_url())
                .blocks(&access_token.get_untracked())
                .await
            {
                Ok(list) => set_block_list.set(Some(list)),
                Err(error) => set_status.set(format!("Blockliste laden: {error}")),
            }
        });
    }));

    // Einstellungen öffnen: den Chat-Thread beiseitelegen und die
    // serverseitigen Listen (Geräte, Blockliste) frisch laden.
    let open_settings = {
        let refresh_devices = refresh_devices.clone();
        let refresh_block_list = refresh_block_list.clone();
        move |_| {
            set_settings_open.set(true);
            set_status.set(String::new());
            refresh_devices();
            refresh_block_list();
        }
    };
    let close_settings = move |_| set_settings_open.set(false);

    // "Versiegelt senden als Vorgabe" umschalten: die Wahl persistieren und
    // sofort auf den Composer-Haken anwenden.
    let on_sealed_default_toggle = {
        let current_storage = current_storage.clone();
        move |ev: web_sys::Event| {
            let on = event_target_checked(&ev);
            set_sealed_default.set(on);
            set_sealed_choice.set(on);
            if let Some(storage) = current_storage() {
                save_sealed_default(&storage, on);
            }
        }
    };

    // Live-Tippen ein-/ausschalten (Paket E): während eines Anrufs sieht der
    // Gesprächspartner den Entwurf in Echtzeit über den verschlüsselten
    // Datenkanal.
    let on_live_typing_toggle = {
        let current_storage = current_storage.clone();
        move |ev: web_sys::Event| {
            let on = event_target_checked(&ev);
            // Der Streaming-Effekt hört auf live_typing: das Ausschalten während
            // eines Anrufs schickt dem Partner selbst ein leeres Update (seine
            // Vorschau verschwindet), das Teilen endet also sofort.
            set_live_typing.set(on);
            if let Some(storage) = current_storage() {
                save_live_typing(&storage, on);
            }
        }
    };

    // Web-Push ein-/ausschalten: registriert (bzw. kündigt) das Browser-Abo
    // und hinterlegt es beim Dienst. Braucht die Browser-Erlaubnis; scheitert
    // das, kehrt der Haken zurück. Der Zustand wird optimistisch gesetzt und
    // bei Fehler zurückgenommen.
    let on_push_toggle = {
        let current_storage = current_storage.clone();
        move |ev: web_sys::Event| {
            let want_on = event_target_checked(&ev);
            set_push_on.set(want_on);
            set_busy.set(true);
            set_status.set(if want_on {
                "Benachrichtigungen werden eingerichtet ...".to_string()
            } else {
                "Benachrichtigungen werden abgeschaltet ...".to_string()
            });
            let current_storage = current_storage.clone();
            spawn_local(async move {
                let delivery = DeliveryClient::new(delivery_url());
                let token = access_token.get_untracked();
                let result = if want_on {
                    crate::push::enable(&delivery, &token).await
                } else {
                    crate::push::disable(&delivery, &token).await
                };
                match result {
                    Ok(()) => {
                        if let Some(storage) = current_storage() {
                            save_push_on(&storage, want_on);
                        }
                        set_status.set(if want_on {
                            "Benachrichtigungen aktiviert.".to_string()
                        } else {
                            "Benachrichtigungen abgeschaltet.".to_string()
                        });
                    }
                    Err(error) => {
                        // Fehlschlag (Erlaubnis verweigert, kein https, Server
                        // ohne Push): Haken zurücknehmen und Grund zeigen.
                        set_push_on.set(!want_on);
                        set_status.set(format!("Benachrichtigungen: {error}"));
                    }
                }
                set_busy.set(false);
            });
        }
    };

    // Ein Handle aus der globalen Blockliste entblocken.
    let on_unblock = {
        let refresh_block_list = refresh_block_list.clone();
        SendWrapper::new(Rc::new(move |handle: String| {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            let refresh_block_list = refresh_block_list.clone();
            spawn_local(async move {
                let result = DeliveryClient::new(delivery_url())
                    .unblock(&access_token.get_untracked(), &handle)
                    .await;
                match result {
                    Ok(()) => {
                        set_status.set(format!("{handle} ist nicht mehr blockiert."));
                        refresh_block_list();
                    }
                    Err(error) => set_status.set(format!("Entblocken: {error}")),
                }
                set_busy.set(false);
            });
        }))
    };

    // Ein neues Gerät freischalten (Web als Erstgerät).
    let on_approve = {
        let current_storage = current_storage.clone();
        let refresh_devices = refresh_devices.clone();
        move |_| {
            if busy.get_untracked() {
                return;
            }
            let payload = link_input.get_untracked();
            if payload.trim().is_empty() {
                set_status.set("Kopplungs-Antrag des neuen Geräts einfügen.".to_string());
                return;
            }
            let Some(storage) = current_storage() else {
                set_status.set("Nicht angemeldet.".to_string());
                return;
            };
            set_busy.set(true);
            let refresh_devices = refresh_devices.clone();
            spawn_local(async move {
                match approve_device(&storage, &access_token.get_untracked(), &payload).await {
                    Ok(number) => {
                        set_link_input.set(String::new());
                        set_status.set(format!(
                            "Gerät freigeschaltet als Nummer {number}. Auf dem neuen Gerät abschließen."
                        ));
                        refresh_devices();
                    }
                    Err(error) => set_status.set(format!("Freischalten: {error}")),
                }
                set_busy.set(false);
            });
        }
    };

    // Ein Gerät entfernen (Revocation). Nimmt die Geräte-ID; das eigene
    // Gerät bietet die Oberfläche gar nicht zum Entfernen an.
    let on_revoke = {
        let refresh_devices = refresh_devices.clone();
        SendWrapper::new(Rc::new(move |device_id: String| {
            if busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            let refresh_devices = refresh_devices.clone();
            spawn_local(async move {
                let result = IdentityClient::new(identity_url())
                    .remove_device(&access_token.get_untracked(), &device_id)
                    .await;
                match result {
                    Ok(()) => {
                        set_status.set("Gerät entfernt.".to_string());
                        refresh_devices();
                    }
                    Err(error) => set_status.set(format!("Entfernen: {error}")),
                }
                set_busy.set(false);
            });
        }))
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
                {move || {
                    // Vor der Anmeldung lebt der Darstellungs-Umschalter in
                    // der Kopfleiste (es gibt dann keine Einstellungen-Seite);
                    // danach steht er dort, um ihn nicht doppelt zu führen.
                    (!logged_in.get())
                        .then(|| {
                            view! {
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
                            }
                        })
                }}
            </header>

            {move || {
                if logged_in.get() {
                    let open_chat_list = open_chat.clone();
                    let confirm_click = on_new_chat_confirm.clone();
                    let confirm_key = on_new_chat_confirm.clone();
                    let group_create_click = on_create_group.clone();
                    let group_create_key = on_create_group.clone();
                    // Frische Klone der Thread-Handler: die innere, auf `selected`
                    // reagierende Closure besitzt eigene Kopien, die äußere
                    // Closure behält ihre Originale für den nächsten Lauf.
                    // `on_back` fängt nur Copy-Signale ein und ist selbst Copy,
                    // braucht also keinen Klon.
                    let on_safety = on_safety.clone();
                    let on_key_check = on_key_check.clone();
                    let on_group_remove = on_group_remove.clone();
                    let on_group_leave = on_group_leave.clone();
                    let on_invite_accept = on_invite_accept.clone();
                    let on_invite_decline = on_invite_decline.clone();
                    let run_report = run_report.clone();
                    let run_delete_all = run_delete_all.clone();
                    let on_delete_local = on_delete_local.clone();
                    let on_call_start = on_call_start.clone();
                    let on_call_accept = on_call_accept.clone();
                    let on_call_reject = on_call_reject.clone();
                    let on_call_hangup = on_call_hangup.clone();
                    let on_call_mute = on_call_mute.clone();
                    let on_send = on_send.clone();
                    let on_fetch = on_fetch.clone();
                    let on_message_key = on_message_key.clone();
                    // Handler der Einstellungen-Ansicht (eigener Zweig des
                    // Haupt-Bereichs), frisch geklont wie die Thread-Handler.
                    let on_kt_check = on_kt_check.clone();
                    let on_approve = on_approve.clone();
                    let on_revoke = on_revoke.clone();
                    let on_unblock = on_unblock.clone();
                    let on_sealed_default_toggle = on_sealed_default_toggle.clone();
                    let on_push_toggle = on_push_toggle.clone();
                    let on_live_typing_toggle = on_live_typing_toggle.clone();
                    let on_push_history = on_push_history.clone();
                    let on_change_password = on_change_password.clone();
                    let on_backup_export = on_backup_export.clone();
                    let open_settings = open_settings.clone();
                    view! {
                        // Anruf-Balken (F2): über allem, weil ein Anruf
                        // unabhängig vom offenen Chat klingelt.
                        {
                            let on_call_accept = on_call_accept.clone();
                            let on_call_reject = on_call_reject.clone();
                            let on_call_hangup = on_call_hangup.clone();
                            let on_call_mute = on_call_mute.clone();
                            move || {
                                let accept = on_call_accept.clone();
                                let reject = on_call_reject.clone();
                                let hangup = on_call_hangup.clone();
                                let mute = on_call_mute.clone();
                                match call_ui.get() {
                                    CallUi::Idle => ().into_any(),
                                    CallUi::Outgoing { peer, .. } => {
                                        view! {
                                            <div class="sm-call-bar" role="status">
                                                <span>{format!("Anruf an {peer} \u{2013} klingelt ...")}</span>
                                                <button
                                                    type="button"
                                                    class="sm-danger-btn"
                                                    on:click=move |_| hangup(())
                                                >
                                                    "Auflegen"
                                                </button>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                    CallUi::Incoming { peer, .. } => {
                                        view! {
                                            <div class="sm-call-bar" role="alert">
                                                <span>{format!("{peer} ruft an")}</span>
                                                <button
                                                    type="button"
                                                    class="sm-primary"
                                                    on:click=move |_| accept(())
                                                >
                                                    "Annehmen"
                                                </button>
                                                <button
                                                    type="button"
                                                    class="sm-danger-btn"
                                                    on:click=move |_| reject(())
                                                >
                                                    "Ablehnen"
                                                </button>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                    CallUi::Active { peer, muted, .. } => {
                                        view! {
                                            <div class="sm-call-bar" role="status">
                                                <span>{format!("Verbunden mit {peer}")}</span>
                                                // Live-Tippen (Paket E): der Entwurf des
                                                // Gesprächspartners, sobald er ihn schreibt.
                                                {move || {
                                                    peer_typing
                                                        .get()
                                                        .map(|draft| {
                                                            view! {
                                                                <span
                                                                    class="sm-call-typing"
                                                                    aria-live="polite"
                                                                >
                                                                    {format!("schreibt: {draft}")}
                                                                </span>
                                                            }
                                                        })
                                                }}
                                                <button
                                                    type="button"
                                                    class="sm-secondary"
                                                    on:click=move |_| mute(())
                                                >
                                                    {if muted { "Ton an" } else { "Stumm" }}
                                                </button>
                                                <button
                                                    type="button"
                                                    class="sm-danger-btn"
                                                    on:click=move |_| hangup(())
                                                >
                                                    "Auflegen"
                                                </button>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                }
                            }
                        }
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
                                            let group_create_click = group_create_click.clone();
                                            let group_create_key = group_create_key.clone();
                                            view! {
                                                <div class="sm-newchat">
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
                                                    <div class="sm-field">
                                                        <label for="sm-newgroupname">"Oder Gruppe: Name (optional)"</label>
                                                        <input
                                                            id="sm-newgroupname"
                                                            placeholder="Team Alpha"
                                                            prop:value=group_name_input
                                                            on:input=move |ev| {
                                                                set_group_name_input
                                                                    .set(event_target_value(&ev))
                                                            }
                                                        />
                                                    </div>
                                                    <div class="sm-field">
                                                        <label for="sm-newgroup">"Mitglieder (mit Komma)"</label>
                                                        <input
                                                            id="sm-newgroup"
                                                            placeholder="bert, carl"
                                                            prop:value=group_input
                                                            on:input=move |ev| {
                                                                set_group_input
                                                                    .set(event_target_value(&ev))
                                                            }
                                                            on:keydown=move |ev: web_sys::KeyboardEvent| {
                                                                if ev.key() == "Enter" {
                                                                    ev.prevent_default();
                                                                    (group_create_key)();
                                                                }
                                                            }
                                                        />
                                                    </div>
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=move |_| (group_create_click)()
                                                    >
                                                        "Gruppe gründen"
                                                    </button>
                                                </div>
                                            }
                                        })
                                }}
                                {move || {
                                    // Offene Einladungen als Banner mit
                                    // Annehmen/Ablehnen. Kein automatischer
                                    // Beitritt: der Nutzer entscheidet.
                                    let list = invites.get();
                                    let labels = invite_labels.get();
                                    (!list.is_empty())
                                        .then(|| {
                                            let accept = on_invite_accept.clone();
                                            let decline = on_invite_decline.clone();
                                            view! {
                                                <ul class="sm-invites" aria-label="Einladungen">
                                                    {list
                                                        .into_iter()
                                                        .map(|group_id| {
                                                            let accept = accept.clone();
                                                            let decline = decline.clone();
                                                            let id_a = group_id.clone();
                                                            let id_d = group_id.clone();
                                                            let text = labels
                                                                .get(&group_id)
                                                                .cloned()
                                                                .unwrap_or_else(|| {
                                                                    "Einladung in eine Gruppe".to_string()
                                                                });
                                                            view! {
                                                                <li class="sm-invite">
                                                                    <span>{text}</span>
                                                                    <div class="sm-invite-actions">
                                                                        <button
                                                                            type="button"
                                                                            class="sm-primary"
                                                                            disabled=busy
                                                                            on:click=move |_| (accept)(id_a.clone())
                                                                        >
                                                                            "Annehmen"
                                                                        </button>
                                                                        <button
                                                                            type="button"
                                                                            class="sm-secondary"
                                                                            disabled=busy
                                                                            on:click=move |_| (decline)(id_d.clone())
                                                                        >
                                                                            "Ablehnen"
                                                                        </button>
                                                                    </div>
                                                                </li>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </ul>
                                            }
                                        })
                                }}
                                <ul class="sm-convos">
                                    {move || {
                                        let sel = selected.get();
                                        let labels = group_labels.get();
                                        let names = contact_names.get();
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
                                                    // Gruppen-Chats zeigen ihren
                                                    // Anzeigenamen statt des
                                                    // grp:-Schlüssels; 1:1-Chats
                                                    // den Kontakt-Anzeigenamen,
                                                    // sonst den rohen Handle.
                                                    let shown = labels
                                                        .get(&peer)
                                                        .map(|ui| ui.label.clone())
                                                        .or_else(|| names.get(&peer).cloned())
                                                        .unwrap_or_else(|| peer.clone());
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
                                                                    {avatar_initial(&shown)}
                                                                </span>
                                                                <span class="sm-convo-name">
                                                                    {shown.clone()}
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
                                        class="sm-secondary sm-settings-open"
                                        on:click=open_settings
                                    >
                                        "Einstellungen"
                                    </button>
                                </div>
                            </nav>

                            <main class="sm-thread" aria-label="Unterhaltung">
                                {
                                    // Einstellungen als eigener Zweig des
                                    // Haupt-Bereichs; die Handler frisch je
                                    // Aufbau klonen (settings_open reaktiv).
                                    let on_kt_check = on_kt_check.clone();
                                    let on_approve = on_approve.clone();
                                    let on_revoke = on_revoke.clone();
                                    let on_unblock = on_unblock.clone();
                                    let on_sealed_default_toggle = on_sealed_default_toggle.clone();
                                    let on_push_toggle = on_push_toggle.clone();
                                    let on_live_typing_toggle = on_live_typing_toggle.clone();
                                    let on_push_history = on_push_history.clone();
                                    let on_change_password = on_change_password.clone();
                                    let on_backup_export = on_backup_export.clone();
                                    let on_rotate_key = on_rotate_key.clone();
                                    move || {
                                        // Diese reaktive Closure läuft mehrfach
                                        // (settings_open, selected); die
                                        // Gruppen-Handler wandern in verschachtelte
                                        // Views, deshalb je Lauf frisch klonen.
                                        let on_group_remove = on_group_remove.clone();
                                        let on_group_leave = on_group_leave.clone();
                                        if settings_open.get() {
                                            let on_revoke = on_revoke.clone();
                                            let on_unblock = on_unblock.clone();
                                            let on_change_password = on_change_password.clone();
                                            let on_backup_export = on_backup_export.clone();
                                            let on_rotate_key = on_rotate_key.clone();
                                            return view! {
                                                <div class="sm-settings" aria-label="Einstellungen">
                                                    <div class="sm-settings-head">
                                                        <h2 tabindex="-1">"Einstellungen"</h2>
                                                        <button
                                                            type="button"
                                                            class="sm-secondary"
                                                            on:click=close_settings
                                                        >
                                                            "Zurück"
                                                        </button>
                                                    </div>

                                                    <section class="sm-set-group" aria-label="Darstellung">
                                                        <h3>"Darstellung"</h3>
                                                        <div class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Modus"
                                                                <small>
                                                                    "Wirkt sofort; die Wahl bleibt auf diesem Gerät gespeichert."
                                                                </small>
                                                            </span>
                                                            <select
                                                                aria-label="Darstellung"
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
                                                    </section>

                                                    <section class="sm-set-group" aria-label="Konto">
                                                        <h3>"Konto"</h3>
                                                        <div class="sm-set-row">
                                                            <span class="sm-set-label">"Handle"</span>
                                                            <span class="sm-set-value">{me}</span>
                                                        </div>
                                                        <div class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Anzeigename"
                                                                <small>
                                                                    "Getrennt vom Handle, jederzeit änderbar (F010); Kontakte adressieren weiter den Handle."
                                                                </small>
                                                            </span>
                                                            <div class="sm-set-inline">
                                                                <input
                                                                    type="text"
                                                                    class="sm-set-input"
                                                                    aria-label="Anzeigename"
                                                                    placeholder="Anzeigename"
                                                                    maxlength="64"
                                                                    prop:value=name_input
                                                                    on:input=move |ev| {
                                                                        set_name_input.set(event_target_value(&ev))
                                                                    }
                                                                />
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_rename
                                                                    disabled=busy
                                                                >
                                                                    "Speichern"
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div class="sm-set-row sm-set-stack">
                                                            <span class="sm-set-label">
                                                                "Passwort ändern"
                                                                <small>"Das neue Passwort verschlüsselt auch die lokale Ablage neu; andere Geräte werden abgemeldet."</small>
                                                            </span>
                                                            <div class="sm-set-form">
                                                                <input
                                                                    type="password"
                                                                    class="sm-set-input"
                                                                    aria-label="Aktuelles Passwort"
                                                                    placeholder="Aktuelles Passwort"
                                                                    prop:value=pw_current
                                                                    on:input=move |ev| {
                                                                        set_pw_current.set(event_target_value(&ev))
                                                                    }
                                                                />
                                                                <input
                                                                    type="password"
                                                                    class="sm-set-input"
                                                                    aria-label="Neues Passwort (12 bis 128 Zeichen)"
                                                                    placeholder="Neues Passwort (12-128)"
                                                                    maxlength="128"
                                                                    prop:value=pw_new
                                                                    on:input=move |ev| {
                                                                        set_pw_new.set(event_target_value(&ev))
                                                                    }
                                                                />
                                                                <input
                                                                    type="password"
                                                                    class="sm-set-input"
                                                                    aria-label="Neues Passwort wiederholen"
                                                                    placeholder="Wiederholen"
                                                                    maxlength="128"
                                                                    prop:value=pw_confirm
                                                                    on:input=move |ev| {
                                                                        set_pw_confirm.set(event_target_value(&ev))
                                                                    }
                                                                />
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_change_password
                                                                    disabled=busy
                                                                >
                                                                    "Passwort ändern"
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div class="sm-set-row sm-set-stack">
                                                            <span class="sm-set-label">
                                                                "Sicherung erstellen"
                                                                <small>"Lädt Gerät, Sitzungen und Verlauf verschlüsselt als Datei herunter. Getrennt vom Gerät aufbewahren; nach dem Leeren des Browser-Speichers damit wiederherstellbar."</small>
                                                            </span>
                                                            <div class="sm-set-form">
                                                                <input
                                                                    type="password"
                                                                    class="sm-set-input"
                                                                    aria-label="Sicherungs-Passwort (mindestens 12 Zeichen)"
                                                                    placeholder="Sicherungs-Passwort (min. 12)"
                                                                    prop:value=backup_export_pw
                                                                    on:input=move |ev| {
                                                                        set_backup_export_pw.set(event_target_value(&ev))
                                                                    }
                                                                />
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_backup_export
                                                                    disabled=busy
                                                                >
                                                                    "Sicherung herunterladen"
                                                                </button>
                                                            </div>
                                                        </div>
                                                        {move || {
                                                            match deletion_pending.get() {
                                                                // Läuft eine Löschung: Frist zeigen und
                                                                // das Widerrufen anbieten.
                                                                Some(until) => {
                                                                    view! {
                                                                        <div class="sm-set-row" role="alert">
                                                                            <span class="sm-set-label sm-set-danger">
                                                                                "Konto wird gelöscht"
                                                                                <small>
                                                                                    "Vorgemerkt bis "
                                                                                    {format_date(until)}
                                                                                    ". Bis dahin kann die Löschung widerrufen werden; danach werden Konto und Schlüssel entfernt."
                                                                                </small>
                                                                            </span>
                                                                            <button
                                                                                type="button"
                                                                                class="sm-secondary"
                                                                                on:click=on_undelete
                                                                                disabled=busy
                                                                            >
                                                                                "Löschung widerrufen"
                                                                            </button>
                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                }
                                                                // Aktiv: Löschen mit Passwort-Bestätigung
                                                                // (zerstörend, deshalb bewusster Schritt).
                                                                None => {
                                                                    view! {
                                                                        <div class="sm-set-row">
                                                                            <span class="sm-set-label sm-set-danger">
                                                                                "Konto löschen"
                                                                                <small>
                                                                                    "Merkt die Löschung mit Widerrufsfrist vor (NF030); danach werden Konto, Geräte und Schlüssel entfernt. Zum Bestätigen das Passwort eingeben."
                                                                                </small>
                                                                            </span>
                                                                            <div class="sm-set-inline">
                                                                                <input
                                                                                    type="password"
                                                                                    class="sm-set-input"
                                                                                    aria-label="Passwort zum Löschen bestätigen"
                                                                                    placeholder="Passwort"
                                                                                    prop:value=delete_pw
                                                                                    on:input=move |ev| {
                                                                                        set_delete_pw.set(event_target_value(&ev))
                                                                                    }
                                                                                />
                                                                                <button
                                                                                    type="button"
                                                                                    class="sm-danger-btn"
                                                                                    on:click=on_delete_account
                                                                                    disabled=busy
                                                                                >
                                                                                    "Konto löschen"
                                                                                </button>
                                                                            </div>
                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                }
                                                            }
                                                        }}
                                                    </section>

                                                    <section class="sm-set-group" aria-label="Sicherheit">
                                                        <h3>"Sicherheit"</h3>
                                                        <label class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Versiegelt senden als Vorgabe"
                                                                <small>
                                                                    "Neue Chats starten mit gesetztem Sealed-Haken; je Nachricht bleibt er im Composer umschaltbar."
                                                                </small>
                                                            </span>
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=sealed_default
                                                                on:change=on_sealed_default_toggle.clone()
                                                            />
                                                        </label>
                                                        <label class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Benachrichtigungen (Web-Push)"
                                                                <small>
                                                                    "Weckt dieses Gerät bei einer neuen Nachricht, auch wenn der Browser geschlossen ist. Braucht die Benachrichtigungs-Erlaubnis; der Push trägt keinen Inhalt, nur einen Hinweis."
                                                                </small>
                                                            </span>
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=push_on
                                                                on:change=on_push_toggle.clone()
                                                                disabled=busy
                                                            />
                                                        </label>
                                                        <label class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Live-Tippen im Anruf"
                                                                <small>
                                                                    "Während eines Anrufs sieht der Gesprächspartner deinen Entwurf in Echtzeit entstehen (über den verschlüsselten Datenkanal des Anrufs, nicht über den Server)."
                                                                </small>
                                                            </span>
                                                            <input
                                                                type="checkbox"
                                                                prop:checked=live_typing
                                                                on:change=on_live_typing_toggle.clone()
                                                            />
                                                        </label>
                                                        <div class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Key-Transparency-Selbstprüfung"
                                                                <small>
                                                                    "Rechnet das eigene Commitment nach und prüft den Beweis gegen die signierte Wurzel."
                                                                </small>
                                                            </span>
                                                            <button
                                                                type="button"
                                                                class="sm-secondary"
                                                                on:click=on_kt_check.clone()
                                                                disabled=busy
                                                            >
                                                                "Jetzt prüfen"
                                                            </button>
                                                        </div>
                                                        {move || {
                                                            kt_info
                                                                .get()
                                                                .map(|(ok, message)| {
                                                                    if ok {
                                                                        view! {
                                                                            <p class="sm-note sm-ok">{message}</p>
                                                                        }
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
                                                        <div class="sm-set-row sm-set-stack">
                                                            <span class="sm-set-label">
                                                                "Konto-Wurzelschlüssel rotieren"
                                                                <small>"Ersetzt den Wurzelschlüssel und signiert alle Geräte-Credentials neu; der alte Schlüssel belegt die Kontinuität (ADR-0010). Nur auf einem Erstgerät mit hinterlegtem Wurzel-Seed möglich. Kontakte sehen danach einen Schlüsselwechsel und sollten die Sicherheitsnummer neu abgleichen."</small>
                                                            </span>
                                                            <div class="sm-set-form">
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_rotate_key
                                                                    disabled=busy
                                                                >
                                                                    "Wurzelschlüssel rotieren"
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </section>

                                                    <section class="sm-set-group" aria-label="Geräte">
                                                        <h3>"Geräte"</h3>
                                                        <ul class="sm-device-list">
                                                            {move || {
                                                                let on_revoke = on_revoke.clone();
                                                                device_rows
                                                                    .get()
                                                                    .into_iter()
                                                                    .map(|d| {
                                                                        let revoke = on_revoke.clone();
                                                                        let id = d.id.clone();
                                                                        view! {
                                                                            <li class="sm-device">
                                                                                <span class="sm-device-num">
                                                                                    {format!("Nr. {}", d.protocol_device_id)}
                                                                                </span>
                                                                                <span class="sm-device-name">
                                                                                    {d.name.clone()}
                                                                                </span>
                                                                                {if d.is_own {
                                                                                    view! {
                                                                                        <span class="sm-device-own">
                                                                                            "dieses Gerät"
                                                                                        </span>
                                                                                    }
                                                                                        .into_any()
                                                                                } else {
                                                                                    view! {
                                                                                        <button
                                                                                            type="button"
                                                                                            class="sm-device-revoke"
                                                                                            on:click=move |_| revoke(id.clone())
                                                                                            disabled=busy
                                                                                        >
                                                                                            "Entfernen"
                                                                                        </button>
                                                                                    }
                                                                                        .into_any()
                                                                                }}
                                                                            </li>
                                                                        }
                                                                    })
                                                                    .collect_view()
                                                            }}
                                                        </ul>
                                                        <label class="sm-field sm-link-field">
                                                            <span>
                                                                "Neues Gerät koppeln: Kopplungs-Code (vom QR) "
                                                                "oder Antrag als Text einfügen"
                                                            </span>
                                                            <textarea
                                                                class="sm-composer-input"
                                                                rows="2"
                                                                prop:value=link_input
                                                                on:input=move |ev| {
                                                                    set_link_input.set(event_target_value(&ev))
                                                                }
                                                            ></textarea>
                                                        </label>
                                                        <button
                                                            type="button"
                                                            class="sm-secondary"
                                                            on:click=on_approve.clone()
                                                            disabled=busy
                                                        >
                                                            "Freischalten"
                                                        </button>
                                                        <div class="sm-set-row">
                                                            <span class="sm-set-label">
                                                                "Verlauf an neue Geräte senden"
                                                                <small>
                                                                    "Schickt den gespeicherten Chat-Verlauf an frisch "
                                                                    "gekoppelte eigene Geräte (sobald sie bereit sind). "
                                                                    "Ein Gerät erhält ihn nur einmal."
                                                                </small>
                                                            </span>
                                                            <button
                                                                type="button"
                                                                class="sm-secondary"
                                                                on:click=on_push_history.clone()
                                                                disabled=busy
                                                            >
                                                                "Verlauf senden"
                                                            </button>
                                                        </div>
                                                    </section>

                                                    <section class="sm-set-group" aria-label="Blockierte Kontakte">
                                                        <h3>"Blockierte Kontakte"</h3>
                                                        {move || {
                                                            let on_unblock = on_unblock.clone();
                                                            match block_list.get() {
                                                                None => {
                                                                    view! { <p class="sm-set-empty">"Wird geladen ..."</p> }
                                                                        .into_any()
                                                                }
                                                                Some(list) if list.is_empty() => {
                                                                    view! {
                                                                        <p class="sm-set-empty">
                                                                            "Niemand blockiert. Blockieren sitzt im jeweiligen Chat-Kopf; hier steht die Gesamtliste."
                                                                        </p>
                                                                    }
                                                                        .into_any()
                                                                }
                                                                Some(list) => {
                                                                    view! {
                                                                        <ul class="sm-block-list">
                                                                            {list
                                                                                .into_iter()
                                                                                .map(|handle| {
                                                                                    let unblock = on_unblock.clone();
                                                                                    let h = handle.clone();
                                                                                    view! {
                                                                                        <li class="sm-set-row">
                                                                                            <span class="sm-set-label">{handle}</span>
                                                                                            <button
                                                                                                type="button"
                                                                                                class="sm-secondary"
                                                                                                on:click=move |_| unblock(h.clone())
                                                                                                disabled=busy
                                                                                            >
                                                                                                "Blockierung aufheben"
                                                                                            </button>
                                                                                        </li>
                                                                                    }
                                                                                })
                                                                                .collect_view()}
                                                                        </ul>
                                                                    }
                                                                        .into_any()
                                                                }
                                                            }
                                                        }}
                                                    </section>

                                                    <section class="sm-set-group" aria-label="Benachrichtigungen">
                                                        <h3>"Benachrichtigungen"</h3>
                                                        <div class="sm-set-row sm-set-plan">
                                                            <span class="sm-set-label">
                                                                "Push auf Mobilgeräte"
                                                                <small>"F200; braucht echte APNs/FCM-Konten und das Push-Gateway."</small>
                                                            </span>
                                                            <span class="sm-set-badge sm-set-extern">"extern"</span>
                                                        </div>
                                                    </section>
                                                </div>
                                            }
                                            .into_any();
                                        }
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
                                            // Gruppen-Chats: Anzeigename statt
                                            // grp:-Schlüssel; Sicherheitsnummer,
                                            // Schlüsselprüfung und Blockieren
                                            // sind 1:1-Mechanik (je Kontakt) und
                                            // fehlen deshalb im Gruppen-Kopf.
                                            let is_group = group_id_of(&peer).is_some();
                                            // Name und Mitgliederliste hängen
                                            // reaktiv am Label-Signal, damit ein
                                            // Entfernen sofort sichtbar wird und
                                            // nicht erst beim Chat-Wechsel.
                                            let name_peer = peer.clone();
                                            let members_peer = peer.clone();
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
                                                    <div class="sm-chat-title">
                                                        <h2
                                                            class="sm-chat-name"
                                                            tabindex="-1"
                                                            node_ref=chat_name_ref
                                                        >
                                                            {move || {
                                                                group_labels
                                                                    .get()
                                                                    .get(&name_peer)
                                                                    .map(|ui| ui.label.clone())
                                                                    .or_else(|| {
                                                                        contact_names.get().get(&name_peer).cloned()
                                                                    })
                                                                    .unwrap_or_else(|| name_peer.clone())
                                                            }}
                                                        </h2>
                                                        {
                                                            // Bei 1:1-Kontakten mit Anzeigenamen den
                                                            // Handle klein darunter, damit die
                                                            // kryptografische Identität sichtbar bleibt
                                                            // (gegen Namens-Täuschung).
                                                            let handle_peer = peer.clone();
                                                            move || {
                                                                let p = handle_peer.clone();
                                                                (group_id_of(&p).is_none()
                                                                    && contact_names.get().contains_key(&p))
                                                                    .then(|| {
                                                                        view! {
                                                                            <span class="sm-chat-handle">{p.clone()}</span>
                                                                        }
                                                                    })
                                                            }
                                                        }
                                                    </div>
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
                                                    {(!is_group)
                                                        .then(|| {
                                                            let on_safety = on_safety.clone();
                                                            let on_key_check = on_key_check.clone();
                                                            let on_call_start = on_call_start.clone();
                                                            let call_peer = peer.clone();
                                                            view! {
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    title="Verschlüsselten Sprachanruf starten"
                                                                    on:click=move |_| on_call_start(call_peer.clone())
                                                                    disabled=busy
                                                                >
                                                                    "Anrufen"
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_safety
                                                                    disabled=busy
                                                                >
                                                                    "Sicherheitsnummer"
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=on_key_check
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
                                                            }
                                                        })}
                                                    {move || {
                                                        // Mitglieder-Liste und Verlassen
                                                        // nur bei einer AKTIVEN Gruppe; ist
                                                        // sie vergessen (entfernt/verlassen),
                                                        // bleibt nur der lesbare Verlauf.
                                                        let forgotten = group_labels
                                                            .get()
                                                            .get(&members_peer)
                                                            .is_some_and(|ui| ui.forgotten);
                                                        let show = is_group && !forgotten;
                                                        // Der innere `move`-Verlauf zieht members_peer
                                                        // in sich hinein; ohne Klon würde die äußere
                                                        // reaktive Closure dadurch zu FnOnce.
                                                        let members_peer = members_peer.clone();
                                                        let remove = on_group_remove.clone();
                                                        let leave = on_group_leave.clone();
                                                        // Diese drei Handler fangen nur Copy-Signale und sind
                                                        // selbst Copy; kein clone nötig.
                                                        let set_role = on_group_role;
                                                        let transfer = on_group_transfer;
                                                        let announce = on_group_announce;
                                                        show.then(move || {
                                                            view! {
                                                                <details class="sm-group-members">
                                                                    <summary>"Mitglieder & Rollen"</summary>
                                                                    <ul>
                                                                        {move || {
                                                                            let own_now = me.get_untracked();
                                                                            let meta = group_meta.get();
                                                                            // Rollen aus der Verwaltungssicht; solange sie
                                                                            // noch lädt, die Handles aus dem Label-Signal
                                                                            // (ohne Rolle, ohne Aktionen).
                                                                            let members = match &meta {
                                                                                Some(m) => m.members.clone(),
                                                                                None => group_labels
                                                                                    .get()
                                                                                    .get(&members_peer)
                                                                                    .map(|ui| {
                                                                                        ui.members
                                                                                            .iter()
                                                                                            .map(|h| GroupMemberInfo {
                                                                                                handle: h.clone(),
                                                                                                role: GroupRole::Member,
                                                                                            })
                                                                                            .collect()
                                                                                    })
                                                                                    .unwrap_or_default(),
                                                                            };
                                                                            let own_role = members
                                                                                .iter()
                                                                                .find(|m| m.handle == own_now)
                                                                                .map(|m| m.role);
                                                                            let remove = remove.clone();
                                                                            members
                                                                                .into_iter()
                                                                                .map(|m| {
                                                                                    let is_self = m.handle == own_now;
                                                                                    let remove = remove.clone();
                                                                                    let t_role = m.role;
                                                                                    let can_remove = !is_self
                                                                                        && t_role != GroupRole::Owner
                                                                                        && matches!(own_role, Some(GroupRole::Owner))
                                                                                            || (!is_self
                                                                                                && t_role == GroupRole::Member
                                                                                                && matches!(own_role, Some(GroupRole::Admin)));
                                                                                    let owner_acts = !is_self
                                                                                        && matches!(own_role, Some(GroupRole::Owner))
                                                                                        && t_role != GroupRole::Owner;
                                                                                    let h_rm = m.handle.clone();
                                                                                    let h_pr = m.handle.clone();
                                                                                    let h_dm = m.handle.clone();
                                                                                    let h_tr = m.handle.clone();
                                                                                    view! {
                                                                                        <li>
                                                                                            <span>
                                                                                                {m.handle.clone()}
                                                                                                " · "
                                                                                                <small>{t_role.label()}</small>
                                                                                            </span>
                                                                                            {(owner_acts && t_role == GroupRole::Member)
                                                                                                .then(|| {
                                                                                                    view! {
                                                                                                        <button type="button" class="sm-secondary" disabled=busy
                                                                                                            on:click=move |_| (set_role)((h_pr.clone(), GroupRole::Admin))>
                                                                                                            "Zu Admin"
                                                                                                        </button>
                                                                                                    }
                                                                                                })}
                                                                                            {(owner_acts && t_role == GroupRole::Admin)
                                                                                                .then(|| {
                                                                                                    view! {
                                                                                                        <button type="button" class="sm-secondary" disabled=busy
                                                                                                            on:click=move |_| (set_role)((h_dm.clone(), GroupRole::Member))>
                                                                                                            "Zu Mitglied"
                                                                                                        </button>
                                                                                                    }
                                                                                                })}
                                                                                            {(owner_acts)
                                                                                                .then(|| {
                                                                                                    view! {
                                                                                                        <button type="button" class="sm-secondary" disabled=busy
                                                                                                            on:click=move |_| (transfer)(h_tr.clone())>
                                                                                                            "Besitz übergeben"
                                                                                                        </button>
                                                                                                    }
                                                                                                })}
                                                                                            {(can_remove)
                                                                                                .then(|| {
                                                                                                    let remove = remove.clone();
                                                                                                    view! {
                                                                                                        <button type="button" class="sm-secondary" disabled=busy
                                                                                                            on:click=move |_| (remove)(h_rm.clone())>
                                                                                                            "Entfernen"
                                                                                                        </button>
                                                                                                    }
                                                                                                })}
                                                                                        </li>
                                                                                    }
                                                                                })
                                                                                .collect_view()
                                                                        }}
                                                                    </ul>
                                                                    {move || {
                                                                        // Announcement-Umschalter nur fuer Staff.
                                                                        let meta = group_meta.get();
                                                                        let own_now = me.get_untracked();
                                                                        let staff = meta
                                                                            .as_ref()
                                                                            .and_then(|m| m.members.iter().find(|x| x.handle == own_now))
                                                                            .map(|m| matches!(m.role, GroupRole::Owner | GroupRole::Admin))
                                                                            .unwrap_or(false);
                                                                        let announcement = meta.as_ref().map(|m| m.settings.announcement).unwrap_or(false);
                                                                        staff.then(move || {
                                                                            view! {
                                                                                <label class="sm-set-row">
                                                                                    <span class="sm-set-label">"Nur Admins dürfen senden"</span>
                                                                                    <input type="checkbox" prop:checked=announcement disabled=busy
                                                                                        on:change=move |ev| (announce)(event_target_checked(&ev)) />
                                                                                </label>
                                                                            }
                                                                        })
                                                                    }}
                                                                </details>
                                                                <button
                                                                    type="button"
                                                                    class="sm-secondary"
                                                                    on:click=leave
                                                                    disabled=busy
                                                                >
                                                                    "Verlassen"
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
                                                        let run_delete_all = run_delete_all.clone();
                                                        let on_delete_local = on_delete_local.clone();
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
                                                                let run_report = run_report.clone();
                                                                let run_delete_all = run_delete_all.clone();
                                                                let on_delete_local = on_delete_local.clone();
                                                                msgs.into_iter()
                                                                    .map(|line| {
                                                                        let mine = line.from == own;
                                                                        let class = if mine {
                                                                            "sm-msg sm-mine"
                                                                        } else {
                                                                            "sm-msg"
                                                                        };
                                                                        // Melden nur für EMPFANGENE Nachrichten
                                                                        // mit abgelegtem Franking-Material. Auch
                                                                        // eine bei allen gelöschte Zeile bleibt
                                                                        // meldbar (der letzte gezeigte Inhalt),
                                                                        // damit ein Absender Missbrauch nicht
                                                                        // durch Nachträgliches Löschen tilgt.
                                                                        let report_id = if mine {
                                                                            None
                                                                        } else {
                                                                            line.report_id.clone()
                                                                        };
                                                                        let report_click = run_report.clone();
                                                                        // Bearbeiten nur für eigene, nicht
                                                                        // gelöschte Zeilen mit ID, binnen 24
                                                                        // Stunden (danach ist die Korrektur-
                                                                        // Erwartung vorbei; empfangene Edits
                                                                        // werden trotzdem angewandt). Löschen
                                                                        // bei allen ohne Frist.
                                                                        let editable = mine
                                                                            && !line.deleted
                                                                            && !line.id.is_empty()
                                                                            && now_unix() < line.at.saturating_add(86_400);
                                                                        let deletable =
                                                                            mine && !line.deleted && !line.id.is_empty();
                                                                        let edit_id = line.id.clone();
                                                                        let edit_text = line.text.clone();
                                                                        let del_all_id = line.id.clone();
                                                                        let del_all = run_delete_all.clone();
                                                                        let del_local_id = line.id.clone();
                                                                        let del_local = on_delete_local.clone();
                                                                        view! {
                                                                            <li class=class>
                                                                                <span class="sm-msg-from">{line.from}</span>
                                                                                {if line.deleted {
                                                                                    view! {
                                                                                        <span class="sm-msg-text sm-msg-deleted">
                                                                                            "(Nachricht gelöscht)"
                                                                                        </span>
                                                                                    }
                                                                                        .into_any()
                                                                                } else {
                                                                                    view! {
                                                                                        <span class="sm-msg-text">{line.text}</span>
                                                                                    }
                                                                                        .into_any()
                                                                                }}
                                                                                <span class="sm-msg-time">
                                                                                    {format_time(line.at)}
                                                                                </span>
                                                                                {(line.edited && !line.deleted)
                                                                                    .then(|| {
                                                                                        view! {
                                                                                            <span
                                                                                                class="sm-msg-edited"
                                                                                                title="Der Absender hat den Text nachträglich geändert"
                                                                                            >
                                                                                                "bearbeitet"
                                                                                            </span>
                                                                                        }
                                                                                    })}
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
                                                                                {editable
                                                                                    .then(|| {
                                                                                        view! {
                                                                                            <button
                                                                                                type="button"
                                                                                                class="sm-msg-action"
                                                                                                title="Text dieser Nachricht bei allen ersetzen (bis 24 Stunden nach dem Senden)"
                                                                                                on:click=move |_| on_edit_start((
                                                                                                    edit_id.clone(),
                                                                                                    edit_text.clone(),
                                                                                                ))
                                                                                                disabled=busy
                                                                                            >
                                                                                                "Bearbeiten"
                                                                                            </button>
                                                                                        }
                                                                                    })}
                                                                                {deletable
                                                                                    .then(|| {
                                                                                        view! {
                                                                                            <button
                                                                                                type="button"
                                                                                                class="sm-msg-action"
                                                                                                title="Bei allen löschen: die Nachricht wird überall zum Grabstein"
                                                                                                on:click=move |_| del_all(
                                                                                                    del_all_id.clone(),
                                                                                                )
                                                                                                disabled=busy
                                                                                            >
                                                                                                "Löschen"
                                                                                            </button>
                                                                                        }
                                                                                    })}
                                                                                {(!line.id.is_empty())
                                                                                    .then(|| {
                                                                                        view! {
                                                                                            <button
                                                                                                type="button"
                                                                                                class="sm-msg-action"
                                                                                                title="Nur aus dem eigenen Verlauf entfernen; bei anderen bleibt sie"
                                                                                                on:click=move |_| del_local(
                                                                                                    del_local_id.clone(),
                                                                                                )
                                                                                                disabled=busy
                                                                                            >
                                                                                                "Für mich"
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

                                                {move || {
                                                    editing
                                                        .get()
                                                        .map(|_| {
                                                            view! {
                                                                <div class="sm-edit-banner">
                                                                    <span>
                                                                        "Bearbeiten: der gesendete Text wird bei allen ersetzt."
                                                                    </span>
                                                                    <button
                                                                        type="button"
                                                                        class="sm-msg-action"
                                                                        on:click=on_edit_cancel
                                                                    >
                                                                        "Abbrechen"
                                                                    </button>
                                                                </div>
                                                            }
                                                        })
                                                }}

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
                                                    {(!is_group)
                                                        .then(|| {
                                                            view! {
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
                                                            }
                                                        })}
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
                                            {import_card()}
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
                                                    <label for="sm-regname">
                                                        "Anzeigename (optional, z. B. Vor- und Nachname)"
                                                    </label>
                                                    <input
                                                        id="sm-regname"
                                                        prop:value=reg_name_input
                                                        on:input=move |ev| {
                                                            set_reg_name_input.set(event_target_value(&ev))
                                                        }
                                                    />
                                                </div>
                                                <div class="sm-field">
                                                    <label for="sm-newpass">
                                                        "Passwort (12 bis 128 Zeichen, alle Zeichen erlaubt)"
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
                                            <section class="sm-card" aria-label="Gerät koppeln">
                                                <h2>"Bestehendes Konto: dieses Gerät koppeln"</h2>
                                                <p class="sm-status">
                                                    "Für ein Konto, das schon auf einem anderen Gerät "
                                                    "liegt: oben das Handle eingeben und koppeln. Dieser "
                                                    "Browser wird ein Zweitgerät (empfängt und sendet, "
                                                    "schaltet aber keine weiteren Geräte frei)."
                                                </p>
                                                <div class="sm-row">
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=on_link_start.clone()
                                                        disabled=busy
                                                    >
                                                        "Kopplung starten"
                                                    </button>
                                                </div>
                                            </section>
                                            {import_card()}
                                        }
                                            .into_any()
                                    }
                                    Boot::Linking { payload, secret } => {
                                        // Der QR-Code trägt das Kopplungs-Geheimnis;
                                        // das Erstgerät scannt ihn (oder tippt den Code)
                                        // und holt den Antrag verschlüsselt vom Relay.
                                        let qr = secret.as_deref().and_then(qr_svg);
                                        view! {
                                            <section class="sm-card" aria-label="Gerät koppeln">
                                                <h2>"Gerät koppeln: freischalten und abschließen"</h2>
                                                <p class="sm-status">
                                                    "Auf dem Erstgerät freischalten: den QR-Code scannen "
                                                    "oder den Kopplungs-Code eingeben (Einstellungen, "
                                                    "Geräte). Danach hier das Passwort eingeben und "
                                                    "abschließen."
                                                </p>
                                                {qr
                                                    .map(|svg| {
                                                        view! {
                                                            <div
                                                                class="sm-qr"
                                                                role="group"
                                                                aria-label="QR-Code zum Koppeln"
                                                                inner_html=svg
                                                            ></div>
                                                        }
                                                    })}
                                                {secret
                                                    .map(|code| {
                                                        view! {
                                                            <label class="sm-field">
                                                                <span>"Kopplungs-Code (falls Scannen nicht geht)"</span>
                                                                <input class="sm-code" readonly prop:value=code />
                                                            </label>
                                                        }
                                                    })}
                                                <details class="sm-link-manual">
                                                    <summary>"Antrag als Text (manueller Weg)"</summary>
                                                    <label class="sm-field">
                                                        <span>"Diesen Antrag auf dem Erstgerät einfügen"</span>
                                                        <textarea
                                                            class="sm-composer-input"
                                                            rows="3"
                                                            readonly
                                                        >
                                                            {payload}
                                                        </textarea>
                                                    </label>
                                                </details>
                                                <div class="sm-field">
                                                    <label for="sm-linkpass">"Passwort des Kontos"</label>
                                                    <input
                                                        id="sm-linkpass"
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
                                                        on:click=on_link_finish.clone()
                                                        disabled=busy
                                                    >
                                                        "Kopplung abschließen"
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="sm-secondary"
                                                        on:click=on_link_cancel.clone()
                                                        disabled=busy
                                                    >
                                                        "Abbrechen"
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
