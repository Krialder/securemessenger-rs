//! 1:1-Audio-Anruf im Browser (F2, WebRTC).
//!
//! Der Medienstrom (Ton) läuft Peer-zu-Peer über RTCPeerConnection, bei Bedarf
//! über einen TURN-Relay (coturn); der Dienst vermittelt NUR die
//! Signalisierung (SDP-Offer/-Answer, ICE-Kandidaten), und die reist
//! Ende-zu-Ende verschlüsselt durch den 1:1-Nachrichtenkanal
//! (`client_app::call::Signal`). Der Server sieht weder Ton noch SDP.
//!
//! Zusätzlich trägt jeder Anruf einen Datenkanal (`sm-data`); Paket E schickt
//! darüber die Tipp-Anzeige, ohne dass ein Tastenanschlag über den Server
//! läuft.
//!
//! Dieses Modul kapselt eine laufende Verbindung als [`CallSession`]. Die
//! ausgehende Signalisierung reicht es über einen Callback zurück (der
//! Aufrufer verschlüsselt und sendet sie); eingehende Signale gibt der
//! Aufrufer per [`CallSession::on_signal`] hinein. Reine Browser-Mechanik,
//! die Kryptografie liegt im 1:1-Kanal.
//!
//! Laufzeit-Beweis (echtes getUserMedia, ICE, TURN) gehört auf ein
//! HTTPS-Deployment mit coturn (Proxmox); hier ist der Code kompiliert, aber
//! nicht im Browser gefahren.

use std::cell::RefCell;
use std::rc::Rc;

use client_app::call::Signal;
use client_app::delivery::TurnCredentials;
use js_sys::{Array, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    HtmlAudioElement, MediaStream, MediaStreamConstraints, MessageEvent, RtcConfiguration,
    RtcDataChannel, RtcDataChannelEvent, RtcIceCandidate, RtcIceCandidateInit, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit, RtcTrackEvent,
};

/// Callback, über den ein ausgehendes Signal (Offer/Answer/ICE/Hangup) den
/// Aufrufer erreicht; der verschlüsselt es und sendet es an den Peer.
pub type SignalSink = Rc<dyn Fn(Signal)>;

/// Am Leben zu haltende Event-Closure (Browser-Callback).
type EventClosure = Closure<dyn FnMut(JsValue)>;

/// Empfangs-Callback für Datenkanal-Text (Paket E).
type DataHandler = Rc<dyn Fn(String)>;

/// Eine laufende Anruf-Verbindung. Hält die RTCPeerConnection, den lokalen
/// Mikrofonstrom, den Datenkanal und die am Leben zu haltenden Callbacks.
pub struct CallSession {
    pc: RtcPeerConnection,
    /// Vom Anrufer vergebene Kennung; reist in jedem ausgehenden Signal mit,
    /// damit die Gegenseite es dem richtigen Anruf zuordnet.
    call_id: String,
    local_stream: RefCell<Option<MediaStream>>,
    data_channel: RefCell<Option<RtcDataChannel>>,
    audio: HtmlAudioElement,
    sink: SignalSink,
    /// Am Leben zu haltende Event-Closures (sonst räumt sie Rust weg und der
    /// Browser ruft ins Leere).
    closures: RefCell<Vec<EventClosure>>,
    /// Callback fürs Empfangen einer Datenkanal-Nachricht (Paket E); gesetzt
    /// vom Aufrufer.
    on_data: RefCell<Option<DataHandler>>,
    /// Callback, wenn die Verbindung endgültig scheitert oder schließt (ICE
    /// failed/disconnected/closed), damit die Oberfläche nicht in „Verbunden"
    /// hängen bleibt, wenn der Peer ohne Auflegen verschwindet.
    on_closed: RefCell<Option<Rc<dyn Fn()>>>,
    /// Ob die Gegenbeschreibung (Offer/Answer des Peers) schon gesetzt ist.
    /// ICE-Kandidaten vor diesem Zeitpunkt lehnt der Browser ab, deshalb
    /// werden sie bis dahin gepuffert.
    remote_set: std::cell::Cell<bool>,
    pending_ice: RefCell<Vec<String>>,
}

impl CallSession {
    /// Baut eine RTCPeerConnection mit den ICE-Servern aus den
    /// TURN-Zugangsdaten und richtet die ICE-Weiterleitung ein.
    pub fn new(
        call_id: &str,
        creds: &TurnCredentials,
        sink: SignalSink,
    ) -> Result<Rc<Self>, String> {
        let config = ice_configuration(creds)?;
        let pc = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|e| format!("RTCPeerConnection: {}", err_str(&e)))?;
        let audio: HtmlAudioElement =
            HtmlAudioElement::new().map_err(|e| format!("Audio-Element: {}", err_str(&e)))?;
        audio.set_autoplay(true);

        let session = Rc::new(CallSession {
            pc,
            call_id: call_id.to_string(),
            local_stream: RefCell::new(None),
            data_channel: RefCell::new(None),
            audio,
            sink,
            closures: RefCell::new(Vec::new()),
            on_data: RefCell::new(None),
            on_closed: RefCell::new(None),
            remote_set: std::cell::Cell::new(false),
            pending_ice: RefCell::new(Vec::new()),
        });
        session.wire_ice();
        session.wire_track();
        session.wire_connection_state();
        Ok(session)
    }

    /// Setzt den Callback für einen endgültig gescheiterten/geschlossenen
    /// Anruf (die Oberfläche geht dann auf Idle).
    pub fn set_on_closed(&self, on_closed: Rc<dyn Fn()>) {
        *self.on_closed.borrow_mut() = Some(on_closed);
    }

    /// Setzt den Empfangs-Callback für Datenkanal-Nachrichten. Genutzt von
    /// Paket E (Live-Tippen); der Datenkanal selbst wird schon hier verdrahtet.
    #[allow(dead_code)]
    pub fn set_on_data(&self, on_data: Rc<dyn Fn(String)>) {
        *self.on_data.borrow_mut() = Some(on_data);
    }

    /// Schickt Text über den Datenkanal (Paket E: Tipp-Anzeige). Still, wenn
    /// der Kanal noch nicht offen ist.
    #[allow(dead_code)]
    pub fn send_data(&self, text: &str) {
        if let Some(channel) = self.data_channel.borrow().as_ref() {
            if channel.ready_state() == web_sys::RtcDataChannelState::Open {
                let _ = channel.send_with_str(text);
            }
        }
    }

    /// Startet den Anruf als ANRUFER: Mikrofon holen, Datenkanal öffnen,
    /// Offer bilden und über den Sink hinausschicken.
    pub async fn start(self: &Rc<Self>) -> Result<(), String> {
        self.attach_microphone().await?;
        // Der Anrufer öffnet den Datenkanal; der Angerufene bekommt ihn per
        // ondatachannel.
        let channel = self.pc.create_data_channel("sm-data");
        self.wire_data_channel(&channel);
        *self.data_channel.borrow_mut() = Some(channel);

        let offer = JsFuture::from(self.pc.create_offer())
            .await
            .map_err(|e| format!("Offer bilden: {}", err_str(&e)))?;
        let sdp = sdp_of(&offer)?;
        self.set_local_description(RtcSdpType::Offer, &sdp).await?;
        (self.sink)(Signal::Offer {
            call_id: self.call_id.clone(),
            sdp,
        });
        Ok(())
    }

    /// Nimmt einen eingehenden Anruf an: das Offer setzen, Mikrofon holen,
    /// Answer bilden und zurückschicken.
    pub async fn accept(self: &Rc<Self>, offer_sdp: &str) -> Result<(), String> {
        self.wire_incoming_data_channel();
        self.set_remote_description(RtcSdpType::Offer, offer_sdp)
            .await?;
        self.attach_microphone().await?;
        let answer = JsFuture::from(self.pc.create_answer())
            .await
            .map_err(|e| format!("Answer bilden: {}", err_str(&e)))?;
        let sdp = sdp_of(&answer)?;
        self.set_local_description(RtcSdpType::Answer, &sdp).await?;
        (self.sink)(Signal::Answer {
            call_id: self.call_id.clone(),
            sdp,
        });
        Ok(())
    }

    /// Verarbeitet ein eingehendes Signal des Peers (Answer/ICE). Offer und
    /// Hangup behandelt der Aufrufer (annehmen bzw. auflegen).
    pub async fn on_signal(self: &Rc<Self>, signal: Signal) -> Result<(), String> {
        match signal {
            Signal::Answer { sdp, .. } => {
                self.set_remote_description(RtcSdpType::Answer, &sdp).await
            }
            Signal::Ice { candidate, .. } => self.add_ice_candidate(&candidate).await,
            // Offer/Hangup steuert der Aufrufer.
            Signal::Offer { .. } | Signal::Hangup { .. } => Ok(()),
        }
    }

    /// Legt auf: die Verbindung und den Mikrofonstrom schließen und dem Peer
    /// ein Hangup schicken.
    pub fn hangup(&self, reason: &str) {
        (self.sink)(Signal::Hangup {
            call_id: self.call_id.clone(),
            reason: reason.to_string(),
        });
        self.close();
    }

    /// Schließt die Verbindung lokal (ohne Hangup zu senden), etwa wenn der
    /// Peer aufgelegt hat.
    pub fn close(&self) {
        if let Some(stream) = self.local_stream.borrow_mut().take() {
            stop_tracks(&stream);
        }
        if let Some(channel) = self.data_channel.borrow_mut().take() {
            channel.close();
        }
        self.pc.close();
    }

    /// Schaltet das eigene Mikrofon stumm oder wieder frei; liefert den neuen
    /// Stumm-Zustand.
    pub fn toggle_mute(&self) -> bool {
        let mut muted = false;
        if let Some(stream) = self.local_stream.borrow().as_ref() {
            let tracks = stream.get_audio_tracks();
            for i in 0..tracks.length() {
                if let Ok(track) = tracks.get(i).dyn_into::<web_sys::MediaStreamTrack>() {
                    let enabled = !track.enabled();
                    track.set_enabled(enabled);
                    muted = !enabled;
                }
            }
        }
        muted
    }

    // --- interne Bausteine ---

    async fn attach_microphone(self: &Rc<Self>) -> Result<(), String> {
        let media = web_sys::window()
            .and_then(|w| w.navigator().media_devices().ok())
            .ok_or("Kein Zugriff auf Mediengeräte")?;
        let constraints = MediaStreamConstraints::new();
        constraints.set_audio(&JsValue::TRUE);
        constraints.set_video(&JsValue::FALSE);
        let stream = JsFuture::from(
            media
                .get_user_media_with_constraints(&constraints)
                .map_err(|e| format!("Mikrofon: {}", err_str(&e)))?,
        )
        .await
        .map_err(|e| format!("Mikrofon-Zugriff abgelehnt: {}", err_str(&e)))?;
        let stream: MediaStream = stream.dyn_into().map_err(|_| "Kein MediaStream")?;
        // Jede lokale Spur an die Verbindung hängen.
        let tracks = stream.get_audio_tracks();
        for i in 0..tracks.length() {
            if let Ok(track) = tracks.get(i).dyn_into::<web_sys::MediaStreamTrack>() {
                let stream_arr = Array::of1(&stream);
                let _ = self.pc.add_track(&track, &stream, &stream_arr);
            }
        }
        *self.local_stream.borrow_mut() = Some(stream);
        Ok(())
    }

    fn wire_ice(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        let cb = Closure::wrap(Box::new(move |ev: JsValue| {
            let Some(session) = this.upgrade() else {
                return;
            };
            let ev: RtcPeerConnectionIceEvent = ev.unchecked_into();
            if let Some(candidate) = ev.candidate() {
                // Als JSON serialisieren, damit die Empfangsseite ihn wieder
                // als RTCIceCandidateInit aufbauen kann.
                let json = js_sys::JSON::stringify(&candidate.to_json())
                    .ok()
                    .and_then(|s| s.as_string())
                    .unwrap_or_default();
                if !json.is_empty() {
                    (session.sink)(Signal::Ice {
                        call_id: session.call_id.clone(),
                        candidate: json,
                    });
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        self.pc
            .set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
        self.closures.borrow_mut().push(cb);
    }

    fn wire_track(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        let cb = Closure::wrap(Box::new(move |ev: JsValue| {
            let Some(session) = this.upgrade() else {
                return;
            };
            let ev: RtcTrackEvent = ev.unchecked_into();
            let streams = ev.streams();
            if let Ok(stream) = streams.get(0).dyn_into::<MediaStream>() {
                // Den entfernten Ton am (unsichtbaren) Audio-Element abspielen.
                session.audio.set_src_object(Some(&stream));
                let _ = session.audio.play();
            }
        }) as Box<dyn FnMut(JsValue)>);
        self.pc.set_ontrack(Some(cb.as_ref().unchecked_ref()));
        self.closures.borrow_mut().push(cb);
    }

    fn wire_connection_state(self: &Rc<Self>) {
        use web_sys::RtcPeerConnectionState;
        let this = Rc::downgrade(self);
        let cb = Closure::wrap(Box::new(move |_ev: JsValue| {
            let Some(session) = this.upgrade() else {
                return;
            };
            // Nur endgültige Zustände räumen auf. `Disconnected` ist im
            // WebRTC vorübergehend (kurzer Paketverlust, WLAN-Wechsel) und
            // kehrt oft von selbst nach `Connected` zurück; würde man hier
            // schon schließen, risse ein kurzer Aussetzer den Anruf ab.
            match session.pc.connection_state() {
                RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => {
                    if let Some(on_closed) = session.on_closed.borrow().as_ref() {
                        on_closed();
                    }
                }
                _ => {}
            }
        }) as Box<dyn FnMut(JsValue)>);
        self.pc
            .set_onconnectionstatechange(Some(cb.as_ref().unchecked_ref()));
        self.closures.borrow_mut().push(cb);
    }

    fn wire_incoming_data_channel(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        let cb = Closure::wrap(Box::new(move |ev: JsValue| {
            let Some(session) = this.upgrade() else {
                return;
            };
            let ev: RtcDataChannelEvent = ev.unchecked_into();
            let channel = ev.channel();
            session.wire_data_channel(&channel);
            *session.data_channel.borrow_mut() = Some(channel);
        }) as Box<dyn FnMut(JsValue)>);
        self.pc.set_ondatachannel(Some(cb.as_ref().unchecked_ref()));
        self.closures.borrow_mut().push(cb);
    }

    fn wire_data_channel(self: &Rc<Self>, channel: &RtcDataChannel) {
        let this = Rc::downgrade(self);
        let cb = Closure::wrap(Box::new(move |ev: JsValue| {
            let Some(session) = this.upgrade() else {
                return;
            };
            let ev: MessageEvent = ev.unchecked_into();
            if let Some(text) = ev.data().as_string() {
                if let Some(on_data) = session.on_data.borrow().as_ref() {
                    on_data(text);
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        channel.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        self.closures.borrow_mut().push(cb);
    }

    async fn set_local_description(&self, kind: RtcSdpType, sdp: &str) -> Result<(), String> {
        let init = RtcSessionDescriptionInit::new(kind);
        init.set_sdp(sdp);
        JsFuture::from(self.pc.set_local_description(&init))
            .await
            .map_err(|e| format!("set_local_description: {}", err_str(&e)))?;
        Ok(())
    }

    async fn set_remote_description(&self, kind: RtcSdpType, sdp: &str) -> Result<(), String> {
        let init = RtcSessionDescriptionInit::new(kind);
        init.set_sdp(sdp);
        JsFuture::from(self.pc.set_remote_description(&init))
            .await
            .map_err(|e| format!("set_remote_description: {}", err_str(&e)))?;
        // Ab jetzt akzeptiert der Browser ICE-Kandidaten; die bis hierher
        // gepufferten nachreichen.
        self.remote_set.set(true);
        let buffered: Vec<String> = self.pending_ice.borrow_mut().drain(..).collect();
        for candidate in buffered {
            if let Err(error) = self.apply_ice(&candidate).await {
                leptos::logging::warn!("Gepufferter ICE-Kandidat verworfen: {error}");
            }
        }
        Ok(())
    }

    /// Fügt einen ICE-Kandidaten hinzu, sobald die Gegenbeschreibung steht;
    /// vorher wird er gepuffert (der Browser lehnt ihn sonst ab).
    async fn add_ice_candidate(&self, candidate_json: &str) -> Result<(), String> {
        if !self.remote_set.get() {
            self.pending_ice
                .borrow_mut()
                .push(candidate_json.to_string());
            return Ok(());
        }
        self.apply_ice(candidate_json).await
    }

    async fn apply_ice(&self, candidate_json: &str) -> Result<(), String> {
        let parsed = js_sys::JSON::parse(candidate_json)
            .map_err(|e| format!("ICE-Kandidat unlesbar: {}", err_str(&e)))?;
        let candidate = Reflect::get(&parsed, &JsValue::from_str("candidate"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        let init = RtcIceCandidateInit::new(&candidate);
        if let Some(mid) = Reflect::get(&parsed, &JsValue::from_str("sdpMid"))
            .ok()
            .and_then(|v| v.as_string())
        {
            init.set_sdp_mid(Some(&mid));
        }
        if let Some(index) = Reflect::get(&parsed, &JsValue::from_str("sdpMLineIndex"))
            .ok()
            .and_then(|v| v.as_f64())
        {
            init.set_sdp_m_line_index(Some(index as u16));
        }
        let candidate =
            RtcIceCandidate::new(&init).map_err(|e| format!("ICE-Init: {}", err_str(&e)))?;
        JsFuture::from(
            self.pc
                .add_ice_candidate_with_opt_rtc_ice_candidate(Some(&candidate)),
        )
        .await
        .map_err(|e| format!("ICE hinzufügen: {}", err_str(&e)))?;
        Ok(())
    }
}

/// Baut die RTCConfiguration aus den TURN-Zugangsdaten (ein ICE-Server je
/// URL, mit Nutzername/Passwort wo vorhanden).
fn ice_configuration(creds: &TurnCredentials) -> Result<RtcConfiguration, String> {
    let servers = Array::new();
    for url in &creds.urls {
        let server = js_sys::Object::new();
        set(&server, "urls", &JsValue::from_str(url))?;
        if !creds.username.is_empty() {
            set(&server, "username", &JsValue::from_str(&creds.username))?;
            set(&server, "credential", &JsValue::from_str(&creds.credential))?;
        }
        servers.push(&server);
    }
    let config = RtcConfiguration::new();
    config.set_ice_servers(&servers);
    Ok(config)
}

fn set(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), String> {
    Reflect::set(obj, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|e| format!("Objekt-Feld {key}: {}", err_str(&e)))
}

/// Liest das `sdp`-Feld aus einem Offer/Answer-Ergebnis (RTCSessionDescription
/// bzw. -Init).
fn sdp_of(desc: &JsValue) -> Result<String, String> {
    Reflect::get(desc, &JsValue::from_str("sdp"))
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| "SDP fehlt in der Beschreibung".to_string())
}

fn stop_tracks(stream: &MediaStream) {
    let tracks = stream.get_tracks();
    for i in 0..tracks.length() {
        if let Ok(track) = tracks.get(i).dyn_into::<web_sys::MediaStreamTrack>() {
            track.stop();
        }
    }
}

fn err_str(value: &JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}
