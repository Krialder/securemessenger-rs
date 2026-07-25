//! Schreibzugriff auf einen vom Nutzer gewählten Ordner (File System Access
//! API), damit die automatische Sicherung ohne weitere Dialoge schreiben kann.
//!
//! Ein Browser darf nicht von sich aus in das Dateisystem schreiben. Die File
//! System Access API dreht das um: der Nutzer wählt EINMAL einen Ordner, der
//! Browser gibt dafür ein Handle heraus, und dieses Handle lässt sich in
//! IndexedDB ablegen und später wiederverwenden. Danach schreibt die App in
//! genau diesen Ordner, ohne dass wieder ein Dialog aufgeht. Das ist die
//! Voraussetzung für Auslöser wie „nach Zeitabstand": ein Download-Dialog je
//! Intervall wäre unbenutzbar.
//!
//! Die API wird über `wasm-bindgen` direkt angebunden statt über `web-sys`,
//! weil die betreffenden Typen dort hinter instabilen Feature-Flags liegen und
//! sich zwischen Versionen ändern. Die hier gebundenen Methoden sind der
//! stabile, in Chrome und Edge ausgelieferte Teil der Spezifikation.
//!
//! [ANNAHME: Firefox und Safari unterstützen `showDirectoryPicker` nicht. Dort
//! bleibt der bestehende Download-Weg (Knopf „Sicherung herunterladen"), und
//! die automatische Sicherung lässt sich nicht einschalten; `is_supported`
//! sagt das der Oberfläche, damit sie den Schalter mit Begründung sperrt statt
//! ins Leere zu laufen. Ein erneuter Besuch kann die Erlaubnis für das
//! gespeicherte Handle verloren haben (der Browser vergisst sie je nach
//! Einstellung); dann fragt `ensure_permission` einmal nach, ausgelöst durch
//! eine Nutzer-Handlung.]

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
    /// Das Handle eines Ordners bzw. einer Datei (FileSystemHandle und
    /// Unterarten). Als ein Typ gebunden, weil wir nur die drei Methoden
    /// brauchen und die Unterscheidung über den Aufruf schon feststeht.
    #[wasm_bindgen(extends = js_sys::Object)]
    #[derive(Clone, Debug)]
    type FsHandle;

    /// Öffnet den Ordner-Auswahldialog; das Ergebnis ist ein Verzeichnis-Handle.
    /// Nur aus einer Nutzer-Handlung heraus erlaubt (Klick).
    #[wasm_bindgen(catch, js_name = showDirectoryPicker, js_namespace = window)]
    fn show_directory_picker() -> Result<js_sys::Promise, JsValue>;

    /// Legt eine Datei im Verzeichnis an oder öffnet die vorhandene.
    #[wasm_bindgen(catch, method, js_name = getFileHandle)]
    fn get_file_handle(
        this: &FsHandle,
        name: &str,
        options: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;

    /// Öffnet einen Schreib-Strom auf die Datei (überschreibt den Inhalt).
    #[wasm_bindgen(catch, method, js_name = createWritable)]
    fn create_writable(this: &FsHandle) -> Result<js_sys::Promise, JsValue>;

    /// Fragt die aktuelle Erlaubnis ab, ohne zu fragen.
    #[wasm_bindgen(catch, method, js_name = queryPermission)]
    fn query_permission(this: &FsHandle, options: &JsValue) -> Result<js_sys::Promise, JsValue>;

    /// Fragt die Erlaubnis beim Nutzer nach (nur aus einer Nutzer-Handlung).
    #[wasm_bindgen(catch, method, js_name = requestPermission)]
    fn request_permission(this: &FsHandle, options: &JsValue) -> Result<js_sys::Promise, JsValue>;

    /// Der Schreib-Strom (FileSystemWritableFileStream).
    #[wasm_bindgen(extends = js_sys::Object)]
    #[derive(Clone, Debug)]
    type FsWritable;

    #[wasm_bindgen(catch, method, js_name = write)]
    fn write_chunk(this: &FsWritable, data: &JsValue) -> Result<js_sys::Promise, JsValue>;

    #[wasm_bindgen(catch, method, js_name = close)]
    fn close_stream(this: &FsWritable) -> Result<js_sys::Promise, JsValue>;
}

/// Der Dateiname der Sicherung im gewählten Ordner. Fest, damit jede
/// Sicherung dieselbe Datei überschreibt und der Ordner nicht zuwächst.
const BACKUP_FILENAME: &str = "securemessenger-sicherung.smbak";

/// Ob der Browser das Wählen eines Ordners überhaupt anbietet. Ist das nicht
/// so (Firefox, Safari), bleibt nur der Download-Weg.
pub fn is_supported() -> bool {
    web_sys::window()
        .map(|w| {
            js_sys::Reflect::has(&w, &JsValue::from_str("showDirectoryPicker")).unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Ein gewählter Ordner. Das Handle ist strukturiert klonbar, lässt sich also
/// in IndexedDB ablegen und beim nächsten Start wieder herausholen.
#[derive(Clone, Debug)]
pub struct Folder {
    handle: FsHandle,
}

impl Folder {
    /// Lässt den Nutzer einen Ordner wählen. Muss aus einer Nutzer-Handlung
    /// heraus aufgerufen werden (Klick), sonst weist der Browser ab. Bricht
    /// der Nutzer ab, ist das ein Fehler und kein leeres Ergebnis (die API
    /// wirft dann).
    pub async fn pick() -> Result<Folder, String> {
        if !is_supported() {
            return Err(
                "Dieser Browser kann keinen Ordner freigeben (Chrome oder Edge nötig).".to_string(),
            );
        }
        let promise =
            show_directory_picker().map_err(|_| "Ordnerauswahl abgebrochen".to_string())?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|_| "Ordnerauswahl abgebrochen".to_string())?;
        Ok(Folder {
            handle: value.unchecked_into(),
        })
    }

    /// Baut aus einem aus IndexedDB geladenen Handle wieder einen Ordner.
    pub fn from_js(value: JsValue) -> Option<Folder> {
        if value.is_undefined() || value.is_null() {
            return None;
        }
        Some(Folder {
            handle: value.unchecked_into(),
        })
    }

    /// Das rohe Handle zum Ablegen in IndexedDB.
    pub fn as_js(&self) -> JsValue {
        self.handle.clone().into()
    }

    /// Ob die Schreib-Erlaubnis noch steht, ohne den Nutzer zu fragen. Der
    /// Browser kann sie zwischen zwei Besuchen verlieren.
    pub async fn has_permission(&self) -> bool {
        let Ok(options) = write_mode() else {
            return false;
        };
        let Ok(promise) = self.handle.query_permission(&options) else {
            return false;
        };
        matches!(
            JsFuture::from(promise).await.ok().and_then(|v| v.as_string()),
            Some(state) if state == "granted"
        )
    }

    /// Fragt die Schreib-Erlaubnis nach. Nur aus einer Nutzer-Handlung heraus,
    /// sonst weist der Browser ab.
    pub async fn ensure_permission(&self) -> Result<(), String> {
        if self.has_permission().await {
            return Ok(());
        }
        let options = write_mode().map_err(|_| "Erlaubnis-Abfrage fehlgeschlagen".to_string())?;
        let promise = self
            .handle
            .request_permission(&options)
            .map_err(|_| "Erlaubnis-Abfrage fehlgeschlagen".to_string())?;
        let state = JsFuture::from(promise)
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        if state == "granted" {
            Ok(())
        } else {
            Err("Der Ordner ist nicht (mehr) zum Schreiben freigegeben.".to_string())
        }
    }

    /// Schreibt die Sicherung in den Ordner und überschreibt eine vorhandene
    /// Datei. Der Schreib-Strom wird erst beim Schließen wirksam, ein
    /// abgebrochener Vorgang lässt die alte Datei also unangetastet.
    pub async fn write_backup(&self, bytes: &[u8]) -> Result<(), String> {
        let create = js_sys::Object::new();
        js_sys::Reflect::set(&create, &"create".into(), &JsValue::TRUE)
            .map_err(|_| "Optionen nicht setzbar".to_string())?;
        let file_promise = self
            .handle
            .get_file_handle(BACKUP_FILENAME, &create.into())
            .map_err(|_| "Datei nicht anlegbar".to_string())?;
        let file: FsHandle = JsFuture::from(file_promise)
            .await
            .map_err(|_| "Datei nicht anlegbar (Erlaubnis fehlt?)".to_string())?
            .unchecked_into();

        let writable_promise = file
            .create_writable()
            .map_err(|_| "Datei nicht schreibbar".to_string())?;
        let writable: FsWritable = JsFuture::from(writable_promise)
            .await
            .map_err(|_| "Datei nicht schreibbar (Erlaubnis fehlt?)".to_string())?
            .unchecked_into();

        let array = js_sys::Uint8Array::from(bytes);
        let write_promise = writable
            .write_chunk(&array.into())
            .map_err(|_| "Schreiben fehlgeschlagen".to_string())?;
        JsFuture::from(write_promise)
            .await
            .map_err(|_| "Schreiben fehlgeschlagen".to_string())?;

        let close_promise = writable
            .close_stream()
            .map_err(|_| "Datei nicht abschliessbar".to_string())?;
        JsFuture::from(close_promise)
            .await
            .map_err(|_| "Datei nicht abschliessbar".to_string())?;
        Ok(())
    }
}

/// Das Options-Objekt `{ mode: "readwrite" }` für die Erlaubnis-Aufrufe.
fn write_mode() -> Result<JsValue, JsValue> {
    let options = js_sys::Object::new();
    js_sys::Reflect::set(&options, &"mode".into(), &"readwrite".into())?;
    Ok(options.into())
}
