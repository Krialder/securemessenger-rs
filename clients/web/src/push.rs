//! Web-Push im Browser (F1): Service Worker registrieren, das Push-Abo
//! anlegen bzw. kündigen und es beim Zustelldienst hinterlegen. Reines
//! Browser-Plumbing; die Server-Seite (VAPID, inhaltsloser Versand) liegt in
//! services/delivery. Der eigentliche Ende-zu-Ende-Beweis (echter Push an
//! einen laufenden Browser über HTTPS) gehört auf die Betriebsumgebung
//! (Proxmox), er lässt sich lokal ohne HTTPS und Push-Dienst nicht führen.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use client_app::delivery::DeliveryClient;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Notification, PushEncryptionKeyName, PushManager, PushSubscription,
    PushSubscriptionOptionsInit, ServiceWorkerContainer, ServiceWorkerRegistration,
};

/// Schaltet Push ein: VAPID-Schlüssel holen, Benachrichtigungs-Erlaubnis
/// erfragen, Service Worker registrieren, abonnieren und das Abo beim Dienst
/// hinterlegen. Ein sprechender Fehler bei jedem Schritt.
pub async fn enable(delivery: &DeliveryClient, token: &str) -> Result<(), String> {
    let vapid = delivery
        .vapid_public_key(token)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Dieser Server bietet kein Web-Push an.".to_string())?;

    if request_permission().await? != "granted" {
        return Err("Benachrichtigungen wurden nicht erlaubt.".to_string());
    }

    let registration = register_service_worker().await?;
    let subscription = subscribe(&registration, &vapid).await?;
    let (endpoint, p256dh, auth) = read_subscription(&subscription)?;
    delivery
        .push_subscribe(token, &endpoint, &p256dh, &auth)
        .await
        .map_err(|e| e.to_string())
}

/// Schaltet Push aus: das Browser-Abo kündigen und beim Dienst entfernen.
pub async fn disable(delivery: &DeliveryClient, token: &str) -> Result<(), String> {
    if let Some(registration) = existing_registration().await? {
        if let Some(subscription) = existing_subscription(&registration).await? {
            if let Ok(promise) = subscription.unsubscribe() {
                let _ = JsFuture::from(promise).await;
            }
        }
    }
    delivery
        .push_unsubscribe(token)
        .await
        .map_err(|e| e.to_string())
}

fn service_worker_container() -> Result<ServiceWorkerContainer, String> {
    let window = web_sys::window().ok_or("kein Fenster")?;
    // navigator.serviceWorker fehlt in unsicheren Kontexten (kein https/localhost).
    Ok(window.navigator().service_worker())
}

async fn request_permission() -> Result<String, String> {
    let promise = Notification::request_permission().map_err(js_err)?;
    let value = JsFuture::from(promise).await.map_err(js_err)?;
    Ok(value.as_string().unwrap_or_default())
}

async fn register_service_worker() -> Result<ServiceWorkerRegistration, String> {
    let container = service_worker_container()?;
    let promise = container.register("/sw.js");
    let value = JsFuture::from(promise)
        .await
        .map_err(|e| format!("Service Worker nicht registrierbar: {}", js_text(&e)))?;
    value
        .dyn_into::<ServiceWorkerRegistration>()
        .map_err(|_| "unerwartetes Registrierungs-Objekt".to_string())
}

async fn existing_registration() -> Result<Option<ServiceWorkerRegistration>, String> {
    let container = service_worker_container()?;
    let value = JsFuture::from(container.get_registration())
        .await
        .map_err(js_err)?;
    Ok(value.dyn_into::<ServiceWorkerRegistration>().ok())
}

async fn subscribe(
    registration: &ServiceWorkerRegistration,
    vapid_public_key: &str,
) -> Result<PushSubscription, String> {
    let manager: PushManager = registration.push_manager().map_err(js_err)?;
    let key_bytes = B64URL
        .decode(vapid_public_key)
        .map_err(|_| "VAPID-Schlüssel ist kein base64url".to_string())?;
    let key_array = js_sys::Uint8Array::from(key_bytes.as_slice());

    let options = PushSubscriptionOptionsInit::new();
    options.set_user_visible_only(true);
    options.set_application_server_key(&JsValue::from(key_array));

    let promise = manager.subscribe_with_options(&options).map_err(js_err)?;
    let value = JsFuture::from(promise)
        .await
        .map_err(|e| format!("Abonnieren fehlgeschlagen: {}", js_text(&e)))?;
    value
        .dyn_into::<PushSubscription>()
        .map_err(|_| "unerwartetes Abo-Objekt".to_string())
}

async fn existing_subscription(
    registration: &ServiceWorkerRegistration,
) -> Result<Option<PushSubscription>, String> {
    let manager: PushManager = registration.push_manager().map_err(js_err)?;
    let value = JsFuture::from(manager.get_subscription().map_err(js_err)?)
        .await
        .map_err(js_err)?;
    Ok(value.dyn_into::<PushSubscription>().ok())
}

/// Liest Endpoint und die beiden Abo-Schlüssel (base64url) aus dem
/// Browser-Abo, so wie der Dienst sie erwartet.
fn read_subscription(subscription: &PushSubscription) -> Result<(String, String, String), String> {
    let endpoint = subscription.endpoint();
    let p256dh = subscription_key(subscription, PushEncryptionKeyName::P256dh)?;
    let auth = subscription_key(subscription, PushEncryptionKeyName::Auth)?;
    Ok((endpoint, p256dh, auth))
}

fn subscription_key(
    subscription: &PushSubscription,
    name: PushEncryptionKeyName,
) -> Result<String, String> {
    let buffer = subscription
        .get_key(name)
        .map_err(js_err)?
        .ok_or("Abo ohne Schlüssel")?;
    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
    Ok(B64URL.encode(bytes))
}

fn js_err(value: JsValue) -> String {
    js_text(&value)
}

fn js_text(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| value.dyn_ref::<js_sys::Error>().map(|e| e.message().into()))
        .unwrap_or_else(|| "unbekannter Browser-Fehler".to_string())
}
