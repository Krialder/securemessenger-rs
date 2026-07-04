//! Geteilte Test-Helfer: die Client-Seite der API.
//!
//! Erzeugt Ed25519-Schlüssel und signiert Geräte-Credentials, wie es sonst
//! der Client-Core täte (specs/geraete-identitaet.md), und schickt Requests
//! über tower::oneshot ohne echten Socket.

// Nicht jeder Test-Binary nutzt alle Helfer; das ist hier kein Fehler.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use identity::credential::credential_message;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Weit in der Zukunft (2100-01-01), damit Credentials in Tests nicht ablaufen.
pub const FAR_FUTURE: u64 = 4102444800;

/// Deterministischer Schlüssel pro Seed; Tests brauchen keine echte Entropie.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn b64_public(key: &SigningKey) -> String {
    BASE64.encode(key.verifying_key().to_bytes())
}

/// Baut den JSON-Block eines Geräts samt gültigem Credential, signiert vom
/// Konto-Identitätsschlüssel: die Client-Seite des Freischalt-Flows.
pub fn signed_device(
    identity: &SigningKey,
    handle: &str,
    device_id: &str,
    device_seed: u8,
) -> Value {
    signed_device_with_key(identity, handle, device_id, &b64_public(&key(device_seed)))
}

/// Wie `signed_device`, aber mit vorgegebenem Geräteschlüssel (Base64):
/// echte Clients registrieren ihren libsignal-Identitätsschlüssel, und der
/// Sealed-Sender-Test braucht genau den im Credential.
pub fn signed_device_with_key(
    identity: &SigningKey,
    handle: &str,
    device_id: &str,
    device_pk: &str,
) -> Value {
    let message = credential_message(handle, device_id, device_pk, FAR_FUTURE);
    let signature = BASE64.encode(identity.sign(message.as_bytes()).to_bytes());
    json!({
        "id": device_id,
        "public_key": device_pk,
        "not_after": FAR_FUTURE,
        "credential": signature,
    })
}

/// Registrierungs-Body mit Konto-Identitätsschlüssel und erstem Gerät.
pub fn register_body(
    identity: &SigningKey,
    handle: &str,
    password: &str,
    device_id: &str,
) -> Value {
    json!({
        "handle": handle,
        "password": password,
        "identity_key": b64_public(identity),
        "device": signed_device(identity, handle, device_id, 42),
    })
}

pub fn login_body(handle: &str, password: &str, device_id: &str) -> Value {
    json!({ "handle": handle, "password": password, "device_id": device_id })
}

pub async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}
