//! Integrationstests des KT-Dienstes: der volle Weg Update -> Epoche ->
//! Beweis, verifiziert mit der akd-Client-Seite (dieselbe gepinnte
//! Bibliothek, die später im Client-Core prüft), plus der
//! Wiederaufbau-Determinismus, an dem das Persistenz-Design hängt.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::Verifier as _;
use http_body_util::BodyExt;
use kt::api::{app, AppState};
use kt::directory::{KtConfiguration, KtDirectory};
use kt::keys::{root_message, RootSigner, SecretVrf};
use kt::store::{InMemoryKtStore, KtStore};
use serde_json::{json, Value};
use tower::ServiceExt;

fn seed(byte: u8) -> String {
    BASE64.encode([byte; 32])
}

async fn build_directory(store: &dyn KtStore) -> Arc<KtDirectory> {
    Arc::new(
        KtDirectory::rebuild(
            store,
            SecretVrf::from_seed_b64(&seed(1)).unwrap(),
            RootSigner::from_seed_b64(&seed(2)).unwrap(),
        )
        .await
        .unwrap(),
    )
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    internal_secret: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(secret) = internal_secret {
        builder = builder.header("x-internal-token", secret);
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

fn update(handle: &str, value: &[u8]) -> Value {
    json!({ "handle": handle, "value": BASE64.encode(value) })
}

#[tokio::test]
async fn update_epoch_proof_roundtrip_with_client_verification() {
    let store: Arc<dyn KtStore> = Arc::new(InMemoryKtStore::default());
    let directory = build_directory(store.as_ref()).await;
    let state = AppState::new(store.clone(), directory.clone()).with_internal_token("kt-geheim");
    let app = app(state);

    // Vor der ersten Epoche: alles leer.
    let (status, _) = send(&app, "GET", "/kt/epoch/latest", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // identity meldet zwei Konten, der Publisher veröffentlicht.
    for (handle, value) in [("alice", b"commit-a".as_slice()), ("bob", b"commit-b")] {
        let (status, _) = send(
            &app,
            "POST",
            "/internal/updates",
            Some(update(handle, value)),
            Some("kt-geheim"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let record = directory
        .publish_pending(store.as_ref())
        .await
        .unwrap()
        .expect("Epoche mit zwei Updates");
    assert_eq!(record.epoch, 1);

    // Die signierte Wurzel: Signatur verifiziert gegen den Info-Schlüssel.
    let (status, info) = send(&app, "GET", "/kt/info", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let signing_key = info["root_signing_key"].as_str().unwrap();
    let (status, epoch) = send(&app, "GET", "/kt/epoch/1", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(
        &BASE64
            .decode(signing_key)
            .unwrap()
            .try_into()
            .expect("32 Byte"),
    )
    .unwrap();
    let root_hash = BASE64.decode(epoch["root_hash"].as_str().unwrap()).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(
        &BASE64.decode(epoch["signature"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        verifying
            .verify(&root_message(1, &root_hash), &signature)
            .is_ok(),
        "Wurzel-Signatur muss gegen den veröffentlichten Schlüssel prüfen"
    );

    // Inklusionsbeweis: mit der akd-Client-Seite verifizieren, wie es
    // später der Client-Core tut.
    let (status, proof_json) = send(&app, "GET", "/kt/proof/alice", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(proof_json["epoch"], 1);
    let proof: akd::LookupProof = bincode::deserialize(
        &BASE64
            .decode(proof_json["proof"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let vrf_public = BASE64
        .decode(info["vrf_public_key"].as_str().unwrap())
        .unwrap();
    let proof_root: [u8; 32] = BASE64
        .decode(proof_json["root_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("32 Byte Wurzel");
    let result = akd::client::lookup_verify::<KtConfiguration>(
        &vrf_public,
        proof_root,
        1,
        akd::AkdLabel::from("alice"),
        proof,
    )
    .expect("Inklusionsbeweis verifiziert");
    assert_eq!(result.value.0, b"commit-a".to_vec());
    assert_eq!(result.version, 1);

    // Unbekanntes Handle: 404, ohne etwas preiszugeben.
    let (status, body) = send(&app, "GET", "/kt/proof/niemand", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "unknown_handle");

    // Schlüsselwechsel: neue Epoche, Historie zeigt beide Versionen.
    let (status, _) = send(
        &app,
        "POST",
        "/internal/updates",
        Some(update("alice", b"commit-a2")),
        Some("kt-geheim"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let record = directory
        .publish_pending(store.as_ref())
        .await
        .unwrap()
        .expect("zweite Epoche");
    assert_eq!(record.epoch, 2);

    let (status, history_json) = send(&app, "GET", "/kt/history/alice", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let history: akd::HistoryProof = bincode::deserialize(
        &BASE64
            .decode(history_json["proof"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let history_root: [u8; 32] = BASE64
        .decode(history_json["root_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("32 Byte Wurzel");
    let results = akd::client::key_history_verify::<KtConfiguration>(
        &vrf_public,
        history_root,
        2,
        akd::AkdLabel::from("alice"),
        history,
        akd::HistoryVerificationParams::default(),
    )
    .expect("Historie verifiziert");
    assert_eq!(results.len(), 2, "beide Versionen in der Historie");
    assert_eq!(results[0].value.0, b"commit-a2".to_vec());
    assert_eq!(results[1].value.0, b"commit-a".to_vec());

    // Konsistenzbeweis zwischen den Epochen, wie ihn Auditoren ziehen.
    let (status, audit_json) = send(&app, "GET", "/kt/consistency?from=1&to=2", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let audit: akd::AppendOnlyProof = bincode::deserialize(
        &BASE64
            .decode(audit_json["proof"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let root1: [u8; 32] = root_hash.clone().try_into().expect("32 Byte");
    let root2: [u8; 32] = BASE64
        .decode(
            send(&app, "GET", "/kt/epoch/2", None, None).await.1["root_hash"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .expect("32 Byte");
    akd::auditor::audit_verify::<KtConfiguration>(vec![root1, root2], audit)
        .await
        .expect("Append-only-Beweis verifiziert");
}

#[tokio::test]
async fn rebuild_is_deterministic_and_detects_tampering() {
    let store: Arc<dyn KtStore> = Arc::new(InMemoryKtStore::default());
    let directory = build_directory(store.as_ref()).await;

    // Zwei Epochen veröffentlichen.
    store.queue_update("alice", b"a1").await.unwrap();
    store.queue_update("bob", b"b1").await.unwrap();
    directory.publish_pending(store.as_ref()).await.unwrap();
    store.queue_update("alice", b"a2").await.unwrap();
    directory.publish_pending(store.as_ref()).await.unwrap();

    // Wiederaufbau aus demselben Log (gleiche Schlüssel): identische
    // Wurzeln, kein Fehler - das ist der Neustart-Fall.
    let rebuilt = KtDirectory::rebuild(
        store.as_ref(),
        SecretVrf::from_seed_b64(&seed(1)).unwrap(),
        RootSigner::from_seed_b64(&seed(2)).unwrap(),
    )
    .await;
    assert!(rebuilt.is_ok(), "Wiederaufbau muss deterministisch sein");

    // Anderer VRF-Schlüssel = andere Labels = andere Wurzeln: der
    // Wiederaufbau MUSS das als Integritätsbruch ablehnen.
    let wrong_key = KtDirectory::rebuild(
        store.as_ref(),
        SecretVrf::from_seed_b64(&seed(9)).unwrap(),
        RootSigner::from_seed_b64(&seed(2)).unwrap(),
    )
    .await;
    match wrong_key {
        Err(kt::directory::DirectoryError::IntegrityViolation(_)) => {}
        Err(other) => panic!("Integritätsbruch erwartet, kam Fehler {other}"),
        Ok(_) => panic!("falscher VRF-Schlüssel darf den Wiederaufbau nicht bestehen"),
    }
}

#[tokio::test]
async fn rejects_bad_requests() {
    let store: Arc<dyn KtStore> = Arc::new(InMemoryKtStore::default());
    let directory = build_directory(store.as_ref()).await;

    // Ohne konfiguriertes Secret existiert die interne Route nicht.
    let bare = app(AppState::new(store.clone(), directory.clone()));
    let (status, _) = send(
        &bare,
        "POST",
        "/internal/updates",
        Some(update("x", b"y")),
        Some("egal"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let app = app(AppState::new(store.clone(), directory.clone()).with_internal_token("kt-geheim"));

    // Falsches oder fehlendes Secret: 401.
    for secret in [None, Some("falsch")] {
        let (status, _) = send(
            &app,
            "POST",
            "/internal/updates",
            Some(update("x", b"y")),
            secret,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Formfehler der Update-Annahme.
    for bad in [
        json!({ "handle": "", "value": BASE64.encode(b"x") }),
        json!({ "handle": "alice", "value": "" }),
        json!({ "handle": "alice", "value": "kein base64!" }),
    ] {
        let (status, body) = send(
            &app,
            "POST",
            "/internal/updates",
            Some(bad),
            Some("kt-geheim"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_update");
    }

    // Konsistenz-Grenzen: kaputte Bereiche und unbekannte Epochen.
    for uri in [
        "/kt/consistency?from=0&to=1",
        "/kt/consistency?from=2&to=1",
        "/kt/consistency?from=1&to=99",
    ] {
        let (status, _) = send(&app, "GET", uri, None, None).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "{uri} muss abgewiesen werden, kam {status}"
        );
    }
    let (status, _) = send(&app, "GET", "/kt/epoch/7", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ops_endpoints_respond() {
    let store: Arc<dyn KtStore> = Arc::new(InMemoryKtStore::default());
    let directory = build_directory(store.as_ref()).await;
    let app = app(AppState::new(store, directory));
    for uri in ["/live", "/ready", "/metrics"] {
        let (status, _) = send(&app, "GET", uri, None, None).await;
        assert_eq!(status, StatusCode::OK, "Endpunkt {uri}");
    }
}
