//! End-to-End-Beweis des Referenzclients: zwei Nutzer chatten über die
//! echten Dienste, und jeder `sm`-Befehl ist ein eigener Prozess.
//!
//! Das ist der Meilenstein-1-Baustein "zwei Instanzen tauschen über die
//! echten Dienste eine Nachricht" (GOAL.md): identity, directory und
//! delivery laufen als echte Router in-process, das gebaute `sm`-Binary
//! (CARGO_BIN_EXE_sm) wird je Befehl frisch gestartet. Dass die Antwort auf
//! `send` nach einem Prozessende noch entschlüsselbar ist, beweist die
//! persistente Sitzungs-Ablage über Prozessgrenzen hinweg.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

const INTERNAL_SECRET: &str = "test-internes-secret";

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Ephemeralport");
    let addr = listener.local_addr().expect("lokale Adresse");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("Testserver");
    });
    format!("http://{addr}")
}

async fn start_stack() -> (String, String, String) {
    let identity_url = serve(identity::api::app(
        identity::api::AppState::new_in_memory().with_internal_token(INTERNAL_SECRET),
    ))
    .await;
    let directory_url = serve(directory::api::app(directory::api::AppState::new(
        Arc::new(directory::store::InMemoryPrekeyStore::default()),
        Arc::new(common::identity_client::HttpIdentityGateway::new(
            &identity_url,
            INTERNAL_SECRET,
        )),
    )))
    .await;
    let delivery_url = serve(delivery::api::app(delivery::api::AppState::new(
        Arc::new(delivery::store::InMemoryMessageStore::default()),
        Arc::new(common::identity_client::HttpIdentityGateway::new(
            &identity_url,
            INTERNAL_SECRET,
        )),
    )))
    .await;
    (identity_url, directory_url, delivery_url)
}

/// Ein CLI-Nutzer: eigene Profil- und Zustandsdatei, eigene Umgebung.
struct CliUser {
    profile: String,
    state: String,
    identity_url: String,
    directory_url: String,
    delivery_url: String,
}

impl CliUser {
    fn new(dir: &Path, name: &str, urls: &(String, String, String)) -> Self {
        Self {
            profile: dir
                .join(format!("{name}-profile.json"))
                .display()
                .to_string(),
            state: dir.join(format!("{name}-state.json")).display().to_string(),
            identity_url: urls.0.clone(),
            directory_url: urls.1.clone(),
            delivery_url: urls.2.clone(),
        }
    }

    /// Startet das echte sm-Binary mit den Argumenten; jeder Aufruf ist ein
    /// eigener Prozess, genau wie beim Nutzer im Terminal.
    fn run(&self, args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_sm"))
            .args(args)
            .env("SM_PROFILE", &self.profile)
            .env("SM_STATE", &self.state)
            .env("SM_IDENTITY_URL", &self.identity_url)
            .env("SM_DIRECTORY_URL", &self.directory_url)
            .env("SM_DELIVERY_URL", &self.delivery_url)
            .output()
            .expect("sm-Binary startet");
        assert!(
            output.status.success(),
            "sm {args:?} scheiterte:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_cli_users_chat_across_process_boundaries() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-chat-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let alice = CliUser::new(&dir, "alice", &urls);
    let bob = CliUser::new(&dir, "bob", &urls);

    // Onboarding: jeder Schritt ein eigener Prozess.
    alice.run(&["register", "alice", "alices-langes-passwort"]);
    alice.run(&["login", "alices-langes-passwort"]);
    alice.run(&["publish-keys"]);
    bob.run(&["register", "bob", "bobs-langes-passwort"]);
    bob.run(&["login", "bobs-langes-passwort"]);
    bob.run(&["publish-keys"]);

    // Alice schreibt Bob; Bob holt ab und liest den Klartext.
    alice.run(&["send", "bob", "hallo bob, ende-zu-ende vom cli"]);
    let received = bob.run(&["recv"]);
    assert!(
        received.contains("[alice] hallo bob, ende-zu-ende vom cli"),
        "Bob muss Alices Nachricht entschlüsseln, stdout war: {received}"
    );

    // Gegenrichtung, wieder in frischen Prozessen: die Ablagen beider
    // Seiten müssen Sitzungen und Prekey-Zustand gehalten haben.
    bob.run(&["send", "alice", "hallo alice, es funktioniert"]);
    let received = alice.run(&["recv"]);
    assert!(
        received.contains("[bob] hallo alice, es funktioniert"),
        "Alice muss Bobs Antwort entschlüsseln, stdout war: {received}"
    );

    // Zweite Nachricht über die bestehende Sitzung (kein Bündel-Abruf mehr).
    alice.run(&["send", "bob", "zweite nachricht, gleicher ratchet"]);
    let received = bob.run(&["recv"]);
    assert!(
        received.contains("[alice] zweite nachricht, gleicher ratchet"),
        "Bob muss auch die Folge-Nachricht entschlüsseln, stdout war: {received}"
    );

    // Aufräumen ist Komfort, kein Testinhalt.
    let _ = std::fs::remove_dir_all(&dir);
}
