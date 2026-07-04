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

    /// Das echte sm-Binary mit der Umgebung dieses Nutzers, noch nicht
    /// gestartet: `run` wartet auf das Ende, der listen-Test hält den
    /// Prozess offen.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sm"));
        command
            .args(args)
            .env("SM_PROFILE", &self.profile)
            .env("SM_STATE", &self.state)
            .env("SM_IDENTITY_URL", &self.identity_url)
            .env("SM_DIRECTORY_URL", &self.directory_url)
            .env("SM_DELIVERY_URL", &self.delivery_url);
        command
    }

    /// Startet das echte sm-Binary mit den Argumenten; jeder Aufruf ist ein
    /// eigener Prozess, genau wie beim Nutzer im Terminal.
    fn run(&self, args: &[&str]) -> String {
        let output = self.command(args).output().expect("sm-Binary startet");
        assert!(
            output.status.success(),
            "sm {args:?} scheiterte:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    /// Wie `run`, liefert aber stdout und stderr (der recv-Befehl schreibt
    /// die Melde-ID auf stderr).
    fn run_full(&self, args: &[&str]) -> (String, String) {
        let output = self.command(args).output().expect("sm-Binary startet");
        assert!(output.status.success(), "sm {args:?} scheiterte");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
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

/// Der Hinweiskanal-Beweis: `sm listen --once` empfängt eine Nachricht, die
/// erst NACH dem Verbindungsaufbau gesendet wird. Der Empfang kann also nur
/// über den WebSocket-Hinweis ausgelöst worden sein, nicht über den
/// initialen Abruf.
#[tokio::test(flavor = "multi_thread")]
async fn listen_receives_message_via_websocket_hint() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-listen-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let alice = CliUser::new(&dir, "alice", &urls);
    let bob = CliUser::new(&dir, "bob", &urls);
    alice.run(&["register", "alice", "alices-langes-passwort"]);
    alice.run(&["login", "alices-langes-passwort"]);
    alice.run(&["publish-keys"]);
    bob.run(&["register", "bob", "bobs-langes-passwort"]);
    bob.run(&["login", "bobs-langes-passwort"]);
    bob.run(&["publish-keys"]);

    // Bob lauscht. Gesendet wird erst, wenn sein Kanal nachweislich steht
    // (die "Verbunden"-Zeile auf stderr kommt nach Auth und Initial-Abruf).
    let mut child = bob
        .command(&["listen", "--once"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sm listen startet");
    let stderr = child.stderr.take().expect("stderr-Pipe");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let stderr_reader = std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut lines = Vec::new();
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("Verbunden") {
                let _ = ready_tx.send(());
            }
            lines.push(line);
        }
        lines
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("listen meldet den stehenden Kanal binnen 20 s");

    alice.run(&["send", "bob", "geweckt vom hinweis"]);

    // listen --once beendet sich nach dem ersten Durchlauf mit Nachrichten;
    // haengt es, ist der Hinweis nie angekommen.
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || child.wait_with_output()),
    )
    .await
    .expect("listen beendet sich nach dem Empfang binnen 30 s")
    .expect("Warte-Task")
    .expect("Prozessende");
    let listen_stderr = stderr_reader.join().unwrap_or_default().join("\n");
    assert!(
        output.status.success(),
        "sm listen scheiterte:\nstderr: {listen_stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[alice] geweckt vom hinweis"),
        "Bob muss die Nachricht über den Hinweis empfangen haben, stdout war: {stdout}\nstderr: {listen_stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Der Abuse-Abwehr-Beweis: eine Nachricht lässt sich beweisbar melden
/// (Message Franking), und ein blockierter Absender kommt nicht mehr durch.
#[tokio::test(flavor = "multi_thread")]
async fn franking_report_verifies_and_blocking_drops() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-abuse-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let alice = CliUser::new(&dir, "alice", &urls);
    let bob = CliUser::new(&dir, "bob", &urls);
    alice.run(&["register", "alice", "alices-langes-passwort"]);
    alice.run(&["login", "alices-langes-passwort"]);
    alice.run(&["publish-keys"]);
    bob.run(&["register", "bob", "bobs-langes-passwort"]);
    bob.run(&["login", "bobs-langes-passwort"]);
    bob.run(&["publish-keys"]);

    // Alice sendet, Bob empfaengt und liest die Melde-ID von stderr ab.
    alice.run(&["send", "bob", "eine meldbare nachricht"]);
    let (stdout, stderr) = bob.run_full(&["recv"]);
    assert!(stdout.contains("[alice] eine meldbare nachricht"));
    let message_id = stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("(Melde-ID: "))
        .and_then(|rest| rest.strip_suffix(")"))
        .expect("recv gibt eine Melde-ID auf stderr aus")
        .to_string();

    // Bob meldet die Nachricht: der Server verifiziert das Franking.
    let reported = bob.run(&["report", &message_id]);
    assert!(
        reported.contains("Meldung verifiziert"),
        "die Meldung muss beweisbar echt sein, stdout war: {reported}"
    );

    // Bob blockiert Alice; ihre naechste Nachricht kommt nicht mehr an.
    bob.run(&["block", "alice"]);
    assert!(bob.run(&["blocks"]).contains("alice"));
    alice.run(&["send", "bob", "das kommt nicht durch"]);
    let blocked = bob.run(&["recv"]);
    assert!(
        blocked.contains("Keine neuen Nachrichten"),
        "die blockierte Nachricht darf nicht ankommen, stdout war: {blocked}"
    );

    // Nach dem Entblocken geht es wieder.
    bob.run(&["unblock", "alice"]);
    alice.run(&["send", "bob", "jetzt wieder"]);
    let received = bob.run(&["recv"]);
    assert!(received.contains("[alice] jetzt wieder"));

    let _ = std::fs::remove_dir_all(&dir);
}
