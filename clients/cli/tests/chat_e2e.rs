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
        identity::api::AppState::new_in_memory()
            .with_internal_token(INTERNAL_SECRET)
            // Zertifikatsausgabe für den Sealed-Sender-Teil des Tests.
            .with_sealed_sender(Arc::new(
                sealed_cert::Issuer::from_seed(&[6u8; 32]).expect("Aussteller"),
            )),
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
    /// Gesetzt schaltet die verschlüsselte Ablage frei (SM_PASSPHRASE).
    passphrase: Option<String>,
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
            passphrase: None,
        }
    }

    /// Wie `new`, aber mit verschlüsselter Ablage unter einer Passphrase.
    fn new_encrypted(
        dir: &Path,
        name: &str,
        urls: &(String, String, String),
        passphrase: &str,
    ) -> Self {
        let mut user = Self::new(dir, name, urls);
        user.passphrase = Some(passphrase.to_string());
        user
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
        if let Some(passphrase) = &self.passphrase {
            command.env("SM_PASSPHRASE", passphrase);
        }
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

    // Schlüsselwechsel-Prüfung: Alice kennt Bobs Geräteschlüssel aus der
    // Sitzung; ein frischer Bündel-Abruf ergibt denselben, also keine Warnung.
    let keycheck = alice.run(&["keycheck", "bob"]);
    assert!(
        keycheck.contains("Schlüssel unverändert"),
        "Bobs Schlüssel darf sich nicht geändert haben, stdout war: {keycheck}"
    );

    // Disappearing Message mit großzügiger Frist: sie wird noch zugestellt
    // (das Verschwinden nach Ablauf prüfen die Store-Tests). Der --ttl-Pfad
    // fliesst also bis zur Zustellung durch.
    alice.run(&["send", "bob", "verschwindet spaeter", "--ttl", "3600"]);
    let received = bob.run(&["recv"]);
    assert!(
        received.contains("[alice] verschwindet spaeter"),
        "die befristete Nachricht muss vor Ablauf ankommen, stdout war: {received}"
    );

    // Sealed Sender: die Hülle geht ohne Token und ohne Absender im
    // Framing an die Zustellung; Bob liest die Nachricht trotzdem mit
    // Absender, weil der aus der geprüften Zertifikatskette kommt.
    let sent = alice.run(&["send", "bob", "versiegelt unterwegs", "--sealed"]);
    assert!(
        sent.contains("versiegelt"),
        "send --sealed muss die Versiegelung bestätigen, stdout war: {sent}"
    );
    let received = bob.run(&["recv"]);
    assert!(
        received.contains("[alice] versiegelt unterwegs"),
        "die versiegelte Nachricht muss mit Absender ankommen, stdout war: {received}"
    );

    // Aufräumen ist Komfort, kein Testinhalt.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Verschlüsselte Ablage: mit SM_PASSPHRASE liegen Profil und Zustand als
/// keystore-Envelope auf der Platte (nicht als lesbares JSON), der volle
/// Chat-Rundlauf funktioniert trotzdem über Prozessgrenzen, und eine
/// falsche Passphrase sperrt den Zugriff.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_storage_roundtrip() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-enc-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let carla = CliUser::new_encrypted(&dir, "carla", &urls, "carlas-tresor-passphrase");
    let dirk = CliUser::new_encrypted(&dir, "dirk", &urls, "dirks-tresor-passphrase");

    carla.run(&["register", "carla", "carlas-langes-passwort"]);
    carla.run(&["login", "carlas-langes-passwort"]);
    carla.run(&["publish-keys"]);
    dirk.run(&["register", "dirk", "dirks-langes-passwort"]);
    dirk.run(&["login", "dirks-langes-passwort"]);
    dirk.run(&["publish-keys"]);

    // Der Chat funktioniert über die verschlüsselte Ablage hinweg (jede
    // Operation entsiegelt, arbeitet, versiegelt neu).
    carla.run(&["send", "dirk", "verschluesselte ablage, klartext chat"]);
    let received = dirk.run(&["recv"]);
    assert!(
        received.contains("[carla] verschluesselte ablage, klartext chat"),
        "der Chat muss auch mit Tresor-Ablage laufen, stdout war: {received}"
    );

    // Beweis auf der Platte: beide Dateien tragen das keystore-Präfix und
    // sind kein lesbares JSON mehr.
    for path in [&carla.profile, &carla.state] {
        let bytes = std::fs::read(path).expect("Datei liegt vor");
        assert!(
            bytes.starts_with(b"smks.v1"),
            "{path} muss ein keystore-Envelope sein"
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes).is_err(),
            "{path} darf kein lesbares JSON mehr sein"
        );
    }

    // Falsche Passphrase: der Zugriff scheitert, kein stiller Klartext.
    let wrong = CliUser::new_encrypted(&dir, "carla", &urls, "falsche-passphrase");
    let output = wrong
        .command(&["whoami"])
        .output()
        .expect("sm-Binary startet");
    assert!(
        !output.status.success(),
        "mit falscher Passphrase darf kein Zugriff gelingen"
    );

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

/// Multi-Device: ein zweites Gerät wird zum selben Konto gekoppelt und
/// empfängt eigene Kopien. Beweist die Nummernvergabe (1 und 2), den
/// Kopplungsfluss (link/approve/link-finish über die echten Dienste) und
/// den Fanout an beide Geräte des Empfängers.
#[tokio::test(flavor = "multi_thread")]
async fn second_device_receives_own_copy() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-mdev-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    // Erstes Gerät: Konto anlegen, anmelden, Prekeys veröffentlichen.
    let mona1 = CliUser::new(&dir, "mona1", &urls);
    mona1.run(&["register", "mona", "monas-langes-passwort"]);
    mona1.run(&["login", "monas-langes-passwort"]);
    mona1.run(&["publish-keys"]);

    // Zweites Gerät (eigenes Profil, gleiches Handle): Kopplung beginnen.
    let mona2 = CliUser::new(&dir, "mona2", &urls);
    let link_out = mona2.run(&["link", "mona", "monas-langes-passwort"]);
    let payload = link_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("sm approve "))
        .expect("Kopplungs-Antrag in der Ausgabe")
        .to_string();

    // Erstgerät schaltet frei; der Server vergibt Nummer 2.
    let approved = mona1.run(&["approve", &payload]);
    assert!(
        approved.contains("Nummer 2"),
        "das zweite Gerät muss Nummer 2 bekommen, stdout war: {approved}"
    );

    // Zweitgerät schließt ab: meldet sich an, übernimmt die Nummer,
    // veröffentlicht Prekeys.
    let finished = mona2.run(&["link-finish", "mona", "monas-langes-passwort"]);
    assert!(
        finished.contains("Nummer 2"),
        "link-finish muss die Nummer bestätigen, stdout war: {finished}"
    );

    // Die Gerätemenge zeigt beide Geräte mit ihren Nummern.
    let devices = mona1.run(&["devices"]);
    assert!(
        devices.contains("Nummer 1") && devices.contains("Nummer 2"),
        "beide Geräte müssen in der Menge stehen, stdout war: {devices}"
    );

    // Ein Dritter schreibt mona; die Zustellung geht an BEIDE Geräte.
    let nils = CliUser::new(&dir, "nils", &urls);
    nils.run(&["register", "nils", "nils-langes-passwort"]);
    nils.run(&["login", "nils-langes-passwort"]);
    nils.run(&["publish-keys"]);
    let sent = nils.run(&["send", "mona", "an alle geraete von mona"]);
    assert!(
        sent.contains("an 2 Gerät(e)"),
        "der Fanout muss beide Geräte adressieren, stdout war: {sent}"
    );

    // Beide Geräte holen unabhängig ab und entschlüsseln dieselbe Nachricht.
    let got1 = mona1.run(&["recv"]);
    assert!(
        got1.contains("[nils] an alle geraete von mona"),
        "Gerät 1 muss die Nachricht lesen, stdout war: {got1}"
    );
    let got2 = mona2.run(&["recv"]);
    assert!(
        got2.contains("[nils] an alle geraete von mona"),
        "Gerät 2 muss dieselbe Nachricht lesen, stdout war: {got2}"
    );

    // Self-Sync: Gerät 1 schreibt nils; Gerät 2 sieht die selbst gesendete
    // Nachricht als ausgehende Kopie (der Verlauf stimmt auf beiden Geräten).
    let sent = mona1.run(&["send", "nils", "sync-probe an nils"]);
    assert!(
        sent.contains("an 1 Gerät(e)"),
        "nils hat ein Gerät; der Self-Sync zählt nicht mit, stdout war: {sent}"
    );
    let synced = mona2.run(&["recv"]);
    assert!(
        synced.contains("[-> nils] sync-probe an nils"),
        "Gerät 2 muss die von Gerät 1 gesendete Nachricht als Sync sehen, stdout war: {synced}"
    );
    // nils selbst bekommt sie natürlich normal.
    let nils_got = nils.run(&["recv"]);
    assert!(
        nils_got.contains("[mona] sync-probe an nils"),
        "nils muss die Nachricht normal empfangen, stdout war: {nils_got}"
    );

    // Revocation: das Erstgerät entfernt das Zweitgerät; ein frischer
    // Absender löst die Menge neu auf und stellt nur noch an eines zu.
    let device_line = devices
        .lines()
        .find(|l| l.contains("Nummer 2"))
        .expect("Zeile des zweiten Geräts");
    let device2_id = device_line
        .split('[')
        .nth(1)
        .and_then(|s| s.split(']').next())
        .expect("Geräte-ID in eckigen Klammern");
    mona1.run(&["unlink", device2_id]);
    let pia = CliUser::new(&dir, "pia", &urls);
    pia.run(&["register", "pia", "pias-langes-passwort"]);
    pia.run(&["login", "pias-langes-passwort"]);
    pia.run(&["publish-keys"]);
    let sent = pia.run(&["send", "mona", "nur noch ein geraet"]);
    assert!(
        sent.contains("an 1 Gerät(e)"),
        "nach der Revocation darf nur ein Gerät adressiert werden, stdout war: {sent}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Passwortwechsel: das alte Passwort wird geprüft, das andere Gerät
/// abgemeldet, und die Neuanmeldung klappt nur mit dem neuen Passwort.
#[tokio::test(flavor = "multi_thread")]
async fn password_change_relogins_and_revokes_other_device() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-passwd-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    // Erstgerät koppelt ein Zweitgerät (wie im Multi-Device-Test).
    let dev1 = CliUser::new(&dir, "pw1", &urls);
    dev1.run(&["register", "pia7", "altes-langes-passwort"]);
    dev1.run(&["login", "altes-langes-passwort"]);
    dev1.run(&["publish-keys"]);
    let dev2 = CliUser::new(&dir, "pw2", &urls);
    let link_out = dev2.run(&["link", "pia7", "altes-langes-passwort"]);
    let payload = link_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("sm approve "))
        .expect("Kopplungs-Antrag")
        .to_string();
    dev1.run(&["approve", &payload]);
    dev2.run(&["link-finish", "pia7", "altes-langes-passwort"]);

    // Falsches altes Passwort scheitert.
    let wrong = dev1
        .command(&["passwd", "falsch", "neues-langes-passwort"])
        .output()
        .expect("sm startet");
    assert!(
        !wrong.status.success(),
        "falsches altes Passwort muss scheitern"
    );

    // Korrekt: Wechsel meldet die anderen Geräte ab.
    let ok = dev1.run(&["passwd", "altes-langes-passwort", "neues-langes-passwort"]);
    assert!(ok.contains("Passwort geändert"), "stdout war: {ok}");

    // Das Erstgerät (dieses Gerät) arbeitet weiter: whoami braucht kein Token,
    // aber ein frischer Login mit dem NEUEN Passwort muss klappen und mit dem
    // alten scheitern.
    let old_login = dev1
        .command(&["login", "altes-langes-passwort"])
        .output()
        .expect("sm startet");
    assert!(
        !old_login.status.success(),
        "altes Passwort darf nicht mehr anmelden"
    );
    let new_login = dev1.run(&["login", "neues-langes-passwort"]);
    assert!(new_login.contains("Angemeldet"), "stdout war: {new_login}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Konto-Löschung vormerken und widerrufen über die echten Dienste
/// (NF030, Widerrufsfrist). Der Purge nach Ablauf prüfen die Store-Tests;
/// hier zählt der Client-zu-Server-Weg der beiden Endpunkte.
#[tokio::test(flavor = "multi_thread")]
async fn account_deletion_schedule_and_undelete() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-del-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let uwe = CliUser::new(&dir, "uwe", &urls);
    uwe.run(&["register", "uwe", "uwes-langes-passwort"]);
    uwe.run(&["login", "uwes-langes-passwort"]);

    // Falsches Passwort: die Löschung wird abgelehnt (Prozess scheitert).
    let wrong = uwe
        .command(&["delete-account", "falsches-passwort"])
        .output()
        .expect("sm startet");
    assert!(
        !wrong.status.success(),
        "eine Löschung mit falschem Passwort darf nicht durchgehen"
    );

    // Korrektes Passwort: vorgemerkt.
    let scheduled = uwe.run(&["delete-account", "uwes-langes-passwort"]);
    assert!(
        scheduled.contains("Löschung vorgemerkt"),
        "die Löschung muss vorgemerkt werden, stdout war: {scheduled}"
    );

    // Widerrufen: das Konto bleibt, eine erneute Anmeldung klappt.
    let cancelled = uwe.run(&["undelete"]);
    assert!(
        cancelled.contains("widerrufen"),
        "der Widerruf muss bestätigt werden, stdout war: {cancelled}"
    );
    uwe.run(&["login", "uwes-langes-passwort"]);

    // Anzeigename ändern (F010): mehrere Argumente werden zu einem Namen
    // verbunden, die CLI gibt die vom Server bestätigte Form aus.
    let renamed = uwe.run(&["rename", "Uwe", "Ullmann"]);
    assert!(
        renamed.contains("Anzeigename geändert: Uwe Ullmann"),
        "die CLI muss die gespeicherte Form bestätigen, stdout war: {renamed}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// MLS-Gruppen über die CLI: gründen, beitreten (Welcome plus Roster über
/// den normalen Abholweg), senden in beide Richtungen -- und jeder
/// `sm`-Befehl ist ein eigener Prozess. Dass ein Beigetretener in einem
/// SPÄTEREN Prozess senden und der Gründer in wieder einem anderen lesen
/// kann, beweist die persistente MLS-Ablage (smmls.v1) über
/// Prozessgrenzen, analog zum 1:1-Ratchet-Beweis oben.
#[tokio::test(flavor = "multi_thread")]
async fn group_chat_over_separate_cli_processes() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-grp-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let anna = CliUser::new(&dir, "anna", &urls);
    let bert = CliUser::new(&dir, "bert", &urls);
    let carl = CliUser::new(&dir, "carl", &urls);
    for (user, handle) in [(&anna, "anna"), (&bert, "bert"), (&carl, "carl")] {
        user.run(&["register", handle, "ein-langes-gruppen-passwort"]);
        user.run(&["login", "ein-langes-gruppen-passwort"]);
        // publish-keys legt neben den 1:1-Prekeys auch MLS-KeyPackages
        // nach; ohne sie könnte niemand eingeladen werden.
        let published = user.run(&["publish-keys"]);
        assert!(
            published.contains("MLS-KeyPackages"),
            "publish-keys muss MLS-KeyPackages nachlegen, stdout war: {published}"
        );
    }

    // Anna gründet die Gruppe; die Zustell-ID steht in der Ausgabe.
    let created = anna.run(&["group-create", "bert", "carl"]);
    let group_id = created
        .split_whitespace()
        .nth(1)
        .expect("Gruppen-ID in der Ausgabe")
        .to_string();
    assert!(
        created.contains("anna, bert, carl"),
        "stdout war: {created}"
    );

    // Anna schreibt VOR der Annahme in die Gruppe: der Text darf nicht
    // verloren gehen, er wird bei Berts Annahme nachgespielt.
    anna.run(&["group-send", &group_id, "vor der annahme gesendet"]);

    // Bert und Carl holen ab: kein automatischer Beitritt mehr, sondern
    // eine EINLADUNG, die vorgemerkt wird (Schutz vor aufgezwungenen
    // Gruppen). Roster und der Vor-Annahme-Text werden dabei gepuffert.
    let bert_recv = bert.run(&["recv"]);
    assert!(
        bert_recv.contains("eingeladen") && !bert_recv.contains("beigetreten"),
        "Bert darf nicht automatisch beitreten, stdout war: {bert_recv}"
    );
    // Die Einladung steht in der Liste.
    let bert_invites = bert.run(&["invites"]);
    assert!(
        bert_invites.contains(&group_id),
        "die Einladung muss in 'invites' stehen, stdout war: {bert_invites}"
    );
    // Annehmen: jetzt erst der Beitritt (Mitglieder aus dem Ratchet-Tree);
    // der gepufferte Roster wird nachgespielt und der Vor-Annahme-Text
    // gezeigt (statt still verworfen).
    let bert_accept = bert.run(&["group-accept", &group_id]);
    assert!(
        bert_accept.contains("beigetreten") && bert_accept.contains("anna"),
        "die Annahme muss beitreten, stdout war: {bert_accept}"
    );
    assert!(
        bert_accept.contains("Roster ist da"),
        "der gepufferte Roster muss beim Beitritt nachgespielt werden, stdout war: {bert_accept}"
    );
    assert!(
        bert_accept.contains("anna: vor der annahme gesendet"),
        "der Vor-Annahme-Text darf nicht verloren gehen, stdout war: {bert_accept}"
    );
    // Carl nimmt ebenfalls an (die Ablehnung prüft ein eigener Test).
    carl.run(&["recv"]);
    carl.run(&["group-accept", &group_id]);

    // Die Gruppe steht in Berts lokaler Liste (samt Mitgliedern aus dem
    // MLS-Ratchet-Tree, nicht aus einer Server-Antwort).
    let groups = bert.run(&["groups"]);
    assert!(
        groups.contains(&group_id) && groups.contains("anna"),
        "stdout war: {groups}"
    );

    // Bert sendet in einem frischen Prozess: sein MLS-Zustand kommt aus
    // der Ablage. Anna (Gründerin) und Carl lesen denselben Text, der
    // Absender stammt aus der von MLS geprüften Credential.
    bert.run(&["group-send", &group_id, "hallo gruppe aus der cli"]);
    for user in [&anna, &carl] {
        let received = user.run(&["recv"]);
        assert!(
            received.contains("bert: hallo gruppe aus der cli"),
            "stdout war: {received}"
        );
    }

    // Und zurück: die Gründerin antwortet, der Beigetretene liest.
    anna.run(&["group-send", &group_id, "willkommen ihr zwei"]);
    let bert_reads = bert.run(&["recv"]);
    assert!(
        bert_reads.contains("anna: willkommen ihr zwei"),
        "stdout war: {bert_reads}"
    );

    // Entfernen mit MLS-Neuschlüsseln: anna wirft carl hinaus. carl
    // erkennt die Entfernung am Commit und räumt lokal auf; bert führt
    // nur seine Mitgliederliste nach.
    let removed = anna.run(&["group-remove", &group_id, "carl"]);
    assert!(
        removed.contains("neu geschlüsselt") && removed.contains("anna, bert"),
        "stdout war: {removed}"
    );
    let carl_out = carl.run(&["recv"]);
    assert!(
        carl_out.contains("Du wurdest aus der Gruppe entfernt"),
        "stdout war: {carl_out}"
    );
    let carl_groups = carl.run(&["groups"]);
    assert!(
        !carl_groups.contains(&group_id),
        "carls Gruppenliste muss leer sein, stdout war: {carl_groups}"
    );
    let bert_update = bert.run(&["recv"]);
    assert!(
        bert_update.contains("Gruppen-Update angewandt") && bert_update.contains("anna, bert"),
        "stdout war: {bert_update}"
    );

    // Die neue Epoche bleibt carl verschlossen: die nächste Nachricht
    // erreicht nur noch bert (carls Gerät ist aus der Gruppen-Gerätemenge,
    // sein lokaler Zustand ist weg).
    anna.run(&["group-send", &group_id, "ohne carl"]);
    let bert_secret = bert.run(&["recv"]);
    assert!(
        bert_secret.contains("anna: ohne carl"),
        "stdout war: {bert_secret}"
    );
    let carl_after = carl.run(&["recv"]);
    assert!(
        !carl_after.contains("ohne carl"),
        "carl darf die Nachricht der neuen Epoche nicht sehen, stdout war: {carl_after}"
    );

    // Verlassen: bert sagt es an und vergisst lokal; anna sieht die
    // Ansage samt Hinweis auf den Remove-Commit.
    let left = bert.run(&["group-leave", &group_id]);
    assert!(
        left.contains("verlassen und lokal vergessen"),
        "stdout war: {left}"
    );
    let anna_notice = anna.run(&["recv"]);
    assert!(
        anna_notice.contains("bert verlässt die Gruppe"),
        "stdout war: {anna_notice}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Eine Einladung wird NICHT automatisch angenommen (Schutz vor
/// aufgezwungenen Gruppen), und ein Ablehnen verwirft sie samt Welcome,
/// ohne beizutreten. Eine Nachricht der Gruppe erreicht den Ablehnenden
/// dann nicht mehr als lesbaren Inhalt.
#[tokio::test(flavor = "multi_thread")]
async fn group_invite_can_be_declined() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-inv-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let ida = CliUser::new(&dir, "ida", &urls);
    let jan = CliUser::new(&dir, "jan", &urls);
    for (user, handle) in [(&ida, "ida"), (&jan, "jan")] {
        user.run(&["register", handle, "ein-langes-gruppen-passwort"]);
        user.run(&["login", "ein-langes-gruppen-passwort"]);
        user.run(&["publish-keys"]);
    }

    let created = ida.run(&["group-create", "jan"]);
    let group_id = created
        .split_whitespace()
        .nth(1)
        .expect("Gruppen-ID")
        .to_string();

    // jan holt ab: eine Einladung, kein Beitritt.
    let jan_recv = jan.run(&["recv"]);
    assert!(
        jan_recv.contains("eingeladen") && !jan_recv.contains("beigetreten"),
        "stdout war: {jan_recv}"
    );
    // Ablehnen: die Einladung ist weg, jan ist keiner Gruppe beigetreten.
    let declined = jan.run(&["group-decline", &group_id]);
    assert!(declined.contains("abgelehnt"), "stdout war: {declined}");
    assert!(
        jan.run(&["groups"]).contains("Keine Gruppen"),
        "jan darf keiner Gruppe beigetreten sein"
    );
    assert!(
        jan.run(&["invites"]).contains("Keine offenen Einladungen"),
        "die Einladung muss verschwunden sein"
    );

    // idas Gruppen-Nachricht erreicht jan nicht als lesbaren Inhalt
    // (er ist der Gruppe nie beigetreten), wird aber sauber verworfen.
    ida.run(&["group-send", &group_id, "hallo trotzdem"]);
    let jan_after = jan.run(&["recv"]);
    assert!(
        !jan_after.contains("hallo trotzdem"),
        "der Ablehnende darf den Inhalt nicht lesen, stdout war: {jan_after}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Wurzelschlüssel-Rotation (ADR-0010) über die echten Dienste: nach der
/// Rotation gilt der neue Schlüssel, ein danach gekoppeltes Gerät wird mit
/// ihm signiert und vom Dienst akzeptiert (der Beweis, dass der Server den
/// neuen Schlüssel übernommen hat und die alte Kette nicht mehr braucht).
#[tokio::test(flavor = "multi_thread")]
async fn root_key_rotation_takes_effect() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-rot-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let vera1 = CliUser::new(&dir, "vera1", &urls);
    vera1.run(&["register", "vera", "veras-langes-passwort"]);
    vera1.run(&["login", "veras-langes-passwort"]);
    vera1.run(&["publish-keys"]);

    // Rotieren: meldet, wie viele Geräte neu signiert wurden (hier eines).
    let rotated = vera1.run(&["rotate-key"]);
    assert!(
        rotated.contains("Wurzelschlüssel rotiert") && rotated.contains("1 Gerät"),
        "die Rotation muss das eine Gerät neu signieren, stdout war: {rotated}"
    );

    // Ein Zweitgerät koppeln: das Erstgerät signiert das Credential jetzt mit
    // dem NEUEN Wurzelschlüssel; der Dienst akzeptiert es nur, wenn er den
    // neuen Schlüssel übernommen hat.
    let vera2 = CliUser::new(&dir, "vera2", &urls);
    let link_out = vera2.run(&["link", "vera", "veras-langes-passwort"]);
    let payload = link_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("sm approve "))
        .expect("Kopplungs-Antrag")
        .to_string();
    let approved = vera1.run(&["approve", &payload]);
    assert!(
        approved.contains("Nummer 2"),
        "das Freischalten mit dem neuen Schlüssel muss klappen, stdout war: {approved}"
    );
    vera2.run(&["link-finish", "vera", "veras-langes-passwort"]);
    let devices = vera1.run(&["devices"]);
    assert!(
        devices.contains("Nummer 1") && devices.contains("Nummer 2"),
        "beide Geräte müssen nach der Rotation in der Menge stehen, stdout war: {devices}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Wiederaufnahme einer unterbrochenen Rotation (ADR-0010, Absturzsicherheit,
/// Finding aus der Selbstprüfung): Bricht der Client zwischen dem
/// Server-Commit und dem lokalen Ablegen ab, hält er den neuen Schlüssel als
/// `pending`. Der Dienst steht dann schon auf dem neuen Schlüssel; die
/// Kontinuitätssignatur des alten passt nicht mehr (invalid_continuity). Der
/// nächste `rotate-key` erkennt das, übernimmt den pending-Schlüssel lokal
/// und das Konto ist NICHT ausgesperrt. Ohne diese Wiederaufnahme wäre der
/// Wurzelschlüssel nach dem einen ungünstigen Abbruch dauerhaft verloren.
#[tokio::test(flavor = "multi_thread")]
async fn interrupted_rotation_resumes_without_lockout() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-rotresume-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    let vera1 = CliUser::new(&dir, "vera1", &urls);
    vera1.run(&["register", "vera", "veras-langes-passwort"]);
    vera1.run(&["login", "veras-langes-passwort"]);
    vera1.run(&["publish-keys"]);

    let read_profile = || -> serde_json::Value {
        let text = std::fs::read_to_string(&vera1.profile).expect("Profil lesbar");
        serde_json::from_str(&text).expect("Profil ist JSON")
    };

    // Den alten Wurzel-Seed festhalten, dann real rotieren: der Dienst steht
    // danach auf dem neuen Schlüssel.
    let k0 = read_profile()["account_seed"].as_str().unwrap().to_string();
    vera1.run(&["rotate-key"]);
    let k1 = read_profile()["account_seed"].as_str().unwrap().to_string();
    assert_ne!(k0, k1, "die Rotation muss den Wurzelschlüssel wechseln");

    // Absturz nach dem Server-Commit nachstellen: der Client denkt noch, der
    // ALTE Schlüssel sei gültig (account_seed = k0), hält aber den neuen als
    // pending (k1). Der Dienst steht bereits auf k1.
    let mut profile = read_profile();
    profile["account_seed"] = serde_json::Value::String(k0.clone());
    profile["pending_account_seed"] = serde_json::Value::String(k1.clone());
    std::fs::write(&vera1.profile, serde_json::to_string(&profile).unwrap())
        .expect("Profil schreibbar");

    // Wiederaufnahme: erkennt am invalid_continuity, dass der Dienst den neuen
    // Schlüssel schon hält, und übernimmt ihn lokal.
    let resumed = vera1.run(&["rotate-key"]);
    assert!(
        resumed.contains("Frühere Rotation abgeschlossen"),
        "die Wiederaufnahme muss den pending-Schlüssel übernehmen, stdout war: {resumed}"
    );
    let after = read_profile();
    assert_eq!(after["account_seed"].as_str().unwrap(), k1);
    assert!(
        after
            .get("pending_account_seed")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty(),
        "der pending-Seed muss nach dem Abschluss geleert sein"
    );

    // Beweis, dass das Konto nicht ausgesperrt ist: ein Zweitgerät koppeln;
    // das Erstgerät signiert mit dem übernommenen Schlüssel, der Dienst (auf
    // demselben Schlüssel) akzeptiert das Credential.
    let vera2 = CliUser::new(&dir, "vera2", &urls);
    let link_out = vera2.run(&["link", "vera", "veras-langes-passwort"]);
    let payload = link_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("sm approve "))
        .expect("Kopplungs-Antrag")
        .to_string();
    let approved = vera1.run(&["approve", &payload]);
    assert!(
        approved.contains("Nummer 2"),
        "nach der Wiederaufnahme muss das Freischalten klappen, stdout war: {approved}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Multi-Device-Gruppen: ein Konto mit zwei gekoppelten Geräten ist mit
/// BEIDEN in der Gruppe (jedes ein eigenes MLS-Leaf), und eine
/// Gruppennachricht erreicht auch das eigene Zweitgerät des Absenders. Das
/// ist der Kern von P4: der Fanout filtert nach Geräte-ID, nicht nach
/// Handle, und der Gründer lädt seine eigenen anderen Geräte mit ein.
#[tokio::test(flavor = "multi_thread")]
async fn group_reaches_own_second_device() {
    let urls = start_stack().await;
    let dir = std::env::temp_dir().join(format!("sm-mdgrp-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("Testverzeichnis");

    // Rosa mit zwei Geräten koppeln (wie second_device_receives_own_copy).
    let rosa1 = CliUser::new(&dir, "rosa1", &urls);
    rosa1.run(&["register", "rosa", "rosas-langes-passwort"]);
    rosa1.run(&["login", "rosas-langes-passwort"]);
    rosa1.run(&["publish-keys"]);
    let rosa2 = CliUser::new(&dir, "rosa2", &urls);
    let link_out = rosa2.run(&["link", "rosa", "rosas-langes-passwort"]);
    let payload = link_out
        .lines()
        .find_map(|l| l.trim().strip_prefix("sm approve "))
        .expect("Kopplungs-Antrag")
        .to_string();
    rosa1.run(&["approve", &payload]);
    rosa2.run(&["link-finish", "rosa", "rosas-langes-passwort"]);
    // Das Zweitgerät braucht eigene MLS-KeyPackages, um eingeladen zu werden.
    rosa2.run(&["publish-keys"]);

    // Timo als drittes Mitglied.
    let timo = CliUser::new(&dir, "timo", &urls);
    timo.run(&["register", "timo", "timos-langes-passwort"]);
    timo.run(&["login", "timos-langes-passwort"]);
    timo.run(&["publish-keys"]);

    // Rosa (Gerät 1) gründet die Gruppe mit timo. Dabei wird auch rosas
    // EIGENES Zweitgerät eingeladen.
    let created = rosa1.run(&["group-create", "timo"]);
    let group_id = created
        .split_whitespace()
        .nth(1)
        .expect("Gruppen-ID")
        .to_string();
    assert!(created.contains("rosa, timo"), "stdout war: {created}");

    // Timo nimmt an. Rosas Zweitgerät bekommt EBENFALLS eine Einladung
    // (vom eigenen Erstgerät) und nimmt an.
    timo.run(&["recv"]);
    timo.run(&["group-accept", &group_id]);
    let rosa2_recv = rosa2.run(&["recv"]);
    assert!(
        rosa2_recv.contains("eingeladen"),
        "rosas Zweitgerät muss eine Einladung bekommen, stdout war: {rosa2_recv}"
    );
    let rosa2_accept = rosa2.run(&["group-accept", &group_id]);
    assert!(
        rosa2_accept.contains("beigetreten"),
        "rosas Zweitgerät muss beitreten, stdout war: {rosa2_accept}"
    );
    rosa2.run(&["recv"]);

    // Rosa sendet vom Erstgerät. Die Nachricht muss timo UND das eigene
    // Zweitgerät erreichen (Fanout nach Geräte-ID).
    rosa1.run(&["group-send", &group_id, "hallo von rosa eins"]);
    let timo_reads = timo.run(&["recv"]);
    assert!(
        timo_reads.contains("rosa: hallo von rosa eins"),
        "timo muss die Nachricht lesen, stdout war: {timo_reads}"
    );
    let rosa2_reads = rosa2.run(&["recv"]);
    assert!(
        rosa2_reads.contains("rosa: hallo von rosa eins"),
        "das eigene Zweitgerät muss die Gruppennachricht bekommen, stdout war: {rosa2_reads}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
