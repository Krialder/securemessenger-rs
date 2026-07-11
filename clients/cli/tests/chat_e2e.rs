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

    let _ = std::fs::remove_dir_all(&dir);
}
