# Scripts

Skripte, um die Entwicklungsumgebung einzurichten und die Dienste plus Web-Client zu starten. Es gibt genau zwei Einstiege, beide bauen auf derselben geteilten Prüf- und Reparatur-Logik auf (`lib-checks.ps1`):

- **Grafisch (Doppelklick):** `SecureMessenger.cmd` im Projekt-Root öffnet das eine App-Fenster `scripts/sm-gui.ps1`.
- **Konsole (Entwickler):** `scripts/sm.ps1` aus einem PowerShell-Terminal.

## SecureMessenger.cmd (grafisch, ein Fenster für alles)

`SecureMessenger.cmd` öffnet `scripts/sm-gui.ps1`, eine WPF-Oberfläche im Stil des Web-Clients (Segoe UI, das App-Blau `#0078D7`, abgerundete Ecken). Der Ablauf im Fenster:

1. **Prüfen:** Beim Öffnen prüft die Oberfläche automatisch die ganze Umgebung und zeigt je Punkt den Zustand (Werkzeuge, Docker, Datenbank, Build).
2. **Auswählen:** Was fehlt oder veraltet ist, bekommt eine vorausgewählte Haken-Auswahl `installieren`/`aktualisieren`. Das schließt schwere Werkzeuge wie Rust, MSVC, WSL und Docker ein, damit dieses eine Fenster auch die Erstinstallation übernimmt.
3. **Starten:** Ein Klick auf den Hauptknopf erledigt die Auswahl und startet danach den Container-Stack samt Web-Client (`http://localhost:3000`).
4. **Anhalten:** Ein `Beenden`-Knopf hält die laufende Umgebung wieder an.

Die langen Schritte (winget, cargo build) laufen in einem Hintergrund-Runspace und melden über eine synchronisierte Warteschlange an einen DispatcherTimer, damit die Oberfläche nie einfriert. Der eigentliche Start läuft über `sm.ps1` (dieselbe eine Startlogik wie die Konsole).

## sm.ps1 (Konsole)

Aus einem PowerShell-Terminal im Projekt-Root (auf einem frischen Rechner mit noch strenger ExecutionPolicy vorweg `powershell -ExecutionPolicy Bypass -File scripts\sm.ps1 ...`):

```powershell
scripts\sm.ps1            # startet den Verbund als Container-Stack (docker compose, Produktionsmodus)
scripts\sm.ps1 -Web       # zusaetzlich der Web-Client (http://localhost:3000)
scripts\sm.ps1 -Sso       # zusaetzlich Keycloak (SSO, Port 8090)
scripts\sm.ps1 -Calls     # zusaetzlich coturn fuer 1:1-Anrufe (F2)
scripts\sm.ps1 -Stop      # faehrt den Stack herunter (Daten bleiben)
scripts\sm.ps1 -Reset     # loescht vorher die Daten-Volumes (down -v)
scripts\sm.ps1 -Setup     # richtet nur ein und aktualisiert, ohne zu starten
```

Die Geheimnisse des Stacks liegen in einer lokalen `.env` im Projekt-Root (nicht eingecheckt, Vorlage `.env.example`); fehlt sie, erzeugt `sm.ps1` sie beim ersten Start mit starken Zufallswerten. Details zum Stack in [deploy/compose/README.md](../deploy/compose/README.md); die echten Kubernetes-Manifeste laufen lokal über `deploy\kind\up.ps1`.

Erststart auf einem frischen Rechner: einmal `scripts\sm.ps1 -Setup` (oder gleich die GUI `SecureMessenger.cmd`, die das ohne ExecutionPolicy-Vorspann erledigt), dann `scripts\sm.ps1`.

`sm.ps1 -Setup` richtet die Umgebung idempotent ein und delegiert dafür an die geteilte Bibliothek `lib-checks.ps1` (dieselbe, die auch die GUI nutzt, damit die Logik nicht doppelt gepflegt wird):

1. **Werkzeuge:** winget, Rust (`cargo`), MSVC Build Tools (Linker für den nativen Build), protoc, das Rust-Target `wasm32-unknown-unknown` (Web-Client), trunk (WASM-Bündler), WSL und Docker.
2. **Rust-Komponenten:** rustfmt und clippy für Format- und Lint-Prüfung.
3. **Docker-Daemon** starten, falls nicht erreichbar (bis zu 120 s Wartezeit).
4. **Entwicklungs-Datenbank:** Container `sm-postgres` (postgres:17-alpine, Passwort `dev`, Port 5432) mit einer Datenbank je Dienst (`identity`, `directory`, `delivery`, `integrations`, `kt`), jeder Dienst braucht seine eigene, sonst kollidieren die sqlx-Migrationstabellen (siehe [ENTWICKLUNG.md](../ENTWICKLUNG.md)). Wegwerf-Instanz: `docker rm -f sm-postgres` setzt alles zurück.

Die Installationen können einen UAC-Dialog auslösen, das ist beim ersten Lauf normal.

## Bibliotheken (nicht direkt starten)

- `lib-checks.ps1`: die eine Wahrheit über den Zustand der Umgebung. Jede Komponente trägt einen Check-Block (liest den Zustand: ok/missing/outdated) und einen idempotenten Fix-Block (installiert/repariert). GUI und Konsole iterieren dieselbe Liste.
- `lib-gui.ps1`: die WPF-Bausteine (Farbthema, XAML-Lader, die Hintergrund-Runspace-Mechanik).

Beide werden per Dot-Sourcing eingebunden, nicht direkt aufgerufen.

## Danach bauen (manuell)

```
cargo test --workspace          # PG-Tests brauchen die TEST_DATABASE_URL*-Variablen, siehe ENTWICKLUNG.md
cargo run -p identity           # ebenso: directory, delivery, integrations, media
docker build -f deploy/docker/Dockerfile --build-arg SERVICE=identity -t securemessenger/identity:dev .
```
