# Scripts

Skripte, um die Entwicklungsumgebung aufzusetzen und Dienste zu starten, die laufen müssen. Es gibt zwei Wege: die grafischen Doppelklick-Anwendungen (`install.cmd`, `SecureMessenger.cmd`) für den geführten Einstieg und die Konsolen-Skripte für Entwickler.

## Grafischer Einstieg: install.cmd und SecureMessenger.cmd (im Projekt-Root)

`install.cmd` öffnet den Installations-Assistenten (`scripts/install-gui.ps1`), eine WPF-Oberfläche im Stil des Web-Clients (Segoe UI, das App-Blau `#0078D7`, abgerundete Ecken). Sie läuft die Einrichtungsschritte als Liste mit Live-Status ab: Werkzeuge prüfen, Fehlendes installieren, Docker und die Datenbank hochfahren, das Projekt bauen. `SecureMessenger.cmd` öffnet die Start-Anwendung (`scripts/start-gui.ps1`): sie prüft beim Öffnen die Umgebung, verweist bei fehlenden schweren Werkzeugen auf den Assistenten, bietet für Veraltetes eine Haken-Auswahl "aktualisieren" an und startet sonst direkt (ein Messenger-Fenster auf `http://localhost:3000`, im Vorführmodus zusätzlich Bob auf 3001).

Die eigentliche Prüf- und Reparaturlogik liegt einmal in `scripts/lib-checks.ps1` (die geteilte Wahrheit über den Zustand: Werkzeuge, Docker, Datenbank, ob die Programme aktuell gebaut sind), die WPF-Bausteine in `scripts/lib-gui.ps1`. Beide GUIs erledigen die langen Schritte in einem Hintergrund-Runspace und halten die Oberfläche über einen DispatcherTimer bedienbar. Der Start selbst läuft über `demo.ps1` (dieselbe eine Startlogik).

## start.cmd (im Projekt-Root)

Der Konsolen-Einstieg für Entwickler. Ruft `scripts/setup.ps1` mit gelockerter ExecutionPolicy auf, sodass das Setup ohne Vorkonfiguration läuft. Ein Konsolenfenster öffnet sich und bleibt bis zum Tastendruck offen. Deckt dieselben Werkzeuge ab wie der Assistent, nur ohne Oberfläche.

## setup.ps1

Richtet die Umgebung ein, idempotent (schon Vorhandenes wird übersprungen):

1. **Prüft die Werkzeuge:** winget, Rust (`cargo`), MSVC Build Tools (Linker für den nativen Build), protoc, das Rust-Target `wasm32-unknown-unknown` (Web-Client), trunk (WASM-Bündler), WSL und Docker.
2. **Installiert Fehlendes:** Rust über winget (`Rustlang.Rustup`), MSVC Build Tools, protoc von GitHub nach `%LOCALAPPDATA%\protoc` (braucht der Krypto-Kern für den libsignal-Build), das wasm32-Target, trunk, bei Bedarf WSL und Docker Desktop (`Docker.DockerDesktop`).
3. **Rüstet Rust-Komponenten nach:** rustfmt und clippy für die Format- und Lint-Prüfung (`cargo fmt`, `cargo clippy`).
4. **Startet Docker Desktop**, wenn der Daemon nicht erreichbar ist, und wartet bis zu 120 Sekunden, bis er bereit ist.
5. **Legt die Entwicklungs-Datenbank an:** Container `sm-postgres` (postgres:17-alpine, Passwort `dev`, Port 5432) mit einer Datenbank je Dienst (`identity`, `directory`, `delivery`, `integrations`, `kt`) - jeder Dienst braucht seine eigene, sonst kollidieren die sqlx-Migrationstabellen (siehe [ENTWICKLUNG.md](../ENTWICKLUNG.md)). Wegwerf-Instanz: `docker rm -f sm-postgres` setzt alles zurück.

Am Ende steht eine Statusübersicht und die nächsten Build-Befehle. Die Installationen können einen UAC-Dialog auslösen, das ist beim ersten Lauf normal. Falls Rust frisch installiert wurde, ist `cargo` erst in einem neuen Terminal im PATH; die `PROTOC`-Variable gilt nur für die Setup-Sitzung, dauerhaft setzt sie `setx PROTOC "%LOCALAPPDATA%\protoc\bin\protoc.exe"`.

## demo.ps1 und demo-stop.ps1

Die Vorführ-Umgebung mit einem Befehl: `demo.ps1` startet die vier Kern-Dienste (identity 8080, directory 8081, delivery 8082, kt 8083) mit eigenen `demo_*`-Datenbanken und deterministischen Demo-Schlüsseln, dazu zwei Web-Clients über trunk (Alice http://localhost:3000, Bob http://localhost:3001). Jeder Prozess bekommt ein eigenes Fenster, weil die Logs Teil der Vorführung sind. `-Reset` löscht die Demo-Datenbanken vorher (frische Vorführung), `-NoWeb` lässt die Web-Clients weg. `demo-stop.ps1` beendet alles wieder: erst über die festgehaltenen Prozess-IDs, dann über die Fenstertitel (`sm-demo-*`), damit auch von Hand nachgestartete Prozesse fallen. Das Drehbuch der Vorführung steht in [DEMO.md](../DEMO.md).

## Danach bauen

```
cargo test --workspace          # PG-Tests brauchen die TEST_DATABASE_URL*-Variablen, siehe ENTWICKLUNG.md
cargo run -p identity           # ebenso: directory, delivery, integrations, media
docker build -f deploy/docker/Dockerfile --build-arg SERVICE=identity -t securemessenger/identity:dev .
```
