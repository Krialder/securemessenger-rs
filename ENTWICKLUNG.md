# Entwicklung

Aufbau und Bauanleitung für den Code des SecureMessengers. Die fachliche Doku liegt in [dokumentation/](dokumentation/), dieses Dokument betrifft nur das Bauen und die Struktur.

## Verzeichnisstruktur

```
Cargo.toml            Workspace-Wurzel (gepinnte Dependencies, Dev-Profil für Argon2)
rust-toolchain.toml   gepinnte Rust-Version (1.96.1)
crates/
  common/             gemeinsame Bausteine (Config, Telemetrie, Betriebs-Endpunkte, identity-Anbindung), ohne Krypto
  kt-format/          kanonische KT-Byte-Formate (Commitment smktc.v1, Wurzelnachricht smkt.v1), geteilt zwischen
                      Server und Clients (auch wasm32); Feature verify liefert die akd-Konfiguration samt Domain-Label
  client-core/        der Krypto-Kern der Clients (libsignal, OpenMLS, gepinnt); kein Dienst hängt davon ab
    src/onetoone.rs   1:1-Sitzungen: PQXDH-Aufbau, Double Ratchet, Safety Number (Wrapper, keine Eigenbauten)
    src/group.rs      MLS-Gruppen: Suite 0x0003, Skipped-Keys-Fenster (Wrapper)
    tests/roundtrips.rs  Integrations-Beweise: PQXDH+Ratchet-Roundtrip, MLS-Gruppen-Roundtrip
  client-app/         Protokoll-Orchestrierung der Clients (GOAL.md): HTTP gegen die Dienste, keine UI, baut nativ und nach wasm32
    src/account.rs    Konto-Wurzelschlüssel (Ed25519) und Geräte-Credential smdc.v1 (Client-Seite)
    src/identity.rs   Client des identity-Dienstes (Registrierung, Login, Rotation, Logout)
    src/directory.rs  Client des Schlüssel-Verzeichnisses (Prekeys veröffentlichen, Bündel holen)
    src/delivery.rs   Client der Zustellung (einreichen, abholen, bestätigen) plus WS-Rahmenvertrag (ws_url, Auth-Frame, Events)
    src/prekeys.rs    Blob-Codec smpk.v1: libsignal-PreKeyBundle in Verzeichnis-Blobs und zurück
    src/wire.rs       Hüllen-Framing smenv.v1 um den libsignal-Chiffretext
    src/storage.rs    Storage-Trait der lokalen Ablage (In-Memory, JSON-Datei; IndexedDB folgt)
    src/protocol_store.rs   libsignals fünf Store-Traits über dem Storage-Trait: Sitzungen überleben Prozessgrenzen
    src/kt.rs         KT-Client und Selbstprüfung: Wurzelsignatur, Wurzelbindung, Inklusionsbeweis, Commitment-Vergleich
    tests/account_e2e.rs    End-to-End gegen den echten identity-Router (in-process)
    tests/messaging_e2e.rs  End-to-End über identity+directory+delivery: PQXDH, E2EE-Umlauf, Ablage ohne Klartext
    tests/kt_e2e.rs   End-to-End über identity+kt: Selbstprüfung besteht, untergeschobener Schlüssel schlägt Alarm
clients/
  cli/                Headless-Referenzclient `sm`: register/login/logout/whoami/publish-keys/send/recv/listen/verify
    tests/chat_e2e.rs Chat-Beweis (jeder Befehl ein eigener Prozess, Dienste in-process) plus Hinweiskanal-Beweis (listen --once)
  web/                Leptos-Web-Client (WASM, CSR): nur Darstellung, Krypto und Protokoll kommen aus den Crates
    src/main.rs       Einstieg mit cfg-Weiche: nativ nur ein Stub, damit `cargo test --workspace` nicht am Browser-Code hängt
    src/app.rs        Oberfläche und Ablaufsteuerung: Konto anlegen, anmelden (nach Neuladen), senden, abrufen
    src/storage.rs    IndexedDB hinter dem Storage-Trait: In-Memory-Spiegel, asynchroner Flush des Gesamtzustands
services/
  identity/           Identitäts- und Auth-Dienst (Fundament, Phase 1)
    migrations/       SQL-Migrationen, von sqlx beim Start eingebettet ausgeführt
    src/api.rs        HTTP-Schicht: Router, Handler, Validierung (inkl. /internal-Routen)
    src/auth.rs       Argon2id-Hashing, Token-Erzeugung und -Hashing (geprüfte Bibliotheken, NF040)
    src/credential.rs Prüfung der Geräte-Credentials (Ed25519-Signaturverifikation; Geräteschlüssel opak nach ADR-0009)
    src/domain.rs     Fachmodell (Account, Device)
    src/pg.rs         PostgreSQL-Umsetzung der Stores (sqlx)
    src/session.rs    Session-Familien: Access-/Refresh-Rotation, Reuse-Erkennung, gerätegebunden (F020)
    src/store.rs      Speicher-Abstraktion (Trait) plus In-Memory-Umsetzung
    tests/api.rs      Integrationstests der HTTP-Schicht (In-Memory)
    tests/pg.rs       Integrationstests gegen echtes PostgreSQL (nur mit TEST_DATABASE_URL)
    tests/helpers/    geteilte Test-Helfer: die Client-Seite der API
  directory/          Schlüssel-Verzeichnis: Prekey-Pools und Bündel-Abruf (F110)
    migrations/       eigene Datenbank, eigene Migrationen (prekeys-Tabelle)
    src/api.rs        HTTP-Schicht: Upload, Zählstände, Bündel-Abruf
    src/domain.rs     Fachmodell (PrekeyKind, Prekey, DeviceBundle, PoolCounts)
    src/pg.rs         PostgreSQL-Umsetzung (FOR UPDATE SKIP LOCKED für Einmal-Prekeys)
    src/store.rs      Speicher-Abstraktion plus In-Memory-Umsetzung
    tests/api.rs      Integrationstests mit Fake-identity-Gateway
    tests/pg.rs       PG-Tests inkl. Nebenläufigkeits-Beweis (nur mit TEST_DATABASE_URL_DIRECTORY)
  delivery/           Zustelldienst: Store-and-Forward plus Echtzeit-Hinweise (F050)
    migrations/       eigene Datenbank (messages partitioniert, message_dedupe)
    src/api.rs        HTTP-Schicht: Einreichen, Abholen, Bestätigen, WebSocket /ws, /internal-Routen
    src/domain.rs     Fachmodell (NewMessage, WaitingMessage, StoreOutcome)
    src/hub.rs        In-Prozess-Verteiler für Echtzeit-Ereignisse (tokio broadcast)
    src/pg.rs         PostgreSQL-Umsetzung (Monatspartitionen, Dedupe-Tabelle)
    src/store.rs      Speicher-Abstraktion plus In-Memory-Umsetzung
    tests/api.rs      Integrationstests inkl. WebSocket über echten TCP-Port
    tests/pg.rs       PG-Tests inkl. Partitions-Nebenläufigkeit (nur mit TEST_DATABASE_URL_DELIVERY)
  integrations/       Basis-Dienste für Fremdprojekte: Benachrichtigung, Präsenz, Mandanten (F070/F080/F100)
    migrations/       eigene Datenbank (integration_tenants, integration_tokens)
    src/api.rs        HTTP-Schicht: Token-Tausch, notify, presence, interne Mandanten-Anlage
    src/auth.rs       Argon2id für Client-Secrets, SHA-256 für Mandanten-Tokens
    src/domain.rs     Fachmodell (Tenant, Scopes)
    src/pg.rs         PostgreSQL-Umsetzung des TenantStore
    src/realtime_client.rs  Anbindung an delivery: Events stoßen, Präsenz abfragen
    src/store.rs      Speicher-Abstraktion plus In-Memory-Umsetzung
    tests/api.rs      Integrationstests mit Fake-identity und Fake-delivery
    tests/pg.rs       PG-Tests (nur mit TEST_DATABASE_URL_INTEGRATIONS)
  media/              Medien-Dienst: verschlüsselte Blobs im Objektspeicher (F180)
    src/api.rs        HTTP-Schicht: Upload (roher Body), Download über Referenz
    tests/api.rs      Integrationstests mit In-Memory-Objektspeicher
  kt/                 Key Transparency: prüfbares Schlüssel-Log (F120)
    migrations/       eigene Datenbank (kt_updates append-only, kt_epochs signierte Wurzeln)
    src/api.rs        HTTP-Schicht: Beweise, Historie, Epochen, /internal/updates
    src/directory.rs  akd-Verzeichnis (AZKS): Wiederaufbau aus dem Log, Epochen-Veröffentlichung
    src/keys.rs       Ed25519-Wurzelsignatur und VRF (per Spec erlaubte Server-Schlüssel)
    src/pg.rs         PostgreSQL-Umsetzung, die Quelle der Wahrheit
    src/store.rs      Speicher-Abstraktion plus In-Memory-Umsetzung
    tests/api.rs      Integrationstests inkl. Client-seitiger Beweis-Verifikation
    tests/pg.rs       PG-Tests inkl. Wiederaufbau-Determinismus (nur mit TEST_DATABASE_URL_KT)
deploy/
  docker/             generisches Multi-Stage-Dockerfile
  k8s/                Kubernetes-Manifeste
scripts/              Setup der Entwicklungsumgebung (start.cmd im Root)
```

Jeder Backend-Dienst ist ein eigenes Binary unter `services/` mit einem Bibliotheksteil für Tests und teilt sich die Querschnitts-Bausteine aus `crates/common`. Weitere Dienste kommen phasenweise dazu, jeder nach demselben Muster wie `identity`.

## Bauen und testen

```
cargo build               # alles
cargo test --workspace    # Unit- und Integrationstests
cargo fmt --all           # formatieren
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p identity     # Dienst starten
```

Argon2 ist in Debug-Builds sonst unbrauchbar langsam, deshalb baut das Dev-Profil die Krypto-Pakete optimiert (siehe `profile.dev.package` in der Workspace-Cargo.toml).

Für den Krypto-Kern (`crates/client-core`) braucht der Build zusätzlich `protoc` (libsignal kompiliert seine Protobuf-Schemas beim Bauen). `scripts/setup.ps1` installiert es nach `%LOCALAPPDATA%\protoc` und setzt `PROTOC`; die Backend-Dienste bauen auch ohne, weil kein Dienst vom Krypto-Kern abhängt (das Docker-Build baut nur `-p <dienst>`).

Der Web-Client (`clients/web`) baut mit `trunk` nach wasm32 (beides installiert `scripts/setup.ps1`):

```
cd clients/web
trunk build     # einmaliger Build nach dist/
trunk serve     # Dev-Server; proxyt /api/* auf die lokalen Dienste (Trunk.toml)
```

Nativ kompiliert `sm-web` nur zu einem erklärenden Stub: der Browser-Code existiert ausschließlich für wasm32, damit `cargo test --workspace` weder Leptos für den Host bauen muss noch an dessen Send-Anforderungen scheitern kann (Begründung in `clients/web/src/main.rs`).

Ohne lokale Toolchain baut Docker im Container:

```
docker build -f deploy/docker/Dockerfile --build-arg SERVICE=identity -t securemessenger/identity:dev .
```

Die CI (`.github/workflows/ci.yml`) fährt dieselbe Kette: `cargo fmt --check`, Clippy mit `-D warnings`, die komplette Testsuite inklusive PG-Integrationstests (Service-Container, eine Datenbank je Dienst) und die Docker-Builds aller Dienste. Der Kubernetes-Zusammenbau liegt in `deploy/k8s` (`kubectl apply -k`), Details in [deploy/README.md](deploy/README.md).

## Persistenz (PostgreSQL)

Die Dienste sprechen ihre Ablage nur über Traits an (`store.rs`, `session.rs`). Zwei Umsetzungen:

- Ohne `DATABASE_URL` startet der Dienst mit prozesslokaler In-Memory-Ablage und warnt im Log. Gut für schnelles Entwickeln, Daten enden mit dem Prozess.
- Mit `DATABASE_URL` (z. B. `postgres://postgres:dev@localhost:5432/identity`) persistiert der Dienst in PostgreSQL. Beim Start laufen die eingebetteten Migrationen aus `services/identity/migrations/`; schlägt Verbindung oder Migration fehl, bricht der Start ab, statt still ohne Persistenz zu laufen.

Lokale Datenbank für Entwicklung und Tests:

```
docker run -d --name sm-postgres -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=identity -p 5432:5432 postgres:17-alpine
```

Die PG-Integrationstests (`tests/pg.rs`) laufen nur, wenn `TEST_DATABASE_URL` gesetzt ist, sonst werden sie still übersprungen; `cargo test` bleibt also auch ohne Datenbank grün. Vor einem Commit, der die Ablage berührt, einmal mit Datenbank laufen lassen:

```
$env:TEST_DATABASE_URL = "postgres://postgres:dev@localhost:5432/identity"
cargo test -p identity --test pg
```

Die Tests räumen nicht auf, sondern nutzen eindeutige Handles pro Lauf; die Wegwerf-Datenbank lässt sich jederzeit mit `docker rm -f sm-postgres` neu aufsetzen. Beide Store-Umsetzungen müssen dieselbe Semantik zeigen, die Trait-Tests in `store.rs` und `tests/pg.rs` prüfen deshalb dieselben Fälle (globale Geräte-ID-Eindeutigkeit, Revocation ohne Löschen, Reuse-Erkennung).

Jeder Dienst hat seine eigene Datenbank (siehe [architektur.md](dokumentation/architektur.md)); schon deshalb, weil sich sonst die sqlx-Migrationstabellen der Dienste in die Quere kämen. Für directory, delivery, integrations und kt also einmalig anlegen und je eine weitere Variable setzen:

```
docker exec sm-postgres psql -U postgres -c "CREATE DATABASE directory"
docker exec sm-postgres psql -U postgres -c "CREATE DATABASE delivery"
docker exec sm-postgres psql -U postgres -c "CREATE DATABASE integrations"
docker exec sm-postgres psql -U postgres -c "CREATE DATABASE kt"
$env:TEST_DATABASE_URL_DIRECTORY = "postgres://postgres:dev@localhost:5432/directory"
$env:TEST_DATABASE_URL_DELIVERY = "postgres://postgres:dev@localhost:5432/delivery"
$env:TEST_DATABASE_URL_INTEGRATIONS = "postgres://postgres:dev@localhost:5432/integrations"
$env:TEST_DATABASE_URL_KT = "postgres://postgres:dev@localhost:5432/kt"
cargo test -p directory --test pg
cargo test -p delivery --test pg
cargo test -p integrations --test pg
cargo test -p kt --test pg
```

## Endpunkte des identity-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `POST /accounts` | Konto samt erstem Gerät anlegen (Handle, Passwort, Identitätsschlüssel, Geräte-Credential); 201, 400, 409 |
| `POST /sessions` | Login mit Handle, Passwort und Geräte-ID, liefert Access- und Refresh-Token (OAuth-Feldnamen); 200, 401 |
| `POST /sessions/refresh` | rotiert das Token-Paar und entwertet das alte; 200, 401 |
| `DELETE /sessions` | Logout über `Authorization: Bearer <token>`, widerruft die Session-Familie; immer 204 |
| `GET /devices` | gültige Gerätemenge des eigenen Kontos; 200, 401 |
| `POST /devices` | weiteres Gerät freischalten (Credential vom Konto-Identitätsschlüssel signiert); 201, 400, 401, 409 |
| `DELETE /devices/{id}` | Gerät revozieren, widerruft dessen Sessions; das eigene Gerät nicht (409); 204, 401, 404 |
| `POST /internal/introspect` | Dienst-zu-Dienst: Access-Token zur Identität auflösen (RFC-7662-Zuschnitt); nur mit `INTERNAL_TOKEN` |
| `GET /internal/accounts/{handle}/devices` | Dienst-zu-Dienst: Identitätsschlüssel und gültige Gerätemenge eines Kontos |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte für Kubernetes und Prometheus |

Fehler kommen als JSON mit `code` und `message` (siehe [schnittstellen.md](dokumentation/schnittstellen.md)). Sessions: Access-Token 15 Minuten, Refresh-Token 30 Tage, jede Rotation entwertet das alte Paar, und ein wiederverwendetes Refresh-Token widerruft die ganze Familie (Diebstahl-Indiz nach OAuth 2.0 Security BCP). Die Laufzeiten sind eine Annahme, die Doku gibt keine Werte vor.

Sessions sind gerätegebunden: der Login braucht eine registrierte, nicht revozierte Geräte-ID, und das Revozieren eines Geräts widerruft dessen Sessions sofort. Geräte-IDs sind client-erzeugte UUIDs in kanonischer Form und global eindeutig; nach einer Revocation bleibt die ID gesperrt, damit alte signierte Credentials nicht wieder gültig werden können. Geräte-Credentials signiert der Client mit dem Konto-Identitätsschlüssel (Ed25519); der Server verifiziert nur (verify_strict) und hält keine privaten Schlüssel. Das Credential-Format `smdc.v1` in `src/credential.rs` ist eine markierte Annahme, die Spec lässt das Format offen.

Die `/internal`-Routen sind Dienst-zu-Dienst-Schnittstellen und dürfen nie öffentlich erreichbar sein: abgesichert über ein Shared Secret im Header `x-internal-token` (Umgebungsvariable `INTERNAL_TOKEN` bei beiden Diensten). Ohne konfiguriertes Secret hängt der Router die Routen gar nicht erst ein (404). So bleibt die Session-Ablage privat beim identity-Dienst, statt dass andere Dienste in seine Datenbank greifen. [ANNAHME: Shared Secret statt mTLS; im Cluster übernimmt später ein Service Mesh oder NetworkPolicy die Netztrennung, siehe Etappe Betrieb.]

## Endpunkte des directory-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `POST /keys/prekeys` | Prekeys des eigenen Geräts hochladen (signierte rotieren, Einmal-Prekeys füllen den Pool); 200 mit Restbestand, 400, 401, 409 |
| `GET /keys/prekeys` | Zählstände der eigenen Einmal-Pools, fürs Nachfüllen durch den Client; 200, 401 |
| `GET /keys/{handle}` | Prekey-Bündel aller gültigen Geräte eines Kontos; konsumiert je einen Einmal-Prekey pro Gerät; 200, 401, 404 |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte |

Der Dienst kennt keine Passwörter und keine Sessions: Bearer-Tokens prüft er über `POST /internal/introspect` beim identity-Dienst (`IDENTITY_URL` plus `INTERNAL_TOKEN`), die Gerätemenge eines Kontos holt er von dort. Prekeys sind für den Server opake Blobs (Base64) mit client-erzeugter UUID; er interpretiert sie nie (Krypto liegt im Client-Core). Ist identity nicht erreichbar, antwortet directory mit 500 - nie mit 401, damit Clients nicht fälschlich ausloggen. Vier Prekey-Arten: `signed`, `one_time`, `pq_signed`, `pq_one_time` (PQXDH braucht klassische und Post-Quantum-Schlüssel, siehe [krypto-kern.md](dokumentation/specs/krypto-kern.md)). Einmal-Prekeys werden beim Bündel-Abruf atomar konsumiert (`FOR UPDATE SKIP LOCKED`), derselbe Schlüssel geht nie an zwei Abrufer. [ANNAHME: Bündel-Abruf nur mit Konto-Session; Rate-Limits pro Abrufer folgen mit der Edge-Etappe. Upload-Batch max. 500 Einträge.] Die Anbindung an identity (`IdentityGateway`, Introspektion plus Gerätemenge) liegt als wiederverwendbarer Baustein in `crates/common/src/identity_client.rs`.

## Endpunkte des delivery-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `POST /messages` | verschlüsselte Hüllen einreichen, Fan-out an alle Geräte des Empfängers; idempotent über client-erzeugte Hüllen-IDs; 200 mit `accepted`/`duplicates`, 400, 401, 404 |
| `GET /messages` | wartende Hüllen des eigenen Geräts abholen (bis 100, Eingangsreihenfolge); entfernt nichts; 200, 401 |
| `POST /messages/ack` | abgeholte Hüllen bestätigen und löschen; idempotent; 200 mit `removed`, 400, 401 |
| `POST /groups` | Gruppe anlegen (client-erzeugte UUID, Mitglieder als Handles, aufgelöst zu Zielgeräten); 201 mit `epoch`/`devices`, 400, 401, 409 |
| `POST /groups/{id}/commit` | Commit serialisieren: passt `from_epoch`, Epoche +1, Mitgliederliste ersetzt, Fan-out; 200 mit `epoch`, 409 `stale_epoch` mit `current_epoch`, 400, 401, 404 |
| `POST /groups/{id}/messages` | Anwendungsnachricht an die Mitglieds-Geräte fächern; nur bekannte Mitglieder; 200 mit `accepted`/`duplicates`, 400, 401, 404 |
| `GET /ws` | WebSocket für Echtzeit-Hinweise; erster Frame `{"token":"..."}` binnen 10 s, danach `{"event":"message.waiting"}`-Hinweise und `integration.notification`-Events; Close 4401 bei Auth-Fehlern, 1011 bei internen Fehlern |
| `POST /internal/events` | Dienst-zu-Dienst (integrations): Event an verbundene Geräte verteilen; nur mit `INTERNAL_TOKEN` |
| `POST /internal/presence/query` | Dienst-zu-Dienst: welche Geräte sind gerade verbunden (Grundlage von F080) |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte |

Der Dienst speichert nur opake, Ende-zu-Ende-verschlüsselte Hüllen (Base64, max. 64 KiB) bis zur Bestätigung durch das Empfängergerät - nie Klartext und keinen Absender. Empfänger werden pro Handle über die interne identity-API zu Konto-UUID und Gerätemenge aufgelöst; jede Hülle adressiert genau ein Gerät (der Client legt pro Zielgerät eine Hülle mit eigener UUID an, so funktioniert Multi-Device-Fan-out). Wiederholte Einreichungen derselben Hüllen-ID sind Erfolg, kein Fehler: die Dedupe-Tabelle erkennt sie auch nach der Zustellung noch. Der WebSocket transportiert ausschließlich Weck-Hinweise und markierte Maschinen-Benachrichtigungen, nie Chat-Inhalte; Clients holen nach jedem Hinweis (und nach jedem Verbinden) per `GET /messages` ab und bestätigen per Ack. Verbundene Sockets bilden zugleich die Präsenz: delivery führt prozesslokal Buch, welche Geräte verbunden sind, und beantwortet darüber die interne Präsenz-Abfrage. [ANNAHME: Einreichen ist bis zur Sealed-Sender-Etappe Bearer-authentifiziert; der Absender wird dabei nur geprüft, nie gespeichert. Batch max. 100 Hüllen. Hinweise laufen In-Prozess (tokio broadcast); ein Message-Bus für Multi-Replik-Betrieb folgt mit der Skalierungs-Etappe.]

## Endpunkte des integrations-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `POST /integrations/token` | Client-Credentials (client_id, client_secret) gegen ein kurzlebiges Mandanten-Token tauschen; 200, 401 |
| `POST /integrations/{tenant}/notify` | markierte Maschinen-Benachrichtigung an alle Geräte eines Nutzers (F070); 200 mit `devices`/`connected`, 400, 401, 403, 404, 429 |
| `GET /integrations/{tenant}/presence/{handle}` | Online-Status eines Nutzers (F080); 200 mit `online`, 401, 403, 404, 429 |
| `POST /internal/tenants` | Betriebs-Route: Mandant anlegen, liefert das Client-Secret genau einmal; nur mit `INTERNAL_TOKEN`; 201, 400, 401, 409 |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte |

Jedes Fremdprojekt ist ein Mandant (F100) mit eigenem Client-Secret (Argon2id-Hash in der Ablage, Klartext nur einmal bei der Anlage sichtbar), eigenen Scopes (`notify`, `presence`) und eigenem Rate-Limit (Standard 60/min, 429 mit `Retry-After`). Ein Token von Projekt A funktioniert nie unter dem Pfad von Projekt B (403 `tenant_mismatch`). Benachrichtigungen sind bewusst minimal: das Event trägt Mandant und Titel, sonst nichts - die Details holt der Nutzer im Fremdprojekt (pflichtenheft.md 5.2 "ehrlich abgegrenzt"). Die Zustellung läuft über die internen delivery-Routen an verbundene Geräte; nicht verbundene Geräte verpassen den Hinweis (Hinweis-Semantik, der Stand lebt im Fremdprojekt). [ANNAHME: Token-Laufzeit 1 Stunde; Rate-Limit als In-Prozess-Zähler bis Redis in den Stack kommt; Präsenz-Freigabe pauschal an, bis Nutzer-Einstellungen das Opt-out ergänzen; Mandanten legt der Betrieb über die interne Route an. SSO (F060) kommt als Keycloak-Deployment (deploy/k8s/keycloak.yaml, Skelett), nicht als Eigenbau.]

## Endpunkte des media-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `POST /media` | verschlüsselten Blob hochladen (roher Body, kein JSON/Base64); 201 mit `{"ref": ...}`, 400, 401, 413, 429 |
| `GET /media/{ref}` | Blob abrufen (`application/octet-stream`); 200, 401, 404, 429 |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte |

Der Client verschlüsselt die Datei, der Schlüssel reist in der Nachricht, nie über diesen Dienst (F180). Der Server sieht nur Chiffretext ohne Namen, Typ oder Metadaten; die Referenz ist eine server-erzeugte UUID und wirkt als Capability (wer Referenz und Schlüssel hat, hat die Datei - mehr Zugriffsschutz gäbe nur Metadaten preis). Ablage über `object_store`: mit `MEDIA_S3_BUCKET`/`MEDIA_S3_ENDPOINT` (plus `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) gegen S3/MinIO, ohne Konfiguration In-Memory mit Warnung. Keine eigene Datenbank. [ANNAHME: Blob max. 50 MiB, Upload 30/min und Abruf 120/min je Konto; Chunking/resumable Uploads sind eine offene Frage; Retention/GC verwaister Blobs folgt mit der Betriebs-Etappe.]

## Endpunkte des kt-Dienstes (aktueller Stand)

| Endpunkt | Zweck |
|----------|-------|
| `GET /kt/info` | öffentlicher Wurzel-Signaturschlüssel und aktuelle Epoche, Einstieg für Clients |
| `GET /kt/proof/{handle}` | Inklusionsbeweis zur aktuellen Epoche (VRF plus akd-Beweis, Base64); 200, 404 |
| `GET /kt/history/{handle}` | Verlauf der Commitments eines Handles über die Epochen |
| `GET /kt/epoch/latest`, `GET /kt/epoch/{n}` | signierte Wurzel (STH) der neuesten bzw. einer bestimmten Epoche |
| `GET /kt/consistency?from=&to=` | Konsistenzbeweis zwischen zwei Epochen (append-only) |
| `POST /internal/updates` | Dienst-zu-Dienst (identity): Schlüsseländerung ins Log aufnehmen; nur mit `INTERNAL_TOKEN` |
| `GET /live`, `/ready`, `/metrics` | Betriebs-Endpunkte |

Das prüfbare Schlüssel-Log (F120) macht einen stillen Schlüsseltausch entdeckbar: identity meldet jede Schlüsseländerung fire-and-forget an `POST /internal/updates`, kt schreibt sie ins append-only `kt_updates`, und der Epochen-Publisher bündelt wartende Updates periodisch zu einer signierten Wurzel (`KT_EPOCH_SECONDS`, Default 1 Stunde, Spec-Zielbereich 1 bis 6). PostgreSQL ist die Quelle der Wahrheit; der Merkle-Baum (AZKS aus der akd-Bibliothek, Metas KT) wird beim Start deterministisch aus dem Log wiederaufgebaut und gegen die gespeicherten Wurzeln geprüft, ein Integritätsbruch ist ein harter Startfehler. Das Konto-Commitment (`smktc.v1`, SHA-256 über Identitätsschlüssel und sortierte Gerätemenge) rechnet identity, kt interpretiert es nie. [ANNAHME: eine Replik, weil der Epochen-Publisher ein Singleton ist (deploy/k8s/kt.yaml); Auditoren und Gossip gegen den Split-View kommen in Phase 3; Beweis-Serialisierung bincode plus Base64.]

## Rate-Limits und SLI-Metriken

Die heißen Pfade sind je Aufrufer limitiert (Pflichtenheft 6.4; 429 mit `Retry-After`): Login 10/min und Registrierung 5/min je Handle (identity), Bündel-Abruf 30/min je Abrufer (directory, er konsumiert fremden Vorrat), Medien-Upload 30/min und -Abruf 120/min je Konto (media), Integrations-API je Mandant (konfigurierbar). Der Baustein ist `common::rate` (festes Minutenfenster). [ANNAHME: In-Prozess-Zähler je Replik statt Redis, bis Redis in den Stack kommt; IP-Limits gehören an die Edge, hinter dem Ingress ist die Quell-IP nicht belastbar.]

Jeder Dienst hängt die Middleware `common::metrics::track` ein; `/metrics` liefert daraus die SLI-Reihen für die SLO-Auswertung (betrieb.md): `http_requests_total{method,route,status}` (Verfügbarkeit) und `http_request_duration_seconds`-Histogramme je Route (p95/p99 rechnet Prometheus aus den Buckets). Die Route ist das axum-Routenmuster, nie der rohe Pfad - sonst explodiert die Kardinalität mit jedem Handle in der URL.

## Grenze: keine Krypto im Backend

Die Nachrichten-Kryptografie wird nicht im Backend gebaut. Sie lebt im Client-Core (libsignal, OpenMLS), das Backend hält und verteilt Chiffretext. Der externe Review von Specs und Krypto-Code blockiert seit [ADR-0008](dokumentation/entscheidungen/0008-krypto-vor-externem-review.md) nicht mehr den Code-Start, sondern den Produktivbetrieb. Im Backend gibt es nur Login- und Identitätsschutz über geprüfte Bibliotheken: das Passwort-Hashing (argon2), das Ablegen von Session-Tokens als SHA-256-Hash (sha2) und die Signatur-Verifikation der Geräte-Credentials (ed25519-dalek); private Schlüssel hält der Server nie. Die eine dokumentierte Ausnahme ist der kt-Dienst: Key Transparency braucht per Spec eigene Server-Schlüssel, die Ed25519-Wurzelsignatur und den VRF-Schlüssel (aus der akd-Bibliothek). Beide signieren beziehungsweise verschleiern nur das öffentliche Schlüssel-Verzeichnis, sie entschlüsseln keine Inhalte, und sie kommen aus Secrets (`KT_SIGNING_KEY`, `KT_VRF_KEY`), nicht aus dem Code.

## Der Krypto-Kern (crates/client-core)

Der gemeinsame Kern der Clients (ADR-0005): PQXDH, Double Ratchet und SPQR aus libsignal, MLS (RFC 9420) aus OpenMLS. Beide Bibliotheken sind per `rev` auf einen Release-Commit gepinnt (libsignal v0.96.4, OpenMLS v0.8.1; die Commits stehen in [krypto-kern.md](dokumentation/specs/krypto-kern.md) und in `crates/client-core/Cargo.toml`). Das Crate orchestriert nur: die heiklen Konstruktionen - die Hybrid-Bindung von PQXDH, die SPQR-Mischung - kommen unverändert aus libsignal, eigene Krypto-Konstruktionen sind dort verboten. Festgelegt an genau einer Stelle: die MLS-Suite 0x0003 (ChaCha20-Poly1305) und das Skipped-Keys-Fenster (2000 vorwärts).

Die Tests in `crates/client-core/tests/roundtrips.rs` sind Integrations-Beweise, keine Krypto-Tests: PQXDH-Aufbau mit ML-KEM-Chiffretext auf der Leitung, Ratchet-Roundtrip in beide Richtungen, Out-of-Order-Zustellung, Replay-Erkennung, MLS-Gruppen-Roundtrip über das TLS-Wire-Format. FFI- und WASM-Schichten sowie die persistente Geräte-Ablage folgen mit der Client-Etappe.
