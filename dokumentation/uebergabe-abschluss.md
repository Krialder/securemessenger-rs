# Übergabe: Stand und Anleitung zur Projekt-Beendigung

Stand 03.07.2026. Zweck: Ein neuer Assistent (oder Mensch) kann hiermit das Projekt mit minimalem Aufwand zum bestmöglichen Abschluss bringen. Arbeitsweise beibehalten: umsetzen -> gegenprüfen -> verbessern, jede Etappe endet grün + committet + Doku synchron. Konventionen: echte Umlaute, keine langen Dashes, [ANNAHME: ...]-Marker, Commits "typ(scope): Imperativ" mit Warum-Body (ue/oe/ae im Commit-Text). Das Repo-Gedächtnis (/memories/repo/projekt-stand.md) enthält alle technischen Fallen.

## Momentaner Stand

**Fertig und committet (Etappen 1-9, live-dokument v0.12):**

| Baustein | Stand |
|----------|-------|
| identity | Konten, Argon2id-Login, rotierende Sessions (F020), Geräte (F030/F040), /internal-API, Rate-Limits |
| directory | Prekey-Pools, atomarer Bündel-Abruf (F110), Rate-Limit je Abrufer |
| delivery | Store-and-Forward (F050), Dedupe, Monatspartitionen, WebSocket-Hinweise, Präsenz, /internal-Routen |
| integrations | Mandanten (F100), Notify (F070), Präsenz (F080), Keycloak-Skelett (F060) |
| media | Verschlüsselte Blobs, object_store/MinIO (F180) |
| client-core | libsignal v0.96.4 + OpenMLS v0.8.1 gepinnt, PQXDH/Ratchet/MLS-Roundtrip-Beweise |
| Querschnitt | SLI-Metriken, common::rate, CI (.github/workflows/ci.yml), Digest-gepinnte Docker-Builds, deploy/k8s per `kubectl apply -k`, setup.ps1 legt sm-postgres + Datenbanken an |

**In Arbeit, NOCH NICHT committet (Etappe 10, Key Transparency F120):**
- services/kt komplett gebaut, kt-Tests grün (inkl. Client-seitiger Beweis-Verifikation mit akd, Wiederaufbau-Determinismus, PG-Neustart-Beweis 2x gelaufen)
- Design: akd =0.12.0 (Metas KT-Bibliothek) gepinnt; PostgreSQL = Quelle der Wahrheit (kt_updates append-only + kt_epochs signierte Wurzeln); AZKS in-memory, beim Start deterministisch wiederaufgebaut, Abweichung = harter Startfehler; Ed25519-Wurzelsignaturen (KT_SIGNING_KEY) + VRF (KT_VRF_KEY) als per Spec erlaubte Server-Schlüssel; Epochen-Publisher (KT_EPOCH_SECONDS, Default 3600)
- common::kt::account_commitment (smktc.v1, SHA-256 über identity_key + sortierte Gerätemenge), common hat jetzt sha2
- identity meldet Schlüsseländerungen fire-and-forget an kt (src/kt_notify.rs, notify_kt nach register/add_device/remove_device, KT_URL + INTERNAL_TOKEN in main.rs)
- Test `key_changes_are_reported_to_kt` in services/identity/tests/api.rs geschrieben, **aber noch nicht gelaufen** (letzter Testlauf abgebrochen)
- Datenbank kt existiert in sm-postgres, Test-Var: TEST_DATABASE_URL_KT=postgres://postgres:dev@localhost:5432/kt

## Anleitung zur Beendigung (in dieser Reihenfolge)

### Schritt 1: Etappe 10 abschließen (fast fertig, geringe Kosten)
```
cargo test --workspace          # alle 5 TEST_DATABASE_URL*-Vars setzen (identity/directory/delivery/integrations/kt)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
docker build -f deploy/docker/Dockerfile --build-arg SERVICE=kt -t securemessenger/kt:dev .
```
Dann: deploy/k8s/kt.yaml (directory.yaml kopieren, Secrets kt-db/url, internal-token/token, kt-keys mit KT_SIGNING_KEY + KT_VRF_KEY); kt in kustomization.yaml und CI-Matrix (.github/workflows/ci.yml: Datenbanken-Liste + docker-Matrix) und identity.yaml (env KT_URL=http://kt) ergänzen; setup.ps1 $databases um 'kt' erweitern; ENTWICKLUNG.md (Strukturbaum, kt-Endpunkt-Tabelle: GET /kt/info, /kt/proof/{handle}, /kt/history/{handle}, /kt/epoch/latest, /kt/epoch/{n}, /kt/consistency?from=&to=, POST /internal/updates; TEST_DATABASE_URL_KT-Hinweis; Krypto-Grenze-Absatz um die KT-Ausnahme erweitern: Server hält VRF- und Wurzelsignatur-Schlüssel per Spec); datenmodell.md (kt_updates/kt_epochs statt altem kt_epochs-Block); live-dokument v0.13-Zeile (Autor "Kai Delor"). Commit: `feat(kt): Key Transparency Grundgeruest (F120)` mit Warum-Body (akd gepinnt statt Merkle-Eigenbau, PG als Quelle der Wahrheit + deterministischer Wiederaufbau, Commitment smktc.v1, fire-and-forget aus identity).

### Schritt 2: Doku-Restpflege (billig, hoher Wert)
- roadmap.md: erledigte Phase-1/1b-Punkte abhaken (identity, Geräte, directory, KT-Grundgerüst, Basis-Dienste)
- README.md im Root kurz auf den Ist-Stand bringen (6 Dienste + Krypto-Kern)

### Schritt 3: Bestmöglicher Abschluss je nach Rest-Budget

**Wenn wenig Budget (Empfehlung bei <5%):** Nur noch "ehrlicher Projektabschluss":
- dokumentation/live-dokument.md v1.0-RC: Abschnitt "Erreichter Stand vs. Roadmap" - was produktionsreif ist (Backend Phase 1/1b), was aussteht (Clients, Sealed Sender, Contact Discovery, MLS-DS, Betrieb/Operatoren, externes Audit blockiert Produktivbetrieb per ADR-0008)
- offene-fragen.md aktualisieren
- Finaler Commit `docs: Projektstand zum Abschluss der Backend-Phasen`
- FERTIG-Kriterium: alles grün, alles committet, keine ungesicherte Arbeit, Doku widerspruchsfrei

**Wenn mittleres Budget:** Zusätzlich MLS-Gruppen-Backend (Etappe 11, überschaubar):
- delivery erweitern: POST /groups (Gruppe = UUID + Mitglieds-Geräte in group_devices-Tabelle, datenmodell.md hat das Schema), POST /groups/{id}/commit (Commit-Ordnung: fortlaufende Epoche je Gruppe, konkurrierende Commits -> 409, specs/mls-delivery-service.md), POST /groups/{id}/messages (Fan-out an Mitglieds-Geräte über bestehendes store_batch)
- Wire-Format bleibt opak (MLSMessage-Bytes b64); Tests nach delivery-Muster

**Wenn großes Budget:** Zusätzlich CLI-Referenz-Client (größter Beweiswert: E2EE Ende-zu-Ende):
- crates/client-core erweitern um HTTP-Anbindung (reqwest) gegen identity/directory/delivery
- Neues Binary tools/smcli: register, login, prekeys hochladen, Session zu Handle aufbauen (Bündel holen -> PQXDH), verschlüsselt senden (POST /messages), abholen + entschlüsseln + ack
- Beweis: zwei CLI-Instanzen tauschen über die echten Dienste eine Nachricht, Server sieht nur Chiffretext
- Das ist das überzeugendste Abschluss-Artefakt fürs BBW-Projekt

### Nicht mehr versuchen (Budget-Fallen)
- Sealed Sender/zkgroup: libsignal-zkgroup-Integration ist mehrtägig; als [ANNAHME]-Lücke dokumentiert lassen
- Native/Web-Clients mit UI, Push-Gateway, NATS/Redis, Operatoren: Betriebs-/Client-Etappen, sauber als offen dokumentiert
- Externes Audit: per ADR-0008 ohnehin externes Ereignis vor Produktivbetrieb

## Verifikations-Loop (unverändert einhalten)
1. `cargo test --workspace` (Env-Vars: TEST_DATABASE_URL, TEST_DATABASE_URL_DIRECTORY, TEST_DATABASE_URL_DELIVERY, TEST_DATABASE_URL_INTEGRATIONS, TEST_DATABASE_URL_KT, alle postgres://postgres:dev@localhost:5432/<name>)
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo fmt --all` (dann `-- --check`)
4. Docker-Build je geändertem Dienst
5. Commit mit Warum-Body, dann ENTWICKLUNG.md + live-dokument.md (Version +0.1, Changelog-Zeile, Autor "Kai Delor")
6. /memories/repo/projekt-stand.md nachziehen

## Wichtige Fallen (Kurzfassung, Details im Repo-Gedächtnis)
- Migrationen nach Anwendung NIE ändern (sqlx-Checksumme); Wegwerf-DB neu anlegen
- Jeder Dienst eigene Datenbank (sqlx-Migrationstabellen kollidieren)
- client-core braucht protoc (setup.ps1 installiert, env PROTOC)
- akd braucht Standard-Features (ohne public_auditing bricht 0.12.0 der Build)
- Neue Dienste: common::metrics::track-Layer + ops_router nicht vergessen; /internal-Routen nur bei gesetztem Secret einhängen (echtes 404)
- identity-Image nach /internal-Vertragsänderungen neu bauen
