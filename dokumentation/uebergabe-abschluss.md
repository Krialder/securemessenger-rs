# Übergabe: Wiedereinstieg und Arbeitsweise

Zweck: Ein neuer Assistent (oder Mensch) kann hiermit das Projekt mit minimalem Aufwand fortführen. Diese Datei hält bewusst KEINEN Ist-Stand (der veraltet sonst); der aktuelle, verbindliche Funktionsstand steht ausschließlich im [Live-Dokument](live-dokument.md), Abschnitt 9a (Bilanz) und Abschnitt 10 (Verlauf). Hier stehen nur die zeitlosen Dinge: Arbeitsweise, Verifikations-Loop, Konventionen und die technischen Fallen.

## Arbeitsweise

Umsetzen, gegenprüfen, verbessern. Jede Etappe endet grün, committet und mit synchroner Doku. Ein baubarer Punkt pro Iteration. Was ein externes Ereignis oder eine echte Organisation braucht (externes Audit nach [ADR-0008](entscheidungen/0008-krypto-vor-externem-review.md), unabhängige KT-Auditoren und Gossip-Betrieb, Push-Provider-Konten, Produktivbetrieb, PQ-MLS aus dem OpenMLS-Combiner-Draft), bleibt als offen markiert, nicht als erledigt ausgegeben.

## Konventionen

- Echte Umlaute (ä ö ü ß), keine langen Dashes (weder — noch –; stattdessen Komma, Doppelpunkt, Klammern oder ein neuer Satz). Kurzer Bindestrich in Komposita bleibt.
- `[ANNAHME: ...]`-Marker für Festlegungen, die nicht aus der Doku folgen, `[OFFENE FRAGE: ...]` für Ungeklärtes.
- Commits: `typ(scope): Imperativ` (Betreff höchstens 50 Zeichen) mit Warum-Body; im Commit-Text ue/oe/ae/ss statt Umlaute.
- `live-dokument.md` ist die einzige Status-Quelle: nach jeder Etappe Version um 0.1 erhöhen, eine Changelog-Zeile in Abschnitt 10, die Bilanz in Abschnitt 9a; die anderen Dokumente pflegen bewusst keinen eigenen Ist-Stand, sondern verweisen hierauf.

## Verifikations-Loop (unverändert einhalten)

1. `cargo test --workspace` mit allen fünf DB-Variablen gesetzt: `TEST_DATABASE_URL`, `TEST_DATABASE_URL_DIRECTORY`, `TEST_DATABASE_URL_DELIVERY`, `TEST_DATABASE_URL_INTEGRATIONS`, `TEST_DATABASE_URL_KT` (alle `postgres://postgres:dev@localhost:5432/<name>`). Ohne diese Variablen werden die PostgreSQL-Tests still übersprungen; genau so ist hier schon ein Bug durchgeschlüpft.
2. `cargo clippy --workspace --all-targets -- -D warnings`, und für den Web-Client zusätzlich clippy nach `wasm32-unknown-unknown` (über sm-web, client-core, client-app).
3. `cargo fmt --all` (danach `-- --check`).
4. Bei Web-Änderungen: `trunk build` in `clients/web` und eine Live-Prüfung in der Browservorschau (der native cargo-Lauf kompiliert den WASM-Client nicht).
5. Docker-Build je geändertem Dienst.
6. Commit mit Warum-Body, dann `live-dokument.md` (Version um 0.1, Changelog-Zeile, Autor "Kai Delor") und `ENTWICKLUNG.md` nachziehen.

## Wichtige Fallen

- Migrationen nach der Anwendung NIE ändern (sqlx-Prüfsumme); stattdessen die Wegwerf-Datenbank neu anlegen.
- Jeder Dienst hat eine eigene Datenbank (die sqlx-Migrationstabellen würden sonst kollidieren).
- `client-core` braucht `protoc` (setup.ps1 installiert es, env `PROTOC`).
- `akd` braucht seine Standard-Features (ohne `public_auditing` bricht 0.12.0 der Build).
- Neue Dienste: den `common::metrics::track`-Layer und den ops_router nicht vergessen; `/internal`-Routen nur bei gesetztem Secret einhängen (sonst ein echtes 404).
- Das identity-Image nach `/internal`-Vertragsänderungen neu bauen.
- MLS (Gruppen): nach JEDER Gruppen-Operation den Sitzungszustand exportieren. Ein Export VOR `create_message` führt zu Ratchet-Reuse, danach scheitert das Entschlüsseln ("deleted to preserve forward secrecy").
