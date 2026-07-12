# GOAL: vollständige, funktionierende SecureMessenger-App

Dieses Dokument ist Ziel und Arbeits-Prompt in einem. Verweise darauf mit `/goal` oder gib es einer frischen Sitzung als Auftrag. Es führt das Projekt zu einer **vollständigen, funktionierenden Anwendung**: erst der Kern (ein durchgehend funktionierender 1:1-E2EE-Chat), dann die Breite, wenn es Sinn ergibt. Es steht über den anderen Dokumenten und zeigt auf sie, statt sie zu kopieren.

## Zuerst lesen, nichts annehmen

In dieser Reihenfolge, dann `git log` und `git status`:

1. `dokumentation/uebergabe-abschluss.md` — Wiedereinstieg, Verifikations-Loop, technische Fallen.
2. `dokumentation/live-dokument.md` Abschnitt 9a: der aktuelle, verbindliche Funktionsstand (die einzige maßgebliche Status-Quelle).
3. `ENTWICKLUNG.md` — Struktur, Bauanleitung, Endpunkt-Tabellen aller Dienste.
4. `dokumentation/live-dokument.md` Abschnitt 10 — was in welcher Etappe entstand.
5. `dokumentation/pflichtenheft.md`, `dokumentation/roadmap.md`, `dokumentation/specs/`, `dokumentation/entscheidungen/` — Soll-Stand und die verbindlichen Entscheidungen.

## Ist-Stand (Kurzfassung, Details in den Quellen oben)

GOAL.md pflegt bewusst KEINEN eigenen Ist-Stand, damit er nicht veraltet. Der aktuelle, verbindliche Funktionsstand steht ausschließlich im [Live-Dokument](dokumentation/live-dokument.md), Abschnitt 9a (Bilanz) und Abschnitt 10 (Verlauf). Grober Rahmen zur Orientierung: der Kern (1:1- und Gruppen-E2EE-Chat in Web und CLI, Multi-Device mit Self-Sync, Key Transparency, Sealed Sender, Contact Discovery, Abuse-Abwehr, Kontoverwaltung samt Wurzelschlüssel-Rotation) ist gebaut und vorführbar. Offen bleibt vor allem, was eine echte Organisation oder ein externes Ereignis braucht (externes Audit nach ADR-0008, unabhängige KT-Auditoren, Push-Provider-Konten, Produktivbetrieb).

## Was "fertig" heißt (gestaffelt und messbar, nicht "perfekt")

"Vollständig funktionierend" ist kein Gefühl, sondern grüne Gates plus ein vorführbarer End-to-End-Beweis. Der Kern gilt zuerst, die Breite folgt.

- **Meilenstein 0 (Risiko zuerst):** `client-core` baut nach `wasm32-unknown-unknown`. Bevor eine Zeile Frontend entsteht, ist bewiesen, dass libsignal und OpenMLS im Browser laufen (oder klar dokumentiert, was dafür feature-gated oder ersetzt werden muss). Ohne diesen Beweis ist der ganze Web-Client Spekulation.
- **Meilenstein 1 (der Kern = "funktionierende Anwendung"):** Zwei Nutzer registrieren sich auf den echten Diensten, veröffentlichen Prekeys, verifizieren die Schlüssel des Gegenübers über Key Transparency, bauen per PQXDH eine Sitzung auf und tauschen echte, Ende-zu-Ende verschlüsselte 1:1-Nachrichten. Web-Frontend in Leptos, echte PostgreSQL-Datenbank, alles grün und reproduzierbar. **Abnahme:** siehe Meilenstein-1-Kriterien unten.
- **Meilenstein 2 und höher (Breite, nur wenn es Sinn ergibt):** MLS-Gruppenchat, Sealed Sender, Contact Discovery, Safety-Number-UI, Betriebs-Härtung. Jeder Punkt ehrlich und verifiziert, kein vorgetäuschter Schutz. Reihenfolge und Budget-Stufen stehen in `uebergabe-abschluss.md`.

Nicht faken: Was hinter dem externen Audit liegt (ADR-0008) oder eine echte Organisation braucht (KT-Auditoren, Push-Provider-Konten, Proxmox-Cluster), bleibt als offen markiert, nicht als erledigt ausgegeben.

## Arbeitsweise (der Verifikations-Loop, unverändert)

Ein Backlog-Punkt pro Iteration, dann der Loop, erst danach der nächste:

1. `cargo test --workspace` mit allen fünf Datenbank-Variablen gesetzt (`TEST_DATABASE_URL`, `_DIRECTORY`, `_DELIVERY`, `_INTEGRATIONS`, `_KT`, je `postgres://postgres:dev@localhost:5432/<name>`). Ohne sie überspringen sich die PostgreSQL-Tests still, das gilt nicht als grün.
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo fmt --all`, dann `-- --check`
4. Docker-Build je geändertem Dienst; für das Frontend der WASM-Build (`trunk build` bzw. `wasm-pack`).
5. Doku synchron: `ENTWICKLUNG.md`, `live-dokument.md` (Version plus 0.1, Changelog-Zeile, Autor "Kai Delor"), `datenmodell.md`/`schnittstellen.md` wo berührt, Repo-Gedächtnis.
6. Conventional Commit `typ(scope): Imperativ` mit Warum-Body und Footer `Co-Authored-By`; Commit-Text ohne Umlaute (ue/oe/ae).

Behaupte nie grün, ohne den Befehl wirklich laufen zu lassen. `cargo` liegt unter `%USERPROFILE%\.cargo\bin`, `protoc` unter `%LOCALAPPDATA%\protoc\bin` (setup.ps1 setzt `PROTOC` pro Sitzung), Docker-Daemon und `sm-postgres` müssen laufen (`scripts/setup.ps1` richtet alles ein).

## Standards

- **Keine Eigenbau-Kryptografie.** Alles Kryptografische kommt aus `client-core` (libsignal, OpenMLS) beziehungsweise den gepinnten Backend-Bibliotheken (argon2, akd). Der Server hält Chiffretext; die einzigen erlaubten Server-Schlüssel sind die von der KT-Spec zugelassenen.
- **Industrie-Niveau, aber ehrlich.** Bau, was baubar und verifizierbar ist, erfinde keine Sicherheit. Unsicheres als `[ANNAHME: ...]` markieren.
- **Schreibstil:** echte Umlaute, keine langen Gedankenstriche, keine Floskeln, jede Entscheidung mit Grund, beschreibende Links.
- **Fragen nur bei echten Weggabelungen** ohne doku-gedeckten Default; alles andere als Annahme markieren und weiterbauen.

## Modell-Aufteilung (Opus 4.8 und Fable, jeweils ultracode)

Der Fable-Klassifikator markiert auf diesem Krypto-Projekt regelmäßig auch harmlose Schritte und fällt dann auf Opus zurück, das ruckelt. Teile die Arbeit danach auf:

- **Opus 4.8:** Krypto-Kern und WASM-Bindung der Krypto, Sealed Sender / zkgroup, Key-Transparency-Interna, Metadaten- und Threat-Model-Themen. Alles, was nah an der Verschleierung vor Zugriff liegt.
- **Beide Modelle:** Backend-Dienste, Frontend-UI (Leptos), Tests, CI, Kubernetes, Doku. Hier ist Fable flüssig.

Für lange, ununterbrochene Bau- und Testläufe ist Opus 4.8 die pragmatische Wahl.

## Frontend: Rust + WASM (Leptos)

Architektur in drei Schichten, damit die Krypto nie in die UI leckt und ein zweiter Client (CLI, später nativ) dieselbe Logik teilt:

```
crates/client-core     Krypto (libsignal, OpenMLS) - existiert, nur Wrapper
crates/client-app      Protokoll-Orchestrierung: HTTP (reqwest) gegen identity/
                       directory/delivery/kt, Sitzungsauf- und -abbau, lokale
                       Schluessel- und Ratchet-Ablage hinter einem Storage-Trait.
                       Keine UI, plattformneutral (native und wasm).
clients/cli            Headless-Referenzclient: beweist den vollen Fluss ohne UI,
                       leicht testbar (zwei Instanzen tauschen eine Nachricht).
clients/web            Leptos-App (WASM), nutzt client-app; Storage-Trait ueber
                       IndexedDB. Nur die Darstellung, keine Krypto.
```

Warum diese Reihenfolge: Erst `client-app` plus `clients/cli` bauen und testen (der ganze Protokollfluss headless, in einem Integrationstest gegen die echten Dienste beweisbar), dann die WASM-Bindung, dann die Leptos-Oberfläche. So steht die schwierige Logik, bevor UI-Arbeit beginnt.

Technische Hinweise: `reqwest` baut nach wasm32 (nutzt `fetch`), für WebSockets im Browser `gloo-net` oder `web-sys`. Bau über `trunk`. Der Web-Client ist laut `sicherheit.md` das kryptografisch schwächste Glied (kein OS-Keystore, XSS): das gehört sichtbar in die UI und in die Doku, nicht kaschiert.

## Optionaler sichtbarer Abnahme-Beweis (Claude-Chrome-Extension)

Wenn die Extension verbunden ist, lohnt ein sichtbarer End-to-End-Test als Abnahme:

1. Zwei Browser-Kontexte (zwei Konten) öffnen den Web-Client.
2. Konto A schreibt Konto B eine Nachricht, B empfängt und entschlüsselt sie.
3. Parallel per `docker exec sm-postgres psql` in die `messages`-Tabelle der delivery-Datenbank schauen: dort steht nur die opake Hülle, kein Klartext.

Das ist der überzeugendste Beleg für ein Ausbildungsprojekt: Man sieht die Nachricht ankommen und sieht zugleich, dass der Server sie nicht lesen kann.

## Meilenstein 1 im Detail (der Kern)

Reihenfolge der Bausteine, jeder mit dem Verifikations-Loop abgeschlossen und committet:

1. **M0 WASM-Spike:** `client-core` nach wasm32 bauen, Ergebnis dokumentieren.
2. **client-app:** Registrierung (Identitäts- und Geräteschlüssel erzeugen, Credential signieren, `POST /accounts`), Login (`POST /sessions`), Prekey-Veröffentlichung (Bündel aus `client-core`, `POST /keys/prekeys`), Sitzungsaufbau (`GET /keys/{handle}`, PQXDH), Senden (Double Ratchet, `POST /messages` je Zielgerät), Empfangen (WebSocket-Hinweis, `GET /messages`, entschlüsseln, `POST /messages/ack`), KT-Verifikation (`GET /kt/proof/{handle}`, Inklusionsbeweis prüfen), Storage-Trait für Schlüssel und Ratchet-Zustand.
3. **clients/cli:** zwei Instanzen tauschen über die echten Dienste eine Nachricht; als Integrationstest, der die Dienste per docker-compose hochfährt.
4. **WASM-Bindung** von `client-app`, IndexedDB-Storage.
5. **clients/web (Leptos):** Anmeldung, Kontakt über Handle, Schlüssel-Verifikation mit Safety Number, Chat-Ansicht. Schlicht, aber echt.

**Abnahmekriterien Meilenstein 1:**

- Zwei Web-Sessions führen einen 1:1-Chat, Nachrichten kommen in beide Richtungen an.
- Ein Blick in die delivery-Datenbank zeigt ausschließlich Chiffretext.
- Ein untergeschobener Schlüssel (Testfall) fällt bei der KT-Verifikation auf.
- `cargo test --workspace` grün (inkl. der fünf PG-Datenbanken und des CLI-Integrationstests), `clippy -D warnings` grün, `fmt` sauber, alle Docker- und WASM-Builds grün.
- `live-dokument.md`, `ENTWICKLUNG.md` und `schnittstellen.md` nachgezogen; die Client-Etappe steht als erreicht drin.

## Meilenstein 2 und höher (Breite, verweisend)

Reihenfolge und Zuschnitt in `uebergabe-abschluss.md` und `roadmap.md`. Kurz:

- **MLS-Gruppenchat:** delivery um `POST /groups`, `/groups/{id}/commit`, `/groups/{id}/messages` erweitern (Schema in `datenmodell.md`, Regeln in `specs/mls-delivery-service.md`); Client um Gruppensitzungen über OpenMLS. Opus-Aufgabe für den Krypto-Teil.
- **Sealed Sender:** anonyme Credentials (zkgroup-Linie), `specs/sealed-sender-und-abuse.md`. Aufwendig, Opus-Aufgabe, darf als markierte Lücke stehen bleiben.
- **Contact Discovery (OPRF):** `specs/contact-discovery.md`.
- **Safety Numbers und Warnung bei Schlüsselwechsel** im Client sichtbar machen.
- **Betrieb:** NATS für das Echtzeit-Fanout über mehrere Repliken, Redis für Rate-Limits und Presence, Operatoren, herausgelöster KT-Epochen-Publisher mit Leader-Wahl.

## Definition of Done (global)

Alles grün (fmt, clippy, Tests inkl. PostgreSQL, Docker- und WASM-Builds), alles committet, keine ungesicherte Arbeit, Doku widerspruchsfrei, und das Live-Dokument benennt klar, was funktioniert und was vor Produktivbetrieb noch aussteht (Sealed Sender, MLS-Härtung, Betrieb, externes Audit). Der Kern (Meilenstein 1) ist die Schwelle, ab der die Anwendung "funktioniert"; die Breite darüber ist Zugabe, kein Vorwand, den Kern unfertig zu lassen.

## Fallen (Details in uebergabe-abschluss.md)

Migrationen nach Anwendung nie ändern (sqlx-Prüfsumme), eine Datenbank je Dienst, `protoc` für `client-core`, akd-Standard-Features, `/internal`-Routen nur bei gesetztem Secret, identity-Image nach jeder `/internal`-Vertragsänderung neu bauen. Für das Frontend zusätzlich: wasm32-Build früh absichern, WebSocket im Browser über `gloo-net`, den Web-Client ehrlich als schwächstes Glied kennzeichnen.
