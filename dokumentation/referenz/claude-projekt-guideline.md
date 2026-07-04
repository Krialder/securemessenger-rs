# Projekt-Guideline für Claude (Opus 4.8 / Fable 5)

Destilliert aus dem SecureMessenger-Projekt: Pflichtenheft-Struktur, Dokumentations-System, Coding-Herangehensweise, Sprache und Arbeits-Loop, so wie sie sich dort bewährt haben, plus die Verbesserungen, die das nächste Projekt von Anfang an haben sollte (Abschnitt 8 nennt sie einzeln). Zum Einsatz: diese Datei als `CLAUDE.md` ins Repo-Root des neuen Projekts legen und die Abschnitte streichen oder anpassen, die nicht zutreffen (etwa das Bedrohungsmodell bei einem Projekt ohne Sicherheitsanspruch). Sie gilt dann für alle Antworten, Dokumente, Code-Kommentare und Commits.

## 1 Harte Sprachregeln (gelten immer, vor allem anderen)

- Detailliert und begründet: Jede Aussage, Empfehlung und Entscheidung trägt ihr Warum. Knappe, unbegründete Antworten sind falsch, auch wenn sie kürzer wären. Der Grund: Ohne das Warum kann der Leser die Entscheidung später weder prüfen noch sicher ändern.
- Keine langen Gedankenstriche: „—" (Em-Dash) und „–" (En-Dash) als Satzzeichen sind verboten. Stattdessen Komma, Doppelpunkt, Klammern oder ein neuer Satz. Der kurze Bindestrich „-" bleibt, wo er hingehört (Komposita wie „IHK-Projekt", Aufzählungszeichen in Markdown).
- Echte Umlaute: Deutsche Wörter schreiben sich mit ä, ö, ü, ß. Umschreibungen (ae, oe, ue, ss) sind nur in technischen Bezeichnern zulässig, in denen Umlaute nicht funktionieren oder Ärger machen: Variablennamen, URLs, Dateinamen, Konsolen-Ausgaben von Skripten und der Commit-Text (Git-Werkzeuge und Terminals gehen mit reinem ASCII verlässlicher um).
- Verbotene Stilwörter: „ehrlich" in allen Varianten („ehrlich gesagt", „ehrliche Einordnung"), „es ist wichtig zu beachten", „in der heutigen Welt", „spielt eine entscheidende Rolle", „zusammenfassend lässt sich sagen", „nicht nur ... sondern auch", Werbe-Adjektive (leistungsstark, nahtlos, robust, umfassend). Das ist eine Startliste, keine abschließende: Die Meta-Regel lautet, Wörter zu streichen, die ein Sprachmodell als wahrscheinlichste Wahl setzen würde, und das treffende, spezifische Wort zu nehmen. Der gemeinsame Feind ist Vorhersagbarkeit, nicht Register-Höhe.
- Sprache der Artefakte: Dokumentation, Code-Kommentare und Antworten auf Deutsch. Bezeichner im Code entweder englisch oder projektweit konsistent deutsch; die Wahl trifft das Glossar (Abschnitt 7) am Projektstart, danach wird nicht gemischt.

## 2 Schreibstil

Für Fließtext (Erklärungen, Design-Doku): zweite Person, Präsens, Aktiv, das Wichtigste zuerst. Kohäsion über Bekanntes-vor-Neuem: Der Satzanfang greift den Faden des vorigen Satzes auf, das Neue steht am Ende; aufgeklebte Konnektoren („darüber hinaus", „zudem") sind meist ein Pflaster für fehlenden Themenfluss. Satzlängen variieren nach Sinn, ein kurzer Satz nach einem langen landet. Verben statt Nominalketten („wir optimieren" statt „die Durchführung der Optimierung erfolgt"). Haltung zeigen: eine Sache die bessere nennen und begründen, statt jede Seite gleich zu gewichten. Der einzige verlässliche Test ist Vorlesen: Wo du stolperst, stolpert der Leser.

Für technische Doku gilt der Diátaxis-Gedanke pro Abschnitt, nicht pro Dokument: Tutorial (auf Schienen, „wir"), How-to (Imperativ, Schritte, kein Hintergrund), Referenz (knapp, faktisch, parallel gebaut; Gleichförmigkeit ist hier ein Feature), Erklärung (Fließtext, beantwortet das Warum). Quer durch alle Typen: Der erste Satz nennt, was die Sache tut und zurückgibt; exakte Werte statt „verschiedene"; dokumentiert wird das Nicht-Offensichtliche (Defaults, Fehlermodi, Seiteneffekte, Stolperfallen), nicht das aus Name und Signatur Ablesbare; kontraintuitives Verhalten wird benannt und das falsche mentale Modell explizit korrigiert; beschreibende Links statt „hier".

## 3 Dokumentations-System

Docs-as-Code: alles als Markdown im Repo, mit dem Code versioniert und im selben Commit nachgezogen wie die Änderung, die es beschreibt. Veraltete Doku ist schlimmer als keine, weil sie Vertrauen kostet, genau wenn man sie braucht.

Der Dokumentensatz, nach Projektgröße skaliert (klein: README plus Live-Dokument genügt; die volle Liste ab mehreren Diensten oder mehreren Wochen Laufzeit):

| Dokument | Zweck |
|----------|-------|
| `README.md` | Zweck, aktueller Stand (mit Datum), Einstieg mit einem Befehl, Wegweiser auf alles Weitere |
| `lastenheft.md` | Anforderungen: das Was und Warum, aus Nutzersicht |
| `pflichtenheft.md` | Die technische Umsetzung: das Wie, mit Stack, Betrieb, nicht-funktionalen Anforderungen |
| `ENTWICKLUNG.md` | Struktur-Baum mit Ein-Zeilen-Zweck je Verzeichnis, Endpunkt-Tabellen je Dienst, lokale Läufe, Umgebungsvariablen |
| `live-dokument.md` | Fortlaufendes Design-Dokument mit Versionsnummer; Abschnitt „Änderungsverlauf" ist die Wahrheit über den Ist-Stand |
| `roadmap.md` | Etappen als Checkboxen, nach Abhängigkeit sortiert, ohne Termine |
| `offene-fragen.md` | Was bewusst unentschieden ist, mit Tendenz und Fälligkeit („muss vor Phase X stehen") |
| `entscheidungen/` (ADRs) | Eine architektonisch signifikante Entscheidung pro Datei: Title, Status, Context, Decision, Consequences; unveränderlich, spätere Entscheidungen ergänzen statt editieren |
| `specs/` | Je kritischem Thema eine ausgearbeitete Spezifikation, bevor gebaut wird |
| `DEMO.md` | Vorführ-Drehbuch: je Behauptung des Projekts der Handgriff, der sie beweist |
| `bedrohungsmodell.md` | Bei Sicherheitsanspruch: STRIDE je Komponente, LINDDUN je Datenfluss, jede Bedrohung mit der Gegenmaßnahme im Code, dazu ein Restrisiko-Register |
| `glossar.md` | Die Fachbegriffe des Projekts mit Festlegung (Abschnitt 7) |
| `umgebungs-fallen.md` | Gelernte Stolperfallen der Werkzeuge und des Zielsystems (Abschnitt 6) |

Konventionen, die das System tragen:

- ANNAHME-Markierung: Jede Setzung, die die Vorgaben offenlassen, und jede bewusste Lücke steht als `**[ANNAHME: ...]**` im Text beziehungsweise als `[ANNAHME: ...]`-Kommentar im Code. Das Muster ist absichtlich grep-bar: `grep -r "ANNAHME"` listet alle offenen Setzungen des Projekts. Nichts wird kaschiert; eine markierte Lücke ist ein Arbeitsstand, eine versteckte ist ein Mangel.
- Änderungsverlauf: Jede abgeschlossene Etappe erhöht die Version des Live-Dokuments um 0.1 und schreibt einen Eintrag mit vier Teilen: was gebaut wurde, warum so, welche Beweise es gibt (Tests, Vorführung), und ein ANNAHME-Block für das, was offen bleibt. Der Verlauf ersetzt Status-Meetings: Wer ihn liest, kennt den Stand.
- Offene Punkte wandern nie stillschweigend raus: erledigt wird abgehakt (mit Verweis auf den Beweis), verworfen wird als verworfen markiert (mit Grund).

## 4 Coding-Herangehensweise

- Kein Eigenbau bei Sicherheit: Kryptografie, Passwort-Hashing, Token-Mechanik und vergleichbare Primitive kommen aus geprüften Bibliotheken, exakt gepinnt (Git-rev oder `=version`, nie eine schwimmende Range). Eigenleistung ist das Komponieren von Standard-Primitiven auf Standard-Wegen; wo eine eigene Komposition nötig ist, wird sie an einer publizierten Konstruktion festgemacht und mit Quelle kommentiert.
- Vertrauensgrenzen als Architektur: Zuerst festlegen, welche Komponente was wissen darf (etwa: Krypto nur im Client-Kern, der Server bewegt opake Bytes), dann bauen. Jede Schicht, die etwas nicht wissen soll, bekommt es auch technisch nicht, statt es nur nicht anzuschauen.
- Geteilte Logik als geteilte Bausteine: Was zwei Seiten exakt gleich rechnen müssen (Formate, Commitments, Prüfungen), lebt in genau einem geteilten Crate/Modul, das beide einbinden. Doppelimplementierung driftet immer auseinander, und zwar genau dann, wenn es weh tut.
- Austauschbarkeit gezielt einbauen, wo ein Wechsel absehbar ist, nicht überall (das wäre spekulative Abstraktion): Schlüssel und Endpunkte über Umgebungsvariablen, Wire- und Speicher-Formate versioniert (`name.v1` als erstes Feld), Vertrauensketten zweistufig (ein stabiler Anker signiert rotierende Arbeitsschlüssel), Ablagen hinter einem Trait mit In-Memory- und Produktiv-Umsetzung. Der Test für die richtige Stelle: Lässt sich die Komponente tauschen, ohne dass die Gegenseite etwas Neues lernen muss?
- Ousterhout als Kompass: tiefe Module (schmale Schnittstelle über mächtiger Implementierung), Information Hiding, Komplexität als Maßstab jeder Entscheidung. DRY gilt für Wissen und Entscheidungen, nicht für zufällig ähnlich aussehenden Code; abstrahiert wird ab der dritten Wiederholung. YAGNI: kein „könnte man später brauchen".
- Fehlerbehandlung: Schnittstellen so entwerfen, dass der Fehler nicht entstehen kann (define-out); wo eine Invariante verletzt wird, hart und früh scheitern statt still weiterlaufen. Ein Dienst, der ohne seine Persistenz anläuft, ist kein Feature, sondern ein Datenverlust mit Verzögerung.
- Kommentare erklären das Warum, die Invariante, die Stolperfalle, nie das Was; sie sitzen am Punkt der Subtilität. Funktions-Header sind Verträge (was rein, was raus, was bei Fehlern) plus Begründung der nicht-offensichtlichen Entscheidung. Modulkopf-Kommentare sagen, warum das Modul existiert und wo seine Grenze liegt.
- Tests sind Beweise, nicht Zeremonie: Jede Etappe endet mit mindestens einem Test, der die Kernbehauptung wörtlich prüft (Beispiel aus dem Ursprungsprojekt: „die gespeicherte Hülle enthält den Klartext nirgends" als String-Suche über die echte Datenbank-Ablage). Dazu die Pyramide: viele Unit-Tests, Integrationstests gegen echte Abhängigkeiten (Dienste in-process auf Ephemeralports, Datenbank-Tests gegen echtes PostgreSQL, die ohne konfigurierte Test-DB still übersprungen werden), wenige End-to-End über die Binaries selbst (je Befehl ein Prozess, das beweist Persistenz über Prozessgrenzen).
- Flakiness ist ein Bug, kein Wetter: Ein instabiler Test wird bis zur Ursache verfolgt (im Ursprungsprojekt war es eine echte Ordnungs-Race in der Datenbank) und der Fix mit mehreren aufeinanderfolgenden grünen Läufen belegt.

## 5 Arbeits-Loop

- Eine Etappe = ein baubarer, beweisbarer Punkt. Vor dem Bauen einen kurzen Bauplan festhalten (welche Verträge, welche Dateien, welcher Beweis), bei mehrtägigen Etappen im Repo, sonst im Memory.
- Verifikations-Loop vor jedem Commit, als eingechecktes Skript (`scripts/verify.ps1` oder Makefile-Target), nicht als Konvention im Kopf: alle Tests (einschließlich der echten Datenbanken), Linter mit Warnungen-als-Fehler auf allen Targets (auch Cross-Targets wie wasm32, wenn vorhanden), Format-Check, Container-Builds der betroffenen Dienste. CI führt exakt dieses Skript aus, damit lokal und CI nie auseinanderlaufen.
- Ein Commit je Etappe. Betreff `typ(scope): Imperativ` (höchstens 50 Zeichen, Conventional Commits: feat/fix/docs/chore/refactor/test), Body bei ~72 Zeichen umbrochen mit Was und vor allem Warum, den Beweisen und einer „Verifiziert:"-Zeile, die den grünen Loop benennt. Commit-Text in ASCII (siehe Sprachregeln). Verboten: „Update", „Fix bug", „WIP", „Phase 1".
- Doku im selben Commit: Änderungsverlauf-Eintrag, betroffene Endpunkt-Tabellen, Roadmap-Häkchen. Ein Commit, dessen Doku fehlt, ist nicht fertig.
- Ehrliche Grenzen, technisch durchgesetzt: Was ein externes Ereignis oder eine echte Organisation braucht (Audits, fremde Betreiber, echte Provider-Konten), bleibt als offen markiert und wird nie als erledigt behauptet. Attrappen, die Erfolg vortäuschen, sind verboten; erlaubt und erwünscht sind echte Minimal-Implementierungen hinter austauschbaren Schnittstellen, die als Zwischenstufe dokumentiert sind (Muster: selbst betriebene Zertifikatskette jetzt, externer Aussteller später, Clients merken den Wechsel nicht).
- Definition of Done, von Tag 1: grüne Gates (Verify-Skript) + ein vorführbarer Beweis (Testfall oder Drehbuch-Schritt in `DEMO.md`) + Doku-Eintrag. Fehlt eines der drei, ist die Etappe offen.

## 6 Zusammenarbeit mit Claude (Opus 4.8 / Fable 5)

- Diese Datei ist die oberste Weisung des Repos; sie gilt für jede Antwort, jeden Kommentar, jeden Commit, ohne dass der Nutzer sie wiederholt.
- Fragen bei echten Entscheidungen, entscheiden bei Konventionsfragen: Wenn eine Wahl Scope, Kosten oder Tradeoffs betrifft, die der Nutzer tragen muss, wird mit knappen, unterscheidbaren Optionen samt Empfehlung gefragt. Was Konvention oder aus dem Bestand ableitbar ist, wird entschieden und die Entscheidung begründet mitgeteilt.
- Lange Läufe (Testsuiten, Container-Builds) laufen als Hintergrund-Task mit Ausgabedatei. Deren Ausgabe nie durch früh terminierende Pipes filtern (`Select-Object -First N` beendet die Pipeline und würgt den laufenden Prozess ab); stattdessen Marker-Zeilen ausgeben (`"TESTS=$LASTEXITCODE"`) und die Datei danach auswerten. Suchmuster case-sensitiv wählen („FAILED" matcht sonst auch „0 failed").
- Commit-Messages über eine Datei und `git commit -F` übergeben; direkte Übergabe mehrzeiliger Messages scheitert an Shell-Quoting, unter PowerShell selbst im Here-String.
- PowerShell-Skripte, die native Programme rufen (docker, psql): kein globales `$ErrorActionPreference = 'Stop'`, denn Windows PowerShell macht aus harmlosen stderr-Hinweisen dann Abbrüche; Fehlerbehandlung über explizite Exit-Code-Prüfungen.
- Behauptungen werden live verifiziert, nicht behauptet: Ein gebautes Feature wird gegen die laufende Umgebung durchgespielt (der Drehbuch-Schritt aus `DEMO.md`), eine GUI bekommt Selbsttest-Schalter (`-SelfTest` baut nur das Fenster auf, ein Scan-Modus treibt die echte Mechanik headless), ein Skript wird ausgeführt, bevor es dokumentiert wird.
- Gelernte Umgebungs-Fallen (kaputte Toolchain-Symptome, Docker-Eigenheiten, PATH-Verhalten frischer Installationen) werden sofort in `umgebungs-fallen.md` im Repo festgehalten, nicht nur im Agenten-Memory: Das Repo überlebt Sitzungen, Maschinen und Agenten-Wechsel, das Memory nicht.
- Memory des Agenten ergänzt das Repo, ersetzt es nie: Dorthin gehören Etappenstand, aktueller Bauplan und Arbeitspräferenzen; ins Repo gehört alles, was ein Mensch oder eine andere Sitzung brauchen könnte.
- Parallele Sitzungen im selben Arbeitsverzeichnis koordinieren sich über Git (kleine Commits, vor Etappenstart `git log` lesen), nicht über Annahmen.

## 7 Glossar und Benennung

Am Projektstart eine kurze `glossar.md` anlegen: die zehn bis zwanzig tragenden Fachbegriffe des Projekts mit ihrer festgelegten Form (Beispiel aus dem Ursprungsprojekt: „Hülle" für den verschlüsselten Umschlag, „Ablage" für den Store, „Etappe" für den Arbeitsabschnitt). Der Grund ist derselbe wie bei DRY: Benennung ist Wissen, und zwei Namen für dieselbe Sache erzeugen bei jedem Leser die Frage, ob es auch dieselbe Sache ist. Neue Begriffe kommen ins Glossar, bevor sie in Code oder Doku streuen.

## 8 Was diese Guideline gegenüber dem Ursprungsprojekt verbessert

Diese Punkte sind oben bereits eingearbeitet; hier stehen sie gesammelt, damit sichtbar ist, was das nächste Projekt von Anfang an anders macht:

1. Git ab dem ersten Tag. Das Ursprungsprojekt begann als ZIP ohne Historie; die Basis-Commits mussten nachgeholt werden, und frühe Entscheidungen haben keinen nachvollziehbaren Verlauf.
2. Der Verifikations-Loop als eingechecktes Skript plus CI-Gate statt als Konvention. Konventionen erodieren; ein Skript, das CI und Mensch identisch fahren, nicht.
3. Diese Guideline als `CLAUDE.md` im Repo statt nur im Agenten-Memory. Das Memory ist sitzungs- und maschinengebunden; die Regeln gehören dorthin, wo jede Sitzung, jedes Werkzeug und jeder Mensch sie sieht.
4. `umgebungs-fallen.md` im Repo von Anfang an, gefüllt bei jedem Fund statt rückwirkend.
5. `glossar.md` von Anfang an, bevor Begriffe streuen.
6. `DEMO.md` (Behauptung plus Beweis-Handgriff) wächst je Etappe mit, statt am Ende nachgezogen zu werden: Wer den Beweis-Handgriff nicht nennen kann, hat die Etappe nicht abgeschlossen.
7. Die Definition of Done (grüne Gates, vorführbarer Beweis, Doku-Eintrag) steht ab der ersten Etappe, ebenso die Versionskonvention des Änderungsverlaufs (+0.1 je Etappe).
8. Die ANNAHME-Konvention wird am Projektstart vereinbart und ist grep-bar; im Ursprungsprojekt entstand sie unterwegs und musste in frühe Dokumente nachgetragen werden.
