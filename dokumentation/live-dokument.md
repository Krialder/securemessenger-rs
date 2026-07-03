# Live-Dokument: SecureMessenger

| Feld | Inhalt |
|------|--------|
| Dokumenttyp | Live-Dokument (Design Doc, fortlaufend gepflegt) |
| Projekt | SecureMessenger (Arbeitstitel) |
| Version | 0.16 |
| Datum | 03.07.2026 |
| Autor dieser Fassung | Kai Delor |
| Owner | Hr. Schiller (Projektleitung), Kai Delor |
| Status | Entwurf, in Arbeit |
| Anspruch | Industrie-Niveau (produktiver E2EE-Messenger), kein Übungsmaßstab |

**Quellen (ausschließlich):** Lastenheft v1.2, Pflichtenheft v1.2, README, architektur.md, protokoll.md, sicherheit.md, datenmodell.md, identitaet-und-geraete.md, schnittstellen.md, betrieb.md, roadmap.md, offene-fragen.md, die ADRs 0001 bis 0007 und die Specs (krypto-kern, mls-delivery-service, sealed-sender-und-abuse, key-transparency, geraete-identitaet, contact-discovery, backup-und-recovery).

**Methodischer Rahmen:** Design Doc nach Google (industrialempathy.com), Google Engineering Practices, Working-Backwards PR/FAQ nach Amazon, Postmortem-Kultur nach Google SRE.

**Legende:** **[ANNAHME: …]** kennzeichnet eine Festlegung, die nicht aus der Doku folgt, sondern hier getroffen wird. **[OFFENE FRAGE: …]** kennzeichnet einen ungeklärten Punkt mit Vorschlag zur Klärung.

**Regel zur Bearbeitungsreihenfolge:** Abschnitt 1 und 2 sind vollständig formuliert und gehen jeder Implementierung voraus. Die Abschnitte 5 und 6 fassen den bereits dokumentierten Entwurf zusammen und verweisen darauf. Neuer Produktivcode und neue API-Spezifikationen entstehen erst nach Bestätigung von Problem und Zielen durch den Owner.

---

## 1 Problem & Kontext

### 1.1 Das Problem

Die IT-Abteilung am RKI BBW Berlin-Kladow hat drei verbundene Probleme, die sich an einem Punkt bündeln.

1. **Vertraulichkeitslücke.** Die Kommunikation läuft über Teams und E-Mail. Diese Werkzeuge sind nicht Ende-zu-Ende verschlüsselt, der Betreiber kann mitlesen, und ein heute mitgeschnittener Verkehr ist später durch einen Quantencomputer angreifbar (harvest now, decrypt later).
2. **Doppelarbeit bei Querschnittsdiensten.** Jedes Ausbildungsprojekt löst Anmeldung, Kontenverwaltung und Benachrichtigung erneut und auf eigene Faust. Das Ergebnis sind uneinheitliche, oft schwache Eigenlösungen.
3. **Uneinheitlicher Betrieb.** Es fehlt ein gemeinsames, reproduzierbares Container- und Deployment-Muster, an dem sich neue Projekte ausrichten.

### 1.2 Kontext und Auftrag

Der SecureMessenger ist eine Ende-zu-Ende verschlüsselte Kommunikationsplattform, deren Server zu keinem Zeitpunkt Klartext sieht, und zugleich die gemeinsame technische Basis für die übrigen Ausbildungsprojekte. Er liefert vier Bausteine, die andere Projekte mitbenutzen: gesicherte Nachrichten, zentrale Identität samt Single Sign-on, Echtzeit-Benachrichtigungen und einen Container-Betriebsrahmen auf Kubernetes.

Der Anspruch ist produktives Niveau. Das System wird an denselben Eigenschaften gemessen wie kommerzielle E2EE-Messenger: nachprüfbare Schlüssel (Key Transparency), nachprüfbarer Client-Code (Binary Transparency), messbare Service Level Objectives und ein externes Sicherheitsaudit vor dem Produktivbetrieb.

### 1.3 Stakeholder

| Stakeholder | Interesse |
|-------------|-----------|
| Nutzer (Azubi) | vertrauliche Kommunikation auf allen Geräten, eine Anmeldung für alle Werkzeuge |
| Ausbilder | datensparsames, moderierbares System ohne eigene Lese-Möglichkeit |
| Administrator (IT-Netz) | stabiler, beobachtbarer On-Premise-Betrieb ohne Zugriff auf Geheimnisse |
| Integrations-Dienst (z. B. AzubiOS) | Identität, Benachrichtigung, Chat als fertige Dienste, ohne eigenen Stack zu ändern |
| Auftraggeber (Ausbildungsleitung) | Vertraulichkeit, einmal gebaute Querschnittsdienste, belegbare Betriebsgüte |

### 1.4 Harte Randbedingungen

- **On-Premise.** Kern-Dienste und Datenhaltung laufen auf der RKI-BBW-Infrastruktur, ohne Cloud-Abhängigkeit. Zwei benannte Ausnahmen: mobiler Push (APNs/FCM) und ein etwaiges späteres SVR (NF120).
- **Fremdprojekte sind unantastbar.** Der SecureMessenger passt sich an deren Schnittstellen an und verlangt keine Änderung an deren Code, Datenmodell oder Betriebsumgebung.
- **Keine Eigenbau-Kryptografie.** Sämtliche kryptografischen Primitive stammen aus geprüften Bibliotheken (libsignal, OpenMLS).

## 2 Ziele & Erfolgskriterien

### 2.1 Ziele

1. **Vertraulichkeit, die hält.** Inhalte bleiben dem Betreiber, dem Netzwerk und so weit möglich einem künftigen Quantenangreifer verborgen.
2. **Querschnittsdienste einmal bauen.** Identität, Benachrichtigung und Chat entstehen einmal sauber und werden von allen Projekten genutzt.
3. **Gemeinsamer Betriebsstandard.** Ein reproduzierbares Kubernetes-Muster, an dem sich Folgeprojekte ausrichten.
4. **Belegbare Betriebsgüte.** Verfügbarkeit, Latenz und Zustellzuverlässigkeit sind als SLOs definiert und werden gemessen.

### 2.2 Erfolgskriterien (messbar)

| Kriterium | Messgröße | Zielwert | Quelle |
|-----------|-----------|----------|--------|
| Inhalt serverseitig unlesbar | DB-Zeile ohne Client-Schlüssel entschlüsselbar | nein, vorgeführt | Lastenheft 8.2.1 |
| SSO produktiv | Drittprojekt-Login über OIDC | erfolgreich ohne eigene Kontenpflege | 8.2.2 |
| Echtzeit-Zustellung | `POST /messages` bis WebSocket-Event | p95 < 500 ms, p99 < 1 s | NF070 |
| Schlüssel-Manipulation | untergeschobener Schlüssel im Test | von Client-Selbstprüfung erkannt | 8.2.4 |
| Verfügbarkeit SSO | erfolgreiche Anmelde-/Token-Antworten | 99,9 % im Monat | NF060 |
| Verfügbarkeit übrige Dienste | erfolgreiche Antworten je Monat (24/7) | 99,5 % | NF060 |
| Zustell-Durability | angenommene Nachrichten bis Ack abrufbar | 99,99 % | NF130 |
| Resilienz Fremdprojekte | simulierter SSO-Ausfall | blockiert Fremdprojekt nicht hart | 8.2.6, NF160 |
| Krypto-Audit | externes Audit des Kerns | bestanden vor Produktivbetrieb | NF050 |

**Sicherheits-Invarianten (kein SLO, sondern hart):** kein Klartext und kein privater Schlüssel auf dem Server (NF010); kein unentdeckter Schlüsselwechsel (Key Transparency). Jede Verletzung ist ein Sicherheitsvorfall.

### 2.3 Nicht-Ziele (Kurzform, Detail in 4.3)

Föderation in der ersten Ausbaustufe, post-quantum Gruppen, komfortables Enclave-Backup (SVR) vor dem Fundament, Identität über Telefonnummer, jede technische Möglichkeit zur Inhaltsherausgabe.

## 3 Nutzerperspektive & Working-Backwards-Skizze

**[Skizze, fiktiv, im PR/FAQ-Stil nach Amazon. Dient der Perspektivprüfung, nicht als Tatsachenmitteilung.]**

### 3.1 Interne Ankündigung (zum gedachten Launch)

> **Die IT-Ausbildung bekommt einen eigenen, abhörsicheren Messenger.**
> Ab heute kommunizieren Auszubildende und Ausbilder über den SecureMessenger. Nachrichten sind Ende-zu-Ende verschlüsselt, der Server speichert ausschließlich unlesbaren Chiffretext. Ein Konto genügt für alle Abteilungs-Werkzeuge, weil die Anmeldung zentral über den SecureMessenger läuft. Andere Projekte wie AzubiOS binden Anmeldung und Benachrichtigung ein, ohne eigene Konten zu pflegen. Wer ein Gerät verliert, verliert nicht seine Identität, und wer wissen will, ob der Schlüssel des Gegenübers echt ist, kann das überprüfen statt es zu glauben.

### 3.2 Nutzer-Szenarien

- **A, vertrauliche Nachricht:** Eine sensible Absprache geht nicht mehr über Teams, sondern verschlüsselt; der Server sieht nur Chiffretext und meist nicht einmal den Absender (Sealed Sender).
- **B, Anmeldung im Projekt:** AzubiOS leitet die Anmeldung per SSO an den SecureMessenger weiter, ein Konto für alle Werkzeuge.
- **C, System-Benachrichtigung:** AzubiOS löst über eine Schnittstelle einen Hinweis aus, der Nutzer bekommt ihn in Echtzeit auf dem Gerät.
- **D, harvest now, decrypt later:** Heute mitgeschnittener 1:1-Verkehr bleibt auch gegen einen späteren Quantencomputer vertraulich (PQXDH hybrid).

### 3.3 FAQ

**Sieht der Betreiber meine Nachrichten?** Nein. Die Krypto läuft im Client, der Server hält nur Chiffretext und öffentliche Schlüssel.

**Was, wenn der Server bösartig ist und falsche Schlüssel ausliefert?** Der Client gleicht jeden Schlüssel automatisch gegen das Key-Transparency-Log ab und schlägt bei Abweichung Alarm. Gegen einen manipulierten Client schützt Binary Transparency.

**Sind Gruppen genauso geschützt wie 1:1?** Inhaltlich ja, aber Gruppen sind noch nicht post-quantum (MLS klassisch, bis der PQ-Standard reif ist). Wer in einer Gruppe ist, ist vor dem Server nicht geheim.

**Sind die Benachrichtigungen von AzubiOS Ende-zu-Ende verschlüsselt?** Nein, und das ist bewusst. Sie kommen von einem Server, nicht von einem Nutzer. Sie tragen nur einen minimalen Hinweis, die Details bleiben im Fremdprojekt.

**Was passiert bei Geräteverlust?** Die lokalen Daten sind an den Geräte-Keystore gebunden und ohne ihn nutzlos. Der Login ist über E-Mail und zweiten Faktor wiederherstellbar, der alte lokale Verlauf hängt am Recovery-Key.

**Was, wenn die Anmeldung (SSO) ausfällt?** Bereits ausgestellte Tokens überbrücken einen kurzen Ausfall, abhängige Projekte fliegen nicht sofort heraus (NF160). Der Dienst läuft redundant mit dem Ziel 99,9 %.

## 4 Anforderungen & Nicht-Ziele

### 4.1 Funktionale Anforderungen (gruppiert, Quelle Lastenheft 5)

- **Identität, Konten, Geräte (F010 bis F050):** Konto über Handle ohne Telefonnummer, rotierende Sessions, Multi-Device mit Freischaltung, Geräte-Identitätsbindung über signiertes Credential in der KT, RBAC.
- **Basis-Dienste (F060 bis F100):** SSO über OpenID Connect, Benachrichtigungs-Schnittstelle, Präsenz-Abruf, Chat als einbindbares Modul, Mandantenfähigkeit.
- **Schlüssel und KT (F110 bis F130):** Prekey-Verzeichnis klassisch und post-quantum, Key Transparency mit Client-Selbstprüfung, Verifikation über Safety Numbers.
- **Nachrichten (F140 bis F170):** 1:1 über PQXDH und Double Ratchet plus SPQR, Gruppen über MLS, idempotente Zustellung, Sealed Sender.
- **Medien, Suche, Echtzeit (F180 bis F200):** verschlüsselter Medienversand, Kontaktsuche per OPRF, WebSocket-Echtzeit plus Push.
- **Clients und Lieferkette (F210, F220):** Web (WASM) und native Clients (FFI) parallel, reproduzierbare signierte Builds mit Binary Transparency.

### 4.2 Nicht-funktionale Anforderungen (Quelle Lastenheft 6)

- **Sicherheit/Datenschutz (NF010 bis NF050):** Zero Knowledge für Inhalte, Post-Quantum-Vertraulichkeit 1:1, DSGVO und Datensparsamkeit, Argon2id, zwei externe Audits.
- **Betrieb/Qualität (NF060 bis NF120):** differenzierte Verfügbarkeit, Latenz-Ziele, Skalierbarkeit, Modularität, Beobachtbarkeit, getestete Backups, On-Premise mit benannten Ausnahmen.
- **Betriebsgüte/Resilienz (NF130 bis NF160):** SLOs mit Fehlerbudget, Kapazitätsplanung, Incident-Response und Postmortems, Resilienz gegenüber Fremdprojekten.

### 4.3 Nicht-Ziele (mit Begründung)

- **Föderation in Stufe 1.** Ein Betreiber schützt Metadaten am besten. Föderation ist später kein Schalter, sondern eine eigene Vertrauenstopologie (ADR-0001).
- **Post-quantum Gruppen.** MLS ist in den Standard-Suiten klassisch, der PQ-Pfad existiert nur als Draft. 1:1 ist über PQXDH abgedeckt.
- **SVR vor dem Fundament.** Komfort-Backup über Enclave kommt später und nur unter Threshold und Genehmigung (NF120).
- **Identität über Telefonnummer.** Bewusst nicht, wegen Personenbezug und sozialem Graph. Preis ist schwerere Sybil-Abwehr.
- **Technische Inhaltsherausgabe.** Das System ist so gebaut, dass der Betreiber Inhalte nicht herausgeben kann. Das ist eine Position mit Compliance-Folgen (siehe 8).
- **Ende-zu-Ende verschlüsselte Maschinen-Benachrichtigungen.** Server-generierte Hinweise können das nicht leisten und werden bewusst minimal gehalten.

## 5 Architektur- / Lösungsentwurf

Zusammenfassung des dokumentierten Entwurfs. Das verbindliche Diagramm und die Dienst-Tabelle stehen in [architektur.md](architektur.md) und [pflichtenheft.md](pflichtenheft.md) Abschnitt 3, die Schnittstellen in [schnittstellen.md](schnittstellen.md), das Krypto-Detail in [protokoll.md](protokoll.md) und [specs/krypto-kern.md](specs/krypto-kern.md).

### 5.1 Form

Eine Handvoll zustandsarmer Rust-Dienste hinter einer Edge-Schicht. Clients sprechen REST für ausgelöste Aktionen und eine dauerhafte WebSocket-Verbindung für servergetriebene Hinweise. Die Krypto läuft nicht im Backend, sondern im Rust-Core auf den Clients (WASM im Web, FFI nativ). Das Backend hält und verteilt Chiffretext.

### 5.2 Dienste

Edge/Ingress, Identität & Auth, OIDC-Provider (Standard-Provider, redundant), Benachrichtigungs-Gateway, Schlüssel-Verzeichnis, Key Transparency, Zustellung, MLS Delivery Service, Echtzeit & Presence, Medien, Kontaktsuche, Push. Datenhaltung: PostgreSQL (geshardet nach Konto-ID, Nachrichten nach Monat partitioniert), Redis (Presence, Zähler), MinIO (Medien), NATS JetStream (Fanout), Merkle-Store (KT).

### 5.3 Krypto-Modell

PQXDH (X25519 plus ML-KEM-768) für den Sitzungsaufbau, Double Ratchet plus SPQR für die laufende 1:1-Sitzung, MLS (RFC 9420, Suite 0x0003) für Gruppen, Sealed Sender mit anonymen Credentials (zkgroup-Linie), Key Transparency (CONIKS-Linie, VRF, Epochen, Auditoren plus Gossip), Binary Transparency mit reproducible builds. Die hybride Bindung in PQXDH und SPQR ist die heikelste Stelle, wird 1:1 aus libsignal übernommen und ist Audit-Schwerpunkt.

### 5.4 Basis-Dienste

SSO über einen gehärteten Standard-OIDC-Provider (Default Keycloak), getrennt von der kryptografischen Identität. Benachrichtigungen als markierte Maschinen-Hinweise mit minimalem Inhalt. Präsenz-Abruf rate-limitiert. Mandantenfähigkeit über OAuth2-Clients je Projekt.

### 5.5 Trust Boundaries (Quelle sicherheit.md)

Vertraut: das Endgerät (solange nicht kompromittiert), der nachprüfbare Client-Core. Nicht vertraut: Transport (deshalb E2E über TLS), Server für Inhalte (nur für Routing notgedrungen), Push-Provider (sehen Token und Timing). Der Web-Client ist das kryptografisch schwächste Glied und wird so behandelt.

### 5.6 Stack

Rust mit tokio, axum, tokio-tungstenite, sqlx, async-nats, redis-rs. Docker plus Kubernetes auf Proxmox, GitOps, Operatoren für den Zustand. Begründung der Sprachwahl in [pflichtenheft.md](pflichtenheft.md) 4.1.

## 6 Implementierungsplan & Artefakte

### 6.1 Phasen (Quelle roadmap.md, Pflichtenheft 11)

| Meilenstein | Inhalt |
|-------------|--------|
| M1 Specs | Bibliotheken pinnen, Threat Model (LINDDUN/STRIDE); der externe Review rückt zum ersten Audit (M4), siehe ADR-0008 |
| M2 Fundament | Identität, Auth, Geräte, Schlüssel-Verzeichnis, KT-Grundgerüst, reproducible builds, SLO-Messung, Web plus ein nativer Client |
| M3 Basis-Dienste | OIDC redundant, Benachrichtigung, Präsenz, Mandanten; Drittprojekt-Test inkl. Degradation |
| M4 1:1-Nachrichten | PQXDH, Ratchet plus SPQR, Multi-Device-Fanout; erstes externes Audit (Hybrid-Bindung) |
| M5 Metadaten/Verifikation | Sealed Sender, KT vollständig (Auditoren, Gossip), Safety Numbers, Contact Discovery |
| M6 Gruppen | MLS, Delivery Service gehärtet |
| M7 Medien/Härtung | Medienversand, Fuzzing, Property-Tests, zweites externes Audit vor Launch |

### 6.2 Artefakte

Quellcode im Git-Repository, Container-Images in der internen Registry, Kubernetes-Manifeste und Helm-Charts, OpenAPI-Spezifikation der REST-API, OIDC-Konfiguration, reproducible-Build-Pipeline mit Binary-Transparency-Log, Threat Model, Audit-Berichte, Restore-Test-Protokoll, System- und Benutzerhandbuch.

### 6.3 Hinweis zur Reihenfolge

Detaillierte API- und Code-Artefakte (über die in [schnittstellen.md](schnittstellen.md) skizzierten Endpunkte hinaus) entstehen erst nach Bestätigung von Abschnitt 1 und 2 durch den Owner. Der Owner hat diese Bestätigung am 30.06.2026 erteilt, seither läuft die Umsetzung (Stand im Änderungsverlauf).

## 7 Betriebsaspekte & Qualität (SRE-Perspektive)

### 7.1 Service Level Objectives (Quelle betrieb.md, NF130)

| SLO | Indikator | Ziel | Fehlerbudget |
|-----|-----------|------|--------------|
| Verfügbarkeit Identität/SSO | erfolgreiche Anmelde-/Token-Antworten je Monat | 99,9 % | rund 43 min/Monat |
| Verfügbarkeit übrige Dienste | erfolgreiche Antworten je Monat (24/7) | 99,5 % | rund 3,6 h/Monat |
| Zustell-Latenz Echtzeit | `POST /messages` bis WebSocket-Event | p95 < 500 ms, p99 < 1 s | Anteil über Schwelle |
| API-Latenz | REST-Antwortzeit | p95 < 2 s | Anteil über Schwelle |
| Zustell-Durability | angenommene Nachrichten bis Ack abrufbar | 99,99 % | kein stiller Verlust |

Bei aufgebrauchtem Fehlerbudget hat Stabilisierung Vorrang vor neuen Funktionen.

### 7.2 Beobachtbarkeit

Strukturierte Logs nach stdout, niemals mit Nachrichteninhalt. Prometheus-Metriken, OpenTelemetry-Tracing über die Dienstgrenzen, `live`- und `ready`-Probes je Dienst. Die Metriken speisen die SLO-Auswertung direkt.

### 7.3 Deployment und Release

Ein Deployment je Dienst mit HPA und mindestens zwei Repliken auf den kritischen Pfaden. Zustand über Operatoren (CloudNativePG, Redis-Operator, NATS, MinIO). GitOps (ArgoCD oder Flux), sodass der Cluster-Zustand aus Git folgt. Client-Builds reproduzierbar und signiert, Hash im Binary-Transparency-Log.

### 7.4 Datenhaltung, Backup, Löschung

Tägliche verschlüsselte Backups mit regelmäßigem Restore-Test (ein ungetestetes Backup zählt nicht). Entschlüsselungs-Geheimnis nicht beim Betreiber. Löschen über Crypto-Shredding, Kontolöschung mit Widerrufsfrist.

### 7.5 Incident-Response

Definierter Eskalationspfad mit Schweregrad-Klassen. Nach jedem SLO-Bruch und jedem Sicherheitsvorfall ein blameless Postmortem (Vorlage in Abschnitt 9). Sicherheitsvorfälle (KT-Split-View-Verdacht, Schlüssel-Leak, kompromittierter Wurzelschlüssel) folgen einem strengeren Security-Incident-Prozess mit sofortiger Eindämmung. **[OFFENE FRAGE: Bereitschafts- und Eskalationsmodell für den 24/7-Betrieb, weil die SLOs ohne Reaktion außerhalb der Bürozeiten nicht haltbar sind.]**

### 7.6 Kapazität

Dimensionierung nach realer Last, die NF080-Fähigkeit ist die technische Kapazität, nicht der Startbedarf. **[OFFENE FRAGE: verbindliche Nutzer- und Gerätezahl, gleichzeitige Verbindungen, Nachrichten pro Tag.]** **[ANNAHME: Startbereich einige Dutzend bis wenige Hundert aktive Konten.]**

## 8 Risiken, Trade-offs & Alternativen

| ID | Risiko | Auswirkung | Gegenmaßnahme (Stand) | Restrisiko / Alternative |
|----|--------|------------|------------------------|--------------------------|
| R1 | KT-Auditor-Governance offen | Split-View-Schutz unvollständig | Client-Gossip als Mindestschutz ab Phase 3 | Restrisiko bis externer Auditor steht; Alternative: Hochschul- oder Vereinsbetrieb |
| R2 | Web-Client schwächstes Glied | XSS oder Extension umgeht Krypto | Binary Transparency, ehrliche Einordnung | Restrisiko bleibt; Alternative: native Clients bevorzugen, Web als Companion |
| R3 | Gruppen nicht post-quantum | harvest-now-decrypt-later für Gruppen | bewusste Grenze, 1:1 ist PQ | Alternative: PQ-MLS nachziehen, sobald in OpenMLS |
| R4 | Wurzelschlüssel-Kompromittierung | Vertrauensbaum offen | Revocation, Out-of-band, Safety-Number-Reset (5.1 Pflichtenheft) | Detail-Mechanik offen, Audit-Gegenstand |
| R5 | OIDC-Provider zweite Laufzeit (JVM) | widerspricht Ein-Sprachen-Ziel | bewusster Trade-off für Sicherheit | Alternative: eigener Rust-OIDC-Dienst mit eigener Angriffsfläche |
| R6 | Push-Provider sehen Token/Timing | Metadaten-Leak, Cloud-Abhängigkeit | nur Wakeup, kein Inhalt; UnifiedPush geprüft | Restrisiko bei Apple/Google bleibt |
| R7 | Abhängigkeit libsignal/OpenMLS | Tempo an fremde Release-Zyklen gebunden | gepinnte Commits, kein Eigenbau | bewusst, bei PQ-MLS sogar Vorteil |
| R8 | Sybil/Abuse ohne Telefonnummer | Massenkonten leichter | PoW plus Privacy Pass, Franking, Empfänger-Kontrollen | Bremse, kein Riegel (sealed-sender-Spec) |
| R9 | Audit-Budget und -Beauftragung | ohne Audit kein Produktivbetrieb | als NF050 verbindlich, früh klären | **[OFFENE FRAGE: Finanzierung der Audits]** |
| R10 | Kapazität ohne Lastzahlen | Fehldimensionierung | Annahme plus offene Frage (7.6) | Klärung mit IT-Infrastruktur |
| R11 | Krypto-Code entsteht vor externem Review (ADR-0008) | Review kann Umbau bereits gebauten Codes verlangen | Eigenanteil minimal halten, Bibliotheks-APIs nicht umbauen, Property-Tests und Fuzzing ab Start | bewusster Trade-off des Auftraggebers; Review bleibt Pflicht vor Produktivbetrieb |

## 9 Postmortem-Vorlage

Blameless nach Google SRE. Auszufüllen nach jedem SLO-Bruch und jedem Sicherheitsvorfall. Schuldzuweisung ist ausgeschlossen, der Fokus liegt auf Systemursachen.

```
# Postmortem: <kurzer Titel>

| Feld | Inhalt |
|------|--------|
| Datum des Vorfalls | |
| Autoren | |
| Status | in Arbeit / abgeschlossen |
| Schweregrad | SEV-1 (kritisch) / SEV-2 / SEV-3 |

## Zusammenfassung
Ein bis drei Sätze: was, wie lange, welche Wirkung.

## Auswirkung
Betroffene Nutzer und Dienste, Dauer, betroffene SLOs und verbrauchtes Fehlerbudget.
Bei Sicherheitsvorfall: Art der möglichen Offenlegung.

## Auslöser (Trigger)
Was den Vorfall unmittelbar ausgelöst hat.

## Erkennung (Detection)
Wie und nach welcher Zeit der Vorfall bemerkt wurde (Alert, Nutzer-Meldung, Audit).

## Grundursachen (Root Cause)
5-Why oder Ursachenkette. Mehr als eine Ursache ist normal.

## Behebung und Wiederherstellung
Was getan wurde, um den Dienst wiederherzustellen.

## Zeitleiste (UTC)
- TT.MM. HH:MM  Ereignis
- TT.MM. HH:MM  Ereignis

## Lessons Learned
- Was lief gut
- Was lief schlecht
- Wo hatten wir Glück

## Maßnahmen (Action Items)
| Maßnahme | Typ (Prävention/Erkennung/Abmilderung) | Owner | Priorität | Ticket |
|----------|----------------------------------------|-------|-----------|--------|

## Anhang
Logs, Metriken, Diagramme, Links.
```

**Beispiel-Vorfallklassen für dieses System:** KT-Inkonsistenz oder Split-View-Verdacht (SEV-1, Security-Prozess), Verdacht auf Schlüssel-Leak (SEV-1), SSO-Ausfall mit Blast Radius auf Fremdprojekte (SEV-2), Prekey-Erschöpfung eines Geräts (SEV-3), Latenz-SLO-Bruch in der Zustellung (SEV-2/3).

## 10 Änderungsverlauf

| Version | Datum | Autor | Beschreibung |
|---------|-------|-------|--------------|
| 0.1 | 30.06.2026 | Kai Delor | Erstfassung, vollständig aus der Eingangsdoku (Hefte v1.1, Top-Level-Docs, ADRs 0001 bis 0007, Specs, offene-fragen) abgeleitet. Alle zehn Pflichtabschnitte ausgefüllt, Annahmen und offene Fragen markiert. |
| 0.2 | 02.07.2026 | Kai Delor | Betrieb auf 24/7 umgestellt (Nutzer-Entscheidung), Fehlerbudget der übrigen Dienste 3,6 h/Monat. Abschnitt 1 und 2 vom Owner bestätigt. Umsetzung gestartet: Rust-Workspace mit identity-Dienst (Registrierung, Login mit Argon2id, Sessions, Tests), Docker- und Kubernetes-Skelett, Setup-Skripte; axum auf 0.8 angehoben. |
| 0.3 | 02.07.2026 | Kai Delor | identity: rotierende Sessions (F020) umgesetzt. Kurzlebige Access-Token und einmal verwendbare Refresh-Token, Rotation über `POST /sessions/refresh`, Wiederverwendung eines rotierten Tokens widerruft die Session-Familie (OAuth 2.0 Security BCP, RFC 9700), Logout widerruft die Familie. Tokens liegen nur als SHA-256-Hash in der Ablage. **[ANNAHME: Laufzeiten 15 Minuten Access, 30 Tage Refresh; die Doku nennt keine Werte.]** |
| 0.4 | 02.07.2026 | Kai Delor | Nutzer-Entscheidung: Krypto-Kern wird vor dem externen Spec-Review gebaut, Review rückt vor den Produktivbetrieb und läuft spätestens mit dem ersten Audit (M4) zusammen. Neu: ADR-0008, Risiko R11, Hefte auf v1.3, Roadmap/betrieb.md/Code-Kommentare nachgezogen. Persistenz-Entscheidung: PostgreSQL direkt nach der Geräteverwaltung. |
| 0.5 | 02.07.2026 | Kai Delor | identity: Geräteverwaltung (F030/F040). Registrierung legt Konto plus erstes Gerät atomar an (Ed25519-Identitätsschlüssel, signiertes Geräte-Credential, Server prüft mit verify_strict), Sessions sind gerätegebunden, `GET/POST /devices` und `DELETE /devices/{id}` mit sofortigem Session-Widerruf; revozierte Geräte-IDs bleiben gesperrt (Credential-Replay-Schutz), das eigene Gerät ist nicht entfernbar (Aussperr-Schutz). **[ANNAHME: Credential-Format smdc.v1, die Spec lässt das Format offen; Gültigkeitsdauer wählt der Client.]** MLS-Neuschlüsseln beim Entfernen folgt mit der MLS-Anbindung. |
| 0.6 | 02.07.2026 | Kai Delor | identity: PostgreSQL-Persistenz hinter den Store-Traits (sqlx, eingebettete Migrationen beim Start). Mit `DATABASE_URL` persistiert der Dienst, ohne läuft er in-memory mit Warnung; Start bricht bei Verbindungs- oder Migrationsfehler ab. Schema nach datenmodell.md (UUID, BYTEA, revoked_at statt Löschen), ergänzt um password_hash/identity_key am Konto, not_after am Gerät und die Session-Tabellen; datenmodell.md nachgezogen. Geräte-IDs sind jetzt client-erzeugte UUIDs in kanonischer Form (global eindeutig, Teil der signierten Credential-Nachricht). Refresh-Rotation läuft in einer Transaktion mit Zeilensperre, Reuse-Erkennung über used_refresh_hashes. PG-Integrationstests inklusive Neustart-Beweis (zwei App-Instanzen, eine Datenbank) laufen nur mit `TEST_DATABASE_URL`. |
| 0.7 | 02.07.2026 | Kai Delor | Schlüssel-Verzeichnis (F110) als eigener directory-Dienst mit eigener Datenbank (Nutzer-Entscheidung: sofort eigener Dienst statt Übergangslösung in identity). Prekey-Pools pro Gerät in vier Arten (signed, one_time, pq_signed, pq_one_time für PQXDH), Upload rotiert signierte und füllt Einmal-Pools, `GET /keys/{handle}` liefert Bündel aller gültigen Geräte und konsumiert Einmal-Prekeys atomar (`FOR UPDATE SKIP LOCKED`, Nebenläufigkeits-Beweis im PG-Test). Prekeys sind opake Blobs, der Server interpretiert sie nie. identity bekam dafür Dienst-zu-Dienst-Routen (`/internal/introspect` nach RFC-7662-Zuschnitt, `/internal/accounts/{handle}/devices`), abgesichert über Shared Secret `INTERNAL_TOKEN`; ohne Secret existieren die Routen nicht. **[ANNAHME: Shared Secret statt mTLS bis zur Betriebs-Etappe; Bündel-Abruf nur mit Konto-Session, Rate-Limit folgt am Edge; Zählstände über eigenen GET-Endpunkt.]** Sender-Credentials (Sealed Sender) folgen mit der zugehörigen Etappe. |
| 0.8 | 02.07.2026 | Kai Delor | Zustellung (F050) als eigener delivery-Dienst mit eigener Datenbank. Store-and-Forward: `POST /messages` nimmt opake Hüllen an (eine je Zielgerät, Fan-out über die interne identity-API), `GET /messages` liefert in Eingangsreihenfolge ohne zu löschen, erst `POST /messages/ack` räumt weg. Idempotenz über eine Dedupe-Tabelle, weil der partitionierte Primärschlüssel (id, received_at) die Hüllen-ID nicht global eindeutig halten kann; Duplikat-Erkennung überlebt die Zustellung, sonst würden späte Retries erneut zustellen. Monatspartitionen legt der Dienst beim Schreiben selbst an (Advisory Lock gegen Rennen). `GET /ws` liefert Echtzeit-Hinweise `message.waiting` (nie Inhalte); Auth über ersten Frame `{"token":...}`, Close 4401/1011. Kein Absender in der Ablage. identity-Konten tragen jetzt eine Server-erzeugte UUID als interne Adresse (`recipient_id`), die interne API liefert sie mit; der `IdentityGateway`-Baustein zog nach crates/common um. **[ANNAHME: Bearer-Auth beim Einreichen bis zur Sealed-Sender-Etappe (Absender wird geprüft, nie gespeichert); Hülle max. 64 KiB, Batch max. 100; Hinweise In-Prozess bis zur Skalierungs-Etappe (NATS).]** |
| 0.9 | 02.07.2026 | Kai Delor | Basis-Dienste für Fremdprojekte (Phase 1b): neuer integrations-Dienst mit eigener Datenbank. Mandantenfähigkeit (F100): jedes Fremdprojekt hat client_id, Argon2id-gehashtes Client-Secret (einmal sichtbar), Scopes (`notify`, `presence`) und eigenes Rate-Limit (429 mit Retry-After); Token-Tausch über `POST /integrations/token` (Client-Credentials-Zuschnitt, SHA-256-Ablage). Benachrichtigungs-Gateway (F070): `POST /integrations/{tenant}/notify` löst ein markiertes, minimales `integration.notification`-Event aus (nur Mandant und Titel), zugestellt über die neuen /internal-Routen von delivery an verbundene Geräte. Präsenz (F080): `GET /integrations/{tenant}/presence/{handle}`; delivery führt die Registry verbundener WebSockets (RAII-Guard) und beantwortet die interne Abfrage. Token eines Mandanten funktionieren nie unter fremdem Pfad (403 tenant_mismatch). SSO (F060): Keycloak-Deployment-Skelett statt Eigenbau (deploy/k8s/keycloak.yaml). **[ANNAHME: Token-Laufzeit 1 h; Rate-Limit In-Prozess bis Redis kommt (je Replik); Präsenz-Freigabe pauschal an bis Nutzer-Einstellungen existieren; Mandanten-Anlage über interne Betriebs-Route; Webhooks und Realm-/Konten-Anbindung von Keycloak folgen später.]** |
| 0.10 | 02.07.2026 | Kai Delor | Krypto-Kern angelegt (`crates/client-core`, ADR-0005): libsignal v0.96.4 und OpenMLS v0.8.1 per `rev` auf Release-Commits gepinnt (Commits in specs/krypto-kern.md "Version-Pins", dort jetzt festgeschrieben). Das Crate orchestriert nur - PQXDH-Hybrid-Bindung und SPQR-Mischung kommen unverändert aus libsignal, kein Backend-Dienst hängt davon ab (Docker baut je Dienst, ohne protoc). Festlegungen an einer Stelle: MLS-Suite 0x0003 (ChaCha20-Poly1305), Skipped-Keys-Fenster 2000 vorwärts. Integrations-Beweise als Tests: PQXDH-Aufbau trägt den ML-KEM-Chiffretext auf der Leitung, Ratchet-Roundtrip beidseitig, Out-of-Order, Replay-Erkennung (DuplicatedMessage), MLS-Gruppen-Roundtrip übers TLS-Wire-Format mit Exporter-Secret-Gleichheit. Build braucht protoc (scripts/setup.ps1 installiert es). **[ANNAHME: PQXDH mit ML-KEM-1024 wie libsignal produktiv; BasicCredential und In-Memory-Ablage bis Geräte-Credentials und Client-Etappe; Out-of-Order-Toleranz 10.]** FFI/WASM und persistente Geräte-Ablage folgen mit der Client-Etappe. |
| 0.11 | 02.07.2026 | Kai Delor | Medien, Rate-Limits, SLI-Metriken. Medien-Dienst (F180): `POST /media` nimmt den verschlüsselten Blob als rohen Body (Referenz = server-erzeugte UUID als Capability), `GET /media/{ref}` liefert ihn zurück; der Server sieht nur Chiffretext ohne Metadaten, der Schlüssel reist in der Nachricht. Ablage über object_store (S3/MinIO per `MEDIA_S3_*`, sonst In-Memory mit Warnung), keine eigene Datenbank. Rate-Limits auf den heißen Pfaden (Pflichtenheft 6.4, Baustein `common::rate`, 429 mit Retry-After): Login 10/min und Registrierung 5/min je Handle, Bündel-Abruf 30/min je Abrufer (konsumiert fremden Vorrat), Medien 30/120 je Konto, Integrations-API je Mandant. SLI-Metriken (betrieb.md): Middleware `common::metrics::track` in allen Diensten, `/metrics` liefert `http_requests_total{method,route,status}` und Latenz-Histogramme je Route (Routenmuster statt roher Pfad gegen Kardinalität). **[ANNAHME: Blob max. 50 MiB, Upload 30/min, Abruf 120/min; Rate-Limits In-Prozess je Replik bis Redis; Login-/Registrierungs-Limits je Handle (IP-Limits an die Edge); Chunking/resumable Uploads offen; Retention/GC mit der Betriebs-Etappe.]** |
| 0.12 | 02.07.2026 | Kai Delor | CI, reproduzierbare Builds, Kubernetes-Zusammenbau (Pflichtenheft 8.2). CI-Pipeline als Vorlage für Folgeprojekte (.github/workflows/ci.yml): Format, Clippy (-D warnings), volle Testsuite inkl. PG-Integrationstests (Service-Container, eine Datenbank je Dienst, protoc für den Krypto-Kern), Docker-Build je Dienst als Matrix. Dockerfile eingabestabil: Basis-Images per Digest gepinnt (Tags sind beweglich), `cargo build --locked` erzwingt den Cargo.lock-Stand; Rust-Version bleibt synchron zu rust-toolchain.toml. deploy/k8s jetzt komplett anwendbar (`kubectl apply -k`): Namespace, je Dienst Deployment+Service, Keycloak, Ingress (nur öffentliche Pfade - /internal taucht dort nie auf), NetworkPolicy (Namespace-Verkehr plus Ingress-Controller, zweite Schicht neben dem Shared Secret), Kustomization. **[ANNAHME: GitHub-Actions-Syntax als Vorlage, Betrieb später auf eigenem Runner; Registry-Push und GitOps-Anbindung folgen mit der Betriebs-Etappe; bit-identische Images sind erst für Client-Builds gefordert (F220), fürs Backend genügt Eingabestabilität; Ingress-Hosts sind Platzhalter.]** |
| 0.13 | 03.07.2026 | Kai Delor | Key Transparency (F120) als eigener kt-Dienst mit eigener Datenbank fertiggestellt. identity meldet jede Schlüsseländerung fire-and-forget an kt (`POST /internal/updates`, Commitment `smktc.v1` = SHA-256 über Identitätsschlüssel und sortierte Gerätemenge); kt führt das append-only Log (`kt_updates`), der Epochen-Publisher bündelt es zu signierten Wurzeln (`kt_epochs`). akd v0.12 (Metas KT-Bibliothek) statt Merkle-Eigenbau; PostgreSQL ist die Quelle der Wahrheit, der AZKS-Baum wird beim Start deterministisch aus dem Log wiederaufgebaut und gegen die Wurzeln geprüft (Integritätsbruch = harter Startfehler). Ed25519-Wurzelsignatur (`KT_SIGNING_KEY`) und VRF (`KT_VRF_KEY`) sind die von der Spec erlaubten Server-Schlüssel, dokumentierte Ausnahme der Krypto-Grenze. Der volle Prüf-Lauf (alle fünf PG-Datenbanken) legte drei versteckte Fehler offen, die behoben wurden: der nie gelaufene KT-Test mit falscher Argumentzahl, ein brüchiger Medien-Test am Router-404 statt Handler-404, zwei clippy-Meldungen im kt-Dienst. kt in CI, Kustomization und Setup verdrahtet, bewusst als Singleton-Deployment (der Epochen-Publisher darf nicht doppelt laufen). **[ANNAHME: eine Replik bis zum herausgelösten, leader-gewählten Publisher; Auditoren und Gossip gegen den Split-View in Phase 3; Epochenlänge `KT_EPOCH_SECONDS` Default 3600.]** |
| 0.14 | 03.07.2026 | Kai Delor | Client-Etappe gestartet (GOAL.md als Zielbild und Arbeits-Prompt, referenzierbar mit /goal; gestaffelte Meilensteine, dreischichtige Client-Architektur). Meilenstein 0 erreicht: der Krypto-Kern `crates/client-core` baut nach `wasm32-unknown-unknown`, die Browser-Machbarkeit des Web-Clients ist damit belegt. Nötig waren drei zielgebundene Weichen (getrandom 0.2 Feature `js`, getrandom 0.3 Feature `wasm_js` plus Compiler-cfg in `.cargo/config.toml`, OpenMLS Feature `js`); native Builds bleiben unverändert, beide Roundtrip-Beweise weiter grün. Erster vertikaler Schnitt von Meilenstein 1: neue Bibliothek `crates/client-app` (Konto- und Geräteschlüssel, signiertes Geräte-Credential `smdc.v1` passend zur Server-Prüfung, HTTP-Client für Registrierung/Login/Rotation/Logout) plus Headless-Referenzclient `clients/cli` (`sm register/login/logout/whoami`). Bewiesen durch hermetische End-to-End-Tests gegen den echten identity-Router in-process (Roundtrip, falsches Passwort 401, doppeltes Handle 409); `client-app` baut ebenfalls nach wasm32 (reqwest über fetch). Nutzer-Entscheidung: die libsignal-Nachrichten-Identität wird der Geräteschlüssel im Credential (Weg A, eine Geräte-Identität statt zwei), Umsetzung mit dem Nachrichten-Layer samt ADR. **[ANNAHME: Klartext-JSON-Profil des CLI als Entwickler-Bequemlichkeit bis zur verschlüsselten Geräte-Ablage des Nachrichten-Layers.]** |
| 0.15 | 03.07.2026 | Kai Delor | Nachrichten-Layer, erster Durchstich (Weg A umgesetzt, ADR-0009): die serialisierte libsignal-Identität des Geräts ist der Geräteschlüssel im Credential; identity prüft Geräteschlüssel seither opak (Base64, 1 bis 128 Bytes) statt als Ed25519-Punkt, die Credential-Signatur bleibt Ed25519 `verify_strict`. Spec zur Geräte-Identität und datenmodell.md nachgezogen. `client-app` neu: Blob-Codec `smpk.v1` (libsignal-`PreKeyBundle` in die opaken Verzeichnis-Blobs und zurück, trägt Registration-ID und Protokoll-Gerätenummer im signierten Blob), Hüllen-Framing `smenv.v1` um den libsignal-Chiffretext, directory-Client (Prekeys veröffentlichen, Bündel holen) und delivery-Client (einreichen, abholen, bestätigen). Krypto-Kern um Zugriffe erweitert (`identity_public`, `identity_keypair_bytes`, `registration_id`, `from_identity_bytes`); CLI-Profil hält jetzt die libsignal-Identität. Kernbeweis `messaging_e2e`: zwei Nutzer über die echte Dienstkette identity+directory+delivery in-process, PQXDH-Sitzungsaufbau aus dem Verzeichnis-Bündel, E2EE-Nachrichten in beide Richtungen, Ack räumt weg, und die Ablage der Zustellung enthält nachweislich keinen Klartext. **[ANNAHME: Hüllen-Framing trägt Absender-Handle und -Gerätenummer im Klartext, sichtbar für den Server und bis zum Ack in der Ablage; genau diese Lücke schließt die Sealed-Sender-Etappe. Protokoll-Gerätenummer konstant 1 bis zur Multi-Device-Etappe. Offen im Nachrichten-Layer: KT-Selbstprüfung im Client, WebSocket-Hinweiskanal, persistente Sitzungs-Ablage, CLI-Sendebefehle.]** |
| 0.16 | 03.07.2026 | Kai Delor | Persistente Sitzungs-Ablage und CLI-Chat. Der Krypto-Kern-`Device` ist jetzt generisch über die Protokoll-Ablage (`ProtocolStoreParts`: die fünf libsignal-Teil-Ablagen als disjunkte `&mut`-Referenzen; In-Memory bleibt der Default für Tests). `client-app` neu: `storage.rs` (Storage-Trait aus GOAL.md, In-Memory und JSON-Datei mit Temporärdatei-plus-Umbenennen gegen zerrissene Zustände) und `protocol_store.rs` (libsignals fünf Store-Traits über dem Storage-Trait, Semantik der In-Memory-Referenz inklusive Trust-on-first-use und Basisschlüssel-Gedächtnis gegen Kyber-Replays). Beweise: Sitzung überlebt die Geräte-Rekonstruktion (zweite Nachricht ist eine Ratchet-, keine Aufbau-Nachricht), verbrauchte Einmal-Prekeys bleiben nach dem Neuladen verbraucht. CLI erweitert um `publish-keys`, `send` (Bündel-Abruf und PQXDH bei Bedarf, Fan-out an alle Geräte des Kontakts) und `recv` (abholen, entschlüsseln, bestätigen); Kontakte und Prekey-Zähler liegen in der Zustands-Ablage. Chat-Beweis `chat_e2e`: zwei Nutzer chatten über die echte Dienstkette, jeder `sm`-Befehl ein eigener Prozess des echten Binaries; damit ist der Meilenstein-1-Baustein "zwei Instanzen tauschen über die echten Dienste Nachrichten" erreicht. **[ANNAHME: Zustands-Ablage unverschlüsseltes JSON wie das Profil (Entwickler-Bequemlichkeit, Keystore-Anbindung eigene Etappe); Storage-Trait synchron, die asynchrone IndexedDB-Anbindung regelt die Web-Etappe; eine Antwort auf eine empfangene Nachricht baut derzeit eine frische PQXDH-Sitzung auf, statt die eingehende weiterzuverwenden.]** |
| 0.17 | 03.07.2026 | Kai Delor | Web-Client baufähig, Entwicklungsumgebung vervollständigt. Der erste Leptos-Schnitt (`clients/web`: Konto anlegen, senden, abrufen; Ablage In-Memory) kompilierte bisher weder nativ noch nach wasm32: `js-sys` fehlte als Abhängigkeit, und der Leptos-Renderer verlangt `Send` von reaktiven Closures, was der bewusst eindrähtige Client-Zustand (`Rc<RefCell<...>>`) nicht erfüllt. Behoben über `SendWrapper` (der Leptos-übliche Weg für den eindrähtigen Browser: panict bei Fremd-Thread-Zugriff, statt still Daten zu zerreißen) und eine cfg-Weiche: der Browser-Code (nach `app.rs` verschoben) existiert nur für wasm32, nativ bleibt ein erklärender Stub, damit `cargo test --workspace` den Web-Client nie wieder brechen kann; seine Abhängigkeiten gelten nur für wasm32. `trunk build` ist damit erstmals grün und gehört ab jetzt zum Verifikations-Loop. Das Setup-Skript deckt die Lücken ab, die die Ersteinrichtung auf einem frischen Rechner offenlegte: beschädigte gepinnte Toolchain wird erkannt und neu installiert (der bloße „cargo vorhanden"-Check übersah sie), WSL wird vor dem Docker-Daemon geprüft und installiert (ohne WSL startet der Daemon nie, die Wartezeit lief ins Leere), verwaiste Docker-Socket-Dateien werden weggeräumt (unlöschbare Reparse-Points nach hartem Stopp blockierten jeden Neustart), MSVC Build Tools, wasm32-Target und trunk werden installiert; `SM_SETUP_NONINTERACTIVE=1` für Läufe ohne Enter-Abfrage. **[ANNAHME: Die Arbeitskopie war ein ZIP ohne Git-Historie; das Repository wurde lokal neu initialisiert (Basis-Commit auf Stand v0.16), damit der Commit-je-Etappe-Workflow wieder gilt. Web-Client-Annahmen aus v0.16 unverändert: In-Memory-Ablage bis zur IndexedDB-Etappe, Abruf per Knopf bis zum WebSocket-Hinweiskanal.]** |
| 0.18 | 03.07.2026 | Kai Delor | KT-Selbstprüfung im Client (Meilenstein-1-Baustein, specs/key-transparency.md "Selbstprüfung durch den Client"). Neues Mini-Crate `crates/kt-format` bündelt die kanonischen KT-Byte-Formate an einer Stelle: das Konto-Commitment `smktc.v1` (bisher in common), die Wurzelnachricht `smkt.v1` (bisher im kt-Dienst) und hinter dem Feature `verify` die geteilte akd-Konfiguration samt Domain-Label. Grund für den Schnitt: Clients müssen exakt dieselben Bytes rechnen wie der Server, dürfen aber nicht von common abhängen (zieht axum und tracing-subscriber, im Browser fehl am Platz); common und kt re-exportieren, identity bleibt unberührt. `client-app` neu: kt-Modul mit `KtClient` (`/kt/info`, `/kt/proof/{handle}`, `/kt/epoch/{n}`) und `verify_self` in vier Schritten (Ed25519-Wurzelsignatur, Wurzelbindung des Beweises, akd-Inklusionsbeweis mit VRF, Byte-Vergleich gegen das lokal nachgerechnete Commitment aus eigenem Identitätsschlüssel plus `GET /devices`); Fehlschläge kommen als eigene Fehlervariante `KeyTransparency`, weil der Alarmfall der Spec anders anzuzeigen ist als ein Dienstausfall. Beweis `kt_e2e`: identity meldet an kt über die echte HTTP-Kette, Selbstprüfung besteht gegen Epoche 1 (auch mit gepinntem Wurzelschlüssel), ein falscher Pin fällt auf, und das Abnahmekriterium aus GOAL.md steht: ein untergeschobenes Commitment (stiller Schlüsseltausch durch den Betreiber) schlägt bei der Selbstprüfung Alarm. `client-app` baut mit akd weiterhin nach wasm32, die Browser-Tauglichkeit der Verifikation ist damit belegt. **[ANNAHME: Bootstrapping des Wurzel-Signaturschlüssels bleibt offen (Spec): ohne übergebenen Pin gilt Trust-on-first-use über `/kt/info`. Die Selbstprüfung ist noch nicht in CLI und Web-UI verdrahtet; das folgt mit deren nächster Etappe.]** |

---

**Pflegehinweis:** Dieses Dokument ist ein Living Document und bleibt als Markdown die Quelle. Es wird nicht als PDF eingefroren, weil ein eingefrorenes Live-Dokument sofort veraltet. Bei neuen Infos oder Änderungen werden die betroffenen Abschnitte aktualisiert und in Abschnitt 10 mit Datum, Autor und kurzer Beschreibung nachgezogen.
