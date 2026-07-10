# Sichere Messaging-Plattform

Verschlüsselte Kommunikation, gebaut gegen die Angreifer von heute und die von morgen. Ein Konto über Web, Mobile und Desktop, der Server bekommt nur Chiffretext zu sehen.

Die Plattform ist zugleich als Basis für die übrigen Ausbildungsprojekte gedacht: Sie liefert Anmeldung (SSO), Benachrichtigung und Chat als geteilte Dienste über Standard-Protokolle, damit ein Projekt wie AzubiOS sie einbindet, ohne seinen eigenen Stack zu ändern. Backend und Krypto-Core sind beide in Rust geschrieben, betrieben über Docker auf Kubernetes. Was das im Einzelnen heißt, steht im [Lastenheft](lastenheft.md) und im [Pflichtenheft](pflichtenheft.md).

Diese Doku ist eine Übersicht plus die Specs, an denen so ein System steht oder fällt. Sie ist ein Plan, mit dem ein Team loslegen kann, und keine fertige Bauanleitung. Was noch offen ist, steht in [offene-fragen.md](offene-fragen.md). Vor dem ersten Produktivcode gehört ein erfahrener Krypto-Mensch ein paar Wochen mit dem Rotstift drüber, das ist hier ausdrücklich eingeplant.

## Die Grundentscheidungen

1. Krypto aus geprüften Bibliotheken, über einen gemeinsamen Rust-Core. libsignal für PQXDH und den Double Ratchet, OpenMLS für Gruppen, beide auf konkrete Commits gepinnt. Kein Eigenbau. Siehe [ADR-0005](entscheidungen/0005-krypto-bibliotheken.md).
2. Nachprüfbar sind zwei Dinge, die Schlüssel und der Code. Key Transparency hält den Server davon ab, falsche Schlüssel auszuliefern. Binary Transparency mit reproducible builds hält ihn davon ab, einem Zielkonto heimlich eine verwanzte App zu schicken. Ohne den zweiten Teil wäre die Schlüssel-Prüfung wertlos, sobald der Server den Client selbst manipulieren kann. Siehe [ADR-0007](entscheidungen/0007-binary-transparency.md).
3. Zentraler Kern, der sich den Weg zu Föderation nicht verbaut. Erstmal ein Betreiber, das schützt Metadaten am besten. Föderation ist später möglich, aber kein Schalter. Siehe [ADR-0001](entscheidungen/0001-hybrid-kern.md).
4. Multi-Plattform, native Clients von Anfang an parallel. Der Web-Client bleibt dabei das kryptografisch schwächste Glied, das steht so in der [sicherheit.md](sicherheit.md).
5. Identität über Username, ohne Telefonnummer. Kontakte über Handles, die Echtheit der Schlüssel sichert Key Transparency.

## Was die Plattform kann

- 1:1-Chats und Gruppen, Ende-zu-Ende verschlüsselt (Double Ratchet beziehungsweise MLS).
- Schlüsselaustausch, der gegen künftige Quantencomputer hält (PQXDH, hybrid).
- Mehrere Geräte pro Konto, jedes mit eigenen, ans Konto gebundenen Schlüsseln.
- Metadaten so weit runtergedrückt, wie es geht (Sealed Sender, keine Telefonnummern).
- Dateiversand und verschlüsselte Anrufe sind geplant, beides ein eigenes Kapitel für sich.

## Wegweiser

| Datei | Inhalt |
|-------|--------|
| [lastenheft.md](lastenheft.md) | Anforderungen im Stil der Ausbildungsprojekte, das Was und Warum |
| [pflichtenheft.md](pflichtenheft.md) | Die technische Umsetzung mit Rust, Kubernetes, Docker, das Wie |
| [live-dokument.md](live-dokument.md) | Fortlaufendes Design Doc: Problem, Ziele, Architektur, SRE, Risiken, Postmortem-Vorlage |
| [architektur.md](architektur.md) | Dienste, der Krypto-Core, Echtzeit, Skalierung |
| [protokoll.md](protokoll.md) | Krypto im Überblick, mit Verweis auf die tiefen Specs |
| [sicherheit.md](sicherheit.md) | Threat Model mit Assets und Grenzen (Überblick) |
| [bedrohungsmodell.md](bedrohungsmodell.md) | Volles STRIDE je Dienst und LINDDUN je Datenfluss, mit Gegenmaßnahmen im Code und Restrisiko-Register |
| [design-system.md](design-system.md) | Design-Entscheidungen des Web-Clients: Token-Architektur, Modi, WCAG-2.2-AA-Kriterien, Security-UX |
| [identitaet-und-geraete.md](identitaet-und-geraete.md) | Konten, Handles, Multi-Device, Verifikation |
| [datenmodell.md](datenmodell.md) | Was der Server speichert, mit Indizes und Partitionierung |
| [schnittstellen.md](schnittstellen.md) | APIs und Echtzeit-Events |
| [betrieb.md](betrieb.md) | Deployment, Skalierung, die teuren Pfade |
| [roadmap.md](roadmap.md) | Reihenfolge, mit einer Spec-Phase vor dem Code |
| [offene-fragen.md](offene-fragen.md) | Was noch nicht entschieden ist |
| [specs/](specs/) | Die ausgearbeiteten Specs |
| [entscheidungen/](entscheidungen/) | Die ADRs |
| [referenz/](referenz/) | Stil-Vorlage der anderen Projekte (AzubiOS-Lastenheft als PDF) und die [übertragbare Projekt-Guideline](referenz/claude-projekt-guideline.md) für neue Projekte mit Claude |

## Stand

Der Kern funktioniert und ist vorgeführt (Meilenstein 1), und die Breite darüber ist weitgehend gebaut: sechs Backend-Dienste, 1:1-E2EE-Chat in Web- und CLI-Client mit Echtzeit-Empfang, Key Transparency mit Selbst- und Konsistenzprüfung, MLS-Gruppen, Contact Discovery über OPRF, Abuse-Abwehr (Message Franking, Blockieren, Proof-of-Work), Disappearing Messages und ein volles Bedrohungsmodell. Die Bilanz gegenüber der Roadmap steht im [Live-Dokument](live-dokument.md) Abschnitt 9a; der jeweils genaue Verlauf in Abschnitt 10. Drei Dinge gehören vorneweg gesagt:

- Gruppen sind aktuell nicht post-quantum. MLS nach RFC 9420 ist in den Standard-Suites klassisch, PQ-MLS läuft noch über einen IETF-Draft. 1:1 ist über PQXDH schon post-quantum.
- Backup über Secure Value Recovery ist eingeplant, kommt aber erst nach dem Fundament. Bis dahin gilt: Recovery-Key sichern.
- Ein externes Sicherheitsaudit hat nicht stattgefunden und muss vor jedem Produktiveinsatz her, mindestens zweimal (ADR-0008).
