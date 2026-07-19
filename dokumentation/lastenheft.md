# Lastenheft

**IT-Ausbildung Kladow**

| Feld | Inhalt |
|------|--------|
| Projektbezeichnung | SecureMessenger (Arbeitstitel, frei ersetzbar) |
| Dokumenttyp | Lastenheft |
| Auftraggeber | Ausbildungsleitung IT, RKI BBW Berlin-Kladow |
| Projektleitung | Hr. Schiller |
| Erstellt am | 30.06.2026 |
| Aktuelle Version | 1.3 |
| Status | Entwurf zur Abnahme |

### Änderungsverlauf

| Nr. | Datum | Version | Autor | Geändertes Kapitel | Art der Änderung | Status |
|-----|-------|---------|-------|--------------------|------------------|--------|
| 1 | 30.06.2026 | 1.0 | Kai Delor | Alle | Erstellung | Entwurf |
| 2 | 30.06.2026 | 1.1 | Kai Delor | 3.2, 4.5, 4.6, 4.7, 6, 10 | Kritische Punkte überarbeitet auf Industrie-Niveau: Verfügbarkeit differenziert (SSO als SPOF), SLOs, Incident-Response und Resilienz als NF ergänzt, On-Premise gegen SVR und Push präzisiert, offene Infrastrukturpunkte sauber gefasst, Anmerkungen entfernt | Entwurf |
| 3 | 02.07.2026 | 1.2 | Kai Delor | 6 | Betrieb auf 24/7 umgestellt (NF060, NF150), Fehlerbudgets neu berechnet (NF130), Knoten-Kapazität vereinheitlicht (NF080) | Entwurf |
| 4 | 02.07.2026 | 1.3 | Kai Delor | 7.1, 7.2 | Externer Spec-Review vom Code-Start auf den Produktivbetrieb verschoben, läuft spätestens mit dem ersten Audit (M4) zusammen; Begründung in ADR-0008 | Entwurf |

---

## 1 Einleitung

Dieses Lastenheft definiert die Anforderungen an die Plattform „SecureMessenger". Sie ist eine Ende-zu-Ende verschlüsselte Kommunikationsplattform, deren Server zu keinem Zeitpunkt Klartext sieht, und die zugleich als gemeinsame technische Basis für die übrigen Ausbildungsprojekte der IT-Abteilung dient. Das Dokument legt den Leistungsumfang und die technischen Rahmenbedingungen verbindlich fest und bildet die Grundlage für das vom Auftragnehmer zu erstellende Pflichtenheft.

Der Anspruch ist Industrie-Niveau, kein Übungsmaßstab. Das System wird an den gleichen Eigenschaften gemessen wie produktive E2EE-Messenger: nachprüfbare Schlüssel, nachprüfbarer Client-Code, messbare Service Level Objectives und ein externes Sicherheitsaudit vor dem Produktivbetrieb.

Der SecureMessenger unterscheidet sich bewusst von einem reinen Chat-Werkzeug. Er liefert vier Bausteine, die andere Projekte mitbenutzen sollen: gesicherte Nachrichten, eine zentrale Identität samt Anmeldung (Single Sign-on), Echtzeit-Benachrichtigungen und einen Container-Betriebsrahmen auf Kubernetes.

## 2 Allgemeines

### 2.1 Gegenstand des Dokuments

Das Dokument spezifiziert die Funktionen, Schnittstellen und Rahmenbedingungen, die für die Umsetzung nötig sind. Es ist die Vorgabe für das Projektteam und beschreibt die Erwartung der Ausbildungsleitung. Wie diese Vorgaben technisch umgesetzt werden, beantwortet das zugehörige Pflichtenheft.

### 2.2 Projektkontext

Der SecureMessenger entsteht im Rahmen der IT-Ausbildung, wird aber auf produktivem Niveau gebaut und betrieben. Dafür gibt es zwei Gründe:

- **Ein Produkt mit konkretem Nutzen.** Es entstehen eine vertrauliche Kommunikation und ein gemeinsamer Identitäts- und Benachrichtigungsdienst für die Abteilung.
- **Der volle Lebenszyklus an einem sicherheitskritischen System.** Die Beteiligten durchlaufen Anforderungsanalyse, Kryptografie aus geprüften Bibliotheken, containerisierte Entwicklung, Deployment auf Kubernetes und ein begleitendes Bedrohungsmodell.

An einem verschlüsselten Messaging-System wird zugleich sichtbar, warum drei Regeln dieses Projekts gelten:

- Eigenbau-Kryptografie ist ausgeschlossen.
- Nachprüfbare Schlüssel und nachprüfbare Programmdateien gehören zusammen.
- Ein externes Sicherheitsaudit vor dem Produktivbetrieb ist zwingend.

### 2.3 Abgrenzung des Projekts

Das System ist für den internen Gebrauch der IT-Abteilung am RKI BBW vorgesehen. Folgende Grenzen gelten für die erste Ausbaustufe:

- **Föderation ist vorbereitet, aber abgeschaltet.** Es gibt zunächst einen Betreiber. Bei einem einzelnen Betreiber fallen weniger Metadaten an als in einem Verbund, und die Komplexität bleibt klein. Föderation ist später kein bloßer Schalter, sondern eine eigene Vertrauenstopologie (siehe ADR-0001).
- **Gruppen sind noch nicht post-quantum.** Die 1:1-Kommunikation ist über PQXDH gegen künftige Quantencomputer abgesichert, MLS-Gruppen folgen erst, wenn der Post-Quantum-Standard reif ist.
- **Komfort-Backup über eine Enclave (Secure Value Recovery) kommt nach dem Fundament und nur unter den Bedingungen aus NF120.** Bis dahin sichern Nutzer ihren Recovery-Key selbst.
- **Die übrigen Ausbildungsprojekte sind unantastbar.** Der SecureMessenger passt sich an deren bestehende Schnittstellen an. Er verlangt von ihnen keine Änderung an Code, Datenmodell oder Betriebsumgebung.

### 2.4 Akteure (Rollenbeschreibung)

Für ein Berechtigungskonzept nach Role-Based Access Control (RBAC) gelten folgende Rollen:

| Rolle | Beschreibung | Berechtigungen |
|-------|--------------|----------------|
| Nutzer (Azubi) | Hauptnutzergruppe | Eigene Chats und Gruppen führen, eigene Geräte verwalten, Kontakte über Handle finden, Schlüssel verifizieren |
| Ausbilder | Fachliche Steuerung und Moderation | Konten freischalten und sperren, Abuse-Meldungen sichten, gruppenbezogene Moderation; kein Zugriff auf Inhalte (technisch ausgeschlossen) |
| Administrator (IT-Netz) | Technischer Betrieb | Zugriff auf Cluster, Logs, Backups, Konfiguration; kein Zugriff auf Klartext oder private Schlüssel |
| Integrations-Dienst (Drittprojekt) | Maschinen-Akteur, z. B. AzubiOS | Authentifizierung von Endnutzern über SSO, Versand von System-Benachrichtigungen, Abruf von Präsenz, alles über dedizierte Schnittstellen mit eigenem Mandanten-Token |

Eine Eigenschaft zieht sich durch alle Rollen: Keine davon kann Nachrichteninhalte lesen. Das ist keine Berechtigungsfrage, sondern eine Eigenschaft des Verfahrens. Der Server hält nur Chiffretext.

### 2.5 Ablage und Gültigkeit

Die Projektergebnisse liegen versioniert im Git-Repository, die Dokumentation als Markdown direkt neben dem Code (Docs-as-Code). Dieses Lastenheft gilt ab der Unterzeichnung durch die Ausbildungsleitung. Änderungen während der Laufzeit bedürfen der Schriftform und werden im Änderungsverlauf nachgezogen.

## 3 Ausgangssituation

### 3.1 Aktuelle Situation

Die Kommunikation in der IT-Ausbildung läuft heute über Standard-Werkzeuge wie Teams und E-Mail. Diese Werkzeuge sind nicht Ende-zu-Ende verschlüsselt, der Betreiber kann mitlesen, und sie sind nicht mit den Ausbildungsprojekten verzahnt. Jedes neue Projekt löst Anmeldung, Benutzerkonten und Benachrichtigungen erneut und auf eigene Faust, was zu uneinheitlichen, oft schwachen Eigenlösungen führt.

### 3.2 Vorhandene Infrastruktur

- **Serverlandschaft:** Bereitstellung On-Premise auf dem vorhandenen Proxmox-Cluster des RKI BBW. Eine oder mehrere virtuelle Maschinen tragen den Kubernetes-Verbund. **[OFFENE FRAGE: Verbindliche Cluster-Ressourcen (Node-Anzahl, CPU, RAM, Storage) und ihre Abgrenzung gegenüber den Ressourcen der Fremdprojekte sind mit der IT-Infrastruktur festzulegen. Ohne diese Zusage ist die Kapazitätsplanung nach NF140 nicht belastbar.]**
- **Bestehende Projekte:** Das Projekt „Azubi-OS" nennt einen Messenger ausdrücklich als austauschbares Modul. Hier setzt der SecureMessenger an: Er liefert dieses Modul und zugleich Identität und Benachrichtigung als geteilte Dienste.
- **Datenbank:** Ein zentraler Datenbank-Server steht bereit. Der SecureMessenger bringt seine eigene Datenhaltung mit, um die Projekte nicht zu koppeln.

### 3.3 Schwachstellenanalyse

- **Vertraulichkeitslücke:** Kein vorhandenes Werkzeug schützt Inhalte gegen den Betreiber oder gegen einen künftigen Quantencomputer, der heutige Mitschnitte später entschlüsselt.
- **Doppelarbeit bei Querschnittsdiensten:** Anmeldung, Kontenverwaltung und Benachrichtigung werden in jedem Projekt neu gebaut.
- **Uneinheitlicher Betrieb:** Es fehlt ein gemeinsames, reproduzierbares Container- und Deployment-Muster, an dem sich neue Projekte ausrichten können.

## 4 Konzept und Rahmenbedingungen

### 4.1 Zielgruppen

- **Auszubildende der IT-Abteilung.** Bedürfnis: vertrauliche, schnelle Kommunikation auf allen Geräten, eine einzige Anmeldung für die Abteilungs-Werkzeuge. Fokus: Bedienbarkeit und nachvollziehbare Sicherheit.
- **Ausbilder.** Bedürfnis: ein moderierbares, datensparsames System ohne eigene Lese-Möglichkeit, klare Abuse-Abwehr. Fokus: Datenschutzkonformität und Übersicht.
- **Administratoren (IT-Netz).** Bedürfnis: stabiler, beobachtbarer Betrieb auf vorhandener Infrastruktur, einfache Backups. Fokus: Betriebssicherheit ohne Zugriff auf Geheimnisse.
- **Andere Ausbildungsprojekte (als Maschinen-Nutzer).** Bedürfnis: Identität, Benachrichtigung und Chat als fertige Dienste über stabile Schnittstellen einbinden, ohne den eigenen Technologie-Stack zu ändern.

### 4.2 Technische Rahmenbedingungen

Die folgenden Rahmenbedingungen sind verbindlich.

- **On-Premise-Betrieb.** Das gesamte System läuft auf der Infrastruktur des RKI BBW. Eine Cloud-Abhängigkeit ist zu vermeiden, weil sie dem Metadatenschutz und der Datenhoheit widerspricht. Die wenigen, technisch unvermeidbaren Ausnahmen sind in NF120 benannt und begründet.
- **Plattformunabhängigkeit der Clients.** Der Web-Client läuft fehlerfrei in den aktuellen Versionen von Microsoft Edge, Google Chrome und Mozilla Firefox. Daneben gibt es native Clients.
- **Modularität.** Jeder Dienst ist einzeln deploy- und austauschbar, ein Ausfall reißt nicht das Gesamtsystem mit.
- **Integration ohne Eingriff.** Andere Projekte binden den SecureMessenger über offene, technologie-neutrale Schnittstellen ein (REST/OpenAPI, OpenID Connect, Webhooks, WebSocket). Sie müssen dafür ihren eigenen Stack nicht anpassen.
- **Keine Eigenbau-Kryptografie.** Sämtliche kryptografischen Primitive stammen aus geprüften Bibliotheken über einen gemeinsamen Rust-Core.

### 4.3 Ziele des Betreibers

- **Vertraulichkeit gegenüber Betreiber und Netzwerk.** Inhalte bleiben dem Betreiber, dem Netzwerk und so weit wie möglich einem künftigen Quantenangreifer verborgen.
- **Querschnittsdienste einmal bauen.** Identität, Benachrichtigung und Chat entstehen einmal sauber und werden von allen Projekten genutzt, statt überall neu und schwächer.
- **Ein gemeinsamer Betriebsstandard.** Der SecureMessenger setzt das Muster für containerisierten, reproduzierbaren Betrieb auf Kubernetes, an dem sich Folgeprojekte ausrichten können.
- **Belegbare Betriebsgüte.** Verfügbarkeit, Latenz und Zustellzuverlässigkeit sind als Service Level Objectives definiert und werden gemessen, nicht behauptet.

### 4.4 Nutzen

**Für die Auszubildenden:** vertrauliche Kommunikation über Web, Mobile und Desktop mit einem Konto; eine einzige Anmeldung für die Abteilungs-Werkzeuge; Schlüssel, deren Echtheit man prüfen kann.

**Für die Ausbilder:** ein datensparsames System, das technisch keine Inhalte herausgeben kann, mit klarer Abuse-Abwehr und Moderation, ohne selbst zum Mitleser zu werden.

**Für die Administration:** ein einheitlicher, beobachtbarer Betrieb auf vorhandener Hardware, mit Backups, die ohne Klartext-Risiko auskommen, weil gelöscht wird, indem Schlüssel vernichtet werden.

**Für andere Projekte:** drei fertige Dienste (Identität, Benachrichtigung, Chat) und ein erprobtes Deployment-Muster.

### 4.5 Exemplarische Anwendungsszenarien (Vorher / Nachher)

- **Szenario A: Vertrauliche Nachricht.** Vorher: Eine sensible Absprache läuft über Teams, der Betreiber kann sie lesen. Nachher: Die Nachricht ist Ende-zu-Ende verschlüsselt, der Server sieht nur Chiffretext und meist nicht einmal den Absender.
- **Szenario B: Anmeldung in einem Projekt.** Vorher: AzubiOS pflegt eigene Konten und Passwörter. Nachher: AzubiOS leitet die Anmeldung per Single Sign-on an den SecureMessenger weiter, ein Konto für alle Werkzeuge.
- **Szenario C: System-Benachrichtigung.** Vorher: AzubiOS müsste eigene Push-Infrastruktur bauen, um über einen freigegebenen Bericht zu informieren. Nachher: AzubiOS ruft eine Schnittstelle des SecureMessengers auf, der Nutzer bekommt die Benachrichtigung in Echtzeit auf seinem Gerät.
- **Szenario D: Mitschnitt heute, Quantencomputer später.** Vorher: Heute mitgeschnittene Inhalte sind später durch einen Quantenrechner lesbar. Nachher: Der hybride PQXDH-Schlüsselaustausch schützt die Vertraulichkeit der 1:1-Inhalte auch gegen diesen Angreifer. Die Stärke dieses Schutzes hängt an der korrekten hybriden Bindung beider Anteile und wird durch das externe Krypto-Audit (NF050) bestätigt.

### 4.6 Systemvoraussetzungen

- **Infrastruktur:** Bereitstellung auf dem Proxmox-Cluster. Eine oder mehrere VMs (Debian 12 oder Ubuntu 24.04) tragen einen Kubernetes-Verbund. Statische IP im internen VLAN, Ports 80 und 443 nach außen, interne Dienst-Ports für die Integration. **[OFFENE FRAGE: Welche eingehenden und ausgehenden Ports die IT-Infrastruktur freigibt, insbesondere der ausgehende Verkehr zu den Push-Diensten APNs und FCM (siehe NF120).]**
- **Clients:** Aktuelle Browser für den Web-Client, native Clients für iOS, Android und Desktop. Kein Support für veraltete Browser.
- **Hardware-Keystore auf Geräten:** Wo vorhanden, werden Secure Enclave, Android Keystore oder TPM für lokale Schlüssel genutzt.

### 4.7 Ressourcen

- **Personell:** Projektleitung und fachliche Abnahme durch die Ausbilder, Umsetzung durch das Projektteam in den Rollen Backend, Client, Kryptografie-Integration und Betrieb.
- **Externe Unterstützung:** Ein erfahrener Kryptografie-Fachkundiger prüft die Specs vor Phase 1 und auditiert später den Kern. Dieser externe Review ist nicht optional, er ist Teil des Plans. **[OFFENE FRAGE: Budget und Beauftragung der externen Audits nach NF050 sind frühzeitig zu klären, weil ohne bestandenes Audit kein Produktivbetrieb mit echtem Schutzbedarf erfolgt.]**
- **Infrastruktur:** Proxmox-Cluster, interner Container-Registry-Zugang, Objektspeicher für Medien und Backups.
- **Lizenzen:** Open-Source-Werkzeuge (Rust-Toolchain, Kubernetes, Docker, PostgreSQL) oder vorhandene Haus-Lizenzen.
- **Zeit:** Entwicklung in mehreren Phasen, abgestimmt auf die Meilensteine in Kapitel 7.

## 5 Funktionale Anforderungen

Die Anforderungen sind nach Modul gruppiert und durchnummeriert. Sie beschreiben das Was. Das Wie steht im Pflichtenheft.

### 5.1 Modul: Identität, Konten und Geräte

- **F010 Konto über Handle:** Ein Konto hängt an einem eindeutigen Username (Handle), nicht an einer Telefonnummer. Der Anzeigename ist davon getrennt und änderbar.
- **F020 Registrierung und Login:** Sicherer Zugang mit rotierenden Sessions (kurzlebiges Access-Token, rotierendes Refresh-Token). Eine optionale E-Mail dient nur der Login-Wiederherstellung.
- **F030 Multi-Device:** Ein Konto trägt mehrere Geräte, jedes mit eigenen Schlüsseln. Ein neues Gerät wird von einem bestehenden freigeschaltet (QR-Code oder Bestätigung).
- **F040 Geräte-Identitätsbindung:** Jeder Geräteschlüssel ist über ein vom Konto-Identitätsschlüssel signiertes Credential ans Konto gebunden und in der Key Transparency sichtbar.
- **F050 RBAC:** Umsetzung der Rollen aus Punkt 2.4.

### 5.2 Modul: Basis-Dienste für andere Projekte

Über dieses Modul binden die übrigen Projekte den SecureMessenger ein, ohne sich selbst zu ändern.

- **F060 Single Sign-on (SSO):** Bereitstellung eines OpenID-Connect-konformen Anmeldedienstes, an den andere Projekte ihre Anmeldung delegieren. Ein Konto für alle Abteilungs-Werkzeuge.
- **F070 Benachrichtigungs-Schnittstelle:** Eine authentifizierte Schnittstelle, über die ein Drittprojekt eine Benachrichtigung an einen Nutzer auslöst, die dieser in Echtzeit auf seinem Gerät erhält.
- **F080 Präsenz- und Status-Abruf:** Andere Projekte können den Online-Status eines Nutzers abfragen, soweit dieser das erlaubt.
- **F090 Chat als einbindbares Modul:** Bereitstellung der Chat-Funktion über eine dokumentierte API und ein einbettbares Client-Modul, das ein Projekt wie AzubiOS aktivieren oder deaktivieren kann.
- **F100 Mandantenfähigkeit:** Jedes Drittprojekt erhält einen eigenen Zugang mit eigenem Token und abgegrenzten Rechten, sodass Projekte sich nicht gegenseitig stören.

### 5.3 Modul: Schlüssel-Verzeichnis und Key Transparency

- **F110 Prekey-Verzeichnis:** Jedes Gerät hinterlegt Prekey-Bündel, klassisch und post-quantum. Abruf rate-limitiert pro Abrufer, atomare Konsumierung der Einmal-Prekeys.
- **F120 Key Transparency:** Ein öffentlich prüfbares Log aller Schlüssel. Der Client gleicht jeden ausgelieferten Schlüssel automatisch dagegen ab, sodass ein untergeschobener Schlüssel auffällt.
- **F130 Verifikation:** Safety Numbers zum manuellen Abgleich zwischen zwei Nutzern, sichtbare Warnung bei einem Schlüsselwechsel.

### 5.4 Modul: Nachrichten (1:1 und Gruppen)

- **F140 1:1-Chat:** Ende-zu-Ende verschlüsselt über PQXDH zum Sitzungsaufbau und Double Ratchet plus SPQR für die laufende Sitzung.
- **F150 Gruppen:** Ende-zu-Ende verschlüsselte Gruppen über MLS (RFC 9420), mit Beitritt, Austritt und Neuschlüsseln.
- **F160 Zustellung:** Store-and-forward bis zur Abholung, idempotent über eine client-erzeugte ID, mit Zustell- und Lesestatus.
- **F170 Sealed Sender:** Der Server erfährt bei den meisten Nachrichten nicht, von wem sie kommen. Die Berechtigung wird über ein anonymes Credential geprüft.

### 5.5 Modul: Medien, Kontaktsuche, Echtzeit

- **F180 Medienversand:** Verschlüsselter Datei-Upload in den Objektspeicher, der Schlüssel reist in der Nachricht, nicht auf dem Server.
- **F190 Kontaktsuche:** Auflösung eines Handles zu einem Konto per OPRF, ohne dass der Server den Suchverlauf lernt.
- **F200 Echtzeit und Presence:** WebSocket-Verbindung für Hinweise auf wartende Nachrichten, Online-Status und Tippanzeigen. Push weckt mobile Geräte, der Inhalt kommt per Pull.

### 5.6 Modul: Clients und Lieferkette

- **F210 Mehrere Clients:** Web-Client (Rust-Core als WebAssembly) sowie native Clients (Rust-Core über FFI), von Beginn an parallel.
- **F220 Binary Transparency:** Reproduzierbare, signierte Builds, deren Prüfsummen in einem Transparenz-Log liegen, damit der Server keinem Zielkonto eine abweichende App unterschieben kann.

## 6 Nicht-funktionale Anforderungen

### 6.1 Sicherheit und Datenschutz

- **NF010 Zero Knowledge für Inhalte:** Der Server speichert und verarbeitet ausschließlich Chiffretext und öffentliche Schlüssel. Klartext und private Schlüssel erreichen den Server nie.
- **NF020 Post-Quantum-Vertraulichkeit (1:1):** Der Sitzungsaufbau ist hybrid (X25519 und ML-KEM-768), sodass ein heute mitgeschnittener 1:1-Verkehr auch gegen einen späteren Quantencomputer geschützt ist. Das betrifft die Vertraulichkeit. Die Authentizität (Signaturen) bleibt klassisch, bis Post-Quantum-Signaturen in die Suiten kommen, was erst mit realen Quantencomputern scharf wird.
- **NF030 DSGVO-Konformität und Datensparsamkeit:** Es werden nur betrieblich nötige Daten erhoben, keine Telefonnummern. Löschen erfolgt über Crypto-Shredding, eine Kontolöschung läuft mit Widerrufsfrist.
- **NF040 Passwort- und Schlüsselableitung:** Argon2id nach aktuellem Stand der Technik.
- **NF050 Externes Audit:** Vor jedem Produktiveinsatz mindestens zwei externe Audits, eines nach Fertigstellung des Krypto-Kerns, eines vor dem Launch. Schwerpunkt des ersten Audits ist die hybride PQXDH- und SPQR-Bindung, weil dort der Post-Quantum-Schutz steht oder fällt. Ohne bestandenes Audit erfolgt kein Produktivbetrieb mit echtem Schutzbedarf.

### 6.2 Betrieb und Qualität

- **NF060 Verfügbarkeit (differenziert, 24/7):** Das System läuft rund um die Uhr, weil ein Messenger auch abends und am Wochenende genutzt wird. Der Identitäts- und SSO-Dienst ist ein Single Point of Failure für alle abhängigen Projekte und erreicht deshalb 99,9 Prozent im Monat. Die übrigen Kern-Dienste erreichen 99,5 Prozent im Monat. Die konkreten Messgrößen und Fehlerbudgets stehen in NF130. Ein 24/7-Ziel verlangt eine Reaktionsfähigkeit auch außerhalb der Bürozeiten (NF150).
- **NF070 Performance:** Ein Echtzeit-Hinweis erreicht ein online verbundenes Gerät im 95. Perzentil in unter 500 ms, im 99. Perzentil in unter 1000 ms. Reguläre API-Antworten im 95. Perzentil unter 2 Sekunden bei normaler Last.
- **NF080 Skalierbarkeit:** Zustandslose Dienste skalieren waagerecht über Kubernetes. Ein WebSocket-Knoten trägt je nach Ausstattung mehrere zehntausend bis hunderttausend Verbindungen. Das ist die technische Kapazität je Knoten, nicht der Startbedarf; die Dimensionierung folgt NF140.
- **NF090 Modularität und Wartbarkeit:** Jeder Dienst ist einzeln deploy- und austauschbar. Ein Dienst-Ausfall degradiert das System, statt es zu stoppen.
- **NF100 Beobachtbarkeit:** Strukturierte Logs nach stdout, niemals mit Nachrichteninhalt. Metriken im Prometheus-Format, Health-Probes je Dienst, verteiltes Tracing über die Dienstgrenzen.
- **NF110 Datensicherung:** Tägliche automatisierte Backups. Backups sind verschlüsselt, das Entschlüsselungs-Geheimnis liegt nicht beim Betreiber. Wiederherstellung wird regelmäßig getestet (Restore-Test), ein ungetestetes Backup gilt nicht als Backup.
- **NF120 On-Premise mit benannten Ausnahmen:** Alle Kern-Dienste und die gesamte Datenhaltung laufen On-Premise auf der RKI-BBW-Infrastruktur, ohne Cloud-Abhängigkeit. Zwei Ausnahmen sind technisch unvermeidbar und werden bewusst zugelassen und dokumentiert:
  1. Mobiler Push über APNs und FCM, der nur das Gerät weckt und keinen Inhalt trägt; für Android wird UnifiedPush als Alternative geprüft.
  2. Eine spätere Secure-Value-Recovery-Funktion, die eine vertrauenswürdige Enclave braucht; sie ist optional, aufgeschoben und nur unter Threshold-Vertrauen über mehrere unabhängige Anbieter sowie mit ausdrücklicher Genehmigung der Ausbildungsleitung zulässig. Bis dahin bleibt der nutzergehaltene Recovery-Key der Standard.

### 6.3 Betriebsgüte, Resilienz und Reaktion

- **NF130 Service Level Objectives und Fehlerbudget:** Die Betriebsgüte ist messbar definiert, je SLO ein Service Level Indicator aus den Metriken (NF100): Verfügbarkeit (NF060), Zustell-Latenz und API-Latenz (NF070), sowie Zustell-Durability von 99,99 Prozent (eine angenommene Nachricht ist bis zur Bestätigung abrufbar, kein stiller Verlust). Wird ein Fehlerbudget aufgebraucht, hat Stabilisierung Vorrang vor neuen Funktionen.
- **NF140 Kapazität und Lastannahmen:** Die Dimensionierung folgt belastbaren Zahlen. **[OFFENE FRAGE: erwartete Nutzer- und Gerätezahl, gleichzeitige Verbindungen und Nachrichten pro Tag.]** **[ANNAHME: Startdimensionierung für die IT-Abteilung im Bereich einiger Dutzend bis weniger Hundert aktiver Konten; die Architektur trägt mehr, der Start wird nicht überdimensioniert.]**
- **NF150 Incident-Response und Postmortems:** Es gibt einen definierten Eskalationspfad mit Schweregrad-Klassen. Nach jedem SLO-Bruch und jedem Sicherheitsvorfall wird ein blameless Postmortem nach dem Muster aus der begleitenden Dokumentation erstellt. Sicherheitsvorfälle (etwa eine Key-Transparency-Inkonsistenz oder ein Verdacht auf Schlüssel-Leak) folgen einem strengeren Security-Incident-Prozess.
- **NF160 Resilienz gegenüber Fremdprojekten:** Ein Ausfall des SecureMessengers degradiert abhängige Fremdprojekte kontrolliert, statt sie hart zu blockieren. Da die Fremdprojekte unantastbar sind, liegt die Verantwortung auf der Messenger-Seite: ausreichend lange Token-Gültigkeit, klar dokumentiertes Verhalten bei Nichterreichbarkeit und Redundanz des SSO-Dienstes.

## 7 Projektsteuerung und Meilensteinplanung

### 7.1 Strategie zur Umsetzung

Vor dem offiziellen Kick-off präsentiert das Team:

- die Rollenverteilung,
- die Methodenwahl mit Begründung,
- ein Grobkonzept mit Mockups für die Clients,
- einen eigenen Projektplan.

Dem Bau ist eine Spec-Phase vorgeschaltet: Die kryptografisch heiklen Teile werden spezifiziert, bevor der erste Produktivcode entsteht. Der externe Review dieser Specs blockiert nicht den Code-Start, sondern den Produktivbetrieb; er läuft spätestens mit dem ersten externen Audit zusammen (Entscheidung vom 02.07.2026, ADR-0008 der Umsetzungsdoku).

### 7.2 Strategische Meilensteine

| ID | Meilenstein | Erwartung | Nachfolger |
|----|-------------|-----------|------------|
| M1 | Specs | Specs der heiklen Teile stehen; der externe Review folgt spätestens mit dem Audit in M4 | M2 |
| M2 | Fundament | Identität, Auth, Geräteverwaltung, Schlüssel-Verzeichnis, KT-Grundgerüst, Web- und ein nativer Client | M3 |
| M3 | Basis-Dienste | SSO, Benachrichtigung und Präsenz-Abruf stehen, ein Drittprojekt bindet sie testweise ein | M4 |
| M4 | 1:1-Nachrichten | PQXDH, Double Ratchet plus SPQR, Multi-Device-Fanout; erstes externes Audit des Kerns | M5 |
| M5 | Metadaten und Verifikation | Sealed Sender, KT vollständig, Safety Numbers, Contact Discovery | M6 |
| M6 | Gruppen | MLS-Gruppen, Delivery Service gehärtet | M7 |
| M7 | Medien und Härtung | Medienversand, Fuzzing, Property-Tests, zweites externes Audit | M8 |
| M8 | Abnahme | Übergabe der Dokumentation und Endabnahme | - |

### 7.3 Qualitätsvorgaben

- **Dokumentationspflicht:** Code ohne aussagekräftige Kommentare oder fehlende API-Beschreibung (OpenAPI) führt zur Ablehnung des Meilensteins.
- **Code-Review-Pflicht:** Vor jedem Merge größerer Funktionen ein Review durch einen Ausbilder oder erfahrenen Mitauszubildenden.
- **Keine Eigenbau-Krypto:** Kryptografische Bausteine kommen ausschließlich aus den gepinnten Bibliotheken.
- **Sicherheit vor Funktion:** Ein Meilenstein gilt erst als erreicht, wenn die zugehörigen Sicherheitseigenschaften nachweisbar sind.

## 8 Lieferumfang und Abnahmekriterien

### 8.1 Lieferumfang

- **Software:** Vollständiger, dokumentierter Quellcode im Git-Repository.
- **Deployment:** Lauffähige Kubernetes-Umgebung mit Container-Images und Manifesten.
- **Schnittstellen:** OpenAPI-Spezifikation der REST-API, OIDC-Konfiguration für SSO, Dokumentation der Webhook- und WebSocket-Events.
- **Dokumentation:** Systemhandbuch (Installation, Betrieb, Backup), Benutzerhandbuch, Architektur- und Sicherheitsdokumentation, Bedrohungsmodell, SLO- und Postmortem-Vorgaben.
- **Nachweise:** Reproducible-Build-Pipeline mit Binary-Transparency-Log, Audit-Berichte, Restore-Test-Protokoll.

### 8.2 Abnahmekriterien

1. **Verschlüsselung nachgewiesen:** Eine in der Datenbank liegende Nachricht ist ohne Client-Schlüssel nicht lesbar, der Nachweis wird vorgeführt.
2. **SSO funktioniert:** Ein Drittprojekt (Testaufbau) meldet einen Nutzer erfolgreich über den SecureMessenger an, ohne eigene Kontenpflege.
3. **Benachrichtigung in Echtzeit:** Ein über die Schnittstelle ausgelöster Hinweis erreicht ein online verbundenes Gerät im 95. Perzentil in unter 500 ms.
4. **Schlüssel-Manipulation fällt auf:** Ein im Test untergeschobener Schlüssel wird von der Client-Selbstprüfung gegen die Key Transparency erkannt.
5. **Multi-Device:** Eine Nachricht erscheint konsistent auf allen Geräten des Empfängers und des Absenders.
6. **Betrieb und Resilienz:** Ein Dienst lässt sich einzeln neu starten, ohne das Gesamtsystem zu stoppen. Ein simulierter SSO-Ausfall blockiert ein abhängiges Fremdprojekt nicht hart (NF160). Metriken, Health-Probes und SLO-Auswertung sind sichtbar.

## 9 Genehmigung und Unterschriften

Mit der Unterzeichnung wird dieses Lastenheft als verbindliche Grundlage für das Pflichtenheft und die Umsetzung anerkannt.

| Ort, Datum | Rolle | Name | Unterschrift |
|------------|-------|------|--------------|
| Berlin, den | Auftraggeber / Ausbilder | | |
| Berlin, den | Projektleitung | | |
| Berlin, den | IT-Infrastruktur (Admin) | | |

## 10 Glossar

- **Ende-zu-Ende-Verschlüsselung (E2EE):** Nur Sender und Empfänger können den Inhalt lesen, der Server nicht.
- **PQXDH:** Hybrider Schlüsselaustausch aus klassischem X25519 und post-quantum ML-KEM-768, schützt die Vertraulichkeit des Sitzungsaufbaus gegen künftige Quantencomputer. Die Authentizität bleibt klassisch, bis Post-Quantum-Signaturen verfügbar sind.
- **Double Ratchet / SPQR:** Verfahren für die laufende Sitzung, das jeder Nachricht einen frischen Schlüssel gibt (Forward Secrecy). SPQR ist der parallele post-quantum Anteil.
- **MLS (RFC 9420):** Standard für Ende-zu-Ende verschlüsselte Gruppen, effizient durch einen Schlüsselbaum (TreeKEM).
- **Key Transparency (KT):** Öffentlich prüfbares Log aller Schlüssel, gegen das Clients automatisch abgleichen, damit der Server keine falschen Schlüssel ausliefert.
- **Binary Transparency:** Prüfbares Log der ausgelieferten Programmdateien, ergänzt durch reproduzierbare Builds, damit der Server keine manipulierte App unterschiebt.
- **Sealed Sender:** Verfahren, das die Absenderkennung vor dem Server verbirgt.
- **Single Sign-on (SSO) / OpenID Connect:** Ein Anmeldedienst, an den andere Projekte ihre Anmeldung delegieren, ein Konto für mehrere Werkzeuge.
- **Single Point of Failure (SPOF):** Ein Bauteil, dessen Ausfall mehrere abhängige Systeme lahmlegt. Hier der Identitäts- und SSO-Dienst, deshalb mit erhöhtem Verfügbarkeitsziel (NF060).
- **SLO / SLI / Fehlerbudget:** Service Level Objective ist das Güte-Ziel, der Service Level Indicator die gemessene Größe dazu, das Fehlerbudget der erlaubte Rest bis zum Ziel.
- **Secure Value Recovery (SVR):** Verfahren, das ein Backup-Geheimnis in einer abgesicherten Enclave hält und über eine PIN entsperrbar macht, ohne dem Betreiber das Geheimnis zu zeigen.
- **Crypto-Shredding:** Löschen durch Vernichten der Schlüssel, sodass zurückbleibender Chiffretext wertlos wird.
- **Rust:** Programmiersprache mit Speichersicherheit ohne Garbage Collector, gewählt für Krypto-Core und Backend-Dienste.
- **Kubernetes / Docker:** Container-Technologie (Docker) und deren Orchestrierung (Kubernetes) für reproduzierbaren, skalierbaren Betrieb.
- **RBAC (Role-Based Access Control):** Zugriffe hängen an Rollen, nicht an einzelnen Personen.
- **Mandantenfähigkeit:** Mehrere Projekte nutzen denselben Dienst getrennt voneinander, jedes mit eigenem Zugang und eigenen Rechten.
- **OPRF:** Verfahren für die Kontaktsuche, das ein Handle auflöst, ohne dem Server den Suchverlauf zu verraten.
