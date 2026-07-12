# Offene Fragen

Was noch nicht entschieden ist. Manches hat schon eine Tendenz, manches ist offen, manches ist nur ein Stichwort, das nicht vergessen werden soll. Jeder Punkt sollte fallen, bevor das zugehörige Stück gebaut wird.

## Was inzwischen gebaut ist

Viele früher offene Punkte sind inzwischen umgesetzt (Contact Discovery, Message Franking und Blockieren, Sybil-Proof-of-Work, KT-Selbst- und Konsistenzprüfung, Schlüsselwechsel-Warnung samt Safety Number, MLS-Gruppen in CLI und Web, Multi-Device, verschlüsselte Geräte-Ablage, Kontoverwaltung samt Wurzelschlüssel-Rotation, server-seitige Disappearing Messages und mehr). Der aktuelle, verbindliche Funktionsstand steht ausschließlich im [Live-Dokument](live-dokument.md), Abschnitt 9a (Bilanz) und 10 (Verlauf); diese Datei hier führt bewusst keine eigene, driftende Fertig-Liste mehr. Was unten steht, ist entweder noch offen oder braucht ein externes Ereignis (Audit) beziehungsweise eine echte Organisation (unabhängige Auditoren, Push-Konten, Cluster) und bleibt deshalb bewusst offen.

## Das Dickste zuerst

**Backup-Enclave.** SGX ist auf Intel-Client-CPUs faktisch tot (EOL), bleibt also AWS Nitro oder Azure Confidential Computing. Tendenz Nitro. Dann hängt die Frage dran: Wo liegen die verschlüsselten Backups physisch, im eigenen Objektspeicher? Und wie wird der Counter-State für das PIN-Limit repliziert, ohne das Limit zu unterlaufen? Das ist ein halbes Subprojekt. Rahmen inzwischen gesetzt (NF120, Pflichtenheft 8.4): SVR ist optional, aufgeschoben und nur unter Threshold über mehrere unabhängige Anbieter sowie mit Genehmigung zulässig; bis dahin bleibt der nutzergehaltene Recovery-Key der Standard. Offen bleiben Enclave-Wahl, Threshold-Aufteilung und Counter-State-Replikation.

**Wer betreibt den KT-Auditor.** Wir selbst reicht nicht für echten Split-View-Schutz. Konsortium? Ein Transparenz-Verein? Mindestschutz inzwischen gesetzt: Client-Gossip (Clients und Auditoren vergleichen ihre signierten Wurzeln) ist ab Phase 3 verbindlich, weil er ohne externe Organisation auskommt. Ein unabhängiger externer Auditor bleibt das Ziel; solange er fehlt, ist im Bedrohungsmodell ehrlich ausgewiesen, dass der Split-View-Schutz reduziert ist. Offen bleibt, wer den externen Auditor betreibt.

**OIDC-Provider für SSO. Entschieden:** gehärteter Standard-Provider (Default Keycloak) statt Eigenbau, redundant betrieben, weil "kein Eigenbau bei Sicherheit" auch für den Anmeldedienst gilt. Finale Produktwahl vor M3.

**Compliance-Position.** CSAR und Online Safety Act. Muss vor Phase 3 stehen, weil es Datenmodell und Server-Fähigkeiten berührt. Aktuell bewusst offen, aber mit Deadline.

## Krypto-Kern

- Exakte Version-Pins für libsignal, OpenMLS, die ML-KEM- und ML-DSA-Implementierung. Beim Integrationsschritt setzen, mit signed commit.
- Skipped-Keys-Fenster: Zielwert bis ~2000 übersprungene Keys, Aging, Speicherlimit pro Sitzung. Genau festlegen.
- Wie SPQR-Versionen in die eigene Wire-Version eingehängt werden.
- Stichtags-Mechanik für erzwungene Re-Handshakes bei Suite-Wechsel.
- PQ-MLS-Zeitpunkt, hängt am Combiner-Draft.

## Geräte und Identität

- ~~Rotation des Konto-Identitätsschlüssels. Das ist die Wurzel, also dringlich, nicht "irgendwann".~~ GELÖST durch [ADR-0010](entscheidungen/0010-wurzelschluessel-rotation.md): kontinuitätssigniertes Ersetzen (der alte Wurzelschlüssel signiert den neuen), atomar unter Kontosperre, mit Ablauf-Erneuerung und absturzsicherem Client. Offen bleibt nur die rollierende Übergangsvariante (alt und neu eine Zeit lang gültig) als spätere Verfeinerung.
- Cross-Signing ja oder nein, und falls ja, wie man die Matrix-Fehler vermeidet (verlorene Cross-Signing-Schlüssel, Verifikations-Loops).
- Safety Number bei Multi-Device: pro Identität rechnen (Tendenz), aber dann muss die Geräte-Sichtbarkeit woanders hin.
- Geräte-Credential-Format im Detail.

## Sealed Sender, Abuse, Messaging

- Genaue zkgroup-Konstruktion und ihr Zusammenspiel mit Multi-Device unter einem Profil.
- PoW-Härte und woran die Privacy-Pass-Ausgabe selbst hängt (sonst verschiebt sich Sybil nur dorthin).
- Disappearing Messages: absenderseitige Schlüssel-Vernichtung gegen empfängerseitige Garbage Collection, beides nicht trivial mit dem Ratchet.
- Edits und Reactions gegen Franking: Was committet der Server, das Original oder die Edit-Kette? Diese Kollision früh klären.
- Default-Aufdringlichkeit von Lesebestätigungen unter Sealed Sender.

## Contact Discovery und MLS-DS

- OPRF-Konstruktion und Rate-Limiting gegen Enumeration über die Suche.
- MLS Delivery Service: Reorder-Garantien, Auflösung konkurrierender Commits, Umgang mit External Commits. Steht in der Spec, die Werte fehlen.

## Betrieb, Zahlen, Kleinkram

- Konkrete Rate-Limit-Schwellen fürs Verzeichnis.
- Epochenlänge KT: Zielbereich 1 bis 6 Stunden, genauer Wert offen (kürzer = schneller sichtbar, mehr Last).
- Sender-Credential-Lebensdauer (~24 Stunden als Startwert).
- Medien-Verschlüsselung im Detail: Chunking, Schlüssel pro Datei, resumable Uploads.
- UnifiedPush für Android wirklich tragfähig?
- Wie ein frischer Client dem KT-Signaturschlüssel überhaupt vertraut (Bootstrapping).

## Qualität

- Umfang der formalen Modelle (ProVerif, Tamarin), Skelett ab Phase 2.
- Fuzzing für Parser und Wire-Code.
- Property-Tests für die Krypto-Integration (Round-Trip, Tampering, Out-of-Order).
