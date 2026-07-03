# Sicherheit und Bedrohungsmodell

Dieses Dokument ist systematischer aufgezogen als eine reine Szenario-Liste: erst was wir schützen, dann die Vertrauensgrenzen, dann die Angreifer, und erst danach die Tabelle, wer gegen wen gewinnt. Ein vollständiges LINDDUN- und STRIDE-Modell kommt vor Phase 2, das hier ist sein Gerüst.

## Assets

Was überhaupt schützenswert ist:

- Nachrichteninhalte im Klartext.
- Private Schlüssel: Konto-Identität, Geräte, Ratchet- und MLS-Zustand.
- Der soziale Graph und die Metadaten, also wer mit wem und wann.
- Gruppenmitgliedschaften.
- Das Recovery-Secret und die Backups.
- Der Konto-Zugang selbst.

## Vertrauensgrenzen

- Das Endgerät gilt als vertrauenswürdig, solange es nicht kompromittiert ist. Fällt diese Annahme, fällt alles.
- Der Krypto-Core im Client wird vertraut, aber nur, wenn der ausgelieferte Code nachprüfbar ist. Genau dafür gibt es Binary Transparency (siehe [ADR-0007](entscheidungen/0007-binary-transparency.md)).
- Der Transport wird nicht vertraut, deshalb liegt E2E über dem TLS.
- Der Server wird für Inhalte nicht vertraut, für Routing und Verfügbarkeit notgedrungen schon.
- Die KT-Auditoren sind eine externe Instanz gegen den Split-View, sie betreten die Bühne ab Phase 3.
- Die Push-Provider (Apple, Google) werden nicht vertraut. Sie sehen Token und Timing.

## Angreifer

- Passiver Betreiber, der mitliest, was er kann.
- Aktiver bösartiger Server, der Schlüssel oder Client-Code austauscht.
- Netzwerk-Angreifer (MITM).
- Datenbank-Leak oder Insider mit Speicherzugriff.
- Schadsoftware auf dem Endgerät.
- Spam- und Sybil-Angreifer ohne die Bremse einer Telefonnummer.
- Ein künftiger Angreifer mit Quantencomputer, der heute schon mitschneidet.
- Die Plattform-Betreiber selbst, über Push und App-Store-Auslieferung.
- Behördlicher Zugriff, der sich rechtlich auf Herausgabe richtet.

## Szenarien

| Szenario | Geschützt? | Warum |
|----------|-----------|-------|
| Server-Datenbank wird geleakt | ja | Nur Chiffretext und öffentliche Schlüssel |
| Betreiber liest Inhalte mit | ja | Kein Klartext im Kern, Sealed Sender verbirgt den Absender |
| Server tauscht Schlüssel | gestaffelt | Selbstprüfung sofort, Split-View erst mit Auditoren (Phase 3) |
| Server liefert verwanzten Client | erkannt | Binary Transparency und reproducible builds |
| Netzwerk-Mitschnitt | ja | TLS plus E2E |
| Mitschnitt heute, Quantencomputer später | 1:1 ja, Gruppen noch nicht | PQXDH hybrid, MLS aktuell klassisch |
| Gestohlenes, gesperrtes Gerät | ja | Lokale Daten an den Geräte-Keystore gebunden |
| Schadsoftware auf dem Gerät | nein | Wer das Gerät kontrolliert, sieht den Klartext |
| Wer ist in welcher Gruppe | nein | Der Delivery Service kennt die Empfänger |
| Verkehrsanalyse (Timing, Menge) | teilweise | Inhalt und meist Absender verborgen, Muster bleiben |
| Push-Metadaten bei Apple/Google | nein | Token und Timing sind sichtbar |
| Spam und Bot-Konten | teilweise | Eigenes Thema, siehe Abuse-Spec |

## Wo es eng wird

Der Web-Client ist das kryptografisch schwächste Glied. Im Browser fehlt der OS-Keystore, das ausgelieferte JavaScript ist nicht signiert, und XSS oder eine bösartige Browser-Extension umgehen die ganze schöne Krypto. Signal Desktop ist aus gutem Grund Electron und kein reiner Web-Client, WhatsApp Web ist als Companion zum Telefon gedacht. Wir bieten den Web-Client trotzdem an, behandeln ihn aber als das, was er ist, und schreiben das hier hin, statt ihn mit den nativen Clients gleichzusetzen.

Push lässt sich nur halb entschärfen. Ein generisches "du hast Neues" hält den Inhalt aus dem Push, aber Apple und Google sehen weiter Token und Timing. Auf iOS kann eine Notification Service Extension den Inhalt im Sandbox des Geräts entschlüsseln, das löst das Token-Tracking nicht, verhindert aber den Inhalts-Leak. Für Android ist UnifiedPush als FCM-Alternative ein offener Prüfpunkt.

Key Transparency wirkt gestaffelt. Die Selbstprüfung im Client fängt ab Phase 1 jeden offenen Schlüsseltausch. Den Split-View, bei dem der Server verschiedenen Leuten verschiedene Verzeichnisse zeigt, fängt erst der Auditor ab Phase 3. Bis dahin ist der Schutz gegen einen aktiv bösartigen Server begrenzt.

Post-Quantum heißt hier Vertraulichkeit. Die Signaturschicht (Ed25519 für Credentials und Handshakes) bleibt klassisch, bis PQ-Signaturen wie ML-DSA in die Suites kommen. Das betrifft die Authentizität und wird erst scharf, wenn Quantencomputer real sind, weil sich eine alte Signatur nicht rückwirkend fälschen lässt.

Prekey-Erschöpfung ist auch ein Krypto-Thema. Sind die Einmal-Prekeys eines Geräts leer, fällt der Aufbau auf den Signed Prekey zurück, was die PQXDH-Eigenschaften für diese Sitzungen schwächt. Die Pool-Größe (rund 100) und das Nachfüllen ab 20 sollen das verhindern.

Schlüsselverlust trifft hart. Sind Recovery-Key und Passphrase weg, ist der lokale Verlauf weg. SVR (siehe [specs/backup-und-recovery.md](specs/backup-und-recovery.md)) mildert das später, kommt aber erst nach dem Fundament.

## Compliance

Wir bauen ein System, in dem der Betreiber technisch keine Inhalte herausgeben kann. Das ist eine politische Position. UK Online Safety Act, die EU-Debatte um Chat-Kontrolle (CSAR), Vorratsdaten: All das berührt so ein Produkt direkt. Eine Position dazu muss vor Phase 3 stehen, weil sie das Datenmodell und die Server-Fähigkeiten beeinflusst. Bis dahin steht es in [offene-fragen.md](offene-fragen.md).

## Löschen heißt Schlüssel vernichten

Daten auf einer Datenbank "sicher zu überschreiben" ist Augenwischerei, sobald Replikation, Write-Ahead-Log, Backups und das Wear-Leveling der SSD mitspielen. Die eine Kopie, die du überschreibst, ist nie die einzige. Der Hebel ist die Verschlüsselung: Vernichtest du die Schlüssel zu einem Datensatz, ist der Chiffretext wertloser Müll. Stammdaten werden gelöscht und laufen über die Backup-Rotation aus, eine Löschfrist erlaubt den Rückzieher.

## Standards

Eine Orientierung, keine Zertifizierung. ML-KEM und ML-DSA aus der NIST-PQC-Auswahl, hybrid mit X25519 und Ed25519. ChaCha20-Poly1305 und AES-256-GCM symmetrisch. Argon2id für Passwörter und Schlüsselableitung. MLS nach RFC 9420. Ein externes Audit hat nicht stattgefunden und muss zweimal her, nach dem Krypto-Kern und vor Launch.
