# Bedrohungsmodell (STRIDE und LINDDUN)

Dieses Dokument baut das Gerüst aus [sicherheit.md](sicherheit.md) zum vollen Modell aus. STRIDE geht die klassischen Sicherheitsbedrohungen je Komponente durch, LINDDUN die Datenschutz-Bedrohungen je Datenfluss. Beide nennen zu jeder Bedrohung die konkrete Gegenmaßnahme im Code, damit das Modell prüfbar bleibt und nicht bei Absichtserklärungen stehen bleibt. Wo eine Bedrohung offen ist, steht das als Restrisiko, nicht kaschiert.

Der Zuschnitt folgt der gebauten Plattform: sechs Dienste (identity, directory, delivery, integrations, media, kt), der Krypto-Kern in den Clients, zwei Referenzclients (CLI, Web). Die Nachrichten-Kryptografie liegt ausschließlich im Client-Kern; der Server hält Chiffretext.

## Systemgrenzen und Datenflüsse

Die betrachteten Flüsse, alle über TLS und die meisten zusätzlich Ende-zu-Ende verschlüsselt:

1. Client zu identity: Registrierung, Login, Geräteverwaltung, Discovery.
2. Client zu directory: Prekey- und KeyPackage-Veröffentlichung, Bündel-Abruf.
3. Client zu delivery: Hüllen einreichen, abholen, bestätigen, WebSocket-Hinweise, Gruppen, Meldungen, Blocklisten.
4. Client zu kt: Selbstprüfung, Konsistenzprüfung.
5. Dienst zu Dienst: directory und delivery lösen Tokens und Gerätemengen über identitys interne Routen auf; identity meldet Schlüsseländerungen an kt; integrations stößt Events über delivery an. Alle abgesichert über ein Shared Secret, im Cluster zusätzlich über NetworkPolicy.

## STRIDE je Komponente

### identity (Konten, Auth, Discovery)

- **Spoofing:** Ein Angreifer gibt sich als fremdes Konto aus. Gegenmaßnahme: Passwörter als Argon2id-Hash, gerätegebundene Sessions mit rotierenden Access- und Refresh-Tokens, Reuse eines rotierten Refresh-Tokens widerruft die ganze Familie (OAuth 2.0 Security BCP). Geräte-Credentials signiert der Konto-Identitätsschlüssel, der Server prüft nur (`verify_strict`) und hält keine privaten Schlüssel.
- **Tampering:** Manipulation der Konto- oder Gerätedaten. Gegenmaßnahme: Eindeutigkeit erzwingt die Datenbank (Unique-Constraints), nicht der Anwendungscode; Geräte-IDs bleiben nach Revocation gesperrt, damit alte signierte Credentials nicht wiederverwendbar sind (Replay-Schutz).
- **Repudiation:** Ein Absender leugnet eine missbräuchliche Nachricht. Das ist ein Delivery-Thema (Franking), nicht identity.
- **Information Disclosure:** Existenz eines Kontos verraten. Gegenmaßnahme: Login prüft auch bei unbekanntem Handle gegen einen Dummy-Hash, damit die Antwortzeit nichts verrät; Contact Discovery läuft oblivious über eine OPRF (der Server sieht den gesuchten Handle nie im Klartext).
- **Denial of Service:** Massenanfragen. Gegenmaßnahme: Rate-Limits je Handle auf Login (10/min) und Registrierung (5/min), Sybil-Bremse über Proof-of-Work bei der Registrierung (`POW_DIFFICULTY`).
- **Elevation of Privilege:** Zugriff auf fremde Geräte oder Sessions. Gegenmaßnahme: Die internen Routen (Introspektion, Gerätemenge) hängen nur bei gesetztem Shared Secret im Router, ohne existieren sie nicht (echtes 404); ein Konto kann nur den eigenen Vorrat und die eigenen Geräte verwalten (Token bestimmt das Gerät, nie der Body).

### directory (Prekeys, KeyPackages)

- **Spoofing:** Fremde Prekeys unterschieben. Gegenmaßnahme: Der Upload landet unter dem Gerät des Bearer-Tokens, nie unter einem im Body genannten. Die Signaturen der Prekeys prüft der Client-Kern beim Bündel-Verarbeiten gegen die Geräte-Identität (nicht der Server, er hält opake Blobs).
- **Tampering:** Prekey-Blobs verändern. Gegenmaßnahme: opake Blobs, deren Signatur der Empfänger-Client prüft; ein manipulierter Blob scheitert dort.
- **Information Disclosure:** Wer ruft wessen Bündel ab (sozialer Graph). Restrisiko: Der Abruf ist Bearer-authentifiziert, der Server sieht Abrufer und Ziel. Sealed Sender verbirgt später den Absender beim Senden, nicht den Bündel-Abruf; das bleibt ein Metadaten-Punkt.
- **Denial of Service:** Einmal-Prekeys leersaugen. Gegenmaßnahme: Rate-Limit je Abrufer (30/min); atomare Konsumierung (`FOR UPDATE SKIP LOCKED`), sodass kein Schlüssel doppelt vergeben wird.
- **Elevation of Privilege:** analog identity; interne Auflösung nur über das Shared Secret.

### delivery (Zustellung, Gruppen, Abuse)

- **Spoofing:** Als fremdes Gerät zustellen lassen oder abholen. Gegenmaßnahme: Empfänger werden über identity zu Konto und Gerätemenge aufgelöst, jede Hülle adressiert genau ein gültiges Gerät; Abholen und Ack laufen über das eigene Bearer-Token.
- **Tampering:** Hüllen verändern oder umordnen. Gegenmaßnahme: Hüllen sind opake, E2E-verschlüsselte Blobs; die Eingangsreihenfolge hält eine monotone Sequenz (nicht der rundungsanfällige Zeitstempel). Gruppen-Commits serialisiert der Dienst über eine fortlaufende Epoche, konkurrierende Commits gegen dieselbe Epoche werden abgewiesen (409).
- **Repudiation:** Missbrauch leugnen. Gegenmaßnahme: Message Franking; der Absender committet sich (`HMAC(K_f, Nachricht)`), der Server bewahrt das Commitment auf, der Empfänger deckt es beim Melden auf, und der Server verifiziert, dass genau diese Nachricht so gesendet wurde. Eine Meldung lässt sich damit nicht fälschen.
- **Information Disclosure:** Absender und Zeitpunkt. Gegenmaßnahme: Sealed Sender; die versiegelte Hülle trägt keinen Absender (er steckt mitverschlüsselt darin, geprüft über die Zertifikatskette aus `crates/sealed-cert`), und die Einreichung läuft ohne Token über `POST /sealed`. Restrisiko: Auf dem klassischen Pfad (`POST /messages`) ist der Absender über das Bearer-Token bekannt (flüchtig, nie gespeichert) und steht im `smenv.v1`-Framing; der Zeitpunkt einer Zustellung bleibt auf beiden Pfaden sichtbar, ebenso der `expires_at`-Zeitpunkt einer Disappearing Message (bewusster Tradeoff des Absenders).
- **Denial of Service:** Posteingang fluten. Gegenmaßnahme: Batch- und Größenlimits je Aufruf; blockierte Absender werden still verworfen (empfängerseitige Kontrolle), ohne dass die Antwort die Blockliste verrät.
- **Elevation of Privilege:** In fremde Gruppen einschreiben. Gegenmaßnahme: Gruppen-Nachrichten gehen nur an bekannte Mitglieds-Geräte; die kryptografische Mitgliedschaft prüft der Client selbst (der Server ist dafür nicht vertrauenswürdig, das ist die Haltung der MLS-DS-Spec).

### kt (Key Transparency)

- **Tampering:** Das Verzeichnis nachträglich umschreiben. Gegenmaßnahme: append-only Log als Quelle der Wahrheit, der AZKS-Baum wird beim Start deterministisch aus dem Log wiederaufgebaut und gegen die gespeicherten Wurzeln geprüft (Integritätsbruch = harter Startfehler). Clients prüfen Konsistenz zwischen Epochen (Append-only-Beweis, `verify_consistency`).
- **Spoofing / Info Disclosure:** Ein stiller Schlüsseltausch. Gegenmaßnahme: Die Client-Selbstprüfung rechnet das eigene Commitment nach und schlägt Alarm, wenn das Verzeichnis abweicht. Der VRF verschleiert die Handle-Labels gegen Durchzählen.
- **Restrisiko Split-View:** Zeigt der Server verschiedenen Parteien in sich konsistente, aber unterschiedliche Verzeichnisse, fängt das erst ein Netz unabhängiger Auditoren plus Gossip. Die Konsistenzprüfung ist der lokale Teil davon; die unabhängigen Betreiber sind offen (Phase 3).

### media, integrations

- **media:** Der Server sieht nur Chiffretext ohne Metadaten; die Referenz wirkt als Capability (wer Referenz und Schlüssel hat, hat die Datei). Restrisiko: Retention und GC verwaister Blobs sind offen.
- **integrations:** Mandantenfähig, jedes Fremdprojekt mit eigenem Argon2id-gehashtem Secret, Scopes und Rate-Limit; ein Token wirkt nie unter fremdem Mandantenpfad (403). Benachrichtigungen sind bewusst minimal (Mandant und Titel), damit der Kanal keine Inhalte trägt.

## LINDDUN je Datenfluss

- **Linkability:** Lassen sich Aktionen desselben Nutzers verketten? Der Bündel- und Discovery-Abruf sind Bearer-authentifiziert, also serverseitig verkettbar. Discovery mildert die Handle-Preisgabe (OPRF), nicht die Verkettung des Abrufers. Restrisiko, das Sealed Sender und anonyme Credentials adressieren.
- **Identifiability:** Wird ein Nutzer identifiziert, wo er anonym bleiben sollte? Beim versiegelten Senden nein (`POST /sealed`, ohne Token, Absender nur in der verschlüsselten Hülle), auf dem klassischen Pfad ja (Bearer), beim Discovery-Ziel nein (OPRF). Der `franking_key` und der Klartext bleiben E2E; der Server lernt Inhalt erst durch eine Meldung des Empfängers.
- **Non-repudiation (hier gewollt):** Message Franking schafft bewusst Nachweisbarkeit für Meldungen, ohne die E2E zu brechen; das ist die kontrollierte Ausnahme vom sonstigen Ziel der Abstreitbarkeit.
- **Detectability:** Ist erkennbar, dass überhaupt kommuniziert wird? Der WebSocket-Hinweis trägt keinen Inhalt, aber Timing und Menge bleiben sichtbar (Verkehrsanalyse). Push-Metadaten sind bei Apple und Google sichtbar.
- **Disclosure of Information:** Inhalts-Preisgabe. Verhindert durch E2E; der Server hält nur Chiffretext, bewiesen im Abnahmetest (Klartext-Suche in der Zustell-Datenbank liefert null Treffer).
- **Unawareness:** Weiß der Nutzer, was preisgegeben wird? Der Web-Client sagt sichtbar an, dass er das schwächste Glied ist (kein OS-Keystore); die Safety Number und die Schlüsselwechsel-Warnung machen Schlüssel-Ereignisse sichtbar.
- **Non-compliance:** Die Compliance-Position (CSAR, Online Safety Act) ist offen und in [offene-fragen.md](offene-fragen.md) verankert; das System ist so gebaut, dass der Betreiber technisch keine Inhalte herausgeben kann.

## Restrisiko-Register

| Risiko | Status | Adressiert durch |
|--------|--------|------------------|
| Absender-Metadaten beim Senden | teilweise | Sealed Sender gebaut (Zertifikatskette, `POST /sealed` ohne Token); offen bleiben anonyme zkgroup-Credentials, Delivery-Tokens und der Web-Client-Pfad |
| Split-View im KT | teilweise | Konsistenzprüfung lokal da; unabhängige Auditoren + Gossip offen (Betreiber) |
| Verkehrsanalyse (Timing, Menge) | offen | Bewusst nicht gelöst; Padding/Cover-Traffic wäre eine eigene Etappe |
| Push-Metadaten bei Apple/Google | offen | Push-Provider werden nicht vertraut; nur Inhalt bleibt draußen |
| PQ-Signaturen (Authentizität) | offen | Ed25519 bis ML-DSA in den Suites ist; betrifft erst reale Quantencomputer |
| PQ-Gruppen | offen | MLS klassisch bis zum Combiner-Draft in OpenMLS (Upstream) |
| Schadsoftware auf dem Endgerät | außerhalb | Wer das Gerät kontrolliert, sieht den Klartext; keine Software löst das |
| Externes Audit | ausstehend | Blockiert per ADR-0008 den Produktivbetrieb, nicht den Bau |

## Verhältnis zu STRIDE-Phasen

Das hier ist das vollständige Gerüst für Phasen 1 bis 3, geerdet am gebauten Stand. Ein formales Handshake-Modell (ProVerif oder Tamarin) und ein zweites, breiteres Audit gehören in die Härtungsphase; sie stehen als offene Punkte in der [roadmap.md](roadmap.md).
