# Roadmap

Sortiert nach Abhängigkeiten, ohne Termine. Zwei Dinge sind bewusst eingebaut: eine Spec-Phase vor dem Code, und Audits laufen mehrfach.

## Phase 0: Specs und Entscheidungen, vor dem Code

- [x] Krypto-Bibliotheken gepinnt (libsignal, OpenMLS), siehe [ADR-0005](entscheidungen/0005-krypto-bibliotheken.md)
- [x] Krypto-Kern: PQXDH-Bindung, MLS-Suite, SPQR, Versionierung, siehe [specs/krypto-kern.md](specs/krypto-kern.md)
- [x] Key-Transparency-Modell, siehe [specs/key-transparency.md](specs/key-transparency.md)
- [x] Sealed Sender, zkgroup-Zugang und Abuse, siehe [specs/sealed-sender-und-abuse.md](specs/sealed-sender-und-abuse.md)
- [x] Geräte-Identitätsbindung, siehe [specs/geraete-identitaet.md](specs/geraete-identitaet.md)
- [x] Contact Discovery, siehe [specs/contact-discovery.md](specs/contact-discovery.md)
- [x] MLS Delivery Service, siehe [specs/mls-delivery-service.md](specs/mls-delivery-service.md)
- [x] Binary Transparency, siehe [ADR-0007](entscheidungen/0007-binary-transparency.md)
- [x] Backup/SVR-Skizze, siehe [specs/backup-und-recovery.md](specs/backup-und-recovery.md)
- [x] Threat-Model-Gerüst zu vollem LINDDUN/STRIDE ausgebaut ([bedrohungsmodell.md](bedrohungsmodell.md): STRIDE je Dienst, LINDDUN je Datenfluss, Restrisiko-Register, jede Bedrohung mit Gegenmaßnahme im Code); formales Handshake-Modell (ProVerif/Tamarin) bleibt der Härtungsphase
- [ ] Externer Krypto-Review auf Specs und Code, spätestens zusammen mit dem ersten Audit (M4); blockiert nicht mehr den Code-Start, sondern den Produktivbetrieb, siehe [ADR-0008](entscheidungen/0008-krypto-vor-externem-review.md)

## Phase 1: Fundament

- [x] Identität und Auth: Konten mit Handle, Login, rotierende Sessions (identity-Dienst, F010-F050)
- [x] Geräteverwaltung und Geräte-Identitätsbindung (Konto-Identitätsschlüssel signiert die Credentials `smdc.v1`, Schlüsseländerungen werden an KT gemeldet)
- [x] Schlüssel-Verzeichnis mit Prekey-Pool (klassisch und post-quantum), atomare Konsumierung (directory-Dienst, F110)
- [x] Key-Transparency-Grundgerüst serverseitig: Epochen, Merkle-Map über akd (kt-Dienst, F120); die Selbstprüfung im Client folgt mit der Client-Etappe
- [x] Reproducible-Build- und Release-Pipeline mit Binary-Transparency-Log: CI mit gepinnten, eingabestabilen Builds steht, und der Log-Mechanismus ist gebaut (`crates/btlog`: hash-verkettetes, Ed25519-signiertes Release-Log plus Werkzeug `sm-bt` mit append/verify/list/lookup); offen bleibt der Betrieb (öffentliche Spiegel, Monitore, Einbindung echter Release-Artefakte beziehungsweise Rekor/Sigstore als Ablösung)
- [x] Web-Client (Leptos/WASM) und nativer CLI-Client parallel: beide registrieren sich, veröffentlichen Schlüssel, tauschen 1:1-E2EE-Nachrichten über PQXDH und Double Ratchet, empfangen über den WebSocket-Hinweiskanal, prüfen Schlüssel über Key Transparency und Safety Number. Meilenstein 1 aus GOAL.md ist mit der Abnahme vom 04.07.2026 erreicht (live-dokument v0.24).

## Phase 1b: Basis-Dienste für andere Projekte

Baut auf Identität und Auth auf, macht den Kern zum Fundament für die übrigen Ausbildungsprojekte.

- [x] OIDC-Provider für Single Sign-on, ein Konto für alle Abteilungs-Werkzeuge: Keycloak-Realm `securemessenger` versioniert und per `--import-realm` geladen (ADR-0011), mit einem vertraulichen und einem öffentlichen OIDC-Client (Authorization Code Flow plus PKCE); der Login-Fluss ist live gegen ein laufendes Keycloak bewiesen (Anmeldung als `azubi-demo`, gültiges id_token). Produktionshärtung (Brute-Force-Schutz, MFA, echte Nutzer-Föderation) bleibt Betriebssache und ist im ADR als offen markiert
- [x] Benachrichtigungs-Gateway für Fremdprojekte (markierte Maschinen-Hinweise, getrennt vom E2E-Chat): `integrations`-Dienst, `POST /integrations/notify`
- [x] Präsenz-Abruf über eine mandantenfähige REST-Schnittstelle (`integrations`-Dienst, `GET /integrations/presence`)
- [x] Webhooks (Push statt Poll): ein Fremdprojekt registriert selbst einen Callback und bekommt Präsenz-Änderungen als Ed25519-signierten Envelope zugestellt (`integrations`-Dienst: `POST/GET/DELETE /integrations/{tenant}/webhooks`, Abo je Handle, `GET /integrations/webhook-key`; delivery meldet Verbindungs-Übergänge). Live über drei Dienste bewiesen; dauerhafter Wiederhol-Speicher (Outbox mit Retry) bleibt offen
- [x] Mandantenfähigkeit mit eigenem Token und Rate-Limit je Projekt (`integrations`-Dienst: Mandanten, `POST /integrations/token` als standardkonformer OAuth2-Client-Credentials-Grant nach RFC 6749, Rate-Limit je Mandant)
- [x] Least Privilege je Token: der OAuth2-`scope`-Parameter verengt das ausgestellte Token auf eine Teilmenge der Mandanten-Rechte (ein geleaktes notify-Token kann keine Präsenz abfragen)
- [x] Konsumentenseitiger Integrations-Leitfaden plus Beispiele in mehreren Sprachen (`dokumentation/integration-leitfaden.md`, `integration-beispiele.md`): ein Drittprojekt bindet ohne eigenen Umbau an, in Python, JavaScript oder PHP oder mit einem aus der OpenAPI generierten Client
- [ ] Testweise Einbindung durch ein echtes Drittprojekt (z. B. AzubiOS) gegen einen laufenden Cluster steht noch aus (die konsumentenseitige Grundlage dafür ist da)

## Phase 2: 1:1-Nachrichten

- [x] Sitzungsaufbau über PQXDH, Double Ratchet plus SPQR (client-core, gepinnt libsignal; Roundtrip-Beweise)
- [x] Senden und Empfangen, Echtzeit-Push (WebSocket-Hinweiskanal), idempotente Zustellung (Dedupe-Tabelle)
- [x] Multi-Device-Fanout (eine Hülle je Zielgerät, delivery löst die Gerätemenge über identity auf)
- [x] Volles Threat Model (LINDDUN, STRIDE) steht ([bedrohungsmodell.md](bedrohungsmodell.md), siehe Phase 0); das formale Handshake-Modell-Skelett (ProVerif oder Tamarin) bleibt der Härtungsphase offen
- [ ] Erstes externes Audit des Krypto-Kerns

## Phase 3: Metadaten, Verifikation, Abuse

- [x] Sealed Sender über server-signierte Absender-Zertifikate (libsignal `sealed_sender_encrypt/decrypt`, Kette Trust Root → Serverschlüssel → Absender, `crates/sealed-cert`): die Hülle trägt keinen Absender, die Einreichung läuft ohne Token (`POST /sealed`); die anonymen zkgroup-Credentials und Delivery-Tokens sind die nächste Ausbaustufe und ersetzen nur die Ausstellung beziehungsweise die Empfänger-Bremse, nicht den Transport
- [x] Key Transparency: Konsistenzbeweise client-seitig prüfbar (`KtClient::verify_consistency`, `sm audit`); der unabhängige Auditor-Betrieb und Gossip gegen den Split-View bleiben offen (Betreiber, Phase 3)
- [x] Safety Numbers (Web und CLI) und sichtbare Warnung bei Schlüsselwechsel (`Device::stored_identity`, `sm keycheck`)
- [x] Contact Discovery (OPRF): der Client blendet den Handle, identity wertet die OPRF aus (voprf, RFC 9497), der Client entblendet und schlägt oblivious nach; rate-limitiert gegen Enumeration, Ergebnis gegen KT prüfbar
- [x] Abuse: Message Franking (HMAC-Commitment, beweisbare Meldung), empfängerseitige Kontrollen (Blockieren) und Sybil-Bremse (Proof-of-Work bei der Registrierung); Privacy Pass für rate-limitierte Tokens bleibt offen
- [ ] Compliance-Position festgelegt (CSAR, Online Safety Act)

## Phase 4: Gruppen

- [x] MLS-Gruppen über OpenMLS: Gründen, Senden, Beitritt per Einladung, Entfernen und Verlassen, Multi-Device-Teilnahme, in CLI und Web bedienbar (live-dokument v0.60 bis v0.66; persistente MLS-Ablage, Einladungs-UX statt Auto-Beitritt, KeyPackage-Pool-Deckel)
- [ ] Delivery Service gegen Ghost Users, External Commits, Reorder gehärtet: die Epochen-Serialisierung steht (CAS auf die Epoche, `409 stale_epoch`, erst-schreibt-gewinnt, Commit 8a638f4); eine gezielte Erkennung von Ghost Users und External Commits bleibt offen

## Phase 5: Medien und Anrufe

- [ ] Verschlüsselter Dateiversand über den Medien-Dienst
- [x] Disappearing Messages: server-seitiges Ablaufen unabgeholter Hüllen (`expires_at`, `sm send --ttl`); die client-seitige Löschung-nach-Lesen und Edits/Reactions (mit ihrer Wirkung auf Franking) bleiben offen
- [ ] Anrufe als eigenes Subprojekt: SFrame, MLS-basiertes Group-Calling, DTLS-SRTP. Der MLS-Exporter ist im Krypto-Kern dafür reserviert.

## Phase 6: Härtung

- [ ] PQ-MLS, sobald der Combiner-Draft in OpenMLS ist
- [ ] PQ-Signaturen (ML-DSA) für die Authentizität
- [x] Property-Tests der Parser und der Krypto-Integration (proptest: Wire-Framings panikfrei auf beliebiger Eingabe, Franking-Bindung, PoW-Konsistenz, KT-Commitment-Invarianten, BT-Log-Manipulationsfestigkeit, Out-of-Order über echte PQXDH-Sitzungen); formale Modelle (ProVerif/Tamarin) und ein cargo-fuzz-Harness (braucht nightly) bleiben offen
- [ ] Zweites externes Audit vor Launch

## Später

- Föderation: serverübergreifende Key Transparency, Discovery, S2S-Auth
- Multi-Region
- Secure Value Recovery scharfschalten (Enclave-Wahl, PIN-Härtung)
- Client-seitige Suche über den lokalen Verlauf
- FIDO2 als phishing-resistenter Login-Faktor
