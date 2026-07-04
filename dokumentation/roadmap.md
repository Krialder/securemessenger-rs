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
- [ ] Threat-Model-Gerüst (Assets, Trust-Boundaries, Adversary-Katalog) zu vollem LINDDUN/STRIDE ausbauen, als Eingang in Phase 1
- [ ] Externer Krypto-Review auf Specs und Code, spätestens zusammen mit dem ersten Audit (M4); blockiert nicht mehr den Code-Start, sondern den Produktivbetrieb, siehe [ADR-0008](entscheidungen/0008-krypto-vor-externem-review.md)

## Phase 1: Fundament

- [x] Identität und Auth: Konten mit Handle, Login, rotierende Sessions (identity-Dienst, F010-F050)
- [x] Geräteverwaltung und Geräte-Identitätsbindung (Konto-Identitätsschlüssel signiert die Credentials `smdc.v1`, Schlüsseländerungen werden an KT gemeldet)
- [x] Schlüssel-Verzeichnis mit Prekey-Pool (klassisch und post-quantum), atomare Konsumierung (directory-Dienst, F110)
- [x] Key-Transparency-Grundgerüst serverseitig: Epochen, Merkle-Map über akd (kt-Dienst, F120); die Selbstprüfung im Client folgt mit der Client-Etappe
- [ ] Reproducible-Build- und Release-Pipeline mit Binary-Transparency-Log (CI mit gepinnten, eingabestabilen Builds steht; das BT-Log ist offen)
- [x] Web-Client (Leptos/WASM) und nativer CLI-Client parallel: beide registrieren sich, veröffentlichen Schlüssel, tauschen 1:1-E2EE-Nachrichten über PQXDH und Double Ratchet, empfangen über den WebSocket-Hinweiskanal, prüfen Schlüssel über Key Transparency und Safety Number. Meilenstein 1 aus GOAL.md ist mit der Abnahme vom 04.07.2026 erreicht (live-dokument v0.24).

## Phase 1b: Basis-Dienste für andere Projekte

Baut auf Identität und Auth auf, macht den Kern zum Fundament für die übrigen Ausbildungsprojekte.

- [ ] OIDC-Provider für Single Sign-on, ein Konto für alle Abteilungs-Werkzeuge
- [ ] Benachrichtigungs-Gateway für Fremdprojekte (markierte Maschinen-Hinweise, getrennt vom E2E-Chat)
- [ ] Präsenz-Abruf über eine mandantenfähige REST-Schnittstelle
- [ ] Mandantenfähigkeit mit eigenem Token und Rate-Limit je Projekt
- [ ] Ein Drittprojekt (z. B. AzubiOS) bindet die Dienste testweise ein, ohne eigenen Umbau

## Phase 2: 1:1-Nachrichten

- [x] Sitzungsaufbau über PQXDH, Double Ratchet plus SPQR (client-core, gepinnt libsignal; Roundtrip-Beweise)
- [x] Senden und Empfangen, Echtzeit-Push (WebSocket-Hinweiskanal), idempotente Zustellung (Dedupe-Tabelle)
- [x] Multi-Device-Fanout (eine Hülle je Zielgerät, delivery löst die Gerätemenge über identity auf)
- [ ] Volles Threat Model (LINDDUN, STRIDE) und ein formales Handshake-Modell-Skelett (ProVerif oder Tamarin), parallel zum Kern
- [ ] Erstes externes Audit des Krypto-Kerns

## Phase 3: Metadaten, Verifikation, Abuse

- [ ] Sealed Sender mit anonymen Credentials (zkgroup)
- [x] Key Transparency: Konsistenzbeweise client-seitig prüfbar (`KtClient::verify_consistency`, `sm audit`); der unabhängige Auditor-Betrieb und Gossip gegen den Split-View bleiben offen (Betreiber, Phase 3)
- [x] Safety Numbers (Web und CLI) und sichtbare Warnung bei Schlüsselwechsel (`Device::stored_identity`, `sm keycheck`)
- [x] Contact Discovery (OPRF): der Client blendet den Handle, identity wertet die OPRF aus (voprf, RFC 9497), der Client entblendet und schlägt oblivious nach; rate-limitiert gegen Enumeration, Ergebnis gegen KT prüfbar
- [x] Abuse: Message Franking (HMAC-Commitment, beweisbare Meldung), empfängerseitige Kontrollen (Blockieren) und Sybil-Bremse (Proof-of-Work bei der Registrierung); Privacy Pass für rate-limitierte Tokens bleibt offen
- [ ] Compliance-Position festgelegt (CSAR, Online Safety Act)

## Phase 4: Gruppen

- [ ] MLS-Gruppen über OpenMLS, Beitritt, Austritt, Neuschlüsseln
- [ ] Delivery Service gehärtet gegen Ghost Users, External Commits, Reorder

## Phase 5: Medien und Anrufe

- [ ] Verschlüsselter Dateiversand über den Medien-Dienst
- [x] Disappearing Messages: server-seitiges Ablaufen unabgeholter Hüllen (`expires_at`, `sm send --ttl`); die client-seitige Löschung-nach-Lesen und Edits/Reactions (mit ihrer Wirkung auf Franking) bleiben offen
- [ ] Anrufe als eigenes Subprojekt: SFrame, MLS-basiertes Group-Calling, DTLS-SRTP. Der MLS-Exporter ist im Krypto-Kern dafür reserviert.

## Phase 6: Härtung

- [ ] PQ-MLS, sobald der Combiner-Draft in OpenMLS ist
- [ ] PQ-Signaturen (ML-DSA) für die Authentizität
- [ ] Formale Modelle vervollständigen, Fuzzing, Property-Tests
- [ ] Zweites externes Audit vor Launch

## Später

- Föderation: serverübergreifende Key Transparency, Discovery, S2S-Auth
- Multi-Region
- Secure Value Recovery scharfschalten (Enclave-Wahl, PIN-Härtung)
- Client-seitige Suche über den lokalen Verlauf
- FIDO2 als phishing-resistenter Login-Faktor
