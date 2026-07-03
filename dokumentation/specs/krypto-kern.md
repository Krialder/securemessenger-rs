# Spec: Krypto-Kern

Hier liegen die Details, die über sicher und angreifbar entscheiden. Die Verfahren kommen aus libsignal (PQXDH, Double Ratchet, SPQR) und OpenMLS, beide auf einen konkreten Commit gepinnt, nicht auf eine schwimmende Major-Version. Was wir festlegen, ist die Integration.

## Version-Pins

Gesetzt mit dem Krypto-Kern-Crate (`crates/client-core`), als `rev` auf den jeweiligen Release-Commit, nicht auf eine schwimmende Version:

- `libsignal` v0.96.4, Commit `57d41c877d5a55d881fb3f52d9b16900118ee29b` (PQXDH, Double Ratchet, SPQR; ML-KEM über libcrux).
- `openmls` v0.8.1, Commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` (dazu `openmls_rust_crypto` und `openmls_basic_credential` aus demselben Commit).
- ML-KEM und ML-DSA über die in libsignal/OpenMLS genutzten Implementierungen, keine eigene. [ANNAHME: PQXDH nutzt ML-KEM-1024, wie libsignal es produktiv verwendet; die ältere Erwartung ML-KEM-768 stammt aus der PQXDH-Beschreibung unten und bleibt dort als Verfahrensreferenz.]

Nachziehen ist ein bewusster Schritt: Pin ändern, Roundtrip-Beweise in `crates/client-core/tests/` laufen lassen, Änderung im Live-Dokument festhalten.

## PQXDH und die Hybrid-Bindung

PQXDH kombiniert mehrere X25519-DH-Schritte (X3DH-Stil) mit dem PQ-KEM ML-KEM-768. Das Sitzungsgeheimnis, grob:

```
SK = KDF( F || DH1 || DH2 || DH3 || DH4 || SS )
```

`DH1..DH4` sind die X25519-Ergebnisse (das vierte nur mit Einmal-Prekey), `SS` das KEM-Geheimnis, `F` ein fester Domain-Präfix. Der KEM-Chiffretext `CT` wird mitgesendet.

Der ganze Gewinn hängt an der Bindung. Könnte ein Angreifer den PQ-Anteil strippen oder `CT` austauschen, fiele man auf reine X25519-Sicherheit zurück. Deshalb gehen alle Anteile gemeinsam durch die KDF, die Associated Data der ersten Nachricht bindet beide Identitätsschlüssel und `CT`, und Domain-Separation-Labels trennen die Ableitung von jeder anderen. Byte-Layout, Labels und `F` übernehmen wir 1:1 aus der PQXDH-Spec von libsignal. An genau dieser Stelle sind in den letzten Jahren reihenweise eigene Hybrid-Konstruktionen gebrochen.

## Double Ratchet und SPQR

Der Nachrichtenschlüssel zieht aus der DH-Kette und der symmetrischen Kette. SPQR ist ein paralleler post-quantum Ratchet, der seinen Anteil beisteuert. Die Mischung ist so bindungskritisch wie bei PQXDH: Beide Chain-Key-Anteile gehen gemeinsam in die KDF (Konkatenation vor der Ableitung), keiner darf strippbar sein. Das Schema übernehmen wir aus libsignal und pinnen es an die SPQR-Version.

## Out-of-Order und Replays

Der Ratchet puffert Message-Keys für Nachrichten in falscher Reihenfolge. Das Fenster braucht harte Grenzen, sonst wird es ein Speicher-DoS. Zielwerte: bis etwa 2000 übersprungene Keys pro Sitzung, Aging der Keys nach einigen Wochen, ein Speicherlimit pro Sitzung. Genau festzulegen.

## MLS-Cipher-Suite

```
MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519   (Suite 0x0003)
```

ChaCha20-Poly1305, damit der symmetrische Teil über die ganze Plattform einheitlich ist und es auch ohne AES-Hardware schnell läuft. Diese Suite ist klassisch, Gruppen sind also nicht post-quantum. Ein PQ-Pfad existiert nur als Draft (`draft-ietf-mls-combiner`), wir ziehen nach, sobald er in OpenMLS landet.

## Post-Quantum-Authentizität

Auch nach dem KEM-Combiner bleibt die Signaturschicht (Ed25519 für Credentials und Handshakes) klassisch, bis PQ-Signaturen (ML-DSA, SLH-DSA) in die Suites kommen. Das betrifft die Authentizität, die Vertraulichkeit ist über PQXDH abgedeckt. Weniger dringend, weil eine Signatur sich nicht rückwirkend fälschen lässt, sie zählt erst, wenn ein Quantencomputer real ist. Steht auf der Roadmap als zweite Welle.

## Krypto-Agilität und Wire-Versionierung

Die Frage, an der viele Projekte scheitern. Unser Ansatz:

1. Jede Hülle und Sitzung trägt Protokoll-Version und Suite-ID, nichts implizit.
2. Das Prekey-Bündel nennt die unterstützten Suites, beim Aufbau wird die höchste gemeinsame gewählt.
3. Downgrade-Schutz: Die ausgehandelte Version geht in den Transkript-Hash. Ein MITM, der eine schwächere Suite erzwingt, zerstört den Handshake.
4. Migration: Neue Sitzungen nehmen die neue Suite, bestehende laufen aus oder werden an einem Stichtag zum Neu-Handshake gezwungen. Eine alte Suite wird serverseitig erst abgeschaltet, wenn die Clients migriert sind.

## Reserviert für Anrufe

Verschlüsselte Anrufe (Phase 5) leiten ihre Medienschlüssel später aus dem MLS-Exporter ab. Das ist nur eine Notiz: Die Exporter-Schnittstelle und die Suite-Bindung müssen schon jetzt so bleiben, dass eine spätere Call-Schicht (SFrame über DTLS-SRTP) darauf aufsetzen kann.

## Zufall und Nonces

Schlüssel und Nonces kommen aus dem CSPRNG der Bibliothek. Nonce-Wiederverwendung ist bei AEAD tödlich und wird durch die Library-Nutzung vermieden.

## Offen

- ~~Die exakten Version-Pins.~~ Gesetzt, siehe "Version-Pins".
- Skipped-Keys-Fenster: Vorwärts-Fenster 2000 ist in `crates/client-core` gesetzt (MLS-Sender-Ratchet); Aging und Speicherlimit pro Sitzung stehen noch aus.
- Stichtags-Mechanik für Re-Handshakes.
- PQ-MLS- und PQ-Signatur-Zeitpunkt.
