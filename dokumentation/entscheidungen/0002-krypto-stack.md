# 0002: Krypto-Stack

**Status:** akzeptiert

## Kontext

Eine sichere Messaging-Plattform steht und fällt mit der Wahl der Verfahren. Zwei Dinge waren gesetzt: nichts selbst bauen, und der Schutz muss halten, wenn in ein paar Jahren ein Quantencomputer alte Mitschnitte angeht.

## Entscheidung

Sitzungsaufbau über PQXDH (X25519 plus ML-KEM-768). Laufende 1:1-Sitzung über Double Ratchet plus SPQR. Gruppen über MLS (RFC 9420, Suite 0x0003). Absender verbergen über Sealed Sender mit anonymen Credentials. Echtheit der Schlüssel über Key Transparency, Echtheit des Clients über Binary Transparency. Symmetrisch ChaCha20-Poly1305 und AES-256-GCM, abgeleitet mit Argon2id und HKDF. Details in [specs/krypto-kern.md](../specs/krypto-kern.md).

## Konsequenzen

1:1 ist post-quantum, mit Forward Secrecy und Post-Compromise Security. Die Echtheits-Frage beim Schlüsselaustausch ist abgedeckt, statt sie dem Nutzer aufzubürden.

Zwei Lücken bleiben offen ausgewiesen. Gruppen sind über MLS noch klassisch, weil die PQ-Variante erst als Draft existiert. Und die Signaturschicht bleibt klassisch, bis PQ-Signaturen in die Suites kommen, was die Authentizität betrifft und erst mit realen Quantencomputern scharf wird. Beides steht auf der Roadmap.
