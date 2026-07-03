# Protokoll und Kryptografie

Der Überblick. Die Details, an denen es hängt, stehen in den Specs unter [specs/](specs/), allen voran [krypto-kern.md](specs/krypto-kern.md). Eine Regel vorweg: Nichts ist selbst gebaut. PQXDH, Double Ratchet und SPQR kommen aus libsignal, die Gruppen aus OpenMLS, beide als Rust-Code auf konkrete Commits gepinnt.

## Schlüssel pro Nutzer, pro Gerät

Jeder Nutzer hat einen langlebigen Konto-Identitätsschlüssel (Ed25519). Der ist die Wurzel und liegt nur beim Nutzer, nie beim Server. Jedes Gerät hat eigene Schlüssel, die über ein vom Konto-Identitätsschlüssel signiertes Credential ans Konto gebunden sind. So hängt kein Geräteschlüssel frei in der Luft, und ein heimlich untergeschobenes Gerät fällt über Key Transparency auf. Das Modell, samt Rotation des Wurzelschlüssels und Cross-Signing, steht in [specs/geraete-identitaet.md](specs/geraete-identitaet.md).

Jedes Gerät lädt einen Vorrat an Prekeys ins Verzeichnis: einen signierten Prekey (wöchentliche Rotation) und etwa 100 Einmal-Prekeys, jeweils klassisch und post-quantum. Damit kann dir jemand eine erste Nachricht schicken, während dein Handy offline in der Tasche steckt.

## Sitzungsaufbau mit PQXDH

Schreibt jemand zum ersten Mal an ein Gerät, holt er dessen Prekey-Bündel und rechnet PQXDH: ein hybrider Schlüsselaustausch aus X25519 und dem PQ-KEM ML-KEM-768. Der PQ-Teil zielt auf ein konkretes Szenario, das Mitschneiden heute und Entschlüsseln später mit einem Quantencomputer. Hybrid heißt, ein Angreifer muss beide Anteile brechen. Wie die beiden gebunden werden, ist die heikelste Stelle und steht in der Krypto-Kern-Spec.

## Laufende Sitzung mit dem Ratchet

Sobald der Chat läuft, übernimmt der Double Ratchet. Er liefert Forward Secrecy (jede Nachricht ein frischer Schlüssel, alte werden gelöscht) und Post-Compromise Security (eine kompromittierte Sitzung heilt sich mit der nächsten Runde). libsignal bringt dazu SPQR mit, einen parallelen post-quantum Ratchet, von Signal Ende 2025 veröffentlicht. Beide Anteile mischen sich zum Nachrichtenschlüssel, womit die laufende 1:1-Sitzung quantenfest wird.

## Gruppen mit MLS

Für Gruppen nehmen wir MLS (RFC 9420) über OpenMLS, mit der ChaCha20-Poly1305-Suite. Der Kern ist ein Schlüsselbaum (TreeKEM): Tritt jemand bei oder geht, reicht ein Update entlang eines Astes, der Aufwand wächst logarithmisch. Genau hier werden ältere Ansätze teuer oder schwach, das Sender-Keys-Modell und Matrix' Megolm bei großen, aktiven Gruppen.

Zwei Haken bleiben. Erstens ist MLS in den Standard-Suites klassisch, Gruppen sind also noch nicht post-quantum (PQ-MLS läuft über einen Draft). Zweitens lebt zwischen Server und Gruppe der Delivery Service, und der ist eine eigene Angriffsfläche (Ghost Users, External Commits, konkurrierende Commits). Beides steht in [specs/krypto-kern.md](specs/krypto-kern.md) und [specs/mls-delivery-service.md](specs/mls-delivery-service.md).

## Mehrere Geräte

Jedes Gerät führt eigene Sitzungen. An einen Nutzer zu schreiben heißt, an jedes seiner Geräte zu verschlüsseln, und an die eigenen Zweitgeräte gleich mit, damit der Verlauf überall stimmt. Ein neues Gerät wird von einem bestehenden freigeschaltet und bekommt sein Credential, ein entferntes verliert seine Sitzungen und löst in Gruppen ein Neuschlüsseln aus.

## Metadaten und Sealed Sender

Bei den meisten Nachrichten weiß der Server nicht, von wem sie kommen. Die Absenderkennung steckt verschlüsselt in der Sendung, geroutet wird über den Empfänger. Wer überhaupt sealed senden darf, läuft über anonyme Credentials (zkgroup-Linie), damit der Server prüfen kann, dass der Absender ein gültiges Konto ist, ohne zu erfahren, welches. Der ganze Ablauf samt Abuse-Abwehr steht in [specs/sealed-sender-und-abuse.md](specs/sealed-sender-und-abuse.md).

## Echtheit der Schlüssel

Verschlüsseln nützt nichts, wenn der Server den falschen Schlüssel unterschiebt. Dagegen läuft Key Transparency, ein öffentlich prüfbares Log aller Schlüssel, gegen das jeder Client automatisch abgleicht. Und weil ein manipulierter Client genauso schlimm wäre wie ein manipulierter Schlüssel, kommt Binary Transparency dazu, siehe [specs/key-transparency.md](specs/key-transparency.md) und [ADR-0007](entscheidungen/0007-binary-transparency.md).

## Lokale Daten

Auf dem Gerät liegt alles verschlüsselt: private Schlüssel, der Ratchet- und MLS-Zustand, der entschlüsselte Cache, die Einstellungen. Der Schlüssel dafür kommt aus dem Hardware-Keystore der Plattform (Secure Enclave, Android Keystore, TPM), wo es einen gibt, sonst aus einer Passphrase. Die Ableitung lässt von Anfang an Platz für ein zweites Entsperr-Geheimnis, damit später Secure Value Recovery dazukann, siehe [specs/backup-und-recovery.md](specs/backup-und-recovery.md).
