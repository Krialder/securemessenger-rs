# 0009: Eine Geräte-Identität - die libsignal-Identität ist der Geräteschlüssel

**Status:** akzeptiert (Entscheidung des Auftraggebers vom 03.07.2026)

## Kontext

Beim Bau des Nachrichten-Layers trafen zwei Schlüsselwelten aufeinander. Die Geräte-Identitätsbindung (specs/geraete-identitaet.md) kennt einen Ed25519-Konto-Wurzelschlüssel, der je Gerät ein Credential über den öffentlichen Geräteschlüssel signiert; der identity-Dienst prüfte diesen Geräteschlüssel bisher als Ed25519-Punkt. Der Krypto-Kern (libsignal) führt für den Sitzungsaufbau eine eigene Geräte-Identität: ein Curve25519-Schlüsselpaar, dessen öffentliche Hälfte der Absender braucht, um das Prekey-Bündel zu verarbeiten und die Prekey-Signaturen zu prüfen.

Ohne Festlegung hätte jedes Gerät zwei Identitäten getragen: eine im Credential und in Key Transparency sichtbare, und eine zweite, die tatsächlich die Nachrichten authentifiziert. Die zweite hätte eigens authentifiziert werden müssen (sonst kann der Server sie beim Verteilen austauschen und sich in Sitzungen einschleichen), also ein zusätzlicher Signatur- und Prüfpfad an der heikelsten Stelle des Systems.

## Entscheidung

Es gibt genau eine Geräte-Identität: die libsignal-Identität des Geräts ist der Geräteschlüssel im Credential. Der Konto-Wurzelschlüssel signiert das Credential über die serialisierte öffentliche libsignal-Identität, der identity-Dienst speichert sie, das Verzeichnis liefert sie im Bündel aus, und das KT-Commitment deckt sie ab. Damit authentifiziert die Kette Konto-Wurzel zu Credential genau den Schlüssel, der später die Sitzungen trägt, und ein vom Server untergeschobener Schlüssel fällt in Key Transparency auf.

Der identity-Dienst prüft den Geräteschlüssel dafür nicht mehr als Ed25519-Punkt, sondern als opake, längenbegrenzte Base64-Bytes. Das ist keine Schwächung: Der Server benutzte den Schlüssel nie selbst, er speicherte und verteilte ihn nur; die einzige serverseitige Signaturprüfung (das Credential gegen den Konto-Wurzelschlüssel) bleibt unverändert Ed25519 mit `verify_strict`. Die inhaltliche Prüfung des Geräteschlüssels geschieht dort, wo sie kryptografisch zählt: im Client beim Verarbeiten des Prekey-Bündels (libsignal verifiziert die Prekey-Signaturen gegen genau diese Identität).

## Konsequenzen

Ein Schlüssel weniger pro Gerät, ein Prüfpfad weniger, und die KT-Sichtbarkeit deckt ohne Zusatzkonstruktion den wirklich benutzten Schlüssel ab; das entspricht der Signal-Architektur. Der Preis: Der identity-Dienst kann die Wohlgeformtheit des Geräteschlüssels nicht mehr kryptografisch prüfen (nur noch Form und Länge), und die Spec zur Geräte-Identität war an dieser Stelle enger formuliert (Ed25519-Geräteschlüssel); sie ist entsprechend nachgezogen. Bestehende Testdaten mit Ed25519-Geräteschlüsseln bleiben gültig, weil 32-Byte-Schlüssel innerhalb der Längengrenze liegen.
