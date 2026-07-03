# 0003: Identität über Username, Multi-Device von Anfang an

**Status:** akzeptiert

## Kontext

Viele Messenger hängen die Identität an die Telefonnummer. Bequemes Onboarding, aber ein direkter Personenbezug, und der Adressbuchabgleich legt den sozialen Graphen offen. Gleichzeitig erwarten Leute dasselbe Konto auf mehreren Geräten.

## Entscheidung

Die Identität hängt an einem Username, eine Telefonnummer braucht es nicht. Gefunden wird über Handles per OPRF-Lookup. Multi-Device ist von Anfang an drin, mit Geräteschlüsseln, die über ein vom Konto-Identitätsschlüssel signiertes Credential ans Konto gebunden sind.

## Konsequenzen

Besserer Datenschutz von Haus aus, kein Personenbezug über die Nummer. Der Preis: Sybil-Abwehr ist schwerer (siehe [specs/sealed-sender-und-abuse.md](../specs/sealed-sender-und-abuse.md)), und das Datenmodell führt pro Konto mehrere Geräte mit eigenen Schlüsseln.

Die Wiederherstellung zerfällt in zwei Teile. Der Login ist über E-Mail und zweiten Faktor rettbar, der lokale Klartext hängt am Recovery-Key. Das gehört unübersehbar in die UI. Und der Wurzelschlüssel des Kontos ist die heikelste Stelle, seine Rotation ist in [specs/geraete-identitaet.md](../specs/geraete-identitaet.md) noch offen.
