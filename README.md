# Sichere Messaging-Plattform

Verschlüsselte Kommunikation, ausgelegt gegen die Angreifer von heute und von morgen (auch gegen künftige Quantencomputer). Ein Konto über Web, Mobile und Desktop, der Server sieht nur Chiffretext. Backend und Krypto-Core sind in Rust geschrieben, betrieben über Docker auf Kubernetes.

Die Plattform dient zugleich als Basis für die übrigen Ausbildungsprojekte: Anmeldung (SSO), Benachrichtigung und Chat stehen als geteilte Dienste über Standard-Protokolle bereit, damit ein Projekt wie AzubiOS sie einbindet, ohne seinen eigenen Stack zu ändern.

Die vollständige Dokumentation liegt in [dokumentation/](dokumentation/). Dort steht, wie das System aufgebaut ist, wie die Verschlüsselung arbeitet, was sie schützt und wie man das Ganze betreibt.

Guter Einstieg:

- [Überblick](dokumentation/README.md)
- [Lastenheft](dokumentation/lastenheft.md)
- [Pflichtenheft](dokumentation/pflichtenheft.md)
- [Architektur](dokumentation/architektur.md)
- [Protokoll und Kryptografie](dokumentation/protokoll.md)
- [Sicherheit und Bedrohungsmodell](dokumentation/sicherheit.md)
- [Roadmap](dokumentation/roadmap.md)
