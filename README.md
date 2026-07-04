# Sichere Messaging-Plattform

Verschlüsselte Kommunikation, ausgelegt gegen die Angreifer von heute und von morgen (auch gegen künftige Quantencomputer). Ein Konto über Web, Mobile und Desktop, der Server sieht nur Chiffretext. Backend und Krypto-Core sind in Rust geschrieben, betrieben über Docker auf Kubernetes.

Die Plattform dient zugleich als Basis für die übrigen Ausbildungsprojekte: Anmeldung (SSO), Benachrichtigung und Chat stehen als geteilte Dienste über Standard-Protokolle bereit, damit ein Projekt wie AzubiOS sie einbindet, ohne seinen eigenen Stack zu ändern.

## Stand

Der Kern funktioniert und ist vorgeführt (Meilenstein 1, Stand 04.07.2026). Zwei Nutzer registrieren sich auf den echten Diensten, veröffentlichen Prekeys, bauen per PQXDH eine Sitzung auf und tauschen Ende-zu-Ende verschlüsselte 1:1-Nachrichten, im Web-Client (Leptos/WASM) wie im CLI-Referenzclient. Der Empfang läuft in Echtzeit über einen WebSocket-Hinweiskanal, Schlüssel lassen sich über Key Transparency (Selbstprüfung) und Safety Number verifizieren. Ein Blick in die Zustell-Datenbank zeigt ausschließlich Chiffretext.

Fertig sind: die sechs Backend-Dienste (identity, directory, delivery, integrations, media, kt) mit je eigener PostgreSQL-Datenbank, der Krypto-Kern (libsignal, OpenMLS, gepinnt), die beiden Clients, CI und die Kubernetes-Manifeste. Offen und als solches markiert: Sealed Sender, MLS-Gruppen, Contact Discovery, die verschlüsselte Geräte-Ablage, die Betriebs-Härtung und das externe Audit, das nach [ADR-0008](dokumentation/entscheidungen/0008-krypto-vor-externem-review.md) den Produktivbetrieb blockiert. Details im [Live-Dokument](dokumentation/live-dokument.md), Abschnitt 10.

Der schnelle lokale Start steht in [ENTWICKLUNG.md](ENTWICKLUNG.md); `start.cmd` richtet die Umgebung ein.

Die vollständige Dokumentation liegt in [dokumentation/](dokumentation/). Dort steht, wie das System aufgebaut ist, wie die Verschlüsselung arbeitet, was sie schützt und wie man das Ganze betreibt.

Guter Einstieg:

- [Überblick](dokumentation/README.md)
- [Lastenheft](dokumentation/lastenheft.md)
- [Pflichtenheft](dokumentation/pflichtenheft.md)
- [Architektur](dokumentation/architektur.md)
- [Protokoll und Kryptografie](dokumentation/protokoll.md)
- [Sicherheit und Bedrohungsmodell](dokumentation/sicherheit.md)
- [Roadmap](dokumentation/roadmap.md)
