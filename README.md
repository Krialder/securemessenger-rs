# Sichere Messaging-Plattform

Verschlüsselte Kommunikation, ausgelegt gegen die Angreifer von heute und von morgen (auch gegen künftige Quantencomputer). Ein Konto über Web, Mobile und Desktop, der Server sieht nur Chiffretext. Backend und Krypto-Core sind in Rust geschrieben, betrieben über Docker auf Kubernetes.

Die Plattform dient zugleich als Basis für die übrigen Ausbildungsprojekte: Anmeldung (SSO), Benachrichtigung und Chat stehen als geteilte Dienste über Standard-Protokolle bereit, damit ein Projekt wie AzubiOS sie einbindet, ohne seinen eigenen Stack zu ändern.

## Stand

Der Kern funktioniert und ist vorführbar. Zwei Nutzer registrieren sich auf den echten Diensten, veröffentlichen Prekeys, bauen per PQXDH eine Sitzung auf und tauschen Ende-zu-Ende verschlüsselte Nachrichten (1:1 und in MLS-Gruppen), im Web-Client (Leptos/WASM) wie im CLI-Referenzclient, auch über mehrere gekoppelte Geräte. Der Empfang läuft in Echtzeit über einen WebSocket-Hinweiskanal, Schlüssel lassen sich über Key Transparency (Selbstprüfung, Konsistenzprüfung), Safety Number und Schlüsselwechsel-Warnung verifizieren. Ein Blick in die Zustell-Datenbank zeigt ausschließlich Chiffretext, und bei versiegelten Nachrichten (Sealed Sender) nicht einmal den Absender.

Der verbindliche, fortlaufend gepflegte Funktionsstand steht im [Live-Dokument](dokumentation/live-dokument.md), Abschnitt 9a (Bilanz) und Abschnitt 10 (Verlauf). Es ist die einzige maßgebliche Status-Quelle, damit der Stand nur an einer Stelle gepflegt wird und nicht mehrfach driftet. Fertig sind unter anderem: die sechs Backend-Dienste (identity, directory, delivery, integrations, media, kt) mit je eigener PostgreSQL-Datenbank, der Krypto-Kern (libsignal, OpenMLS, gepinnt), die beiden Clients, MLS-Gruppen, Multi-Device mit Self-Sync, die verschlüsselte Geräte-Ablage (Keystore), Kontoverwaltung samt Wurzelschlüssel-Rotation, Contact Discovery über OPRF, die Abuse-Abwehr (Message Franking, Blockieren, Proof-of-Work), Disappearing Messages, Sealed Sender über austauschbare Absender-Zertifikate, CI und die Kubernetes-Manifeste. Offen und als solches markiert: die Betriebs-Härtung und das externe Audit, das nach [ADR-0008](dokumentation/entscheidungen/0008-krypto-vor-externem-review.md) den Produktivbetrieb blockiert.

Für den geführten Einstieg genügt eine Doppelklick-Anwendung im Stil des Messengers: `SecureMessenger.cmd` öffnet ein Fenster, das die Umgebung prüft, Fehlendes per Haken-Auswahl einrichtet (auch die Erstinstallation von Rust, Docker und Co.) und danach den Container-Stack samt Web-Client startet. Der Konsolen-Weg ist `scripts\sm.ps1` (aus einem PowerShell-Terminal): ohne Argument startet der Verbund über Docker Compose im Produktionsmodus (Secrets aus einer automatisch erzeugten lokalen `.env`), `-Web` nimmt den Web-Client dazu, `-Sso` Keycloak, `-Stop` beendet, `-Setup` richtet nur ein. Details in [deploy/compose/README.md](deploy/compose/README.md); die echten Kubernetes-Manifeste laufen lokal über [deploy/kind](deploy/kind/up.ps1), mehr in [ENTWICKLUNG.md](ENTWICKLUNG.md).

Die vollständige Dokumentation liegt in [dokumentation/](dokumentation/). Dort steht, wie das System aufgebaut ist, wie die Verschlüsselung arbeitet, was sie schützt und wie man das Ganze betreibt.

Guter Einstieg:

- [Überblick](dokumentation/README.md)
- [Lastenheft](dokumentation/lastenheft.md)
- [Pflichtenheft](dokumentation/pflichtenheft.md)
- [Architektur](dokumentation/architektur.md)
- [Protokoll und Kryptografie](dokumentation/protokoll.md)
- [Sicherheit und Bedrohungsmodell](dokumentation/sicherheit.md)
- [Roadmap](dokumentation/roadmap.md)

## Lizenz

Dieses Projekt steht unter der **GNU Affero General Public License v3.0** (AGPL-3.0-only), voller Text in [LICENSE](LICENSE). Der Krypto-Kern (Signals libsignal) ist AGPL, und da AGPL Netzwerk-Copyleft ist, wird das kombinierte Werk unter AGPL offengelegt: wer den Dienst betreibt und über ein Netz anbietet, muss den korrespondierenden Quellcode unter denselben Bedingungen zugänglich machen.
