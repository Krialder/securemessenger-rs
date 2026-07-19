# Sichere Messaging-Plattform

Ein Ende-zu-Ende verschlüsselter Messenger. Die Schlüssel bleiben auf den Geräten, der Server transportiert und speichert nur Chiffretext (Store-and-Forward-System). Ein Konto lässt sich auf mehreren Geräten nutzen. Backend und Krypto-Kern sind in Rust geschrieben und laufen als Container, lokal über Docker Compose oder auf Kubernetes.

Die Plattform ist zugleich die gemeinsame Grundlage der übrigen Ausbildungsprojekte: Anmeldung (SSO), Benachrichtigung und Chat liegen als geteilte Dienste hinter Standard-Protokollen, damit ein Projekt wie AzubiOS sie einbinden kann, ohne seinen eigenen Stack umzubauen.

## Schnellstart

Voraussetzungen: Windows mit PowerShell und Docker Desktop. Rust, das wasm32-Target, trunk und protoc braucht nur, wer selbst baut; die Doppelklick-Anwendung installiert Fehlendes auf Wunsch mit.

Der geführte Weg ist `SecureMessenger.cmd`. Ein Doppelklick öffnet ein Fenster, das die Umgebung prüft, Fehlendes per Haken einrichtet und danach den Stack samt Web-Client startet.

Der Konsolen-Weg aus einem PowerShell-Terminal:

```powershell
scripts\sm.ps1              # Dienste über Docker Compose (Produktionsmodus)
scripts\sm.ps1 -Web         # zusätzlich der Web-Client auf http://localhost:3000
scripts\sm.ps1 -Sso         # zusätzlich Keycloak als SSO-Provider
scripts\sm.ps1 -Calls       # zusätzlich coturn, damit Anrufe funktionieren
scripts\sm.ps1 -Setup       # nur einrichten, nicht starten
scripts\sm.ps1 -Stop        # alles beenden
```

Ohne Argument startet der Verbund im Produktionsmodus. Die Secrets zieht er aus einer lokalen `.env`, die beim ersten Start mit Zufallswerten erzeugt wird; sie gehört nicht ins Repository. Einzelheiten in [deploy/compose/README.md](deploy/compose/README.md).

## Was das System kann

- 1:1-Chats und Gruppen, Ende-zu-Ende verschlüsselt (Double Ratchet beziehungsweise MLS nach RFC 9420).
- Mehrere Geräte pro Konto, jedes mit eigenen Schlüsseln, dazu Self-Sync der gesendeten Nachrichten.
- Nachrichten bearbeiten und löschen, für alle oder nur lokal.
- Sprachanrufe zwischen zwei Browsern (WebRTC, TURN über coturn) samt Live-Tippen über den Datenkanal.
- Web-Push, damit eine Nachricht auch bei geschlossenem Browser ankommt.
- Schlüssel prüfen auf drei Wegen: Key Transparency (Selbst- und Konsistenzprüfung), Sicherheitsnummer, Warnung bei einem Schlüsselwechsel.
- Verschlüsselte Sicherungsdatei, mit der sich ein Gerät nach einem geleerten Browser-Speicher wiederherstellen lässt.
- Metadaten klein halten: Sealed Sender verbirgt den Absender vor dem Server, Contact Discovery läuft über OPRF, Handles statt Telefonnummern.
- Abwehr von Missbrauch: Message Franking, Blockieren, Proof-of-Work.

## Wie weit die Verschlüsselung trägt

PQXDH sichert den Sitzungsaufbau im 1:1-Chat auch gegen einen Angreifer, der den Verkehr heute mitschneidet und erst später zu entschlüsseln versucht. Die MLS-Gruppen laufen bis auf Weiteres klassisch: ein post-quantum-fähiges MLS hängt an der Bibliothek und steht in der [Roadmap](dokumentation/roadmap.md), nicht im Funktionsstand.

Ein externes Sicherheitsaudit hat nicht stattgefunden. Nach [ADR-0008](dokumentation/entscheidungen/0008-krypto-vor-externem-review.md) blockiert das den Produktivbetrieb, unabhängig davon, wie vollständig der Funktionsstand aussieht.

## Betreiben

| Weg | Womit | Wofür |
|-----|-------|-------|
| Lokal | `scripts\sm.ps1` (Docker Compose) | Entwicklung und Vorführung |
| Server | `ServerDeploy.cmd`, `deploy\remote\deploy.ps1` | Stack per SSH auf eine Linux-VM, etwa auf einem Proxmox-Host ([README](deploy/remote/README.md)) |
| Kubernetes | [deploy/kind](deploy/kind/up.ps1) | die echten Manifeste lokal fahren, für Hochverfügbarkeit und Skalierung |

Mehr zum Bauen, Testen und zur Verzeichnisstruktur in [ENTWICKLUNG.md](ENTWICKLUNG.md).

## Stand

Der Kern läuft und lässt sich vorführen. Zwei Nutzer registrieren sich auf den echten Diensten, veröffentlichen Prekeys, bauen per PQXDH eine Sitzung auf und tauschen verschlüsselte Nachrichten, im Web-Client (Leptos/WASM) wie im CLI-Referenzclient. Neue Nachrichten kündigt ein WebSocket-Hinweiskanal an, geholt werden sie per Pull. Ein Blick in die Zustell-Datenbank zeigt nur Chiffretext, bei versiegelten Nachrichten nicht einmal den Absender.

Gebaut sind unter anderem die sechs Backend-Dienste (identity, directory, delivery, integrations, media, kt) mit je eigener PostgreSQL-Datenbank, der Krypto-Kern (libsignal und OpenMLS, auf feste Commits gepinnt), beide Clients, die verschlüsselte Geräte-Ablage, die Kontoverwaltung samt Rotation des Wurzelschlüssels, CI und die Kubernetes-Manifeste. Offen sind die Betriebs-Härtung und das externe Audit.

Den verbindlichen Funktionsstand führt das [Live-Dokument](dokumentation/live-dokument.md): Abschnitt 9a die Bilanz, Abschnitt 10 den Verlauf. Es ist die einzige maßgebliche Status-Quelle, damit der Stand an einer Stelle gepflegt wird und nicht an mehreren auseinanderläuft.

## Dokumentation

Die vollständige Dokumentation liegt in [dokumentation/](dokumentation/): wie das System aufgebaut ist, wie die Verschlüsselung arbeitet, was sie schützt und wie man das Ganze betreibt.

- [Überblick](dokumentation/README.md)
- [Lastenheft](dokumentation/lastenheft.md)
- [Pflichtenheft](dokumentation/pflichtenheft.md)
- [Architektur](dokumentation/architektur.md)
- [Protokoll und Kryptografie](dokumentation/protokoll.md)
- [Sicherheit und Bedrohungsmodell](dokumentation/sicherheit.md)
- [Roadmap](dokumentation/roadmap.md)

## Lizenz

Dieses Projekt steht unter der GNU Affero General Public License v3.0 (AGPL-3.0-only), voller Text in [LICENSE](LICENSE). Der Krypto-Kern (Signals libsignal) ist AGPL, und da AGPL Netzwerk-Copyleft ist, wird das kombinierte Werk unter AGPL offengelegt: wer den Dienst betreibt und über ein Netz anbietet, muss den korrespondierenden Quellcode unter denselben Bedingungen zugänglich machen.
