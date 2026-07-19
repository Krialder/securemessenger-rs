# Betrieb und Skalierung

## Deployment

- **Dienste:** jeder Rust-Dienst ist ein eigenes Kubernetes-Deployment mit eigener Autoskalierung, davor ein Ingress als Edge mit TLS.
- **Images:** je Dienst ein Docker-Image aus einem Multi-Stage-Build, die Runtime-Stage statisch gegen musl gelinkt.
- **Zustand:** PostgreSQL, Redis, Objektspeicher, NATS und der KT-Merkle-Store laufen über erprobte Operatoren statt von Hand, weil Backup, Failover und Upgrades sonst zur Daueraufgabe werden.
- **Cluster:** der Proxmox-Verbund, damit wir keine Cloud-Abhängigkeit eingehen. Multi-Region kommt später.

## Warum Rust für die Dienste

Die Dienste sind in Rust geschrieben, auch die Realtime-Schicht. Drei Gründe tragen das:

1. Das Backend teilt die Sprache mit dem Krypto-Core (libsignal, OpenMLS). Wire-Typen und Tests gelten dadurch für beide Seiten, und niemand wechselt zwischen zwei Laufzeiten hin und her.
2. Rust schließt eine ganze Klasse von Speicherfehlern zur Compile-Zeit aus, ohne Garbage-Collector-Pausen. Das zählt bei vielen offenen WebSocket-Verbindungen.
3. Das Async-Ökosystem trägt die nebenläufige Last: tokio den Kern, axum die REST-Schicht, tokio-tungstenite die WebSockets.

Elixir auf der BEAM war historisch eine Option für Presence und Fanout (WhatsApp skaliert so), scheidet hier aber aus, weil eine zweite Laufzeit dem Ein-Sprachen-Vorteil widerspräche.

## Der Krypto-Core im Betrieb

Die Krypto läuft auf den Clients, nicht im Backend. Fürs Backend heißt das: keine privaten Schlüssel, kein Entschlüsseln, kleinere Angriffsfläche. Der Rust-Core wird als WebAssembly fürs Web und als native Bibliothek über FFI gebaut. Die Builds sind reproducible und signiert, ihre Hashes landen im Binary-Transparency-Log, damit der Server keinem Zielkonto eine abweichende App unterschieben kann (siehe [ADR-0007](entscheidungen/0007-binary-transparency.md)).

## Skalierung und die teuren Pfade

Die zustandslosen Dienste skalieren waagerecht. Die heißen Pfade Echtzeit und Zustellung skalieren unabhängig. Presence liegt in Redis mit gebündelten Updates, das Fanout läuft über NATS.

Der Sonderfall ist das Schlüssel-Verzeichnis: PQXDH-Handshakes sind teuer, ML-KEM-Schlüssel rund 1,2 KB, und der Prekey-Pool ist erschöpfbar. Dagegen stehen drei Maßnahmen:

- Rate-Limits pro Abrufer.
- Ein Pool von rund 100 Einmal-Prekeys, Nachfüllen ab 20.
- Atomare Konsumierung, siehe [Datenmodell](datenmodell.md).

Auch die Epochen-Berechnung der Key Transparency ist Last und bekommt einen eigenen Pfad.

## Echtzeit-Zustellung

Die WebSocket-Knoten halten die Verbindungen und sind austauschbar. Eine eingehende Nachricht findet über NATS den Knoten mit der Zielverbindung. Offline-Geräte weckt Push, die Sendung wartet im Store-and-forward bis zur Abholung.

## Push

Push weckt nur, der Inhalt kommt per Pull. APNs und FCM sehen trotzdem Geräte-Token und Timing (siehe [sicherheit.md](sicherheit.md)). Auf iOS prüfen wir eine Notification Service Extension, die den Inhalt im Geräte-Sandbox entschlüsselt, das hält den Inhalt aus dem Push, ohne das Token-Tracking zu lösen. Für Android steht UnifiedPush als FCM-Alternative auf der Liste.

## Beobachtbarkeit

Strukturierte Logs nach stdout, niemals mit Nachrichteninhalt. Metriken im Prometheus-Format, Health-Probes je Dienst (`live` und `ready`), Tracing über die Dienstgrenzen. Die Metriken speisen direkt die SLO-Auswertung.

## Service Level Objectives

Je SLO gibt es einen Service Level Indicator aus den Metriken, plus ein Fehlerbudget als erlaubten Rest bis zum Ziel.

| SLO | Indikator | Ziel | Fehlerbudget |
|-----|-----------|------|--------------|
| Verfügbarkeit Identität / SSO | erfolgreiche Anmelde- und Token-Antworten je Monat | 99,9 % | rund 43 min / Monat |
| Verfügbarkeit übrige Kern-Dienste | erfolgreiche Antworten je Monat (24/7) | 99,5 % | rund 3,6 h / Monat |
| Zustell-Latenz Echtzeit | `POST /messages` bis WebSocket-Event beim Online-Empfänger | p95 < 500 ms, p99 < 1 s | Anteil über Schwelle |
| API-Latenz | Antwortzeit der REST-Endpunkte | p95 < 2 s | Anteil über Schwelle |
| Zustell-Durability | angenommene Nachrichten, die bis zum Ack abrufbar bleiben | 99,99 % | kein stiller Verlust |

Der Identitäts- und SSO-Dienst trägt das strengste Ziel, weil sein Ausfall alle abhängigen Projekte trifft. Er läuft deshalb redundant mit mehreren Repliken. Ist ein Fehlerbudget aufgebraucht, hat Stabilisierung Vorrang vor neuen Funktionen. Die Key-Transparency-Korrektheit ist kein SLO, sondern eine harte Invariante: Jede erkannte Inkonsistenz ist ein Sicherheitsvorfall.

## Incident-Response und Postmortems

Es gibt einen definierten Eskalationspfad mit Schweregrad-Klassen. Nach jedem SLO-Bruch und jedem Sicherheitsvorfall entsteht ein blameless Postmortem, das nach Systemursachen fragt, nicht nach Schuld. Sicherheitsvorfälle (Verdacht auf KT-Split-View, Schlüssel-Leak, kompromittierter Wurzelschlüssel) folgen einem strengeren Security-Incident-Prozess mit sofortiger Eindämmung.

## Die Plattform als Basis für andere Projekte

Das Deployment-Muster (Helm-Charts, Kubernetes-Manifeste, CI-Vorlagen) dient zugleich als Referenz für Folgeprojekte. Das ist ein Angebot, kein Zwang. Bestehende Projekte wie AzubiOS bleiben auf ihrer Umgebung (Proxmox, Docker Compose) und nutzen die Dienste über das Netzwerk. Neue Projekte können das Muster übernehmen und im selben Cluster mitlaufen. Der Betrieb der Basis-Dienste (Identität, Benachrichtigung) folgt denselben Regeln wie der Rest, mit zusätzlichem Rate-Limiting pro Mandant.

## Audit-Timing

Nicht erst am Ende. Ein externes Audit gehört mindestens zweimal eingeplant, einmal sobald der Krypto-Kern steht und nochmal vor dem Launch. Der externe Review der Specs läuft spätestens mit dem ersten Audit zusammen und prüft Specs und Code gemeinsam (ADR-0008); ohne ihn kein Produktivbetrieb mit echtem Schutzbedarf.

## Datenhaltung und Löschung

Knappe Aufbewahrung, zugestellte Nachrichten verschwinden, die Tabelle ist nach Monat partitioniert. Verschlüsselte Backups liegen im Objektspeicher des Betreibers, das Geheimnis zu ihrer Entschlüsselung liegt nie beim Betreiber. Solange Secure Value Recovery noch nicht aktiv ist (NF120), leitet es sich aus dem nutzergehaltenen Recovery-Key ab, später aus der SVR-Enclave über eine PIN. Gelöscht wird über Crypto-Shredding, eine Kontolöschung läuft mit Widerrufsfrist und vernichtet danach die zugehörigen Schlüssel.
