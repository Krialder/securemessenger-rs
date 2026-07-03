# Spec: Key Transparency

Das Subsystem, an dem ein E2E-System steht oder fällt. Verschlüsseln ist gelöst. Die offene Frage: Woher weiß mein Client, dass der Schlüssel, den der Server mir für einen Kontakt gibt, wirklich dem Kontakt gehört und nicht dem Betreiber, der mitlesen will?

Ohne Antwort darauf ist E2E gegen einen aktiv bösartigen Server wertlos. Er liefert seinen eigenen Schlüssel, du verschlüsselst an ihn, er liest und reicht weiter. Key Transparency macht den Tausch entdeckbar.

## Die Idee

Der Server führt alle Schlüssel in einem öffentlich nachprüfbaren Verzeichnis. Technisch ist das eine verifiable map (Label zu Wert) auf einem Merkle-Baum, gestützt auf einen append-only Log der signierten Wurzeln. Die Map selbst ist veränderlich, ein Schlüsselwechsel ändert einen Eintrag. Der Log darüber wird nur angehängt. Das Modell folgt CONIKS und den späteren Systemen (Google KT, Metas KT für WhatsApp 2023 und Messenger 2025). Wir setzen ein bekanntes Design um.

## VRF gegen das Durchzählen

Ein Merkle-Baum direkt auf dem Handle hätte ein Datenschutzproblem: Jeder könnte den Baum ablaufen und die Nutzerliste herausziehen, bei selbstgewählten Usernamen besonders leicht. Deshalb läuft das Label über eine VRF: `label = VRF(handle)`. Die VRF bildet den Handle auf einen undurchsichtigen Index ab und liefert einen Beweis für die Korrektheit. Der Server beweist Inklusion, ohne zu verraten, welche Handles existieren.

## Epochen und signierte Wurzeln

Das Verzeichnis arbeitet in Epochen, Zielbereich 1 bis 6 Stunden je Epoche (kürzer macht Manipulation schneller sichtbar, kostet aber mehr Last). Am Epochenende veröffentlicht der Server eine signierte Wurzel (STH). Zwei Eigenschaften müssen beweisbar sein:

1. Append-only, richtig verstanden. Nicht die Map ist unveränderlich, sondern ihre Historie: die Folge der Wurzeln und, pro Label, die Versionskette der Werte. Der Server kann Vergangenes nicht umschreiben, nur neue Versionen anhängen.
2. Konsistenz. Zwischen zwei Wurzeln gibt es einen Beweis, dass die neue aus der alten hervorgeht.

## Selbstprüfung durch den Client

Jeder Client überwacht seine eigene Schlüsselhistorie. Er weiß, was er veröffentlicht hat, und prüft, dass im Verzeichnis genau das steht. Schiebt der Server einen Rogue-Key (oder ein Rogue-Gerät, siehe [geraete-identitaet.md](geraete-identitaet.md)) ein, taucht das im eigenen Eintrag auf, und der Client schlägt Alarm. Das ist der primäre Hebel, weil das Opfer selbst mitliest. Er läuft ab Phase 1.

## Auditoren und Gossip

Bleibt der Split-View: Der Server zeigt dir und deinem Kontakt verschiedene Verzeichnisse. Dagegen helfen unabhängige Auditoren, die die Wurzelfolge auf Append-only und Konsistenz prüfen, plus Gossip, also dass Clients und Auditoren ihre Wurzeln vergleichen. Zwei widersprüchliche Wurzeln zur selben Epoche überführen den Betreiber. Dieser Teil kommt in Phase 3, und wer die Auditoren betreibt, steht noch offen.

## Was der Server hält

- Den Merkle-Baum der verifiable map.
- Die Folge der signierten Wurzeln pro Epoche.
- Den VRF-Schlüssel (privat) und den Signaturschlüssel der Wurzeln.
- Pro Konto die aktuelle Geräte- und Schlüsselmenge, auf die das Commitment zeigt.

Die genaue Merkle-Bauart (Sparse Merkle Tree, Commitment-Schema, Beschneidung langer Historien) zurren wir gegen eine konkrete KT-Bibliothek fest, bevor sich das Datenmodell zementiert.

## Was es schlägt, was nicht

Geschlagen: der stille Schlüssel- oder Geräte-Tausch durch den Server, offen über die Selbstprüfung und versteckt über Gossip plus Auditoren. Nicht geschlagen: Ein Erstkontakt bleibt ein Vertrauen-beim-ersten-Sehen, bis genug Epochen vergangen sind. Und KT sagt nur, dass ein Schlüssel im Verzeichnis steht, nicht, dass die Person dahinter die richtige ist, dafür gibt es die Safety Number.

## Offen

- Wer betreibt den Auditor (Phase 3).
- Gossip-Transport, in-band oder out-of-band.
- Genaue Epochenlänge.
- Bootstrapping des Wurzel-Signaturschlüssels für frische Clients.
- Commitment-Schema für mehrere Geräte pro Konto.
