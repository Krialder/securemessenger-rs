# 0006: Key-Transparency-Modell

**Status:** akzeptiert

## Kontext

E2E gegen einen aktiv bösartigen Server hält nur, wenn der Client prüfen kann, dass der ausgelieferte Schlüssel echt ist. Ein simples, nur-anhängbares Log wäre bloß ein Audit-Trail und kein Schutz, es verhindert nicht, dass der Server einem Opfer einen anderen Schlüssel zeigt als dem Rest.

## Entscheidung

Wir setzen ein vollwertiges Key-Transparency-System um, in der Linie von CONIKS und den späteren Systemen (Google KT, Metas KT). Bausteine: eine verifiable Merkle-Map über einem append-only Log, eine VRF über das Handle gegen das Durchzählen, signierte Wurzeln pro Epoche mit Konsistenzbeweisen, Selbstprüfung der eigenen Historie im Client, und Auditoren plus Gossip gegen den Split-View. Ausgearbeitet in [specs/key-transparency.md](../specs/key-transparency.md).

## Konsequenzen

Ein stiller Schlüssel- oder Geräte-Tausch fällt auf, offen über die Selbstprüfung (ab Phase 1) und versteckt über Gossip plus Auditoren (ab Phase 3). Die Safety Number bleibt als manueller Zusatz.

Das ist ein eigenes Subsystem mit eigenem Datenmodell und eigener Betriebslast. Die offene Governance-Frage ist, wer den Auditor betreibt. Ohne unabhängige Instanz ist der Split-View-Schutz schwächer, die Frage steht in [offene-fragen.md](../offene-fragen.md).
