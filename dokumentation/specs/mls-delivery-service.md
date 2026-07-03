# Spec: MLS Delivery Service

RFC 9420 beschreibt das Protokoll, aber den Delivery Service (DS) lässt es bewusst offen, und genau dort sitzen die praktischen Angriffe. Der DS verteilt die Handshake- und Anwendungsnachrichten einer Gruppe und hält die Liste der Mitgliedsgeräte fürs Fanout. Er wird für Inhalte nicht vertraut, für Reihenfolge und Zustellung notgedrungen schon.

## Was schiefgehen kann

Konkurrierende Commits sind der häufigste Fall. Zwei Mitglieder ändern die Gruppe gleichzeitig, beide Commits zielen auf dieselbe Epoche, und nur einer kann gewinnen. Der DS serialisiert und lehnt den veralteten ab, der Verlierer wendet seinen Commit gegen die neue Epoche neu an. Die Policy (first-wins nach Ankunft, Ablehnung mit klarer Fehlermeldung) gehört festgelegt.

Bei den Ghost Users können Geräteliste des Servers und tatsächliche MLS-Mitgliedschaft auseinanderlaufen. Mitgliedschaftsänderungen gehen über authentifizierte Commits, der DS kann also kein Mitglied fälschen. Trotzdem müssen die Clients die Bindung zwischen MLS-Gruppe und Zustell-Geräteliste selbst prüfen, statt dem Server zu glauben.

Ein Welcome führt ein neues Mitglied ein, und der DS könnte es zurückhalten oder an die falsche Partei schicken. Der Empfänger verifiziert den Gruppenzustand, bevor er beitritt.

External Commits erlauben einen Beitritt über die öffentliche Gruppeninfo. Wer das darf, ist eine Gruppen-Policy und muss gegated sein, sonst hängt sich jeder mit der Info in die Gruppe.

Bei Reihenfolge und Replays bestimmt der DS, was in welcher Folge ankommt. MLS schützt über Epochennummern, aber der Client muss Reorder innerhalb einer Epoche und alte Wiederholungen nach klaren Regeln behandeln.

## Unsere Haltung

Der DS ist nicht vertrauenswürdig für den Inhalt und nur begrenzt für die Reihenfolge. Die Clients verifizieren den MLS-Transkript-Zustand selbst, die Geräteliste wird gegen die kryptografische Mitgliedschaft geprüft, External Commits laufen über eine Gruppen-Policy, und konkurrierende Commits löst der DS nach einer festen Regel auf. Das ist der Rahmen, die genauen Regeln und Garantien sind noch zu schreiben.

## Offen

- Reorder-Garantien, die der DS gibt, und was der Client erzwingt.
- Auflösungsregel für konkurrierende Commits im Detail.
- External-Commit-Policy pro Gruppe.
- Wie die Bindung Geräteliste zu MLS-Mitgliedschaft im Client geprüft wird.
