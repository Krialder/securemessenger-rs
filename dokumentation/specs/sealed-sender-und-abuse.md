# Spec: Sealed Sender und Abuse

Zwei Themen, die zusammengehören. Sealed Sender verbirgt den Absender vor dem Server. Genau das macht Abuse-Abwehr schwerer, weil der Server nicht mehr nach Absender filtern kann. Deshalb in einem Dokument.

## Sealed Sender

Der Server stellt zu, ohne zu lernen, von wem die Nachricht kommt. Er kennt nur den Empfänger. Der Absender legt seine Identität und den Inhalt in eine Hülle, die nur der Empfänger öffnet. Der Empfänger lernt aus der Hülle, wer geschrieben hat, der Server nicht.

## Zugang über anonyme Credentials

Wenn jeder anonym an jeden senden könnte, wäre das ein Spam-Traumland. Die ältere Signal-Lösung leitet ein Zugangstoken aus dem Profil-Schlüssel des Empfängers ab. Das reicht aber nicht sauber für Multi-Device unter einem Profil, und genau das ist der wunde Punkt. Deshalb gehen wir auf anonyme Credentials in der zkgroup-Linie: Der Server stellt einem Konto ein Credential aus, und beim Senden weist der Client per Zero-Knowledge-Beweis nach, dass er ein gültiges, berechtigtes Konto ist, ohne zu verraten, welches. Der Server verifiziert den Beweis und stellt zu.

Das ist der Punkt, an dem die naheliegende Vokabel (Privacy Pass) nicht ganz passt: Privacy Pass ist gut für rate-limitierte, anonyme Tokens, aber die Konto-Gültigkeit über mehrere Geräte hinweg ist das, wofür zkgroup gebaut ist.

## Sybil-Widerstand bei der Registrierung

Ohne Telefonnummer fällt die natürliche Bremse gegen Massenkonten weg. Entschieden ist eine Kombination aus Proof-of-Work bei der Registrierung und Privacy Pass für rate-limitierte, anonyme Tokens auf teuren Aktionen danach. Das ist eine Bremse, kein Riegel. PoW trifft schwache Geräte härter als ein Botnetz, die Asymmetrie ist begrenzt, und die Privacy-Pass-Ausgabe braucht selbst ein Tor. Deshalb wirkt der Baustein nur zusammen mit Franking und den empfängerseitigen Kontrollen.

## Message Franking

Sealed Sender macht Meldungen schwer: Wenn der Server den Absender nicht kennt, wie meldet ein Empfänger eine missbräuchliche Nachricht beweisbar, ohne dass sich Meldungen fälschen lassen? Antwort ist kryptografisches Franking (Grubbs, Lu, Ristenpart). Der Absender hängt ein Franking-Tag an, der Server committet sich beim Transport darauf (er bewahrt das Commitment im `franking_log` auf), ohne den Inhalt zu sehen. Meldet der Empfänger, deckt er den Tag auf, und der Server verifiziert, dass genau diese Nachricht so gesendet wurde. Niemand kann eine Meldung fälschen, und die E2E bleibt unberührt.

## Empfängerseitige Kontrollen

Blockieren, "wer darf mir schreiben", eine Anfrage-Inbox für Erstkontakte, Rate-Limits pro Empfänger. Die letzte und wichtigste Verteidigungslinie, weil sie beim Nutzer liegt und keine Server-Einsicht braucht.

## Lieferbestätigungen

Quittungen (zugestellt, gelesen) sind unter Sealed Sender ein eigenes Problem: Der Server kennt den Absender nicht, an wen also zurückmelden? Die Quittung geht als eigene Sealed-Sender-Nachricht zurück an den ursprünglichen Absender, dessen Identität der Empfänger aus der Hülle gelernt hat. Sie läuft über denselben Kanal rückwärts. Wie aufdringlich Lesebestätigungen per Default sind, ist offen.

## Disappearing Messages, Edits, Reactions

Diese Features kommen in Phase 2/3 und brechen das Modell, wenn man sie nicht früh denkt.

- Disappearing Messages haben eine eigene Krypto-Story: absenderseitige Schlüssel-Vernichtung gegen empfängerseitige Garbage Collection, beides nicht trivial mit dem Ratchet.
- Edits und Reactions kollidieren mit Franking. Wird eine Nachricht editiert, stellt sich die Frage, worauf sich das Franking-Commitment bezieht, auf das Original oder die Edit-Kette. Das muss geklärt sein, bevor Franking steht, sonst lassen sich editierte Nachrichten nicht sauber melden.

## Vorbilder

Signal hat Sealed Sender 2018 eingeführt und mehrfach über die Abuse-Folgen geschrieben. Anonyme Credentials kommen aus der zkgroup-Arbeit, Franking aus der Forschung zu Message Franking, Privacy Pass ist der Standard für anonyme Tokens.

## Offen

- Genaue zkgroup-Konstruktion und das Multi-Device-Zusammenspiel.
- PoW-Härte, Privacy-Pass-Ausgabe.
- Franking-Verhalten bei Edits.
- Anfrage-Inbox für Erstkontakte ja oder nein.
