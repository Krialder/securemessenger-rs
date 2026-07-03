# Spec: Contact Discovery

Ein Handle zu einem Konto auflösen, ohne dass der Server lernt, wer wen sucht, und ohne dass jemand die Nutzerliste durchzählen kann. Klingt simpel, ist die Stelle, an der viele Messenger Metadaten verlieren.

## Warum das hier einfacher ist als bei Signal

Signals CDSi löst ein anderes Problem: Telefonnummern aus dem Adressbuch gegen die Nutzerbasis abgleichen, ohne das ganze Adressbuch preiszugeben. Das braucht SGX-Enclaves und ist schwer. Wir haben keine Telefonnummern und kein Adressbuch-Matching. Bei uns sucht jemand gezielt nach einem Handle, das er schon kennt. Die Aufgabe ist also "Handle zu Konto", nicht "tausend Nummern auf einmal". Das vereinfacht die Sache deutlich.

## Der Ansatz: OPRF

Der Server soll den gesuchten Handle nicht im Klartext sehen und keinen Suchverlauf aufbauen. Dafür läuft die Auflösung über eine Oblivious Pseudorandom Function: Der Client blendet den Handle, der Server wertet die OPRF darüber aus, ohne den Klartext zu sehen, der Client entblendet das Ergebnis und schlägt damit das Konto nach. Der Server lernt nicht, welcher Handle gesucht wurde.

Gegen Enumeration (jemand rät Handles in Masse) hilft striktes Rate-Limiting pro Abrufer, plus die Tatsache, dass das Ergebnis ohne Kenntnis des Handles nichts wert ist.

## Anschluss an Key Transparency

Hat die Suche ein Konto aufgelöst, holt der Client dessen Schlüssel und prüft sie gegen das KT-Log, bevor eine Sitzung startet. Discovery liefert also nur den Einstieg, die Echtheit kommt von Key Transparency.

## Offen

- Genaue OPRF-Konstruktion und Schlüsselverwaltung auf Serverseite.
- Rate-Limit-Schwellen gegen Enumeration.
- Ob auffindbare Handles ein Opt-in brauchen.
