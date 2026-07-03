# 0008: Krypto-Umsetzung vor dem externen Spec-Review

**Status:** akzeptiert (Entscheidung des Auftraggebers vom 02.07.2026)

## Kontext

Die bisherige Regel stammt aus der Spec-Phase: externer Krypto-Review auf die Specs, bevor der erste Produktivcode der Phasen 1 und höher entsteht (Lastenheft 7.1, Roadmap Phase 0). Der Review ist aber nicht kurzfristig beschaffbar, Budget und Anbieter sind offen (Risiko R9 im Live-Dokument). Als Blocker würde er das Projekt auf unbestimmte Zeit anhalten.

Dem steht gegenüber, dass der Eigenanteil an Kryptografie bewusst dünn ist: Die heiklen Verfahren kommen unverändert aus auditierten Bibliotheken (libsignal, OpenMLS, siehe ADR-0005), der eigene Code ist Orchestrierung darüber. Code vor externem Review ist zudem Branchenpraxis; auch Signal entwickelt fortlaufend und lässt Audits auf den realen Code laufen statt nur auf Papier.

## Entscheidung

Der Krypto-Kern wird gebaut, bevor der externe Spec-Review stattgefunden hat. Die Review-Pflicht bleibt bestehen, wandert aber im Zeitplan: Sie blockiert nicht mehr den Code-Start, sondern den Produktivbetrieb, und wird spätestens mit dem ersten externen Audit (M4) zusammengelegt, das dann Specs und Code gemeinsam prüft.

Interne Absicherung bis dahin: Der Eigenanteil bleibt minimal (Bibliotheks-APIs werden nicht umgebaut), Property-Tests und Wire-Fuzzing laufen von Anfang an, und jede Abweichung von den Specs wird als offene Frage markiert statt still entschieden.

## Konsequenzen

Das Projekt kommt ohne externen Blocker voran, und der spätere Review prüft echten Code statt nur Dokumente, was seinen Aussagewert erhöht. Der Preis ist ein Umbau-Risiko: Verlangt der Review Architekturänderungen, ist bereits gebauter Code betroffen. Das Risiko ist begrenzt, weil die auditierten Bibliotheken die heiklen Teile tragen; es steht als eigenes Risiko im Live-Dokument (Abschnitt 8). Unverändert gilt: Ohne bestandenen Review samt Audit kein Produktivbetrieb mit echtem Schutzbedarf (NF050).
