# 0007: Binary Transparency und reproducible builds

**Status:** akzeptiert

## Kontext

Key Transparency sorgt dafür, dass der Server keinen falschen Schlüssel ausliefert. Es nützt aber nichts, wenn der Server stattdessen einem Zielkonto eine verwanzte App unterschiebt, die die richtigen Schlüssel benutzt und trotzdem mitliest. Geo-spezifische Builds, Side-Channel-Updates und manipuliertes Auslieferungs-JavaScript im Web sind reale Wege dahin. Ein System, das KT für die Schlüssel baut, aber den Code ungeprüft lässt, hat ein Loch an der Wurzel.

## Entscheidung

Die Client-Builds sind reproducible und signiert. Ihre Hashes landen in einem append-only Transparency-Log. Clients, Auditoren oder App-Stores können prüfen, dass die laufende Binary zu einem öffentlich geloggten, reproduzierbaren Build gehört. Für den Web-Client heißt das nachprüfbar ausgeliefertes, versioniertes JavaScript statt frei austauschbarem Code.

## Konsequenzen

Damit schließt sich das Loch, das KT allein offenlässt. Der Preis ist eine deterministische Build-Pipeline, und die ist nicht geschenkt, vor allem mobil und bei WASM, wo Reproduzierbarkeit Arbeit macht. Dazu kommt der Betrieb des Logs und der Verifikationspfad im Client. Den Aufwand nehmen wir in Kauf, weil ohne Binary Transparency die ganze Schlüssel-Verifikation an einem manipulierbaren Client hängt.
