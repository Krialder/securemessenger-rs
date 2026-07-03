# 0004: Native Clients plus Web, nativ von Anfang an parallel

**Status:** akzeptiert

## Kontext

Ein Web-Client ist schnell ausgerollt und überall erreichbar, hat im Browser aber harte Grenzen: kein OS-Keystore, kein signiertes JavaScript, XSS und Extensions als Einfallstor. Die Reihenfolge "erst Web, native später" hat eine Falle, der schwächste Client wird zum Default und bleibt es.

## Entscheidung

Web, iOS, Android und Desktop, mindestens ein nativer Client von Anfang an parallel zum Web-Client. Die nativen binden private Schlüssel über den Plattform-Keystore an die Hardware.

## Konsequenzen

Das beste Schutzniveau steht dort, wo es geht, und der Browser bleibt als niedrigschwelliger Zugang. Klar benannt wird dabei, dass der Web-Client kryptografisch das schwächste Glied ist, das steht in der [sicherheit.md](../sicherheit.md) als eigene Zeile. Signal Desktop ist aus diesem Grund Electron, WhatsApp Web ein Companion. Wir bieten Web mit offener Einordnung an, ohne es mit nativ gleichzusetzen.
