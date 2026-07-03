# 0001: Zentraler Kern, vorbereitet auf Föderation

**Status:** akzeptiert

## Kontext

Ein zentraler Betreiber schützt Metadaten am besten, weil alles durch eine Hand läuft. Ein föderiertes Netz ist offener und unabhängiger, gibt dafür über jede Servergrenze Metadaten preis und ist im Betrieb komplexer. Die Frage war, womit man anfängt, ohne sich den anderen Weg zu verbauen.

## Entscheidung

Wir bauen einen zentralen Kern und benennen Identitäten intern als `handle@home-server`, auch bei nur einem Server. Eine S2S-Schnittstelle ist grob umrissen, aber abgeschaltet.

## Konsequenzen

Der Betrieb bleibt am Anfang beherrschbar, der Metadatenschutz ist so stark, wie er bei einem Betreiber sein kann.

Die Reichweite dieser Vorbereitung ist begrenzt: Sie de-riskt die Benennung, mehr nicht. Echte Föderation ist eine andere Vertrauenstopologie und braucht serverübergreifende Key Transparency, ein Server-Discovery-Protokoll und S2S-Authentifizierung. Das ist nicht entworfen und bewusst aufgeschoben, weil Föderation aus ist. Der Eindruck, es wäre später nur ein Schalter, stimmt nicht.
