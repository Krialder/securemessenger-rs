# Werkzeuge

Hilfsskripte rund um das Projekt.

## md2pdf.py

Erzeugt aus einer Markdown-Datei ein PDF im Layout der AzubiOS-Vorlage (Kopfzeile, Seitennummer, Tabellen). Die Markdown-Dateien unter `dokumentation/` sind die Quelle, PDFs werden bei Bedarf erzeugt und nicht im Projekt vorgehalten.

Voraussetzung: `pip install reportlab`

Aufruf aus dem Projekt-Stammverzeichnis:

```
python werkzeuge/md2pdf.py dokumentation/lastenheft.md lastenheft.pdf
python werkzeuge/md2pdf.py dokumentation/pflichtenheft.md pflichtenheft.pdf
```

Nützlich vor allem für die unterschriftsreife Fassung des Lasten- und Pflichtenhefts (Abnahme), wo eine PDF-Momentaufnahme gebraucht wird. Für die laufende Arbeit reicht Markdown.
