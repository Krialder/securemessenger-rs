@echo off
REM Erststart: oeffnet den grafischen Installations-Assistenten.
REM Prueft und installiert die noetigen Werkzeuge, faehrt Docker und die
REM Datenbank hoch und baut das Projekt. -STA ist fuer die WPF-Oberflaeche
REM noetig, -WindowStyle Hidden versteckt die Konsole, damit nur das
REM App-Fenster erscheint. "start" gibt die Eingabeaufforderung sofort frei.
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0scripts\install-gui.ps1"
