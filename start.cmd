@echo off
REM Konsolen-Einstieg fuer Entwickler (Alternative zur GUI SecureMessenger.cmd).
REM Reicht Argumente an scripts\sm.ps1 durch:
REM   start.cmd          startet die Umgebung (Dienste plus Web-Client)
REM   start.cmd -Setup   richtet nur ein und aktualisiert (Werkzeuge, DBs, Build)
REM   start.cmd -Stop    beendet eine laufende Umgebung
REM Erststart auf einem frischen Rechner: einmal "start.cmd -Setup", dann
REM "start.cmd" (oder gleich die GUI SecureMessenger.cmd, die beides in einem
REM Fenster erledigt). Weitere Schalter (-Reset, -Solo, -NoWeb) siehe sm.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\sm.ps1" %*
