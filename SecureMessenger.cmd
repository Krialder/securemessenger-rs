@echo off
REM Alltags-Start: oeffnet die Start-Anwendung. Sie prueft, ob die Umgebung
REM stimmt und aktuell ist, bietet Aktualisierungen an oder startet direkt
REM Dienste und Web-Client. -STA fuer die WPF-Oberflaeche, -WindowStyle
REM Hidden versteckt die Konsole; "start" gibt die Eingabeaufforderung frei.
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0scripts\start-gui.ps1"
