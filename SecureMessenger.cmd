@echo off
REM Doppelklick-Einstieg: oeffnet die eine SecureMessenger-Oberflaeche. Sie
REM prueft die Umgebung, richtet Fehlendes per Haken-Auswahl ein (auch die
REM Erstinstallation) und startet dann Dienste und Web-Client. -STA fuer die
REM WPF-Oberflaeche, -WindowStyle Hidden versteckt die Konsole; "start" gibt
REM die Eingabeaufforderung sofort frei.
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0scripts\sm-gui.ps1"
