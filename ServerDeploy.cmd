@echo off
REM Doppelklick-Einstieg fuer die Server-Auslieferung: oeffnet das Fenster,
REM in dem man die Verbindungsdaten der Ziel-VM (Proxmox) eingibt, einmal
REM den SSH-Schluessel einrichtet und den Stack hochlaedt und startet.
REM -STA fuer WPF, -WindowStyle Hidden versteckt die Start-Konsole.
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0deploy\remote\deploy-gui.ps1"
