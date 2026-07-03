@echo off
REM Doppelklick-Einstieg fuer die Entwicklungsumgebung.
REM Startet das PowerShell-Setup mit gelockerter ExecutionPolicy nur fuer diesen Lauf.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1"
