<#
  Beendet die Vorfuehr-Umgebung aus scripts\demo.ps1.

  Zwei Wege, bewusst redundant: erst die in %TEMP%\sm-demo-pids.txt
  festgehaltenen Prozess-IDs, danach ein Aufraeumlauf ueber die
  Fenstertitel (sm-demo-*), falls die PID-Datei fehlt oder Prozesse
  von Hand nachgestartet wurden. Die demo_*-Datenbanken bleiben stehen;
  eine frische Vorfuehrung erzwingt scripts\demo.ps1 -Reset.
#>

$root = Split-Path $PSScriptRoot -Parent
$pidFile = Join-Path $env:TEMP 'sm-demo-pids.txt'
$stopped = 0

if (Test-Path $pidFile) {
    foreach ($procId in Get-Content $pidFile) {
        try {
            Stop-Process -Id ([int]$procId) -Force -Confirm:$false -ErrorAction Stop
            $stopped++
        } catch {}
    }
    Remove-Item $pidFile -Force -Confirm:$false -ErrorAction SilentlyContinue
}

# Fenster-Aufraeumlauf: die Start-Fenster heissen sm-demo-<dienst>. Deren
# Kindprozesse (die eigentlichen Dienst-Binaries, trunk) haengen an der
# jeweiligen powershell und fallen mit ihr.
foreach ($p in Get-Process powershell -ErrorAction SilentlyContinue) {
    if ($p.MainWindowTitle -like 'sm-demo-*') {
        try { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop; $stopped++ } catch {}
    }
}
# Uebrig gebliebene Dienst- und trunk-Prozesse, deren Elternfenster schon
# weg ist, am Namen einsammeln.
foreach ($name in 'identity', 'directory', 'delivery', 'kt', 'trunk') {
    foreach ($p in Get-Process $name -ErrorAction SilentlyContinue) {
        $exePath = try { $p.Path } catch { '' }
        # Nur Prozesse aus diesem Projektbaum beenden, keine fremden.
        if ($exePath -like "$root*" -or $name -eq 'trunk') {
            try { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop; $stopped++ } catch {}
        }
    }
}

Write-Host "Vorfuehr-Umgebung gestoppt ($stopped Prozess(e) beendet)."
