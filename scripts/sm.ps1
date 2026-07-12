<#
  SecureMessenger: ein Konsolen-Einstieg fuer alles.

  Loest die frueher getrennten Skripte setup.ps1 (einrichten), demo.ps1
  (starten) und demo-stop.ps1 (stoppen) ab. Die eigentliche Pruef- und
  Reparatur-Logik der Einrichtung liegt weiterhin an einer Stelle
  (lib-checks.ps1, dieselbe, die auch die grafische Oberflaeche nutzt), damit
  Konsole und GUI nicht auseinanderdriften.

  Aufrufe:
    sm.ps1              startet die Umgebung (vier Dienste plus Web-Clients)
    sm.ps1 -Setup       richtet nur ein und aktualisiert (Werkzeuge, Docker,
                        Datenbanken, Build), ohne zu starten
    sm.ps1 -Stop        beendet eine laufende Umgebung
    sm.ps1 -Reset       loescht die demo_*-Datenbanken vor dem Start
    sm.ps1 -Solo        nur ein Web-Client (Alice, 3000) statt Alice und Bob
    sm.ps1 -NoWeb       nur die Dienste, keine Web-Clients
    sm.ps1 -NoBuild     ueberspringt cargo build (die GUI baut selbst)
    sm.ps1 -Hidden      Dienst-Fenster versteckt (fuer den GUI-Start)
    sm.ps1 -OpenBrowser oeffnet nach dem Start den Standardbrowser
#>
param(
    [switch]$Setup,
    [switch]$Stop,
    [switch]$Reset,
    [switch]$Solo,
    [switch]$NoWeb,
    [switch]$NoBuild,
    [switch]$Hidden,
    [switch]$OpenBrowser
)

# Kein globales 'Stop': native Programme (docker, psql) schreiben Hinweise
# auf stderr, und PowerShell 5.1 wuerde daraus einen Abbruch machen. Die
# Fehlerbehandlung laeuft ueber explizite Exit-Code-Pruefungen.
$ErrorActionPreference = 'Continue'
$scriptsDir = $PSScriptRoot
$root = Split-Path $scriptsDir -Parent

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "    [x]  $m" -ForegroundColor Red }
function Have($name)    { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# ---------------------------------------------------------------------------
# Stoppen: die frueher eigene demo-stop.ps1. Erst die festgehaltenen
# Prozess-IDs, dann ein Aufraeumlauf ueber die Fenstertitel (sm-demo-*) und
# uebrig gebliebene Dienst-/trunk-Prozesse aus diesem Projektbaum.
# ---------------------------------------------------------------------------
if ($Stop) {
    $pidFile = Join-Path $env:TEMP 'sm-demo-pids.txt'
    $stopped = 0
    if (Test-Path $pidFile) {
        foreach ($procId in Get-Content $pidFile) {
            try { Stop-Process -Id ([int]$procId) -Force -Confirm:$false -ErrorAction Stop; $stopped++ } catch {}
        }
        Remove-Item $pidFile -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($p in Get-Process powershell -ErrorAction SilentlyContinue) {
        if ($p.MainWindowTitle -like 'sm-demo-*') {
            try { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop; $stopped++ } catch {}
        }
    }
    foreach ($name in 'identity', 'directory', 'delivery', 'kt', 'integrations', 'trunk') {
        foreach ($p in Get-Process $name -ErrorAction SilentlyContinue) {
            $exePath = try { $p.Path } catch { '' }
            if ($exePath -like "$root*" -or $name -eq 'trunk') {
                try { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop; $stopped++ } catch {}
            }
        }
    }
    Write-Host "Umgebung gestoppt ($stopped Prozess(e) beendet)."
    exit 0
}

# ---------------------------------------------------------------------------
# Einrichten: die frueher eigene setup.ps1. Delegiert an die geteilte
# Pruef-Bibliothek (lib-checks.ps1), damit Konsole und GUI dieselbe Logik
# nutzen: je Komponente pruefen und bei Bedarf reparieren/installieren.
# ---------------------------------------------------------------------------
if ($Setup) {
    . (Join-Path $scriptsDir 'lib-checks.ps1')
    Initialize-SmEnv
    Write-Step 'Umgebung pruefen und einrichten'
    $log = { param($t) Write-Host "        $t" -ForegroundColor DarkGray }
    $allOk = $true
    foreach ($c in (Get-SmComponents)) {
        $st = Test-SmComponent $c
        if ($st.State -eq 'ok') { Write-Ok "$($c.Name): $($st.Detail)"; continue }
        Write-Host "    ... $($c.Name): $($st.Detail), richte ein" -ForegroundColor Yellow
        try { [void](& $c.Fix $log) } catch { & $log "Fehler: $_" }
        $after = Test-SmComponent $c
        if ($after.State -eq 'ok') { Write-Ok "$($c.Name): $($after.Detail)" }
        else {
            if (-not $c.Optional) { $allOk = $false }
            Write-Bad "$($c.Name): offen ($($after.Detail))"
        }
    }
    if ($allOk) {
        Write-Host "`nEinrichtung abgeschlossen. Starten mit: scripts\sm.ps1 (oder Doppelklick auf SecureMessenger.cmd)." -ForegroundColor White
    } else {
        Write-Host "`nEinige Punkte brauchen noch Aufmerksamkeit (siehe oben)." -ForegroundColor Yellow
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Starten: die frueher eigene demo.ps1. Fuenf Dienste (identity 8080,
# directory 8081, delivery 8082, kt 8083, integrations 8085) mit eigenen
# demo_*-Datenbanken und deterministischen Demo-Schluesseln, dazu die
# Web-Clients ueber trunk. integrations ist die Mandanten-API fuer
# Fremdprojekte (OAuth2, notify, presence); der Chat-Demo nutzt sie nicht,
# aber sie gehoert zum Fundament fuer die anderen Projekte und laeuft mit.
# ---------------------------------------------------------------------------

# Werkzeuge aufloesen (PATH-Rueckfaelle fuer frische Sitzungen).
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (-not (Have 'cargo') -and (Test-Path (Join-Path $cargoBin 'cargo.exe'))) { $env:Path = "$cargoBin;$env:Path" }
$dockerCliDir = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
if (-not (Have 'docker') -and (Test-Path (Join-Path $dockerCliDir 'docker.exe'))) { $env:Path = "$dockerCliDir;$env:Path" }
$protocExe = Join-Path $env:LOCALAPPDATA 'protoc\bin\protoc.exe'
if (-not $env:PROTOC -and (Test-Path $protocExe)) { $env:PROTOC = $protocExe }
$trunkExe = Join-Path $cargoBin 'trunk.exe'

foreach ($tool in 'cargo', 'docker') {
    if (-not (Have $tool)) { Write-Bad "$tool fehlt; zuerst scripts\sm.ps1 -Setup ausfuehren"; exit 1 }
}
try { docker info *> $null } catch {}
if ($LASTEXITCODE -ne 0) { Write-Bad 'Docker-Daemon nicht erreichbar; zuerst scripts\sm.ps1 -Setup ausfuehren'; exit 1 }

# Deterministische Demo-Schluessel (32 Bytes je Wert, Base64). NUR fuer die
# Vorfuehrung; in jeder echten Umgebung kommen sie aus einem Secret-Store.
function DemoKey([byte]$b) { return [Convert]::ToBase64String((, [byte]$b * 32)) }
$ktSigningKey  = DemoKey 1
$ktVrfKey      = DemoKey 2
$oprfKey       = DemoKey 3
$sealedRoot    = DemoKey 4
$internalToken = 'demo-internes-secret'

# 1. Datenbanken
Write-Step 'Demo-Datenbanken (sm-postgres)'
$databases = @('demo_identity', 'demo_directory', 'demo_delivery', 'demo_kt', 'demo_integrations')
docker start sm-postgres *> $null
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    docker exec sm-postgres pg_isready -U postgres *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Bad 'sm-postgres nicht bereit; zuerst scripts\sm.ps1 -Setup ausfuehren'; exit 1 }
foreach ($db in $databases) {
    if ($Reset) {
        docker exec sm-postgres psql -U postgres -c "DROP DATABASE IF EXISTS $db" *> $null
    }
    $exists = docker exec sm-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$db'" 2>$null
    if ("$exists".Trim() -ne '1') {
        docker exec sm-postgres psql -U postgres -c "CREATE DATABASE $db" *> $null
        Write-Ok "Datenbank $db angelegt"
    } else {
        Write-Ok "Datenbank $db vorhanden"
    }
}

# 2. Binaries bauen (ein Lauf; die Fenster starten danach sofort). -NoBuild
# ueberspringt das, wenn der Aufrufer (GUI-Start) schon gebaut hat.
if ($NoBuild) {
    Write-Ok 'Build uebersprungen (-NoBuild)'
} else {
    Write-Step 'Baue Dienste und CLI (cargo build, erster Lauf dauert)'
    Push-Location $root
    cargo build -p identity -p directory -p delivery -p kt -p integrations -p sm-cli
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Bad 'Build fehlgeschlagen'; exit 1 }
    Pop-Location
    Write-Ok 'Build fertig'
}

# 3. Dienste starten, je Dienst ein Fenster mit sichtbaren Logs.
Write-Step 'Starte Dienste (identity 8080, directory 8081, delivery 8082, kt 8083, integrations 8085)'
$pids = @()
$windowStyle = if ($Hidden) { 'Hidden' } else { 'Normal' }
function Start-Service([string]$name, [string]$bind, [hashtable]$extraEnv) {
    $exe = Join-Path $root "target\debug\$name.exe"
    $envLines = "`$env:BIND_ADDR='$bind'; `$env:INTERNAL_TOKEN='$script:internalToken'; "
    foreach ($k in $extraEnv.Keys) { $envLines += "`$env:$k='$($extraEnv[$k])'; " }
    $cmd = "`$host.UI.RawUI.WindowTitle='sm-demo-$name'; $envLines & '$exe'"
    $p = Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd -PassThru -WindowStyle $script:windowStyle
    $script:pids += $p.Id
    Write-Ok "$name gestartet (PID $($p.Id), $bind)"
}
$pg = 'postgres://postgres:dev@localhost:5432'
Start-Service 'identity' '127.0.0.1:8080' @{
    DATABASE_URL             = "$pg/demo_identity"
    KT_URL                   = 'http://127.0.0.1:8083'
    CDS_OPRF_KEY             = $oprfKey
    SEALED_SENDER_TRUST_ROOT = $sealedRoot
    POW_DIFFICULTY           = '8'
}
Start-Service 'directory' '127.0.0.1:8081' @{
    DATABASE_URL = "$pg/demo_directory"
    IDENTITY_URL = 'http://127.0.0.1:8080'
}
Start-Service 'delivery' '127.0.0.1:8082' @{
    DATABASE_URL = "$pg/demo_delivery"
    IDENTITY_URL = 'http://127.0.0.1:8080'
}
Start-Service 'kt' '127.0.0.1:8083' @{
    DATABASE_URL     = "$pg/demo_kt"
    KT_SIGNING_KEY   = $ktSigningKey
    KT_VRF_KEY       = $ktVrfKey
    KT_EPOCH_SECONDS = '5'
}
# Mandanten-API fuer Fremdprojekte: braucht identity (Nutzer aufloesen) und
# delivery (Events, Praesenz) sowie dasselbe INTERNAL_TOKEN, das Start-Service
# ohnehin setzt (schaltet die interne Mandanten-Anlage-Route frei).
Start-Service 'integrations' '127.0.0.1:8085' @{
    DATABASE_URL = "$pg/demo_integrations"
    IDENTITY_URL = 'http://127.0.0.1:8080'
    DELIVERY_URL = 'http://127.0.0.1:8082'
}

# 4. Auf Bereitschaft warten
Write-Step 'Warte auf /ready aller Dienste'
$ports = @(8080, 8081, 8082, 8083, 8085)
foreach ($port in $ports) {
    $ok = $false
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/ready" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $ok = $true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if ($ok) { Write-Ok "Port $port bereit" } else { Write-Bad "Port $port antwortet nicht; Fenster 'sm-demo-*' pruefen" }
}

# 5. Web-Clients, je ein trunk-Dev-Server mit /api-Proxys. -Solo startet nur
# Alice (Alltags-Start), sonst Alice und Bob (Zwei-Personen-Vorfuehrung).
$startedPorts = @()
if (-not $NoWeb) {
    $clients = if ($Solo) { @(@{ name = 'alice'; port = 3000 }) } else { @(@{ name = 'alice'; port = 3000 }, @{ name = 'bob'; port = 3001 }) }
    Write-Step ("Starte Web-Client(s): " + (($clients | ForEach-Object { "$($_.name) $($_.port)" }) -join ', '))
    if (-not ((Have 'trunk') -or (Test-Path $trunkExe))) {
        Write-Bad 'trunk fehlt; zuerst scripts\sm.ps1 -Setup ausfuehren (oder -NoWeb nutzen)'
    } else {
        $trunk = if (Have 'trunk') { 'trunk' } else { $trunkExe }
        $webDir = Join-Path $root 'clients\web'
        foreach ($entry in $clients) {
            $cmd = "`$host.UI.RawUI.WindowTitle='sm-demo-web-$($entry.name)'; Set-Location '$webDir'; & '$trunk' serve --port $($entry.port)"
            $p = Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd -PassThru -WindowStyle $windowStyle
            $pids += $p.Id
            $startedPorts += $entry.port
            Write-Ok "Web-Client $($entry.name) auf http://localhost:$($entry.port) (PID $($p.Id))"
        }
    }
}

# PIDs fuer 'sm.ps1 -Stop' festhalten.
$pids -join "`n" | Out-File -FilePath (Join-Path $env:TEMP 'sm-demo-pids.txt') -Encoding ascii

# Optional den Browser oeffnen. Der trunk-Server braucht nach dem Start einen
# Moment, bis er die Seite ausliefert; kurz auf den ersten Port warten.
if ($OpenBrowser -and $startedPorts.Count -gt 0) {
    $first = $startedPorts[0]
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$first/" -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { break }
        } catch { Start-Sleep -Seconds 1 }
    }
    foreach ($port in $startedPorts) { Start-Process "http://localhost:$port" | Out-Null }
}

Write-Host "`nUmgebung laeuft." -ForegroundColor White
$webInfo = if ($Solo) { 'http://localhost:3000' } else { 'http://localhost:3000 (Alice)  http://localhost:3001 (Bob)' }
if (-not $NoWeb) {
    Write-Host "    Web:     $webInfo"
    # Vorschlags-Konten fuer die Vorfuehrung: die Konten legt der Vorfuehrende
    # beim ersten Mal selbst an (Passwort mindestens 12 Zeichen), danach nur
    # noch anmelden. Diese Werte passen zu den Beispielen in DEMO.md.
    Write-Host "    Demo-Konten (beim ersten Mal 'Konto anlegen', danach anmelden):"
    Write-Host "      Alice (3000): Handle 'alice'  Passwort 'alices-langes-passwort'"
    if (-not $Solo) {
        Write-Host "      Bob   (3001): Handle 'bob'    Passwort 'bobs-langes-passwort'"
    }
}
Write-Host "    CLI:     $root\target\debug\sm.exe (im PATH-freien Aufruf: .\target\debug\sm.exe help)"
Write-Host '    Stoppen: scripts\sm.ps1 -Stop'
Write-Host '    Drehbuch der Vorfuehrung: DEMO.md im Projekt-Root'
