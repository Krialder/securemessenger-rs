<#
  Startet die komplette Vorfuehr-Umgebung des SecureMessengers mit einem
  Befehl: vier Dienste (identity 8080, directory 8081, delivery 8082,
  kt 8083), eigene demo_*-Datenbanken im sm-postgres-Container und zwei
  Web-Clients (Alice http://localhost:3000, Bob http://localhost:3001).

  Warum eigene demo_*-Datenbanken: die Vorfuehrung soll reproduzierbar
  bleiben und darf sich nicht mit den Test-Datenbanken (identity, delivery,
  ...) mischen, in denen cargo test arbeitet. Zuruecksetzen:
  scripts\demo.ps1 -Reset loescht die demo_*-Datenbanken vorher.

  Die Schluessel (KT-Signatur, KT-VRF, Discovery-OPRF, Sealed-Sender-Trust-
  Root) sind DETERMINISTISCHE DEMO-WERTE, damit jeder Neustart zu den in den
  Clients gepinnten Ankern passt. In jeder echten Umgebung kommen sie aus
  einem Secret-Store; genau dafuer sind es Umgebungsvariablen.

  Jeder Dienst laeuft in einem eigenen Fenster (Logs sichtbar, gut fuer die
  Vorfuehrung). scripts\demo-stop.ps1 beendet alles wieder.

  Das Drehbuch der Vorfuehrung steht in DEMO.md im Projekt-Root.
#>
param(
    # Loescht die demo_*-Datenbanken vor dem Start (frische Vorfuehrung).
    [switch]$Reset,
    # Nur Dienste, keine Web-Clients (fuer reine CLI-Vorfuehrungen).
    [switch]$NoWeb,
    # Nur ein Web-Client (Alice, 3000) statt Alice und Bob. Das ist der
    # Alltags-Start: eine Messenger-Instanz statt der Zwei-Personen-Vorfuehrung.
    [switch]$Solo,
    # Oeffnet nach dem Start den Standardbrowser auf den/die Web-Client(s).
    [switch]$OpenBrowser,
    # Startet die Dienst-Fenster versteckt (WindowStyle Hidden). Fuer den
    # GUI-Start, der die Logs nicht als Konsolenfenster zeigen will; die
    # Konsolen-Vorfuehrung laesst sie sichtbar.
    [switch]$Hidden,
    # Ueberspringt cargo build. Der GUI-Start baut selbst (nur wenn noetig
    # und vom Nutzer bestaetigt) und ruft demo.ps1 dann mit -NoBuild, damit
    # nicht doppelt gebaut wird.
    [switch]$NoBuild
)

# Kein globales 'Stop': native Programme (docker, psql) schreiben Hinweise
# auf stderr, und PowerShell 5.1 wuerde daraus einen Abbruch machen. Die
# Fehlerbehandlung laeuft stattdessen ueber explizite Exit-Code-Pruefungen.
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Bad($m)  { Write-Host "    [x]  $m" -ForegroundColor Red }
function Have($name)    { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Werkzeuge aufloesen (wie setup.ps1: PATH-Rueckfaelle fuer frische Sitzungen).
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (-not (Have 'cargo') -and (Test-Path (Join-Path $cargoBin 'cargo.exe'))) { $env:Path = "$cargoBin;$env:Path" }
$dockerCliDir = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
if (-not (Have 'docker') -and (Test-Path (Join-Path $dockerCliDir 'docker.exe'))) { $env:Path = "$dockerCliDir;$env:Path" }
$protocExe = Join-Path $env:LOCALAPPDATA 'protoc\bin\protoc.exe'
if (-not $env:PROTOC -and (Test-Path $protocExe)) { $env:PROTOC = $protocExe }
$trunkExe = Join-Path $cargoBin 'trunk.exe'

foreach ($tool in 'cargo', 'docker') {
    if (-not (Have $tool)) { Write-Bad "$tool fehlt; zuerst scripts\setup.ps1 ausfuehren"; exit 1 }
}
try { docker info *> $null } catch {}
if ($LASTEXITCODE -ne 0) { Write-Bad 'Docker-Daemon nicht erreichbar; zuerst scripts\setup.ps1 ausfuehren'; exit 1 }

# Deterministische Demo-Schluessel (32 Bytes je Wert, Base64). NUR fuer die
# Vorfuehrung; siehe Kopfkommentar.
function DemoKey([byte]$b) { return [Convert]::ToBase64String((,[byte]$b * 32)) }
$ktSigningKey  = DemoKey 1
$ktVrfKey      = DemoKey 2
$oprfKey       = DemoKey 3
$sealedRoot    = DemoKey 4
$internalToken = 'demo-internes-secret'

# 1. Datenbanken
Write-Step 'Demo-Datenbanken (sm-postgres)'
$databases = @('demo_identity', 'demo_directory', 'demo_delivery', 'demo_kt')
docker start sm-postgres *> $null
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    docker exec sm-postgres pg_isready -U postgres *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Bad 'sm-postgres nicht bereit; zuerst scripts\setup.ps1 ausfuehren'; exit 1 }
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
    cargo build -p identity -p directory -p delivery -p kt -p sm-cli
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Bad 'Build fehlgeschlagen'; exit 1 }
    Pop-Location
    Write-Ok 'Build fertig'
}

# 3. Dienste starten, je Dienst ein Fenster mit sichtbaren Logs.
Write-Step 'Starte Dienste (identity 8080, directory 8081, delivery 8082, kt 8083)'
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
    # Sybil-Bremse klein, damit die Registrierung in der Vorfuehrung nicht
    # wartet, die Bremse aber sichtbar aktiv ist (256 Hashes im Schnitt).
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
    # Kurze Epochen, damit Verzeichnis-Aenderungen in der Vorfuehrung
    # binnen Sekunden pruefbar sind.
    KT_EPOCH_SECONDS = '5'
}

# 4. Auf Bereitschaft warten
Write-Step 'Warte auf /ready aller Dienste'
$ports = @(8080, 8081, 8082, 8083)
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
        Write-Bad 'trunk fehlt; zuerst scripts\setup.ps1 ausfuehren (oder -NoWeb nutzen)'
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

# PIDs fuer demo-stop.ps1 festhalten.
$pids -join "`n" | Out-File -FilePath (Join-Path $env:TEMP 'sm-demo-pids.txt') -Encoding ascii

# Optional den Browser oeffnen. Der trunk-Server braucht nach dem Start einen
# Moment, bis er die Seite ausliefert; kurz auf den ersten Port warten, damit
# der Browser nicht auf eine noch tote Adresse trifft.
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
if (-not $NoWeb) { Write-Host "    Web:     $webInfo" }
Write-Host "    CLI:     $root\target\debug\sm.exe (im PATH-freien Aufruf: .\target\debug\sm.exe help)"
Write-Host '    Stoppen: scripts\demo-stop.ps1'
Write-Host '    Drehbuch der Vorfuehrung: DEMO.md im Projekt-Root'
