<#
  SecureMessenger: ein Konsolen-Einstieg fuer alles.

  Startet den Verbund als Container-Stack (docker compose): gesundheits-
  geprueft, selbstheilend, im Produktionsmodus (SM_ENV=production). Die
  Geheimnisse liegen in einer lokalen .env (nicht eingecheckt); fehlt sie,
  erzeugt dieses Skript sie mit starken Zufallswerten. Die Pruef- und
  Reparatur-Logik der Einrichtung liegt in lib-checks.ps1 (dieselbe, die
  auch die grafische Oberflaeche nutzt).

  Aufrufe:
    sm.ps1              startet den Stack (Dienste, PostgreSQL, MinIO)
    sm.ps1 -Web         zusaetzlich der Web-Client (http://localhost:3000)
    sm.ps1 -Sso         zusaetzlich Keycloak (SSO-Provider, Port 8090)
    sm.ps1 -Calls       zusaetzlich coturn fuer 1:1-Anrufe (F2); erzeugt bei
                        Bedarf das TURN-Geheimnis in der .env
    sm.ps1 -Stop        faehrt den Stack herunter (Daten bleiben)
    sm.ps1 -Reset       loescht vorher die Daten-Volumes (down -v)
    sm.ps1 -Setup       richtet nur ein und aktualisiert (Werkzeuge, Docker,
                        Test-Datenbanken, Build), ohne zu starten
    sm.ps1 -OpenBrowser oeffnet nach dem Start den Browser (mit -Web)

  Kubernetes lokal (die echten Manifeste auf kind): deploy\kind\up.ps1
#>
param(
    [switch]$Setup,
    [switch]$Stop,
    [switch]$Reset,
    [switch]$Sso,
    [switch]$Web,
    [switch]$Calls,
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
# Einrichten: delegiert an die geteilte Pruef-Bibliothek (lib-checks.ps1),
# damit Konsole und GUI dieselbe Logik nutzen: je Komponente pruefen und bei
# Bedarf reparieren/installieren.
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
    # Model Runner auch dann abschalten, wenn der Daemon schon lief (dann rief
    # die Komponenten-Schleife den daemon-Fix nie auf): die Ursache der
    # wiederkehrenden Docker-Abstuerze bleibt so dauerhaft aus.
    if (Test-SmDockerDaemon) { Disable-SmModelRunner }
    if ($allOk) {
        Write-Host "`nEinrichtung abgeschlossen. Starten mit: scripts\sm.ps1 (oder Doppelklick auf SecureMessenger.cmd)." -ForegroundColor White
    } else {
        Write-Host "`nEinige Punkte brauchen noch Aufmerksamkeit (siehe oben)." -ForegroundColor Yellow
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Ab hier: der Container-Stack. Docker sicherstellen (Selbstheilung wie in
# -Setup: abgestuerzten Daemon wiederbeleben statt abbrechen), dann compose.
# ---------------------------------------------------------------------------
$dockerCliDir = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
if (-not (Have 'docker') -and (Test-Path (Join-Path $dockerCliDir 'docker.exe'))) { $env:Path = "$dockerCliDir;$env:Path" }
if (-not (Have 'docker')) { Write-Bad 'docker fehlt; zuerst scripts\sm.ps1 -Setup ausfuehren'; exit 1 }

. (Join-Path $scriptsDir 'lib-checks.ps1')
$healLog = { param($t) Write-Host "        $t" -ForegroundColor DarkGray }
if (-not (Test-SmDockerDaemon)) {
    Write-Step 'Docker-Daemon nicht erreichbar, belebe ihn wieder'
    $daemonComp = Get-SmComponents | Where-Object { $_.Key -eq 'daemon' }
    [void](& $daemonComp.Fix $healLog)
}
if (-not (Test-SmDockerDaemon)) {
    Write-Bad 'Docker-Daemon liess sich nicht starten; Docker Desktop pruefen (docker desktop status).'
    exit 1
}
# Ursache der wiederkehrenden Abstuerze klein halten: Model Runner aus.
Disable-SmModelRunner

Push-Location $root

if ($Stop) {
    Write-Step 'Stack herunterfahren (docker compose down)'
    docker compose down
    Pop-Location
    Write-Host 'Stack gestoppt (Daten bleiben; -Reset beim naechsten Start loescht sie).'
    exit 0
}

# Geheimnisse: eine lokale .env neben docker-compose.yml, beim ersten Start
# mit starken Zufallswerten erzeugt (Formate wie deploy/k8s/SECRETS.md:
# Seeds 32 Bytes Base64, Passwoerter/Tokens 32 Bytes Hex). Vorhandene .env
# bleibt unangetastet, damit Schluessel (v. a. die KT-Schluessel, die das
# Transparenz-Log signieren) Neustarts ueberleben.
$envFile = Join-Path $root '.env'
# Zufalls-Helfer VOR der .env-Pruefung, damit sie auch beim Nachziehen des
# TURN-Geheimnisses (vorhandene .env, -Calls) zur Verfuegung stehen.
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
function New-RandBytes { $b = New-Object byte[] 32; $rng.GetBytes($b); return $b }
function New-Seed { return [Convert]::ToBase64String((New-RandBytes)) }
function New-Hex  { return -join ((New-RandBytes) | ForEach-Object { $_.ToString('x2') }) }
# base64url ohne Padding: das Format des VAPID-Privatschluessels (delivery
# liest ihn per URL_SAFE_NO_PAD). 32 zufaellige Bytes sind mit
# ueberwaeltigender Wahrscheinlichkeit ein gueltiger P-256-Skalar.
function New-SeedUrl { return (New-Seed).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
if (-not (Test-Path $envFile)) {
    Write-Step 'Erzeuge .env mit starken Zufallswerten (einmalig)'
    @(
        "POSTGRES_PASSWORD=$(New-Hex)"
        "INTERNAL_TOKEN=$(New-Hex)"
        "CDS_OPRF_KEY=$(New-Seed)"
        "SEALED_SENDER_TRUST_ROOT=$(New-Seed)"
        "KT_SIGNING_KEY=$(New-Seed)"
        "KT_VRF_KEY=$(New-Seed)"
        "INTEGRATIONS_WEBHOOK_SIGNING_KEY=$(New-Seed)"
        "VAPID_PRIVATE_KEY=$(New-SeedUrl)"
        "VAPID_SUBJECT=mailto:admin@securemessenger.local"
        "MEDIA_S3_ACCESS_KEY=sm-media"
        "MEDIA_S3_SECRET_KEY=$(New-Hex)"
        "KEYCLOAK_ADMIN_PASSWORD=$(New-Hex)"
    ) | Out-File -FilePath $envFile -Encoding ascii
    Write-Ok '.env angelegt (nicht eingecheckt; Werte bei Bedarf dort nachlesen)'
} else {
    Write-Ok '.env vorhanden'
}

# Anrufe sind opt-in: das TURN-Geheimnis wird nur mit -Calls erzeugt (sonst
# wuerde delivery Anrufe anbieten, obwohl coturn gar nicht laeuft). Fehlt es
# in einer vorhandenen .env, hier nachziehen (wie envgen.sh beim Server).
# TURN_URLS zeigen auf localhost: coturn faehrt mit network_mode host, zwei
# Browser-Tabs auf DIESEM Rechner bauen darueber einen Anruf auf.
if ($Calls) {
    $envText = if (Test-Path $envFile) { Get-Content $envFile -Raw } else { '' }
    if ($envText -notmatch '(?m)^TURN_SHARED_SECRET=.+$') {
        Write-Step 'Ergaenze das TURN-Geheimnis fuer Anrufe in .env'
        Add-Content -Path $envFile -Encoding ascii -Value @(
            "TURN_SHARED_SECRET=$(New-Hex)"
            'TURN_URLS=stun:localhost:3478,turn:localhost:3478?transport=udp'
        )
        Write-Ok 'TURN_SHARED_SECRET und TURN_URLS in .env ergaenzt'
    }
    else {
        Write-Ok 'TURN-Geheimnis in .env vorhanden'
    }
}

# Der Entwicklungs-Container sm-postgres (Test-Datenbanken fuer cargo test)
# belegt sonst Port 5432; der Stack bringt seine eigene Datenbank mit.
docker stop sm-postgres *> $null

if ($Reset) {
    Write-Step 'Loesche Daten-Volumes (docker compose down -v)'
    docker compose down -v
}

$composeArgs = @()
if ($Sso) { $composeArgs += @('--profile', 'sso') }
if ($Web) { $composeArgs += @('--profile', 'web') }
if ($Calls) { $composeArgs += @('--profile', 'calls') }
Write-Step 'Stack bauen und starten (docker compose up -d --build; erster Build dauert)'
docker compose @composeArgs up -d --build
$ok = ($LASTEXITCODE -eq 0)
Pop-Location
if (-not $ok) {
    Write-Bad 'docker compose up fehlgeschlagen (Ausgabe oben pruefen).'
    exit 1
}

Write-Ok 'Stack laeuft. Status: docker compose ps'
Write-Host '    Dienste: identity 8080, directory 8081, delivery 8082, kt 8083, media 8084, integrations 8085'
if ($Web) { Write-Host '    Web:     http://localhost:3000' }
if ($Sso) { Write-Host '    SSO:     http://localhost:8090 (Admin-Passwort in der .env)' }
if ($Calls) { Write-Host '    Anrufe:  coturn laeuft (TURN localhost:3478); zwei Browser-Tabs auf diesem Rechner koennen anrufen' }
Write-Host "    CLI:     $root\target\debug\sm.exe (Referenzclient; bauen mit cargo build -p sm-cli)"
Write-Host '    Stoppen: scripts\sm.ps1 -Stop'

if ($OpenBrowser -and $Web) {
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/' -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { break }
        } catch { Start-Sleep -Seconds 1 }
    }
    Start-Process 'http://localhost:3000' | Out-Null
}
