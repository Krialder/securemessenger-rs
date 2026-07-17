<#
  Engine der Server-Auslieferung: Bausteine, die Konsole (deploy.ps1) und
  GUI (deploy-gui.ps1) teilen. BIBLIOTHEK, per Dot-Sourcing einbinden.

  Modell: das Ziel ist ein Linux-Host (Proxmox-VM oder LXC) ueber SSH mit
  Schluessel-Anmeldung. Das Verbindungsprofil (Host, Port, Benutzer,
  Schluesseldatei, Zielordner) liegt lokal in profile.json (gitignored);
  Passwoerter werden NIE gespeichert, die einmalige Schluessel-Einrichtung
  (Initialize-SmDeployKey) ersetzt sie. Die Images baut die lokale Maschine
  und uebertraegt sie fertig (docker save/scp/load), der Server kompiliert
  nie; die .env mit den Geheimnissen entsteht AUF dem Server (envgen.sh)
  und verlaesst ihn nicht.
#>

Set-StrictMode -Off
$script:DeployDir = $PSScriptRoot
$script:DeployRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:ProfileFile = Join-Path $PSScriptRoot 'profile.json'
$script:RemoteScriptsDir = Join-Path $PSScriptRoot 'remote-scripts'
$script:RemoteTmp = '/tmp/sm-deploy'

function Write-DeployStep($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-DeployOk($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-DeployBad($m)  { Write-Host "    [x]  $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Profil
# ---------------------------------------------------------------------------
function Get-SmDeployProfile {
    if (-not (Test-Path $script:ProfileFile)) { return $null }
    try { return (Get-Content $script:ProfileFile -Raw | ConvertFrom-Json) } catch { return $null }
}

function Save-SmDeployProfile($p) {
    $p | ConvertTo-Json | Out-File -FilePath $script:ProfileFile -Encoding ascii
}

function New-SmDeployProfile($TargetHost, $Port, $User, $KeyFile, $TargetDir) {
    if (-not $Port) { $Port = 22 }
    if (-not $KeyFile) { $KeyFile = Join-Path $script:DeployDir 'keys\id_ed25519' }
    if (-not $TargetDir) { $TargetDir = '/opt/securemessenger' }
    return [pscustomobject]@{
        TargetHost = $TargetHost
        Port       = [int]$Port
        User       = $User
        KeyFile    = $KeyFile
        TargetDir  = $TargetDir
    }
}

# ---------------------------------------------------------------------------
# SSH-Grundbausteine. BatchMode=yes laesst Aufrufe mit fehlendem Schluessel
# sofort scheitern, statt still auf eine Passwort-Eingabe zu warten.
# ---------------------------------------------------------------------------
function Test-SmSshAvailable {
    return [bool](Get-Command ssh -ErrorAction SilentlyContinue)
}

function Get-SmSshBaseArgs($p, [switch]$Interactive) {
    $sshArgs = @('-p', "$($p.Port)",
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=10')
    if (-not $Interactive) { $sshArgs += @('-o', 'BatchMode=yes', '-i', $p.KeyFile) }
    $sshArgs += "$($p.User)@$($p.TargetHost)"
    return $sshArgs
}

# Fuehrt EIN Kommando auf dem Server aus. Die Kommandos hier sind bewusst
# frei von doppelten Anfuehrungszeichen: PowerShell 5.1 zerlegt eingebettete
# Quotes beim Durchreichen an native Programme (gelernte Falle).
function Invoke-SmRemote($p, [string]$Command) {
    $sshArgs = (Get-SmSshBaseArgs $p) + @('--', $Command)
    # stderr sofort zu Strings machen: PowerShell 5.1 verpackt native
    # stderr-Zeilen sonst in ErrorRecords (NativeCommandError-Rauschen),
    # obwohl das Programm sauber lief.
    $out = & ssh @sshArgs 2>&1 | ForEach-Object { "$_" }
    return [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Exit = $LASTEXITCODE; Output = ($out | Out-String).TrimEnd() }
}

function Copy-SmToRemote($p, [string]$LocalPath, [string]$RemotePath) {
    $scpArgs = @('-P', "$($p.Port)",
        '-o', 'StrictHostKeyChecking=accept-new', '-o', 'BatchMode=yes',
        '-i', $p.KeyFile, $LocalPath, "$($p.User)@$($p.TargetHost):$RemotePath")
    # scp meldet Fortschritt auf stderr; die ForEach-Zeile stringifiziert die
    # Records, bevor PowerShell 5.1 sie zu Fehlern aufblaest.
    & scp @scpArgs 2>&1 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
    return ($LASTEXITCODE -eq 0)
}

# Laedt die versionierten Server-Skripte nach /tmp/sm-deploy und macht sie
# ausfuehrbar; jeder Lauf frisch, damit Skript-Aenderungen sofort gelten.
function Publish-SmRemoteScripts($p) {
    $r = Invoke-SmRemote $p "mkdir -p $script:RemoteTmp"
    if (-not $r.Ok) { return $false }
    foreach ($f in Get-ChildItem $script:RemoteScriptsDir -Filter '*.sh') {
        if (-not (Copy-SmToRemote $p $f.FullName "$script:RemoteTmp/$($f.Name)")) { return $false }
    }
    # CR strippen und ausfuehrbar machen: falls die lokale Kopie doch mit
    # CRLF vorliegt, wuerde der Linux-Kernel sonst am Shebang scheitern
    # (/bin/sh\r). sed ist auf jedem Zielsystem vorhanden.
    return (Invoke-SmRemote $p "sed -i 's/\r$//' $script:RemoteTmp/*.sh && chmod +x $script:RemoteTmp/*.sh").Ok
}

function Invoke-SmRemoteScript($p, [string]$ScriptName, [string]$ScriptArgs) {
    return Invoke-SmRemote $p "sh $script:RemoteTmp/$ScriptName $ScriptArgs"
}

# ---------------------------------------------------------------------------
# Verbindung und Zielsystem
# ---------------------------------------------------------------------------
function Test-SmDeployConnection($p) {
    return (Invoke-SmRemote $p 'echo sm-verbunden').Output -match 'sm-verbunden'
}

function Get-SmRemoteInfo($p) {
    $probe = Invoke-SmRemote $p 'uname -sm; grep PRETTY_NAME /etc/os-release 2>/dev/null; command -v docker >/dev/null 2>&1 && docker --version || echo docker-fehlt; docker compose version 2>/dev/null || echo compose-fehlt; df -h / | tail -1'
    return $probe.Output
}

# ---------------------------------------------------------------------------
# Einmalige Schluessel-Einrichtung: erzeugt ein ed25519-Paar (falls es
# fehlt) und traegt den oeffentlichen Teil auf dem Server ein. DIESER eine
# Aufruf fragt interaktiv nach dem Server-Passwort; danach laeuft alles
# ueber den Schluessel und kein Passwort wird je gespeichert.
# ---------------------------------------------------------------------------
function Initialize-SmDeployKey($p) {
    $keyDir = Split-Path $p.KeyFile -Parent
    if (-not (Test-Path $keyDir)) { New-Item -ItemType Directory -Force -Path $keyDir | Out-Null }
    if (-not (Test-Path $p.KeyFile)) {
        Write-DeployStep "Erzeuge SSH-Schluessel ($($p.KeyFile))"
        & ssh-keygen -t ed25519 -f $p.KeyFile -N '' -C 'securemessenger-deploy' | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-DeployBad 'ssh-keygen fehlgeschlagen'; return $false }
    }
    Write-DeployStep 'Trage den oeffentlichen Schluessel auf dem Server ein (einmalige Passwort-Eingabe)'
    $pub = (Get-Content "$($p.KeyFile).pub" -Raw).Trim()
    $sshArgs = (Get-SmSshBaseArgs $p -Interactive) + @('--', "mkdir -p .ssh; chmod 700 .ssh; echo $pub >> .ssh/authorized_keys; chmod 600 .ssh/authorized_keys; echo schluessel-eingetragen")
    & ssh @sshArgs
    if ($LASTEXITCODE -ne 0) { Write-DeployBad 'Eintragen fehlgeschlagen (Passwort falsch? Server erreichbar?)'; return $false }
    if (Test-SmDeployConnection $p) { Write-DeployOk 'Schluessel-Anmeldung funktioniert'; return $true }
    Write-DeployBad 'Schluessel eingetragen, aber die Schluessel-Anmeldung schlaegt fehl (PubkeyAuthentication auf dem Server pruefen)'
    return $false
}

# ---------------------------------------------------------------------------
# Bauen und Uebertragen
# ---------------------------------------------------------------------------
function Build-SmImages([switch]$Web) {
    Write-DeployStep 'Baue die Images lokal (docker compose build)'
    Push-Location $script:DeployRoot
    $buildArgs = @('compose')
    if ($Web) { $buildArgs += @('--profile', 'web') }
    $buildArgs += 'build'
    & docker @buildArgs
    $ok = ($LASTEXITCODE -eq 0)
    Pop-Location
    if ($ok) { Write-DeployOk 'Images gebaut' } else { Write-DeployBad 'Image-Build fehlgeschlagen' }
    return $ok
}

# Quellstand uebertragen: git archive HEAD = der COMMITTETE Stand, sauber
# und reproduzierbar (Uncommittetes reist bewusst nicht mit). Der Server
# braucht die Quellen nicht zum Bauen, nur docker-compose.yml und die
# gemounteten Dateien (postgres-init, keycloak-Realm) - das ganze Archiv
# ist klein genug, um nicht zu rosinenpicken.
function Publish-SmSource($p) {
    Write-DeployStep "Uebertrage den Projektstand (git archive HEAD) nach $($p.TargetDir)"
    $tmp = Join-Path $env:TEMP 'sm-deploy-src.tar.gz'
    Push-Location $script:DeployRoot
    & git archive --format=tar.gz -o $tmp HEAD
    $ok = ($LASTEXITCODE -eq 0)
    Pop-Location
    if (-not $ok) { Write-DeployBad 'git archive fehlgeschlagen'; return $false }
    $r = Invoke-SmRemote $p "mkdir -p $($p.TargetDir)"
    if (-not $r.Ok) { Write-DeployBad "Zielordner nicht anlegbar: $($r.Output)"; return $false }
    if (-not (Copy-SmToRemote $p $tmp "$script:RemoteTmp/src.tar.gz")) { Write-DeployBad 'Upload fehlgeschlagen'; return $false }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $r = Invoke-SmRemote $p "tar -xzf $script:RemoteTmp/src.tar.gz -C $($p.TargetDir) && rm $script:RemoteTmp/src.tar.gz"
    if ($r.Ok) { Write-DeployOk 'Projektstand entpackt' } else { Write-DeployBad "Entpacken fehlgeschlagen: $($r.Output)" }
    return $r.Ok
}

function Publish-SmImages($p, [switch]$Web) {
    Write-DeployStep 'Uebertrage die fertig gebauten Images (docker save / load)'
    $images = @('securemessenger-local:dev')
    if ($Web) { $images += 'securemessenger-web:latest' }
    $tmp = Join-Path $env:TEMP 'sm-deploy-images.tar'
    & docker save -o $tmp @images
    if ($LASTEXITCODE -ne 0) { Write-DeployBad 'docker save fehlgeschlagen (Images gebaut?)'; return $false }
    $size = [math]::Round((Get-Item $tmp).Length / 1MB)
    Write-DeployOk "Archiv $size MB, uebertrage..."
    if (-not (Copy-SmToRemote $p $tmp "$script:RemoteTmp/images.tar")) { Write-DeployBad 'Upload fehlgeschlagen'; return $false }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $r = Invoke-SmRemote $p "sh -c 'if docker info >/dev/null 2>&1; then docker load -i $script:RemoteTmp/images.tar; else sudo docker load -i $script:RemoteTmp/images.tar; fi' && rm $script:RemoteTmp/images.tar"
    if ($r.Ok) { Write-DeployOk 'Images auf dem Server geladen' } else { Write-DeployBad "docker load fehlgeschlagen: $($r.Output)" }
    return $r.Ok
}
