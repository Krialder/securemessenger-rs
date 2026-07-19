<#
  Server-Auslieferung: bringt den SecureMessenger-Stack auf eine Linux-VM
  (z. B. auf dem Proxmox-Server) und startet ihn dort. Einmalige VM-Anlage
  und Details: deploy\remote\README.md.

  Ablauf der Voll-Auslieferung (Standard ohne Schalter):
    Verbindung pruefen -> Zielsystem erkennen -> Docker sicherstellen ->
    Projektstand hochladen (git archive HEAD) -> lokal gebaute Images
    uebertragen (der Server kompiliert nie) -> .env AUF dem Server erzeugen
    (Geheimnisse verlassen ihn nie) -> Stack starten -> Healthchecks.

  Aufrufe:
    deploy.ps1 -Configure -TargetHost <ip> -User <name> [...]  Profil anlegen
    deploy.ps1 -SetupKey       SSH-Schluessel erzeugen und eintragen
                               (fragt EINMAL nach dem Server-Passwort)
    deploy.ps1 -CheckOnly      nur Verbindung + Zielsystem-Bericht
    deploy.ps1                 Voll-Auslieferung
    deploy.ps1 -Web -Sso       zusaetzlich Web-Client bzw. Keycloak
    deploy.ps1 -Calls          zusaetzlich coturn fuer 1:1-Anrufe (F2). Braucht
                               offene Ports 3478 UDP/TCP + 49160-49200 UDP auf
                               dem Server; bei NAT EXTERNAL_IP in der .env.
    deploy.ps1 -SkipBuild      lokalen Image-Build ueberspringen
    deploy.ps1 -NoStart        alles uebertragen, nicht starten
    deploy.ps1 -Status         Stack-Status auf dem Server
    deploy.ps1 -Stop           Stack auf dem Server herunterfahren
#>
param(
    [switch]$Configure,
    [switch]$SetupKey,
    [switch]$CheckOnly,
    [switch]$Status,
    [switch]$Stop,
    [switch]$Web,
    [switch]$Sso,
    [switch]$Calls,
    [switch]$SkipBuild,
    [switch]$NoStart,
    [string]$TargetHost,
    [int]$Port,
    [string]$User,
    [string]$KeyFile,
    [string]$TargetDir
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib-deploy.ps1')

if (-not (Test-SmSshAvailable)) {
    Write-DeployBad 'ssh fehlt. Windows-Feature "OpenSSH-Client" installieren (Einstellungen -> Optionale Features).'
    exit 1
}

# ---------------------------------------------------------------------------
# Profil aufloesen: gespeichertes Profil, Parameter ueberschreiben. Fehlt
# etwas Wesentliches, fragt der interaktive Lauf nach (Wizard), ein
# nicht-interaktiver bricht mit klarer Meldung ab.
# ---------------------------------------------------------------------------
$saved = Get-SmDeployProfile
if ($saved) {
    if (-not $TargetHost) { $TargetHost = $saved.TargetHost }
    if (-not $Port) { $Port = $saved.Port }
    if (-not $User) { $User = $saved.User }
    if (-not $KeyFile) { $KeyFile = $saved.KeyFile }
    if (-not $TargetDir) { $TargetDir = $saved.TargetDir }
}
$interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
if (-not $TargetHost -and $interactive) {
    Write-Host 'Kein Verbindungsprofil gefunden; Angaben zum Server:' -ForegroundColor White
    $TargetHost = Read-Host 'Server (IP oder Name)'
    $User = Read-Host 'SSH-Benutzer (z. B. root oder deploy)'
    $portIn = Read-Host 'SSH-Port [22]'
    if ($portIn) { $Port = [int]$portIn }
}
if (-not $TargetHost -or -not $User) {
    Write-DeployBad 'Profil unvollstaendig: -Configure -TargetHost <ip> -User <name> [-Port 22] [-KeyFile pfad] [-TargetDir /opt/securemessenger]'
    exit 1
}
$p = New-SmDeployProfile $TargetHost $Port $User $KeyFile $TargetDir
Save-SmDeployProfile $p
Write-DeployOk "Profil: $($p.User)@$($p.TargetHost):$($p.Port) -> $($p.TargetDir) (Schluessel $($p.KeyFile))"
if ($Configure) { exit 0 }

if ($SetupKey) {
    if (Initialize-SmDeployKey $p) { exit 0 } else { exit 1 }
}

# Ab hier braucht jeder Weg die Schluessel-Verbindung.
Write-DeployStep 'Pruefe die SSH-Verbindung (Schluessel-Anmeldung)'
if (-not (Test-SmDeployConnection $p)) {
    Write-DeployBad 'Keine Verbindung. Erst deploy.ps1 -SetupKey ausfuehren (traegt den Schluessel ein), Host/Port/Benutzer pruefen.'
    exit 1
}
Write-DeployOk 'verbunden'

if ($Status -or $Stop) {
    if (-not (Publish-SmRemoteScripts $p)) { Write-DeployBad 'Skript-Upload fehlgeschlagen'; exit 1 }
    $scriptName = 'status.sh'
    if ($Stop) { $scriptName = 'stop.sh' }
    $r = Invoke-SmRemoteScript $p $scriptName $p.TargetDir
    Write-Host $r.Output
    exit $r.Exit
}

Write-DeployStep 'Zielsystem'
Get-SmRemoteInfo $p | ForEach-Object { Write-Host "    $_" }

if (-not (Publish-SmRemoteScripts $p)) { Write-DeployBad 'Skript-Upload fehlgeschlagen'; exit 1 }

Write-DeployStep 'Stelle Docker auf dem Server sicher'
$r = Invoke-SmRemoteScript $p 'ensure-docker.sh' ''
Write-Host $r.Output
if (-not $r.Ok) { Write-DeployBad 'Docker fehlt auf dem Server (Meldung oben); danach erneut ausliefern.'; exit 1 }

if ($CheckOnly) {
    Write-Host "`nAlles bereit fuer die Auslieferung (deploy.ps1 ohne -CheckOnly)." -ForegroundColor White
    exit 0
}

if (-not $SkipBuild) {
    if (-not (Build-SmImages -Web:$Web)) { exit 1 }
}
if (-not (Publish-SmSource $p)) { exit 1 }
if (-not (Publish-SmImages $p -Web:$Web)) { exit 1 }

Write-DeployStep 'Erzeuge die .env auf dem Server (falls sie fehlt)'
# Mit -Calls die Server-Adresse an envgen geben: es erzeugt das TURN-Geheimnis
# und setzt TURN_URLS auf diese Adresse (der Browser erreicht coturn dort).
$envArgs = $p.TargetDir
if ($Calls) { $envArgs = "$($p.TargetDir) $($p.TargetHost)" }
$r = Invoke-SmRemoteScript $p 'envgen.sh' $envArgs
Write-Host "    $($r.Output)"
if (-not $r.Ok) { Write-DeployBad 'envgen fehlgeschlagen'; exit 1 }

if ($NoStart) {
    Write-Host "`nUebertragen ohne Start (-NoStart). Starten: deploy.ps1 -Status / start.sh auf dem Server." -ForegroundColor White
    exit 0
}

Write-DeployStep 'Starte den Stack auf dem Server'
$startArgs = $p.TargetDir
if ($Web) { $startArgs = "$startArgs web" }
if ($Sso) { $startArgs = "$startArgs sso" }
if ($Calls) { $startArgs = "$startArgs calls" }
$r = Invoke-SmRemoteScript $p 'start.sh' $startArgs
Write-Host $r.Output
if (-not $r.Ok) { Write-DeployBad 'Start fehlgeschlagen (Ausgabe oben; deploy.ps1 -Status fuer den Zustand)'; exit 1 }

Write-Host "`nAusgeliefert und gestartet." -ForegroundColor White
Write-Host "    Dienste:  http://$($p.TargetHost):8080-8085 (identity, directory, delivery, kt, media, integrations)"
if ($Web) { Write-Host "    Web:      http://$($p.TargetHost):3000" }
if ($Sso) { Write-Host "    SSO:      http://$($p.TargetHost):8090 (Admin-Passwort in $($p.TargetDir)/.env auf dem Server)" }
if ($Calls) { Write-Host "    Anrufe:   coturn laeuft (TURN $($p.TargetHost):3478). Ports 3478 UDP/TCP + 49160-49200 UDP oeffnen; bei NAT EXTERNAL_IP in der .env setzen." }
Write-Host '    Status:   deploy.ps1 -Status | Stoppen: deploy.ps1 -Stop'
