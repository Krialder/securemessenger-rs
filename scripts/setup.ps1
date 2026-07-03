<#
  Richtet die Entwicklungsumgebung fuer den SecureMessenger ein.

  Was es tut:
    1. prueft, was schon vorhanden ist (winget, Rust, MSVC-Linker, protoc,
       Docker, WSL, wasm32-Target, trunk)
    2. installiert Fehlendes ueber winget bzw. laedt protoc und trunk von GitHub
    3. repariert eine beschaedigte gepinnte Rust-Toolchain (rust-toolchain.toml)
    4. startet Docker Desktop, wenn der Daemon nicht laeuft; vorher werden
       verwaiste Socket-Dateien weggeraeumt, an denen der Start sonst scheitert
    5. legt die lokale Entwicklungs-Datenbank an (Container sm-postgres
       mit einer Datenbank je Dienst, siehe ENTWICKLUNG.md)

  Idempotent: Vorhandenes wird uebersprungen. Wird ueber start.cmd im Projekt-Root
  per Doppelklick gestartet. Konsolen-Ausgaben bewusst ASCII, damit sie in jeder
  Windows-Konsole sauber erscheinen. Mit SM_SETUP_NONINTERACTIVE=1 entfaellt die
  Enter-Abfrage am Ende (fuer Agenten- und CI-Laeufe).
#>

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!]  $m" -ForegroundColor Yellow }
function Write-Bad($m)  { Write-Host "    [x]  $m" -ForegroundColor Red }
function Have($name)    { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Test-DockerDaemon {
    if (-not (Have 'docker')) { return $false }
    try { docker info *> $null } catch { return $false }
    return ($LASTEXITCODE -eq 0)
}

# Verwaiste Unix-Socket-Dateien frueherer, hart beendeter Docker-Laeufe. Der
# Daemon loescht sie beim Start selbst; wenn Windows das mit "The file cannot
# be accessed by the system" verweigert (kaputte Reparse Points), stirbt er
# mit genau dieser Meldung im Fehlerdialog. Loeschen schlaegt dann auch hier
# fehl, das Umbenennen des Elternordners funktioniert aber, und Docker legt
# ihn frisch an. Bekannte Fundorte: Docker\run und docker-secrets-engine.
function Clear-StaleDockerSockets {
    $dirs = @(
        (Join-Path $env:LOCALAPPDATA 'Docker\run'),
        (Join-Path $env:LOCALAPPDATA 'docker-secrets-engine')
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { continue }
        $stale = Get-ChildItem $d -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
        if (-not $stale) { continue }
        $deleted = $true
        foreach ($f in $stale) {
            try { Remove-Item $f.FullName -Force -Confirm:$false -ErrorAction Stop }
            catch { $deleted = $false }
        }
        if (-not $deleted) {
            $backup = $d + '.broken-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
            try {
                Rename-Item $d $backup -ErrorAction Stop
                Write-Note "verwaiste Docker-Sockets beiseite geraeumt: $d -> $backup"
            } catch {
                Write-Bad "verwaiste Sockets in $d nicht entfernbar, der Docker-Start kann daran scheitern"
            }
        }
    }
}

Write-Host "SecureMessenger - Entwicklungsumgebung einrichten" -ForegroundColor White

# Der Docker-Client liegt nach einer Desktop-Installation nicht in jedem
# Terminal im PATH (erst nach Ab- und Anmelden); der feste Installationspfad
# ist der Rueckfall, damit die Pruefungen unten nicht falsch "fehlt" melden.
$dockerCliDir = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
if (-not (Have 'docker') -and (Test-Path (Join-Path $dockerCliDir 'docker.exe'))) {
    $env:Path = "$dockerCliDir;$env:Path"
}

# 1. winget (Voraussetzung fuer die Installationen)
Write-Step "Pruefe winget (Paketmanager)"
if (Have 'winget') {
    Write-Ok "winget vorhanden"
} else {
    Write-Bad "winget fehlt. Bitte 'App Installer' aus dem Microsoft Store installieren und erneut starten."
    if ($env:SM_SETUP_NONINTERACTIVE -ne '1') { Read-Host "Mit Enter beenden" }
    exit 1
}

# 2. Rust-Toolchain
Write-Step "Pruefe Rust (cargo)"
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (-not (Have 'cargo') -and (Test-Path (Join-Path $cargoBin 'cargo.exe'))) {
    # rustup traegt .cargo\bin nur in den Benutzer-PATH ein; Sitzungen, die
    # vor der Installation geoeffnet wurden, sehen das nicht. PATH-Rueckfall
    # statt eines unnoetigen winget-Laufs.
    $env:Path = "$cargoBin;$env:Path"
}
if (-not (Have 'cargo')) {
    Write-Note "cargo fehlt, installiere Rust ueber winget (rustup)"
    winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements
    if (Test-Path $cargoBin) { $env:Path = "$cargoBin;$env:Path" }
    if (-not (Have 'cargo')) {
        Write-Note "Rust installiert, aber cargo noch nicht im PATH dieser Sitzung. Bitte ein neues Terminal oeffnen."
    }
}

# 2a. Die gepinnte Toolchain wirklich ausfuehren, nicht nur finden. Eine
#     beschaedigte Installation (Symptom: "error: Missing manifest in
#     toolchain", etwa nach einem abgebrochenen rustup-Download) besteht den
#     Have-Check, aber kein cargo-Kommando laeuft damit. Neuinstallation der
#     exakten Version aus rust-toolchain.toml behebt das.
$rustupExe = if (Have 'rustup') { 'rustup' } else { Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe" }
$pinned = $null
$tomlPath = Join-Path $PSScriptRoot '..\rust-toolchain.toml'
if (Test-Path $tomlPath) {
    $match = Select-String -Path $tomlPath -Pattern 'channel\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($match) { $pinned = $match.Matches[0].Groups[1].Value }
}
if ((Have 'cargo') -and $pinned -and ((Have 'rustup') -or (Test-Path $rustupExe))) {
    & $rustupExe run $pinned rustc --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Note "gepinnte Toolchain $pinned fehlt oder ist beschaedigt, installiere sie neu (Download dauert einige Minuten)"
        & $rustupExe toolchain uninstall "$pinned-x86_64-pc-windows-msvc" *> $null
        & $rustupExe toolchain install $pinned --component rustfmt --component clippy
        & $rustupExe run $pinned rustc --version *> $null
        if ($LASTEXITCODE -eq 0) { Write-Ok "Toolchain $pinned repariert" }
        else { Write-Bad "Toolchain $pinned weiterhin defekt; manuell pruefen: rustup toolchain install $pinned" }
    } else {
        Write-Ok ("cargo vorhanden: " + (& $rustupExe run $pinned cargo --version))
    }
} elseif (Have 'cargo') {
    Write-Ok ("cargo vorhanden: " + (cargo --version))
}

# 2b. Rust-Komponenten fuer Format- und Lint-Pruefung (cargo fmt, cargo clippy)
Write-Step "Pruefe Rust-Komponenten (rustfmt, clippy)"
if ((Have 'rustup') -or (Test-Path $rustupExe)) {
    & $rustupExe component add rustfmt clippy *> $null
    Write-Ok "rustfmt und clippy vorhanden"
} else {
    Write-Note "rustup nicht gefunden, Komponenten uebersprungen"
}

# 2c. MSVC Build Tools: das MSVC-Target von Rust braucht link.exe aus den
#     C++ Build Tools ("error: linker `link.exe` not found" ohne sie).
#     Erkennung ueber vswhere -find direkt auf link.exe: die Abfrage nach
#     Komponenten-IDs (-requires) bleibt bei reinen Build-Tools-
#     Installationen leer und meldete faelschlich "fehlt".
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
function Test-MsvcLinker {
    if (-not (Test-Path $vswhere)) { return $false }
    $link = & $vswhere -latest -products '*' -find 'VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe' 2>$null
    return [bool]$link
}
Write-Step "Pruefe MSVC Build Tools (link.exe)"
$msvcOk = Test-MsvcLinker
if ($msvcOk) {
    Write-Ok "C++ Build Tools vorhanden"
} else {
    Write-Note "C++ Build Tools fehlen, installiere sie ueber winget (mehrere GB, dauert; UAC-Abfrage bestaetigen)"
    winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    $msvcOk = Test-MsvcLinker
    if ($msvcOk) {
        Write-Ok "C++ Build Tools installiert"
    } else {
        Write-Bad "C++ Build Tools weiterhin nicht auffindbar; ohne link.exe schlaegt jeder cargo-Build fehl"
    }
}

# 2d. Client-Werkzeuge: der Web-Client (clients/web) baut nach
#     wasm32-unknown-unknown und wird von trunk gebuendelt (GOAL.md,
#     Verifikations-Loop Schritt 4). trunk kommt als vorgebautes Binary von
#     GitHub, weil cargo install es minutenlang kompilieren wuerde.
Write-Step "Pruefe Client-Werkzeuge (wasm32-Target, trunk)"
if ($pinned -and ((Have 'rustup') -or (Test-Path $rustupExe))) {
    $targets = & $rustupExe target list --installed --toolchain $pinned 2>$null
    if ($targets -contains 'wasm32-unknown-unknown') {
        Write-Ok "wasm32-unknown-unknown vorhanden"
    } else {
        Write-Note "wasm32-Target fehlt, installiere es fuer Toolchain $pinned"
        & $rustupExe target add wasm32-unknown-unknown --toolchain $pinned
        Write-Ok "wasm32-unknown-unknown installiert"
    }
} else {
    Write-Note "rustup oder Toolchain-Pin nicht gefunden, wasm32-Target uebersprungen"
}
$trunkExe = Join-Path $cargoBin 'trunk.exe'
if ((Have 'trunk') -or (Test-Path $trunkExe)) {
    Write-Ok "trunk vorhanden"
} else {
    Write-Note "trunk fehlt, lade das Windows-Binary von GitHub (trunk-rs/trunk)"
    try {
        $rel = Invoke-RestMethod https://api.github.com/repos/trunk-rs/trunk/releases/latest
        $asset = $rel.assets | Where-Object name -like "*x86_64-pc-windows-msvc.zip" | Select-Object -First 1
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$env:TEMP\trunk.zip"
        Expand-Archive -Path "$env:TEMP\trunk.zip" -DestinationPath $cargoBin -Force
        Write-Ok ("trunk installiert: " + (& $trunkExe --version))
    } catch {
        Write-Bad "trunk-Download fehlgeschlagen. Manuell: cargo install trunk --locked"
    }
}

# 3. protoc (Protobuf-Compiler): braucht der Krypto-Kern (crates/client-core),
#    weil libsignal seine Protobuf-Schemas beim Bauen kompiliert. Die
#    Backend-Dienste bauen auch ohne.
Write-Step "Pruefe protoc (fuer den Krypto-Kern)"
$protocDir = Join-Path $env:LOCALAPPDATA "protoc"
$protocExe = Join-Path $protocDir "bin\protoc.exe"
if (Have 'protoc') {
    Write-Ok ("protoc vorhanden: " + (protoc --version))
} elseif (Test-Path $protocExe) {
    $env:PROTOC = $protocExe
    Write-Ok ("protoc vorhanden unter " + $protocExe)
    Write-Note "PROTOC nur fuer diese Sitzung gesetzt; dauerhaft: setx PROTOC `"$protocExe`""
} else {
    Write-Note "protoc fehlt, lade das Windows-Paket von GitHub (protocolbuffers/protobuf)"
    try {
        $rel = Invoke-RestMethod https://api.github.com/repos/protocolbuffers/protobuf/releases/latest
        $asset = $rel.assets | Where-Object name -like "protoc-*-win64.zip" | Select-Object -First 1
        New-Item -ItemType Directory -Force -Path $protocDir | Out-Null
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$env:TEMP\protoc.zip"
        Expand-Archive -Path "$env:TEMP\protoc.zip" -DestinationPath $protocDir -Force
        $env:PROTOC = $protocExe
        Write-Ok ("protoc installiert: " + (& $protocExe --version))
        Write-Note "PROTOC nur fuer diese Sitzung gesetzt; dauerhaft: setx PROTOC `"$protocExe`""
    } catch {
        Write-Bad "protoc-Download fehlgeschlagen. Manuell: https://github.com/protocolbuffers/protobuf/releases"
    }
}

# 4. Docker-Client
Write-Step "Pruefe Docker"
if (Have 'docker') {
    Write-Ok ("Docker-Client vorhanden: " + (docker --version))
} else {
    Write-Note "Docker-Client fehlt, installiere Docker Desktop ueber winget"
    winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
    Write-Note "Docker Desktop installiert. Eventuell ist ein Windows-Neustart noetig, bevor der Daemon laeuft."
    if (Test-Path (Join-Path $dockerCliDir 'docker.exe')) { $env:Path = "$dockerCliDir;$env:Path" }
}

# 4a. WSL: Docker Desktop laeuft ueber das WSL2-Backend. Ohne installierte
#     WSL-Plattform kommt der Daemon nie hoch; jede Wartezeit unten waere
#     verschenkt. Deshalb wird WSL vor dem Daemon geprueft und bei Bedarf
#     installiert (ohne Distribution, Docker bringt seine eigene mit).
Write-Step "Pruefe WSL (Backend von Docker Desktop)"
if (Have 'wsl') {
    wsl.exe --status *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "WSL vorhanden"
    } else {
        Write-Note "WSL fehlt, installiere die Plattform (braucht Adminrechte, gleich erscheint eine UAC-Abfrage)"
        try {
            Start-Process wsl.exe -Verb RunAs -ArgumentList '--install', '--no-distribution' -Wait
            wsl.exe --status *> $null
            if ($LASTEXITCODE -eq 0) { Write-Ok "WSL installiert" }
            else { Write-Note "WSL installiert, wirkt aber erst nach einem Windows-Neustart" }
        } catch {
            Write-Bad "WSL-Installation abgelehnt oder fehlgeschlagen; Docker Desktop startet ohne WSL nicht"
        }
    }
} else {
    Write-Bad "wsl.exe nicht gefunden; WSL manuell installieren (wsl --install), sonst startet Docker Desktop nicht"
}

# 5. Docker-Daemon starten, falls noetig
Write-Step "Pruefe Docker-Daemon"
if (Test-DockerDaemon) {
    Write-Ok "Docker-Daemon laeuft"
} elseif (Have 'docker') {
    Write-Note "Daemon nicht erreichbar, starte Docker Desktop neu"
    # Haengengebliebene Prozesse eines gescheiterten Starts nehmen den neuen
    # Start sonst nicht an; ohne erreichbaren Daemon ist das Beenden verlustfrei.
    Get-Process | Where-Object { $_.Name -like '*docker*' } |
        Stop-Process -Force -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Clear-StaleDockerSockets
    $dd = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dd) {
        Start-Process $dd | Out-Null
        Write-Host "    Warte auf den Daemon (bis zu 180s) " -NoNewline
        $ready = $false
        for ($i = 0; $i -lt 90; $i++) {
            Start-Sleep -Seconds 2
            if (Test-DockerDaemon) { $ready = $true; break }
            Write-Host "." -NoNewline
        }
        Write-Host ""
        if ($ready) { Write-Ok "Docker-Daemon laeuft jetzt" }
        else { Write-Bad "Daemon nicht rechtzeitig bereit. Docker Desktop manuell pruefen (Fehlerdialog, WSL2-Backend, ggf. Windows-Neustart)." }
    } else {
        Write-Bad "Docker Desktop nicht gefunden unter: $dd"
    }
}

# 6. Entwicklungs-Datenbank: ein PostgreSQL-Container, eine Datenbank je
#    Dienst (die sqlx-Migrationstabellen duerfen sich nicht in die Quere
#    kommen, ENTWICKLUNG.md). Wegwerf-Instanz: docker rm -f sm-postgres
#    setzt alles zurueck.
Write-Step "Pruefe Entwicklungs-Datenbank (sm-postgres)"
$databases = @('identity', 'directory', 'delivery', 'integrations', 'kt')
$pgReady = $false
if (Test-DockerDaemon) {
    $existing = docker ps -a --filter "name=^sm-postgres$" --format "{{.Names}}"
    if (-not $existing) {
        Write-Note "Container fehlt, starte postgres:17-alpine als sm-postgres (Port 5432, Passwort dev)"
        docker run -d --name sm-postgres -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=identity -p 5432:5432 postgres:17-alpine *> $null
    } elseif (-not (docker ps --filter "name=^sm-postgres$" --format "{{.Names}}")) {
        Write-Note "Container vorhanden, aber gestoppt; starte ihn"
        docker start sm-postgres *> $null
    }
    Write-Host "    Warte auf PostgreSQL " -NoNewline
    for ($i = 0; $i -lt 30; $i++) {
        docker exec sm-postgres pg_isready -U postgres *> $null
        if ($LASTEXITCODE -eq 0) { $pgReady = $true; break }
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline
    }
    Write-Host ""
    if ($pgReady) {
        foreach ($db in $databases) {
            $exists = docker exec sm-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$db'" 2>$null
            if ("$exists".Trim() -ne '1') {
                docker exec sm-postgres psql -U postgres -c "CREATE DATABASE $db" *> $null
                Write-Ok "Datenbank $db angelegt"
            } else {
                Write-Ok "Datenbank $db vorhanden"
            }
        }
    } else {
        Write-Bad "PostgreSQL nicht rechtzeitig bereit; Datenbanken uebersprungen (docker logs sm-postgres pruefen)"
    }
} else {
    Write-Note "Docker-Daemon nicht erreichbar, Datenbank uebersprungen"
}

# 7. Zusammenfassung
Write-Step "Status"
$cargoState  = if (Have 'cargo')  { 'ok' } else { 'fehlt' }
$msvcState   = if ($msvcOk) { 'ok' } else { 'fehlt' }
$protocState = if ((Have 'protoc') -or (Test-Path $protocExe)) { 'ok' } else { 'fehlt' }
$trunkState  = if ((Have 'trunk') -or (Test-Path $trunkExe)) { 'ok' } else { 'fehlt' }
$dockerState = if (Have 'docker') { 'ok' } else { 'fehlt' }
$daemonState = if (Test-DockerDaemon) { 'laeuft' } else { 'nicht erreichbar' }
$pgState     = if ($pgReady) { "laeuft ($($databases -join ', '))" } else { 'nicht bereit' }
Write-Host "    cargo   : $cargoState"
Write-Host "    msvc    : $msvcState"
Write-Host "    protoc  : $protocState"
Write-Host "    trunk   : $trunkState"
Write-Host "    docker  : $dockerState (Daemon: $daemonState)"
Write-Host "    postgres: $pgState"

Write-Host "`nFertig. Naechste Schritte aus dem Projekt-Root:" -ForegroundColor White
Write-Host "    cargo test --workspace                # PG-Tests laufen mit den TEST_DATABASE_URL*-Variablen, siehe ENTWICKLUNG.md"
Write-Host "    cargo run -p identity                 # ebenso: directory, delivery, integrations, media"
Write-Host "    docker build -f deploy/docker/Dockerfile --build-arg SERVICE=identity -t securemessenger/identity:dev ."
if ($env:SM_SETUP_NONINTERACTIVE -ne '1') { Read-Host "`nMit Enter schliessen" }
