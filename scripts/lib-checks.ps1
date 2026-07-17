<#
  Gemeinsame Pruef- und Reparatur-Bibliothek der Einrichtung.

  BIBLIOTHEK, nicht direkt starten: wird per Dot-Sourcing (`. lib-checks.ps1`)
  von der grafischen Oberflaeche (sm-gui.ps1) und dem Konsolen-Einstieg
  (sm.ps1 -Setup) eingebunden.

  Das ist die einzige Wahrheit ueber den Zustand der Umgebung: Welche
  Werkzeuge fehlen, was veraltet ist, ob Docker und die Datenbank laufen und
  ob die gebauten Programme aktuell sind. Beide Einstiege (die GUI sm-gui.ps1
  und die Konsole sm.ps1 -Setup) dot-sourcen diese Datei und iterieren
  dieselbe Komponentenliste; so richten grafischer und Konsolen-Weg mit exakt
  derselben Logik ein, ohne dass die Pruef-Logik doppelt gepflegt wird.

  Jede Komponente traegt zwei Skriptbloecke: Check liest den Zustand
  (schnell, ohne Nebenwirkung) und liefert ok/missing/outdated/unknown mit
  einem Detailtext; Fix repariert idempotent und meldet Fortschritt ueber
  einen uebergebenen Logger. Wer die Liste durchlaeuft, kann so ohne
  Sonderfaelle "pruefen, und bei Bedarf reparieren" ausdruecken.
#>

Set-StrictMode -Off
$script:SmRoot = Split-Path $PSScriptRoot -Parent

# Werkzeuge liegen nach einer frischen Installation nicht immer im PATH der
# aktuellen Sitzung (rustup und Docker tragen sich erst fuer neue Terminals
# ein). Diese Rueckfaelle machen die Pruefungen verlaesslich, ohne auf ein
# neues Fenster zu warten. Auch als eigene Funktion, damit die GUI und
# sm.ps1 die Umgebung gleich aufsetzen.
function Initialize-SmEnv {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if ((Test-Path $cargoBin) -and ($env:Path -notlike "*$cargoBin*")) {
        $env:Path = "$cargoBin;$env:Path"
    }
    $dockerCliDir = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
    if ((Test-Path $dockerCliDir) -and ($env:Path -notlike "*$dockerCliDir*")) {
        $env:Path = "$dockerCliDir;$env:Path"
    }
    if (-not $env:PROTOC) {
        $protocExe = Join-Path $env:LOCALAPPDATA 'protoc\bin\protoc.exe'
        if (Test-Path $protocExe) { $env:PROTOC = $protocExe }
    }
}

function Test-SmHave($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Test-SmDockerDaemon {
    if (-not (Test-SmHave 'docker')) { return $false }
    try { docker info *> $null } catch { return $false }
    return ($LASTEXITCODE -eq 0)
}

# Docker Desktops Model Runner (Inference) legt die kaputten Sockets an, die
# den Daemon unter Windows immer wieder sterben lassen (siehe
# Clear-SmStaleDockerSockets). Der unterstuetzte, umkehrbare Weg ihn
# abzuschalten ist `docker desktop disable model-runner`; das haelt die
# Ursache klein statt nur das Symptom aufzuraeumen. Idempotent und
# best-effort: aeltere Docker-Versionen kennen den Befehl nicht, das ist
# dann ein harmloser No-op. Rueckgaengig per `docker desktop enable
# model-runner` oder in den Einstellungen unter AI.
function Disable-SmModelRunner {
    if (-not (Test-SmHave 'docker')) { return }
    # Gibt es die Docker-Desktop-CLI mit dem disable-Zweig ueberhaupt?
    docker desktop disable --help *> $null
    if ($LASTEXITCODE -ne 0) { return }
    docker desktop disable model-runner *> $null
}

# Verwaiste Socket-Dateien hart beendeter Docker-Laeufe (kaputte Reparse
# Points unter Docker\run) lassen den Daemon-Start mit "The file cannot be
# accessed by the system" sterben; der Inference-Manager legt sie auch bei
# abgeschaltetem EnableInference wieder an (Stand 07/2026). Loeschen
# scheitert oft, das Umbenennen des Ordners funktioniert, Docker legt ihn
# frisch an. Sie MUSS vor jedem programmatischen Docker-Desktop-Start
# laufen, sonst haengt der Start im Fehlerdialog.
function Clear-SmStaleDockerSockets {
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
            try { Rename-Item $d $backup -ErrorAction Stop } catch {}
        }
    }
}

# Der gepinnte Toolchain-Kanal aus rust-toolchain.toml. Alles Rust-Bezogene
# haengt daran: Format, Lint und das wasm-Target gelten je Toolchain.
function Get-SmToolchainChannel {
    $tomlPath = Join-Path $script:SmRoot 'rust-toolchain.toml'
    if (-not (Test-Path $tomlPath)) { return $null }
    $match = Select-String -Path $tomlPath -Pattern 'channel\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($match) { return $match.Matches[0].Groups[1].Value }
    return $null
}

function Get-SmRustupExe {
    if (Test-SmHave 'rustup') { return 'rustup' }
    $exe = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    if (Test-Path $exe) { return $exe }
    return $null
}

# link.exe aus den MSVC Build Tools; das MSVC-Rust-Target braucht ihn zum
# Linken. Erkennung ueber vswhere -find, weil die Abfrage nach
# Komponenten-IDs bei reinen Build-Tools-Installationen leer bleibt.
function Test-SmMsvcLinker {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $false }
    $link = & $vswhere -latest -products '*' -find 'VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe' 2>$null
    return [bool]$link
}

# Statusobjekt einer Komponente nach dem Check.
function New-SmStatus($state, $detail) {
    return [pscustomobject]@{ State = $state; Detail = $detail }
}

# Ist ein gebautes Binary aelter als der neueste Quelltext, muss neu gebaut
# werden. Heuristik ueber Aenderungszeiten: schnell und gut genug, um ein
# unnoetiges (aber harmlos-inkrementelles) cargo build zu vermeiden.
function Get-SmNewestSourceTime {
    $dirs = @('crates', 'services', 'clients') | ForEach-Object { Join-Path $script:SmRoot $_ }
    $newest = Get-ChildItem -Path $dirs -Recurse -File -Include '*.rs', '*.toml', '*.sql' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $times = @()
    if ($newest) { $times += $newest.LastWriteTime }
    foreach ($f in @('Cargo.toml', 'Cargo.lock')) {
        $p = Join-Path $script:SmRoot $f
        if (Test-Path $p) { $times += (Get-Item $p).LastWriteTime }
    }
    if ($times.Count -eq 0) { return [datetime]::MinValue }
    return ($times | Sort-Object -Descending | Select-Object -First 1)
}

# Die Binaries, die der Start (sm.ps1) braucht.
$script:SmBinaries = @('identity', 'directory', 'delivery', 'kt', 'integrations', 'sm')
$script:SmBuildPackages = @('identity', 'directory', 'delivery', 'kt', 'integrations', 'sm-cli')

# Der gepinnte Kanal einmal beim Laden aufloesen und im Skript-Scope ablegen.
# Die Check-/Fix-Bloecke greifen ueber $script: darauf zu, weil PowerShell-
# Skriptbloecke lokale Variablen der erzeugenden Funktion NICHT einfangen
# (kein Closure ohne GetNewClosure); der Skript-Scope ist der verlaessliche
# gemeinsame Anker, auch im Hintergrund-Runspace der GUIs.
$script:SmPinned = Get-SmToolchainChannel

# Baut die geordnete Komponentenliste. Reihenfolge = Abhaengigkeit: erst die
# Werkzeuge, dann Docker und Daemon, dann Datenbank, zuletzt der Build.
function Get-SmComponents {
    $components = New-Object System.Collections.ArrayList

    [void]$components.Add([pscustomobject]@{
        Key = 'winget'; Name = 'winget (Paketmanager)'; Kind = 'tool'
        Why = 'Installiert Rust, Docker und die Build Tools'
        Optional = $false
        Check = {
            if (Test-SmHave 'winget') { New-SmStatus 'ok' 'vorhanden' }
            else { New-SmStatus 'missing' 'fehlt; App Installer aus dem Microsoft Store noetig' }
        }
        Fix = { param($log)
            & $log 'winget laesst sich nicht automatisch installieren.'
            & $log 'Bitte "App Installer" aus dem Microsoft Store installieren und erneut starten.'
            return $false
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'rust'; Name = 'Rust (cargo)'; Kind = 'tool'
        Why = 'Baut Dienste, Clients und den Krypto-Kern'
        Optional = $false
        Check = {
            $rustup = Get-SmRustupExe
            if (-not (Test-SmHave 'cargo')) { return New-SmStatus 'missing' 'cargo nicht im PATH' }
            if ($script:SmPinned -and $rustup) {
                & $rustup run $script:SmPinned rustc --version *> $null
                if ($LASTEXITCODE -ne 0) { return New-SmStatus 'outdated' "Toolchain $script:SmPinned fehlt oder ist beschaedigt" }
                return New-SmStatus 'ok' "cargo mit Toolchain $script:SmPinned"
            }
            New-SmStatus 'ok' 'cargo vorhanden'
        }
        Fix = { param($log)
            $rustup = Get-SmRustupExe
            if (-not (Test-SmHave 'cargo') -and -not $rustup) {
                & $log 'Installiere Rust ueber winget (rustup)...'
                winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements
                Initialize-SmEnv
                $rustup = Get-SmRustupExe
            }
            if ($script:SmPinned -and $rustup) {
                & $log "Installiere/repariere Toolchain $script:SmPinned (Download dauert einige Minuten)..."
                # Erst deinstallieren: eine beschaedigte Toolchain ("Missing
                # manifest") repariert 'toolchain install' NICHT, nur ein
                # sauberer Neustand hilft. Ist sie gar nicht installiert, ist
                # die Deinstallation ein harmloser No-op.
                & $rustup toolchain uninstall "$script:SmPinned-x86_64-pc-windows-msvc" *> $null
                & $rustup toolchain install $script:SmPinned --component rustfmt --component clippy
                & $rustup run $script:SmPinned rustc --version *> $null
                return ($LASTEXITCODE -eq 0)
            }
            return (Test-SmHave 'cargo')
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'components'; Name = 'rustfmt und clippy'; Kind = 'tool'
        Why = 'Format- und Lint-Pruefung'
        Optional = $true
        Check = {
            $rustup = Get-SmRustupExe
            if (-not $rustup) { return New-SmStatus 'unknown' 'rustup nicht gefunden' }
            $installed = & $rustup component list --installed 2>$null
            $ok = ($installed -match 'rustfmt') -and ($installed -match 'clippy')
            if ($ok) { New-SmStatus 'ok' 'vorhanden' } else { New-SmStatus 'missing' 'rustfmt oder clippy fehlt' }
        }
        Fix = { param($log)
            $rustup = Get-SmRustupExe
            if (-not $rustup) { return $false }
            & $log 'Ergaenze rustfmt und clippy...'
            & $rustup component add rustfmt clippy *> $null
            return $true
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'msvc'; Name = 'C++ Build Tools (link.exe)'; Kind = 'tool'
        Why = 'Der Linker fuer das MSVC-Rust-Target'
        Optional = $false
        Check = {
            if (Test-SmMsvcLinker) { New-SmStatus 'ok' 'link.exe gefunden' }
            else { New-SmStatus 'missing' 'link.exe fehlt' }
        }
        Fix = { param($log)
            & $log 'Installiere die C++ Build Tools ueber winget (mehrere GB, dauert; UAC bestaetigen)...'
            winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --override '--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
            return (Test-SmMsvcLinker)
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'wasm'; Name = 'wasm32-Target'; Kind = 'tool'
        Why = 'Baut den Web-Client (clients/web)'
        Optional = $false
        Check = {
            $rustup = Get-SmRustupExe
            if (-not ($script:SmPinned -and $rustup)) { return New-SmStatus 'unknown' 'Toolchain-Pin oder rustup fehlt' }
            $targets = & $rustup target list --installed --toolchain $script:SmPinned 2>$null
            if ($targets -contains 'wasm32-unknown-unknown') { New-SmStatus 'ok' 'installiert' }
            else { New-SmStatus 'missing' 'wasm32-unknown-unknown fehlt' }
        }
        Fix = { param($log)
            $rustup = Get-SmRustupExe
            if (-not ($script:SmPinned -and $rustup)) { return $false }
            & $log "Installiere wasm32-unknown-unknown fuer $script:SmPinned..."
            & $rustup target add wasm32-unknown-unknown --toolchain $script:SmPinned
            return $true
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'trunk'; Name = 'trunk (Web-Buendler)'; Kind = 'tool'
        Why = 'Serviert und baut den Web-Client'
        Optional = $false
        Check = {
            $trunkExe = Join-Path $env:USERPROFILE '.cargo\bin\trunk.exe'
            if ((Test-SmHave 'trunk') -or (Test-Path $trunkExe)) { New-SmStatus 'ok' 'vorhanden' }
            else { New-SmStatus 'missing' 'fehlt' }
        }
        Fix = { param($log)
            $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
            $trunkExe = Join-Path $cargoBin 'trunk.exe'
            & $log 'Lade das trunk-Windows-Binary von GitHub...'
            try {
                $rel = Invoke-RestMethod https://api.github.com/repos/trunk-rs/trunk/releases/latest
                $asset = $rel.assets | Where-Object name -like '*x86_64-pc-windows-msvc.zip' | Select-Object -First 1
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$env:TEMP\trunk.zip"
                if (-not (Test-Path $cargoBin)) { New-Item -ItemType Directory -Force -Path $cargoBin | Out-Null }
                Expand-Archive -Path "$env:TEMP\trunk.zip" -DestinationPath $cargoBin -Force
                return (Test-Path $trunkExe)
            } catch { & $log "trunk-Download fehlgeschlagen: $_"; return $false }
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'protoc'; Name = 'protoc (Protobuf-Compiler)'; Kind = 'tool'
        Why = 'Der Krypto-Kern kompiliert libsignals Protobuf-Schemas'
        Optional = $false
        Check = {
            $protocExe = Join-Path $env:LOCALAPPDATA 'protoc\bin\protoc.exe'
            if ((Test-SmHave 'protoc') -or (Test-Path $protocExe)) { New-SmStatus 'ok' 'vorhanden' }
            else { New-SmStatus 'missing' 'fehlt' }
        }
        Fix = { param($log)
            $protocDir = Join-Path $env:LOCALAPPDATA 'protoc'
            $protocExe = Join-Path $protocDir 'bin\protoc.exe'
            & $log 'Lade das protoc-Windows-Paket von GitHub...'
            try {
                $rel = Invoke-RestMethod https://api.github.com/repos/protocolbuffers/protobuf/releases/latest
                $asset = $rel.assets | Where-Object name -like 'protoc-*-win64.zip' | Select-Object -First 1
                New-Item -ItemType Directory -Force -Path $protocDir | Out-Null
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$env:TEMP\protoc.zip"
                Expand-Archive -Path "$env:TEMP\protoc.zip" -DestinationPath $protocDir -Force
                $env:PROTOC = $protocExe
                return (Test-Path $protocExe)
            } catch { & $log "protoc-Download fehlgeschlagen: $_"; return $false }
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'docker'; Name = 'Docker Desktop'; Kind = 'tool'
        Why = 'Container fuer PostgreSQL und die Dienst-Images'
        Optional = $false
        Check = {
            if (Test-SmHave 'docker') { New-SmStatus 'ok' 'Client vorhanden' }
            else { New-SmStatus 'missing' 'fehlt' }
        }
        Fix = { param($log)
            & $log 'Installiere Docker Desktop ueber winget...'
            winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
            Initialize-SmEnv
            & $log 'Docker Desktop installiert. Eventuell ist ein Windows-Neustart noetig.'
            return (Test-SmHave 'docker')
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'wsl'; Name = 'WSL (Docker-Backend)'; Kind = 'tool'
        Why = 'Docker Desktop laeuft ueber WSL2'
        Optional = $false
        Check = {
            if (-not (Test-SmHave 'wsl')) { return New-SmStatus 'missing' 'wsl.exe nicht gefunden' }
            wsl.exe --status *> $null
            if ($LASTEXITCODE -eq 0) { New-SmStatus 'ok' 'vorhanden' } else { New-SmStatus 'missing' 'WSL nicht eingerichtet' }
        }
        Fix = { param($log)
            & $log 'Installiere die WSL-Plattform (Adminrechte, UAC-Abfrage erscheint)...'
            try {
                Start-Process wsl.exe -Verb RunAs -ArgumentList '--install', '--no-distribution' -Wait
                wsl.exe --status *> $null
                if ($LASTEXITCODE -ne 0) { & $log 'WSL installiert, wirkt aber erst nach einem Windows-Neustart.' }
                return $true
            } catch { & $log 'WSL-Installation abgelehnt oder fehlgeschlagen.'; return $false }
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'daemon'; Name = 'Docker-Daemon'; Kind = 'service'
        Why = 'Muss laufen, damit Container starten'
        Optional = $false
        Check = {
            if (Test-SmDockerDaemon) { New-SmStatus 'ok' 'laeuft' }
            else { New-SmStatus 'missing' 'nicht erreichbar' }
        }
        Fix = { param($log)
            if (Test-SmDockerDaemon) { return $true }
            & $log 'Starte Docker Desktop...'
            $dd = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
            if (-not (Test-Path $dd)) { & $log 'Docker Desktop nicht gefunden.'; return $false }
            # Haengengebliebene Prozesse eines gescheiterten Starts nehmen
            # den neuen Start sonst nicht an, und verwaiste Sockets lassen
            # ihn im Fehlerdialog sterben.
            Get-Process | Where-Object { $_.Name -like '*docker*' } |
                Stop-Process -Force -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Clear-SmStaleDockerSockets
            Start-Process $dd | Out-Null
            for ($i = 0; $i -lt 90; $i++) {
                Start-Sleep -Seconds 2
                if (Test-SmDockerDaemon) {
                    & $log 'Docker-Daemon laeuft jetzt.'
                    # Model Runner abschalten, sobald der Daemon steht: er ist
                    # die Ursache der wiederkehrenden Socket-Abstuerze.
                    Disable-SmModelRunner
                    return $true
                }
            }
            & $log 'Daemon nicht rechtzeitig bereit; Docker Desktop manuell pruefen.'
            return $false
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'postgres'; Name = 'Entwicklungs-Datenbank (sm-postgres)'; Kind = 'service'
        Why = 'PostgreSQL-Container mit einer Datenbank je Dienst'
        Optional = $false
        Check = {
            if (-not (Test-SmDockerDaemon)) { return New-SmStatus 'unknown' 'Docker-Daemon noch nicht erreichbar' }
            $running = docker ps --filter 'name=^sm-postgres$' --format '{{.Names}}' 2>$null
            if ($running) { New-SmStatus 'ok' 'Container laeuft' } else { New-SmStatus 'missing' 'Container fehlt oder ist gestoppt' }
        }
        Fix = { param($log)
            if (-not (Test-SmDockerDaemon)) { & $log 'Docker-Daemon nicht erreichbar.'; return $false }
            $existing = docker ps -a --filter 'name=^sm-postgres$' --format '{{.Names}}' 2>$null
            if (-not $existing) {
                & $log 'Starte postgres:17-alpine als sm-postgres (Port 5432)...'
                docker run -d --name sm-postgres -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=identity -p 5432:5432 postgres:17-alpine *> $null
            } elseif (-not (docker ps --filter 'name=^sm-postgres$' --format '{{.Names}}' 2>$null)) {
                & $log 'Starte den vorhandenen sm-postgres-Container...'
                docker start sm-postgres *> $null
            }
            $ready = $false
            for ($i = 0; $i -lt 30; $i++) {
                docker exec sm-postgres pg_isready -U postgres *> $null
                if ($LASTEXITCODE -eq 0) { $ready = $true; break }
                Start-Sleep -Seconds 1
            }
            if (-not $ready) { & $log 'PostgreSQL nicht rechtzeitig bereit.'; return $false }
            foreach ($db in @('identity', 'directory', 'delivery', 'integrations', 'kt')) {
                $exists = docker exec sm-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$db'" 2>$null
                if ("$exists".Trim() -ne '1') {
                    docker exec sm-postgres psql -U postgres -c "CREATE DATABASE $db" *> $null
                    & $log "Datenbank $db angelegt."
                }
            }
            return $true
        }
    })

    [void]$components.Add([pscustomobject]@{
        Key = 'build'; Name = 'Programme gebaut und aktuell'; Kind = 'build'
        Why = 'Dienste und CLI aus dem aktuellen Quellstand'
        Optional = $false
        Check = {
            $binDir = Join-Path $script:SmRoot 'target\debug'
            $times = @()
            foreach ($bin in $script:SmBinaries) {
                $p = Join-Path $binDir "$bin.exe"
                if (-not (Test-Path $p)) { return New-SmStatus 'outdated' "noch nicht gebaut ($bin fehlt)" }
                $times += (Get-Item $p).LastWriteTime
            }
            $oldestBinary = ($times | Sort-Object | Select-Object -First 1)
            $newestSource = Get-SmNewestSourceTime
            if ($newestSource -gt $oldestBinary) { New-SmStatus 'outdated' 'Quelltext ist neuer als der letzte Build' }
            else { New-SmStatus 'ok' 'aktuell' }
        }
        Fix = { param($log)
            Initialize-SmEnv
            & $log 'Baue Dienste und CLI (cargo build, erster Lauf dauert)...'
            Push-Location $script:SmRoot
            $buildArgs = @('build')
            foreach ($p in $script:SmBuildPackages) { $buildArgs += @('-p', $p) }
            & cargo @buildArgs
            $ok = ($LASTEXITCODE -eq 0)
            Pop-Location
            if ($ok) { & $log 'Build fertig.' } else { & $log 'Build fehlgeschlagen.' }
            return $ok
        }
    })

    return $components.ToArray()
}

# Fuehrt den Check einer Komponente aus und liefert ein flaches Statusobjekt
# mit allen Anzeigefeldern. Fehler im Check werden zu 'unknown', damit ein
# einzelner harter Fall nicht den ganzen Durchlauf kippt.
function Test-SmComponent($component) {
    try {
        $status = & $component.Check
    } catch {
        $status = New-SmStatus 'unknown' "Pruefung fehlgeschlagen: $_"
    }
    return [pscustomobject]@{
        Key = $component.Key; Name = $component.Name; Why = $component.Why
        Kind = $component.Kind; Optional = $component.Optional
        State = $status.State; Detail = $status.Detail
    }
}
