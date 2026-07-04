<#
  Grafischer Alltags-Start.

  Prueft beim Oeffnen, ob die Umgebung stimmt und aktuell ist, und bietet je
  nach Befund an: fehlen schwere Werkzeuge (winget, Rust, MSVC, WSL, Docker),
  verweist es auf den Installations-Assistenten; sind nur Kleinigkeiten
  veraltet (Format-Komponenten, wasm-Target, trunk, protoc, Projekt-Build),
  bekommen sie eine Haken-Auswahl "aktualisieren"; ist alles gut, startet es
  einfach. Docker-Daemon und Datenbank werden beim Start ohnehin hochgefahren.

  Der eigentliche Start laeuft ueber scripts\demo.ps1 (die eine Startlogik,
  geteilt mit der Konsolen-Vorfuehrung): im Alltag mit -Solo (ein
  Messenger-Fenster auf http://localhost:3000), im Vorfuehrmodus zusaetzlich
  Bob auf 3001.

  Mit -SelfTest wird nur das Fenster aufgebaut und wieder geschlossen; mit
  -ScanTest laeuft zusaetzlich der Scan ueber die echte Pump-Mechanik durch
  (fuer den automatisierten Test, ohne die Oberflaeche interaktiv zu zeigen).
#>
param([switch]$SelfTest, [switch]$ScanTest)

$ErrorActionPreference = 'Stop'
$scriptsDir = $PSScriptRoot
. (Join-Path $scriptsDir 'lib-gui.ps1')
. (Join-Path $scriptsDir 'lib-checks.ps1')
Initialize-SmEnv

# Klassen je Komponente: schwere Werkzeuge blockieren und verweisen auf die
# Installation; Dienste werden beim Start automatisch hochgefahren; alles
# uebrige ist im Alltag aktualisierbar.
$script:SmHeavy = @('winget', 'rust', 'msvc', 'wsl', 'docker')
$script:SmService = @('daemon', 'postgres')

$t = $script:SmTheme
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SecureMessenger" Height="640" Width="580"
        WindowStartupLocation="CenterScreen" Background="$($t.Bg)"
        FontFamily="Segoe UI" ResizeMode="CanMinimize">
  <Grid Margin="20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,14">
      <TextBlock Text="SecureMessenger" FontSize="22" FontWeight="Bold" Foreground="$($t.Text)"/>
      <TextBlock x:Name="Subtitle" Text="Pruefe die Umgebung..." FontSize="13"
                 Foreground="$($t.Muted)" Margin="0,2,0,0"/>
    </StackPanel>

    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
      <StackPanel x:Name="RowsPanel"/>
    </ScrollViewer>

    <StackPanel Grid.Row="2" Margin="0,12,0,0">
      <TextBlock x:Name="StatusLine" Text="" FontSize="13" Foreground="$($t.Muted)" Margin="0,0,0,4"/>
      <ProgressBar x:Name="Progress" Height="6" Minimum="0" Maximum="100" Value="0"
                   Foreground="$($t.Accent)" Background="$($t.Border)" BorderThickness="0"/>
    </StackPanel>

    <Expander Grid.Row="3" Header="Protokoll" Margin="0,10,0,0" Foreground="$($t.Muted)">
      <TextBox x:Name="LogBox" Height="110" IsReadOnly="True" TextWrapping="Wrap"
               VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"
               Background="$($t.Card)" BorderBrush="$($t.Border)"/>
    </Expander>

    <Grid Grid.Row="4" Margin="0,14,0,0">
      <CheckBox x:Name="DemoMode" Content="Vorfuehrmodus (Alice und Bob)" VerticalAlignment="Center"
                Foreground="$($t.Muted)"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="InstallerBtn" Content="Installation oeffnen" Visibility="Collapsed" Width="150" Height="36"
                Margin="0,0,10,0" Background="$($t.Card)" Foreground="$($t.Text)" BorderBrush="$($t.Border)"/>
        <Button x:Name="StopBtn" Content="Beenden" Visibility="Collapsed" Width="110" Height="36"
                Margin="0,0,10,0" Background="$($t.Card)" Foreground="$($t.Text)" BorderBrush="$($t.Border)"/>
        <Button x:Name="PrimaryBtn" Content="Pruefe..." IsEnabled="False" Width="180" Height="36"
                Background="$($t.Accent)" Foreground="White" BorderThickness="0" FontWeight="SemiBold"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
"@

$window = Read-SmXaml $xaml
$ui = @{
    RowsPanel   = $window.FindName('RowsPanel')
    Subtitle    = $window.FindName('Subtitle')
    StatusLine  = $window.FindName('StatusLine')
    Progress    = $window.FindName('Progress')
    LogBox      = $window.FindName('LogBox')
    Primary     = $window.FindName('PrimaryBtn')
    InstallerBtn= $window.FindName('InstallerBtn')
    StopBtn     = $window.FindName('StopBtn')
    DemoMode    = $window.FindName('DemoMode')
    Window      = $window
    Rows        = @{}
    Checks      = @{}
    States      = @{}
    Timer       = $null
    Job         = $null
    Phase       = 'scanning'   # scanning | ready | working | running
}

foreach ($component in (Get-SmComponents)) {
    $row = New-SmRow $component
    $ui.Rows[$row.Key] = $row
    [void]$ui.RowsPanel.Children.Add($row.Element)
}

$queue = New-SmQueue

# Nach dem Scan die Auswahl aufbauen und den Primaerknopf einstellen.
function Complete-Scan {
    $blocked = $false
    $updatable = 0
    foreach ($key in $ui.Rows.Keys) {
        $state = $ui.States[$key]
        if ($state -eq 'ok') { continue }
        if ($script:SmHeavy -contains $key) { $blocked = $true; continue }
        if ($script:SmService -contains $key) {
            Set-SmRowState $ui.Rows[$key] $state 'wird beim Start hochgefahren'
            continue
        }
        # Aktualisierbar: Haken anbieten (vorausgewaehlt).
        $check = New-Object System.Windows.Controls.CheckBox
        $check.Content = 'aktualisieren'
        $check.IsChecked = $true
        $check.Foreground = (New-SmBrush $script:SmTheme.Accent)
        $ui.Rows[$key].Slot.Content = $check
        $ui.Checks[$key] = $check
        $updatable++
    }

    $ui.Progress.Value = 0
    if ($blocked) {
        $ui.Phase = 'blocked'
        $ui.Subtitle.Text = 'Es fehlen Werkzeuge. Bitte zuerst die Installation ausfuehren.'
        $ui.StatusLine.Text = 'Nicht startbereit.'
        $ui.InstallerBtn.Visibility = 'Visible'
        $ui.Primary.Content = 'Starten'
        $ui.Primary.IsEnabled = $false
    } elseif ($updatable -gt 0) {
        $ui.Phase = 'ready'
        $ui.Subtitle.Text = 'Einige Punkte lassen sich aktualisieren.'
        $ui.StatusLine.Text = ''
        $ui.Primary.Content = 'Aktualisieren und starten'
        $ui.Primary.IsEnabled = $true
    } else {
        $ui.Phase = 'ready'
        $ui.Subtitle.Text = 'Alles bereit.'
        $ui.StatusLine.Text = ''
        $ui.Primary.Content = 'Starten'
        $ui.Primary.IsEnabled = $true
    }
}

$onMessage = {
    param($msg)
    switch ($msg.kind) {
        'status' {
            if ($ui.Rows.ContainsKey($msg.key)) {
                $ui.States[$msg.key] = $msg.state
                Set-SmRowState $ui.Rows[$msg.key] $msg.state $msg.detail
            }
        }
        'log'      { $ui.LogBox.AppendText($msg.text + "`r`n"); $ui.LogBox.ScrollToEnd() }
        'phase'    { $ui.StatusLine.Text = $msg.text }
        'progress' { $ui.Progress.Value = $msg.value }
        'scandone' {
            if ($ui.Timer) { $ui.Timer.Stop() }
            if ($ui.Job) { Stop-SmJob $ui.Job; $ui.Job = $null }
            Complete-Scan
        }
        'launched' {
            $ui.Progress.Value = 100
            if ($ui.Timer) { $ui.Timer.Stop() }
            if ($ui.Job) { Stop-SmJob $ui.Job; $ui.Job = $null }
            $ui.Phase = 'running'
            $urls = if ($msg.solo) { 'http://localhost:3000' } else { 'http://localhost:3000 (Alice), http://localhost:3001 (Bob)' }
            $ui.Subtitle.Text = 'Laeuft. Im Browser geoeffnet.'
            $ui.StatusLine.Text = $urls
            $ui.Primary.Visibility = 'Collapsed'
            $ui.StopBtn.Visibility = 'Visible'
        }
    }
}.GetNewClosure()

# Scan-Codeblock: nur lesen, Status je Komponente melden.
$scanWorker = @'
. (Join-Path $ScriptsDir 'lib-checks.ps1')
Initialize-SmEnv
foreach ($c in (Get-SmComponents)) {
    $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = 'running'; detail = 'pruefe...' })
    $st = Test-SmComponent $c
    $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = $st.State; detail = $st.Detail })
}
$Queue.Enqueue(@{ kind = 'scandone' })
'@

# Start-Codeblock: ausgewaehlte Aktualisierungen erledigen, Docker-Daemon
# sicherstellen, dann ueber demo.ps1 starten (das kuemmert sich um Datenbank,
# Dienste, Web-Client und Browser). Der Build laeuft nur, wenn ausgewaehlt;
# demo.ps1 wird mit -NoBuild aufgerufen, damit nichts doppelt gebaut wird.
$startWorker = @'
. (Join-Path $ScriptsDir 'lib-checks.ps1')
Initialize-SmEnv
$log = { param($t) $Queue.Enqueue(@{ kind = 'log'; text = $t }) }
$comps = @{}
foreach ($c in (Get-SmComponents)) { $comps[$c.Key] = $c }

# 1. Ausgewaehlte Aktualisierungen.
foreach ($key in $Selected) {
    $c = $comps[$key]
    if (-not $c) { continue }
    $Queue.Enqueue(@{ kind = 'phase'; text = "Aktualisiere $($c.Name)..." })
    $Queue.Enqueue(@{ kind = 'status'; key = $key; state = 'running'; detail = 'aktualisiere...' })
    try { [void](& $c.Fix $log) } catch { & $log "Fehler: $_" }
    $after = Test-SmComponent $c
    $Queue.Enqueue(@{ kind = 'status'; key = $key; state = $after.State; detail = $after.Detail })
}

# 2. Docker-Daemon sicherstellen (demo.ps1 setzt ihn voraus).
$daemon = $comps['daemon']
$Queue.Enqueue(@{ kind = 'phase'; text = 'Stelle den Docker-Daemon sicher...' })
$Queue.Enqueue(@{ kind = 'status'; key = 'daemon'; state = 'running'; detail = 'starte...' })
if ((Test-SmComponent $daemon).State -ne 'ok') { try { [void](& $daemon.Fix $log) } catch { & $log "Fehler: $_" } }
$Queue.Enqueue(@{ kind = 'status'; key = 'daemon'; state = (Test-SmComponent $daemon).State; detail = '' })

# 3. Starten ueber demo.ps1.
$Queue.Enqueue(@{ kind = 'phase'; text = 'Starte Dienste und Web-Client...' })
$demo = Join-Path $ScriptsDir 'demo.ps1'
$demoArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $demo, '-Hidden', '-NoBuild', '-OpenBrowser')
if ($Solo) { $demoArgs += '-Solo' }
& powershell @demoArgs 2>&1 | ForEach-Object { $Queue.Enqueue(@{ kind = 'log'; text = "$_" }) }
$Queue.Enqueue(@{ kind = 'launched'; solo = $Solo })
'@

$ui.Primary.Add_Click({
    if ($ui.Phase -ne 'ready') { return }
    $ui.Phase = 'working'
    $ui.Primary.IsEnabled = $false
    $ui.DemoMode.IsEnabled = $false
    $ui.StatusLine.Text = 'Starte...'
    $selected = @()
    foreach ($key in $ui.Checks.Keys) { if ($ui.Checks[$key].IsChecked) { $selected += $key } }
    $solo = -not [bool]$ui.DemoMode.IsChecked
    $ui.Timer = Register-SmQueuePump $ui.Window $queue $onMessage
    $ui.Job = Start-SmJob $startWorker @{ Queue = $queue; ScriptsDir = $scriptsDir; Selected = $selected; Solo = $solo }
}.GetNewClosure())

$ui.InstallerBtn.Add_Click({
    Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', (Join-Path $scriptsDir 'install-gui.ps1') | Out-Null
    $ui.Window.Close()
}.GetNewClosure())

$ui.StopBtn.Add_Click({
    Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $scriptsDir 'demo-stop.ps1') -Wait -WindowStyle Hidden | Out-Null
    $ui.Window.Close()
}.GetNewClosure())

$window.Add_Closed({ if ($ui.Job) { Stop-SmJob $ui.Job } }.GetNewClosure())

if ($SelfTest) {
    Write-Host 'start-gui: Fenster aufgebaut, Selbsttest ok.'
    $window.Close()
    return
}

# Beim Oeffnen sofort den Scan starten.
$ui.Timer = Register-SmQueuePump $window $queue $onMessage
$ui.Job = Start-SmJob $scanWorker @{ Queue = $queue; ScriptsDir = $scriptsDir }

if ($ScanTest) {
    # Den Dispatcher (und damit die Pump-Ticks) laufen lassen, bis der Scan
    # den Zustand aus 'scanning' bewegt hat, dann Ergebnis melden. So laeuft
    # dieselbe Kette wie im echten Betrieb, nur ohne sichtbares Fenster.
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    $deadline = (Get-Date).AddSeconds(40)
    $stopper = New-Object System.Windows.Threading.DispatcherTimer
    $stopper.Interval = [TimeSpan]::FromMilliseconds(300)
    $stopper.Add_Tick({
        if (($ui.Phase -ne 'scanning') -or ((Get-Date) -gt $deadline)) { $frame.Continue = $false }
    }.GetNewClosure())
    $stopper.Start()
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    Write-Host ("ScanTest: phase=$($ui.Phase) primary='$($ui.Primary.Content)' enabled=$($ui.Primary.IsEnabled) installerBtn=$($ui.InstallerBtn.Visibility)")
    Write-Host ("  build-Zeile: $($ui.Rows['build'].Icon.Text) / states erfasst: $($ui.States.Count)")
    $window.Close()
    return
}

[void]$window.ShowDialog()
