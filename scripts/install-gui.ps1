<#
  Grafischer Installations-Assistent (Erststart).

  Oeffnet ein Fenster im Stil des Messengers und laeuft die Einrichtungs-
  schritte ab: Werkzeuge pruefen, Fehlendes installieren, Docker und die
  Datenbank hochfahren, das Projekt bauen. Jeder Schritt zeigt live seinen
  Zustand; die eigentliche Arbeit erledigt die geteilte Pruef-Bibliothek
  (lib-checks.ps1) in einem Hintergrund-Runspace, damit das Fenster waehrend
  langer Schritte (winget, cargo build) bedienbar bleibt.

  Mit -SelfTest baut das Skript nur das Fenster auf und beendet sich wieder
  (fuer den automatisierten Aufbau-Test, ohne die Oberflaeche zu zeigen).
#>
param([switch]$SelfTest)

$ErrorActionPreference = 'Stop'
$scriptsDir = $PSScriptRoot
. (Join-Path $scriptsDir 'lib-gui.ps1')
. (Join-Path $scriptsDir 'lib-checks.ps1')
Initialize-SmEnv

$t = $script:SmTheme
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SecureMessenger einrichten" Height="660" Width="580"
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
      <TextBlock Text="Einrichtung: die noetigen Werkzeuge pruefen und installieren."
                 FontSize="13" Foreground="$($t.Muted)" Margin="0,2,0,0"/>
    </StackPanel>

    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
      <StackPanel x:Name="RowsPanel"/>
    </ScrollViewer>

    <StackPanel Grid.Row="2" Margin="0,12,0,0">
      <TextBlock x:Name="StatusLine" Text="Bereit." FontSize="13" Foreground="$($t.Muted)" Margin="0,0,0,4"/>
      <ProgressBar x:Name="Progress" Height="6" Minimum="0" Maximum="100" Value="0"
                   Foreground="$($t.Accent)" Background="$($t.Border)" BorderThickness="0"/>
    </StackPanel>

    <Expander Grid.Row="3" Header="Protokoll" Margin="0,10,0,0" Foreground="$($t.Muted)">
      <TextBox x:Name="LogBox" Height="120" IsReadOnly="True" TextWrapping="Wrap"
               VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"
               Background="$($t.Card)" BorderBrush="$($t.Border)"/>
    </Expander>

    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="StartBtn" Content="Jetzt starten" IsEnabled="False" Width="130" Height="36"
              Margin="0,0,10,0" Background="$($t.Card)" Foreground="$($t.Text)" BorderBrush="$($t.Border)"/>
      <Button x:Name="PrimaryBtn" Content="Installieren" Width="140" Height="36"
              Background="$($t.Accent)" Foreground="White" BorderThickness="0" FontWeight="SemiBold"/>
    </StackPanel>
  </Grid>
</Window>
"@

$window = Read-SmXaml $xaml
$rowsPanel = $window.FindName('RowsPanel')
$statusLine = $window.FindName('StatusLine')
$progress = $window.FindName('Progress')
$logBox = $window.FindName('LogBox')
$primary = $window.FindName('PrimaryBtn')
$startBtn = $window.FindName('StartBtn')

# Zeilen aus der Komponentenliste bauen und die veraenderlichen Teile je
# Schluessel merken, damit die Queue-Meldungen die richtige Zeile treffen.
$rows = @{}
foreach ($component in (Get-SmComponents)) {
    $row = New-SmRow $component
    $rows[$row.Key] = $row
    [void]$rowsPanel.Children.Add($row.Element)
}

# Gemeinsamer Zustand, den der Queue-Handler anfassen darf. Als Hashtable,
# damit die Closure die spaeter gesetzten Felder (Timer, Job) sieht.
$ui = @{
    Rows = $rows; StatusLine = $statusLine; Progress = $progress; LogBox = $logBox
    Primary = $primary; StartBtn = $startBtn; Window = $window
    Timer = $null; Job = $null; Installing = $false
}

$queue = New-SmQueue

$onMessage = {
    param($msg)
    switch ($msg.kind) {
        'status'   { if ($ui.Rows.ContainsKey($msg.key)) { Set-SmRowState $ui.Rows[$msg.key] $msg.state $msg.detail } }
        'log'      { $ui.LogBox.AppendText($msg.text + "`r`n"); $ui.LogBox.ScrollToEnd() }
        'phase'    { $ui.StatusLine.Text = $msg.text }
        'progress' { $ui.Progress.Value = $msg.value }
        'done'     {
            $ui.Progress.Value = 100
            if ($ui.Timer) { $ui.Timer.Stop() }
            if ($ui.Job) { Stop-SmJob $ui.Job; $ui.Job = $null }
            if ($msg.ok) {
                $ui.StatusLine.Text = 'Einrichtung abgeschlossen. Alles bereit.'
                $ui.StartBtn.IsEnabled = $true
            } else {
                $ui.StatusLine.Text = 'Einige Punkte brauchen noch Aufmerksamkeit (siehe Protokoll).'
            }
            $ui.Primary.Content = 'Fertig'
            $ui.Primary.IsEnabled = $true
            $ui.Installing = $false
        }
    }
}.GetNewClosure()

$ui.Timer = Register-SmQueuePump $window $queue $onMessage

# Der Arbeits-Codeblock im Hintergrund-Runspace: dot-sourced lib-checks,
# laeuft die Komponenten, prueft und repariert, meldet ueber die Queue.
$worker = @'
. (Join-Path $ScriptsDir 'lib-checks.ps1')
Initialize-SmEnv
$comps = Get-SmComponents
$total = $comps.Count
$log = { param($t) $Queue.Enqueue(@{ kind = 'log'; text = $t }) }
$allOk = $true
$i = 0
foreach ($c in $comps) {
    $i++
    $Queue.Enqueue(@{ kind = 'progress'; value = [int](($i - 1) / $total * 100) })
    $Queue.Enqueue(@{ kind = 'phase'; text = "[$i/$total] $($c.Name)" })
    $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = 'running'; detail = 'pruefe...' })
    $st = Test-SmComponent $c
    if ($st.State -eq 'ok') {
        $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = 'ok'; detail = $st.Detail })
        continue
    }
    & $log "==> $($c.Name): $($st.Detail)"
    try { [void](& $c.Fix $log) } catch { & $log "Fehler: $_" }
    $after = Test-SmComponent $c
    if ($after.State -eq 'ok') {
        $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = 'ok'; detail = $after.Detail })
    } else {
        if (-not $c.Optional) { $allOk = $false }
        $Queue.Enqueue(@{ kind = 'status'; key = $c.Key; state = 'failed'; detail = $after.Detail })
        & $log "    offen: $($after.Detail)"
    }
}
$Queue.Enqueue(@{ kind = 'progress'; value = 100 })
$Queue.Enqueue(@{ kind = 'done'; ok = $allOk })
'@

$primary.Add_Click({
    if ($ui.Primary.Content -eq 'Fertig') { $ui.Window.Close(); return }
    if ($ui.Installing) { return }
    $ui.Installing = $true
    $ui.Primary.IsEnabled = $false
    $ui.StatusLine.Text = 'Einrichtung laeuft...'
    foreach ($k in $ui.Rows.Keys) { Set-SmRowState $ui.Rows[$k] 'pending' $null }
    $ui.Job = Start-SmJob $worker @{ Queue = $queue; ScriptsDir = $scriptsDir }
}.GetNewClosure())

$startBtn.Add_Click({
    # Den Alltags-Start oeffnen und den Assistenten schliessen.
    Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', (Join-Path $scriptsDir 'start-gui.ps1') | Out-Null
    $ui.Window.Close()
}.GetNewClosure())

$window.Add_Closed({ if ($ui.Job) { Stop-SmJob $ui.Job } }.GetNewClosure())

if ($SelfTest) {
    Write-Host 'install-gui: Fenster aufgebaut, Selbsttest ok.'
    $window.Close()
    return
}

[void]$window.ShowDialog()
