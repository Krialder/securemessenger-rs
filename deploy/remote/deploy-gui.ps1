<#
  Grafische Server-Auslieferung: ein Fenster, um die Verbindungsdaten des
  Zielservers (Proxmox-VM) einzugeben, einmalig den SSH-Schluessel
  einzurichten und den Stack hochzuladen und zu starten. Nutzt dieselbe
  Engine wie die Konsole (lib-deploy.ps1) und dieselben WPF-Bausteine wie
  die Start-GUI (scripts/lib-gui.ps1).

  Start ueber ServerDeploy.cmd (im Projekt-Root) oder:
    powershell -NoProfile -ExecutionPolicy Bypass -STA -File deploy\remote\deploy-gui.ps1

  -SelfTest baut nur das Fenster auf und schliesst wieder (fuer Pruefungen
  ohne Desktop).
#>
param([switch]$SelfTest)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$deployDir = $PSScriptRoot
$scriptsDir = Join-Path (Split-Path (Split-Path $deployDir -Parent) -Parent) 'scripts'
. (Join-Path $scriptsDir 'lib-gui.ps1')
. (Join-Path $deployDir 'lib-deploy.ps1')

$t = $script:SmTheme
$saved = Get-SmDeployProfile

# Vorbelegung: gespeichertes Profil, sonst sinnvolle Vorgaben.
$vHost = if ($saved) { $saved.TargetHost } else { '' }
$vPort = if ($saved) { "$($saved.Port)" } else { '22' }
$vUser = if ($saved) { $saved.User } else { 'root' }
$vDir = if ($saved) { $saved.TargetDir } else { '/opt/securemessenger' }

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SecureMessenger auf den Server bringen" Width="560" Height="640"
        WindowStartupLocation="CenterScreen" Background="$($t.Bg)" FontFamily="Segoe UI">
  <Grid Margin="20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0">
      <TextBlock Text="Auslieferung auf den Server" FontSize="20" FontWeight="SemiBold" Foreground="$($t.Text)"/>
      <TextBlock x:Name="Subtitle" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="$($t.Muted)"
        Text="Verbindungsdaten der Linux-VM eingeben, einmal den Schluessel einrichten, dann ausliefern. Anleitung zur VM: deploy/remote/README.md."/>
    </StackPanel>

    <Border Grid.Row="1" Background="$($t.Card)" CornerRadius="10" Padding="16" Margin="0,14,0,0" BorderBrush="$($t.Border)" BorderThickness="1">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="130"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.Column="0" Text="Server (IP/Name)" VerticalAlignment="Center" Foreground="$($t.Text)" Margin="0,0,0,8"/>
        <TextBox   Grid.Row="0" Grid.Column="1" x:Name="TbHost" Text="$vHost" Margin="0,0,0,8" Padding="6,4"/>
        <TextBlock Grid.Row="1" Grid.Column="0" Text="SSH-Port" VerticalAlignment="Center" Foreground="$($t.Text)" Margin="0,0,0,8"/>
        <TextBox   Grid.Row="1" Grid.Column="1" x:Name="TbPort" Text="$vPort" Margin="0,0,0,8" Padding="6,4"/>
        <TextBlock Grid.Row="2" Grid.Column="0" Text="SSH-Benutzer" VerticalAlignment="Center" Foreground="$($t.Text)" Margin="0,0,0,8"/>
        <TextBox   Grid.Row="2" Grid.Column="1" x:Name="TbUser" Text="$vUser" Margin="0,0,0,8" Padding="6,4"/>
        <TextBlock Grid.Row="3" Grid.Column="0" Text="Zielordner" VerticalAlignment="Center" Foreground="$($t.Text)" Margin="0,0,0,8"/>
        <TextBox   Grid.Row="3" Grid.Column="1" x:Name="TbDir" Text="$vDir" Margin="0,0,0,8" Padding="6,4"/>
        <StackPanel Grid.Row="4" Grid.Column="1" Orientation="Horizontal" Margin="0,4,0,0">
          <CheckBox x:Name="CbWeb" Content="Web-Client" Foreground="$($t.Text)" Margin="0,0,16,0"/>
          <CheckBox x:Name="CbSso" Content="Keycloak (SSO)" Foreground="$($t.Text)"/>
        </StackPanel>
      </Grid>
    </Border>

    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,14,0,0">
      <Button x:Name="BtnKey" Content="1. Schluessel einrichten" Width="200" Height="38"
        Background="$($t.Card)" Foreground="$($t.Text)" BorderBrush="$($t.Border)"/>
      <Button x:Name="BtnDeploy" Content="2. Ausliefern und starten" Width="220" Height="38" Margin="12,0,0,0"
        Background="$($t.Accent)" Foreground="White" BorderThickness="0" FontWeight="SemiBold"/>
    </StackPanel>

    <Border Grid.Row="3" Background="$($t.Card)" CornerRadius="10" Padding="10" Margin="0,14,0,0" BorderBrush="$($t.Border)" BorderThickness="1">
      <TextBox x:Name="LogBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
        FontFamily="Consolas" FontSize="12" Background="$($t.Card)" BorderThickness="0"/>
    </Border>

    <StackPanel Grid.Row="4" Margin="0,10,0,0">
      <TextBlock x:Name="StatusLine" Text="Bereit." Foreground="$($t.Muted)" Margin="0,0,0,4"/>
      <ProgressBar x:Name="Progress" Height="5" Minimum="0" Maximum="100" Value="0" IsIndeterminate="False"
        Foreground="$($t.Accent)" Background="$($t.Border)" BorderThickness="0"/>
    </StackPanel>
  </Grid>
</Window>
"@

$window = Read-SmXaml $xaml
$ui = @{
    Host = $window.FindName('TbHost'); Port = $window.FindName('TbPort')
    User = $window.FindName('TbUser'); Dir = $window.FindName('TbDir')
    Web = $window.FindName('CbWeb'); Sso = $window.FindName('CbSso')
    Key = $window.FindName('BtnKey'); Deploy = $window.FindName('BtnDeploy')
    Log = $window.FindName('LogBox'); Status = $window.FindName('StatusLine')
    Progress = $window.FindName('Progress'); Window = $window
    Timer = $null; Job = $null
}

function Add-Log($text) { $ui.Log.AppendText("$text`r`n"); $ui.Log.ScrollToEnd() }

# Profil aus den Feldern lesen und speichern; gibt es zurueck.
function Save-FromFields {
    $port = 22; [void][int]::TryParse($ui.Port.Text, [ref]$port)
    $p = New-SmDeployProfile $ui.Host.Text.Trim() $port $ui.User.Text.Trim() $null $ui.Dir.Text.Trim()
    Save-SmDeployProfile $p
    return $p
}

function Set-Busy([bool]$busy) {
    $ui.Key.IsEnabled = -not $busy
    $ui.Deploy.IsEnabled = -not $busy
    $ui.Progress.IsIndeterminate = $busy
}

# Nachrichten aus dem Arbeits-Runspace verarbeiten (UI-Thread).
$onMessage = {
    param($msg)
    switch ($msg.kind) {
        'log'    { Add-Log $msg.text }
        'status' { $ui.Status.Text = $msg.text }
        'done'   {
            if ($ui.Timer) { $ui.Timer.Stop() }
            if ($ui.Job) { Stop-SmJob $ui.Job; $ui.Job = $null }
            Set-Busy $false
            $ui.Progress.Value = 100
            $ui.Status.Text = if ($msg.ok) { 'Fertig.' } else { 'Mit Fehler beendet (Protokoll oben).' }
        }
    }
}.GetNewClosure()

# Schluessel einrichten: braucht die einmalige Passwort-Eingabe, die nur in
# einem echten Konsolenfenster funktioniert (ssh liest das Passwort vom
# Terminal). Darum ein sichtbares Fenster, auf das wir warten.
$ui.Key.Add_Click({
    if (-not $ui.Host.Text.Trim()) { $ui.Status.Text = 'Bitte zuerst den Server eintragen.'; return }
    $p = Save-FromFields
    $ui.Status.Text = 'Schluessel-Einrichtung im Konsolenfenster (Server-Passwort eingeben)...'
    Add-Log "Starte Schluessel-Einrichtung fuer $($p.User)@$($p.TargetHost):$($p.Port)"
    $deployPs1 = Join-Path $deployDir 'deploy.ps1'
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $deployPs1, '-SetupKey',
        '-TargetHost', $p.TargetHost, '-Port', "$($p.Port)", '-User', $p.User, '-TargetDir', $p.TargetDir)
    $proc = Start-Process powershell -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -eq 0) { Add-Log 'Schluessel eingerichtet.'; $ui.Status.Text = 'Schluessel bereit. Jetzt ausliefern.' }
    else { Add-Log 'Schluessel-Einrichtung fehlgeschlagen (siehe das Konsolenfenster).'; $ui.Status.Text = 'Schluessel-Einrichtung fehlgeschlagen.' }
}.GetNewClosure())

# Ausliefern: die Konsole deploy.ps1 im Arbeits-Runspace, Ausgabe in den Log.
$ui.Deploy.Add_Click({
    if (-not $ui.Host.Text.Trim()) { $ui.Status.Text = 'Bitte zuerst den Server eintragen.'; return }
    $p = Save-FromFields
    Set-Busy $true
    $ui.Log.Clear()
    $ui.Status.Text = 'Liefere aus...'
    $deployPs1 = Join-Path $deployDir 'deploy.ps1'
    $worker = @'
$smArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$DeployPs1)
if ($Web) { $smArgs += '-Web' }
if ($Sso) { $smArgs += '-Sso' }
& powershell @smArgs 2>&1 | ForEach-Object { $Queue.Enqueue(@{ kind='log'; text = "$_" }) }
$Queue.Enqueue(@{ kind='done'; ok = ($LASTEXITCODE -eq 0) })
'@
    $queue = New-SmQueue
    $ui.Timer = Register-SmQueuePump $ui.Window $queue $onMessage
    $ui.Job = Start-SmJob $worker @{
        Queue = $queue; DeployPs1 = $deployPs1
        Web = [bool]$ui.Web.IsChecked; Sso = [bool]$ui.Sso.IsChecked
    }
}.GetNewClosure())

$window.Add_Closed({ if ($ui.Job) { Stop-SmJob $ui.Job } }.GetNewClosure())

if ($SelfTest) {
    Write-Host "deploy-gui: Fenster aufgebaut, Selbsttest ok (Felder: $($ui.Host.Text)/$($ui.User.Text))."
    $window.Close()
    return
}

[void]$window.ShowDialog()
