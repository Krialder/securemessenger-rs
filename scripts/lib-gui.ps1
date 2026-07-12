<#
  Gemeinsame WPF-Bausteine der beiden grafischen Einstiege.

  BIBLIOTHEK, nicht direkt starten: wird per Dot-Sourcing (`. lib-gui.ps1`)
  von install-gui.ps1 und start-gui.ps1 eingebunden.

  Enthaelt das Farbthema im Stil des Web-Clients (Segoe UI als System-Schrift
  unter Windows, das Blau #0078D7 aus der App, abgerundete Ecken), einen
  XAML-Lader und die Hintergrund-Mechanik. Letztere ist noetig, weil die
  langen Schritte (winget, cargo build, Docker) die Oberflaeche einfrieren
  wuerden, liefen sie auf dem UI-Thread. Loesung: ein Arbeits-Runspace
  erledigt die Schritte, meldet Fortschritt ueber eine synchronisierte
  Warteschlange, und ein DispatcherTimer auf dem UI-Thread leert sie und
  aktualisiert die Anzeige. Das ist das uebliche, verlaessliche Muster fuer
  WPF unter Windows PowerShell.
#>

Set-StrictMode -Off

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# Farbthema. Die Werte spiegeln clients/web/index.html: Akzent-Blau
# rgba(0,120,215) = #0078D7, Zeilenhintergrund wie die Chat-Blasen
# rgba(127,127,127,0.15). Bewusst hell mit blauem Akzent, statt die
# OS-Theme-Erkennung nachzubauen; das haelt die Oberflaeche schlicht.
$script:SmTheme = @{
    Accent     = '#0078D7'
    AccentDark = '#005A9E'
    Bg         = '#FBFBFD'
    Card       = '#FFFFFF'
    Row        = '#F2F3F5'
    Text       = '#1B1B1F'
    Muted      = '#6B6B70'
    Ok         = '#1A8A3B'
    Warn       = '#B4690E'
    Bad        = '#C42B1C'
    Border     = '#E1E1E6'
}

# Laedt ein XAML-Fragment zu einem WPF-Window. Kein Code-Behind: Ereignisse
# werden danach in PowerShell ueber .Add_*(...) verdrahtet, Elemente ueber
# FindName geholt.
function Read-SmXaml([string]$xaml) {
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    return [Windows.Markup.XamlReader]::Load($reader)
}

# Fuehrt einen Codeblock auf dem UI-Thread aus (fuer Aktualisierungen aus
# Ereignis-Handlern heraus, die schon dort laufen, ist es ein direkter Aufruf).
function Invoke-SmOnUi($window, [scriptblock]$block) {
    $window.Dispatcher.Invoke([action]$block)
}

# Eine threadsichere Warteschlange fuer die Fortschrittsmeldungen zwischen
# Arbeits-Runspace und UI-Thread. Der Komma-Operator ist noetig, weil eine
# Queue aufzaehlbar ist: ohne ihn entrollt PowerShell die (leere) Queue beim
# Rueckgeben zu nichts, und der Aufrufer bekaeme $null.
function New-SmQueue {
    $queue = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
    return , $queue
}

# Startet einen Codeblock in einem eigenen Runspace. Der Block bekommt die
# uebergebenen Variablen (u. a. die synchronisierte Queue und das
# Skriptverzeichnis) gesetzt und laeuft, ohne den UI-Thread zu blockieren.
# Rueckgabe ist ein Handle zum Aufraeumen.
function Start-SmJob([string]$scriptText, [hashtable]$variables) {
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    foreach ($k in $variables.Keys) {
        $runspace.SessionStateProxy.SetVariable($k, $variables[$k])
    }
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript($scriptText)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{ PowerShell = $ps; Handle = $handle; Runspace = $runspace }
}

function Stop-SmJob($job) {
    if (-not $job) { return }
    try { $job.PowerShell.EndInvoke($job.Handle) } catch {}
    try { $job.PowerShell.Dispose() } catch {}
    try { $job.Runspace.Close(); $job.Runspace.Dispose() } catch {}
}

# Haengt einen DispatcherTimer an das Fenster, der die Queue viermal pro
# Sekunde leert und fuer jede Meldung den uebergebenen Handler aufruft. Der
# Handler laeuft auf dem UI-Thread und darf die Oberflaeche direkt anfassen.
function Register-SmQueuePump($window, $queue, [scriptblock]$onMessage) {
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.Add_Tick({
        while ($queue.Count -gt 0) {
            $msg = $queue.Dequeue()
            & $onMessage $msg
        }
    }.GetNewClosure())
    $timer.Start()
    return $timer
}

# Baut die abgerundete Statuszeile einer Komponente als WPF-Element und gibt
# die veraenderlichen Teile (Symbol, Detailtext) zum spaeteren Aktualisieren
# zurueck. Ein Symbol statt eines Bildes haelt die Oberflaeche
# abhaengigkeitsfrei: Punkt (offen), Sanduhr (laeuft), Haken (ok), Kreuz
# (Fehler).
function New-SmRow($component) {
    $border = New-Object System.Windows.Controls.Border
    $border.Background = (New-SmBrush $script:SmTheme.Row)
    $border.CornerRadius = [System.Windows.CornerRadius]::new(8)
    $border.Padding = [System.Windows.Thickness]::new(12, 9, 12, 9)
    $border.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)

    $grid = New-Object System.Windows.Controls.Grid
    $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = 'Auto'
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = '*'
    $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = 'Auto'
    $grid.ColumnDefinitions.Add($c0); $grid.ColumnDefinitions.Add($c1); $grid.ColumnDefinitions.Add($c2)

    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text = [char]0x2022  # Punkt
    $icon.FontSize = 18
    $icon.Width = 24
    $icon.VerticalAlignment = 'Center'
    $icon.Foreground = (New-SmBrush $script:SmTheme.Muted)
    [System.Windows.Controls.Grid]::SetColumn($icon, 0)

    $texts = New-Object System.Windows.Controls.StackPanel
    [System.Windows.Controls.Grid]::SetColumn($texts, 1)
    $name = New-Object System.Windows.Controls.TextBlock
    $name.Text = $component.Name
    $name.FontWeight = 'SemiBold'
    $name.Foreground = (New-SmBrush $script:SmTheme.Text)
    $detail = New-Object System.Windows.Controls.TextBlock
    $detail.Text = $component.Why
    $detail.FontSize = 12
    $detail.TextWrapping = 'Wrap'
    $detail.Foreground = (New-SmBrush $script:SmTheme.Muted)
    [void]$texts.Children.Add($name)
    [void]$texts.Children.Add($detail)

    # Optionale rechte Spalte (z. B. Checkbox) haengt der Aufrufer selbst ein.
    $slot = New-Object System.Windows.Controls.ContentControl
    [System.Windows.Controls.Grid]::SetColumn($slot, 2)
    $slot.VerticalAlignment = 'Center'

    [void]$grid.Children.Add($icon)
    [void]$grid.Children.Add($texts)
    [void]$grid.Children.Add($slot)
    $border.Child = $grid

    return [pscustomobject]@{
        Key = $component.Key; Element = $border; Icon = $icon; Detail = $detail; Slot = $slot
    }
}

function New-SmBrush([string]$hex) {
    return New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($hex))
}

# Setzt Symbol und Farbe einer Zeile nach dem Zustand.
function Set-SmRowState($row, [string]$state, [string]$detail) {
    switch ($state) {
        'ok'       { $row.Icon.Text = [char]0x2713; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Ok) }   # Haken
        'running'  { $row.Icon.Text = [char]0x231B; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Accent) } # Sanduhr
        'missing'  { $row.Icon.Text = [char]0x2715; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Bad) }   # Kreuz
        'outdated' { $row.Icon.Text = [char]0x21BB; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Warn) }  # Kreis-Pfeil
        'failed'   { $row.Icon.Text = [char]0x2715; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Bad) }
        default    { $row.Icon.Text = [char]0x2022; $row.Icon.Foreground = (New-SmBrush $script:SmTheme.Muted) }
    }
    if ($detail) { $row.Detail.Text = $detail }
}
