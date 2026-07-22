# Description: Console rendering helpers for the ServerVitals health-check CLI.
# Provides truecolor ANSI output, a gradient banner, an animated spinner and a
# bordered, colour-coded results table. Degrades gracefully with -NoColor.

$e = [char]27                                   # ESC, referenced as ${e} in strings
$script:UseAnsi = $true
$script:Fg = $null
# Is stdout a real terminal? Every in-place redraw needs \r and cursor movement to mean
# something; redirected to a file or CI log they don't, and hundreds of frames pile up on
# one enormous line. Set once at init; Write-Transient and friends no-op when false.
$script:IsTty = $true
$script:SpinnerFrames = @('⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏')

# One layout rule for the whole UI, so nothing sits half a step out of line:
#   column 0 - the section heading marker ($SectionMark) only
#   column 3 - the heading text and every section body under it: plain lines, leading
#              markers (┃, ✔, ●, spinner) and box borders alike
#   column 6 - text following a marker or a box border (marker/border + 2 spaces)
$script:Gutter  = '   '     # -> column 3: the indent of every section body
$script:Gap     = '  '      # between a marker/border and its text
$script:Content = '      '  # -> column 6: continuation lines under a marker's text
$script:BoxPad  = '  '      # inner padding between a box border and its content

# U+258C LEFT HALF BLOCK, not the nicer U+258E quarter block: quarter blocks are absent
# from Consolas and render as tofu. U+258C is CP437, like the █ ░ of the progress bars.
$script:SectionMark = '▌'

# The banner is a masthead, not a section, so it sits flush left above the headings.
$script:BannerGutter = ''

# The check groups HealthCheck.ps1 reports progress for, in run order. Drives both the
# progress bar and the per-check strip, so a new group goes here and in its $Mark call.
$script:ScanSteps = @('OS','HW','USR','SVC','APP','UPD','EVT')

#------------------------------------------------------------------------------
# Initialisation
#------------------------------------------------------------------------------
function Initialize-Palette
{ $mk = { param($r,$g,$b,[switch]$Bold)
          if(-not $script:UseAnsi) { return '' }
          $prefix = if($Bold) { "${e}[1m" } else { '' }
          return "$prefix${e}[38;2;${r};${g};${b}m"
        }
  $script:Fg = @{
      Reset   = if($script:UseAnsi){"${e}[0m"}else{''}
      Bold    = if($script:UseAnsi){"${e}[1m"}else{''}
      Dim     = if($script:UseAnsi){"${e}[2m"}else{''}
      Cyan    = & $mk 56 211 238
      CyanB   = & $mk 56 211 238 -Bold
      Teal    = & $mk 45 212 191
      Green   = & $mk 74 222 128
      GreenB  = & $mk 74 222 128 -Bold
      Yellow  = & $mk 250 204 21
      Red     = & $mk 248 113 113
      RedB    = & $mk 248 113 113 -Bold
      Purple  = & $mk 167 139 250
      PurpleB = & $mk 167 139 250 -Bold
      Blue    = & $mk 96 165 250
      Gray    = & $mk 148 163 184
      White   = & $mk 226 232 240
      WhiteB  = & $mk 226 232 240 -Bold
  }
}

function Initialize-ConsoleUI
{ param([switch]$NoColor)
  # Redirected output can't be redrawn in place, and ANSI colour in a log file is noise.
  # IsOutputRedirected is reliable on both 5.1 and 7; if it's unavailable, assume a terminal.
  try   { $script:IsTty = -not [Console]::IsOutputRedirected }
  catch { $script:IsTty = $true }
  $script:UseAnsi = (-not $NoColor) -and $script:IsTty

  # UTF-8 output, or the box-drawing / braille glyphs render wrong.
  try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

  # Enable virtual-terminal (ANSI) processing for 5.1 / conhost.
  if($script:UseAnsi)
  { try
    { if(-not ('ConUI.NativeVT' -as [type]))
      { Add-Type -Name NativeVT -Namespace ConUI -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern System.IntPtr GetStdHandle(int nStdHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool GetConsoleMode(System.IntPtr hConsoleHandle, out uint lpMode);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool SetConsoleMode(System.IntPtr hConsoleHandle, uint dwMode);
'@ -ErrorAction Stop
      }
      $h = [ConUI.NativeVT]::GetStdHandle(-11)
      [uint32]$mode = 0
      if([ConUI.NativeVT]::GetConsoleMode($h, [ref]$mode))
      { [void][ConUI.NativeVT]::SetConsoleMode($h, $mode -bor 0x0004) }   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    }
    catch { }   # No VT support: ANSI may show literally, nothing fatal.
  }

  Initialize-Palette
}

#------------------------------------------------------------------------------
# Primitives
#------------------------------------------------------------------------------
function Get-UIWidth
{ try { $w = $Host.UI.RawUI.WindowSize.Width; if($w -gt 20) { return [math]::Min($w - 1, 100) } } catch { }
  return 78
}

# The shared right edge for the masthead and every section rule, so they terminate on the
# same column. Full usable width by design: the summary table is capped inside Get-UIWidth,
# so the rules always run past its right edge. 34 is the floor the banner subtitle needs.
function Get-CardWidth
{ return [math]::Max(34, (Get-UIWidth) - $script:BannerGutter.Length) }

function Paint
{ param([string]$Text, [string]$Color = 'White')
  if($script:UseAnsi -and $script:Fg -and $script:Fg.ContainsKey($Color) -and $script:Fg[$Color])
  { return "$($script:Fg[$Color])$Text$($script:Fg.Reset)" }
  return $Text
}

function Format-Cell
{ param([string]$Text, [int]$Width, [string]$Color = 'White',
        [ValidateSet('left','center','right')][string]$Align = 'left')
  if($null -eq $Text) { $Text = '' }
  if($Text.Length -gt $Width)
  { # Middle-ellipsis: host names in a set share a prefix and differ in the suffix
    # (SRV-APP-01 / -02), so a tail cut makes them indistinguishable. Under 5 columns
    # there's no room for that, so fall back to a tail cut.
    if($Width -ge 5)
    { $keepR = [math]::Floor(($Width - 1) / 2)
      $keepL = $Width - 1 - $keepR
      $Text  = $Text.Substring(0, $keepL) + '…' + $Text.Substring($Text.Length - $keepR)
    }
    else { $Text = $Text.Substring(0, $Width) }
  }
  $pad = $Width - $Text.Length
  switch($Align)
  { 'center' { $l = [math]::Floor($pad / 2); $r = $pad - $l; $Text = (' ' * $l) + $Text + (' ' * $r) }
    'right'  { $Text = (' ' * $pad) + $Text }
    default  { $Text = $Text + (' ' * $pad) }
  }
  return (Paint $Text $Color)
}

# Truecolor gradient across a string, one escape per character. Returns it so callers can
# embed it; Write-GradientRule prints it.
function Get-GradientText
{ param([string]$Text, [int[]]$From = @(56,211,238), [int[]]$To = @(167,139,250), [switch]$Bold)
  if(-not $script:UseAnsi) { return $Text }
  $n = $Text.Length
  $sb = [System.Text.StringBuilder]::new()
  if($Bold) { [void]$sb.Append("${e}[1m") }
  for($i = 0; $i -lt $n; $i++)
  { $t = if($n -le 1) { 0 } else { $i / ($n - 1) }
    $r = [int]($From[0] + ($To[0] - $From[0]) * $t)
    $g = [int]($From[1] + ($To[1] - $From[1]) * $t)
    $b = [int]($From[2] + ($To[2] - $From[2]) * $t)
    [void]$sb.Append("${e}[38;2;${r};${g};${b}m" + $Text[$i])
  }
  [void]$sb.Append($script:Fg.Reset)
  return $sb.ToString()
}

function Write-GradientRule
{ param([int]$Width = 60, [string]$Char = '─', [string]$Text,
        [int[]]$From = @(56,211,238), [int[]]$To = @(167,139,250))
  if(-not $Text) { $Text = ($Char * $Width) }
  Write-Host (Get-GradientText -Text $Text -From $From -To $To)
}

#------------------------------------------------------------------------------
# Transient (redrawn) vs permanent lines
#------------------------------------------------------------------------------
function Write-Transient
{ param([string]$Text)
  # A frame is meant to be overwritten, and a file keeps every one. Drop them rather than
  # emit hundreds of \r-joined copies of one line into a log.
  if(-not $script:IsTty) { return }
  if($script:UseAnsi) { Write-Host ("${e}[2K`r" + $Text) -NoNewline }
  else                { Write-Host ("`r" + $Text + (' ' * 8)) -NoNewline }
}

function Write-Permanent
{ param([string]$Text)
  if(-not $script:IsTty) { Write-Host $Text; return }   # no line to erase when redirected
  if($script:UseAnsi) { Write-Host ("${e}[2K`r" + $Text) }
  else                { Write-Host ("`r" + $Text) }
}

function Get-SpinnerFrame
{ param([int]$Index)
  return $script:SpinnerFrames[$Index % $script:SpinnerFrames.Count]
}

# Erase a multi-line transient block, leaving the cursor on its first line so the next
# frame overwrites it. Without ANSI there is no cursor movement, only the current line.
function Clear-TransientBlock
{ param([int]$Lines = 2)
  if(-not $script:IsTty)   { return }   # nothing was drawn, nothing to erase
  if(-not $script:UseAnsi) { Write-Host ("`r" + (' ' * 100) + "`r") -NoNewline; return }
  $sb = "${e}[2K"
  for($i = 1; $i -lt $Lines; $i++) { $sb += "`n${e}[2K" }
  if($Lines -gt 1) { $sb += "${e}[$($Lines - 1)A" }
  Write-Host ($sb + "`r") -NoNewline
}

function Get-ProgressBar
{ param([double]$Fraction, [int]$Width = 14, [string]$Color = 'Cyan')
  if($Fraction -lt 0) { $Fraction = 0 } elseif($Fraction -gt 1) { $Fraction = 1 }
  $filled = [int][math]::Round($Width * $Fraction)
  return (Paint ('█' * $filled) $Color) + (Paint ('░' * ($Width - $filled)) 'Dim')
}

#------------------------------------------------------------------------------
# Status lines (styled replacement for raw timestamped log echo)
#------------------------------------------------------------------------------
function Write-Status
{ param([string]$Text, [ValidateSet('info','ok','warn','error')][string]$Level = 'info', [string]$Detail)
  switch($Level)
  { 'ok'    { $sym = '✔'; $accent = 'Green';  $col = 'White' }
    'warn'  { $sym = '▲'; $accent = 'Yellow'; $col = 'Yellow' }
    'error' { $sym = '✗'; $accent = 'Red';    $col = 'Red' }
    default { $sym = '›'; $accent = 'Cyan';   $col = 'Gray' }
  }
  Write-Host ($script:Gutter + (Paint $sym $accent) + $script:Gap + (Paint $Text $col))

  # -Detail hangs a second line off the marker on an elbow, so an over-long message still
  # reads as one group. The elbow takes the marker's colour to bind them; detail stays gray.
  if($Detail)
  { Write-Host ($script:Gutter + (Paint '╰─' $accent) + ' ' + (Paint $Detail 'Gray')) }
}

# Read-Host with the marker + indent of the status lines around it, so a prompt doesn't
# break the section's column. Throws like Read-Host when non-interactive; callers catch it.
function Read-Prompt
{ param([string]$Text)
  return Read-Host ($script:Gutter + (Paint '?' 'Yellow') + $script:Gap + (Paint $Text 'White'))
}

#------------------------------------------------------------------------------
# Banner
#------------------------------------------------------------------------------
# A framed header card: rounded gradient border, gradient wordmark, subtitle / version on
# the right edge. Rows carry a plain-text twin because padding must be measured on visible
# characters only - the rendered strings are mostly zero-width ANSI.
function Show-Banner
{ param([string]$Version = '1.0.0')

  $avail = (Get-CardWidth) - 2        # the shared card width, minus its two borders

  $rows = @(
    @{ PlainL = 'ServerVitals'
       TextL  = Get-GradientText 'ServerVitals' -Bold
       PlainR = 'Console Edition'
       TextR  = Paint 'Console Edition' 'Teal' }
    @{ PlainL = 'Windows server health check'
       TextL  = Paint 'Windows server health check' 'Gray'
       PlainR = "v$Version"
       TextR  = Paint "v$Version" 'Dim' }
  )

  # Widest row decides the card; a row occupies BoxPad + left + >=1 space + right + BoxPad.
  $fixed  = (2 * $script:BoxPad.Length) + 1
  $needed = 0
  foreach($r in $rows) { $n = $r.PlainL.Length + $r.PlainR.Length + $fixed; if($n -gt $needed) { $needed = $n } }
  if($avail -lt $needed)
  { # Too narrow for both: keep the wordmark, drop the right-hand column rather than wrap.
    foreach($r in $rows) { $r.PlainR = ''; $r.TextR = '' }
    $needed = 0
    foreach($r in $rows) { $n = $r.PlainL.Length + $fixed; if($n -gt $needed) { $needed = $n } }
  }
  $inner = [math]::Max($needed, $avail)

  $bl = Paint '│' 'Cyan'              # borders take the two ends of the gradient
  $br = Paint '│' 'Purple'

  Write-Host ''
  Write-Host ($script:BannerGutter + (Get-GradientText ('╭' + ('─' * $inner) + '╮')))
  foreach($r in $rows)
  { $pad = $inner - (2 * $script:BoxPad.Length) - $r.PlainL.Length - $r.PlainR.Length
    if($pad -lt 1) { $pad = 1 }
    Write-Host ($script:BannerGutter + $bl + $script:BoxPad + $r.TextL + (' ' * $pad) + $r.TextR + $script:BoxPad + $br)
  }
  Write-Host ($script:BannerGutter + (Get-GradientText ('╰' + ('─' * $inner) + '╯')))
  Write-Host ''
}

#------------------------------------------------------------------------------
# Info panel (key / value)
#------------------------------------------------------------------------------
function Show-InfoPanel
{ param([Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Data)
  # Marker + key/value, so these rows share the column of the status lines above. The
  # marker is faint by design: these are static facts, not events.
  $dot = Paint '·' 'Gray'
  foreach($key in $Data.Keys)
  { $label = Paint ($key.PadRight(10)) 'Gray'
    $value = Paint ([string]$Data[$key]) 'White'
    Write-Host ($script:Gutter + $dot + $script:Gap + $label + $value)
  }
  Write-Host ''
}

#------------------------------------------------------------------------------
# Per-host scan status lines
#------------------------------------------------------------------------------
# $Progress is the synchronized hashtable the scanning runspace writes into: 'Stage' =
# the group running, plus one 'ok'/'warn'/'fail' entry per finished group. Absent, the
# strip renders empty.
# Host-name column: a typical NetBIOS name, capped against the console by Get-ScanNameWidth.
$script:ScanNameWidth = 18
# Transient lines currently on screen. Write-ScanResult erases exactly this many; a scan
# that finished before a frame was drawn leaves it 0, so nothing is erased and no stray
# newline + cursor-up is emitted.
$script:TransientLines = 0

# Everything but the host name costs a fixed 38 columns (gutter 3 + spinner 1 + gap 2 +
# space 1 + bar 14 + space 1 + pct 4 + gap 3 + timer 6 + gap 3), plus the [i/n] counter.
function Get-ScanNameWidth
{ param([int]$Index = 1, [int]$Total = 1)
  $fixed = 38 + ("[$Index/$Total]").Length
  return [math]::Max(6, [math]::Min($script:ScanNameWidth, (Get-UIWidth) - $fixed))
}

function Write-ScanProgress
{ param([string]$Server, [int]$FrameIndex, [double]$Elapsed, [int]$Index, [int]$Total, [hashtable]$Progress)

  $stage = ''; $done = 0
  if($Progress)
  { $stage = [string]$Progress['Stage']
    $done  = @($script:ScanSteps | Where-Object { $Progress[$_] }).Count
  }
  $frac = if($script:ScanSteps.Count) { $done / $script:ScanSteps.Count } else { 0 }

  if(-not $script:UseAnsi)
  { Write-Transient ($script:Gutter + ("scanning {0}  {1,3:0}%  {2}  {3,5:0.0}s  [{4}/{5}]" -f $Server, ($frac * 100), $stage, $Elapsed, $Index, $Total))
    if($script:IsTty) { $script:TransientLines = 1 }   # one drawn, one to erase
    return
  }

  # Fit the name to what's left of the line. A long FQDN pushed line 1 past the console
  # width, the terminal wrapped it, and the two-line block became three - at which point
  # the trailing ${e}[1A and the erase were both a row out and frames marched down the
  # screen. Format-Cell middle-ellipsises, so the ends that distinguish hosts survive.
  $nameW = Get-ScanNameWidth -Index $Index -Total $Total
  $spin  = Paint (Get-SpinnerFrame $FrameIndex) 'Cyan'
  $name  = Format-Cell -Text $Server -Width $nameW -Color 'White'
  $bar   = Get-ProgressBar -Fraction $frac
  $pct   = Paint ("{0,3:0}%" -f ($frac * 100)) 'Teal'
  $timer = Paint ("{0,5:0.0}s" -f $Elapsed) 'Dim'
  $count = Paint ("[$Index/$Total]") 'Gray'
  $line1 = $script:Gutter + $spin + $script:Gap + $name + ' ' + $bar + ' ' + $pct + '   ' + $timer + '   ' + $count

  # $Progress is optional and indexing $null throws; the guard above covered only the
  # -NoColor path, so an ANSI caller omitting it died here. Fall back to an all-pending strip.
  $cells = foreach($s in $script:ScanSteps)
  { switch([string]$(if($Progress) { $Progress[$s] } else { '' }))
    { 'ok'    { (Paint '✔' 'Green')  + (Paint " $s" 'Gray') }
      'warn'  { (Paint '▲' 'Yellow') + (Paint " $s" 'Gray') }
      'fail'  { (Paint '✗' 'Red')    + (Paint " $s" 'Gray') }
      default { if($s -eq $stage) { (Paint '…' 'Cyan') + (Paint " $s" 'White') }
                else              { (Paint '·' 'Dim')  + (Paint " $s" 'Dim') } }
    }
  }
  $line2 = $script:Content + ($cells -join '  ')

  # Both lines, then step back up so the next frame redraws in place.
  Write-Host ("${e}[2K" + $line1 + "`n${e}[2K" + $line2 + "${e}[1A`r") -NoNewline
  $script:TransientLines = 2
}

function Write-ScanResult
{ param([string]$Server, [string]$Status, [double]$Elapsed)
  # Erase exactly what was drawn - see $script:TransientLines.
  if($script:TransientLines -gt 0) { Clear-TransientBlock -Lines $script:TransientLines }
  $script:TransientLines = 0
  switch($Status)
  { 'Online'  { $icon = Paint '●' 'Green';  $st = Paint 'online'  'Green' }
    'Offline' { $icon = Paint '○' 'Gray';   $st = Paint 'offline' 'Gray' }
    'Timeout' { $icon = Paint '◷' 'Yellow'; $st = Paint 'timeout' 'Yellow' }
    default   { $icon = Paint '✗' 'Red';    $st = Paint 'error'   'Red' }
  }
  # Same width budget as the progress line: same column, and no wrap on a long FQDN.
  $name  = Format-Cell -Text $Server -Width (Get-ScanNameWidth) -Color 'White'
  $timer = Paint ("{0,5:0.0}s" -f $Elapsed) 'Dim'
  Write-Permanent ($script:Gutter + $icon + $script:Gap + $name + ' ' + $st + '   ' + $timer)
}

#------------------------------------------------------------------------------
# Results table
#------------------------------------------------------------------------------
function Convert-Mark
{ param([string]$Value)
  $ok   = [char]::ConvertFromUtf32(0x2714)   # ✔ returned by HealthCheck.ps1
  $bad  = [char]::ConvertFromUtf32(0x2716)   # ✖
  $warn = [char]::ConvertFromUtf32(0x26A0)   # ⚠
  switch($Value)
  { $ok     { return @{ Glyph = '●'; Color = 'Green' } }
    $bad    { return @{ Glyph = '✗'; Color = 'Red' } }
    $warn   { return @{ Glyph = '▲'; Color = 'Yellow' } }
    'N/A'   { return @{ Glyph = '·'; Color = 'Gray' } }
    default { return @{ Glyph = $Value; Color = 'White' } }
  }
}

function Show-SummaryTable
{ param([Parameter(Mandatory)][object[]]$Results)

  $serverW = 6
  foreach($r in $Results) { if(([string]$r.Server).Length -gt $serverW) { $serverW = ([string]$r.Server).Length } }
  # Cap SERVER so a long FQDN can't push the table past the console width. Every other
  # column is fixed, so the non-server width is a constant 69 (STATUS 7 + seven 3-wide
  # checks + RESULT 10, each +2 padding, plus 11 borders) with one extra space on the
  # leading column. SERVER takes what's left, never below 6; Format-Cell truncates.
  $maxServerW = [math]::Max(6, (Get-UIWidth) - 70 - $script:Gutter.Length)
  if($serverW -gt $maxServerW) { $serverW = $maxServerW }

  $cols = @(
    @{ H = 'SERVER'; W = $serverW; A = 'left';   K = 'Server' }
    @{ H = 'STATUS'; W = 7;        A = 'left';   K = 'Status' }
    @{ H = 'HW';     W = 3;        A = 'center'; K = 'HardWare_Check' }
    @{ H = 'OS';     W = 3;        A = 'center'; K = 'OS_Check' }
    @{ H = 'USR';    W = 3;        A = 'center'; K = 'Users_Check' }
    @{ H = 'SVC';    W = 3;        A = 'center'; K = 'Service_Check' }
    @{ H = 'APP';    W = 3;        A = 'center'; K = 'Application_Check' }
    @{ H = 'UPD';    W = 3;        A = 'center'; K = 'Update_Check' }
    @{ H = 'EVT';    W = 3;        A = 'center'; K = 'EventLog_Check' }
    @{ H = 'RESULT'; W = 10;       A = 'left';   K = 'All_Good' }
  )

  # One space of padding per cell, $BoxPad on the leading column so its text lands on the
  # shared content column. The border segments account for that extra space too.
  $lead = { param($i) if($i -eq 0) { $script:BoxPad } else { ' ' } }

  $border = {
    param($left, $mid, $right)
    $segs = for($i = 0; $i -lt $cols.Count; $i++) { '─' * ($cols[$i].W + 1 + (& $lead $i).Length) }
    $script:Gutter + (Paint ($left + ($segs -join $mid) + $right) 'Gray')
  }

  # Header
  Write-Host (& $border '┌' '┬' '┐')
  $headerCells = for($i = 0; $i -lt $cols.Count; $i++)
  { $c = $cols[$i]; (& $lead $i) + (Format-Cell -Text $c.H -Width $c.W -Align $c.A -Color 'CyanB') + ' ' }
  Write-Host ($script:Gutter + (Paint '│' 'Gray') + (($headerCells) -join (Paint '│' 'Gray')) + (Paint '│' 'Gray'))
  Write-Host (& $border '├' '┼' '┤')

  # Rows
  foreach($row in $Results)
  { $cells = for($i = 0; $i -lt $cols.Count; $i++)
    { $c = $cols[$i]
      $raw = [string]$row.($c.K)
      if($c.K -like '*_Check')
      { $m = Convert-Mark $raw; $txt = $m.Glyph; $col = $m.Color }
      elseif($c.K -eq 'Status')
      { $txt = $raw
        $col = switch($raw) { 'Online' {'Green'} 'Offline' {'Gray'} 'Timeout' {'Yellow'} 'Error' {'Red'} default {'White'} }
      }
      elseif($c.K -eq 'All_Good')
      { $txt = $raw
        $col = switch($raw) { 'Yes' {'GreenB'} 'No' {'RedB'} 'Check File' {'Yellow'} default {'Gray'} }
      }
      else { $txt = $raw; $col = 'White' }
      (& $lead $i) + (Format-Cell -Text $txt -Width $c.W -Align $c.A -Color $col) + ' '
    }
    Write-Host ($script:Gutter + (Paint '│' 'Gray') + (($cells) -join (Paint '│' 'Gray')) + (Paint '│' 'Gray'))
  }
  Write-Host (& $border '└' '┴' '┘')

  # Legend
  Write-Host ''
  $legend = $script:Gutter + (Paint '●' 'Green') + ' ' + (Paint 'healthy' 'Gray') +
            '    ' + (Paint '▲' 'Yellow') + ' ' + (Paint 'partial / warning' 'Gray') +
            '    ' + (Paint '✗' 'Red') + ' ' + (Paint 'failed' 'Gray') +
            '    ' + (Paint '·' 'Gray') + ' ' + (Paint 'n/a (offline)' 'Gray')
  Write-Host $legend
}

#------------------------------------------------------------------------------
# End-of-run stats panel
#------------------------------------------------------------------------------
function Show-RunSummary
{ param([Parameter(Mandatory)][object[]]$Results, [double]$Elapsed)

  $total   = $Results.Count
  $healthy = @($Results | Where-Object { $_.All_Good -eq 'Yes' }).Count
  $partial = @($Results | Where-Object { $_.All_Good -eq 'Check File' }).Count
  $down    = @($Results | Where-Object { $_.Status -ne 'Online' }).Count
  $frac    = if($total) { $healthy / $total } else { 0 }

  # Plain-text twin per row: padding is measured on visible characters, and the coloured
  # strings are full of zero-width ANSI.
  $rows = @(
    @{ Plain = "hosts $total    healthy $healthy    partial $partial    down $down"
       Text  = (Paint 'hosts '   'Gray') + (Paint $total   'WhiteB') + '    ' +
               (Paint 'healthy ' 'Gray') + (Paint $healthy 'GreenB') + '    ' +
               (Paint 'partial ' 'Gray') + (Paint $partial 'Yellow') + '    ' +
               (Paint 'down '    'Gray') + (Paint $down    'RedB') }
    @{ Plain = ('█' * 20) + ("  {0,3:0}% healthy   elapsed {1:0.0}s" -f ($frac * 100), $Elapsed)
       Text  = (Get-ProgressBar -Fraction $frac -Width 20 -Color 'Green') +
               (Paint ("  {0,3:0}% healthy" -f ($frac * 100)) 'Gray') +
               (Paint ("   elapsed {0:0.0}s" -f $Elapsed) 'Dim') }
  )

  $inner = 0
  foreach($r in $rows) { if($r.Plain.Length -gt $inner) { $inner = $r.Plain.Length } }

  $span  = $inner + (2 * $script:BoxPad.Length)
  $title = '─ RUN SUMMARY '
  Write-Host ''
  Write-Host ($script:Gutter + (Paint ('┌' + $title + ('─' * ($span - $title.Length)) + '┐') 'Gray'))
  foreach($r in $rows)
  { $pad = ' ' * ($inner - $r.Plain.Length)
    Write-Host ($script:Gutter + (Paint '│' 'Gray') + $script:BoxPad + $r.Text + $pad + $script:BoxPad + (Paint '│' 'Gray'))
  }
  Write-Host ($script:Gutter + (Paint ('└' + ('─' * $span) + '┘') 'Gray'))
}

function Write-SectionTitle
{ param([string]$Text)
  Write-Host ''
  # The heading sits flush left, its body indented by $Gutter beneath it. A rule runs from
  # the label to the card's right edge and turns down into the section, fading as it goes.
  $label = $Text.ToUpper()
  $used  = $script:SectionMark.Length + $script:Gap.Length + $label.Length + 1   # mark + gap + label + space
  $rule  = (Get-CardWidth) - $used - 1                    # -1 for the ╮ terminator
  # A heading too long for a rule prints alone - no dangling space.
  $tail  = if($rule -gt 0) { ' ' + (Get-GradientText -Text (('─' * $rule) + '╮') -From @(167,139,250) -To @(71,85,105)) } else { '' }
  Write-Host ((Paint $script:SectionMark 'Purple') + $script:Gap + (Paint $label 'WhiteB') + $tail)
}
