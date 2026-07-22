<#
.SYNOPSIS
    ServerVitals - console health-check tool for Windows servers.

.DESCRIPTION
    Runs a health check against one or more Windows hosts, renders a live,
    colour-coded console dashboard, writes a detailed per-server HTML report
    and a summary CSV, and optionally emits the result objects.

.PARAMETER Servers
    One or more server names / IPs. Comma-separated on the command line.

.PARAMETER InputCsv
    Path to a CSV with a 'Server' column. Overrides the default in Path.json.

.PARAMETER OutputPath
    Directory for reports and logs. Defaults to the configured logs\Outputs.

.PARAMETER PassThru
    Emit the per-server result objects to the pipeline after the run.

.PARAMETER Credential
    Credentials for remote hosts, flowed into the CIM session and remote event-log
    queries. Ignored for the local machine (local connections reject credentials).

.PARAMETER NoColor
    Disable ANSI colour (still uses UTF-8 glyphs).

.PARAMETER NoElevate
    Do not auto-relaunch elevated when started without administrator rights.

.PARAMETER TimeoutSeconds
    Per-host scan deadline. If a host's scan exceeds this, the runspace is aborted,
    the host is reported as 'Timeout', and the run continues. Default 180.

.EXAMPLE
    .\main.ps1 -Servers SERVER01,SERVER02

.EXAMPLE
    .\main.ps1 -InputCsv .\config\Inputs.csv -OutputPath C:\Reports

.EXAMPLE
    .\main.ps1 -Servers REMOTE01 -Credential (Get-Credential) -NoElevate
#>
[CmdletBinding()]
param(
    [string[]]    $Servers,
    [string]      $InputCsv,
    [string]      $OutputPath,
    [pscredential]$Credential,
    # 0/negative tripped the deadline on the first poll, so every host timed out unrun.
    [ValidateRange(1, 86400)]
    [int]         $TimeoutSeconds = 180,
    [switch]      $PassThru,
    [switch]      $NoColor,
    [switch]      $NoElevate
)

$ErrorActionPreference = 'Stop'

# Absolutise now, while we still have the cwd: elevation relaunches in System32, where a
# relative -InputCsv/-OutputPath would resolve to the wrong place.
if($InputCsv)   { $InputCsv   = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location -PSProvider FileSystem).ProviderPath, $InputCsv)) }
if($OutputPath) { $OutputPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location -PSProvider FileSystem).ProviderPath, $OutputPath)) }

#--- Auto-elevate to Administrator --------------------------------------------
# Elevated runs see more (event logs, account/task detail), so relaunch via UAC. Skipped
# for -NoElevate and for -PassThru/-Credential, which can't cross an elevation boundary.
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $IsAdmin -and -not $NoElevate)
{ if($PassThru -or $Credential)
  { Write-Warning 'Not running as administrator. Skipping auto-elevation (-PassThru/-Credential cannot cross an elevation boundary); some local checks may be incomplete. Pass -NoElevate to silence this.' }
  else
  { $hostExe  = (Get-Process -Id $PID).Path
    $relaunch = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-NoElevate')
    if($Servers)    { $relaunch += '-Servers';    $relaunch += ($Servers -join ',') }
    if($InputCsv)   { $relaunch += '-InputCsv';   $relaunch += ('"{0}"' -f $InputCsv) }
    if($OutputPath) { $relaunch += '-OutputPath'; $relaunch += ('"{0}"' -f $OutputPath) }
    if($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $relaunch += '-TimeoutSeconds'; $relaunch += $TimeoutSeconds }
    if($NoColor)    { $relaunch += '-NoColor' }
    try
    { Write-Host 'Requesting administrator elevation (a new window will open)...' -ForegroundColor Yellow
      Start-Process -FilePath $hostExe -ArgumentList $relaunch -Verb RunAs | Out-Null
      exit
    }
    catch
    { Write-Warning "Elevation was cancelled or failed; continuing without admin rights. $($_.Exception.Message)" }
  }
}

Import-Module "$PSScriptRoot\helper_modules\common_utils.psm1"   -Force
Import-Module "$PSScriptRoot\helper_modules\html_formatter.psm1" -Force
Import-Module "$PSScriptRoot\helper_modules\console_ui.psm1"     -Force

Initialize-ConsoleUI -NoColor:$NoColor

#--- Banner -------------------------------------------------------------------
# Drawn before anything else writes: startup messages go to the log file and re-render
# through Write-Status, so raw timestamped lines never land between the banner's rules.
Show-Banner -Version (Get-AppVersion)

#--- Load configuration -------------------------------------------------------
$ConfigPath = "$PSScriptRoot\config\Path.json"
if(-not (Test-Path $ConfigPath))
{ Write-Host (Paint "  Configuration file not found at $ConfigPath" 'Red'); exit 1 }
try   { $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json }
catch { Write-Host (Paint "  $ConfigPath is not valid JSON: $($_.Exception.Message)" 'Red'); exit 1 }

# Resolve relative config paths to absolute so runspaces don't depend on the cwd.
function Resolve-ConfigPath([string]$Path)
{ if([string]::IsNullOrWhiteSpace($Path)) { return $Path }
  if([System.IO.Path]::IsPathRooted($Path)) { return $Path }
  return (Join-Path $PSScriptRoot ($Path -replace '^\.[\\/]', ''))
}

# Path.json is hand-edited, so every key is optional. A ConvertFrom-Json PSCustomObject
# THROWS on assignment to a property it doesn't carry, so go through accessors that
# tolerate a missing/blank key, fall back to the documented default, and say so.
function Get-ConfigValue([object]$Object, [string]$Name)
{ $prop = $Object.PSObject.Properties[$Name]
  if($prop) { return [string]$prop.Value }
  return ''
}
function Set-ConfigValue([object]$Object, [string]$Name, $Value)
{ if($Object.PSObject.Properties[$Name]) { $Object.$Name = $Value }
  else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

# The values config/Path.json ships with, so a partial config still yields the stock layout.
$ConfigDefaults = [ordered]@{
    logPath            = '.\logs\Outputs'
    ServerReportFolder = 'ServerReports'
    helperModulePath   = '.\helper_modules'
    InputCSVPath       = '.\config\Inputs.csv'
    CoreScriptsPath    = '.\core_scripts\HealthCheck.ps1'
    HTMLTemplatePath   = '.\config\ReportTemplate.html'
}
# ServerReportFolder is a folder NAME, not a path - never root it against $PSScriptRoot.
$NameOnlyKeys   = @('ServerReportFolder')
$defaultedKeys  = @()
foreach($key in $ConfigDefaults.Keys)
{ $value = Get-ConfigValue $Config $key
  if([string]::IsNullOrWhiteSpace($value)) { $value = $ConfigDefaults[$key]; $defaultedKeys += $key }
  if($NameOnlyKeys -notcontains $key)      { $value = Resolve-ConfigPath $value }
  Set-ConfigValue $Config $key $value
}
if($OutputPath) { Set-ConfigValue $Config 'logPath' $OutputPath }

# One version string for banner + HTML report, threaded down so the two can't drift.
Set-ConfigValue $Config 'ReportVersion' (Get-AppVersion)

# No default can stand in for these: fail here, named, not deep inside a runspace.
foreach($required in @(@{ Key = 'CoreScriptsPath';  What = 'health-check script' },
                       @{ Key = 'HTMLTemplatePath'; What = 'HTML report template' }))
{ $path = Get-ConfigValue $Config $required.Key
  if(-not (Test-Path -LiteralPath $path))
  { Write-Host (Paint "  The $($required.What) named by '$($required.Key)' in $ConfigPath was not found:" 'Red')
    Write-Host (Paint "    $path" 'Red')
    exit 1
  }
}

#--- Prepare log / output directories (archive previous run) ------------------
# Archive OUR OWN artifacts only, so a user -OutputPath holding their files is never
# bulk-swept. These patterns cover everything this run writes.
$ourArtifacts = @('ServerHealthReport.csv', 'serverVital*.log',
                  # Legacy names: no longer written, archived so an older output folder ends clean.
                  'HealthCheckReport_*.html', 'ServerHealthReport.html')
# Per-server reports get their own sub-folder, so the output folder stays readable at scale.
$reportFolderName = $Config.ServerReportFolder
# Archive INTO logPath, not its parent: everything this run writes lives under logPath.
# (Split-Path -Parent put 'C:\ArchiveLog' at the drive root for -OutputPath C:\Reports, and
# gave CreateFolder an empty path for -OutputPath D:\.) ArchiveLog is never re-archived -
# $ourArtifacts matches files only, and $reportFolderName is the sole folder swept.
$null = CreateFolder -FolderPath $Config.logPath -ActionType 'Keep'
$null = CreateFolder -FolderPath $Config.logPath -ActionType 'Archive' -DestinationPath $Config.logPath -ItemFilter $ourArtifacts -FolderFilter @($reportFolderName)
$reportDir = Join-Path $Config.logPath $reportFolderName
$null = CreateFolder -FolderPath $reportDir -ActionType 'Keep'

$LogHCU = Join-Path $Config.logPath 'serverVital.log'

# Log to file, render through the UI layer: timestamped format on disk, styled line on screen.
function Say
{ param([string]$Message, [ValidateSet('info','ok','warn','error')][string]$Level = 'info', [string]$Display, [string]$Detail)
  $logLevel = switch($Level) { 'ok' {'SUCCESS'} 'warn' {'WARNING'} 'error' {'ERROR'} default {'INFO'} }
  # The log line stays whole; only the console splits onto the detail line.
  Write-Log -Message $Message -Level $logLevel -LogPath $LogHCU -NoConsole
  Write-Status -Text $(if($Display) { $Display } else { $Message }) -Level $Level -Detail $Detail
}

Write-Log -Message 'ServerVitals console started.' -Level 'INFO' -LogPath $LogHCU -NoConsole

# Heads both the input-resolution messages and the info panel, like every other section.
Write-SectionTitle 'Run details'

# Report substituted defaults: silently swapping paths would make a typo'd key look applied.
if($defaultedKeys.Count -gt 0)
{ Say "config/Path.json is missing or blank for: $($defaultedKeys -join ', '). Using built-in defaults." 'warn' `
      -Display "Config incomplete; using defaults for $($defaultedKeys.Count) key(s)" -Detail ($defaultedKeys -join ', ') }

#--- Resolve the server list --------------------------------------------------
# Precedence: (1) -Servers, else (2) CSV (-InputCsv or the configured default),
# else (3) offer a local-only scan - never a hard exit on missing input.
if($Servers -and $Servers.Count -gt 0)
{ # (1) -Servers wins. Say when a CSV is being ignored rather than stay silent.
  if($InputCsv)
  { Say '-InputCsv was ignored because -Servers was supplied.' 'warn' }
}
else
{ # (2) No -Servers: fall back to the CSV (explicit -InputCsv, else the configured default).
  $csvToUse = if($InputCsv) { $InputCsv } else { $Config.InputCSVPath }

  # Why the CSV can't be used; $null on success. Reason ONLY - the path goes on the
  # detail line, since the two concatenated overflow the console.
  # Settle the blank-path case FIRST: the announcement below calls Split-Path -Leaf,
  # which rejects an empty string, so a blank InputCSVPath crashed before reaching here.
  $csvStatus = $null
  if([string]::IsNullOrWhiteSpace($csvToUse))
  { $csvStatus = 'no CSV path is configured'
    Say 'No -Servers parameter supplied, and no CSV path is configured.' 'warn' `
        -Display 'No -Servers given, and no CSV path is configured.'
  }
  else
  { Say "No -Servers parameter supplied; looking for a server list in CSV '$csvToUse'." 'info' `
        -Display "No -Servers given; reading the server list from $(Split-Path -Leaf $csvToUse)"

    if(-not (Test-Path $csvToUse)) { $csvStatus = 'file not found' }
    else
    { # @() keeps .Count safe: a header-only file yields $null, which Get-Member rejects.
      # A locked/malformed file is a CSV status like any other, not a reason to abort the run.
      try   { $csvRows = @(Import-Csv -Path $csvToUse) }
      catch { $csvRows = @(); $csvStatus = "file could not be read: $($_.Exception.Message)" }

      if($csvStatus) { }
      elseif($csvRows.Count -eq 0)
      { $csvStatus = 'file is empty / header-only, no data rows' }
      elseif(-not ($csvRows | Get-Member -Name Server -MemberType NoteProperty))
      { $csvStatus = "file has no 'Server' column" }
      else
      { $fromCsv = @($csvRows | Select-Object -ExpandProperty Server | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if($fromCsv.Count -eq 0) { $csvStatus = "'Server' column has no non-blank entries" }
        else
        { $Servers = $fromCsv
          Say "Imported $($Servers.Count) server(s) from $csvToUse." 'ok' `
              -Display "Imported $($Servers.Count) server(s) from $(Split-Path -Leaf $csvToUse)" }
      }
    }
  }

  # (3) Neither -Servers nor a usable CSV: report the CSV status and confirm a local scan.
  if(-not $Servers -or $Servers.Count -eq 0)
  { Say "No usable server input: $csvStatus ($csvToUse)." 'warn' `
        -Display "No -Servers given, and the CSV is not usable: $csvStatus" -Detail $csvToUse
    # Read-Host throws under -NonInteractive (scheduled task / CI / redirected stdin);
    # treat an unpromptable session as a decline so it exits cleanly.
    try   { $answer = Read-Prompt "Both inputs are absent. Run a health check against this local machine ($env:COMPUTERNAME)? [Y/N]" }
    catch { $answer = 'N'; Write-Status 'Non-interactive session; cannot prompt for confirmation.' 'warn' }
    if($answer -match '^\s*(y|yes)\s*$')
    { $Servers = @($env:COMPUTERNAME)
      Say "User confirmed local-only scan of $env:COMPUTERNAME." 'info' -Display "Proceeding with a local-only scan of $env:COMPUTERNAME."
    }
    else
    { Say 'User declined the local-only scan; nothing to do.' 'error' -Display 'No servers to scan. Exiting.'
      exit 1
    }
  }
}
# Split comma-bearing entries ("a,b" on the CLI, and the single token the elevation
# relaunch forwards), trim, drop blanks, and drop case-insensitive duplicates
# (HashSet.Add returns false for a seen name) so no host is scanned - or written - twice.
$seen = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
$Servers = $Servers | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Where-Object { $seen.Add($_) }

if(-not $Servers -or $Servers.Count -eq 0)
{ Say 'No servers specified.' 'error' -Display 'No servers specified. Nothing to do.'
  exit 1
}

#--- Run details panel --------------------------------------------------------
# No 'Hosts' row (a long list wraps badly; the count is in the scan counter and run
# summary) and no 'Reports' row (the Reports section shows it).
$info = [ordered]@{
    'Date'   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    'User'   = "$env:USERDOMAIN\$env:USERNAME"
    'Access' = if($IsAdmin) { 'Administrator' } else { 'Standard user' }
    'Auth'   = if($Credential) { "credential: $($Credential.UserName)" } else { 'current identity' }
}
Show-InfoPanel -Data $info

#--- Scan each host (runspace + animated spinner) -----------------------------
Write-SectionTitle 'Scanning hosts'

$coreScript = {
    # NB: these names must NOT collide with HealthCheck.ps1's param block ($Servers,
    # $PathFile, $LogHCU) - dot-sourcing re-runs it here and would blank them. Hence $LogFile.
    param($ServerName, $Config, $LogFile, [pscredential]$Cred, [hashtable]$Prog)
    Import-Module "$($Config.helperModulePath)\common_utils.psm1"   -Force
    Import-Module "$($Config.helperModulePath)\html_formatter.psm1" -Force
    . $Config.CoreScriptsPath
    Get-ServerHealth -ServerName $ServerName -PathFiles $Config -LogHCU $LogFile -Credential $Cred -Progress $Prog
}

$results    = New-Object System.Collections.Generic.List[object]
$total      = $Servers.Count
$index      = 0
$runWatch   = [System.Diagnostics.Stopwatch]::StartNew()

Write-Log -Message "Scanning $total host(s): $($Servers -join ', ')" -Level 'INFO' -LogPath $LogHCU -NoConsole

foreach($server in $Servers)
{ $index++
  Write-Log -Message "[$index/$total] Starting scan of ${server}." -Level 'INFO' -LogPath $LogHCU -NoConsole
  $runspace = [runspacefactory]::CreateRunspace()
  $runspace.Open()
  $psInstance = [powershell]::Create()
  $psInstance.Runspace = $runspace
  # Synchronized: the runspace publishes the current check group, this thread reads it
  # to draw the progress bar. Only ever written by one side.
  $progress = [hashtable]::Synchronized(@{})
  $null = $psInstance.AddScript($coreScript).
      AddArgument($server).AddArgument($Config).
      AddArgument($LogHCU).AddArgument($Credential).AddArgument($progress)

  $watch    = [System.Diagnostics.Stopwatch]::StartNew()
  $handle   = $psInstance.BeginInvoke()
  $frame    = 0
  $timedOut = $false
  while(-not $handle.IsCompleted)
  { if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds)
    { # Deadline hit: abort the (likely wedged) runspace. BeginStop, not Stop() - a
      # synchronous stop blocks until the pipeline actually stops, which a stuck native
      # DCOM call may never do, defeating the deadline. The CIM session is reclaimed on
      # dispose / when the stuck call unwinds.
      $timedOut = $true
      $null = $psInstance.BeginStop($null, $null)
      break
    }
    Write-ScanProgress -Server $server -FrameIndex $frame -Elapsed ($watch.Elapsed.TotalSeconds) -Index $index -Total $total -Progress $progress
    $frame++
    Start-Sleep -Milliseconds 90
  }

  # -NoConsole on both: these fire where the transient progress block is being redrawn,
  # and a raw timestamped line flush-left is exactly the interleaving it prevents. The
  # failure still shows on screen as the host's Timeout / Error status line below.
  if($timedOut)
  { $output = $null
    Write-Log -Message "Scan of ${server} timed out after ${TimeoutSeconds}s; aborted." -Level 'ERROR' -LogPath $LogHCU -NoConsole
  }
  else
  { try   { $output = $psInstance.EndInvoke($handle) }
    catch { $output = $null; Write-Log -Message "Runspace failed for ${server}: $_" -Level 'ERROR' -LogPath $LogHCU -NoConsole }
  }
  $watch.Stop()

  $obj = $output | Where-Object { $_ -is [pscustomobject] } | Select-Object -Last 1
  if(-not $obj)
  { $status = if($timedOut) { 'Timeout' } else { 'Error' }
    $obj = [pscustomobject]@{
        Server = $server; Status = $status
        HardWare_Check = 'N/A'; OS_Check = 'N/A'; Users_Check = 'N/A'; Service_Check = 'N/A'
        Application_Check = 'N/A'; Update_Check = 'N/A'; EventLog_Check = 'N/A'; All_Good = 'No'
    }
  }
  $results.Add($obj)
  Write-ScanResult -Server $server -Status ([string]$obj.Status) -Elapsed ($watch.Elapsed.TotalSeconds)
  # Record the outcome, not just failures: a clean run left a two-line log that said
  # nothing about which hosts were scanned or how they scored.
  Write-Log -Message ("[$index/$total] {0} -> {1} (result {2}) in {3:0.0}s" -f `
                      $server, $obj.Status, $obj.All_Good, $watch.Elapsed.TotalSeconds) `
            -Level 'INFO' -LogPath $LogHCU -NoConsole

  # A timed-out runspace may still be stopping, so Dispose/Close can throw. Never let
  # cleanup of one host abort the run.
  try { $psInstance.Dispose() } catch { }
  try { $runspace.Close()     } catch { }
  try { $runspace.Dispose()   } catch { }
}

$runWatch.Stop()

#--- Summary table ------------------------------------------------------------
Write-SectionTitle 'Health summary'
Show-SummaryTable -Results ([object[]]$results)
Show-RunSummary -Results ([object[]]$results) -Elapsed ($runWatch.Elapsed.TotalSeconds)

#--- Export summary CSV (driven off the real properties) ----------------------
# CSV only: the summary is already on screen and the per-server reports carry the detail,
# so a third rendering of the same table added nothing.
$csvPath = Join-Path $Config.logPath 'ServerHealthReport.csv'

# Excel and friends open a CSV as ANSI and render the ✔ / ✖ / ⚠ glyphs as "âœ”", so spell
# them out for the file. The objects keep the symbols, so the table and -PassThru are unaffected.
$MarkWords = @{ ([char]0x2714) = 'OK'; ([char]0x2716) = 'Failed'; ([char]0x26A0) = 'Warning' }
function ConvertTo-PlainMark([object]$Value)
{ $text = [string]$Value
  foreach($glyph in $MarkWords.Keys) { $text = $text.Replace([string]$glyph, $MarkWords[$glyph]) }
  return $text
}

try
{ $results |
      Select-Object -Property @(
          'Server', 'Status'
          @{ Name = 'HardWare_Check';    Expression = { ConvertTo-PlainMark $_.HardWare_Check } }
          @{ Name = 'OS_Check';          Expression = { ConvertTo-PlainMark $_.OS_Check } }
          @{ Name = 'Users_Check';       Expression = { ConvertTo-PlainMark $_.Users_Check } }
          @{ Name = 'Service_Check';     Expression = { ConvertTo-PlainMark $_.Service_Check } }
          @{ Name = 'Application_Check'; Expression = { ConvertTo-PlainMark $_.Application_Check } }
          @{ Name = 'Update_Check';      Expression = { ConvertTo-PlainMark $_.Update_Check } }
          @{ Name = 'EventLog_Check';    Expression = { ConvertTo-PlainMark $_.EventLog_Check } }
          'All_Good'
      ) |
      Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
  # File only: the full path wraps over several lines. The Reports section below shows
  # the folder once, with the file names under it.
  Write-Log -Message "Summary exported to $csvPath" -Level 'SUCCESS' -LogPath $LogHCU -NoConsole
  $csvWritten = $true
}
catch
{ # -NoConsole as in the scan loop; the Reports section below reports it as not written.
  Write-Log -Message "Failed to export summary: $_" -Level 'ERROR' -LogPath $LogHCU -NoConsole
  $csvWritten = $false
}

#--- Footer -------------------------------------------------------------------
$online = @($results | Where-Object { $_.Status -eq 'Online' }).Count
Write-SectionTitle 'Reports'
$pad = '   '   # column 3, matching every other content line (see console_ui.psm1)
Write-Host ($pad + (Paint 'Folder    ' 'Gray') + (Paint $Config.logPath 'White'))
if($csvWritten) { Write-Host ($pad + (Paint 'Summary   ' 'Gray') + (Paint (Split-Path -Leaf $csvPath) 'White')) }
else            { Write-Host ($pad + (Paint 'Summary   ' 'Gray') + (Paint 'not written - see the log for the reason' 'Red')) }
Write-Host ($pad + (Paint 'Log       ' 'Gray') + (Paint (Split-Path -Leaf $LogHCU) 'White'))
# Only advertise reports that exist: offline / timed-out hosts never reach the writing
# stage, so an all-unreachable run pointed at an empty folder and a pattern matching nothing.
$reportCount = @(Get-ChildItem -LiteralPath $reportDir -Filter 'HealthCheckReport_*.html' -File -ErrorAction SilentlyContinue).Count
if($reportCount -gt 0)
{ Write-Host ($pad + (Paint 'Per-host  ' 'Gray') + (Paint "$reportFolderName\HealthCheckReport_<server>.html" 'White') +
              (Paint "  ($reportCount of $total)" 'Gray')) }
else
{ Write-Host ($pad + (Paint 'Per-host  ' 'Gray') + (Paint 'none written - no host was reachable enough to report on' 'Gray')) }
Write-Host ''
Write-Host ($pad + (Paint "Done. $online/$total host(s) online." 'GreenB'))
Write-Host ''

Write-Log -Message ("Run complete: {0}/{1} online, {2} report(s) written, elapsed {3:0.0}s." -f `
                    $online, $total, $reportCount, $runWatch.Elapsed.TotalSeconds) `
          -Level 'INFO' -LogPath $LogHCU -NoConsole

if($PassThru) { $results }
