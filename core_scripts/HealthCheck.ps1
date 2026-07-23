param([string[]]$Servers, $PathFile, $LogHCU, [pscredential]$Credential)

# This file is dual-purpose. Dot-sourcing it (no -Servers, no -PathFile) only DEFINES
# Get-ServerHealth - which is exactly what the console host's runspace does. Invoking it
# with -Servers runs the standalone JSON runner at the bottom. Neither path may exit on
# the other's behalf: the old unconditional "exit" here killed the runspace before the
# function was ever defined, so the host had nothing to call and every scan reported Error.
if($PathFile)
{ Import-Module "$($PathFile.helperModulePath)\common_utils.psm1"   -Force
  Import-Module "$($PathFile.helperModulePath)\html_formatter.psm1" -Force
}

# Function to get server health metrics
function Get-ServerHealth
{ param($ServerName, $PathFiles, $LogHCU, [pscredential]$Credential, [hashtable]$Progress)
  $SuccessSymbol = [char]::ConvertFromUtf32(0x2714)
  $FailedSymbol = [char]::ConvertFromUtf32(0x2716)
  $WarningSymbol = [char]::ConvertFromUtf32(0x26A0)

  # Live progress for the console host. $Stage publishes the group currently running,
  # $Mark records ok/warn/fail for it once the group finishes. main.ps1 polls the same
  # synchronized hashtable from its spinner loop. Both no-op when -Progress is absent,
  # so the dot-sourced and standalone paths are unaffected.
  $Stage = { param($Name) if($Progress) { $Progress['Stage'] = $Name } }
  $Mark  = { param($Name, $Count, $Max)
             if($Progress) { $Progress[$Name] = if($Count -ge $Max) { 'ok' } elseif($Count -gt 0) { 'warn' } else { 'fail' } } }

  # Alternate credentials apply to genuinely remote hosts only - a local connection rejects
  # them. Flowed into the CIM session (and so into every query that reuses it) and into the
  # remote event-log reads. The Windows Update COM object takes no credential, so that one
  # check always runs as the caller.
  $LocalNames = [System.Collections.Generic.List[string]]@('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME, [System.Net.Dns]::GetHostName())
  # Own FQDN and NIC IPs count as local too, so scanning yourself by FQDN/IP isn't routed
  # down the (usually blocked) remote WU-over-DCOM path.
  try
  { $HostEntry = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)
    $LocalNames.Add($HostEntry.HostName)
    foreach($Addr in $HostEntry.AddressList) { $LocalNames.Add($Addr.IPAddressToString) }
  }
  catch { }   # Best-effort: the base names above still cover the common cases.
  $IsLocal    = $LocalNames -contains $ServerName
  $UseCred    = ($Credential -and -not $IsLocal)
  $CimSession = $null

  try
  { # Ping is a hint, not a gate: a host can block ICMP yet still answer WMI, so it counts
    # as reachable if EITHER the ping or the CIM session succeeds.
    $Pingable = Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction SilentlyContinue

    # One DCOM CIM session per host, reused by every Win32_* query, the scheduled tasks and
    # the printers. DCOM mirrors the transport the old Get-WmiObject used, so this works
    # without WinRM - which -ComputerName on Get-CimInstance would require, and which is
    # usually not enabled.
    try
    { $CimArgs = @{ ComputerName = $ServerName; SessionOption = (New-CimSessionOption -Protocol Dcom); ErrorAction = 'Stop' }
      if($UseCred) { $CimArgs.Credential = $Credential }
      $CimSession = New-CimSession @CimArgs
    }
    catch
    { Write-Log -Message "Failed to open CIM session to $($ServerName): $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
    }

    # Reachability has THREE outcomes, not two, because ping and the session answer different
    # questions: ping says the box is on the network, the session says we can actually read
    # something off it. Every check needs the session, so without one there is nothing to run.
    # Carrying on with $CimSession = $null fed "Cannot bind argument to parameter 'CimSession'
    # because it is null" to all 20 checks - twenty log lines naming a PowerShell binding
    # failure, while the real cause sat buried twenty lines above them.
    if($null -ne $CimSession)
    { $ReportTitle = "System Health Report"
      $ScanStarted = Get-Date

      # Per-server reports live in their own folder, which is what main.ps1 counts when it
      # prints the Reports section. Falls back to the log folder if the key is absent.
      $ReportFolder = if($PathFiles.ServerReportFolder) { $PathFiles.ServerReportFolder } else { 'ServerReports' }
      $ReportDir    = Join-Path $PathFiles.logPath $ReportFolder
      if(-not (Test-Path -LiteralPath $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null }
      # Sanitise for use as a filename: IPv6 literals (::1), domain\host and the like carry
      # characters the filesystem rejects. Every illegal one collapses to '_', so 'srv:1' and
      # 'srv|1' shared a single file and the second silently overwrote the first. Append a
      # hash of the ORIGINAL name whenever sanitising changed it, leaving normal names alone.
      $SafeName = ($ServerName -replace '[\\/:*?"<>|]', '_')
      if($SafeName -ne $ServerName)
      { $Md5 = [System.Security.Cryptography.MD5]::Create()
        try   { $Hash = [System.BitConverter]::ToString($Md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ServerName))).Replace('-','').Substring(0,8) }
        finally { $Md5.Dispose() }
        $SafeName = "${SafeName}_$Hash"
      }
      $OutputFile   = Join-Path $ReportDir "HealthCheckReport_$($SafeName).html"
      $TemplatePath = $PathFiles.HTMLTemplatePath

      # Only Company and Version reach the page. The version comes from the config object
      # (single source: Get-AppVersion), so the banner and the report cannot disagree.
      $reportInfo = [PSCustomObject]@{
               Company = "OnePower"
               Version = if($PathFiles.ReportVersion) { [string]$PathFiles.ReportVersion } else { 'unknown' }
      }

      # Escape text going into the page OUTSIDE a table cell. ConvertTo-Html escapes cell
      # values, but -PreContent banners and the identity header are inserted verbatim and
      # carry host names and exception messages. Hand-rolled so the runspace needs no
      # System.Web assembly load.
      $HtmlEscape = { param([string]$Text)
          ([string]$Text).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
      }

      # Round and format a number with an INVARIANT decimal point, never the machine's locale
      # separator. ConvertTo-Html renders a raw double via .ToString(), which on a comma-decimal
      # host (de-DE etc.) emits "35,52" - and the dashboard's parseFloat reads that as 35, so
      # the ,52 of every percentage and GB figure was silently dropped in the KPIs and the
      # threshold colouring. A fixed dot keeps the whole report canonical, like the ISO dates.
      $Num = { param($Value, [int]$Decimals = 2)
          [math]::Round([double]$Value, $Decimals).ToString([System.Globalization.CultureInfo]::InvariantCulture)
      }

      # A failed check and one with genuinely nothing to report both leave the fragment
      # $null, and an empty section cannot tell them apart. Substitute an explicit note.
      $Fragment = { param($Value, [string]$EmptyNote)
          if([string]::IsNullOrWhiteSpace([string]$Value))
          { return [string](AddPreContentMessage -Type "Information" -Message $EmptyNote) }
          return [string]$Value
      }

      # -Encoding UTF8 is required: the template has no BOM and contains non-ASCII, which 5.1
      # would otherwise decode as ANSI and bake into every report as mojibake. Guarded on its
      # own because this sits above every check - a missing or locked template used to fall
      # into the outer catch and report the host as Error with all seven checks failed before
      # a single one had run. Lose the HTML, not the scan.
      $html = $null
      try
      { if([string]::IsNullOrWhiteSpace([string]$TemplatePath)) { throw "No HTML template path was configured (HTMLTemplatePath)." }
        $html = Get-Content -LiteralPath $TemplatePath -Raw -Encoding UTF8
      }
      catch
      { Write-Log -Message "Failed to load HTML report template '$($TemplatePath)' for $($ServerName); the scan will continue without an HTML report: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #OS Data.................................................................................................................................................................................
      #Operating System Data
      & $Stage 'OS'
      $OSCheck = 0
      try
      { $OSDetails = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession -ErrorAction Stop
        # CIM returns LastBootUpTime as a real DateTime. The old ConvertToDateTime() was a
        # method on the WMI object; under PowerShell 7 that object arrives deserialized via
        # the WinPS compatibility shim with no methods at all, so the column rendered blank.
        $OSInfo = $OSDetails | Select-Object -Property Organization,RegisteredUser,CSName,Caption,BuildNumber,ServicePackMajorVersion,Version, @{Name='LastBootTime';Expression={$_.LastBootUpTime}} | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch OS details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #TimeZone Data
      try
      { $TimeZoneDetails = Get-CimInstance -ClassName Win32_TimeZone -CimSession $CimSession -ErrorAction Stop
        $TimeZoneInfo = $TimeZoneDetails | Select-Object -Property @{Name='Name';Expression={$_.Caption }}, Bias, DaylightName | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch TimeZone details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Share folder
      try
      { $ShareDetails = Get-CimInstance -ClassName Win32_Share -CimSession $CimSession -ErrorAction Stop
        $ShareInfo = $ShareDetails | Select-Object -Property Name,Description,Path,Status | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch share folder details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Schedule task (targets the scanned host via the CIM session - the bare call read the
      #SCANNING machine's tasks and reported them as the remote host's)
      try
      { $ScheduleTaskDetails = Get-ScheduledTask -CimSession $CimSession -ErrorAction Stop
        $ScheduleTaskInfo = $ScheduleTaskDetails | Select-Object -Property TaskName, Description, Author, State | Sort-Object -Property State | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Schedule task details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'OS' $OSCheck 4

      #Hardware Data............................................................................................................................................................................
      #BIOS Data
      & $Stage 'HW'
      $HardWareCheck = 0
      try
      { $BIOSDetails = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession -ErrorAction Stop
        $BIOSInfo = $BIOSDetails | Select-Object -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version | ConvertTo-HTML -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch BIOS details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Battery Data
      try
      { $BatteryDetails = Get-CimInstance -ClassName Win32_Battery -CimSession $CimSession -ErrorAction Stop
        $BatteryInfo = $BatteryDetails | Select-Object -Property Caption, EstimatedChargeRemaining,EstimatedRunTime,Status | ConvertTo-HTML -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Battery details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get CPU Usage
      try
      { $CPUDetails = Get-CimInstance -ClassName Win32_Processor -CimSession $CimSession -ErrorAction Stop
        $CPUInfo = $CPUDetails | Select-Object -Property Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,@{Name="ClockSpeed(GHz)"; Expression={ & $Num ($_.MaxClockSpeed/1000) }},LoadPercentage | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch CPU details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get Memory Usage
      try
      { # Reuse the Win32_OperatingSystem instance from the OS section - it carries the memory
        # counters - and re-query only if that call failed.
        $MemoryDetails = if($OSDetails) { $OSDetails } else { Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession -ErrorAction Stop }
        $MemoryInfo = $MemoryDetails | Select-Object -Property @{Name="TotalMemory(GB)"; Expression={ & $Num ($_.TotalVisibleMemorySize/1MB) }}, @{Name="FreeMemory(GB)"; Expression={ & $Num ($_.FreePhysicalMemory/1MB) }},
                    @{Name="UsedMemory(GB)"; Expression={ & $Num (($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB) }},
                    @{Name="MemoryUsage(%)"; Expression={ & $Num ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/$_.TotalVisibleMemorySize)*100) }} | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Memory details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get Disk Usage
      try
      { # DriveType=3 = local fixed disk; without it mapped network drives and removable media
        # are listed as the host's own storage, with no column to tell them apart. Drop
        # zero-size drives too (empty optical / card-reader slots): the usage maths below
        # divides by Size, and one divide-by-zero takes out the whole disk table.
        $Disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -CimSession $CimSession -ErrorAction Stop | Where-Object { $_.Size -gt 0 }
        $DiskInfo = $Disk | Select-Object -Property DeviceID, VolumeName, @{Name="TotalDisk(GB)"; Expression={ & $Num ($_.Size/1GB) }}, @{Name="FreeDisk(GB)"; Expression={ & $Num ($_.FreeSpace/1GB) }},
                  @{Name="UsedDisk(GB)"; Expression={ & $Num (($_.Size - $_.FreeSpace)/1GB) }},
                  @{Name="DiskUsage(%)"; Expression={ & $Num ((($_.Size - $_.FreeSpace)/$_.Size)*100) }} | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Disk details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Printer
      try
      { # Via the CIM session, not -ComputerName: the latter took the spooler RPC path, where
        # -ComputerName localhost hung indefinitely (and Inputs.csv ships "localhost", so it
        # was the default path). The session form returns instantly for local and remote alike.
        $Printer = Get-Printer -CimSession $CimSession -ErrorAction Stop
        $PrintersInfo = $Printer | Select-Object Name, Type, DriverName, PortName, Shared, PrinterStatus | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Printer details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'HW' $HardWareCheck 6

      #Users Data.................................................................................................................................................................................
      #Local Users
      & $Stage 'USR'
      $UsersCheck = 0
      try
      { # Filter LocalAccount SERVER-SIDE. The client-side Where-Object this replaces first
        # pulled every account the provider could see - on a domain-joined host that is the
        # whole domain over DCOM, which takes minutes and blows the per-host timeout.
        $LocalUsersDetails = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -CimSession $CimSession -ErrorAction Stop
        $LocalUsersInfo = $LocalUsersDetails | Select-Object Name, Disabled, Lockout, PasswordRequired, Description | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Local Users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Admin users, via CIM associations over the session. Get-LocalGroupMember accepts
      #neither -ComputerName nor -CimSession, so it always read the SCANNING machine: every
      #remote scan reported our own administrators as the target's. Match the well-known SID
      #rather than the name, because group names are localised - Name='Administrators'
      #returns an empty table on non-English Windows.
      try
      { $AdminGroup = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -CimSession $CimSession -ErrorAction Stop
        $AdminUsersDetails = $AdminGroup | Get-CimAssociatedInstance -Association Win32_GroupUser -CimSession $CimSession -ErrorAction Stop
        $AdminUsersInfo = $AdminUsersDetails | Select-Object Name, Domain, Caption | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch admin users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #RDP users. Well-known SID again, not the localised name. An absent group is a normal
      #state (client editions of Windows have none), so it scores as a pass with an empty
      #section rather than an error that downgrades the whole host.
      try
      { $RDPGroup = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-555'" -CimSession $CimSession -ErrorAction Stop
        if($RDPGroup)
        { $RDPUsersDetails = $RDPGroup | Get-CimAssociatedInstance -Association Win32_GroupUser -CimSession $CimSession -ErrorAction Stop
          $RDPUsersInfo = $RDPUsersDetails | Select-Object Name, Domain, Caption | ConvertTo-HTML -Fragment
        }
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch RDP Users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Local Groups
      try
      { # Server-side LocalAccount filter, as for local users above - without it this listed
        # every group in the domain.
        $LocalGroupsDetails = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" -CimSession $CimSession -ErrorAction Stop
        $LocalGroupsInfo = $LocalGroupsDetails | Select-Object -Property Name, Domain | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch local groups details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'USR' $UsersCheck 4

      #Services Data............................................................................................................................................................................................................................................
      & $Stage 'SVC'
      $ServiceCheck = 0
      try
      { $ServiceDetails = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession -ErrorAction Stop

        #Active and Automatic Services
        $AAService = $ServiceDetails | Where-Object { ($_.State -eq "Running") -and ($_.StartMode -eq "Auto") } | Select-Object -Property DisplayName, Name, StartMode, State | ConvertTo-Html -Fragment

        #Active and Manual Services
        $AMService = $ServiceDetails | Where-Object { ($_.State -eq "Running") -and ($_.StartMode -eq "Manual") } | Select-Object -Property DisplayName, Name, StartMode, State | ConvertTo-Html -Fragment

        #Stopped and Automatic Services
        $SAService = $ServiceDetails | Where-Object { ($_.State -eq "Stopped") -and ($_.StartMode -eq "Auto") } | Select-Object -Property DisplayName, Name, StartMode, State | ConvertTo-Html -Fragment

        #Stopped and Manual Services
        $SMService = $ServiceDetails | Where-Object { ($_.State -eq "Stopped") -and ($_.StartMode -eq "Manual") } | Select-Object -Property DisplayName, Name, StartMode, State | ConvertTo-Html -Fragment

        #Disabled Services
        $DService = $ServiceDetails | Where-Object { ($_.StartMode -eq "Disabled") } | Select-Object -Property DisplayName, Name, StartMode, State | ConvertTo-Html -Fragment
        $ServiceCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Service details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'SVC' $ServiceCheck 1

      #Applications Data............................................................................................................................................................................................................................................
      & $Stage 'APP'
      $ApplicationCheck = 0
      try
      { # Add/Remove Programs registry keys via StdRegProv over the same session. Replaces
        # Win32_Product, which triggers an MSI consistency check on every enumerated product
        # (minutes per host) and only ever saw MSI installs. This is near-instant and covers
        # EXE installers too.
        $HKLM = [uint32]2147483650   # HKEY_LOCAL_MACHINE - decimal, or 5.1 wraps the hex literal negative
        $UninstallPaths = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        # Read one REG_SZ value from a subkey over the CIM session.
        $GetRegStr = { param($KeyPath, $ValueName)
            (Invoke-CimMethod -CimSession $CimSession -Namespace 'root\cimv2' -ClassName StdRegProv -MethodName GetStringValue `
                -Arguments @{ hDefKey = $HKLM; sSubKeyName = $KeyPath; sValueName = $ValueName } -ErrorAction Stop).sValue
        }
        $AppList = foreach($BasePath in $UninstallPaths)
        { $Enum = Invoke-CimMethod -CimSession $CimSession -Namespace 'root\cimv2' -ClassName StdRegProv -MethodName EnumKey `
              -Arguments @{ hDefKey = $HKLM; sSubKeyName = $BasePath } -ErrorAction Stop
          foreach($Sub in $Enum.sNames)
          { $KeyPath = "$BasePath\$Sub"
            $Name = & $GetRegStr $KeyPath 'DisplayName'
            if([string]::IsNullOrWhiteSpace($Name)) { continue }   # no DisplayName = not a user-facing app

            # Skip OS/system components, as Add/Remove Programs does.
            $SystemComponent = (Invoke-CimMethod -CimSession $CimSession -Namespace 'root\cimv2' -ClassName StdRegProv -MethodName GetDWORDValue `
                -Arguments @{ hDefKey = $HKLM; sSubKeyName = $KeyPath; sValueName = 'SystemComponent' } -ErrorAction Stop).uValue
            if($SystemComponent -eq 1) { continue }

            # Safe-parse: a blank or malformed InstallDate renders empty instead of throwing,
            # which is what ParseExact did on every app that ships without one.
            $RawDate = & $GetRegStr $KeyPath 'InstallDate'
            $InstallDate = ''
            $parsed = [datetime]::MinValue
            if($RawDate -and [datetime]::TryParseExact([string]$RawDate, 'yyyyMMdd', $null, [System.Globalization.DateTimeStyles]::None, [ref]$parsed))
            { $InstallDate = $parsed.ToString('yyyy-MM-dd') }

            [PSCustomObject]@{
                Name        = $Name
                Vendor      = & $GetRegStr $KeyPath 'Publisher'
                Version     = & $GetRegStr $KeyPath 'DisplayVersion'
                InstallDate = $InstallDate
            }
          }
        }
        # De-duplicate on Name+Version: products like the VC++ redistributables ship several
        # versions under one DisplayName, and "-Unique Name" alone would keep just one.
        $AppInfo = $AppList | Sort-Object Name, Version -Unique | ConvertTo-Html -Fragment
        $ApplicationCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch application details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'APP' $ApplicationCheck 1

      #Updates Data............................................................................................................................................................................................................................................
      #Get-HotFix
      & $Stage 'UPD'
      $UpdateCheck = 0
      try
      { $HotFixDetails = Get-CimInstance -ClassName Win32_QuickFixEngineering -CimSession $CimSession -ErrorAction Stop
        $HotFixInfo = $HotFixDetails | Select-Object -Property HotFixID, Description, InstalledBy, InstalledOn | ConvertTo-Html -Fragment
        $UpdateCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch hotfix details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Update History
      try
      { # The WU agent is COM, not WMI, so it cannot use the CIM session: local instance
        # locally, DCOM activation remotely. Always the caller's identity - the agent takes
        # no alternate credentials. Without the remote branch this silently reported the
        # SCANNING machine's update history as the target's.
        if($IsLocal)
        { $UpdateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop }
        else
        { $UpdateType = [System.Type]::GetTypeFromProgID('Microsoft.Update.Session', $ServerName, $true)
          $UpdateSession = [System.Activator]::CreateInstance($UpdateType)
        }
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        # Clamp to what's there: QueryHistory raises E_INVALIDARG past the total history,
        # and a freshly-imaged host holds fewer than 20 entries.
        $HistoryCount = [Math]::Min(20, [int]$UpdateSearcher.GetTotalHistoryCount())
        $UpdateHistory = if($HistoryCount -le 0) { AddPreContentMessage -Type "Information" -Message "No update history available" }
        else { $UpdateSearcher.QueryHistory(0, $HistoryCount) | Select-Object Title,Date,
        @{Name="Operation"; Expression={
        Switch ($_.Operation) {
            1 { "Installation" }
            2 { "Uninstallation" }
            3 { "Other" }
            Default { "Unknown" }
          }
        }},
        @{Name="Result"; Expression={
        # Plain words, no emoji: every other table in the report is plain text, and the
        # glyphs were an encoding hazard for anything reading the HTML as ANSI.
        Switch ($_.ResultCode) {
            1 { "In Progress" }
            2 { "Succeeded" }
            3 { "Succeeded (restart required)" }
            4 { "Failed" }
            5 { "Aborted" }
            Default { "Unknown" }
          }
        }} | ConvertTo-Html -Fragment -PreContent (AddPreContentMessage -Type "Information" -Message "Displaying latest 20 Update details only") }
        $UpdateCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch update history details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'UPD' $UpdateCheck 2

      #Event Logs Data............................................................................................................................................................................................................................................
      & $Stage 'EVT'
      $EventLogCheck = 0
      $StartDate = (Get-Date).AddDays(-15)
      $PreContent = (AddPreContentMessage -Type "Information" -Message "Displaying up to 20 most recent error and critical log details not older than 15 days")
      # Filter Critical(1)/Error(2) since $StartDate at the SOURCE, capped at 20. Pulling the
      # newest 1000 events of ANY level and filtering client-side missed real errors on busy
      # hosts - 1000 informational entries can span less than an hour. 'NoMatchingEventsFound'
      # is a healthy state, not a failure: count it as a pass with an empty-section note.
      # Get-WinEvent uses RPC, separate from the DCOM session and gated by the "Remote Event
      # Log Management" firewall rule, so a read failure is bannered in the report too.
      #Application Logs
      try
      { $AppEvtArgs = @{ FilterHashtable = @{ LogName = 'Application'; Level = 1, 2; StartTime = $StartDate }; MaxEvents = 20; ComputerName = $ServerName; ErrorAction = 'Stop' }
        if($UseCred) { $AppEvtArgs.Credential = $Credential }
        # Emit TimeCreated as a fixed yyyy-MM-dd HH:mm:ss string, NOT the raw DateTime.
        # ConvertTo-Html renders a DateTime via .ToString(), which is locale-dependent
        # (20-07-2026 here, 7/20/2026 in the US, 20.07.2026 in Germany), and the dashboard's
        # error histogram then has to guess the field order from the digits - it sorted US
        # dates into the wrong months and couldn't split the German form at all. A fixed
        # ISO-style string sorts correctly everywhere; the separators are literals, so the
        # format is itself culture-independent.
        $AEvent = Get-WinEvent @AppEvtArgs | Select-Object -Property @{Name='TimeCreated';Expression={ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent
        $EventLogCheck++
      }
      catch
      { if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*')
        { $AEvent = (AddPreContentMessage -Type "Information" -Message "No error or critical Application events in the last 15 days")
          $EventLogCheck++
        }
        else
        { $AEvent = (AddPreContentMessage -Type "Warning" -Message "Application event log could not be read: $(& $HtmlEscape $_.Exception.Message) For a remote host, enable the 'Remote Event Log Management' firewall rule on the target.")
          Write-Log -Message "Failed to fetch application event log details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
        }
      }

      #System Logs
      try
      { $SysEvtArgs = @{ FilterHashtable = @{ LogName = 'System'; Level = 1, 2; StartTime = $StartDate }; MaxEvents = 20; ComputerName = $ServerName; ErrorAction = 'Stop' }
        if($UseCred) { $SysEvtArgs.Credential = $Credential }
        # Fixed yyyy-MM-dd HH:mm:ss, as for the Application log above - see the note there.
        $SEvent = Get-WinEvent @SysEvtArgs | Select-Object -Property @{Name='TimeCreated';Expression={ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent
        $EventLogCheck++
      }
      catch
      { if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*')
        { $SEvent = (AddPreContentMessage -Type "Information" -Message "No error or critical System events in the last 15 days")
          $EventLogCheck++
        }
        else
        { $SEvent = (AddPreContentMessage -Type "Warning" -Message "System event log could not be read: $(& $HtmlEscape $_.Exception.Message) For a remote host, enable the 'Remote Event Log Management' firewall rule on the target.")
          Write-Log -Message "Failed to fetch system event log details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
        }
      }
      & $Mark 'EVT' $EventLogCheck 2
      & $Stage 'report'

      #--- Substitute placeholders, write the report ------------------------------
      # Literal String.Replace, NOT the -replace operator: -replace treats the replacement
      # as a regex substitution, so a '$' in fragment data - the C$/IPC$/ADMIN$ admin shares,
      # prices, event-log message text - is mangled as $&, $1 or $`. String.Replace is
      # ordinal and case-SENSITIVE, so the placeholder strings here must match the template
      # exactly, including case; a re-cased comment silently drops that section. The [string]
      # cast keeps it null-safe and preserves the array-join of ConvertTo-Html -Fragment.
      # Every fragment goes through $Fragment for its empty-section note. The whole block is
      # skipped when the template failed to load: the checks still ran and the summary is
      # still valid, there is just no page to render them into.
      if($null -eq $html)
      { Write-Log -Message "No HTML report written for $($ServerName): the report template could not be loaded." -Level "WARNING" -LogPath $LogHCU
      }
      else
      {
      $SafeServer  = & $HtmlEscape $ServerName
      $GeneratedAt = $ScanStarted.ToString('yyyy-MM-dd HH:mm:ss')
      $html = $html.Replace("{{REPORT_TITLE}}", "$SafeServer - $ReportTitle")
      $html = $html.Replace("{{CompanyName-ReportTitle}}", "$($reportInfo.Company) - $ReportTitle")
      $html = $html.Replace("{{SERVER_NAME}}", $SafeServer)
      $html = $html.Replace("{{GENERATED_AT}}", "Generated: $GeneratedAt")
      $html = $html.Replace("{{Computer Name: ThisPC}}", "Computer Name: $SafeServer")
      $html = $html.Replace("{{Generated: ReportTimestamp}}", "Generated: $GeneratedAt")
      $html = $html.Replace("{{Scanned By: ReportAuthor}}", "Scanned By: $(& $HtmlEscape "$env:USERDOMAIN\$env:USERNAME")")
      $html = $html.Replace("{{Report Version: ReportVersion}}", "Report Version: $($reportInfo.Version)")
      $html = $html.Replace("<!-- Hardware_BIOS -->", (& $Fragment $BIOSInfo 'BIOS details could not be read.'))
      $html = $html.Replace("<!-- Hardware_Battery -->", (& $Fragment $BatteryInfo 'No battery detected on this host.'))
      $html = $html.Replace("<!-- Hardware_CPU-->", (& $Fragment $CPUInfo 'CPU details could not be read.'))
      $html = $html.Replace("<!-- Hardware_RAM -->", (& $Fragment $MemoryInfo 'Memory details could not be read.'))
      $html = $html.Replace("<!-- Hardware_Disk -->", (& $Fragment $DiskInfo 'No fixed disks found, or disk details could not be read.'))
      $html = $html.Replace("<!-- Hardware_Printer -->", (& $Fragment $PrintersInfo 'No printers installed, or printer details could not be read.'))
      $html = $html.Replace("<!-- OS_OS -->", (& $Fragment $OSInfo 'Operating system details could not be read.'))
      $html = $html.Replace("<!-- OS_TimeZone -->", (& $Fragment $TimeZoneInfo 'Time zone details could not be read.'))
      $html = $html.Replace("<!-- OS_ShareFolder -->", (& $Fragment $ShareInfo 'No shared folders, or share details could not be read.'))
      $html = $html.Replace("<!-- OS_ScheduleTask -->", (& $Fragment $ScheduleTaskInfo 'No scheduled tasks, or task details could not be read.'))
      $html = $html.Replace("<!-- Users_User -->", (& $Fragment $LocalUsersInfo 'No local user accounts, or user details could not be read.'))
      $html = $html.Replace("<!-- Users_admin -->", (& $Fragment $AdminUsersInfo 'The Administrators group has no members, or its membership could not be read.'))
      $html = $html.Replace("<!-- Users_RDP -->", (& $Fragment $RDPUsersInfo 'The Remote Desktop Users group has no members, or does not exist on this host.'))
      $html = $html.Replace("<!-- Users_Groups -->", (& $Fragment $LocalGroupsInfo 'No local groups, or group details could not be read.'))
      $html = $html.Replace("<!-- Active_Automatic_Services -->", (& $Fragment $AAService 'No running automatic services, or service details could not be read.'))
      $html = $html.Replace("<!-- Active_Manual_Services -->", (& $Fragment $AMService 'No running manual services, or service details could not be read.'))
      $html = $html.Replace("<!-- Stop_Automatic_Services -->", (& $Fragment $SAService 'No stopped automatic services - nothing set to start automatically is down.'))
      $html = $html.Replace("<!-- Stop_Manual_Services -->", (& $Fragment $SMService 'No stopped manual services, or service details could not be read.'))
      $html = $html.Replace("<!-- Disable_Services -->", (& $Fragment $DService 'No disabled services, or service details could not be read.'))
      $html = $html.Replace("<!-- Application_InstalledApps -->", (& $Fragment $AppInfo 'No installed applications found, or the registry could not be read.'))
      $html = $html.Replace("<!-- Updates_Hotfix -->", (& $Fragment $HotFixInfo 'No hotfixes reported, or hotfix details could not be read.'))
      $html = $html.Replace("<!-- Updates_Details -->", (& $Fragment $UpdateHistory 'Update history is unavailable. On a remote host this usually means DCOM activation of the Windows Update agent is blocked.'))
      $html = $html.Replace("<!-- Event_Log_Application -->", (& $Fragment $AEvent 'Application event log could not be read.'))
      $html = $html.Replace("<!-- Event_Log_System -->", (& $Fragment $SEvent 'System event log could not be read.'))

      # WriteAllText with an explicit UTF8 BOM rather than Out-File: Out-File's default
      # encoding differs between 5.1 (UTF-16LE) and 7 (UTF-8), so the same report was written
      # in two different encodings depending on which host ran it. Wrapped in its own
      # try/catch so a locked file or a full disk logs an error instead of downgrading a
      # scan that actually succeeded to "Error".
      try
      { [System.IO.File]::WriteAllText($OutputFile, $html, (New-Object System.Text.UTF8Encoding($true))) }
      catch
      { Write-Log -Message "Failed to write HTML report '$($OutputFile)' for $($ServerName): $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU }
      }

      # Determine if all metrics are good. Test -eq 0 FIRST: with the "Check File" test in
      # front, 0 satisfies it too, so the "No" branch was unreachable and a host on which
      # every single check failed still reported "Check File". $MaxScore is summed from the
      # per-group maxima rather than hardcoded, so adding a check to a group cannot leave a
      # stale literal behind that silently makes a full pass unreachable instead.
      $MaxScore = 6 + 4 + 4 + 1 + 1 + 2 + 2
      $AllValueCount = $HardWareCheck + $OSCheck + $UsersCheck + $ServiceCheck + $ApplicationCheck + $UpdateCheck + $EventLogCheck
      $AllGood = if($AllValueCount -eq 0){"No"} elseif($AllValueCount -lt $MaxScore){"Check File"} else{"Yes"}

      # Return the server health data
      return [PSCustomObject]@{
                Server             = $ServerName
                Status             = "Online"
                HardWare_Check     = if($HardWareCheck -lt 6){"$WarningSymbol" } else{"$SuccessSymbol" }
                OS_Check           = if($OSCheck -lt 4){$WarningSymbol} else{$SuccessSymbol}
                Users_Check        = if($UsersCheck -lt 4){$WarningSymbol} else{$SuccessSymbol}
                Service_Check      = if($ServiceCheck -lt 1){$WarningSymbol} else{$SuccessSymbol}
                Application_Check  = if($ApplicationCheck -lt 1){$WarningSymbol} else{$SuccessSymbol}
                Update_Check       = if($UpdateCheck -lt 2){$WarningSymbol} else{$SuccessSymbol}
                EventLog_Check     = if($EventLogCheck -lt 2){$WarningSymbol} else{$SuccessSymbol}
                All_Good           = $AllGood
            }
    }
    else
    { # Answered ping but refused WMI: the host is up, we just cannot see into it. Say so and
      # name the fix, rather than reporting it Offline (a lie - it replied) or Online with
      # everything failed (also a lie - nothing was ever read).
      if($Pingable)
      { Write-Log -Message ("$($ServerName) responded to ping but no WMI/DCOM session could be opened, so no check could run. " +
                            "On the target, allow 'Windows Management Instrumentation (WMI)' through the firewall and confirm the account used is an administrator there.") `
                  -Level "ERROR" -LogPath $LogHCU
      }
      return [PSCustomObject]@{
                Server             = $ServerName
                Status             = if($Pingable) { "Unreachable" } else { "Offline" }
                HardWare_Check     = "N/A"
                OS_Check           = "N/A"
                Users_Check        = "N/A"
                Service_Check      = "N/A"
                Application_Check  = "N/A"
                Update_Check       = "N/A"
                EventLog_Check     = "N/A"
                All_Good           = "N/A"
            }
    }
  }
  catch
  { Write-Log -Message "Health check failed for $($ServerName): $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
    return [PSCustomObject]@{
            Server             = $ServerName
            Status             = "Error"
            HardWare_Check     = $FailedSymbol
            OS_Check           = $FailedSymbol
            Users_Check        = $FailedSymbol
            Service_Check      = $FailedSymbol
            Application_Check  = $FailedSymbol
            Update_Check       = $FailedSymbol
            EventLog_Check     = $FailedSymbol
            All_Good           = "No"
        }
  }
  finally
  { # One session per host, so it must be closed on every path out - including the early
    # Offline return and the outer catch - or a long server list leaks DCOM connections.
    if($CimSession) { Remove-CimSession -CimSession $CimSession -ErrorAction SilentlyContinue }
  }
}

# Standalone runner: only when invoked with -Servers. Dot-sourcing stops above this line.
if($Servers -and $Servers.Count -gt 0 -and $PathFile)
{ $ServerHealthData = $Servers | ForEach-Object { Get-ServerHealth -ServerName $_ -PathFiles $PathFile -LogHCU $LogHCU -Credential $Credential }
  $ServerHealthData | ConvertTo-Json -Depth 2
}
