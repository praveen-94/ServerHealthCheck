param([string[]]$Servers, $PathFile, $LogHCU)

# This file is dual-purpose. Dot-sourcing it (no -Servers, no -PathFile) only DEFINES
# Get-ServerHealth - which is exactly what the console host's runspace does. Invoking it
# with -Servers runs the standalone JSON runner at the bottom. Neither path may exit on
# the other's behalf: the old unconditional "exit" here killed the runspace before the
# function was ever defined, so the host had nothing to call and every scan reported Error.
if($PathFile)
{ Import-Module "$($PathFile.helperModulePath)\common_utils.psm1"
  Import-Module "$($PathFile.helperModulePath)\html_formatter.psm1"
}

# Function to get server health metrics
function Get-ServerHealth
{ param($ServerName, $PathFiles, $LogHCU, [PSCredential]$Credential, $Progress)
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

  # Alternate credentials apply to genuinely remote hosts only - a local WMI connection
  # rejects them. Splatted into the calls that accept -Credential; Get-ScheduledTask,
  # Get-LocalGroupMember, Get-Printer and the Windows Update COM object do not, so those
  # keep using the caller's identity.
  $LocalNames = @('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME)
  $IsLocal    = $LocalNames -contains $ServerName
  $Cred       = @{}
  if($Credential -and -not $IsLocal) { $Cred['Credential'] = $Credential }

  try
  { if(Test-Connection -ComputerName $ServerName -Count 1 -Quiet)
    { $ReportTitle = "System Health Report"

      # Per-server reports live in their own folder, which is what main.ps1 counts when it
      # prints the Reports section. Falls back to the log folder if the key is absent.
      $ReportFolder = if($PathFiles.ServerReportFolder) { $PathFiles.ServerReportFolder } else { 'ServerReports' }
      $ReportDir    = Join-Path $PathFiles.logPath $ReportFolder
      if(-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
      $OutputFile   = Join-Path $ReportDir "HealthCheckReport_$($ServerName).html"
      $TemplatePath = $PathFiles.HTMLTemplatePath

      $reportInfo = [PSCustomObject]@{
               Author  = "Praveen"
               Dates   = $(Get-Date)
               Computer = $ServerName
               Company = "OnePower"
               Version = if($PathFiles.ReportVersion) { $PathFiles.ReportVersion } else { "1.0.0" }
      }

      #Load template
      $html = Get-Content $TemplatePath -Raw

      #OS Data.................................................................................................................................................................................
      #Operating System Data
      & $Stage 'OS'
      $OSCheck = 0
      try
      { $OSDetails = Get-WmiObject -Class Win32_OperatingSystem -Computername $ServerName @Cred -ErrorAction Stop
        $OSInfo = $OSDetails | Select-Object -Property Organization,RegisteredUser,CSName,Caption,BuildNumber,ServicePackMajorVersion,Version, @{Name='LastBootTime';Expression={$_.ConvertToDateTime($_.LastBootUpTime)}} | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch OS details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #TimeZone Data
      try
      { $TimeZoneDetails = Get-WmiObject -Class Win32_TimeZone -ComputerName $ServerName @Cred -ErrorAction Stop
        $TimeZoneInfo = $TimeZoneDetails | Select-Object -Property @{Name='Name';Expression={$_.Caption }}, Bias, DaylightName | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch TimeZone details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Share folder
      try
      { $ShareDetails = Get-WmiObject -Class Win32_Share  -ComputerName $ServerName @Cred -ErrorAction Stop
        $ShareInfo = $ShareDetails | Select-Object -Property Name,Description,Path,Status | ConvertTo-HTML -Fragment
        $OSCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch share folder details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Schedule task
      try
      { $ScheduleTaskDetails = Get-ScheduledTask -ErrorAction Stop
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
      { $BIOSDetails = Get-WmiObject -Class Win32_BIOS -Computername $ServerName @Cred -ErrorAction Stop
        $BIOSInfo = $BIOSDetails | Select-Object -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version | ConvertTo-HTML -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch BIOS details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Battery Data
      try
      { $BatteryDetails = Get-WmiObject -Class Win32_Battery -Computername $ServerName @Cred -ErrorAction Stop
        $BatteryInfo = $BatteryDetails | Select-Object -Property Caption, EstimatedChargeRemaining,EstimatedRunTime,Status | ConvertTo-HTML -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Battery details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get CPU Usage
      try
      { $CPUDetails = Get-WmiObject Win32_Processor -ComputerName $ServerName @Cred -ErrorAction Stop
        $CPUInfo = $CPUDetails | Select-Object -Property Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,@{Name="ClockSpeed(GHz)"; Expression={$_.MaxClockSpeed/1000}},LoadPercentage | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch CPU details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get Memory Usage
      try
      { $MemoryDetails = Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName @Cred -ErrorAction Stop
        $MemoryInfo = $MemoryDetails | Select-Object -Property @{Name="TotalMemory(GB)"; Expression={[math]::Round($_.TotalVisibleMemorySize/1MB, 2)}}, @{Name="FreeMemory(GB)"; Expression={[math]::Round($_.FreePhysicalMemory/1MB, 2)}},
                    @{Name="UsedMemory(GB)"; Expression={[math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB, 2)}},
                    @{Name="MemoryUsage(%)"; Expression={[math]::Round((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/$_.TotalVisibleMemorySize)*100, 2)}} | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Memory details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Get Disk Usage
      try
      { $Disk = Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName @Cred -ErrorAction Stop
        $DiskInfo = $Disk | Select-Object -Property DeviceID, @{Name="TotalDisk(GB)"; Expression={[math]::Round($_.Size/1GB, 2)}}, @{Name="FreeDisk(GB)"; Expression={[math]::Round($_.FreeSpace/1GB, 2)}},
                  @{Name="UsedDisk(GB)"; Expression={[math]::Round(($_.Size - $_.FreeSpace)/1GB, 2)}},
                  @{Name="DiskUsage(%)"; Expression={[math]::Round((($_.Size - $_.FreeSpace)/$_.Size)*100, 2)}} | ConvertTo-Html -Fragment
        $HardWareCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Disk details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Printer
      try
      { # Get-Printer -ComputerName localhost hangs indefinitely in the spooler RPC path -
        # the real host name and the plain no -ComputerName form both return instantly.
        # Inputs.csv ships "localhost", so this is the default path: query locally when local.
        $Printer = if($IsLocal) { Get-Printer -ErrorAction Stop }
                   else        { Get-Printer -ComputerName $ServerName -ErrorAction Stop }
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
      { $LocalUsersDetails = Get-WmiObject -Class Win32_UserAccount -Computername $ServerName @Cred -ErrorAction Stop
        $LocalUsersInfo = $LocalUsersDetails | Where-Object { $_.LocalAccount -eq $true } | Select-Object Name, Disabled, Lockout, PasswordRequired, Description | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch Local Users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Admin Users
      try
      { $AdminUsersDetails = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $AdminUsersInfo = $AdminUsersDetails | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch admin users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #RDP Users
      try
      { $RDPUsersDetails = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction Stop
        $RDPUsersInfo = $RDPUsersDetails | ConvertTo-HTML -Fragment
        $UsersCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch RDP Users details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #RDP Users
      try
      { $LocalGroupsDetails = Get-WmiObject -Class Win32_Group -ComputerName $ServerName @Cred -ErrorAction Stop
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
      { $ServiceDetails = Get-WmiObject Win32_Service -ComputerName $ServerName @Cred -ErrorAction Stop

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
      { $AppDetails = Get-WmiObject -Class Win32_Product -Computername $ServerName @Cred -ErrorAction Stop
        $AppInfo = $AppDetails | Select-Object -Property Name, Vendor, Version, @{Name="InstallDate";Expression={([datetime]::ParseExact($_.InstallDate, "yyyyMMdd", $null)).ToString("yyyy-MM-dd")}} | ConvertTo-Html -Fragment
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
      { $HotFixDetails = Get-WmiObject -Class Win32_QuickFixEngineering -Computername $ServerName @Cred -ErrorAction Stop
        $HotFixInfo = $HotFixDetails | Select-Object -Property HotFixID, Description, InstalledBy, InstalledOn | ConvertTo-Html -Fragment
        $UpdateCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch hotfix details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #Update History
      try
      { $UpdateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $UpdateHistory = $UpdateSearcher.QueryHistory(0, 20) | Select-Object Title,Date,
        @{Name="Operation"; Expression={
        Switch ($_.Operation) {
            1 { "Installation" }
            2 { "Uninstallation" }
            3 { "Other" }
            Default { "Unknown" }
          }
        }},
        @{Name="Result"; Expression={
        Switch ($_.ResultCode) {
            1 { "In Progress" }
            2 { "✅ Succeeded" }
            3 { "⚠️ Requires Restart" }
            4 { "❌ Failed" }
            5 { "❌ Aborted" }
            Default { "Unknown" }
          }
        }} | ConvertTo-Html -Fragment -PreContent (AddPreContentMessage -Type "Information" -Message "Displaying latest 20 Update details only")
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
      $PreContent = (AddPreContentMessage -Type "Information" -Message "Displaying first 20 error and critical log details not older than 15 days")
      #Application Logs
      try
      { $ApplicationEvents = Get-WinEvent -LogName "Application" -ComputerName $ServerName @Cred -MaxEvents 1000 -ErrorAction Stop | Where-Object {$_.TimeCreated -ge $StartDate -and ($_.Level -eq 1 -or $_.Level -eq 2)}
        $AEvent = $ApplicationEvents | Select-Object -First 20 -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent
        $EventLogCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch application event log details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }

      #System Logs
      try
      { $SystemEvents = Get-WinEvent -LogName "System" -ComputerName $ServerName @Cred -MaxEvents 1000 -ErrorAction Stop| Where-Object {$_.TimeCreated -ge $StartDate -and ($_.Level -eq 1 -or $_.Level -eq 2)}
        $SEvent = $SystemEvents | Select-Object -First 20 -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent
        $EventLogCheck++
      }
      catch
      { Write-Log -Message "Failed to fetch system event log details: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogHCU
      }
      & $Mark 'EVT' $EventLogCheck 2

      #Replace placeholders, save html file
      $html = $html -replace "{{REPORT_TITLE}}", $ReportTitle
      $html = $html -replace "{{CompanyName-ReportTitle}}", "$($reportInfo.Company) - $ReportTitle"
      $html = $html -replace "{{Computer Name: ThisPC}}", "Computer Name: $ServerName"
      $html = $html -replace "{{Report Version: ReportVersion}}", "Report Version: $($reportInfo.Version)"
      $html = $html -replace "<!-- Report Details -->", $reportInfo
      $html = $html -replace "<!-- Hardware_BIOS -->", $BIOSInfo
      $html = $html -replace "<!-- Hardware_Battery -->", $BatteryInfo
      $html = $html -replace "<!-- Hardware_CPU-->", $CPUInfo
      $html = $html -replace "<!-- Hardware_RAM -->", $MemoryInfo
      $html = $html -replace "<!-- Hardware_Disk -->", $DiskInfo
      $html = $html -replace "<!-- Hardware_Printer -->", $PrintersInfo
      $html = $html -replace "<!-- OS_OS -->", $OSInfo
      $html = $html -replace "<!-- OS_TimeZone -->", $TimeZoneInfo
      $html = $html -replace "<!-- OS_ShareFolder -->", $ShareInfo
      $html = $html -replace "<!-- OS_ScheduleTask -->", $ScheduleTaskInfo
      $html = $html -replace "<!-- Users_User -->", $LocalUsersInfo
      $html = $html -replace "<!-- Users_admin -->", $AdminUsersInfo
      $html = $html -replace "<!-- Users_RDP -->", $RDPUsersInfo
      $html = $html -replace "<!-- Users_Groups -->", $LocalGroupsInfo
      $html = $html -replace "<!-- Active_Automatic_Services -->", $AAService
      $html = $html -replace "<!-- Active_Manual_Services -->", $AMService
      $html = $html -replace "<!-- Stop_Automatic_Services -->", $SAService
      $html = $html -replace "<!-- Stop_Manual_Services -->", $SMService
      $html = $html -replace "<!-- Disable_Services -->", $DService
      $html = $html -replace "<!-- Application_InstalledApps -->",$AppInfo
      $html = $html -replace "<!-- Updates_Hotfix -->", $HotFixInfo
      $html = $html -replace "<!-- Updates_Details -->",  $UpdateHistory
      $html = $html -replace "<!-- Event_Log_Application -->", $AEvent
      $html = $html -replace "<!-- Event_Log_System -->", $SEvent

      $html | Out-File $OutputFile | Out-Null

      # Determine if all metrics are good
      $AllValueCount = $HardWareCheck + $OSCheck + $UsersCheck + $ServiceCheck + $ApplicationCheck + $UpdateCheck + $EventLogCheck
      $AllGood = if($AllValueCount -lt 20){"Check File"} elseif($AllValueCount -eq 0){"No"} else{ "Yes" }

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
    { return [PSCustomObject]@{
                Server             = $ServerName
                Status             = "Offline"
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
}

# Standalone runner: only when invoked with -Servers. Dot-sourcing stops above this line.
if($Servers -and $Servers.Count -gt 0 -and $PathFile)
{ $ServerHealthData = $Servers | ForEach-Object { Get-ServerHealth -ServerName $_ -PathFiles $PathFile -LogHCU $LogHCU }
  $ServerHealthData | ConvertTo-Json -Depth 2
}
