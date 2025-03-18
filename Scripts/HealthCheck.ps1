param([string[]]$Servers, $PathFile)

Import-Module "$($PathFile.ModulePath)\UtilityModule.psm1"
Import-Module "$($PathFile.ModulePath)\HtmlModule.psm1"
Write-Host "Path File : $PathFile"

if(-not $Servers -or $Servers.Count -eq 0) 
{ Write-Host "No servers specified!"
  exit
}

# Function to get server health metrics
function Get-ServerHealth 
{ param($ServerName,$PathFiles)
  try 
  { if(Test-Connection -ComputerName $ServerName -Count 1 -Quiet) 
    { $ReportTitle = "System Health Report"
      $OutputFile = "$($PathFiles.logPath)\HealthCheckReport_$($ServerName).html"
      $TemplatePath = $PathFiles.HTMLFilePathHC
      
      $reportInfo = [PSCustomObject]@{
               Author  = "Praveen"
               Dates   = $(Get-Date)
               Computer = $ServerName
               Company = "OnePower"
               Version = "1.0.0"
      }
    
      #Load template
      $html = Get-Content $TemplatePath -Raw
      
      #OS Data.................................................................................................................................................................................
      #Operating System Data
      $OSDetails = Get-WmiObject -Class Win32_OperatingSystem -Computername $ServerName
      $OSInfo = $OSDetails | Select-Object -Property Organization,RegisteredUser,CSName,Caption,BuildNumber,ServicePackMajorVersion,Version, @{Name='LastBootTime';Expression={$_.ConvertToDateTime($_.LastBootUpTime)}} | ConvertTo-HTML -Fragment
      
      #TimeZone Data
      $TimeZoneDetails = Get-WmiObject -Class Win32_TimeZone -ComputerName $ServerName
      $TimeZoneInfo = $TimeZoneDetails | Select-Object -Property @{Name='Name';Expression={$_.Caption }}, Bias, DaylightName | ConvertTo-HTML -Fragment

      #Share folder 
      $ShareDetails = Get-WmiObject -Class Win32_Share  -ComputerName $ServerName
      $ShareInfo = $ShareDetails | Select-Object -Property Name,Description,Path,Status | ConvertTo-HTML -Fragment

      #Schedule task
      $ScheduleTaskDetails = Get-ScheduledTask 
      $ScheduleTaskInfo = $ScheduleTaskDetails | Select-Object -Property TaskName, Description, Author, State | Sort-Object -Property State | ConvertTo-HTML -Fragment
      
      #Hardware Data............................................................................................................................................................................
      #BIOS Data
      $BIOSDetails = Get-WmiObject -Class Win32_BIOS -Computername $ServerName 
      $BIOSInfo = $BIOSDetails | Select-Object -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version | ConvertTo-HTML -Fragment

      #Battery Data
      $BatteryDetails = Get-WmiObject -Class Win32_Battery -Computername $ServerName
      $BatteryInfo = $BatteryDetails | Select-Object -Property Caption, EstimatedChargeRemaining,EstimatedRunTime,Status | ConvertTo-HTML -Fragment

      #Get CPU Usage
      $CPUDetails = Get-WmiObject Win32_Processor -ComputerName $ServerName
      $CPU = $CPUDetails | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
      $CPUInfo = $CPUDetails | Select-Object -Property Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,@{Name="ClockSpeed(GHz)"; Expression={$_.MaxClockSpeed/1000}},LoadPercentage | ConvertTo-Html -Fragment

      #Get Memory Usage
      $MemoryDetails = Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName
      $MemoryUsage = [math]::Round(((($MemoryDetails.TotalVisibleMemorySize - $MemoryDetails.FreePhysicalMemory) / $MemoryDetails.TotalVisibleMemorySize) * 100), 2)
      $MemoryInfo = $MemoryDetails | Select-Object -Property @{Name="TotalMemory(GB)"; Expression={[math]::Round($_.TotalVisibleMemorySize/1MB, 2)}}, @{Name="FreeMemory(GB)"; Expression={[math]::Round($_.FreePhysicalMemory/1MB, 2)}}, 
                    @{Name="UsedMemory(GB)"; Expression={[math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB, 2)}},
                    @{Name="MemoryUsage(%)"; Expression={[math]::Round((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/$_.TotalVisibleMemorySize)*100, 2)}} | ConvertTo-Html -Fragment

      #Get Disk Usage
      $Disk = Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName
      $SystemDisk = $Disk | Where-Object { $_.DeviceID -eq "$env:SystemDrive"}
      $DiskUsage = [math]::Round(((($SystemDisk.Size - $SystemDisk.FreeSpace) / $SystemDisk.Size) * 100), 2)
      $DiskInfo = $Disk | Select-Object -Property DeviceID, @{Name="TotalDisk(GB)"; Expression={[math]::Round($_.Size/1GB, 2)}}, @{Name="FreeDisk(GB)"; Expression={[math]::Round($_.FreeSpace/1GB, 2)}}, 
                  @{Name="UsedDisk(GB)"; Expression={[math]::Round(($_.Size - $_.FreeSpace)/1GB, 2)}},
                  @{Name="DiskUsage(%)"; Expression={[math]::Round((($_.Size - $_.FreeSpace)/$_.Size)*100, 2)}} | ConvertTo-Html -Fragment

      #Printer
      $Printer = Get-Printer -ComputerName $ServerName 
      $PrintersInfo = $Printer | Select-Object Name, Type, DriverName, PortName, Shared, PrinterStatus | ConvertTo-Html -Fragment

      #Services Data............................................................................................................................................................................................................................................
      $ServiceDetails = Get-WmiObject Win32_Service -ComputerName $ServerName 

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

      #Applications Data............................................................................................................................................................................................................................................
      $AppDetails = Get-WmiObject -Class Win32_Product -Computername $ServerName
      $AppInfo = $AppDetails | Select-Object -Property Name, Vendor, Version, @{Name="InstallDate";Expression={([datetime]::ParseExact($_.InstallDate, "yyyyMMdd", $null)).ToString("yyyy-MM-dd")}} | ConvertTo-Html -Fragment

      #Updates Data............................................................................................................................................................................................................................................
      #Get-HotFix
      $HotFixDetails = Get-WmiObject -Class Win32_QuickFixEngineering -Computername $ServerName
      $HotFixInfo = $HotFixDetails | Select-Object -Property HotFixID, Description, InstalledBy, InstalledOn | ConvertTo-Html -Fragment

      #Update History
      $UpdateSession = New-Object -ComObject Microsoft.Update.Session
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
      }},
      @{Name="Error"; Expression={
        Switch ($_.HResult) {
            0x0         { "✅ No Error (Success)" }
            0x80240022  { "❌ Windows Update Access Denied" }
            0x800f081f  { "❌ Missing Required Files" }
            0x80240017  { "❌ Update Not Applicable" }
            0x80070005  { "❌ Access Denied (Permissions Issue)" }
            0x80070422  { "❌ Windows Update Service Disabled" }
            Default     { "Unknown Error: $($_.HResult)" }
        }
      }} | ConvertTo-Html -Fragment -PreContent (AddPreContentMessage -Type "Information" -Message "Displaying latest 20 Update details only")

      #Event Logs Data............................................................................................................................................................................................................................................
      $StartDate = (Get-Date).AddDays(-15)
      $PreContent = (AddPreContentMessage -Type "Information" -Message "Displaying first 20 error and critical log details not older than 15 days")
      #Application Logs
      $ApplicationEvents = Get-WinEvent -LogName "Application" -ComputerName $ServerName -MaxEvents 1000 | Where-Object {$_.TimeCreated -ge $StartDate -and ($_.Level -eq 1 -or $_.Level -eq 2)} 
      $AEvent = $ApplicationEvents | Select-Object -First 20 -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent

      #System Logs
      $SystemEvents = Get-WinEvent -LogName "System" -ComputerName $ServerName -MaxEvents 1000 | Where-Object {$_.TimeCreated -ge $StartDate -and ($_.Level -eq 1 -or $_.Level -eq 2)} 
      $SEvent = $SystemEvents | Select-Object -First 20 -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Html -Fragment -PreContent $PreContent
      
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
      $html = $html -replace "<!-- Security -->", $eventLogsTable

      $html | Out-File $OutputFile | Out-Null

      # Determine if all metrics are good
      $AllGood = if(($CPU -lt 80) -and ($MemoryUsage -lt 80) -and ($DiskUsage -lt 80)) { "Yes" } else { "No" }

      # Return the server health data
      return [PSCustomObject]@{
                Server             = $ServerName
                Status             = "Online"
                CPU_Usage          = "$CPU%"
                CPU_Usage_Value    = if ($CPU -gt 80) { "High" } else { "Normal" }
                Memory_Usage       = "$MemoryUsage%"
                Memory_Usage_Value = if ($MemoryUsage -gt 80) { "High" } else { "Normal" }
                Disk_Usage         = "$DiskUsage%"
                Disk_Usage_Value   = if ($DiskUsage -gt 80) { "High" } else { "Normal" }
                All_Good           = $AllGood
            }
    } 
    else 
    { return [PSCustomObject]@{
                Server             = $ServerName
                Status             = "Offline"
                CPU_Usage          = "N/A"
                CPU_Usage_Value    = "N/A"
                Memory_Usage       = "N/A"
                Memory_Usage_Value = "N/A"
                Disk_Usage         = "N/A"
                Disk_Usage_Value   = "N/A"
                All_Good           = "No"
            }
    }
  } 
  catch 
  { $_
    return [PSCustomObject]@{
            Server             = $ServerName
            Status             = "Error"
            CPU_Usage          = "Error"
            CPU_Usage_Value    = "Error"
            Memory_Usage       = "Error"
            Memory_Usage_Value = "Error"
            Disk_Usage         = "Error"
            Disk_Usage_Value   = "Error"
            All_Good           = "No"
        }
  }
}

$ServerHealthData = $Servers | ForEach-Object { Get-ServerHealth -ServerName $_ -PathFiles $PathFile }
$ServerHealthData | ConvertTo-Json -Depth 2


<#
#admin
$members = ([ADSI]"WinNT://$($env:ComputerName)/Administrators,group").psbase.Invoke("Members")
$members | foreach { $out = New-Object PSObject
                     $us = $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)
                     $us
                     }


Get-LocalGroupMember -Group "Administrators"
net localgroup Administrators


$Users = ((Get-WmiObject -Class Win32_GroupUser | Where-Object { $_.GroupComponent -like "*Administrators*" } | Select-Object -Property PartComponent) -split ",")[1]



#local
$members = ([ADSI]"WinNT://$($env:ComputerName)/Users,group").psbase.Invoke("Members")
$members | foreach { $out = New-Object PSObject
                     $us = $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)
                     $us
                     }

Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true } | Select-Object Name, FullName, SID, Disabled, Lockout, PasswordRequired
Get-LocalUser
net user

#RDP
$members = ([ADSI]"WinNT://$($env:ComputerName)/Remote Desktop Users,group").psbase.Invoke("Members")
$members | foreach { $out = New-Object PSObject
                     $us = $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)
                     $us
                     }

Get-LocalGroupMember -Group "Remote Desktop Users"
net localgroup "Remote Desktop Users"

#IIS website
get-website
#>