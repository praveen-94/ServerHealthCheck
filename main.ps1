Import-Module "$PSScriptRoot\helper_modules\common_utils.psm1"

$ConfigPath = "$PSScriptRoot\config\Path.json"
if(-not (Test-Path $ConfigPath)) 
{ Write-Log -Message "Error: Configuration file not found at $ConfigPath." -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  exit
}
else 
{ $Config = Get-Content -Path $ConfigPath | ConvertFrom-Json
}

#Create logs directory............................................................................................................................................
$dirM = CreateFolder -FolderPath "$PSScriptRoot\logs" -ActionType "Keep"
$dirS = CreateFolder -FolderPath "$PSScriptRoot\logs\Outputs" -ActionType "Archive" -DestinationPath "$PSScriptRoot\logs"
$LogHCU = "$($Config.logPath)\serverVital.log"
$ErrorLogHCU = "$($Config.logPath)\serverVitalError.log"

Write-Log -Message "Health Check Utility started." -Level "INFO" -LogPath $LogHCU
Write-Log -Message "Creating Main log directories:`n$($dirM)" -Level "INFO" -LogPath $LogHCU
Write-Log -Message "Creating Sub log directories:`n$($dirS)" -Level "INFO" -LogPath $LogHCU

#Load XAML UI from configuration file and display the window........................................................................................................
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$XAMLPath = $Config.XAMLFilePath
[xml]$XAMLData = Get-Content -Path $XAMLPath -Raw
if(-not $XAMLData.DocumentElement) 
{ Write-Log -Message "Error: Failed to read XAML file. Check for syntax errors or encoding issues." -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  exit
}

$XmlReader = New-Object System.Xml.XmlNodeReader $XAMLData
$Window = [Windows.Markup.XamlReader]::Load($XmlReader)
if(-not $Window) 
{ Write-Log -Message "Error: Failed to load XAML UI. Check for XAML syntax errors." -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  exit
}
Write-Log -Message "XAML UI loaded successfully." -Level "SUCCESS" -LogPath $LogHCU

#Get UI elements....................................................................................................................................................
$ServerGrid = $Window.FindName("ServerGrid")
$ExportButton = $Window.FindName("ExportButton")
$ServerInput = $Window.FindName("ServerInput")
$StartRefreshButton = $Window.FindName("StartRefreshButton")
$StopButton = $Window.FindName("StopButton")
$ImportButton = $Window.FindName("ImportButton")
$ProgressBar = $Window.FindName("ProgressBar")
$StatusText = $Window.FindName("StatusText")
$ClearButton = $Window.FindName("ClearButton")

#Global variables...................................................................................................................................................
$Global:HealthCheckRunning = $false

#Function to update status bar......................................................................................................................................
function Update-Status 
{ param([string]$Message,[string]$Color = "White")
  $StatusText.Text = $Message
  $StatusText.Foreground = $Color
}

#Function to clear server input and grid............................................................................................................................
function Clear-ServerInput 
{ try 
  { Write-Log -Message "Clearing input data" -Level "INFO" -LogPath $LogHCU
    if($ServerGrid.ItemsSource -and $ServerGrid.ItemsSource.Count -gt 0) #Check if there is data in the DataGrid and Prompt the user to export data before clearing
    { $ExportConfirmation = [System.Windows.MessageBox]::Show("Do you want to export the data before clearing?", "Export Data", "YesNo", "Question")
      if($ExportConfirmation -eq "Yes") 
      { Export-Report
        Write-Log -Message "Exporting data before clearing" -Level "INFO" -LogPath $LogHCU
      }
    }
    $ServerInput.Text = ""
    $ServerGrid.ItemsSource = $null
    $ProgressBar.Value = 0
    Update-Status -Message "Ready" -Color "White"
    Update-Status -Message "Server input cleared." -Color "White"
    Write-Log -Message "Input data clear" -Level "SUCCESS" -LogPath $LogHCU
  }
  catch 
  { Update-Status -Message "Failed to clear server input. Check logs for details." -Color "Red"
    Write-Log -Message "Failed to clear server input: $_" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  }
}

#Function to fetch and update server health data.....................................................................................................................
function Update-ServerData 
{ try 
  { if($Global:HealthCheckRunning) 
    { [System.Windows.MessageBox]::Show("Health check is already running.", "Warning", "OK", "Warning")
      Write-Log -Message "Health check is already running." -Level "WARNING" -LogPath $LogHCU
      return
    }

    $ClearButton.IsEnabled = $false
    $StartRefreshButton.IsEnabled = $false
    $ImportButton.IsEnabled = $false
    $ExportButton.IsEnabled = $false

    $Servers = $ServerInput.Text -split "," | ForEach-Object { $_.Trim() }
    if(-not $Servers -or $Servers -contains "") 
    { [System.Windows.MessageBox]::Show("No servers specified.", "Error", "OK", "Error")
      Write-Log -Message "No servers specified." -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
      return
    }

    #Update status and progress bar
    Update-Status -Message "Fetching server health data..." -Color "Yellow"
    Write-Log -Message "Fetching server health data for servers: $($Servers -join ', ')" -Level "INFO" -LogPath $LogHCU
    $ProgressBar.Value = 0

    #Start background job for health check
    $Global:HealthCheckRunning = $true
    $Runspace = [RunspaceFactory]::CreateRunspace()
    $Runspace.Open()
    $PSInstance = [PowerShell]::Create().AddScript({
            param ($Servers, $Config, $PSScriptRoot, $LogHCU, $ErrorLogHCU)
            & "$PSScriptRoot\core_scripts\HealthCheck.ps1" -Servers $Servers -PathFile $Config -LogHCU $LogHCU -ErrorLogHCU $ErrorLogHCU
        }).AddArgument($Servers).AddArgument($Config).AddArgument($PSScriptRoot).AddArgument($LogHCU).AddArgument($ErrorLogHCU)
    $PSInstance.Runspace = $Runspace
    $Handle = $PSInstance.BeginInvoke()

    #Monitor job progress
    while(-not $Handle.IsCompleted) 
    { $ProgressBar.Value = ($ProgressBar.Value + 10) % 100
      Start-Sleep -Milliseconds 500
    }

    #Get job output
    $RawOutput = $PSInstance.EndInvoke($Handle)
    Write-Log -Message "Server health RAW Output: $RawOutput" -Level "DEBUG" -LogPath $LogHCU
    $ServerHealthJson = $RawOutput | ConvertFrom-Json
    if(-not $ServerHealthJson) 
    { Update-Status -Message "No data found for the servers provided." -Color "Red"
      Write-Log -Message "No data found for the servers provided." -Level "WARNING" -LogPath $LogHCU -errorLog $ErrorLogHCU
      return
    }

    #Update UI
    $ServerGrid.ItemsSource = $null
    $ServerGrid.ItemsSource = $ServerHealthJson
    Update-Status -Message "Health check completed successfully." -Color "Green"
    $ProgressBar.Value = 100
    Write-Log -Message "Health check completed successfully." -Level "SUCCESS" -LogPath $LogHCU
  } 
  catch 
  { Update-Status -Message "Failed to update server data. Check logs for details." -Color "Red"
    Write-Log -Message "Failed to update server data: $_" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
    [System.Windows.MessageBox]::Show("Failed to update server data. Check logs for details.", "Error", "OK", "Error")
  } 
  finally 
  { if($Runspace) 
    { $Runspace.Close()
      $Runspace.Dispose()
    }
    $Global:HealthCheckRunning = $false
    $ClearButton.IsEnabled = $true
    $StartRefreshButton.IsEnabled = $true
    $ImportButton.IsEnabled = $true
    $ExportButton.IsEnabled = $true
  }
}

#Function to import server list from CSV............................................................................................................................
function Import-ServerList 
{ try 
  { $CSVPath = $Config.InputCSVPath
    Write-Log -Message "Importing server list from CSV file..." -Level "INFO" -LogPath $LogHCU
    if(-not (Test-Path $CSVPath)) 
    { [System.Windows.MessageBox]::Show("CSV file not found at default path, Please select manually", "Error", "OK", "Error")
      Write-Log -Message "CSV file not found at $CSVPath, Select manually" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU

      $FileDialog = New-Object Microsoft.Win32.OpenFileDialog
      $FileDialog.Filter = "CSV Files (*.csv)|*.csv"
      if($FileDialog.ShowDialog() -eq $true) 
      { $CSVPath = $FileDialog.FileName
      }
    } 

    $ServerList = Import-Csv -Path $CSVPath | Select-Object -ExpandProperty Server
    if(-not $ServerList) 
    { [System.Windows.MessageBox]::Show("No servers found in '$CSVPath' CSV file", "Error", "OK", "Error")
      Write-Log -Message "No servers found in '$CSVPath' CSV file" -Level "WARNING" -LogPath $LogHCU -errorLog $ErrorLogHCU
      return
    }

    $ServerInput.Text = $ServerList -join ", "
    Update-Status -Message "Server list imported successfully." -Color "Green"
    Write-Log -Message "Server list imported successfully from $CSVPath." -Level "SUCCESS" -LogPath $LogHCU
 } 
 catch 
 { Update-Status -Message "Failed to import server list. Check logs for details." -Color "Red"
   Write-Log -Message "Failed to import server list: $_" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
 }
}

#Function to export data................................................................................................................................................
function Export-Report 
{ try 
  { $ClearButton.IsEnabled = $false
    $StartRefreshButton.IsEnabled = $false
    $ImportButton.IsEnabled = $false
    $ExportButton.IsEnabled = $false

    $ExportData = $ServerGrid.ItemsSource
    Write-Log -Message "Exporting report data..." -Level "INFO" -LogPath $LogHCU
    if(-not $ExportData) 
    { [System.Windows.MessageBox]::Show("No data available to export.", "Error", "OK", "Error")
      Write-Log -Message "No data available to export." -Level "WARNING" -LogPath $LogHCU
      return
    }

    #Export to CSV
    $CSVPath = $Config.CSVExportPath
    $ExportData | Export-Csv -Path $CSVPath -NoTypeInformation

    #Export to HTML
    $HTMLPath = $Config.HTMLExportPath
    $HTMLContent = @"
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
            </style>
        </head>
        <body>
            <h2>Server Health Report</h2>
            <table>
                <tr><th>Server</th><th>CPU Usage</th><th>Memory Usage</th><th>Disk Usage</th><th>Service Status</th><th>Status</th></tr>
"@
    foreach($Row in $ExportData) 
    { $HTMLContent += "<tr><td>$($Row.Server)</td><td>$($Row.CPU_Usage)</td><td>$($Row.Memory_Usage)</td><td>$($Row.Disk_Usage)</td><td>$($Row.Service)</td><td>$($Row.Status)</td></tr>"
    }
    $HTMLContent += "</table></body></html>"
    $HTMLContent | Set-Content -Path $HTMLPath

    [System.Windows.MessageBox]::Show("Report saved as CSV and HTML.", "Success", "OK", "Information")
    Update-Status -Message "Report exported successfully." -Color "Green"
    Write-Log -Message "Report exported successfully to $CSVPath and $HTMLPath." -Level "SUCCESS" -LogPath $LogHCU
  } 
  catch 
  { Update-Status -Message "Failed to export report. Check logs for details." -Color "Red"
    Write-Log -Message "Failed to export report: $_" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  }
  finally 
  { $ClearButton.IsEnabled = $true
    $StartRefreshButton.IsEnabled = $true
    $ImportButton.IsEnabled = $true
    $ExportButton.IsEnabled = $true
  }
}

#Function to stop health check and close the tool............................................................................................................................
function Stop-Tool 
{ try 
  { if($Global:HealthCheckRunning -and $Runspace) 
    { $Runspace.Close()
      $Runspace.Dispose()
      $Global:HealthCheckRunning = $false
    }
    $Window.Close()
    Write-Log -Message "Tool stopped by user." -Level "SUCCESS" -LogPath $LogHCU
  } 
  catch 
  { Update-Status -Message "Failed to stop tool. Check logs for details." -Color "Red"
    Write-Log -Message "Failed to stop tool: $_" -Level "ERROR" -LogPath $LogHCU -errorLog $ErrorLogHCU
  }
}

#Bind buttons.................................................................................................................................................................
$StartRefreshButton.Add_Click({  Update-ServerData })
$ClearButton.Add_Click({ Clear-ServerInput })
$ExportButton.Add_Click({ Export-Report })
$ImportButton.Add_Click({ Import-ServerList })
$StopButton.Add_Click({ Stop-Tool })

#Show the window
$Window.ShowDialog() | Out-Null

#>