# Description: This module contains utility functions that can be used in other scripts.

#function to write log
function Write-Log 
{ param([string]$Message,[string]$Level = "GENERAL", [string]$LogPath, [string]$errorLog)
  $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  if($Level -eq "ERROR" -or $Level -eq "FAILURE") 
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Red
   "$Timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append
   "$Timestamp [$Level] $Message" | Out-File -FilePath $errorLog -Append
  }
  elseif($Level -eq "DEBUG" -or $Level -eq "WARNING") 
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Yellow
   "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append
  }
  elseif($Level -eq "SUCCESS")
  { Write-Host "$Message" -ForegroundColor Green
   "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append
  }
  elseif($Level -eq "INFO")
  { Write-Host "$Timestamp [$Level]: $Message"
   "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append
  }
  else 
  { Write-Host "$Message"
   "$Message" | Out-File -FilePath $LogPath -Append
  }
}

#function to create folder
function CreateFolder 
{ param([Parameter(Mandatory=$true)][string]$FolderPath,[switch]$IncludeTimestamp,[ValidateSet("Replace", "Move", "Keep", "Archive")][string]$ActionType = "Replace", [string]$DestinationPath)
 
  if($IncludeTimestamp) 
  { $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $FolderPath = Join-Path -Path (Split-Path -Path $FolderPath -Parent) -ChildPath ("$(Split-Path -Path $FolderPath -Leaf)_$Timestamp")
  }

  if(Test-Path -Path $FolderPath) 
  { switch($ActionType) 
    { "Move"   { if(-not $DestinationPath) 
                 { throw "The 'DestinationPath' parameter is required when ActionType is 'Move'."
                 }
                 Move-Item -Path $FolderPath -Destination $DestinationPath -Force
                 Write-Output "Moved existing folder to: $DestinationPath"
                }
      "Replace" { Remove-Item -Path $FolderPath -Recurse -Force
                  Write-Output "Replaced existing folder."
                }
      "Keep"    { Write-Output "Folder already exists. Keeping the existing folder."
                  return
                }
      "Archive" { if(-not $DestinationPath) 
                  { throw "The 'DestinationPath' parameter is required when ActionType is 'Archive'."
                  }

                  $ArchiveLogFolder = Join-Path -Path $DestinationPath -ChildPath "ArchiveLog"
                  if(-not (Test-Path -Path $ArchiveLogFolder)) 
                  { New-Item -Path $ArchiveLogFolder -ItemType Directory | Out-Null
                    Write-Output "Created ArchiveLog folder: $ArchiveLogFolder"
                  }

                  $OutputsFolder = Join-Path -Path $ArchiveLogFolder -ChildPath ("Outputs_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                  New-Item -Path $OutputsFolder -ItemType Directory | Out-Null
                  Write-Output "Created Outputs folder: $OutputsFolder"

                  $Files = Get-ChildItem -Path $FolderPath -File
                  if($Files.Count -eq 0) 
                  { Write-Output "No files found in the source folder: $FolderPath"
                    return
                  }
              
                  foreach($File in $Files) 
                  { Write-Output "Moving file: $($File.Name)"
                    Move-Item -Path $File.FullName -Destination $OutputsFolder -Force
                  }
                  Write-Output "Moved old log files to archive folder: $OutputsFolder"
                }
    }
  }
  else 
  { New-Item -Path $FolderPath -ItemType Directory | Out-Null
    Write-Output "Created folder: $FolderPath" 
  }
}

#function to draw line
function DrawLine 
{ param([string]$LineChar = "-", [string]$LogFilePath, [switch]$LogToFile, [switch]$fixedWidth, [switch]$PrintInConsole)
  if($fixedWidth) 
  { $ConsoleWidth = 175
  }
  else 
  { $ConsoleWidth = $Host.UI.RawUI.WindowSize.Width
  }
  
  if($PrintInConsole) 
  { $Line = $LineChar * $ConsoleWidth
    Write-Output $Line
  }

  if($LogToFile) 
  { if(-not $LogFilePath) 
    { throw "The 'LogFilePath' parameter is required when LogToFile is specified."
    }
    $line2 = $LineChar * 175
    Add-Content -Path $LogFilePath -Value $Line2
  }
}