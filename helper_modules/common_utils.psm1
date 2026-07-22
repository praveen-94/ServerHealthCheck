# Description: Shared utility functions for the ServerVitals scripts.

# The one version string for the whole tool: main.ps1 stamps it on the banner and threads
# it into the config so HealthCheck.ps1 stamps the same value on every report. A literal
# in both files meant bumping one and shipping a banner and report that disagreed.
$script:AppVersion = '1.0.0'
function Get-AppVersion { return $script:AppVersion }

# Level-based console colouring + UTF-8 file append.
function Write-Log
{ param([string]$Message,[string]$Level = "GENERAL", [string]$LogPath, [switch]$NoConsole)
  $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  # ONE log file: errors are tagged in the level column, so they are found by filtering
  # it ("Select-String '\[ERROR\]'") rather than by opening a second file.
  # -NoConsole writes the file only - main.ps1 uses it for lines it renders itself
  # through Write-Status, so styled output isn't interleaved with raw echoes.
  if($NoConsole)
  { if($LogPath) { "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
    return
  }
  # $LogPath is guarded everywhere: Out-File throws on a blank path, so callers that omit
  # it still get console output. The file format is "<ts> [<LEVEL>]: <msg>" for EVERY
  # level - ERROR alone once dropped the colon, breaking any fixed-separator parse.
  if($Level -eq "ERROR" -or $Level -eq "FAILURE")
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Red
    if($LogPath) { "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
  }
  elseif($Level -eq "DEBUG" -or $Level -eq "WARNING")
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Yellow
    if($LogPath) { "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
  }
  elseif($Level -eq "SUCCESS")
  { Write-Host "$Message" -ForegroundColor Green
    if($LogPath) { "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
  }
  elseif($Level -eq "INFO")
  { Write-Host "$Timestamp [$Level]: $Message"
    if($LogPath) { "$Timestamp [$Level]: $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
  }
  else
  { Write-Host "$Message"
    if($LogPath) { "$Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
  }
}

# Folder setup with Keep/Replace/Move/Archive semantics, used for log rotation.
function CreateFolder
{ param([Parameter(Mandatory=$true)][string]$FolderPath,[switch]$IncludeTimestamp,[ValidateSet("Replace", "Move", "Keep", "Archive")][string]$ActionType = "Replace", [string]$DestinationPath, [string[]]$ItemFilter, [string[]]$FolderFilter)
 
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

                  # Work out WHAT would move before creating anything to move it into:
                  # creating Outputs_<timestamp> up front left an empty folder behind on
                  # every run with nothing to archive, the first run included.
                  # -ItemFilter (main.ps1 passes the tool's own artifact patterns) moves
                  # ONLY those, so an -OutputPath holding the user's files is never swept.
                  # No filter = move everything, safe for the tool-owned default folder.
                  $Files = if($ItemFilter)
                           { @($ItemFilter | ForEach-Object { Get-ChildItem -Path $FolderPath -Filter $_ -File -ErrorAction SilentlyContinue } |
                               Sort-Object -Property FullName -Unique) }
                           else
                           { @(Get-ChildItem -Path $FolderPath -File) }
                  # Folders we own (the report folder) are archived whole, matched by exact
                  # name so nothing else is touched. An EMPTY one is left alone - moving it
                  # only to recreate it immediately achieves nothing.
                  $Folders = if($FolderFilter)
                             { @(Get-ChildItem -Path $FolderPath -Directory -ErrorAction SilentlyContinue |
                                 Where-Object { $FolderFilter -contains $_.Name } |
                                 Where-Object { @(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue).Count -gt 0 }) }
                             else { @() }

                  if($Files.Count -eq 0 -and $Folders.Count -eq 0)
                  { Write-Output "Nothing to archive in: $FolderPath"
                    return
                  }

                  $ArchiveLogFolder = Join-Path -Path $DestinationPath -ChildPath "ArchiveLog"
                  if(-not (Test-Path -Path $ArchiveLogFolder))
                  { New-Item -Path $ArchiveLogFolder -ItemType Directory | Out-Null
                    Write-Output "Created ArchiveLog folder: $ArchiveLogFolder"
                  }

                  $OutputsFolder = Join-Path -Path $ArchiveLogFolder -ChildPath ("Outputs_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                  New-Item -Path $OutputsFolder -ItemType Directory | Out-Null
                  Write-Output "Created Outputs folder: $OutputsFolder"

                  foreach($File in $Files)
                  { Write-Output "Moving file: $($File.Name)"
                    Move-Item -Path $File.FullName -Destination $OutputsFolder -Force
                  }
                  foreach($Folder in $Folders)
                  { Write-Output "Moving folder: $($Folder.Name)"
                    Move-Item -Path $Folder.FullName -Destination $OutputsFolder -Force
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