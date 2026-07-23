# Description: Shared utility functions for the ServerVitals scripts.

# The one version string for the whole tool: main.ps1 stamps it on the banner and threads
# it into the config so HealthCheck.ps1 stamps the same value on every report. A literal
# in both files meant bumping one and shipping a banner and report that disagreed.
$script:AppVersion = '1.0.0'
function Get-AppVersion { return $script:AppVersion }

# One explicit encoding for the log file, identical on both editions. "Out-File -Encoding
# UTF8" does NOT mean one thing: Windows PowerShell 5.1 writes a BOM, PowerShell 7 does not,
# so the same tool produced two different files depending on which shell launched it - and
# anything that guesses (Excel, older editors) reads the BOM-less one as ANSI, turning a host
# named "Müller-SRV01" into "MÃ¼ller-SRV01". AppendAllText writes the BOM when it creates the
# file and appends plainly afterwards, so exactly one BOM lands at the top.
$script:LogEncoding = New-Object System.Text.UTF8Encoding($true)
function Write-LogLine
{ param([string]$Path, [string]$Line)
  # $LogPath is optional throughout: callers that omit it still get console output.
  if([string]::IsNullOrWhiteSpace($Path)) { return }
  [System.IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine, $script:LogEncoding)
}

# Level-based console colouring + UTF-8 file append.
function Write-Log
{ param([string]$Message,[string]$Level = "GENERAL", [string]$LogPath, [switch]$NoConsole)
  $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  # ONE log file: errors are tagged in the level column, so they are found by filtering
  # it ("Select-String '\[ERROR\]'") rather than by opening a second file.
  # -NoConsole writes the file only - main.ps1 uses it for lines it renders itself
  # through Write-Status, so styled output isn't interleaved with raw echoes.
  if($NoConsole)
  { Write-LogLine -Path $LogPath -Line "$Timestamp [$Level]: $Message"
    return
  }
  # $LogPath is guarded everywhere: Out-File throws on a blank path, so callers that omit
  # it still get console output. The file format is "<ts> [<LEVEL>]: <msg>" for EVERY
  # level - ERROR alone once dropped the colon, breaking any fixed-separator parse.
  if($Level -eq "ERROR" -or $Level -eq "FAILURE")
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Red
    Write-LogLine -Path $LogPath -Line "$Timestamp [$Level]: $Message"
  }
  elseif($Level -eq "DEBUG" -or $Level -eq "WARNING")
  { Write-Host "$Timestamp [$Level]: $Message" -ForegroundColor Yellow
    Write-LogLine -Path $LogPath -Line "$Timestamp [$Level]: $Message"
  }
  elseif($Level -eq "SUCCESS")
  { Write-Host "$Message" -ForegroundColor Green
    Write-LogLine -Path $LogPath -Line "$Timestamp [$Level]: $Message"
  }
  elseif($Level -eq "INFO")
  { Write-Host "$Timestamp [$Level]: $Message"
    Write-LogLine -Path $LogPath -Line "$Timestamp [$Level]: $Message"
  }
  else
  { Write-Host "$Message"
    Write-LogLine -Path $LogPath -Line "$Message"
  }
}

# Folder setup with Keep/Replace/Move/Archive semantics, used for log rotation.
function CreateFolder
{ param([Parameter(Mandatory=$true)][string]$FolderPath,[switch]$IncludeTimestamp,[ValidateSet("Replace", "Move", "Keep", "Archive")][string]$ActionType = "Replace", [string]$DestinationPath, [string[]]$ItemFilter, [string[]]$FolderFilter)
 
  if($IncludeTimestamp) 
  { $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $FolderPath = Join-Path -Path (Split-Path -Path $FolderPath -Parent) -ChildPath ("$(Split-Path -Path $FolderPath -Leaf)_$Timestamp")
  }

  # -LiteralPath throughout, never -Path: -Path treats the value as a WILDCARD PATTERN, and
  # '[' / ']' are legal in Windows folder names. A real folder called "Reports[1]" was read
  # as the pattern "Reports1", reported as not existing, and then created - at which point
  # Windows said it already exists and the whole run died on a raw New-Item error. The
  # archive sweep failed the same way, silently matching nothing so old outputs never rotated.
  # New-Item is exempt: it has no -LiteralPath, and creation does not glob (verified).
  if(Test-Path -LiteralPath $FolderPath)
  { switch($ActionType)
    { "Move"   { if(-not $DestinationPath)
                 { throw "The 'DestinationPath' parameter is required when ActionType is 'Move'."
                 }
                 Move-Item -LiteralPath $FolderPath -Destination $DestinationPath -Force
                 Write-Output "Moved existing folder to: $DestinationPath"
                }
      "Replace" { Remove-Item -LiteralPath $FolderPath -Recurse -Force
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
                           { @($ItemFilter | ForEach-Object { Get-ChildItem -LiteralPath $FolderPath -Filter $_ -File -ErrorAction SilentlyContinue } |
                               Sort-Object -Property FullName -Unique) }
                           else
                           { @(Get-ChildItem -LiteralPath $FolderPath -File) }
                  # Folders we own (the report folder) are archived whole, matched by exact
                  # name so nothing else is touched. An EMPTY one is left alone - moving it
                  # only to recreate it immediately achieves nothing.
                  $Folders = if($FolderFilter)
                             { @(Get-ChildItem -LiteralPath $FolderPath -Directory -ErrorAction SilentlyContinue |
                                 Where-Object { $FolderFilter -contains $_.Name } |
                                 Where-Object { @(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue).Count -gt 0 }) }
                             else { @() }

                  if($Files.Count -eq 0 -and $Folders.Count -eq 0)
                  { Write-Output "Nothing to archive in: $FolderPath"
                    return
                  }

                  $ArchiveLogFolder = Join-Path -Path $DestinationPath -ChildPath "ArchiveLog"
                  if(-not (Test-Path -LiteralPath $ArchiveLogFolder))
                  { New-Item -Path $ArchiveLogFolder -ItemType Directory -Force | Out-Null
                    Write-Output "Created ArchiveLog folder: $ArchiveLogFolder"
                  }

                  # The timestamp is per-second, so two runs starting in the same second (a
                  # scripted back-to-back invocation) would collide on one folder and New-Item
                  # would throw. Append a counter until the name is free.
                  $OutputsBase   = Join-Path -Path $ArchiveLogFolder -ChildPath ("Outputs_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
                  $OutputsFolder = $OutputsBase
                  $suffix        = 1
                  while(Test-Path -LiteralPath $OutputsFolder)
                  { $suffix++; $OutputsFolder = "${OutputsBase}_$suffix" }
                  New-Item -Path $OutputsFolder -ItemType Directory -Force | Out-Null
                  Write-Output "Created Outputs folder: $OutputsFolder"

                  foreach($File in $Files)
                  { Write-Output "Moving file: $($File.Name)"
                    Move-Item -LiteralPath $File.FullName -Destination $OutputsFolder -Force
                  }
                  foreach($Folder in $Folders)
                  { Write-Output "Moving folder: $($Folder.Name)"
                    Move-Item -LiteralPath $Folder.FullName -Destination $OutputsFolder -Force
                  }
                  Write-Output "Moved old log files to archive folder: $OutputsFolder"
                }
    }
  }
  else
  { New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
    Write-Output "Created folder: $FolderPath"
  }
}