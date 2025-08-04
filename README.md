# ServerVitals Health Check Tool
---------------------------------------------------------------------------------------------------------------------------------------
## Overview
ServerVitals Health Check Tool is a PowerShell-based tool for monitoring server health, exporting reports, and providing a dashboard UI. It supports CSV and HTML report generation, customizable configuration, and a user-friendly interface built with WPF XAML.

---------------------------------------------------------------------------------------------------------------------------------------
## Features
- Import server lists from CSV files, Or fill it manually
- Fetch and display server health data (CPU, Memory, Disk, Service Status)
- Export health reports to CSV and HTML
- Customizable configuration via `config/Path.json`
- Logging of operations and errors
- WPF-based dashboard UI

---------------------------------------------------------------------------------------------------------------------------------------
## Project Structure
```
ServerVitals_Tools/
├── config/                # Configuration files to display UI
│   ├── DashBoardUI.xaml
│   |── ReportTemplate.html
|   |── Inputs.csv
│   └── Path.json
├── assets/                       # Images used in UI
├── logs/                         # Store Logs created by tools
├── helper_modules/                      # store helper modules 
│   ├── common_utils.psm1
│   |── common_utils.psd1
|   |── html_formatter.psm1
|   └── html_formatter.psd1
├── core_scripts/                      # scripts use by main logic
│   └── HealthCheck.ps1
├── main.ps1                      # entry point of project
├── requirements.txt              # Installed dependencies (if any)
├── .gitignore                    # Files/folders to ignore in version control
└── README.md                     # Project overview and instructions
```
---------------------------------------------------------------------------------------------------------------------------------------
## Getting Started
1. **Requirements**
   - Windows PowerShell (Desktop Edition)
   - .NET Framework (for WPF UI)
2. **Configuration**
   - Edit `config/Path.json` to set paths for logs, modules, input CSV, and export files.
3. **Usage**
   - Run `main.ps1` in PowerShell.
   - Use the dashboard UI to import server lists, start health checks, and export reports.

---------------------------------------------------------------------------------------------------------------------------------------
## Logging
Logs are saved in `logs/Outputs/`:
- `HealthCheckUtilityLog.txt`: General operations
- `HealthCheckUtilityErrorLog.txt`: Errors

---------------------------------------------------------------------------------------------------------------------------------------
## Exported Reports
- CSV: `logs/Outputs/ServerHealthReport.csv`
- HTML: `logs/Outputs/ServerHealthReport.html`

---------------------------------------------------------------------------------------------------------------------------------------
## Author
Praveen Ahirwar
