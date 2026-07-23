# ServerVitals Health Check Tool

## Overview
ServerVitals is a **console** tool that checks the health of one or more Windows machines and produces two kinds of output: a live, colour-coded terminal dashboard, and a detailed per-server HTML report.

It is Windows-only — the checks use `Win32_*` CIM classes, `Get-WinEvent`, `Get-ScheduledTask`, `Get-Printer` and the `Microsoft.Update.Session` COM object — but it runs on **both Windows PowerShell 5.1 and PowerShell 7**.

Metrics are gathered over a single **CIM session per host using DCOM**, which mirrors the transport the old `Get-WmiObject` used. That means **WinRM does not need to be enabled** on the target — unlike `Get-CimInstance -ComputerName`, which defaults to WS-Man.

> Earlier versions were driven by a WPF/XAML window. That GUI has been removed in favour of the console interface: it required an STA apartment, which pinned the tool to Windows PowerShell 5.1.

---

## Features
- Scan one or more hosts by name/IP, or import a server list from CSV
- ~20 metric groups per host: OS, hardware, disks, memory, CPU, local users and groups, services, scheduled tasks, installed applications, Windows Update history, printers and event logs
- Live terminal dashboard: per-host progress bar, per-check status strip, and a colour-coded summary table
- Detailed HTML report per server, plus a summary CSV
- Per-host timeout so one unresponsive machine can't stall the run
- Remote scanning with alternate credentials
- Auto-elevation via UAC (elevated runs see more event-log and account detail)

---

## Requirements
- Windows
- Windows PowerShell 5.1 **or** PowerShell 7+
- Administrator rights recommended (the tool will offer to elevate itself)
- No external modules; nothing to install

---

## Getting Started

Run the entry point from the repo root:

```powershell
.\main.ps1 -Servers SERVER01,SERVER02
```

With no `-Servers`, the tool falls back to the CSV named in `config/Path.json` (`config/Inputs.csv`, which ships a single `Server` column set to `localhost`). If that CSV is missing or empty, it asks you to confirm a local-only scan rather than failing.

### Parameters

| Parameter | Description |
|---|---|
| `-Servers` | One or more server names / IPs, comma-separated. Takes precedence over any CSV. |
| `-InputCsv` | Path to a CSV with a `Server` column. Overrides the default in `Path.json`. |
| `-OutputPath` | Directory for reports and logs. Defaults to the configured `logs\Outputs`. |
| `-Credential` | Credentials for remote hosts. Ignored for the local machine, which rejects alternate credentials. |
| `-TimeoutSeconds` | Per-host scan deadline. Exceeding it marks the host `Timeout` and the run continues. Default `180`. |
| `-PassThru` | Also emit the per-server result objects to the pipeline. |
| `-NoColor` | Disable ANSI colour (still uses UTF-8 glyphs). |
| `-NoElevate` | Do not auto-relaunch elevated. |

### Examples

```powershell
.\main.ps1 -Servers SERVER01,SERVER02
.\main.ps1 -InputCsv .\config\Inputs.csv -OutputPath C:\Reports
.\main.ps1 -Servers REMOTE01 -Credential (Get-Credential)
.\main.ps1 -Servers SERVER01 -PassThru          # emit result objects to the pipeline
.\main.ps1 -Servers SERVER01 -NoColor           # no ANSI colour
.\main.ps1 -Servers SERVER01 -NoElevate         # don't auto-relaunch elevated
.\main.ps1 -Servers SERVER01 -TimeoutSeconds 300
```

A full local scan takes roughly 15–20 seconds.

`-PassThru` and `-Credential` cannot cross an elevation boundary, so auto-elevation is skipped for them; run an already-elevated shell if you need both.

### Running the check directly

`core_scripts/HealthCheck.ps1` is dual-purpose. Dot-sourcing it only *defines* `Get-ServerHealth` (this is what the console host's runspace does); invoking it with `-Servers` runs a standalone runner that emits the summary as JSON, bypassing the console UI:

```powershell
& .\core_scripts\HealthCheck.ps1 -Servers @("SERVER01") -PathFile $Config -LogHCU $LogHCU
```

---

## Configuration

All paths live in `config/Path.json` and are resolved to absolute at startup, so the tool does not depend on the working directory:

| Key | Purpose |
|---|---|
| `logPath` | Where reports and logs are written |
| `ServerReportFolder` | Folder *name* (not a path) for the per-server HTML reports |
| `helperModulePath` | Location of the helper modules |
| `InputCSVPath` | Default server-list CSV |
| `CoreScriptsPath` | The health-check script |
| `HTMLTemplatePath` | The report template |

Every key is optional and falls back to a built-in default; substituted keys are reported on a warning line at startup.

---

## Output

Written under `logs/Outputs/` (or `-OutputPath`):

| Output | Path |
|---|---|
| Per-server HTML report | `ServerReports/HealthCheckReport_<ServerName>.html` |
| Summary CSV | `ServerHealthReport.csv` |
| Log | `serverVital.log` |

Errors are written to the same log tagged `[ERROR]`:

```powershell
Select-String '\[ERROR\]' .\logs\Outputs\serverVital.log
```

Each run archives the previous run's outputs into `logs/Outputs/ArchiveLog/Outputs_<timestamp>/`. Only the tool's own artifacts are moved, so a custom `-OutputPath` holding your own files is never swept.

---

## Project Structure

```
ServerHealthCheck/
├── config/
│   ├── Inputs.csv             # default server list (Server column)
│   ├── Path.json              # all configurable paths
│   └── ReportTemplate.html    # per-server HTML report template
├── core_scripts/
│   └── HealthCheck.ps1        # the health check itself (Get-ServerHealth)
├── helper_modules/
│   ├── common_utils.psm1      # logging, folder/archive helpers, version
│   ├── console_ui.psm1        # terminal rendering: banner, progress, tables
│   └── html_formatter.psm1    # info/warning/error banners in reports
├── assets/                    # images (currently unreferenced)
├── logs/                      # generated reports and logs (gitignored)
├── main.ps1                   # entry point: console host + orchestration
├── .gitignore
└── README.md
```

---

## Notes
- A host is reported **Offline** only when both the ping *and* the WMI connection fail, so a machine that blocks ICMP but allows WMI is still scanned.
- The overall result reads `Yes` only when all sub-checks pass; a single unavailable feature downgrades the host to `Check File`. On client editions of Windows this is common — for example, Windows Home has no *Remote Desktop Users* group.
- Remote Windows Update history relies on DCOM COM activation being permitted on the target (often blocked) and always uses the caller's identity, not `-Credential`.

---

## Author
Praveen Ahirwar
