# Extracting PowerShell from Event Logs

With PowerShell v5 came the ability to do Deep Script Block Logging.
This logging will contains all script blocks run by PowerShell.
This means that if a malicious script uses dynamic code genetation to hide what it is doing
(Such as scripts generated with Invoke-Obfuscation), all steps of the codem, inclding the final unobfuscated
script block, will be logged as plain text.

This repository contains two methods for extracting and collating scripts logged inside the Event Logs.

The first is a standalone PowerShell script designed to extract scriptblocks from a single source.

The seconds is a python script designed to be run as part of a [HELK (Hunting ELK)](https://github.com/Cyb3rWard0g/HELK) setup,
to extract scripts from logs collected from multiple places.
This script solved the problem of some scriptblocks being split across
mutliple events by aggregating events based on the process PID.


# 1) Get-PSEventScripts PowerShell Module

## Overview
This PowerShell Module will parse these event logs and extract all these scripts, obfuscated or not, into seperate
runanble .ps1 files, to either manually analyze, submit to VirusTotal, or execute inside your own Sandbox runner.


## Installation
The script is contained in the single file - `collectScriptblocksHELK.py`.
Simply import the `getPSEventScripts.psm1` module (enabling an execution policy that alows scripts),
and use it by calling `Get-PSEventScripts`:
```
powershell -ep Unrestricted
Import-Module .\getPSEventScripts.psm1
Get-Help Get-PSEventScripts
```

## Options
This module also lets you filter out known-good scripts, filter by date range, and even parse events that were
exported from another machine.

Run `Get-Help Get-PSEventScripts -detailed` for all the paramaters.


## Usage
Run `Get-Help Get-PSEventScripts -examples` for more examples:
1. Get all scripts in the past 24 hours
```
Get-PSEventScripts -startTime (Get-Date).AddHours(-24)
```

2. Get all scripts that aren't simple oneliners or single interactive commands, by only getting scripts of a moderate character length
```
Get-PSEventScripts -minScriptLen 500
```

3. Get all scripts, besides any scripts in either the current user's local .vscode folder, or the current folder where this script is run.
```
Get-PSEventScripts -ignorePaths (Get-Item -Path ".\" -Verbose).FullName, "$env:USERPROFILE\.vscode"
```

4. Get all scripts from a log you got from another machine, that you exported as "pshellog.evtx"
```
Get-PSEventScripts -logfile pshellog.evtx
```

# 2) HELK Python Script
## Overview
This Python Script is designed to be run inside a [HELK (Hunting ELK)](https://github.com/Cyb3rWard0g/HELK) setup (possibly as a Juypter Notebook).

## Installation
Use The script in conjunction with a HELK setup, running it either on the Juypter Notebook HELK container,
or on a machine that can directly reach a Spark server and the ElasticSearch server.

## Options
Run `python3 collectScriptblocksHELK.py --help` for options, including the output directory to store the extracted .ps1 files.

The defaults should work out-of-the-box if running inside the Juypter Notebook HELK container.

# References

### PowerShell ♥ the Blue Team
https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/


### Real-Time Sysmon Processing via KSQL and HELK
https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-1-initial-integration-88c2b6eac839
