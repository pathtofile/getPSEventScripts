<# 
 .Synopsis
  Parses PowerShell Event logs an extracts logged scripts

 .Description
  Parses PowerShell Event logs and extracts logged script. Pair this with enabling "Deep Script Block logging" in
  PowerShell 5 to get de-obfuscated scripts, which are much more human-readable, and eaiser for automatic
  analysis systems such as VirusTotal to find dodgyness

 .Parameter outFolder
  The folder to put the scripts and file summary into. Defaults to a folder called "output".

 .Parameter clearOutFolder
  If True, delete all .ps1 and .csv scripts from outFolder. Defaults to True.

 .Parameter logfile
  If Set, read events from this event log file. Othewise, query local system for events

 .Parameter startTime
  If Set, only get events after this time. Use '(get-Date).AddHours(-24)' to get events in the last 24 hours.

 .Parameter maxEvents
  If Set, Only return this many of the most recent events

 .Parameter minScriptLen
  If Set, only gets scripts on this many characters long. This is usefull to ignore interactive commands or small
  system scripts. Length is measured by number of characters, not lines, so complex onelineres will stil be logged.
  The character length of a typical small script is around 500 characters.

 .Parameter ignorePaths
  If Set, an array of paths of known-good scripts to not log. Usefull to e.g. ignore any local appdata VSCode scripts,
  but could technically lead you missing scripts.

 .Parameter ignoreSignatures
  If Set, and array of strings that will be present in known-good scripts not to log. Usefull to e.g. ignore scripts
  with a "created by xxx" header that you put at the start of all your legit scripts. This could technically lead
  to you missing scripts.


 .Example
   # Get all scripts in the past 24 hours
   Get-PSEventScripts -startTime (Get-Date).AddHours(-24)

 .Example
   # Get all scripts that aren't simple oneliners or single interactive commands,
   # by only getting scripts of a moderate character length
   Get-PSEventScripts -minScriptLen 500

 .Example
   # Get all scripts, besides any scripts in either the current user's local .vscode folder,
   # or the current folder where this script is run.
   Get-PSEventScripts -ignorePaths (Get-Item -Path ".\" -Verbose).FullName, "$env:USERPROFILE\.vscode"

 .Example
   # Get all scripts, besides any containing the string "__cmdletization",
   # which is present in many of your inbuilt scripts, and don't think an attacker would make their script
   # blend in with yours
   Get-PSEventScripts -ignoreSignatures "__cmdletization"

 .Example
   # Get all scripts from a log you got from another machine, that you exported as "pshellog.evtx"
   Get-PSEventScripts -logfile pshellog.evtx

#>
function Get-PSEventScripts {
    param(
        [string] $outFolder = "output",
        [string] $clearOutFolder = $true,
        [string] $logfile,
        [DateTime] $startTime,
        [int] $maxEvents,
        [int] $minScriptLen,
        [string[]] $ignorePaths = @(),
        [string[]] $ignoreSignatures = @()
        )

    $mappings_file = @{}

    # Create output folder if needed
    If (-not (Test-Path $outFolder)) {
        New-Item -ItemType Directory $outFolder
    }
    Elseif (-not ((Get-Item $outFolder) -is [System.IO.DirectoryInfo])) {
        Write-LogError "Output Folder '$outFolder' Must be a Directory"
        return
    }
    Else {
        Write-LogInfo "Using output folder: $outFolder"
    }

    If ($clearOutFolder) {
        Write-LogInfo "Clearing '$outFolder' of all .ps1 and .csv files"
        Remove-Item "$outFolder/*.ps1"
        Remove-Item "$outFolder/*.csv"
    }

    $getEventLog = "Getting Events"
    $eventFilterHashtable = @{ ProviderName="Microsoft-Windows-PowerShell"; Id = 4104}
    If (-not $null -eq $startTime) {
        $eventFilterHashtable['StartTime'] = $startTime
        $getEventLog += " After $startTime"
    }

    If (-not $null -eq $minScriptLen) {
        $getEventLog += " Of at least $minScriptLen characters"
    }

    # Get the Events that match our criteria
    If (-not $null -eq $maxEvents) {
        $getEventLog += " (max $MaxEvents records)"
        Write-LogInfo $getEventLog
        $events = Get-WinEvent -FilterHashtable $eventFilterHashtable -MaxEvents $maxEvents
    }
    Else {
        Write-LogInfo $getEventLog
        $events = Get-WinEvent -FilterHashtable $eventFilterHashtable
    }

    Write-LogInfo "Parsing Events"
    foreach ($event in $events)
    {
        $script_id = [regex]::match($event.Message, "ScriptBlock ID: (\w+-\w+-\w+-\w+-\w+)").Groups[1].Value
        $script_path = [regex]::match(($event.Message.Split("`n"))[-1], "Path: (.*)").Groups[1].Value

        # First, check if we care about the script or not
        If ($event.Message.Contains("Get-PSEventScripts") -or $script_path.EndsWith("getPSEventScripts.ps1")) {
            # This script, ignore
            continue
        }
        If ((-not $null -eq $minScriptLen) -and $event.Message.Length -lt $minScriptLen) {
            # This script is too small, ignore
            continue
        }
        $ignore = $false

        # Check signatures to ignore are not present
        ForEach ($ignoreSignature in $ignoreSignatures) {
            If ($event.Message.Contains($ignoreSignature)) {
                $ignore = $true
                break
            }
        }
        If ($ignore) {
            continue
        }

        # Check script is not in filepaths to ignore
        ForEach ($ignorePath in $ignorePaths) {
            If (([URI]$ignorePath).IsBaseOf($script_path)) {
                $ignore = $true
                break
            }
        }
        If ($ignore) {
            continue
        }

        # The first and last 3 lines of the Message aren't part of the script, so remove them
        $messageplit = $event.Message.Split("`n")
        $script = $messageplit[1..($messageplit.Length-3)]  -join "`n"
        $script.TrimEnd() | Out-File "$outFolder/$script_id.ps1"
        
        If (-not $script_path -eq "")
        {
            $mappings_file[$script_id] = $script_path
        }
    }

    # Delete duplicate files
    # NOTE: I don't care too much for super-long chained oneliners inside a script
    # But this is one of the most efficient ways to do this particular task
    Write-LogInfo "Removing Duplicates scripts"
    Get-ChildItem "$outFolder/*.ps1" | Get-FileHash | Group-Object -property hash | Where-Object { $_.count -gt 1 } | `
      ForEach-Object { $_.group | Select-Object -skip 1 } | Remove-Item

    # Finally, if one file is completley in another remove it
    Write-LogInfo "Removing Files contained in other files"
    foreach ($file in Get-ChildItem "$outFolder/*.ps1")
    {
        $delete = $false
        foreach ($fileCheck in Get-ChildItem "$outFolder/*.ps1")
        {
            # Ignore if the exact same file
            If ($file.Name -eq $fileCheck.Name)
            {
                continue
            }
            
            # Ignore if original file is larger
            If ($file.Length -gt $fileCheck.Length)
            {
                continue
            }

            $text = Get-Content $file
            $textCheck = Get-Content $fileCheck
            if (($textCheck -join "").Contains(($text -join "")))
            {
                $delete = $true
                break
            }
        }
        if ($delete)
        {
           Remove-Item $file
        }
    }

    Write-LogInfo "Writing file summaries to csv"
    # Log Mappings to a file
    Remove-Item "$outFolder/fileMappings.csv" -ErrorAction Ignore
    foreach ($guid in $mappings_file.Keys)
    {
        # If we still have a file then add it to the list
        if (test-path "$outFolder/$guid.ps1")
        {
            $filename = $mappings_file[$guid]
            $text = ("$guid,$filename")
            ("$guid,$filename") | Out-File -Append "$outFolder\fileMappings.csv"
        }
    }
    Write-LogInfo "Details on any scripts run from a file is located in $outFolder\fileMappings.csv"
}

function Write-LogInfo {
    param([string] $string)
    Write-Host -f Green "[*] $string"
}
function Write-LogWarning {
    param([string] $string)
    Write-Host -f Yellow "[*] $string"
}
function Write-LogError {
    param([string] $string)
    Write-Host -b Black -f Red "[*] $string"
}

export-modulemember -function Get-PSEventScripts
