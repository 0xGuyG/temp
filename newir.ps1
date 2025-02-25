# Script for Incident Response System Information Collection
# Create a timestamp for the collection
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computerName = $env:COMPUTERNAME
$collectorName = $env:USERNAME

# Create a dedicated output directory
$outputDir = Join-Path -Path (Get-Location) -ChildPath "IR_Collection_${computerName}_${timestamp}"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# Initialize transcript logging
Start-Transcript -Path (Join-Path -Path $outputDir -ChildPath "IR_Collection_Transcript.txt")

Write-Host "[+] Starting Incident Response Collection at $timestamp"
Write-Host "[+] Collection performed by $collectorName on $computerName"

# Function for error handling and logging
function Get-IRData {
    param (
        [string]$Component,
        [scriptblock]$Collection
    )
    
    Write-Host "[+] Collecting $Component..."
    try {
        & $Collection
    }
    catch {
        Write-Host "[-] Error collecting $Component $_" -ForegroundColor Red
        return $null
    }
}
```

The line 29 appears to be in the function definition area. Let's try a different approach with a much more simplified script that avoids any potentially problematic syntax:

```powershell
# Incident Response Data Collection Script
# Set timestamp format for file naming
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computerName = $env:COMPUTERNAME

# Create output directory
$outputDir = "IR_Collection_$computerName`_$timestamp"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# Start logging
$logFile = "$outputDir\IR_Collection_Log.txt"
"[$(Get-Date)] Starting incident response collection on $computerName" | Out-File -FilePath $logFile

# Create a function to run commands and capture output to file
function Run-Command {
    param (
        [string]$Name,
        [string]$Command
    )
    
    "[$(Get-Date)] Collecting $Name" | Out-File -FilePath $logFile -Append
    $outputFile = "$outputDir\IR_$Name.txt"
    
    try {
        # Run command and redirect output to file
        "INCIDENT RESPONSE DATA: $Name" | Out-File -FilePath $outputFile
        "Collection Time: $(Get-Date)" | Out-File -FilePath $outputFile -Append
        "Command: $Command" | Out-File -FilePath $outputFile -Append
        "-----------------------------------------" | Out-File -FilePath $outputFile -Append
        
        # Execute command and capture output
        Invoke-Expression $Command | Out-File -FilePath $outputFile -Append
        
        "[$(Get-Date)] Successfully collected $Name" | Out-File -FilePath $logFile -Append
    }
    catch {
        "[$(Get-Date)] Error collecting $Name : $_" | Out-File -FilePath $logFile -Append
    }
}

# Collect system information
Run-Command -Name "ComputerSystem" -Command "Get-WmiObject -Class Win32_ComputerSystem | Format-List *"
Run-Command -Name "OperatingSystem" -Command "Get-WmiObject -Class Win32_OperatingSystem | Format-List *"
Run-Command -Name "BiOS" -Command "Get-WmiObject -Class Win32_BIOS | Format-List *"

# Collect user information
Run-Command -Name "LocalUsers" -Command "Get-LocalUser | Format-List *"
Run-Command -Name "LocalGroups" -Command "Get-LocalGroup | Format-List *"
Run-Command -Name "AdminGroup" -Command "net localgroup Administrators"

# Collect network information
Run-Command -Name "IPConfig" -Command "ipconfig /all"
Run-Command -Name "NetworkAdapters" -Command "Get-NetAdapter | Format-List *"
Run-Command -Name "ActiveConnections" -Command "netstat -anob"
Run-Command -Name "RoutingTable" -Command "route print"
Run-Command -Name "ARPCache" -Command "arp -a"

# Collect process information
Run-Command -Name "RunningProcesses" -Command "Get-Process | Sort-Object -Property WorkingSet -Descending | Format-Table Name, Id, Path, Company, CPU, WorkingSet, StartTime -AutoSize"
Run-Command -Name "ProcessConnections" -Command "Get-NetTCPConnection | Where-Object State -eq 'Established' | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -AutoSize"
Run-Command -Name "TaskList" -Command "tasklist /v"

# Collect service information
Run-Command -Name "RunningServices" -Command "Get-Service | Where-Object Status -eq 'Running' | Format-Table Name, DisplayName, Status, StartType -AutoSize"
Run-Command -Name "ServiceDetails" -Command "Get-WmiObject -Class Win32_Service | Format-List Name, DisplayName, State, StartMode, PathName, StartName"

# Collect startup and persistence information
Run-Command -Name "StartupCommands" -Command "Get-WmiObject -Class Win32_StartupCommand | Format-List *"
Run-Command -Name "ScheduledTasks" -Command "Get-ScheduledTask | Where-Object State -ne 'Disabled' | Format-List *"
Run-Command -Name "RunKeys" -Command "Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List *"

# Collect security information
Run-Command -Name "SecurityEvents" -Command "Get-EventLog -LogName Security -Newest 1000 | Format-Table TimeGenerated, EntryType, EventID, Message -AutoSize"
Run-Command -Name "FirewallRules" -Command "Get-NetFirewallRule | Where-Object Enabled -eq 'True' | Format-Table Name, DisplayName, Direction, Action, Profile -AutoSize"
Run-Command -Name "AntivirusProduct" -Command "Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Format-List *"

# Collect system file information
Run-Command -Name "RecentlyModifiedExes" -Command "Get-ChildItem -Path C:\Windows\System32 -Include *.exe -Recurse -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Sort-Object LastWriteTime -Descending | Format-Table FullName, LastWriteTime, Length -AutoSize"

# Create a summary file
$summaryFile = "$outputDir\IR_Summary.txt"
@"
===========================================================================
INCIDENT RESPONSE DATA COLLECTION SUMMARY
===========================================================================
Computer Name: $computerName
Collection Time: $(Get-Date)
===========================================================================
FILES COLLECTED:
"@ | Out-File -FilePath $summaryFile

Get-ChildItem -Path $outputDir -Filter "IR_*.txt" | ForEach-Object {
    "- $($_.Name)" | Out-File -FilePath $summaryFile -Append
}

# Create a ZIP archive
$zipFile = "$outputDir.zip"
"[$(Get-Date)] Creating zip archive $zipFile" | Out-File -FilePath $logFile -Append
Compress-Archive -Path $outputDir -DestinationPath $zipFile -Force

"[$(Get-Date)] Collection completed. Files saved to: $zipFile" | Out-File -FilePath $logFile -Append
"[$(Get-Date)] Collection completed. Files saved to: $zipFile"