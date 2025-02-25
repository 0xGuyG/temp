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
        Write-Host "[-] Error collecting $Component: $_" -ForegroundColor Red
        return $null
    }
}

# Get computer system information
$computerSystemInfo = Get-IRData -Component "Computer System" -Collection {
    Get-WmiObject -Class Win32_ComputerSystem | 
    Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors, Domain, Name
}

# Get operating system information
$operatingSystemInfo = Get-IRData -Component "Operating System" -Collection {
    Get-WmiObject -Class Win32_OperatingSystem | 
    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, LocalDateTime, RegisteredUser
}

# Get local users information
$localUsersInfo = Get-IRData -Component "Local Users" -Collection {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, AccountExpires
}

# Get local administrators
$localAdminsInfo = Get-IRData -Component "Local Administrators" -Collection {
    $admins = net localgroup Administrators
    $admins | Select-Object -Skip 4 | Select-Object -SkipLast 1
}

# Get network configuration
$networkInfo = Get-IRData -Component "Network Configuration" -Collection {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength
    Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias
    Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
}

# Get active network connections
$networkConnectionsInfo = Get-IRData -Component "Network Connections" -Collection {
    Get-NetTCPConnection | Where-Object State -eq 'Established' | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

# Get running processes
$processInfo = Get-IRData -Component "Processes" -Collection {
    Get-Process | Select-Object Name, Id, Path, Company, ProductVersion, StartTime, 
    CPU, WorkingSet, HandleCount, Responding | Sort-Object -Property WorkingSet -Descending
}

# Get services
$servicesInfo = Get-IRData -Component "Services" -Collection {
    Get-Service | Select-Object Name, DisplayName, Status, StartType, 
    @{Name="Account"; Expression={(Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $_.Name}).StartName}}
}

# Get installed software
$installedSoftwareInfo = Get-IRData -Component "Installed Software" -Collection {
    Get-WmiObject -Class Win32_Product | Select-Object Name, Vendor, Version, InstallDate
}

# Get security event logs
$securityEventsInfo = Get-IRData -Component "Security Events" -Collection {
    Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4624,4625,4720,4722,4724,4728,4732,4756,4738,4648
        StartTime=(Get-Date).AddDays(-1)
    } -MaxEvents 500 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, Message
}

# Get startup items
$startupItemsInfo = Get-IRData -Component "Startup Items" -Collection {
    Get-WmiObject -Class Win32_StartupCommand | 
    Select-Object Command, User, Location
    
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key
        }
    }
}

# Get scheduled tasks
$scheduledTasksInfo = Get-IRData -Component "Scheduled Tasks" -Collection {
    Get-ScheduledTask | Where-Object State -ne 'Disabled' | 
    Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime
}

# Get firewall rules
$firewallRulesInfo = Get-IRData -Component "Firewall Rules" -Collection {
    Get-NetFirewallRule | Where-Object Enabled -eq 'True' | 
    Select-Object Name, DisplayName, Enabled, Direction, Action
}

# Export data to separate files
$outputFiles = @{
    "ComputerSystem" = $computerSystemInfo
    "OperatingSystem" = $operatingSystemInfo
    "LocalUsers" = $localUsersInfo
    "LocalAdmins" = $localAdminsInfo
    "NetworkConfiguration" = $networkInfo
    "NetworkConnections" = $networkConnectionsInfo
    "Processes" = $processInfo
    "Services" = $servicesInfo
    "InstalledSoftware" = $installedSoftwareInfo
    "SecurityEvents" = $securityEventsInfo
    "StartupItems" = $startupItemsInfo
    "ScheduledTasks" = $scheduledTasksInfo
    "FirewallRules" = $firewallRulesInfo
}

foreach ($key in $outputFiles.Keys) {
    $outputFile = Join-Path -Path $outputDir -ChildPath "IR_${key}_${timestamp}.txt"
    try {
        $outputFiles[$key] | Format-List | Out-File -FilePath $outputFile
        Write-Host "[+] Exported $key data to $outputFile"
    }
    catch {
        Write-Host "[-] Error exporting $key data: $_" -ForegroundColor Red
    }
}

# Create a summary file
$summaryFile = Join-Path -Path $outputDir -ChildPath "IR_Summary_${timestamp}.txt"
$summary = @"
===========================================================================
INCIDENT RESPONSE DATA COLLECTION SUMMARY
===========================================================================
Computer Name: $computerName
Collection Time: $(Get-Date)
Collected By: $collectorName
===========================================================================
FILES COLLECTED:
"@

foreach ($key in $outputFiles.Keys) {
    $summary += "`n- IR_${key}_${timestamp}.txt"
}

$summary | Out-File -FilePath $summaryFile

# Create a ZIP archive of all collected data
$zipPath = "${outputDir}.zip"
Compress-Archive -Path $outputDir -DestinationPath $zipPath -Force

Write-Host "[+] Collection completed. Files saved to: $zipPath"
Stop-Transcript

# Calculate and save file hashes for integrity
Get-ChildItem -Path $outputDir -Recurse -File | 
    Get-FileHash -Algorithm SHA256 | 
    Export-Csv -Path (Join-Path -Path $outputDir -ChildPath "FileHashes.csv")
