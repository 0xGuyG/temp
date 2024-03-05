# Get computer system information
$computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem |
    Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors

# Get operating system information
$operatingSystemInfo = Get-WmiObject -Class Win32_OperatingSystem |
    Select-Object Caption, Version, CSDVersion, OSArchitecture, InstallDate, LastBootUpTime, RegisteredUser

# Get local users information
$localUsers = Get-LocalUser

# Get security event logs for instance ID 4720
$securityEventLogs = Get-EventLog -LogName Security -InstanceId 4720 | Select-Object *

# Get administrators' group information
$administratorsGroup = net localgroup Administrators

# Get process information
$processInfo = Get-WmiObject -Class Win32_Process | Select-Object ProcessName, ProcessId, CommandLine

# Get running service information
$runningServices = Get-WmiObject -Class Win32_Service | Where-Object { $_.State -eq 'Running' } | Select-Object Name, ProcessId, Status, Started, State, PathName

# Get startup commands
$startupCommands = gwmi Win32_StartupCommand

# Get scheduled tasks in 'Ready' state
$scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }

# Define the path for the output file in the current directory
$outputFilePath = Join-Path -Path (Get-Location) -ChildPath "System_Info.txt"

# Combine all information into a single string
$output = @"
Computer System Information:
$($computerSystemInfo | Out-String)

Operating System Information:
$($operatingSystemInfo | Out-String)

Local Users Information:
$($localUsers | Out-String)

Security Event Logs (Event ID 4720):
$($securityEventLogs | Out-String)

Administrators Group Information:
$administratorsGroup

Process Information:
$($processInfo | Out-String)

Running Services Information:
$($runningServices | Out-String)

Startup Commands Information:
$($startupCommands | Out-String)

Scheduled Tasks Information (Ready state):
$($scheduledTasks | Out-String)
"@

# Write the output to the text file
try {
    $output | Out-File -FilePath $outputFilePath -Encoding UTF8
    Write-Host "System information has been saved to: $outputFilePath"
} catch {
    Write-Host "Error occurred while saving system information to the file: $_"
}
