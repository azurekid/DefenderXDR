# Example: Advanced Hunting Query
# This example demonstrates how to run advanced hunting queries

# Import the module
Import-Module ../DefenderXDR/DefenderXDR.psd1 -Force

# Connect (replace with your credentials)
$accessToken = "YOUR_ACCESS_TOKEN_HERE"
Connect-DefenderXDR -AccessToken $accessToken

# Example 1: Find PowerShell executions
Write-Host "Example 1: Finding PowerShell executions from the last 7 days..."
$query1 = @"
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-encoded"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| limit 100
"@

$results1 = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query1
Write-Host "Found $($results1.Count) PowerShell executions with encoding"
$results1 | Format-Table -AutoSize

# Example 2: Find failed sign-in attempts
Write-Host "`nExample 2: Finding failed sign-in attempts..."
$query2 = @"
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count() by AccountName, IPAddress
| where FailedAttempts > 5
| order by FailedAttempts desc
"@

$results2 = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query2
Write-Host "Found $($results2.Count) accounts with multiple failed sign-ins"
$results2 | Format-Table -AutoSize

# Example 3: Network connections to suspicious domains
Write-Host "`nExample 3: Finding network connections..."
$query3 = @"
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("download", "temp", "tmp")
| summarize ConnectionCount=count() by DeviceName, RemoteUrl, RemoteIP
| order by ConnectionCount desc
| limit 50
"@

$results3 = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query3
Write-Host "Found $($results3.Count) devices with suspicious network connections"
$results3 | Format-Table -AutoSize

# Example 4: File creation events
Write-Host "`nExample 4: Finding suspicious file creations..."
$query4 = @"
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\temp\\", "\\tmp\\", "\\downloads\\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| limit 100
"@

$results4 = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query4
Write-Host "Found $($results4.Count) suspicious file creations"
$results4 | Format-Table -AutoSize

# Export results to CSV
Write-Host "`nExporting results to CSV files..."
$results1 | Export-Csv -Path "powershell_executions.csv" -NoTypeInformation
$results2 | Export-Csv -Path "failed_signins.csv" -NoTypeInformation
$results3 | Export-Csv -Path "network_connections.csv" -NoTypeInformation
$results4 | Export-Csv -Path "file_creations.csv" -NoTypeInformation

Write-Host "Results exported successfully!"

# Disconnect
Disconnect-DefenderXDR
