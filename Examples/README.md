# DefenderXDR Module Examples

This directory contains example scripts demonstrating how to use the DefenderXDR PowerShell module.

## Prerequisites

Before running these examples:

1. Install the DefenderXDR module (see [INSTALLATION.md](../INSTALLATION.md))
2. Configure an Azure AD application with required permissions
3. Have your credentials ready (tenant ID, client ID, client secret, or access token)

## Examples Overview

### 01-Get-Alerts.ps1
**Purpose**: Basic alert retrieval and filtering

This example demonstrates:
- Connecting to Defender XDR
- Retrieving security alerts
- Filtering alerts by severity
- Filtering alerts by time period
- Checking connection status

**Use Case**: Daily security monitoring and alert review

### 02-Alert-Triage.ps1
**Purpose**: Automated alert triage workflow

This example demonstrates:
- Processing new alerts automatically
- Assigning alerts based on severity
- Adding contextual comments
- Implementing triage logic
- Batch processing alerts

**Use Case**: SOC automation for initial alert triage

### 03-Advanced-Hunting.ps1
**Purpose**: Running advanced hunting queries

This example demonstrates:
- Executing KQL queries against Defender XDR data
- Multiple query examples (PowerShell executions, failed logins, network connections, file creations)
- Exporting results to CSV
- Data analysis and threat hunting

**Use Case**: Proactive threat hunting and security investigations

### 04-Threat-Intelligence.ps1
**Purpose**: Managing threat intelligence indicators (Graph API)

This example demonstrates:
- Submitting threat indicators (domains, IPs, file hashes)
- Bulk importing indicators
- Listing current indicators
- Removing indicators
- Different indicator types and actions

**Use Case**: IOC management and threat intelligence integration using Graph API

### 05-Defender-Endpoint-Indicators.ps1
**Purpose**: Managing threat indicators using Defender Endpoint API

This example demonstrates:
- Retrieving threat indicators from Defender Endpoint API
- Getting specific indicators by ID
- Filtering and ordering indicators
- Bulk importing multiple indicators
- Single and batch removal operations
- Pipeline usage for indicator management

**Use Case**: Advanced IOC management using the native Defender Endpoint API with support for bulk operations

## How to Use These Examples

### Step 1: Update Credentials

Edit each example file and replace the placeholder credentials:

```powershell
# Replace this line:
$accessToken = "YOUR_ACCESS_TOKEN_HERE"

# With your actual token or credentials:
$tenantId = "your-tenant-id"
$clientId = "your-client-id"  
$clientSecret = "your-client-secret"

Connect-DefenderXDR -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
```

### Step 2: Run the Example

```powershell
# Navigate to the Examples directory
cd DefenderXDR/Examples

# Run an example
.\01-Get-Alerts.ps1
```

### Step 3: Review the Output

Each example includes Write-Host statements to show progress and results.

## Customizing Examples

Feel free to modify these examples for your environment:

### Modify Filters

```powershell
# Original
$alerts = Get-DefenderXDRAlert -Filter "severity eq 'high'"

# Modified - get medium and high severity
$alerts = Get-DefenderXDRAlert -Filter "severity eq 'high' or severity eq 'medium'"
```

### Change Time Periods

```powershell
# Last 7 days instead of 24 hours
$lastWeek = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
$alerts = Get-DefenderXDRAlert -Filter "createdDateTime ge $lastWeek"
```

### Adjust Assignment Logic

```powershell
# Assign to different teams based on category
switch ($alert.category) {
    'Malware' { $assignTo = "malware-team@contoso.com" }
    'Phishing' { $assignTo = "phishing-team@contoso.com" }
    default { $assignTo = "soc-general@contoso.com" }
}
```

## Creating Your Own Scripts

Use these examples as templates for your own automation:

### Template: Basic Script

```powershell
# Import module
Import-Module DefenderXDR

# Connect
Connect-DefenderXDR -TenantId "..." -ClientId "..." -ClientSecret "..."

try {
    # Your code here
    $results = Get-DefenderXDRAlert -Top 10
    
    # Process results
    foreach ($result in $results) {
        # Your logic
    }
}
catch {
    Write-Error "Error: $_"
}
finally {
    # Always disconnect
    Disconnect-DefenderXDR
}
```

### Template: Scheduled Script

```powershell
<#
.SYNOPSIS
    Automated Defender XDR monitoring script
.DESCRIPTION
    Runs on a schedule to process alerts and incidents
.NOTES
    Schedule with Task Scheduler or cron
#>

# Configure logging
$logFile = "C:\Logs\DefenderXDR_$(Get-Date -Format 'yyyyMMdd').log"
Start-Transcript -Path $logFile

try {
    # Import and connect
    Import-Module DefenderXDR
    Connect-DefenderXDR -TenantId $env:DEFENDER_TENANT `
                         -ClientId $env:DEFENDER_CLIENT `
                         -ClientSecret $env:DEFENDER_SECRET
    
    # Your automation logic
    $newAlerts = Get-DefenderXDRAlert -Filter "status eq 'new'" -Top 100
    
    foreach ($alert in $newAlerts) {
        # Process each alert
    }
    
    Write-Host "Processed $($newAlerts.Count) alerts"
}
catch {
    Write-Error "Script failed: $_"
    # Send notification email
}
finally {
    Disconnect-DefenderXDR
    Stop-Transcript
}
```

## Advanced Scenarios

### Scenario 1: Automated Incident Response

```powershell
# Get high severity incidents
$incidents = Get-DefenderXDRIncident -Filter "severity eq 'high' and status eq 'active'"

foreach ($incident in $incidents) {
    # Auto-escalate and notify
    Update-DefenderXDRIncident -IncidentId $incident.id `
                                -AssignedTo "incident-response@contoso.com" `
                                -Tags @("auto-escalated", "high-priority")
    
    # Send notification (using your notification system)
    Send-Notification -To "incident-response@contoso.com" `
                      -Subject "High Severity Incident: $($incident.id)" `
                      -Body "Incident details: $($incident | ConvertTo-Json)"
}
```

### Scenario 2: Threat Intelligence Sync

```powershell
# Sync IOCs from your threat feed
$threatFeed = Invoke-RestMethod -Uri "https://your-threat-feed.com/api/indicators"

foreach ($ioc in $threatFeed) {
    # Submit to Defender
    Set-DefenderXDRThreatIndicator `
        -IndicatorValue $ioc.value `
        -IndicatorType $ioc.type `
        -Action "block" `
        -ThreatType $ioc.threatType `
        -Description "Auto-imported from threat feed"
}
```

### Scenario 3: Security Metrics Dashboard

```powershell
# Collect metrics
$secureScore = Get-DefenderXDRSecureScore | Select-Object -First 1
$openAlerts = Get-DefenderXDRAlert -Filter "status ne 'resolved'" -Top 1000
$activeIncidents = Get-DefenderXDRIncident -Filter "status eq 'active'" -Top 1000

# Create summary
$metrics = @{
    SecureScore = $secureScore.currentScore
    MaxScore = $secureScore.maxScore
    OpenAlerts = $openAlerts.Count
    HighSeverityAlerts = ($openAlerts | Where-Object {$_.severity -eq 'high'}).Count
    ActiveIncidents = $activeIncidents.Count
    Timestamp = Get-Date
}

# Export or display metrics
$metrics | ConvertTo-Json | Out-File "metrics_$(Get-Date -Format 'yyyyMMdd').json"
```

## Best Practices

1. **Always Disconnect**: Use try-finally to ensure disconnection
2. **Error Handling**: Wrap operations in try-catch blocks
3. **Logging**: Use Start-Transcript for scheduled scripts
4. **Credentials**: Use secure credential storage (see INSTALLATION.md)
5. **Rate Limiting**: Be mindful of API rate limits
6. **Filtering**: Use filters to reduce data transfer and processing
7. **Testing**: Test scripts in a non-production environment first

## Troubleshooting

### Script Hangs
- Check your token hasn't expired
- Verify network connectivity
- Look for infinite loops in your code

### No Data Returned
- Verify your filter syntax
- Check permissions on your Azure AD app
- Ensure you have data in Defender XDR

### Authentication Errors
- Verify tenant ID, client ID, and client secret
- Check that admin consent was granted
- Ensure the client secret hasn't expired

## Additional Resources

- [README.md](../README.md) - Full module documentation
- [INSTALLATION.md](../INSTALLATION.md) - Installation guide
- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/api/resources/security-api-overview)
- [Defender XDR Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender/)

## Contributing

Have a useful example? Please contribute it!

1. Create your example script
2. Add documentation
3. Test thoroughly
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
