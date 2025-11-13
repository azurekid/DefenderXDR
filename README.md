# DefenderXDR PowerShell Module

PowerShell module for managing Microsoft Defender XDR (Extended Detection and Response) configurations through Microsoft Graph API.

## Overview

This module provides a comprehensive set of cmdlets to interact with Microsoft Defender XDR using the Microsoft Graph API. It enables security administrators and analysts to automate security operations, manage alerts and incidents, work with threat intelligence, and perform advanced hunting queries.

## Features

- **Authentication**: Secure authentication to Microsoft Graph API
  - Access token authentication
  - Client credentials (service principal) authentication
  - Token expiration management

- **Security Alerts Management**
  - Get security alerts with filtering and pagination
  - Update alert status, classification, and assignment
  - Add comments to alerts

- **Incident Management**
  - Retrieve and filter security incidents
  - Update incident properties
  - Add comments to incidents

- **Threat Intelligence**
  - Get threat intelligence indicators
  - Submit new threat indicators
  - Remove threat indicators

- **Security Posture**
  - Get Microsoft Secure Score
  - Retrieve Secure Score control profiles

- **Advanced Hunting**
  - Execute KQL queries against Defender XDR data

## Installation

### From Local Path

```powershell
# Clone the repository
git clone https://github.com/azurekid/DefenderXDR.git

# Import the module
Import-Module ./DefenderXDR/DefenderXDR/DefenderXDR.psd1
```

### Verify Installation

```powershell
Get-Module DefenderXDR
Get-Command -Module DefenderXDR
```

## Prerequisites

- PowerShell 5.1 or PowerShell 7+
- Azure AD Application with appropriate permissions:
  - `SecurityEvents.Read.All` - Read security events
  - `SecurityEvents.ReadWrite.All` - Read and write security events
  - `SecurityActions.Read.All` - Read security actions
  - `SecurityActions.ReadWrite.All` - Read and write security actions
  - `ThreatIndicators.ReadWrite.OwnedBy` - Manage threat indicators

## Quick Start

### 1. Authentication with Access Token

```powershell
# Import the module
Import-Module DefenderXDR

# Connect using an access token
Connect-DefenderXDR -AccessToken "eyJ0eXAiOiJKV1QiLCJub25jZSI6..."

# Check connection status
Get-DefenderXDRAccessToken
```

### 2. Authentication with Client Credentials

```powershell
# Connect using client ID and secret
Connect-DefenderXDR -TenantId "contoso.onmicrosoft.com" `
                     -ClientId "12345678-1234-1234-1234-123456789012" `
                     -ClientSecret "your-client-secret"
```

### 3. Working with Alerts

```powershell
# Get all high severity alerts
$alerts = Get-DefenderXDRAlert -Filter "severity eq 'high'" -Top 50

# Get a specific alert
$alert = Get-DefenderXDRAlert -AlertId "da12345678901234567890123456789012"

# Update alert status
Update-DefenderXDRAlert -AlertId $alert.id -Status "inProgress" -AssignedTo "analyst@contoso.com"

# Add a comment
New-DefenderXDRAlertComment -AlertId $alert.id -Comment "Investigating this alert"

# Mark as resolved
Update-DefenderXDRAlert -AlertId $alert.id -Status "resolved" -Classification "falsePositive"
```

### 4. Working with Incidents

```powershell
# Get recent incidents
$incidents = Get-DefenderXDRIncident -Top 20

# Get high severity incidents
$highSeverityIncidents = Get-DefenderXDRIncident -Filter "severity eq 'high'"

# Update incident
Update-DefenderXDRIncident -IncidentId "123" -Status "active" -AssignedTo "soc-team@contoso.com"

# Add comment to incident
New-DefenderXDRIncidentComment -IncidentId "123" -Comment "Escalating to Tier 2"
```

### 5. Threat Intelligence

```powershell
# Get threat indicators
$indicators = Get-DefenderXDRThreatIntelligence -Top 100

# Submit a malicious domain indicator
Submit-DefenderXDRThreatIndicator -IndicatorValue "malicious.com" `
                                    -IndicatorType "domainName" `
                                    -Action "block" `
                                    -ThreatType "Malware" `
                                    -Description "Known C2 server" `
                                    -Severity 5

# Submit a file hash indicator
Submit-DefenderXDRThreatIndicator -IndicatorValue "abc123..." `
                                    -IndicatorType "fileSha256" `
                                    -Action "alert" `
                                    -ThreatType "Malware"

# Remove an indicator
Remove-DefenderXDRThreatIndicator -IndicatorId "ti123..."
```

### 6. Security Posture

```powershell
# Get current Secure Score
$secureScore = Get-DefenderXDRSecureScore

# Get all security control profiles
$controls = Get-DefenderXDRSecureScoreControlProfile

# Get specific control
$mfaControl = Get-DefenderXDRSecureScoreControlProfile -ControlId "AdminMFA"
```

### 7. Defender Endpoint API - Threat Indicators

```powershell
# Get all threat indicators
$indicators = Get-DefenderXDRIndicator -Top 100

# Get specific indicator by ID
$indicator = Get-DefenderXDRIndicator -IndicatorId "12345"

# Filter indicators
$highSeverity = Get-DefenderXDRIndicator -Filter "severity eq 'High'" -OrderBy "creationTime desc"

# Bulk import indicators
$indicatorsToImport = @(
    @{
        indicatorValue = "malicious.com"
        indicatorType = "DomainName"
        action = "Block"
        severity = "High"
        title = "Malicious Domain"
        description = "Known phishing domain"
        expirationTime = (Get-Date).AddDays(30).ToString('o')
    },
    @{
        indicatorValue = "192.0.2.1"
        indicatorType = "IpAddress"
        action = "Alert"
        severity = "Medium"
        title = "Suspicious IP"
    }
)
Import-DefenderXDRIndicators -Indicators $indicatorsToImport

# Remove single indicator
Remove-DefenderXDRIndicator -IndicatorId "12345"

# Batch remove expired indicators
$expired = Get-DefenderXDRIndicator -Filter "expirationTime lt $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
$expiredIds = $expired | Select-Object -ExpandProperty id
Remove-DefenderXDRIndicatorBatch -IndicatorIds $expiredIds
```

### 8. Advanced Hunting

```powershell
# Simple query
$query = "DeviceProcessEvents | where FileName == 'powershell.exe' | limit 10"
$results = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query

# Complex query with multiple lines
$query = @"
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl contains "suspicious"
| summarize Count=count() by DeviceName, RemoteUrl
| order by Count desc
"@
$results = Invoke-DefenderXDRAdvancedHuntingQuery -Query $query

# Export results
$results | Export-Csv -Path "hunting_results.csv" -NoTypeInformation
```

### 9. Disconnect

```powershell
# Disconnect and clear stored credentials
Disconnect-DefenderXDR
```

## Common Workflows

### Workflow 1: Alert Triage

```powershell
# Get new high severity alerts
$newAlerts = Get-DefenderXDRAlert -Filter "status eq 'new' and severity eq 'high'" -Top 50

foreach ($alert in $newAlerts) {
    Write-Host "Processing alert: $($alert.title)"
    
    # Update to in progress
    Update-DefenderXDRAlert -AlertId $alert.id -Status "inProgress" -AssignedTo "analyst@contoso.com"
    
    # Add initial triage comment
    New-DefenderXDRAlertComment -AlertId $alert.id -Comment "Alert triaged, investigating..."
}
```

### Workflow 2: Incident Response

```powershell
# Get active incidents
$activeIncidents = Get-DefenderXDRIncident -Filter "status eq 'active'"

foreach ($incident in $activeIncidents) {
    # Get associated alerts
    $alerts = Get-DefenderXDRAlert -Filter "incidentId eq '$($incident.id)'"
    
    Write-Host "Incident $($incident.id) has $($alerts.Count) alerts"
    
    # Take action based on severity
    if ($incident.severity -eq 'high') {
        Update-DefenderXDRIncident -IncidentId $incident.id `
                                    -AssignedTo "senior-analyst@contoso.com" `
                                    -Tags @("high-priority", "urgent")
    }
}
```

### Workflow 3: Threat Intelligence Management

```powershell
# Import IOCs from a file
$iocs = Import-Csv "iocs.csv"

foreach ($ioc in $iocs) {
    Submit-DefenderXDRThreatIndicator -IndicatorValue $ioc.Value `
                                       -IndicatorType $ioc.Type `
                                       -Action "block" `
                                       -ThreatType $ioc.ThreatType `
                                       -Description $ioc.Description
}

Write-Host "Submitted $($iocs.Count) threat indicators"
```

## API Permissions

To use this module, you need to register an Azure AD application and grant it the appropriate permissions based on which functions you plan to use.

### Permission Validation

**New in this release:** All functions now validate that your access token contains the required permissions before making API calls. If your token lacks the necessary permissions, you'll receive a clear error message indicating which permissions are required.

### Microsoft Graph API Permissions

#### Security Alerts Functions
- **Get-DefenderXDRAlert**: `SecurityEvents.Read.All` or `SecurityEvents.ReadWrite.All`
- **Update-DefenderXDRAlert**: `SecurityEvents.ReadWrite.All`
- **New-DefenderXDRAlertComment**: `SecurityEvents.ReadWrite.All`

#### Incident Management Functions
- **Get-DefenderXDRIncident**: `SecurityIncident.Read.All` or `SecurityIncident.ReadWrite.All`
- **Update-DefenderXDRIncident**: `SecurityIncident.ReadWrite.All`
- **New-DefenderXDRIncidentComment**: `SecurityIncident.ReadWrite.All`

#### Threat Intelligence Functions (Graph API)
- **Get-DefenderXDRThreatIntelligence**: `ThreatIndicators.Read.All` or `ThreatIndicators.ReadWrite.OwnedBy`
- **Submit-DefenderXDRThreatIndicator**: `ThreatIndicators.ReadWrite.OwnedBy`
- **Remove-DefenderXDRThreatIndicator**: `ThreatIndicators.ReadWrite.OwnedBy`

#### Security Posture Functions
- **Get-DefenderXDRSecureScore**: `SecurityEvents.Read.All` or `SecurityEvents.ReadWrite.All`
- **Get-DefenderXDRSecureScoreControlProfile**: `SecurityEvents.Read.All` or `SecurityEvents.ReadWrite.All`

#### Advanced Hunting Functions
- **Invoke-DefenderXDRAdvancedHuntingQuery**: `ThreatHunting.Read.All`

### Defender Endpoint API Permissions

The following functions use the Defender Endpoint API (`api.securitycenter.microsoft.com`) and require different permissions:

#### Threat Indicator Functions (Defender Endpoint API)
- **Get-DefenderXDRIndicator**: `Ti.Read.All` or `Ti.ReadWrite`
- **Import-DefenderXDRIndicators**: `Ti.ReadWrite`
- **Remove-DefenderXDRIndicator**: `Ti.ReadWrite`
- **Remove-DefenderXDRIndicatorBatch**: `Ti.ReadWrite`

### Recommended Permissions for Common Scenarios

#### Read-Only Security Monitoring
```
- SecurityEvents.Read.All
- SecurityIncident.Read.All
- ThreatIndicators.Read.All
- Ti.Read.All
- ThreatHunting.Read.All
```

#### Full Security Operations
```
- SecurityEvents.ReadWrite.All
- SecurityIncident.ReadWrite.All
- ThreatIndicators.ReadWrite.OwnedBy
- Ti.ReadWrite
- ThreatHunting.Read.All
```

#### Threat Intelligence Management Only
```
- ThreatIndicators.ReadWrite.OwnedBy (Graph API)
- Ti.ReadWrite (Defender Endpoint API)
```

### Permission Types

The module supports both **Application permissions** (for unattended scripts/service principals) and **Delegated permissions** (for interactive use). The permission validation works with both types.

## Error Handling

The module includes comprehensive error handling:

```powershell
try {
    $alerts = Get-DefenderXDRAlert -Filter "invalid filter"
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)"
}
```

## Logging and Debugging

Enable verbose output for detailed logging:

```powershell
# Enable verbose output
$VerbosePreference = 'Continue'

# Run commands
Get-DefenderXDRAlert -Verbose

# Disable verbose output
$VerbosePreference = 'SilentlyContinue'
```

## Module Functions

### Authentication
- `Connect-DefenderXDR` - Connect to Defender XDR
- `Disconnect-DefenderXDR` - Disconnect from Defender XDR
- `Get-DefenderXDRAccessToken` - Get current token information

### Security Alerts
- `Get-DefenderXDRAlert` - Get security alerts
- `Update-DefenderXDRAlert` - Update an alert
- `New-DefenderXDRAlertComment` - Add comment to an alert

### Incidents
- `Get-DefenderXDRIncident` - Get incidents
- `Update-DefenderXDRIncident` - Update an incident
- `New-DefenderXDRIncidentComment` - Add comment to an incident

### Threat Intelligence (Graph API)
- `Get-DefenderXDRThreatIntelligence` - Get threat indicators via Graph API
- `Submit-DefenderXDRThreatIndicator` - Submit a threat indicator via Graph API
- `Remove-DefenderXDRThreatIndicator` - Remove a threat indicator via Graph API

### Threat Intelligence (Defender Endpoint API)
- `Get-DefenderXDRIndicator` - Get threat indicators via Defender Endpoint API
- `Import-DefenderXDRIndicators` - Bulk import threat indicators
- `Remove-DefenderXDRIndicator` - Remove a single threat indicator
- `Remove-DefenderXDRIndicatorBatch` - Batch remove multiple threat indicators

### Security Posture
- `Get-DefenderXDRSecureScore` - Get Secure Score
- `Get-DefenderXDRSecureScoreControlProfile` - Get security controls

### Advanced Hunting
- `Invoke-DefenderXDRAdvancedHuntingQuery` - Run hunting queries

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/azurekid/DefenderXDR/issues
- Documentation: https://github.com/azurekid/DefenderXDR

## References

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/api/overview)
- [Microsoft Defender XDR](https://docs.microsoft.com/en-us/microsoft-365/security/defender/)
- [Graph API Security Reference](https://docs.microsoft.com/en-us/graph/api/resources/security-api-overview)
