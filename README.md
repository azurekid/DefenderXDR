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

- **Custom Detection Rules**
  - Create custom detection rules based on KQL queries
  - Get and manage detection rules
  - Update and remove detection rules

- **Threat Intelligence**
  - Get threat intelligence indicators
  - Submit new threat indicators
  - Remove threat indicators

- **Security Posture**
  - Get Microsoft Secure Score
  - Retrieve Secure Score control profiles

- **Advanced Hunting**
  - Execute KQL queries against Defender XDR data

- **Object-Oriented Classes** (PowerShell 7.0+)
  - Typed objects for Alerts, Incidents, and Indicators
  - Built-in validation and methods
  - Enhanced IntelliSense support
  - Factory functions for object creation

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

- PowerShell Core 7.0 or higher
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

### 5. Custom Detection Rules

```powershell
# Get all detection rules
$rules = Get-DefenderXDRDetectionRule

# Get a specific detection rule
$rule = Get-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012"

# Create a new detection rule
New-DefenderXDRDetectionRule -DisplayName "Suspicious PowerShell Execution" `
                              -QueryCondition "DeviceProcessEvents | where FileName == 'powershell.exe' and ProcessCommandLine contains 'Invoke-Expression'" `
                              -Severity "high" `
                              -Description "Detects suspicious PowerShell execution patterns" `
                              -Category "Execution" `
                              -MitreTechniques @("T1059.001")

# Create a detection rule with schedule
$schedule = @{ 
    period = 'PT1H'  # Run every hour (ISO 8601 duration format)
}
New-DefenderXDRDetectionRule -DisplayName "Failed Login Attempts" `
                              -QueryCondition "SigninLogs | where ResultType != 0 | summarize FailedAttempts=count() by UserPrincipalName | where FailedAttempts > 5" `
                              -Severity "medium" `
                              -Schedule $schedule

# Update a detection rule
Update-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012" `
                                 -Severity "high" `
                                 -IsEnabled $true

# Disable a detection rule
Update-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012" -IsEnabled $false

# Remove a detection rule
Remove-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012"

# Get only enabled rules
$enabledRules = Get-DefenderXDRDetectionRule -Filter "isEnabled eq true"
```

### 6. Threat Intelligence

```powershell
# Get threat indicators
$indicators = Get-DefenderXDRThreatIntelligence -Top 100

# Submit a malicious domain indicator
Set-DefenderXDRThreatIndicator -IndicatorValue "malicious.com" `
                                    -IndicatorType "domainName" `
                                    -Action "block" `
                                    -ThreatType "Malware" `
                                    -Description "Known C2 server" `
                                    -Severity 5

# Submit a file hash indicator
Set-DefenderXDRThreatIndicator -IndicatorValue "abc123..." `
                                    -IndicatorType "fileSha256" `
                                    -Action "alert" `
                                    -ThreatType "Malware"

# Update an existing indicator
Set-DefenderXDRThreatIndicator -IndicatorId "ti123..." `
                                    -Action "allowed" `
                                    -Description "False positive - now allowed"

# Remove an indicator
Remove-DefenderXDRThreatIndicator -IndicatorId "ti123..."
```

### 7. Security Posture

```powershell
# Get current Secure Score
$secureScore = Get-DefenderXDRSecureScore

# Get all security control profiles
$controls = Get-DefenderXDRSecureScoreControlProfile

# Get specific control
$mfaControl = Get-DefenderXDRSecureScoreControlProfile -ControlId "AdminMFA"
```

### 8. Defender Endpoint API - Threat Indicators

```powershell
# Get all threat indicators
$indicators = Get-DefenderXDRIndicator -Top 100

# Get specific indicator by ID
$indicator = Get-DefenderXDRIndicator -IndicatorId "12345"

# Filter indicators
$highSeverity = Get-DefenderXDRIndicator -Filter "severity eq 'High'" -OrderBy "creationTime desc"

# Create a single indicator
Submit-DefenderXDRIndicator -IndicatorValue "malicious.com" `
                         -IndicatorType "DomainName" `
                         -Action "AlertAndBlock" `
                         -Title "Malicious Domain" `
                         -Severity "High" `
                         -Description "Known phishing domain" `
                         -ExpirationTime (Get-Date).AddDays(30).ToString('o')

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

### 9. Advanced Hunting

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

### 10. Disconnect

```powershell
# Disconnect and clear stored credentials
Disconnect-DefenderXDR
```

## Using Classes (PowerShell 5.1+)

This module includes PowerShell classes for enhanced type safety, validation, and object-oriented programming. Classes provide:

- **Type Safety**: Strongly-typed objects with validation
- **Methods**: Built-in methods for common operations
- **IntelliSense**: Better IDE support and auto-completion
- **Validation**: Automatic validation of properties and parameters

### Available Classes

- **`DefenderEntity`**: Base class for all Defender objects
- **`DefenderAlert`**: Alert objects with status update methods
- **`DefenderIncident`**: Incident objects with assignment and status methods
- **`DefenderIndicator`**: Threat indicator objects with validation
- **`DefenderQueryResult`**: Advanced hunting results with processing methods
- **`DefenderXDRClient`**: API client for managing connections
- **`DefenderValidator`**: Static validation methods

### Creating Objects with Classes

```powershell
# Create a new alert object
$alert = New-DefenderAlert -AlertId "da123..." -Title "Suspicious Login" -Severity "High"

# Update alert status using methods
$alert.UpdateStatus("inProgress")
$alert.AddComment("Investigating suspicious login pattern")
$alert.SetClassification("truePositive")

# Create an incident
$incident = New-DefenderIncident -IncidentId "ic456..." -Title "Brute Force Attack" -Severity "High"
$incident.AssignTo("security-team@contoso.com")
$incident.UpdateStatus("active")

# Create a threat indicator with validation
$indicator = New-DefenderIndicator -IndicatorValue "192.168.1.100" `
                                   -IndicatorType "IpAddress" `
                                   -Action "Block" `
                                   -Title "Malicious IP Address"
$indicator.SetExpiration((Get-Date).AddDays(30))
```

### Converting API Responses to Class Objects

```powershell
# Get alerts and convert to typed objects
$apiAlerts = Get-DefenderXDRAlert -Top 10
$typedAlerts = $apiAlerts | ConvertTo-DefenderAlert

# Work with typed objects
foreach ($alert in $typedAlerts) {
    if ($alert.Severity -eq 'High') {
        $alert.UpdateStatus('inProgress')
        # Additional processing...
    }
}

# Convert incidents
$apiIncidents = Get-DefenderXDRIncident -Top 5
$typedIncidents = $apiIncidents | ConvertTo-DefenderIncident
```

### Using the Defender Client Class

```powershell
# Create a client instance (future enhancement)
$client = [DefenderXDRClient]::new()
$client.Connect("client-secret-here")

# Get typed objects directly
$alerts = $client.GetAlerts("severity eq 'high'", 20)
$incidents = $client.GetIncidents("", 10)

# Run hunting queries with result processing
$queryResult = $client.RunHuntingQuery("DeviceProcessEvents | limit 100")
$highCpuProcesses = $queryResult.Where({ $_.CpuUsage -gt 80 })
$queryResult.ExportToCsv("high_cpu_processes.csv")
```

### Validation with Classes

```powershell
# Static validation methods
[DefenderValidator]::ValidateAlertStatus("inProgress")  # Valid
[DefenderValidator]::ValidateAlertStatus("invalid")     # Throws exception

[DefenderValidator]::ValidateIpAddress("192.168.1.1")   # Valid
[DefenderValidator]::ValidateIpAddress("999.999.999.999") # Throws exception

[DefenderValidator]::ValidateEmail("user@contoso.com")  # Valid
[DefenderValidator]::ValidateEmail("invalid-email")     # Throws exception
```

### Benefits of Using Classes

1. **Type Safety**: Catch errors at development time rather than runtime
2. **IntelliSense**: Better IDE support with property and method completion
3. **Validation**: Automatic validation prevents invalid data
4. **Methods**: Rich functionality built into objects
5. **Maintainability**: Object-oriented design is easier to extend and maintain
6. **Testing**: Easier to mock and test with typed objects

### Compatibility

Classes are supported in:
- PowerShell 5.1 (Windows PowerShell)
- PowerShell 7+ (PowerShell Core)
- All supported platforms (Windows, Linux, macOS)

The module automatically loads classes when available. If you're using an older PowerShell version that doesn't support classes, the module will still work with traditional functions.

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
    Set-DefenderXDRThreatIndicator -IndicatorValue $ioc.Value `
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

**Permission Matching:** The validation supports flexible permission matching. A token with a more permissive version of a permission (ending in `.All`) will satisfy requirements for the base permission. For example:
- A token with `Ti.ReadWrite.All` satisfies requirements for `Ti.ReadWrite`
- A token with `SecurityEvents.ReadWrite.All` satisfies requirements for `SecurityEvents.Read.All`

This ensures that tokens with broader permissions can be used for operations requiring more specific permissions.

### Microsoft Graph API Permissions

#### Security Alerts Functions
- **Get-DefenderXDRAlert**: `SecurityEvents.Read.All` or `SecurityEvents.ReadWrite.All`
- **Update-DefenderXDRAlert**: `SecurityEvents.ReadWrite.All`
- **New-DefenderXDRAlertComment**: `SecurityEvents.ReadWrite.All`

#### Incident Management Functions
- **Get-DefenderXDRIncident**: `SecurityIncident.Read.All` or `SecurityIncident.ReadWrite.All`
- **Update-DefenderXDRIncident**: `SecurityIncident.ReadWrite.All`
- **New-DefenderXDRIncidentComment**: `SecurityIncident.ReadWrite.All`

#### Custom Detection Rules Functions
- **Get-DefenderXDRDetectionRule**: `SecurityEvents.Read.All` or `SecurityEvents.ReadWrite.All`
- **New-DefenderXDRDetectionRule**: `SecurityEvents.ReadWrite.All`
- **Update-DefenderXDRDetectionRule**: `SecurityEvents.ReadWrite.All`
- **Remove-DefenderXDRDetectionRule**: `SecurityEvents.ReadWrite.All`

#### Threat Intelligence Functions (Graph API)
- **Get-DefenderXDRThreatIntelligence**: `ThreatIndicators.Read.All` or `ThreatIndicators.ReadWrite.OwnedBy`
- **Set-DefenderXDRThreatIndicator**: `ThreatIndicators.ReadWrite.OwnedBy`
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

### Custom Detection Rules
- `Get-DefenderXDRDetectionRule` - Get custom detection rules
- `New-DefenderXDRDetectionRule` - Create a new custom detection rule
- `Update-DefenderXDRDetectionRule` - Update a detection rule
- `Remove-DefenderXDRDetectionRule` - Remove a detection rule

### Threat Intelligence (Graph API)
- `Get-DefenderXDRThreatIntelligence` - Get threat indicators via Graph API
- `Set-DefenderXDRThreatIndicator` - Submit or update a threat indicator via Graph API
- `Remove-DefenderXDRThreatIndicator` - Remove a threat indicator via Graph API

### Threat Intelligence (Defender Endpoint API)
- `Get-DefenderXDRIndicator` - Get threat indicators via Defender Endpoint API
- `Submit-DefenderXDRIndicator` - Submit a single threat indicator
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
