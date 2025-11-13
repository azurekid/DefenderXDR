# DefenderXDR PowerShell Module

PowerShell module for managing Microsoft Defender XDR Threat Intelligence Indicators via the API.

## Overview

This module provides a comprehensive set of cmdlets to interact with the Microsoft Defender XDR Threat Intelligence Indicator API. It allows you to create, read, update, and delete threat intelligence indicators programmatically.

## Features

- **Authentication**: Connect to Microsoft Defender XDR API using app credentials or access tokens
- **CRUD Operations**: Complete support for Create, Read, Update, and Delete operations on TI Indicators
- **Bulk Operations**: Import and export indicators from/to CSV files
- **Pipeline Support**: PowerShell pipeline support for efficient batch operations
- **Comprehensive Help**: Detailed help documentation for all cmdlets

## Prerequisites

- PowerShell 5.1 or higher
- Azure AD App Registration with the following API permissions:
  - Microsoft Threat Protection API: `Ti.ReadWrite` (Application permission)
- App credentials (Tenant ID, App ID, App Secret)

## Installation

### Manual Installation

1. Clone or download this repository
2. Copy the `DefenderXDR` folder to one of your PowerShell module paths:
   ```powershell
   $env:PSModulePath -split ';'
   ```
3. Import the module:
   ```powershell
   Import-Module DefenderXDR
   ```

### Verify Installation

```powershell
Get-Module -Name DefenderXDR -ListAvailable
```

## Getting Started

### Authentication

First, connect to the Defender XDR API:

```powershell
# Using App Credentials
$appSecret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
Connect-DefenderXDR -TenantId "your-tenant-id" -AppId "your-app-id" -AppSecret $appSecret

# Using Pre-obtained Access Token
Connect-DefenderXDR -AccessToken "your-access-token"
```

### Basic Operations

#### List All Indicators

```powershell
Get-DefenderXDRTIIndicator
```

#### Get a Specific Indicator

```powershell
Get-DefenderXDRTIIndicator -Id "12345"
```

#### Filter Indicators

```powershell
# By indicator value
Get-DefenderXDRTIIndicator -IndicatorValue "malicious.com"

# By indicator type
Get-DefenderXDRTIIndicator -IndicatorType DomainName
```

#### Create a New Indicator

```powershell
# Block a malicious domain
New-DefenderXDRTIIndicator -IndicatorValue "malicious.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Malicious Domain" `
    -Description "Known phishing domain" `
    -Severity High

# Alert on suspicious IP
New-DefenderXDRTIIndicator -IndicatorValue "192.0.2.1" `
    -IndicatorType IpAddress `
    -Action Alert `
    -Title "Suspicious IP" `
    -Description "Known C2 server" `
    -Severity Medium `
    -ExpirationTime (Get-Date).AddDays(30)

# Block malicious file hash
New-DefenderXDRTIIndicator -IndicatorValue "3395856ce81f2b7382dee72602f798b642f14140" `
    -IndicatorType FileSha1 `
    -Action Block `
    -Title "Malware Hash" `
    -Severity High
```

#### Update an Indicator

```powershell
# Update severity
Set-DefenderXDRTIIndicator -Id "12345" -Severity Critical

# Update action and description
Set-DefenderXDRTIIndicator -Id "12345" `
    -Action AlertAndBlock `
    -Description "Updated: Known APT infrastructure"
```

#### Delete an Indicator

```powershell
# Delete a specific indicator
Remove-DefenderXDRTIIndicator -Id "12345"

# Pipeline example
Get-DefenderXDRTIIndicator -IndicatorValue "old-domain.com" | Remove-DefenderXDRTIIndicator
```

### Bulk Operations

#### Import Indicators from CSV

```powershell
Import-DefenderXDRTIIndicator -Path "C:\indicators.csv"
```

CSV file format:
```csv
IndicatorValue,IndicatorType,Action,Title,Description,Severity
malicious1.com,DomainName,Block,Bad Domain 1,Phishing site,High
192.0.2.1,IpAddress,Alert,Suspicious IP,Known C2,Medium
bad-url.com/malware,Url,Block,Malicious URL,Drive-by download,High
```

#### Export Indicators to CSV

```powershell
Export-DefenderXDRTIIndicator -Path "C:\exported-indicators.csv"
```

### Disconnect

```powershell
Disconnect-DefenderXDR
```

## Cmdlet Reference

### Connection Management

- `Connect-DefenderXDR` - Establish connection to Defender XDR API
- `Disconnect-DefenderXDR` - Clear stored connection

### Indicator Management

- `Get-DefenderXDRTIIndicator` - Retrieve threat intelligence indicators
- `New-DefenderXDRTIIndicator` - Create a new threat intelligence indicator
- `Set-DefenderXDRTIIndicator` - Update an existing threat intelligence indicator
- `Remove-DefenderXDRTIIndicator` - Delete a threat intelligence indicator

### Bulk Operations

- `Import-DefenderXDRTIIndicator` - Import indicators from CSV file
- `Export-DefenderXDRTIIndicator` - Export indicators to CSV file

## Supported Indicator Types

- `FileSha1` - SHA1 file hash
- `FileSha256` - SHA256 file hash
- `FileMd5` - MD5 file hash
- `IpAddress` - IPv4 or IPv6 address
- `DomainName` - Domain name
- `Url` - URL

## Supported Actions

- `Alert` - Generate an alert when the indicator is detected
- `AlertAndBlock` - Generate an alert and block the indicator
- `Block` - Block the indicator
- `Allowed` - Allow the indicator (whitelist)

## Supported Severity Levels

- `Informational`
- `Low`
- `Medium`
- `High`

## Advanced Examples

### Pipeline Operations

```powershell
# Get all high severity indicators and update them to critical
Get-DefenderXDRTIIndicator | 
    Where-Object { $_.severity -eq 'High' } | 
    Set-DefenderXDRTIIndicator -Severity Critical

# Find and remove expired indicators
Get-DefenderXDRTIIndicator | 
    Where-Object { $_.expirationTime -lt (Get-Date) } | 
    Remove-DefenderXDRTIIndicator
```

### Error Handling

```powershell
try {
    New-DefenderXDRTIIndicator -IndicatorValue "test.com" `
        -IndicatorType DomainName `
        -Action Block `
        -Title "Test Domain" `
        -Severity High
}
catch {
    Write-Error "Failed to create indicator: $_"
}
```

### Using WhatIf and Confirm

```powershell
# Preview changes without executing
New-DefenderXDRTIIndicator -IndicatorValue "test.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Test" `
    -WhatIf

# Require confirmation for deletions
Remove-DefenderXDRTIIndicator -Id "12345" -Confirm
```

## API Reference

For more information about the Microsoft Defender XDR Threat Intelligence Indicator API, see:
- [Microsoft Defender Endpoint API - TI Indicator](https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator)

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify your app has the correct API permissions
   - Ensure admin consent has been granted for the permissions
   - Check that your Tenant ID, App ID, and App Secret are correct

2. **API Errors**
   - Use `-Verbose` parameter to see detailed API requests
   - Check the error message for specific API error codes

3. **Connection Issues**
   - Ensure you have network connectivity to `api.securitycenter.microsoft.com`
   - Verify firewall rules allow HTTPS traffic to Microsoft endpoints

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the terms specified in the LICENSE file.

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Check the Microsoft Defender documentation

## Changelog

### Version 1.0.0
- Initial release
- Support for TI Indicator CRUD operations
- Bulk import/export functionality
- Comprehensive cmdlet help
