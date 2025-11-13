# DefenderXDR

PowerShell module for managing Microsoft Defender XDR Threat Intelligence Indicators.

## Overview

This module provides cmdlets to interact with the Microsoft Defender XDR Threat Intelligence Indicator API, allowing you to programmatically manage threat indicators including creation, retrieval, update, and deletion operations.

## Features

- **Authentication**: Connect to Microsoft Defender XDR API using app credentials or access tokens
- **Complete CRUD Operations**: Create, Read, Update, and Delete threat intelligence indicators
- **Bulk Operations**: Import and export indicators from/to CSV files
- **Pipeline Support**: Full PowerShell pipeline support for efficient batch operations
- **Comprehensive Documentation**: Detailed help for all cmdlets with examples

## Installation

1. Clone or download this repository
2. Import the module:
   ```powershell
   Import-Module ./DefenderXDR/DefenderXDR.psd1
   ```

## Quick Start

```powershell
# Connect to Defender XDR API
$appSecret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
Connect-DefenderXDR -TenantId "your-tenant-id" -AppId "your-app-id" -AppSecret $appSecret

# List all indicators
Get-DefenderXDRTIIndicator

# Create a new indicator
New-DefenderXDRTIIndicator -IndicatorValue "malicious.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Malicious Domain" `
    -Severity High

# Disconnect
Disconnect-DefenderXDR
```

## Available Cmdlets

- `Connect-DefenderXDR` - Establish connection to Defender XDR API
- `Disconnect-DefenderXDR` - Clear stored connection
- `Get-DefenderXDRTIIndicator` - Retrieve threat intelligence indicators
- `New-DefenderXDRTIIndicator` - Create a new threat intelligence indicator
- `Set-DefenderXDRTIIndicator` - Update an existing threat intelligence indicator
- `Remove-DefenderXDRTIIndicator` - Delete a threat intelligence indicator
- `Import-DefenderXDRTIIndicator` - Import indicators from CSV file
- `Export-DefenderXDRTIIndicator` - Export indicators to CSV file

## Documentation

For detailed documentation and examples, see:
- [Module README](DefenderXDR/README.md) - Complete module documentation
- [Examples](DefenderXDR/Examples.md) - Comprehensive usage examples

## API Reference

This module implements the Microsoft Defender Endpoint TI Indicator API:
- [Microsoft Defender Endpoint API - TI Indicator](https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator)

## Requirements

- PowerShell 5.1 or higher
- Azure AD App Registration with Microsoft Threat Protection API permissions (Ti.ReadWrite)

## License

See LICENSE file for details.
