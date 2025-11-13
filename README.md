# DefenderXDR

PowerShell module for Defender XDR configurations

## Overview

This repository contains PowerShell functions to interact with Microsoft Defender XDR (formerly Microsoft Defender for Endpoint) APIs. The implementation is based on the official Microsoft Defender Endpoint API documentation.

## Features

- **Get-DefenderXDRIndicators**: Retrieve threat intelligence indicators from Defender for Endpoint
  - Supports retrieving all indicators or a specific indicator by ID
  - Azure AD OAuth2 authentication
  - Secure credential handling with SecureString
  - Comprehensive help documentation

## Quick Start

See [FUNCTION_README.md](FUNCTION_README.md) for detailed documentation on using the Get-DefenderXDRIndicators function.

```powershell
# Import the function
. ./Get-DefenderXDRIndicators.ps1

# Authenticate and retrieve indicators
$secret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
$indicators = Get-DefenderXDRIndicators `
    -TenantId "contoso.onmicrosoft.com" `
    -AppId "12345678-1234-1234-1234-123456789012" `
    -AppSecret $secret
```

## Files

- `Get-DefenderXDRIndicators.ps1` - Main function to retrieve indicators
- `FUNCTION_README.md` - Detailed documentation and usage guide
- `Example-Usage.ps1` - Example scripts demonstrating various use cases
- `Test-Function.ps1` - Validation tests for the function

## API Reference

Based on Microsoft Defender Endpoint API documentation:
- [Threat Intelligence Indicators API](https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator)

## Prerequisites

- PowerShell 5.1 or PowerShell Core 7.x
- Azure AD application with Ti.ReadWrite or Ti.ReadWrite.All permissions
- Admin consent granted for the API permissions

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
