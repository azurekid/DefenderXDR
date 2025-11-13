# Defender XDR Indicators Function

This repository contains a PowerShell function to interact with Microsoft Defender XDR (Defender for Endpoint) Threat Intelligence Indicators API.

## Overview

The `Get-DefenderXDRIndicators` function allows you to retrieve threat intelligence indicators from Microsoft Defender for Endpoint using the REST API.

## API Documentation

This implementation is based on the Microsoft Defender Endpoint API documentation:
https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator

## Prerequisites

1. **Azure AD App Registration**: You need an Azure AD application with the following:
   - Application (client) ID
   - Client secret
   - API Permission: `Ti.ReadWrite` or `Ti.ReadWrite.All` for Microsoft Defender for Endpoint

2. **PowerShell**: PowerShell 5.1 or PowerShell Core 7.x

## Setup

### Register an Azure AD Application

1. Go to the Azure Portal
2. Navigate to Azure Active Directory > App registrations
3. Click "New registration"
4. Give it a name (e.g., "Defender XDR Indicators")
5. Click "Register"
6. Note the **Application (client) ID** and **Directory (tenant) ID**
7. Go to "Certificates & secrets" and create a new client secret
8. Note the secret value (you won't be able to see it again)
9. Go to "API permissions" and add:
   - Microsoft Threat Protection > Application permissions > Ti.ReadWrite.All
10. Click "Grant admin consent"

## Usage

### Import the Function

```powershell
# Import the function
. ./Get-DefenderXDRIndicators.ps1
```

### Retrieve All Indicators

```powershell
# Convert your app secret to a SecureString
$appSecret = ConvertTo-SecureString "your-app-secret-here" -AsPlainText -Force

# Get all indicators
$indicators = Get-DefenderXDRIndicators `
    -TenantId "contoso.onmicrosoft.com" `
    -AppId "12345678-1234-1234-1234-123456789012" `
    -AppSecret $appSecret

# Display indicators
$indicators | Format-Table
```

### Retrieve a Specific Indicator

```powershell
# Convert your app secret to a SecureString
$appSecret = ConvertTo-SecureString "your-app-secret-here" -AsPlainText -Force

# Get a specific indicator by ID
$indicator = Get-DefenderXDRIndicators `
    -TenantId "contoso.onmicrosoft.com" `
    -AppId "12345678-1234-1234-1234-123456789012" `
    -AppSecret $appSecret `
    -IndicatorId "12345"

# Display indicator
$indicator
```

### Enable Verbose Output

```powershell
# Use -Verbose to see detailed operation logs
Get-DefenderXDRIndicators `
    -TenantId "contoso.onmicrosoft.com" `
    -AppId "12345678-1234-1234-1234-123456789012" `
    -AppSecret $appSecret `
    -Verbose
```

## Function Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `TenantId` | String | Yes | Azure AD tenant ID or domain (e.g., "contoso.onmicrosoft.com") |
| `AppId` | String | Yes | Azure AD application (client) ID |
| `AppSecret` | SecureString | Yes | Azure AD application secret |
| `IndicatorId` | String | No | Specific indicator ID to retrieve. If not provided, all indicators are returned |

## Return Value

The function returns:
- **Without IndicatorId**: An array of indicator objects
- **With IndicatorId**: A single indicator object

Each indicator object contains properties such as:
- `id`: Unique identifier
- `indicatorValue`: The indicator value (IP, domain, hash, etc.)
- `indicatorType`: Type of indicator (e.g., FileSha1, FileSha256, IpAddress, DomainName, Url)
- `action`: Action to take (Alert, AlertAndBlock, Allowed)
- `severity`: Severity level (Informational, Low, Medium, High)
- `title`: Indicator title
- `description`: Indicator description
- `expirationTime`: When the indicator expires
- `createdBy`: Who created the indicator
- `createdDateTime`: When the indicator was created

## Error Handling

The function includes comprehensive error handling:
- Authentication failures are caught and reported
- API errors are caught and the response body is displayed
- Sensitive data (app secret, token) is cleared from memory after use

## Security Considerations

- Always use `SecureString` for the app secret
- The function clears sensitive data from memory after use
- Consider using Azure Key Vault to store app secrets instead of hardcoding them
- Limit the permissions of the Azure AD app to the minimum required

## API Endpoints Used

- **Authentication**: `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`
- **List Indicators**: `GET https://api.securitycenter.microsoft.com/api/indicators`
- **Get Indicator**: `GET https://api.securitycenter.microsoft.com/api/indicators/{id}`

## Examples

See the Examples section in the function help:

```powershell
Get-Help Get-DefenderXDRIndicators -Examples
```

## Troubleshooting

### Authentication Fails

- Verify your TenantId, AppId, and AppSecret are correct
- Ensure the Azure AD app has been granted admin consent for the API permissions
- Check that the app secret hasn't expired

### No Indicators Returned

- Verify the Azure AD app has the correct permissions (Ti.ReadWrite or Ti.ReadWrite.All)
- Ensure admin consent has been granted
- Check if any indicators exist in your Defender for Endpoint tenant

### API Errors

- Use the `-Verbose` parameter to see detailed operation logs
- Check the error message for specific API error codes
- Verify network connectivity to Azure endpoints

## License

This project is provided as-is for educational and practical purposes.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
