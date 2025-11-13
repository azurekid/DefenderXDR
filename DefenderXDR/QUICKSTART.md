# Quick Start Guide

This guide will help you get started with the DefenderXDR PowerShell module in minutes.

## Prerequisites

Before you begin, you need:

1. **PowerShell 5.1 or higher**
   ```powershell
   $PSVersionTable.PSVersion
   ```

2. **Azure AD App Registration** with the following:
   - Tenant ID
   - Application (Client) ID
   - Application Secret
   - API Permissions: `Microsoft Threat Protection API` → `Ti.ReadWrite` (Application permission)
   - Admin consent granted

## Step 1: Import the Module

```powershell
# Navigate to the module directory
cd DefenderXDR

# Import the module
Import-Module .\DefenderXDR.psd1
```

## Step 2: Connect to Defender XDR

```powershell
# Prepare your credentials
$tenantId = "your-tenant-id.onmicrosoft.com"
$appId = "your-app-id"
$appSecretText = "your-app-secret"
$appSecret = ConvertTo-SecureString $appSecretText -AsPlainText -Force

# Connect
Connect-DefenderXDR -TenantId $tenantId -AppId $appId -AppSecret $appSecret
```

## Step 3: Test the Connection

```powershell
# List existing indicators
Get-DefenderXDRTIIndicator
```

## Step 4: Create Your First Indicator

```powershell
# Block a malicious domain
New-DefenderXDRTIIndicator -IndicatorValue "malicious-test.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Test Malicious Domain" `
    -Description "This is a test indicator" `
    -Severity Medium
```

## Step 5: View Your Indicator

```powershell
# Search for your indicator
Get-DefenderXDRTIIndicator -IndicatorValue "malicious-test.com"
```

## Step 6: Update an Indicator

```powershell
# First, get the indicator ID
$indicator = Get-DefenderXDRTIIndicator -IndicatorValue "malicious-test.com"

# Update the severity
Set-DefenderXDRTIIndicator -Id $indicator.id -Severity High
```

## Step 7: Clean Up

```powershell
# Delete the test indicator
Remove-DefenderXDRTIIndicator -Id $indicator.id

# Disconnect
Disconnect-DefenderXDR
```

## Common Tasks

### Bulk Import from CSV

```powershell
# Use the sample file
Import-DefenderXDRTIIndicator -Path ".\sample-indicators.csv" -Verbose
```

### Export All Indicators

```powershell
Export-DefenderXDRTIIndicator -Path "C:\temp\my-indicators.csv"
```

### Filter by Type

```powershell
# Get only IP address indicators
Get-DefenderXDRTIIndicator -IndicatorType IpAddress
```

### Pipeline Operations

```powershell
# Find and update all medium severity indicators
Get-DefenderXDRTIIndicator | 
    Where-Object { $_.severity -eq 'Medium' } |
    Set-DefenderXDRTIIndicator -Severity High
```

## Getting Help

```powershell
# List all available commands
Get-Command -Module DefenderXDR

# Get help for a specific command
Get-Help New-DefenderXDRTIIndicator -Full

# View examples
Get-Help New-DefenderXDRTIIndicator -Examples
```

## Next Steps

- Review the [complete README](README.md) for detailed documentation
- Check out [Examples.md](Examples.md) for 15 comprehensive usage examples
- Explore the [sample CSV file](sample-indicators.csv) for bulk import templates

## Troubleshooting

### "Not connected to Defender XDR"
Make sure you've run `Connect-DefenderXDR` successfully before running other commands.

### Authentication Failures
- Verify your Tenant ID, App ID, and App Secret are correct
- Ensure admin consent has been granted for the API permissions
- Check that the app registration has the `Ti.ReadWrite` permission

### API Errors
Use the `-Verbose` parameter to see detailed API request information:
```powershell
New-DefenderXDRTIIndicator -IndicatorValue "test.com" -IndicatorType DomainName -Action Block -Title "Test" -Verbose
```

## Security Best Practices

1. **Never store secrets in plain text**
   ```powershell
   # Store secrets securely
   $appSecret = Read-Host "Enter App Secret" -AsSecureString
   ```

2. **Use least privilege**
   - Only grant `Ti.ReadWrite` permission, nothing more
   - Use RBAC groups to limit indicator visibility

3. **Set expiration times**
   ```powershell
   New-DefenderXDRTIIndicator -IndicatorValue "temp.com" `
       -IndicatorType DomainName `
       -Action Block `
       -Title "Temporary Block" `
       -ExpirationTime (Get-Date).AddDays(30)
   ```

4. **Audit regularly**
   ```powershell
   # Export for compliance review
   Export-DefenderXDRTIIndicator -Path "audit-$(Get-Date -Format 'yyyyMMdd').csv"
   ```
