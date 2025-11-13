# Installation Guide

This guide will help you install and configure the DefenderXDR PowerShell module.

## Prerequisites

### PowerShell Version
- PowerShell 5.1 or later
- PowerShell 7.x (recommended)

To check your PowerShell version:
```powershell
$PSVersionTable.PSVersion
```

### Azure AD App Registration

Before using this module, you need to create an Azure AD application with the appropriate permissions.

#### Step 1: Register an Azure AD Application

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Provide a name (e.g., "DefenderXDR PowerShell Module")
5. Select **Accounts in this organizational directory only**
6. Click **Register**

#### Step 2: Configure API Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Application permissions** (for unattended scripts) or **Delegated permissions** (for interactive use)
5. Add the following permissions:
   - `SecurityEvents.Read.All`
   - `SecurityEvents.ReadWrite.All`
   - `SecurityActions.Read.All`
   - `SecurityActions.ReadWrite.All`
   - `ThreatIndicators.ReadWrite.OwnedBy`
6. Click **Add permissions**
7. Click **Grant admin consent** (requires Global Admin or Privileged Role Admin)

#### Step 3: Create a Client Secret (for service principal authentication)

1. In your app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Add a description and select an expiration period
4. Click **Add**
5. **Important**: Copy the secret value immediately - you won't be able to see it again!

#### Step 4: Note Important Values

Copy the following values from your app registration:
- **Application (client) ID**: Found on the Overview page
- **Directory (tenant) ID**: Found on the Overview page
- **Client secret value**: Copied in Step 3

## Installation Methods

### Method 1: Clone from GitHub

```powershell
# Clone the repository
git clone https://github.com/azurekid/DefenderXDR.git

# Navigate to the directory
cd DefenderXDR

# Import the module
Import-Module ./DefenderXDR/DefenderXDR.psd1
```

### Method 2: Manual Installation to PowerShell Modules Path

```powershell
# Find your PowerShell modules path
$modulePath = ($env:PSModulePath -split ';')[0]
Write-Host "Modules path: $modulePath"

# Clone the repository
git clone https://github.com/azurekid/DefenderXDR.git

# Copy the module to the modules path
Copy-Item -Path "./DefenderXDR/DefenderXDR" -Destination "$modulePath/DefenderXDR" -Recurse

# Import the module
Import-Module DefenderXDR
```

### Method 3: Download ZIP and Extract

1. Download the repository as a ZIP file from GitHub
2. Extract the ZIP file
3. Copy the `DefenderXDR` folder to your PowerShell modules directory
4. Import the module: `Import-Module DefenderXDR`

## Verify Installation

After installation, verify the module is loaded correctly:

```powershell
# Check if module is imported
Get-Module DefenderXDR

# List available commands
Get-Command -Module DefenderXDR

# Check module version
(Get-Module DefenderXDR).Version
```

## Configuration

### Store Credentials Securely

**Never store credentials in plain text!** Use PowerShell's secure credential storage:

#### Option 1: Use Secure Strings (Windows only)

```powershell
# Store client secret securely
$clientSecret = Read-Host "Enter Client Secret" -AsSecureString
$encryptedSecret = $clientSecret | ConvertFrom-SecureString
$encryptedSecret | Out-File "$env:USERPROFILE\.defenderxdr_secret.txt"

# Later, retrieve the secret
$encryptedSecret = Get-Content "$env:USERPROFILE\.defenderxdr_secret.txt"
$clientSecret = $encryptedSecret | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret)
$plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
```

#### Option 2: Use Azure Key Vault

```powershell
# Store secret in Key Vault
Set-AzKeyVaultSecret -VaultName "mykeyvault" -Name "DefenderXDRSecret" -SecretValue $clientSecret

# Retrieve secret
$secret = Get-AzKeyVaultSecret -VaultName "mykeyvault" -Name "DefenderXDRSecret"
$plainSecret = $secret.SecretValue | ConvertFrom-SecureString -AsPlainText
```

#### Option 3: Environment Variables (for CI/CD)

```powershell
# Set environment variables
$env:DEFENDERXDR_TENANT_ID = "your-tenant-id"
$env:DEFENDERXDR_CLIENT_ID = "your-client-id"
$env:DEFENDERXDR_CLIENT_SECRET = "your-client-secret"

# Use in your scripts
Connect-DefenderXDR -TenantId $env:DEFENDERXDR_TENANT_ID `
                     -ClientId $env:DEFENDERXDR_CLIENT_ID `
                     -ClientSecret $env:DEFENDERXDR_CLIENT_SECRET
```

## First Connection

### Using Access Token

```powershell
# Get an access token (example using Azure CLI)
$token = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv

# Connect
Connect-DefenderXDR -AccessToken $token
```

### Using Client Credentials

```powershell
# Connect using service principal
Connect-DefenderXDR -TenantId "your-tenant-id" `
                     -ClientId "your-client-id" `
                     -ClientSecret "your-client-secret"

# Verify connection
Get-DefenderXDRAccessToken
```

## Testing the Installation

Run a simple test to ensure everything works:

```powershell
# Import module
Import-Module DefenderXDR

# Connect
Connect-DefenderXDR -TenantId "your-tenant-id" `
                     -ClientId "your-client-id" `
                     -ClientSecret "your-client-secret"

# Get alerts
$alerts = Get-DefenderXDRAlert -Top 5

# Display results
$alerts | Select-Object id, title, severity, status

# Disconnect
Disconnect-DefenderXDR
```

## Troubleshooting

### Issue: Module Not Found

**Solution**: Ensure the module is in a directory listed in `$env:PSModulePath`

```powershell
# Check module paths
$env:PSModulePath -split ';'

# Add a custom path temporarily
$env:PSModulePath += ";C:\Path\To\Modules"
```

### Issue: Insufficient Permissions

**Error**: `Insufficient privileges to complete the operation`

**Solution**: 
1. Verify API permissions are granted and admin consent is provided
2. Ensure the account/service principal has the necessary roles in Defender XDR
3. Wait a few minutes after granting permissions for changes to propagate

### Issue: Authentication Failed

**Error**: `Failed to connect to Defender XDR`

**Solution**:
1. Verify your client ID, tenant ID, and client secret are correct
2. Check that the client secret hasn't expired
3. Ensure the token has the correct scopes for Microsoft Graph

### Issue: Token Expired

**Error**: `Access token has expired`

**Solution**: Reconnect to get a new token

```powershell
Disconnect-DefenderXDR
Connect-DefenderXDR -TenantId "..." -ClientId "..." -ClientSecret "..."
```

## Uninstallation

To remove the module:

```powershell
# Remove from current session
Remove-Module DefenderXDR

# Delete from modules directory
$modulePath = ($env:PSModulePath -split ';')[0]
Remove-Item "$modulePath/DefenderXDR" -Recurse -Force
```

## Next Steps

- Review the [README.md](README.md) for usage examples
- Explore the [Examples](Examples/) folder for sample scripts
- Check the [CHANGELOG.md](CHANGELOG.md) for version history

## Support

For issues or questions:
- GitHub Issues: https://github.com/azurekid/DefenderXDR/issues
- Documentation: https://github.com/azurekid/DefenderXDR

## Security Notice

- Never commit credentials to source control
- Use secure storage mechanisms for secrets
- Regularly rotate client secrets
- Follow the principle of least privilege when assigning permissions
- Monitor your Azure AD application sign-in logs
