# Example Usage of Get-DefenderXDRIndicators Function

# This file demonstrates how to use the Get-DefenderXDRIndicators function
# DO NOT commit real credentials to source control!

# Step 1: Import the function
. ./Get-DefenderXDRIndicators.ps1

# Step 2: Set your Azure AD application credentials
# Replace these with your actual values
$tenantId = "your-tenant.onmicrosoft.com"  # Or tenant GUID
$appId = "12345678-1234-1234-1234-123456789012"  # Your app registration client ID
$appSecretValue = "your-app-secret-here"  # Your app secret value

# Step 3: Convert the app secret to a SecureString
$appSecret = ConvertTo-SecureString $appSecretValue -AsPlainText -Force

# Example 1: Get all indicators
Write-Host "Example 1: Retrieving all indicators..." -ForegroundColor Cyan
try {
    $allIndicators = Get-DefenderXDRIndicators -TenantId $tenantId -AppId $appId -AppSecret $appSecret -Verbose
    Write-Host "Retrieved $($allIndicators.Count) indicators" -ForegroundColor Green
    $allIndicators | Select-Object -First 5 | Format-Table id, indicatorValue, indicatorType, action, severity
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 2: Get a specific indicator by ID
Write-Host "`nExample 2: Retrieving a specific indicator..." -ForegroundColor Cyan
$indicatorId = "12345"  # Replace with an actual indicator ID from your tenant
try {
    $indicator = Get-DefenderXDRIndicators -TenantId $tenantId -AppId $appId -AppSecret $appSecret -IndicatorId $indicatorId -Verbose
    Write-Host "Retrieved indicator:" -ForegroundColor Green
    $indicator | Format-List
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 3: Filter and process indicators
Write-Host "`nExample 3: Filter high severity indicators..." -ForegroundColor Cyan
try {
    $indicators = Get-DefenderXDRIndicators -TenantId $tenantId -AppId $appId -AppSecret $appSecret
    $highSeverity = $indicators | Where-Object { $_.severity -eq 'High' }
    Write-Host "Found $($highSeverity.Count) high severity indicators" -ForegroundColor Green
    $highSeverity | Select-Object -First 5 | Format-Table indicatorValue, indicatorType, action, title
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 4: Group indicators by type
Write-Host "`nExample 4: Group indicators by type..." -ForegroundColor Cyan
try {
    $indicators = Get-DefenderXDRIndicators -TenantId $tenantId -AppId $appId -AppSecret $appSecret
    $grouped = $indicators | Group-Object -Property indicatorType
    Write-Host "Indicators by type:" -ForegroundColor Green
    $grouped | Format-Table Name, Count
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Best Practices:
# 1. Store credentials in Azure Key Vault or a secure credential store
# 2. Use managed identities when possible
# 3. Never commit real credentials to source control
# 4. Rotate app secrets regularly
# 5. Use the principle of least privilege for API permissions
