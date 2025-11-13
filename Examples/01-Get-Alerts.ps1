# Example: Connect to Defender XDR and Get Alerts
# This example demonstrates how to connect to Defender XDR and retrieve security alerts

# Import the module
Import-Module ../DefenderXDR/DefenderXDR.psd1 -Force

# Option 1: Connect with access token
# You can get an access token from Azure Portal, Azure CLI, or other authentication methods
$accessToken = "YOUR_ACCESS_TOKEN_HERE"
Connect-DefenderXDR -AccessToken $accessToken

# Option 2: Connect with Client Credentials (Service Principal)
# Uncomment and use this if you have a service principal configured
<#
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = "your-client-secret"

Connect-DefenderXDR -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
#>

# Check connection status
$tokenInfo = Get-DefenderXDRAccessToken
Write-Host "Connected: $($tokenInfo.HasToken)"
Write-Host "Token expires in: $($tokenInfo.MinutesRemaining) minutes"

# Get all alerts (top 10)
Write-Host "`nRetrieving top 10 alerts..."
$alerts = Get-DefenderXDRAlert -Top 10
Write-Host "Retrieved $($alerts.Count) alerts"

# Display alert summary
foreach ($alert in $alerts) {
    Write-Host "`nAlert ID: $($alert.id)"
    Write-Host "  Title: $($alert.title)"
    Write-Host "  Severity: $($alert.severity)"
    Write-Host "  Status: $($alert.status)"
    Write-Host "  Created: $($alert.createdDateTime)"
}

# Get high severity alerts
Write-Host "`n`nRetrieving high severity alerts..."
$highSeverityAlerts = Get-DefenderXDRAlert -Filter "severity eq 'high'" -Top 20
Write-Host "Found $($highSeverityAlerts.Count) high severity alerts"

# Get alerts from the last 24 hours
$yesterday = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Host "`nRetrieving alerts from the last 24 hours..."
$recentAlerts = Get-DefenderXDRAlert -Filter "createdDateTime ge $yesterday" -Top 50
Write-Host "Found $($recentAlerts.Count) alerts in the last 24 hours"

# Disconnect
Disconnect-DefenderXDR
