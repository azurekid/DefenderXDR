# Example: Defender Endpoint Threat Indicator Management
# This example demonstrates the new Defender Endpoint API functions for threat indicators

# Import the module
Import-Module ../DefenderXDR/DefenderXDR.psd1 -Force

# Connect (replace with your credentials)
$accessToken = "YOUR_ACCESS_TOKEN_HERE"
Connect-DefenderXDR -AccessToken $accessToken

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Defender Endpoint API - Threat Indicator Management Examples" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Example 1: Get all threat indicators
Write-Host "`nExample 1: Retrieving all threat indicators..." -ForegroundColor Yellow
$allIndicators = Get-DefenderXDRIndicator -Top 10
Write-Host "Retrieved $($allIndicators.Count) indicators (showing first 10)"
$allIndicators | Select-Object id, indicatorValue, indicatorType, action | Format-Table

# Example 2: Get a specific indicator by ID
Write-Host "`nExample 2: Getting a specific indicator by ID..." -ForegroundColor Yellow
if ($allIndicators.Count -gt 0) {
    $firstIndicator = Get-DefenderXDRIndicator -IndicatorId $allIndicators[0].id
    Write-Host "Retrieved indicator: $($firstIndicator.indicatorValue)"
    $firstIndicator | Format-List
}

# Example 3: Import multiple indicators in bulk
Write-Host "`nExample 3: Bulk importing threat indicators..." -ForegroundColor Yellow

$indicatorsToImport = @(
    @{
        indicatorValue = "example-malicious.com"
        indicatorType = "DomainName"
        action = "Block"
        severity = "High"
        title = "Example Malicious Domain"
        description = "This is an example domain for demonstration purposes"
        expirationTime = (Get-Date).AddDays(30).ToString('o')
        recommendedActions = "Block and alert on this domain"
    },
    @{
        indicatorValue = "192.0.2.100"
        indicatorType = "IpAddress"
        action = "Alert"
        severity = "Medium"
        title = "Example Suspicious IP"
        description = "This is an example IP for demonstration purposes"
        expirationTime = (Get-Date).AddDays(30).ToString('o')
    },
    @{
        indicatorValue = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        indicatorType = "FileSha256"
        action = "Block"
        severity = "High"
        title = "Example Malware Hash"
        description = "This is an example file hash for demonstration purposes"
        expirationTime = (Get-Date).AddDays(90).ToString('o')
    }
)

Write-Host "Importing $($indicatorsToImport.Count) indicators..."
# Uncomment to actually import:
# $importResult = Import-DefenderXDRIndicators -Indicators $indicatorsToImport
# Write-Host "Import completed: $($importResult.status)"

# Example 4: Filter indicators
Write-Host "`nExample 4: Filtering indicators..." -ForegroundColor Yellow

# Get high severity indicators
$highSeverityFilter = "severity eq 'High'"
$highSeverityIndicators = Get-DefenderXDRIndicator -Filter $highSeverityFilter -Top 50
Write-Host "Found $($highSeverityIndicators.Count) high severity indicators"

# Get indicators by type
$domainIndicators = Get-DefenderXDRIndicator -Filter "indicatorType eq 'DomainName'" -Top 20
Write-Host "Found $($domainIndicators.Count) domain indicators"

# Example 5: Order and pagination
Write-Host "`nExample 5: Ordering and pagination..." -ForegroundColor Yellow

# Get most recently created indicators
$recentIndicators = Get-DefenderXDRIndicator -OrderBy "creationTime desc" -Top 10
Write-Host "Retrieved $($recentIndicators.Count) most recently created indicators"
$recentIndicators | Select-Object indicatorValue, creationTime, action | Format-Table

# Get next page
if ($recentIndicators.Count -eq 10) {
    $nextPage = Get-DefenderXDRIndicator -OrderBy "creationTime desc" -Top 10 -Skip 10
    Write-Host "Retrieved $($nextPage.Count) indicators from next page"
}

# Example 6: Remove a single indicator
Write-Host "`nExample 6: Removing a single indicator..." -ForegroundColor Yellow
# Uncomment to actually remove:
# if ($allIndicators.Count -gt 0) {
#     $indicatorToRemove = $allIndicators[-1].id
#     Remove-DefenderXDRIndicator -IndicatorId $indicatorToRemove -Confirm:$false
#     Write-Host "Removed indicator: $indicatorToRemove"
# }

# Example 7: Batch remove indicators
Write-Host "`nExample 7: Batch removing expired indicators..." -ForegroundColor Yellow

# Get expired indicators
$expiredIndicators = Get-DefenderXDRIndicator -Filter "expirationTime lt $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')" -Top 100

if ($expiredIndicators.Count -gt 0) {
    Write-Host "Found $($expiredIndicators.Count) expired indicators"
    
    # Uncomment to actually remove:
    # $expiredIds = $expiredIndicators | Select-Object -ExpandProperty id
    # Remove-DefenderXDRIndicatorBatch -IndicatorIds $expiredIds -Confirm:$false
    # Write-Host "Batch removed $($expiredIds.Count) expired indicators"
}
else {
    Write-Host "No expired indicators found"
}

# Example 8: Pipeline usage
Write-Host "`nExample 8: Using pipeline for removal..." -ForegroundColor Yellow
# Uncomment to actually remove:
# Get-DefenderXDRIndicator -Filter "severity eq 'Informational'" | 
#     Where-Object { $_.expirationTime -lt (Get-Date) } |
#     Remove-DefenderXDRIndicator -Confirm:$false

Write-Host "`nNote: Most removal operations are commented out to prevent accidental deletions"

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Examples completed!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Disconnect
Disconnect-DefenderXDR
