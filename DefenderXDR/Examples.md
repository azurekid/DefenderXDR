# DefenderXDR Module Examples

## Example 1: Basic Connection and List Indicators

```powershell
# Import the module
Import-Module DefenderXDR

# Connect to Defender XDR
$appSecret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
Connect-DefenderXDR -TenantId "your-tenant-id.onmicrosoft.com" `
    -AppId "12345678-1234-1234-1234-123456789012" `
    -AppSecret $appSecret

# List all indicators
Get-DefenderXDRTIIndicator

# Disconnect when done
Disconnect-DefenderXDR
```

## Example 2: Create Multiple Indicators

```powershell
# Connect to the API
Connect-DefenderXDR -AccessToken $token

# Create a malicious domain indicator
New-DefenderXDRTIIndicator -IndicatorValue "phishing-site.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Phishing Domain" `
    -Description "Active phishing campaign targeting finance sector" `
    -Severity High `
    -RecommendedActions "Block at perimeter, investigate affected users"

# Create a suspicious IP indicator
New-DefenderXDRTIIndicator -IndicatorValue "203.0.113.42" `
    -IndicatorType IpAddress `
    -Action Alert `
    -Title "Suspicious IP Address" `
    -Description "Observed C2 communication" `
    -Severity Medium `
    -ExpirationTime (Get-Date).AddDays(90)

# Create a malware hash indicator
$hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
New-DefenderXDRTIIndicator -IndicatorValue $hash `
    -IndicatorType FileSha256 `
    -Action AlertAndBlock `
    -Title "Ransomware Hash" `
    -Description "Known ransomware variant" `
    -Severity High
```

## Example 3: Search and Filter Indicators

```powershell
# Find all indicators for a specific domain
$domain = "malicious.com"
$indicators = Get-DefenderXDRTIIndicator -IndicatorValue $domain

# Get all IP address indicators
$ipIndicators = Get-DefenderXDRTIIndicator -IndicatorType IpAddress

# Get a specific indicator by ID
$indicator = Get-DefenderXDRTIIndicator -Id "5678"
```

## Example 4: Update Indicators

```powershell
# Update the severity of an indicator
Set-DefenderXDRTIIndicator -Id "12345" -Severity Critical

# Change action from Alert to Block
Set-DefenderXDRTIIndicator -Id "12345" -Action Block

# Update multiple properties
Set-DefenderXDRTIIndicator -Id "12345" `
    -Action AlertAndBlock `
    -Severity High `
    -Description "Updated: Active threat - immediate action required" `
    -ExpirationTime (Get-Date).AddDays(365)

# Update indicators via pipeline
Get-DefenderXDRTIIndicator -IndicatorType DomainName | 
    Where-Object { $_.severity -eq 'Medium' } |
    Set-DefenderXDRTIIndicator -Severity High
```

## Example 5: Delete Indicators

```powershell
# Delete a specific indicator
Remove-DefenderXDRTIIndicator -Id "12345"

# Delete with confirmation
Remove-DefenderXDRTIIndicator -Id "12345" -Confirm

# Delete via pipeline
Get-DefenderXDRTIIndicator -IndicatorValue "old-threat.com" |
    Remove-DefenderXDRTIIndicator

# Bulk delete indicators older than 90 days
Get-DefenderXDRTIIndicator |
    Where-Object { $_.createdDateTime -lt (Get-Date).AddDays(-90) } |
    Remove-DefenderXDRTIIndicator -Confirm:$false
```

## Example 6: Bulk Import from CSV

```powershell
# Create a CSV file with indicators
$csvContent = @"
IndicatorValue,IndicatorType,Action,Title,Description,Severity
bad-domain1.com,DomainName,Block,Malicious Domain 1,Phishing,High
bad-domain2.com,DomainName,Block,Malicious Domain 2,Malware distribution,High
198.51.100.1,IpAddress,Alert,Suspicious IP 1,Scanning activity,Medium
198.51.100.2,IpAddress,Alert,Suspicious IP 2,Brute force attempts,Medium
"@

# Save to file
$csvContent | Out-File -FilePath "C:\temp\indicators.csv" -Encoding UTF8

# Import the indicators
Import-DefenderXDRTIIndicator -Path "C:\temp\indicators.csv" -Verbose
```

## Example 7: Export Indicators

```powershell
# Export all indicators to CSV
Export-DefenderXDRTIIndicator -Path "C:\temp\all-indicators.csv"

# Export filtered indicators
Get-DefenderXDRTIIndicator -IndicatorType DomainName |
    Export-Csv -Path "C:\temp\domain-indicators.csv" -NoTypeInformation

# Export high severity indicators
Get-DefenderXDRTIIndicator |
    Where-Object { $_.severity -eq 'High' } |
    Export-Csv -Path "C:\temp\high-severity-indicators.csv" -NoTypeInformation
```

## Example 8: Pipeline Operations

```powershell
# Create multiple indicators from an array
$threats = @(
    @{ Value = "threat1.com"; Type = "DomainName" }
    @{ Value = "threat2.com"; Type = "DomainName" }
    @{ Value = "192.0.2.1"; Type = "IpAddress" }
)

foreach ($threat in $threats) {
    New-DefenderXDRTIIndicator -IndicatorValue $threat.Value `
        -IndicatorType $threat.Type `
        -Action Block `
        -Title "Automated Threat Block" `
        -Severity High
}

# Update all indicators with a specific pattern
Get-DefenderXDRTIIndicator |
    Where-Object { $_.title -like "*Phishing*" } |
    Set-DefenderXDRTIIndicator -RecommendedActions "Immediate user awareness training required"
```

## Example 9: Error Handling

```powershell
# Wrap API calls in try-catch
try {
    Connect-DefenderXDR -TenantId $tenantId -AppId $appId -AppSecret $appSecret
    
    $result = New-DefenderXDRTIIndicator -IndicatorValue "test.com" `
        -IndicatorType DomainName `
        -Action Block `
        -Title "Test Indicator" `
        -Severity Medium
    
    Write-Host "Indicator created successfully: $($result.id)"
}
catch {
    Write-Error "Operation failed: $($_.Exception.Message)"
}
finally {
    Disconnect-DefenderXDR
}
```

## Example 10: Using WhatIf for Testing

```powershell
# Test what would happen without making changes
New-DefenderXDRTIIndicator -IndicatorValue "test.com" `
    -IndicatorType DomainName `
    -Action Block `
    -Title "Test" `
    -Severity High `
    -WhatIf

# Preview bulk operations
Import-DefenderXDRTIIndicator -Path "C:\indicators.csv" -WhatIf

# Preview deletions
Get-DefenderXDRTIIndicator |
    Where-Object { $_.severity -eq 'Low' } |
    Remove-DefenderXDRTIIndicator -WhatIf
```

## Example 11: Working with Expiration Times

```powershell
# Create indicator that expires in 30 days
New-DefenderXDRTIIndicator -IndicatorValue "temporary-threat.com" `
    -IndicatorType DomainName `
    -Action Alert `
    -Title "Temporary Threat" `
    -Severity Medium `
    -ExpirationTime (Get-Date).AddDays(30)

# Extend expiration for existing indicators
$indicator = Get-DefenderXDRTIIndicator -Id "12345"
Set-DefenderXDRTIIndicator -Id $indicator.id `
    -ExpirationTime (Get-Date).AddDays(180)

# Find indicators expiring soon
$expiringIndicators = Get-DefenderXDRTIIndicator |
    Where-Object { 
        $_.expirationTime -and 
        ([datetime]$_.expirationTime -lt (Get-Date).AddDays(7))
    }
```

## Example 12: Advanced Filtering and Reporting

```powershell
# Generate a report of indicators by type
$report = Get-DefenderXDRTIIndicator | 
    Group-Object -Property indicatorType | 
    Select-Object Name, Count

$report | Format-Table -AutoSize

# Generate severity distribution report
Get-DefenderXDRTIIndicator |
    Group-Object -Property severity |
    Select-Object @{N='Severity';E={$_.Name}}, 
                  @{N='Count';E={$_.Count}}, 
                  @{N='Percentage';E={($_.Count / $totalIndicators * 100).ToString("0.00") + "%"}}

# Find indicators with no expiration
$noExpiration = Get-DefenderXDRTIIndicator |
    Where-Object { -not $_.expirationTime }
```

## Example 13: Integration with Other Security Tools

```powershell
# Import IOCs from threat intelligence feed
$threatFeed = Invoke-RestMethod -Uri "https://your-threat-feed.com/iocs.json"

foreach ($ioc in $threatFeed) {
    try {
        New-DefenderXDRTIIndicator -IndicatorValue $ioc.value `
            -IndicatorType $ioc.type `
            -Action Block `
            -Title "Threat Feed: $($ioc.source)" `
            -Description $ioc.description `
            -Severity High
        
        Write-Host "Added IOC: $($ioc.value)"
    }
    catch {
        Write-Warning "Failed to add IOC $($ioc.value): $_"
    }
}
```

## Example 14: Scheduled Maintenance Tasks

```powershell
# Script to clean up expired indicators (run as scheduled task)
Connect-DefenderXDR -AccessToken $token

# Get and remove expired indicators
$expired = Get-DefenderXDRTIIndicator |
    Where-Object { 
        $_.expirationTime -and 
        ([datetime]$_.expirationTime -lt (Get-Date))
    }

Write-Host "Found $($expired.Count) expired indicators"

$expired | Remove-DefenderXDRTIIndicator -Confirm:$false

Disconnect-DefenderXDR
```

## Example 15: Audit and Compliance

```powershell
# Generate audit report
$auditReport = Get-DefenderXDRTIIndicator | 
    Select-Object id, 
                  indicatorValue, 
                  indicatorType, 
                  action, 
                  severity, 
                  createdDateTime, 
                  createdBy, 
                  expirationTime

# Export for compliance
$auditReport | Export-Csv -Path "C:\compliance\indicator-audit-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Summary statistics
$stats = @{
    TotalIndicators = ($auditReport).Count
    BlockActions = ($auditReport | Where-Object { $_.action -eq 'Block' }).Count
    HighSeverity = ($auditReport | Where-Object { $_.severity -eq 'High' }).Count
    GeneratedDate = Get-Date
}

$stats | ConvertTo-Json | Out-File "C:\compliance\indicator-stats-$(Get-Date -Format 'yyyyMMdd').json"
```
