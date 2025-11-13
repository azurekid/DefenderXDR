# Example: Threat Intelligence Management
# This example demonstrates how to manage threat indicators

# Import the module
Import-Module ../DefenderXDR/DefenderXDR.psd1 -Force

# Connect (replace with your credentials)
$accessToken = "YOUR_ACCESS_TOKEN_HERE"
Connect-DefenderXDR -AccessToken $accessToken

# Example 1: Submit a malicious domain indicator
Write-Host "Example 1: Submitting malicious domain indicator..."
$domain = Set-DefenderXDRThreatIndicator `
    -IndicatorValue "malicious-domain.com" `
    -IndicatorType "domainName" `
    -Action "block" `
    -ThreatType "Malware" `
    -Severity 5 `
    -Title "Known C2 Server" `
    -Description "Domain associated with APT group XYZ" `
    -ExpirationDateTime (Get-Date).AddDays(90)

Write-Host "Domain indicator submitted: $($domain.id)"

# Example 2: Submit a file hash indicator
Write-Host "`nExample 2: Submitting file hash indicator..."
$fileHash = Set-DefenderXDRThreatIndicator `
    -IndicatorValue "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" `
    -IndicatorType "fileSha256" `
    -Action "alert" `
    -ThreatType "Malware" `
    -Severity 4 `
    -Title "Ransomware Sample" `
    -Description "SHA256 hash of known ransomware variant"

Write-Host "File hash indicator submitted: $($fileHash.id)"

# Example 3: Submit an IP address indicator
Write-Host "`nExample 3: Submitting IP address indicator..."
$ip = Set-DefenderXDRThreatIndicator `
    -IndicatorValue "192.0.2.100" `
    -IndicatorType "ipAddress" `
    -Action "block" `
    -ThreatType "C2" `
    -Severity 5 `
    -Title "Malicious IP Address" `
    -Description "IP address used for command and control"

Write-Host "IP address indicator submitted: $($ip.id)"

# Example 4: Bulk import from CSV
Write-Host "`nExample 4: Bulk importing indicators from CSV..."

# Sample CSV content (create a file with this structure):
# IndicatorValue,IndicatorType,Action,ThreatType,Severity,Description
# evil1.com,domainName,block,Malware,5,Phishing domain
# evil2.com,domainName,block,Phishing,4,Known phishing site
# abc123...,fileSha256,alert,Malware,5,Trojan hash

# For this example, we'll create the data inline
$iocs = @(
    [PSCustomObject]@{
        IndicatorValue = "phishing-site.com"
        IndicatorType = "domainName"
        Action = "block"
        ThreatType = "Phishing"
        Severity = 4
        Description = "Known phishing domain targeting financial sector"
    },
    [PSCustomObject]@{
        IndicatorValue = "192.0.2.200"
        IndicatorType = "ipAddress"
        Action = "block"
        ThreatType = "Botnet"
        Severity = 3
        Description = "Botnet controller IP"
    }
)

foreach ($ioc in $iocs) {
    Write-Host "  Submitting: $($ioc.IndicatorValue)..."
    
    Set-DefenderXDRThreatIndicator `
        -IndicatorValue $ioc.IndicatorValue `
        -IndicatorType $ioc.IndicatorType `
        -Action $ioc.Action `
        -ThreatType $ioc.ThreatType `
        -Severity $ioc.Severity `
        -Description $ioc.Description
}

Write-Host "Bulk import complete!"

# Example 5: Update an existing indicator
Write-Host "`nExample 5: Updating an existing threat indicator..."
# Note: You would get the indicator ID from a previous operation or query
# $existingIndicatorId = $domain.id
# Set-DefenderXDRThreatIndicator `
#     -IndicatorId $existingIndicatorId `
#     -Action "allowed" `
#     -Description "Updated to allowed after investigation - false positive" `
#     -Severity 1

# Example 6: List current threat indicators
Write-Host "`nExample 6: Listing current threat indicators..."
$indicators = Get-DefenderXDRThreatIntelligence -Top 10
Write-Host "Current indicators: $($indicators.Count)"

foreach ($indicator in $indicators) {
    Write-Host "`nIndicator ID: $($indicator.id)"
    Write-Host "  Type: $($indicator.threatType)"
    Write-Host "  Action: $($indicator.action)"
    Write-Host "  Value: $($indicator.domainName)$($indicator.url)$($indicator.networkIPv4)$($indicator.fileHashValue)"
}

# Example 7: Remove an indicator (uncomment to use)
<#
Write-Host "`nExample 6: Removing an indicator..."
$indicatorToRemove = "indicator-id-here"
Remove-DefenderXDRThreatIndicator -IndicatorId $indicatorToRemove -Confirm:$false
Write-Host "Indicator removed successfully"
#>

# Disconnect
Disconnect-DefenderXDR
