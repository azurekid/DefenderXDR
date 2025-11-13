# Example: Alert Triage Workflow
# This example demonstrates automated alert triage

# Import the module
Import-Module ../DefenderXDR/DefenderXDR.psd1 -Force

# Connect (replace with your credentials)
$accessToken = "YOUR_ACCESS_TOKEN_HERE"
Connect-DefenderXDR -AccessToken $accessToken

# Configuration
$assignTo = "security-analyst@contoso.com"

# Get new alerts that need triage
Write-Host "Getting new alerts for triage..."
$newAlerts = Get-DefenderXDRAlert -Filter "status eq 'new'" -Top 50

Write-Host "Found $($newAlerts.Count) new alerts to triage"

# Process each alert
foreach ($alert in $newAlerts) {
    Write-Host "`n----------------------------------------"
    Write-Host "Processing Alert: $($alert.title)"
    Write-Host "  Severity: $($alert.severity)"
    Write-Host "  Category: $($alert.category)"
    
    # Determine action based on severity
    switch ($alert.severity) {
        'high' {
            Write-Host "  Action: High priority - assigning and marking in progress"
            
            # Update alert to in progress
            Update-DefenderXDRAlert -AlertId $alert.id `
                                     -Status "inProgress" `
                                     -AssignedTo $assignTo
            
            # Add comment
            New-DefenderXDRAlertComment -AlertId $alert.id `
                                         -Comment "High severity alert - prioritized for investigation"
        }
        'medium' {
            Write-Host "  Action: Medium priority - assigning"
            
            Update-DefenderXDRAlert -AlertId $alert.id `
                                     -Status "inProgress" `
                                     -AssignedTo $assignTo
            
            New-DefenderXDRAlertComment -AlertId $alert.id `
                                         -Comment "Medium severity alert - queued for investigation"
        }
        'low' {
            Write-Host "  Action: Low priority - logging"
            
            New-DefenderXDRAlertComment -AlertId $alert.id `
                                         -Comment "Low severity alert - will review when time permits"
        }
        'informational' {
            Write-Host "  Action: Informational - auto-resolving"
            
            Update-DefenderXDRAlert -AlertId $alert.id `
                                     -Status "resolved" `
                                     -Classification "informationalExpectedActivity"
            
            New-DefenderXDRAlertComment -AlertId $alert.id `
                                         -Comment "Informational alert - auto-resolved"
        }
    }
}

Write-Host "`n----------------------------------------"
Write-Host "Alert triage complete!"

# Disconnect
Disconnect-DefenderXDR
