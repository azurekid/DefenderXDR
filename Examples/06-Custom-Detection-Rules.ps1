<#
.SYNOPSIS
    Example script demonstrating custom detection rules management in Microsoft Defender XDR

.DESCRIPTION
    This script shows how to use the DefenderXDR module to manage custom detection rules.
    Detection rules allow you to create custom alerts based on KQL queries that monitor
    your environment for specific patterns and behaviors.

.NOTES
    Requires SecurityEvents.ReadWrite.All permission
#>

# Import the DefenderXDR module
Import-Module DefenderXDR

# Connect to Defender XDR (use your preferred authentication method)
# Option 1: Using an access token
# Connect-DefenderXDR -AccessToken "your-access-token"

# Option 2: Using client credentials
# Connect-DefenderXDR -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"

Write-Host "=== Custom Detection Rules Management Examples ===" -ForegroundColor Cyan

# Example 1: Get all detection rules
Write-Host "`n1. Getting all custom detection rules..." -ForegroundColor Yellow
try {
    $allRules = Get-DefenderXDRDetectionRule
    Write-Host "Found $($allRules.Count) detection rules" -ForegroundColor Green
    $allRules | Select-Object displayName, isEnabled, @{Name='Severity';Expression={$_.detectionAction.alertTemplate.severity}} | Format-Table
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 2: Get only enabled rules
Write-Host "`n2. Getting only enabled detection rules..." -ForegroundColor Yellow
try {
    $enabledRules = Get-DefenderXDRDetectionRule -Filter "isEnabled eq true"
    Write-Host "Found $($enabledRules.Count) enabled rules" -ForegroundColor Green
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 3: Create a new detection rule for suspicious PowerShell activity
Write-Host "`n3. Creating a new detection rule for suspicious PowerShell execution..." -ForegroundColor Yellow
try {
    $newRule = New-DefenderXDRDetectionRule `
        -DisplayName "Suspicious PowerShell Execution Pattern" `
        -QueryCondition "DeviceProcessEvents | where FileName =~ 'powershell.exe' and ProcessCommandLine has_any ('Invoke-Expression', 'IEX', 'Invoke-WebRequest', 'downloadstring') | where InitiatingProcessFileName !in ('explorer.exe', 'wmiprvse.exe')" `
        -Severity "high" `
        -Description "Detects suspicious PowerShell execution patterns that may indicate malicious activity such as fileless malware or living-off-the-land attacks" `
        -RecommendedActions "1. Review the PowerShell command line arguments. 2. Check the parent process. 3. Investigate the user account. 4. Review recent file modifications." `
        -Category "Execution" `
        -MitreTechniques @("T1059.001", "T1086") `
        -IsEnabled $true
    
    Write-Host "✓ Detection rule created successfully!" -ForegroundColor Green
    Write-Host "  Rule ID: $($newRule.id)" -ForegroundColor Gray
    Write-Host "  Display Name: $($newRule.displayName)" -ForegroundColor Gray
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 4: Create a detection rule with a schedule
Write-Host "`n4. Creating a detection rule with custom schedule..." -ForegroundColor Yellow
try {
    $schedule = @{
        period = 'PT1H'  # Run every hour (ISO 8601 duration format)
    }
    
    $scheduledRule = New-DefenderXDRDetectionRule `
        -DisplayName "Multiple Failed Sign-ins" `
        -QueryCondition "SigninLogs | where ResultType != 0 | summarize FailedAttempts=count() by UserPrincipalName, IPAddress | where FailedAttempts > 5" `
        -Severity "medium" `
        -Description "Detects multiple failed sign-in attempts which may indicate credential stuffing or brute force attacks" `
        -Category "CredentialAccess" `
        -MitreTechniques @("T1110") `
        -Schedule $schedule `
        -IsEnabled $true
    
    Write-Host "✓ Scheduled detection rule created successfully!" -ForegroundColor Green
    Write-Host "  Rule ID: $($scheduledRule.id)" -ForegroundColor Gray
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 5: Get a specific rule by ID
Write-Host "`n5. Retrieving a specific detection rule..." -ForegroundColor Yellow
if ($newRule -and $newRule.id) {
    try {
        $specificRule = Get-DefenderXDRDetectionRule -RuleId $newRule.id
        Write-Host "✓ Retrieved rule: $($specificRule.displayName)" -ForegroundColor Green
        Write-Host "  Status: $(if($specificRule.isEnabled){'Enabled'}else{'Disabled'})" -ForegroundColor Gray
        Write-Host "  Severity: $($specificRule.detectionAction.alertTemplate.severity)" -ForegroundColor Gray
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

# Example 6: Update a detection rule
Write-Host "`n6. Updating detection rule severity..." -ForegroundColor Yellow
if ($newRule -and $newRule.id) {
    try {
        Update-DefenderXDRDetectionRule `
            -RuleId $newRule.id `
            -Severity "medium" `
            -Description "Updated: Detects suspicious PowerShell execution patterns. Severity reduced after tuning."
        
        Write-Host "✓ Detection rule updated successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

# Example 7: Disable a detection rule
Write-Host "`n7. Disabling a detection rule..." -ForegroundColor Yellow
if ($scheduledRule -and $scheduledRule.id) {
    try {
        Update-DefenderXDRDetectionRule -RuleId $scheduledRule.id -IsEnabled $false
        Write-Host "✓ Detection rule disabled successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

# Example 8: Get the most recently created rules
Write-Host "`n8. Getting the 5 most recently created rules..." -ForegroundColor Yellow
try {
    $recentRules = Get-DefenderXDRDetectionRule -OrderBy "createdDateTime desc" -Top 5
    Write-Host "Recent rules:" -ForegroundColor Green
    $recentRules | Select-Object displayName, createdDateTime, isEnabled | Format-Table
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Example 9: Remove a detection rule (with confirmation)
Write-Host "`n9. Removing a detection rule..." -ForegroundColor Yellow
if ($scheduledRule -and $scheduledRule.id) {
    try {
        # Note: This will prompt for confirmation due to ConfirmImpact = 'High'
        Remove-DefenderXDRDetectionRule -RuleId $scheduledRule.id -Confirm:$false
        Write-Host "✓ Detection rule removed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

# Example 10: Bulk operations - Create multiple detection rules
Write-Host "`n10. Creating multiple detection rules from a template..." -ForegroundColor Yellow
try {
    $ruleTemplates = @(
        @{
            DisplayName = "Suspicious Registry Modification"
            Query = "DeviceRegistryEvents | where RegistryKey has 'Run' or RegistryKey has 'RunOnce' | where InitiatingProcessFileName !in ('explorer.exe', 'services.exe')"
            Severity = "medium"
            Category = "Persistence"
            Techniques = @("T1547")
        },
        @{
            DisplayName = "Unusual File Creation in System Directories"
            Query = "DeviceFileEvents | where ActionType == 'FileCreated' and FolderPath has_any ('windows\\system32', 'windows\\syswow64') | where InitiatingProcessFileName !in ('msiexec.exe', 'dllhost.exe', 'svchost.exe')"
            Severity = "high"
            Category = "DefenseEvasion"
            Techniques = @("T1036")
        }
    )
    
    foreach ($template in $ruleTemplates) {
        $rule = New-DefenderXDRDetectionRule `
            -DisplayName $template.DisplayName `
            -QueryCondition $template.Query `
            -Severity $template.Severity `
            -Category $template.Category `
            -MitreTechniques $template.Techniques `
            -IsEnabled $true
        
        Write-Host "  ✓ Created: $($template.DisplayName)" -ForegroundColor Green
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

Write-Host "`n=== Examples Complete ===" -ForegroundColor Cyan

# Disconnect
# Disconnect-DefenderXDR
