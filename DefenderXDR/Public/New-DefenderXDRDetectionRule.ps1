function New-DefenderXDRDetectionRule {
    <#
    .SYNOPSIS
        Create a custom detection rule in Microsoft Defender XDR
    .DESCRIPTION
        Creates a new custom detection rule in Microsoft Defender XDR using the Microsoft Graph API.
        Detection rules allow you to create custom alerts based on KQL queries.
    .PARAMETER DisplayName
        Display name for the detection rule
    .PARAMETER QueryCondition
        The KQL query that defines when the rule should trigger
    .PARAMETER Severity
        Severity level of alerts created by this rule (informational, low, medium, high)
    .PARAMETER IsEnabled
        Whether the rule is enabled (default: true)
    .PARAMETER Description
        Description of what the detection rule does
    .PARAMETER RecommendedActions
        Recommended actions to take when this rule triggers
    .PARAMETER ImpactedAssets
        Array of impacted asset types (user, device, mailbox, etc.)
    .PARAMETER Category
        Category of the detection (DefenseEvasion, Execution, Collection, etc.)
    .PARAMETER MitreTechniques
        Array of MITRE ATT&CK technique IDs (e.g., "T1548", "T1078")
    .PARAMETER Schedule
        Hashtable defining the execution schedule with keys: period, nextRunDateTime
    .EXAMPLE
        New-DefenderXDRDetectionRule -DisplayName "Suspicious PowerShell Execution" `
                                      -QueryCondition "DeviceProcessEvents | where FileName == 'powershell.exe' and ProcessCommandLine contains 'Invoke-Expression'" `
                                      -Severity "high" `
                                      -Description "Detects suspicious PowerShell execution patterns"
    .EXAMPLE
        $schedule = @{ period = 'P1D'; nextRunDateTime = (Get-Date).AddHours(1).ToString('o') }
        New-DefenderXDRDetectionRule -DisplayName "Failed Login Attempts" `
                                      -QueryCondition "SigninLogs | where ResultType != 0" `
                                      -Severity "medium" `
                                      -Schedule $schedule
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [string]$QueryCondition,

        [Parameter(Mandatory = $false)]
        [ValidateSet('informational', 'low', 'medium', 'high')]
        [string]$Severity = 'medium',

        [Parameter(Mandatory = $false)]
        [bool]$IsEnabled = $true,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$RecommendedActions,

        [Parameter(Mandatory = $false)]
        [string[]]$ImpactedAssets,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DefenseEvasion', 'Execution', 'Collection', 'CommandAndControl', 'CredentialAccess', 
                     'Discovery', 'Exfiltration', 'Exploitation', 'Impact', 'InitialAccess', 
                     'LateralMovement', 'Persistence', 'PrivilegeEscalation')]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string[]]$MitreTechniques,

        [Parameter(Mandatory = $false)]
        [hashtable]$Schedule
    )

    try {
        # Validate permissions for custom detection rules
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/rules/detectionRules"
        
        # Build the detection condition
        $detectionAction = @{
            alertTemplate = @{
                title = $DisplayName
                severity = $Severity
            }
            responseActions = @()
        }

        if ($Description) {
            $detectionAction.alertTemplate['description'] = $Description
        }

        if ($RecommendedActions) {
            $detectionAction.alertTemplate['recommendedActions'] = $RecommendedActions
        }

        if ($Category) {
            $detectionAction.alertTemplate['category'] = $Category
        }

        if ($MitreTechniques) {
            $detectionAction.alertTemplate['mitreTechniques'] = $MitreTechniques
        }

        if ($ImpactedAssets) {
            $detectionAction.alertTemplate['impactedAssets'] = $ImpactedAssets
        }

        # Build the query condition
        $queryConditionObject = @{
            queryText = $QueryCondition
        }

        # Build the main body
        $body = @{
            displayName = $DisplayName
            isEnabled = $IsEnabled
            detectionAction = $detectionAction
            queryCondition = $queryConditionObject
        }

        if ($Schedule) {
            $body['schedule'] = $Schedule
        }

        if ($PSCmdlet.ShouldProcess($DisplayName, "Create custom detection rule")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Detection rule created successfully: $($response.id)"
            return $response
        }
    }
    catch {
        Write-Error "Failed to create detection rule: $_"
        throw
    }
}
