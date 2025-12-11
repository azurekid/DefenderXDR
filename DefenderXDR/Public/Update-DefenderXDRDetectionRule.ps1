function Update-DefenderXDRDetectionRule {
    <#
    .SYNOPSIS
        Update a custom detection rule in Microsoft Defender XDR
    .DESCRIPTION
        Updates properties of an existing custom detection rule in Microsoft Defender XDR
    .PARAMETER RuleId
        The ID of the detection rule to update
    .PARAMETER DisplayName
        New display name for the detection rule
    .PARAMETER QueryCondition
        New KQL query that defines when the rule should trigger
    .PARAMETER Severity
        New severity level (informational, low, medium, high)
    .PARAMETER IsEnabled
        Enable or disable the rule
    .PARAMETER Description
        New description of the detection rule
    .PARAMETER RecommendedActions
        New recommended actions
    .PARAMETER ImpactedAssets
        New array of impacted asset types
    .PARAMETER Category
        New category of the detection
    .PARAMETER MitreTechniques
        New array of MITRE ATT&CK technique IDs
    .PARAMETER Schedule
        New execution schedule
    .EXAMPLE
        Update-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012" -IsEnabled $false
        Disable a detection rule
    .EXAMPLE
        Update-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012" `
                                         -Severity "high" `
                                         -Description "Updated description"
        Update severity and description of a detection rule
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [string]$QueryCondition,

        [Parameter(Mandatory = $false)]
        [ValidateSet('informational', 'low', 'medium', 'high')]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [bool]$IsEnabled,

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
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/rules/detectionRules/$RuleId"
        
        $body = @{}

        # Only include properties that were specified
        if ($PSBoundParameters.ContainsKey('DisplayName')) {
            $body['displayName'] = $DisplayName
        }

        if ($PSBoundParameters.ContainsKey('IsEnabled')) {
            $body['isEnabled'] = $IsEnabled
        }

        # Build detection action if any alert template properties are provided
        $hasAlertTemplateChanges = $PSBoundParameters.ContainsKey('Severity') -or 
                                    $PSBoundParameters.ContainsKey('Description') -or 
                                    $PSBoundParameters.ContainsKey('RecommendedActions') -or 
                                    $PSBoundParameters.ContainsKey('Category') -or 
                                    $PSBoundParameters.ContainsKey('MitreTechniques') -or 
                                    $PSBoundParameters.ContainsKey('ImpactedAssets')

        if ($hasAlertTemplateChanges) {
            $alertTemplate = @{}
            
            if ($PSBoundParameters.ContainsKey('Severity')) {
                $alertTemplate['severity'] = $Severity
            }
            if ($PSBoundParameters.ContainsKey('Description')) {
                $alertTemplate['description'] = $Description
            }
            if ($PSBoundParameters.ContainsKey('RecommendedActions')) {
                $alertTemplate['recommendedActions'] = $RecommendedActions
            }
            if ($PSBoundParameters.ContainsKey('Category')) {
                $alertTemplate['category'] = $Category
            }
            if ($PSBoundParameters.ContainsKey('MitreTechniques')) {
                $alertTemplate['mitreTechniques'] = $MitreTechniques
            }
            if ($PSBoundParameters.ContainsKey('ImpactedAssets')) {
                $alertTemplate['impactedAssets'] = $ImpactedAssets
            }

            $body['detectionAction'] = @{
                alertTemplate = $alertTemplate
            }
        }

        if ($PSBoundParameters.ContainsKey('QueryCondition')) {
            $body['queryCondition'] = @{
                queryText = $QueryCondition
            }
        }

        if ($PSBoundParameters.ContainsKey('Schedule')) {
            $body['schedule'] = $Schedule
        }

        if ($body.Count -eq 0) {
            Write-Warning "No properties specified to update"
            return
        }

        if ($PSCmdlet.ShouldProcess("Detection rule $RuleId", "Update detection rule properties")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method PATCH -Body $body
            Write-Verbose "Detection rule updated successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to update detection rule: $_"
        throw
    }
}
