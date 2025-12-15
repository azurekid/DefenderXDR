function Update-DefenderXDRCustomDetection {
    <#
    .SYNOPSIS
        Update an existing custom detection rule in Microsoft Defender XDR
    .DESCRIPTION
        Updates properties of an existing custom detection rule. Supports updating display name, enabled status,
        query condition, schedule, and detection actions.
    .PARAMETER Id
        The unique identifier of the custom detection rule to update. Required.
    .PARAMETER DisplayName
        Updated friendly name of the custom detection rule.
    .PARAMETER Enabled
        Whether the rule should be enabled or disabled.
    .PARAMETER QueryText
        Updated Advanced Hunting KQL query to execute when the rule runs.
    .PARAMETER SchedulePeriod
        Updated schedule period for rule execution. Valid values: 1H, 2H, 4H, 8H, 12H, 24H.
    .PARAMETER AlertTitle
        Updated alert title template.
    .PARAMETER AlertDescription
        Updated alert description template.
    .PARAMETER AlertSeverity
        Updated alert severity. One of: Informational, Low, Medium, High.
    .PARAMETER AlertCategory
        Updated logical category or classification for the detection.
    .PARAMETER AlertRecommendedActions
        Updated recommended remediation or triage actions.
    .PARAMETER AlertImpactedAssets
        Updated impacted assets configuration. Pass $null to clear existing assets.
    .PARAMETER ResponseActions
        Updated response actions to take when detection triggers.
    .PARAMETER OrganizationalScope
        Updated organizational scope for the detection.
    .PARAMETER EndpointUri
        Optional full endpoint URI to PATCH to. Overrides built-in candidates.
    .EXAMPLE
        Update-DefenderXDRCustomDetection -Id "12345" -DisplayName "Updated Rule Name" -Enabled $false
    .EXAMPLE
        Update-DefenderXDRCustomDetection -Id "12345" -QueryText "DeviceProcessEvents | where FileName == 'notepad.exe'" -SchedulePeriod "2H"
    .EXAMPLE
        Update-DefenderXDRCustomDetection -Id "12345" -AlertTitle "New Alert Title" -AlertSeverity "High" -AlertRecommendedActions "Isolate device immediately"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [bool]$Enabled,

        [Parameter(Mandatory = $false)]
        [string]$QueryText,

        [Parameter(Mandatory = $false)]
        [ValidateSet('1H','2H','4H','8H','12H','24H')]
        [string]$SchedulePeriod,

        [Parameter(Mandatory = $false)]
        [string]$AlertTitle,

        [Parameter(Mandatory = $false)]
        [string]$AlertDescription,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Informational','Low','Medium','High')]
        [string]$AlertSeverity,

        [Parameter(Mandatory = $false)]
        [string]$AlertCategory,

        [Parameter(Mandatory = $false)]
        [string]$AlertRecommendedActions,

        [Parameter(Mandatory = $false)]
        [object]$AlertImpactedAssets,

        [Parameter(Mandatory = $false)]
        [object]$ResponseActions,

        [Parameter(Mandatory = $false)]
        [object]$OrganizationalScope,

        [Parameter(Mandatory = $false)]
        [string]$EndpointUri
    )

    begin {
        # Validate permissions: updating custom detections requires write access
        Test-DefenderXDRPermission -RequiredPermissions @('CustomDetection.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
    }

    process {
        try {
            # Build update body with only provided parameters
            $body = @{}

            if ($PSBoundParameters.ContainsKey('DisplayName')) {
                $body.displayName = $DisplayName
            }

            if ($PSBoundParameters.ContainsKey('Enabled')) {
                $body.isEnabled = $Enabled
            }

            # Build nested objects only if their properties are specified
            $queryCondition = @{}
            if ($PSBoundParameters.ContainsKey('QueryText')) {
                $queryCondition.queryText = $QueryText
            }

            $schedule = @{}
            if ($PSBoundParameters.ContainsKey('SchedulePeriod')) {
                $schedule.period = $SchedulePeriod
            }

            $alertTemplate = @{}
            if ($PSBoundParameters.ContainsKey('AlertTitle')) {
                $alertTemplate.title = $AlertTitle
            }
            if ($PSBoundParameters.ContainsKey('AlertDescription')) {
                $alertTemplate.description = $AlertDescription
            }
            if ($PSBoundParameters.ContainsKey('AlertSeverity')) {
                $alertTemplate.severity = $AlertSeverity.ToLower()
            }
            if ($PSBoundParameters.ContainsKey('AlertCategory')) {
                $alertTemplate.category = $AlertCategory
            }
            if ($PSBoundParameters.ContainsKey('AlertRecommendedActions')) {
                $alertTemplate.recommendedActions = $AlertRecommendedActions
            }
            if ($PSBoundParameters.ContainsKey('AlertImpactedAssets')) {
                $alertTemplate.impactedAssets = $AlertImpactedAssets
            }

            $detectionAction = @{}
            if ($alertTemplate.Count -gt 0) {
                $detectionAction.alertTemplate = $alertTemplate
            }
            if ($PSBoundParameters.ContainsKey('ResponseActions')) {
                $detectionAction.responseActions = $ResponseActions
            }
            if ($PSBoundParameters.ContainsKey('OrganizationalScope')) {
                $detectionAction.organizationalScope = $OrganizationalScope
            }

            # Add nested objects to body if they have content
            if ($queryCondition.Count -gt 0) {
                $body.queryCondition = $queryCondition
            }
            if ($schedule.Count -gt 0) {
                $body.schedule = $schedule
            }
            if ($detectionAction.Count -gt 0) {
                $body.detectionAction = $detectionAction
            }

            # If no updates specified, return early
            if ($body.Count -eq 0) {
                Write-Warning "No update parameters specified. Nothing to update."
                return
            }

            $graphCandidates = @(
                "https://graph.microsoft.com/beta/security/rules/detectionRules/$Id"
            )

            $candidateUris = if ($EndpointUri) { @($EndpointUri) } else { $graphCandidates }

            if ($PSCmdlet.ShouldProcess("Custom Detection Rule $Id", 'Update')) {
                foreach ($uri in $candidateUris) {
                    Write-Verbose "Attempting custom detection update via $uri"
                    try {
                        $response = Invoke-DefenderXDRRequest -Uri $uri -Method PATCH -Body $body
                        if ($response) {
                            Write-Verbose "Custom detection updated successfully via $uri"
                            return $response
                        }
                    }
                    catch {
                        $msg = $_.Exception.Message
                        Write-Verbose "Endpoint failed: $uri - $msg"
                        continue
                    }
                }
                throw "Failed to update custom detection using all known endpoints. Verify API availability and permissions."
            }
        }
        catch {
            Write-Error "Failed to update custom detection rule: $_"
            throw
        }
    }
}