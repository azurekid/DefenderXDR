function Submit-DefenderXDRIndicator {
    <#
    .SYNOPSIS
        Submit a new threat indicator to Microsoft Defender Endpoint
    .DESCRIPTION
        Submits a new threat intelligence indicator to Microsoft Defender Endpoint API
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator
        Supports pipeline input from Get-DefenderXDRIndicator for updating or recreating indicators.
    .PARAMETER IndicatorValue
        Identity of the Indicator entity. Required
    .PARAMETER IndicatorType
        Type of the indicator. Possible values are: FileSha1, FileMd5, CertificateThumbprint, FileSha256, IpAddress, DomainName, and Url. Required
    .PARAMETER Action
        The action that is taken if the indicator is discovered in the organization. Possible values are: Alert, Warn, Block, Audit, BlockAndRemediate, AlertAndBlock, and Allowed. Required. The GenerateAlert parameter must be set to TRUE when creating an action with Audit.
    .PARAMETER Application
        A user-friendly name for the content blocked by the indicator. If specified, this text will be shown in the blocking notification in place of the blocked filename or domain. This field only works for new indicators; it doesn't update the value on an existing indicator. Optional
    .PARAMETER Title
        Indicator alert title. Required
    .PARAMETER Description
        Description of the indicator. Required
    .PARAMETER ExpirationTime
        The expiration time of the indicator. Optional
    .PARAMETER Severity
        The severity of the indicator. Possible values are: Informational, Low, Medium, and High. Optional
    .PARAMETER RecommendedActions
        TI indicator alert recommended actions. Optional
    .PARAMETER RbacGroupNames
        Comma-separated list of RBAC group names the indicator would be applied to. Optional
    .PARAMETER EducateUrl
        Custom notification/support URL. Supported for Block and Warn action types for URL indicators. Optional
    .PARAMETER GenerateAlert
        True if alert generation is required, False if this indicator shouldn't generate an alert.
    .PARAMETER RbacGroupIds
        List of RBAC group IDs the indicator would be applied to
    .PARAMETER Category
        Category of the indicator
    .PARAMETER MitreTechniques
        Array of MITRE ATT&CK techniques associated with the indicator
    .PARAMETER LookBackPeriod
        The period during which matches on the indicator are detected. Format: ISO 8601 duration (e.g., "P30D" for 30 days)
    .EXAMPLE
        Submit-DefenderXDRIndicator -IndicatorValue "malicious.com" -IndicatorType "DomainName" -Action "AlertAndBlock" -Title "Malicious Domain" -Description "Known phishing domain" -Severity "High"
        Creates a new domain indicator that blocks and alerts
    .EXAMPLE
        Submit-DefenderXDRIndicator -IndicatorValue "192.0.2.1" -IndicatorType "IpAddress" -Action "Alert" -Title "Suspicious IP" -Description "Known C2 server" -Severity "Medium"
        Creates a new IP address indicator
    .EXAMPLE
        $params = @{
            IndicatorValue = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            IndicatorType = "FileSha256"
            Action = "AlertAndBlock"
            Title = "Malware Hash"
            Severity = "High"
            Description = "Known malware sample"
            ExpirationTime = (Get-Date).AddDays(90).ToString('o')
            MitreTechniques = @("T1566", "T1204")
        }
        Submit-DefenderXDRIndicator @params
        Creates a new file hash indicator with expiration and MITRE techniques
    .EXAMPLE
        Get-DefenderXDRIndicator -IndicatorId "123" | Submit-DefenderXDRIndicator
        Recreates an indicator from an existing one using pipeline input
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('FileSha1', 'FileMd5', 'CertificateThumbprint', 'FileSha256', 'IpAddress', 'DomainName', 'Url')]
        [string]$IndicatorType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Alert', 'Warn', 'Block', 'Audit', 'BlockAndRemediate', 'AlertAndBlock', 'Allowed')]
        [string]$Action,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Application,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ExpirationTime,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$RecommendedActions,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$RbacGroupNames,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EducateUrl,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$GenerateAlert,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int[]]$RbacGroupIds,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Category,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string[]]$MitreTechniques,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$LookBackPeriod
    )

    process {
        try {
            # Validate permissions
            Test-DefenderXDRPermission -RequiredPermissions @('Ti.ReadWrite') -FunctionName $MyInvocation.MyCommand.Name

            $baseUri = "https://api.securitycenter.microsoft.com/api"
            $uri = "$baseUri/indicators"

            # Build the indicator object
            $indicator = @{
                indicatorValue = $IndicatorValue
                indicatorType = $IndicatorType
                action = $Action
                title = $Title
                description = $Description
            }

            # Add optional parameters if provided
            if ($Severity) { $indicator['severity'] = $Severity }
            if ($RecommendedActions) { $indicator['recommendedActions'] = $RecommendedActions }
            if ($RbacGroupNames) { $indicator['rbacGroupNames'] = $RbacGroupNames }
            if ($RbacGroupIds) { $indicator['rbacGroupIds'] = $RbacGroupIds }
            if ($Category) { $indicator['category'] = $Category }
            if ($ExpirationTime) { $indicator['expirationTime'] = $ExpirationTime }
            if ($PSBoundParameters.ContainsKey('GenerateAlert')) { $indicator['generateAlert'] = $GenerateAlert }
            if ($Application) { $indicator['application'] = $Application }
            if ($EducateUrl) { $indicator['educateUrl'] = $EducateUrl }
            if ($MitreTechniques) { $indicator['mitreTechniques'] = $MitreTechniques }
            if ($LookBackPeriod) { $indicator['lookBackPeriod'] = $LookBackPeriod }

            if ($PSCmdlet.ShouldProcess($IndicatorValue, "Create threat indicator in Defender Endpoint")) {
                Write-Verbose "Creating indicator: $IndicatorValue ($IndicatorType)"
                $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $indicator
                Write-Verbose "Indicator created successfully with ID: $($response.id)"
                return $response
            }
        }
        catch {
            Write-Error "Failed to create threat indicator: $_"
            throw
        }
    }
}
