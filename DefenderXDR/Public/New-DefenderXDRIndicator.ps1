function New-DefenderXDRIndicator {
    <#
    .SYNOPSIS
        Create a new threat indicator in Microsoft Defender Endpoint
    .DESCRIPTION
        Submits a new threat intelligence indicator to Microsoft Defender Endpoint API
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator
    .PARAMETER IndicatorValue
        The value of the indicator (e.g., domain, IP address, URL, or file hash)
    .PARAMETER IndicatorType
        Type of the indicator. Valid values: FileSha1, FileSha256, IpAddress, DomainName, Url
    .PARAMETER Action
        The action to take when the indicator is detected. Valid values: Alert, AlertAndBlock, Allowed
    .PARAMETER Title
        Title for the indicator
    .PARAMETER Description
        Description of the indicator
    .PARAMETER Severity
        Severity of the indicator. Valid values: Informational, Low, Medium, High
    .PARAMETER RecommendedActions
        Recommended actions for the indicator
    .PARAMETER RbacGroupNames
        List of RBAC group names the indicator would be applied to
    .PARAMETER Category
        Category of the indicator
    .PARAMETER ExpirationTime
        Expiration time of the indicator in ISO 8601 format
    .PARAMETER GenerateAlert
        Whether to generate an alert when the indicator is detected
    .EXAMPLE
        New-DefenderXDRIndicator -IndicatorValue "malicious.com" -IndicatorType "DomainName" -Action "AlertAndBlock" -Title "Malicious Domain" -Severity "High"
        Creates a new domain indicator that blocks and alerts
    .EXAMPLE
        New-DefenderXDRIndicator -IndicatorValue "192.0.2.1" -IndicatorType "IpAddress" -Action "Alert" -Title "Suspicious IP" -Severity "Medium" -Description "Known C2 server"
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
        }
        New-DefenderXDRIndicator @params
        Creates a new file hash indicator with expiration
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet('FileSha1', 'FileSha256', 'IpAddress', 'DomainName', 'Url')]
        [string]$IndicatorType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Alert', 'AlertAndBlock', 'Allowed')]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [string]$RecommendedActions,

        [Parameter(Mandatory = $false)]
        [string[]]$RbacGroupNames,

        [Parameter(Mandatory = $false)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$ExpirationTime,

        [Parameter(Mandatory = $false)]
        [bool]$GenerateAlert
    )

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
        }

        # Add optional parameters if provided
        if ($Description) { $indicator['description'] = $Description }
        if ($Severity) { $indicator['severity'] = $Severity }
        if ($RecommendedActions) { $indicator['recommendedActions'] = $RecommendedActions }
        if ($RbacGroupNames) { $indicator['rbacGroupNames'] = $RbacGroupNames }
        if ($Category) { $indicator['category'] = $Category }
        if ($ExpirationTime) { $indicator['expirationTime'] = $ExpirationTime }
        if ($PSBoundParameters.ContainsKey('GenerateAlert')) { $indicator['generateAlert'] = $GenerateAlert }

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
