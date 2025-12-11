function Get-DefenderXDRDetectionRule {
    <#
    .SYNOPSIS
        Get custom detection rules from Microsoft Defender XDR
    .DESCRIPTION
        Retrieves custom detection rules from Microsoft Defender XDR through the Microsoft Graph API
    .PARAMETER RuleId
        Specific detection rule ID to retrieve
    .PARAMETER Filter
        OData filter expression to filter detection rules
    .PARAMETER Top
        Number of results to return (default: 100)
    .PARAMETER Skip
        Number of results to skip for pagination
    .PARAMETER OrderBy
        Property to order results by
    .EXAMPLE
        Get-DefenderXDRDetectionRule
        Get all detection rules
    .EXAMPLE
        Get-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012"
        Get a specific detection rule by ID
    .EXAMPLE
        Get-DefenderXDRDetectionRule -Filter "isEnabled eq true" -Top 50
        Get the first 50 enabled detection rules
    .EXAMPLE
        Get-DefenderXDRDetectionRule -OrderBy "createdDateTime desc" -Top 10
        Get the 10 most recently created detection rules
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$RuleId,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Top = 100,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Skip,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$OrderBy
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.Read.All', 'SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/rules/detectionRules/$RuleId"
        }
        else {
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/rules/detectionRules"
            
            $queryParams = @()
            if ($Filter) { $queryParams += "`$filter=$Filter" }
            if ($Top) { $queryParams += "`$top=$Top" }
            if ($Skip) { $queryParams += "`$skip=$Skip" }
            if ($OrderBy) { $queryParams += "`$orderby=$OrderBy" }
            
            if ($queryParams.Count -gt 0) {
                $uri += "?" + ($queryParams -join '&')
            }
        }

        Write-Verbose "Retrieving detection rules from: $uri"
        $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return $response
        }
        else {
            return $response.value
        }
    }
    catch {
        Write-Error "Failed to get detection rules: $_"
        throw
    }
}
