function Get-DefenderXDRIndicator {
    <#
    .SYNOPSIS
        Get threat indicators from Microsoft Defender XDR
    .DESCRIPTION
        Retrieves threat indicators from either the Defender Endpoint API or Microsoft Graph Security tiIndicators API
        (depending on the Connect-DefenderXDR audience used).
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/get-ti-indicators-collection
        and https://learn.microsoft.com/en-us/graph/api/security-list-tiindicators
    .PARAMETER IndicatorId
        Specific indicator ID to retrieve
    .PARAMETER Top
        Number of results to return for pagination
    .PARAMETER Skip
        Number of results to skip for pagination
    .PARAMETER OrderBy
        Field to order results by
    .PARAMETER Filter
        OData filter expression
    .EXAMPLE
        Get-DefenderXDRIndicator
        Gets all threat indicators
    .EXAMPLE
        Get-DefenderXDRIndicator -IndicatorId "123"
        Gets a specific threat indicator by ID
    .EXAMPLE
        Get-DefenderXDRIndicator -Top 100 -OrderBy "lastUpdateTime desc"
        Gets the 100 most recently updated indicators
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$IndicatorId,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Top,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Skip,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$OrderBy,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$Filter
    )

    try {
            # Validate permissions for both Defender (Ti.*) and Graph (ThreatIndicators.*) audiences
            $requiredPermissions = @(
                'Ti.Read.All',
                'Ti.ReadWrite',
                'ThreatIndicators.Read.All',
                'ThreatIndicators.ReadWrite.All'
            )
            Test-DefenderXDRPermission -RequiredPermissions $requiredPermissions -FunctionName $MyInvocation.MyCommand.Name

            if (-not $script:hasPermission) {
                Write-Verbose "Permission check failed for threat indicators. Aborting request."
                return
            }

            $usingGraph = ($script:ApiAudience -eq 'Graph')
            $securityBaseUri = 'https://api.securitycenter.microsoft.com/api/indicators'
            $graphBaseUri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators" 
            $baseUri = if ($usingGraph) { $graphBaseUri } else { $securityBaseUri }
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$baseUri/$IndicatorId"
        }
        else {
            $uri = $baseUri
            
            $queryParams = @()
            if ($Top) { $queryParams += "`$top=$Top" }
            if ($Skip) { $queryParams += "`$skip=$Skip" }
            if ($OrderBy) { $queryParams += "`$orderby=$OrderBy" }
            if ($Filter) { $queryParams += "`$filter=$Filter" }
            
            if ($queryParams.Count -gt 0) {
                $uri += "?" + ($queryParams -join '&')
            }
        }

        Write-Verbose "Retrieving indicator(s) from: $uri"
        $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return $response
        }
        else {
            # Response should contain a value property with the collection
            if ($response.value) {
                return $response.value
            }
            return $response
        }
    }
    catch {
        Write-Error "Failed to get threat indicators: $_"
        throw
    }
}
