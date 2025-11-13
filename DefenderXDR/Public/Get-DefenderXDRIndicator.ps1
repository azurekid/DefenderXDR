function Get-DefenderXDRIndicator {
    <#
    .SYNOPSIS
        Get threat indicators from Microsoft Defender Endpoint
    .DESCRIPTION
        Retrieves threat indicators from Microsoft Defender Endpoint API
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/get-ti-indicators-collection
        and https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator
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
        # Use Defender Endpoint API
        $baseUri = "https://api.securitycenter.microsoft.com/api"
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$baseUri/indicators/$IndicatorId"
        }
        else {
            $uri = "$baseUri/indicators"
            
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
