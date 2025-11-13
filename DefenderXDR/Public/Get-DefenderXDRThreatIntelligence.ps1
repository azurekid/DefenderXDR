function Get-DefenderXDRThreatIntelligence {
    <#
    .SYNOPSIS
        Get threat intelligence indicators from Microsoft Defender XDR
    .DESCRIPTION
        Retrieves threat intelligence indicators from Microsoft Defender XDR through Graph API
    .PARAMETER IndicatorId
        Specific indicator ID to retrieve
    .PARAMETER Filter
        OData filter expression
    .PARAMETER Top
        Number of results to return (default: 100)
    .PARAMETER Skip
        Number of results to skip for pagination
    .EXAMPLE
        Get-DefenderXDRThreatIntelligence
    .EXAMPLE
        Get-DefenderXDRThreatIntelligence -IndicatorId "ti123..."
    .EXAMPLE
        Get-DefenderXDRThreatIntelligence -Filter "threatType eq 'Malware'" -Top 50
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$IndicatorId,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Top = 100,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Skip
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators/$IndicatorId"
        }
        else {
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators"
            
            $queryParams = @()
            if ($Filter) { $queryParams += "`$filter=$Filter" }
            if ($Top) { $queryParams += "`$top=$Top" }
            if ($Skip) { $queryParams += "`$skip=$Skip" }
            
            if ($queryParams.Count -gt 0) {
                $uri += "?" + ($queryParams -join '&')
            }
        }

        $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            return $response
        }
        else {
            return $response.value
        }
    }
    catch {
        Write-Error "Failed to get threat intelligence indicators: $_"
        throw
    }
}
