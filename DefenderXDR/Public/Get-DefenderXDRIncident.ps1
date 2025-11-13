function Get-DefenderXDRIncident {
    <#
    .SYNOPSIS
        Get security incidents from Microsoft Defender XDR
    .DESCRIPTION
        Retrieves security incidents from Microsoft Defender XDR through Graph API
    .PARAMETER IncidentId
        Specific incident ID to retrieve
    .PARAMETER Filter
        OData filter expression
    .PARAMETER Top
        Number of results to return (default: 100)
    .PARAMETER Skip
        Number of results to skip for pagination
    .PARAMETER OrderBy
        Field to order results by
    .EXAMPLE
        Get-DefenderXDRIncident
    .EXAMPLE
        Get-DefenderXDRIncident -IncidentId "12345"
    .EXAMPLE
        Get-DefenderXDRIncident -Filter "severity eq 'high'" -Top 50
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$IncidentId,

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
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityIncident.Read.All', 'SecurityIncident.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/incidents/$IncidentId"
        }
        else {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/incidents"
            
            $queryParams = @()
            if ($Filter) { $queryParams += "`$filter=$Filter" }
            if ($Top) { $queryParams += "`$top=$Top" }
            if ($Skip) { $queryParams += "`$skip=$Skip" }
            if ($OrderBy) { $queryParams += "`$orderby=$OrderBy" }
            
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
        Write-Error "Failed to get incidents: $_"
        throw
    }
}
