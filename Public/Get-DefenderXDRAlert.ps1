function Get-DefenderXDRAlert {
    <#
    .SYNOPSIS
        Get security alerts from Microsoft Defender XDR
    .DESCRIPTION
        Retrieves security alerts from Microsoft Defender XDR through Graph API
    .PARAMETER AlertId
        Specific alert ID to retrieve
    .PARAMETER Filter
        OData filter expression
    .PARAMETER Top
        Number of results to return (default: 100)
    .PARAMETER Skip
        Number of results to skip for pagination
    .PARAMETER OrderBy
        Field to order results by
    .EXAMPLE
        Get-DefenderXDRAlert
    .EXAMPLE
        Get-DefenderXDRAlert -AlertId "da12345678901234567890123456789012"
    .EXAMPLE
        Get-DefenderXDRAlert -Filter "severity eq 'high'" -Top 50
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$AlertId,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Top = 50,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Skip,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$OrderBy
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.Read.All', 'SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/alerts_v2/$AlertId"
        }
        else {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/alerts_v2"
            
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
        Write-Error "Failed to get alerts: $_"
        throw
    }
}
