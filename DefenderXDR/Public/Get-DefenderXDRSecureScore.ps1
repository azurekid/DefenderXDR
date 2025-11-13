function Get-DefenderXDRSecureScore {
    <#
    .SYNOPSIS
        Get Microsoft Secure Score information
    .DESCRIPTION
        Retrieves Microsoft Secure Score data from Microsoft Defender XDR
    .PARAMETER Top
        Number of results to return
    .EXAMPLE
        Get-DefenderXDRSecureScore
    .EXAMPLE
        Get-DefenderXDRSecureScore -Top 30
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$Top = 1
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.Read.All', 'SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/secureScores"
        
        if ($Top) {
            $uri += "?`$top=$Top"
        }

        $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET
        return $response.value
    }
    catch {
        Write-Error "Failed to get secure score: $_"
        throw
    }
}
