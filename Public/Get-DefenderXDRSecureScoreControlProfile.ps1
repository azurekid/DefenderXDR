function Get-DefenderXDRSecureScoreControlProfile {
    <#
    .SYNOPSIS
        Get Secure Score control profiles
    .DESCRIPTION
        Retrieves Secure Score control profiles (security recommendations) from Microsoft Defender XDR
    .PARAMETER ControlId
        Specific control profile ID to retrieve
    .PARAMETER Top
        Number of results to return
    .EXAMPLE
        Get-DefenderXDRSecureScoreControlProfile
    .EXAMPLE
        Get-DefenderXDRSecureScoreControlProfile -ControlId "AdminMFA"
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$ControlId,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [int]$Top = 100
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.Read.All', 'SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/secureScoreControlProfiles/$ControlId"
        }
        else {
            $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/secureScoreControlProfiles"
            
            if ($Top) {
                $uri += "?`$top=$Top"
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
        Write-Error "Failed to get secure score control profiles: $_"
        throw
    }
}
