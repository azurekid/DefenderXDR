function Remove-DefenderXDRIndicator {
    <#
    .SYNOPSIS
        Remove a threat indicator from Microsoft Defender Endpoint
    .DESCRIPTION
        Deletes a threat intelligence indicator from Microsoft Defender Endpoint API by ID
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/delete-ti-indicator-by-id
    .PARAMETER IndicatorId
        The ID of the indicator to remove
    .EXAMPLE
        Remove-DefenderXDRIndicator -IndicatorId "123"
    .EXAMPLE
        Get-DefenderXDRIndicator | Where-Object {$_.severity -eq 'Informational'} | Remove-DefenderXDRIndicator
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [string]$IndicatorId
    )

    process {
        try {
            # Validate permissions
            Test-DefenderXDRPermission -RequiredPermissions @('Ti.ReadWrite') -FunctionName $MyInvocation.MyCommand.Name
            
            $baseUri = "https://api.securitycenter.microsoft.com/api"
            $uri = "$baseUri/indicators/$IndicatorId"

            if ($PSCmdlet.ShouldProcess($IndicatorId, "Remove threat indicator from Defender Endpoint")) {
                $null = Invoke-DefenderXDRRequest -Uri $uri -Method DELETE
                Write-Verbose "Threat indicator $IndicatorId removed successfully"
                Write-Information "Threat indicator $IndicatorId removed successfully" -InformationAction Continue
            }
        }
        catch {
            Write-Error "Failed to remove threat indicator ${IndicatorId}: $_"
            throw
        }
    }
}
