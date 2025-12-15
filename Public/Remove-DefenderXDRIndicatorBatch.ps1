function Remove-DefenderXDRIndicatorBatch {
    <#
    .SYNOPSIS
        Remove multiple threat indicators from Microsoft Defender Endpoint
    .DESCRIPTION
        Deletes multiple threat intelligence indicators from Microsoft Defender Endpoint API in a batch operation
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/batch-delete-ti-indicators
    .PARAMETER IndicatorIds
        Array of indicator IDs to remove
    .EXAMPLE
        Remove-DefenderXDRIndicatorBatch -IndicatorIds @("123", "456", "789")
    .EXAMPLE
        $ids = Get-DefenderXDRIndicator | Where-Object {$_.expirationTime -lt (Get-Date)} | Select-Object -ExpandProperty id
        Remove-DefenderXDRIndicatorBatch -IndicatorIds $ids
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$IndicatorIds
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('Ti.ReadWrite') -FunctionName $MyInvocation.MyCommand.Name
        
        $baseUri = "https://api.securitycenter.microsoft.com/api"
        $uri = "$baseUri/indicators/BatchDelete"

        $body = @{
            IndicatorIds = $IndicatorIds
        }

        if ($PSCmdlet.ShouldProcess("$($IndicatorIds.Count) indicators", "Batch remove from Defender Endpoint")) {
            Write-Verbose "Removing $($IndicatorIds.Count) threat indicators"
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Batch removal completed successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to batch remove threat indicators: $_"
        throw
    }
}
