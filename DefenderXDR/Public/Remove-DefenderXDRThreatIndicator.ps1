function Remove-DefenderXDRThreatIndicator {
    <#
    .SYNOPSIS
        Remove a threat indicator from Microsoft Defender XDR
    .DESCRIPTION
        Deletes a threat intelligence indicator from Microsoft Defender XDR
    .PARAMETER IndicatorId
        The ID of the indicator to remove
    .EXAMPLE
        Remove-DefenderXDRThreatIndicator -IndicatorId "ti123..."
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$IndicatorId
    )

    process {
        try {
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators/$IndicatorId"

            if ($PSCmdlet.ShouldProcess($IndicatorId, "Remove threat indicator")) {
                $null = Invoke-DefenderXDRRequest -Uri $uri -Method DELETE
                Write-Verbose "Threat indicator removed successfully"
                Write-Information "Threat indicator $IndicatorId removed successfully" -InformationAction Continue
            }
        }
        catch {
            Write-Error "Failed to remove threat indicator: $_"
            throw
        }
    }
}
