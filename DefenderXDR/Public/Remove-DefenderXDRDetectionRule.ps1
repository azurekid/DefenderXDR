function Remove-DefenderXDRDetectionRule {
    <#
    .SYNOPSIS
        Remove a custom detection rule from Microsoft Defender XDR
    .DESCRIPTION
        Deletes a custom detection rule from Microsoft Defender XDR
    .PARAMETER RuleId
        The ID of the detection rule to remove
    .EXAMPLE
        Remove-DefenderXDRDetectionRule -RuleId "12345678-1234-1234-1234-123456789012"
        Remove a specific detection rule
    .EXAMPLE
        Get-DefenderXDRDetectionRule -Filter "isEnabled eq false" | ForEach-Object { Remove-DefenderXDRDetectionRule -RuleId $_.id }
        Remove all disabled detection rules
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('id')]
        [string]$RuleId
    )

    process {
        try {
            # Validate permissions
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
            
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/rules/detectionRules/$RuleId"
            
            if ($PSCmdlet.ShouldProcess("Detection rule $RuleId", "Delete detection rule")) {
                $response = Invoke-DefenderXDRRequest -Uri $uri -Method DELETE
                Write-Verbose "Detection rule deleted successfully: $RuleId"
                return $response
            }
        }
        catch {
            Write-Error "Failed to remove detection rule: $_"
            throw
        }
    }
}
