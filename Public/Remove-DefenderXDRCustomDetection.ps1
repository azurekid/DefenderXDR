function Remove-DefenderXDRCustomDetection {
    <#
    .SYNOPSIS
        Delete a custom detection rule from Microsoft Defender XDR
    .DESCRIPTION
        Permanently deletes a custom detection rule by its ID. This action cannot be undone.
    .PARAMETER Id
        The unique identifier of the custom detection rule to delete. Required.
    .PARAMETER EndpointUri
        Optional full endpoint URI to DELETE from. Overrides built-in candidates.
    .EXAMPLE
        Remove-DefenderXDRCustomDetection -Id "12345"
    .EXAMPLE
        Get-DefenderXDRCustomDetection | Where-Object { $_.displayName -like "*test*" } | Remove-DefenderXDRCustomDetection
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [string]$EndpointUri
    )

    begin {
        # Validate permissions: deleting custom detections requires write access
        Test-DefenderXDRPermission -RequiredPermissions @('CustomDetection.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
    }

    process {
        try {
            $graphCandidates = @(
                "https://graph.microsoft.com/beta/security/rules/detectionRules/$Id"
            )

            $candidateUris = if ($EndpointUri) { @($EndpointUri) } else { $graphCandidates }

            if ($PSCmdlet.ShouldProcess("Custom Detection Rule $Id", 'Delete')) {
                foreach ($uri in $candidateUris) {
                    Write-Verbose "Attempting custom detection deletion via $uri"
                    try {
                        $response = Invoke-DefenderXDRRequest -Uri $uri -Method DELETE
                        # DELETE returns 204 No Content on success
                        Write-Verbose "Custom detection deleted successfully via $uri"
                        return $true
                    }
                    catch {
                        $msg = $_.Exception.Message
                        Write-Verbose "Endpoint failed: $uri - $msg"
                        continue
                    }
                }
                throw "Failed to delete custom detection using all known endpoints. Verify API availability and permissions."
            }
        }
        catch {
            Write-Error "Failed to delete custom detection rule: $_"
            throw
        }
    }
}