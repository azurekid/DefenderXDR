function New-DefenderXDRAlertComment {
    <#
    .SYNOPSIS
        Add a comment to a security alert
    .DESCRIPTION
        Adds a comment to a security alert in Microsoft Defender XDR
    .PARAMETER AlertId
        The ID of the alert to add a comment to
    .PARAMETER Comment
        The comment text to add
    .EXAMPLE
        New-DefenderXDRAlertComment -AlertId "da123..." -Comment "Investigating this alert"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AlertId,

        [Parameter(Mandatory = $true)]
        [string]$Comment
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/alerts_v2/$AlertId/comments"
        
        $body = @{
            comment = $Comment
        }

        if ($PSCmdlet.ShouldProcess("Alert $AlertId", "Add comment")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Comment added successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to add comment to alert: $_"
        throw
    }
}
