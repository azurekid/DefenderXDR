function New-DefenderXDRIncidentComment {
    <#
    .SYNOPSIS
        Add a comment to a security incident
    .DESCRIPTION
        Adds a comment to a security incident in Microsoft Defender XDR
    .PARAMETER IncidentId
        The ID of the incident to add a comment to
    .PARAMETER Comment
        The comment text to add
    .EXAMPLE
        New-DefenderXDRIncidentComment -IncidentId "123" -Comment "Investigating this incident"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,

        [Parameter(Mandatory = $true)]
        [string]$Comment
    )

    try {
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/incidents/$IncidentId/comments"
        
        $body = @{
            comment = $Comment
        }

        if ($PSCmdlet.ShouldProcess("Incident $IncidentId", "Add comment")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Comment added successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to add comment to incident: $_"
        throw
    }
}
