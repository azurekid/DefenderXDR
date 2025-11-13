function Update-DefenderXDRIncident {
    <#
    .SYNOPSIS
        Update a security incident in Microsoft Defender XDR
    .DESCRIPTION
        Updates properties of a security incident such as status, classification, or assignment
    .PARAMETER IncidentId
        The ID of the incident to update
    .PARAMETER Status
        New status for the incident (active, resolved, redirected)
    .PARAMETER Classification
        Classification of the incident (unknown, falsePositive, truePositive, informationalExpectedActivity)
    .PARAMETER Determination
        Determination/sub-classification of the incident
    .PARAMETER AssignedTo
        User principal name to assign the incident to
    .PARAMETER Tags
        Tags to add to the incident
    .EXAMPLE
        Update-DefenderXDRIncident -IncidentId "123" -Status "active" -AssignedTo "analyst@contoso.com"
    .EXAMPLE
        Update-DefenderXDRIncident -IncidentId "123" -Status "resolved" -Classification "falsePositive"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('active', 'resolved', 'redirected', 'unknownFutureValue')]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateSet('unknown', 'falsePositive', 'truePositive', 'informationalExpectedActivity', 'unknownFutureValue')]
        [string]$Classification,

        [Parameter(Mandatory = $false)]
        [ValidateSet('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 
                     'other', 'multiStagedAttack', 'compromisedAccount', 'phishing', 'maliciousUserActivity', 
                     'notMalicious', 'notEnoughDataToValidate', 'confirmedActivity', 'lineOfBusinessApplication',
                     'unknownFutureValue')]
        [string]$Determination,

        [Parameter(Mandatory = $false)]
        [string]$AssignedTo,

        [Parameter(Mandatory = $false)]
        [string[]]$Tags
    )

    try {
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/incidents/$IncidentId"
        
        $body = @{}
        if ($Status) { $body['status'] = $Status }
        if ($Classification) { $body['classification'] = $Classification }
        if ($Determination) { $body['determination'] = $Determination }
        if ($AssignedTo) { $body['assignedTo'] = $AssignedTo }
        if ($Tags) { $body['tags'] = $Tags }

        if ($body.Count -eq 0) {
            Write-Warning "No properties specified to update"
            return
        }

        if ($PSCmdlet.ShouldProcess("Incident $IncidentId", "Update incident properties")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method PATCH -Body $body
            Write-Verbose "Incident updated successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to update incident: $_"
        throw
    }
}
