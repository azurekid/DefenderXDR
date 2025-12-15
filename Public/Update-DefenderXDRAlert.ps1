function Update-DefenderXDRAlert {
    <#
    .SYNOPSIS
        Update a security alert in Microsoft Defender XDR
    .DESCRIPTION
        Updates properties of a security alert such as status, classification, or determination
    .PARAMETER AlertId
        The ID of the alert to update
    .PARAMETER Status
        New status for the alert (new, inProgress, resolved)
    .PARAMETER Classification
        Classification of the alert (unknown, falsePositive, truePositive, informationalExpectedActivity)
    .PARAMETER Determination
        Determination/sub-classification of the alert
    .PARAMETER AssignedTo
        User principal name to assign the alert to
    .EXAMPLE
        Update-DefenderXDRAlert -AlertId "da123..." -Status "inProgress" -AssignedTo "analyst@contoso.com"
    .EXAMPLE
        Update-DefenderXDRAlert -AlertId "da123..." -Status "resolved" -Classification "falsePositive"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AlertId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('new', 'inProgress', 'resolved')]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateSet('unknown', 'falsePositive', 'truePositive', 'informationalExpectedActivity', 'benignPositive')]
        [string]$Classification,

        [Parameter(Mandatory = $false)]
        [ValidateSet('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 
                     'other', 'multiStagedAttack', 'compromisedUser', 'phishing', 'maliciousUserActivity', 
                     'clean', 'insufficientData', 'confirmedUserActivity', 'lineOfBusinessApplication')]
        [string]$Determination,

        [Parameter(Mandatory = $false)]
        [string]$AssignedTo
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('SecurityEvents.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
        
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/alerts_v2/$AlertId"
        
        $body = @{}
        if ($Status) { $body['status'] = $Status }
        if ($Classification) { $body['classification'] = $Classification }
        if ($Determination) { $body['determination'] = $Determination }
        if ($AssignedTo) { $body['assignedTo'] = $AssignedTo }

        if ($body.Count -eq 0) {
            Write-Warning "No properties specified to update"
            return
        }

        if ($PSCmdlet.ShouldProcess("Alert $AlertId", "Update alert properties")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method PATCH -Body $body
            Write-Verbose "Alert updated successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to update alert: $_"
        throw
    }
}
