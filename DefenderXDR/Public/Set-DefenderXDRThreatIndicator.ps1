function Set-DefenderXDRThreatIndicator {
    <#
    .SYNOPSIS
        Submit or update a threat indicator in Microsoft Defender XDR
    .DESCRIPTION
        Creates a new threat intelligence indicator or updates an existing one in Microsoft Defender XDR
    .PARAMETER IndicatorId
        The ID of an existing indicator to update (optional - if not provided, a new indicator is created)
    .PARAMETER IndicatorValue
        The value of the indicator (IP, URL, domain, file hash, etc.)
    .PARAMETER IndicatorType
        Type of indicator (domainName, url, ipAddress, fileSha1, fileSha256, fileMd5)
    .PARAMETER Action
        Action to take (alert, block, allowed)
    .PARAMETER ThreatType
        Type of threat (Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList)
    .PARAMETER Severity
        Severity level (0-5, where 5 is most severe)
    .PARAMETER Description
        Description of the indicator
    .PARAMETER ExpirationDateTime
        When the indicator expires
    .PARAMETER Title
        Title/name for the indicator
    .EXAMPLE
        Set-DefenderXDRThreatIndicator -IndicatorValue "malicious.com" -IndicatorType "domainName" -Action "block" -ThreatType "Malware"
        Creates a new threat indicator
    .EXAMPLE
        Set-DefenderXDRThreatIndicator -IndicatorId "abc123" -Action "allowed" -Description "Updated to allowed"
        Updates an existing threat indicator
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [string]$IndicatorId,

        [Parameter(Mandatory = $false)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $false)]
        [ValidateSet('domainName', 'url', 'ipAddress', 'fileSha1', 'fileSha256', 'fileMd5')]
        [string]$IndicatorType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('alert', 'block', 'allowed')]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Botnet', 'C2', 'CryptoMining', 'Darknet', 'DDoS', 'MaliciousUrl', 'Malware', 'Phishing', 
                     'Proxy', 'PUA', 'WatchList', 'unknown')]
        [string]$ThreatType = 'unknown',

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 5)]
        [int]$Severity = 3,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [datetime]$ExpirationDateTime,

        [Parameter(Mandatory = $false)]
        [string]$Title
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('ThreatIndicators.ReadWrite.OwnedBy') -FunctionName $MyInvocation.MyCommand.Name
        
        # Determine if this is an update or create operation
        $isUpdate = $PSBoundParameters.ContainsKey('IndicatorId')
        
        if ($isUpdate) {
            # Update operation
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators/$IndicatorId"
            $method = 'PATCH'
            $operation = "Update threat indicator"
            $target = $IndicatorId
        }
        else {
            # Create operation - require mandatory fields
            if (-not $IndicatorValue) {
                throw "IndicatorValue is required when creating a new indicator"
            }
            if (-not $IndicatorType) {
                throw "IndicatorType is required when creating a new indicator"
            }
            if (-not $Action) {
                throw "Action is required when creating a new indicator"
            }
            
            $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators"
            $method = 'POST'
            $operation = "Submit threat indicator"
            $target = $IndicatorValue
        }
        
        $body = @{}
        
        # Add action and targetProduct if provided
        if ($Action) { 
            $body['action'] = $Action
        }
        if (-not $isUpdate) {
            $body['targetProduct'] = 'Microsoft Defender ATP'
        }

        # Set the indicator value based on type (only for create)
        if ($IndicatorType -and $IndicatorValue) {
            switch ($IndicatorType) {
                'domainName' { $body['domainName'] = $IndicatorValue }
                'url' { $body['url'] = $IndicatorValue }
                'ipAddress' { 
                    $body['networkIPv4'] = $IndicatorValue
                    $body['networkIPv6'] = $IndicatorValue
                }
                'fileSha1' { $body['fileHashValue'] = $IndicatorValue; $body['fileHashType'] = 'sha1' }
                'fileSha256' { $body['fileHashValue'] = $IndicatorValue; $body['fileHashType'] = 'sha256' }
                'fileMd5' { $body['fileHashValue'] = $IndicatorValue; $body['fileHashType'] = 'md5' }
            }
        }

        if ($ThreatType) { $body['threatType'] = $ThreatType }
        if ($Severity) { $body['severity'] = $Severity }
        if ($Description) { $body['description'] = $Description }
        if ($Title) { $body['title'] = $Title }
        if ($ExpirationDateTime) { 
            $body['expirationDateTime'] = $ExpirationDateTime.ToUniversalTime().ToString('o')
        }

        if ($PSCmdlet.ShouldProcess($target, $operation)) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method $method -Body $body
            Write-Verbose "Threat indicator $(if ($isUpdate) { 'updated' } else { 'submitted' }) successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to $(if ($isUpdate) { 'update' } else { 'submit' }) threat indicator: $_"
        throw
    }
}

# Create alias for backward compatibility
Set-Alias -Name Submit-DefenderXDRThreatIndicator -Value Set-DefenderXDRThreatIndicator
