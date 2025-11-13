function Submit-DefenderXDRThreatIndicator {
    <#
    .SYNOPSIS
        Submit a threat indicator to Microsoft Defender XDR
    .DESCRIPTION
        Creates a new threat intelligence indicator in Microsoft Defender XDR
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
        Submit-DefenderXDRThreatIndicator -IndicatorValue "malicious.com" -IndicatorType "domainName" -Action "block" -ThreatType "Malware"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet('domainName', 'url', 'ipAddress', 'fileSha1', 'fileSha256', 'fileMd5')]
        [string]$IndicatorType,

        [Parameter(Mandatory = $true)]
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
        $uri = "$script:GraphBaseUri/$script:GraphAPIBetaVersion/security/tiIndicators"
        
        $body = @{
            action = $Action
            targetProduct = 'Microsoft Defender ATP'
        }

        # Set the indicator value based on type
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

        if ($ThreatType) { $body['threatType'] = $ThreatType }
        if ($Severity) { $body['severity'] = $Severity }
        if ($Description) { $body['description'] = $Description }
        if ($Title) { $body['title'] = $Title }
        if ($ExpirationDateTime) { 
            $body['expirationDateTime'] = $ExpirationDateTime.ToUniversalTime().ToString('o')
        }

        if ($PSCmdlet.ShouldProcess($IndicatorValue, "Submit threat indicator")) {
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Threat indicator submitted successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to submit threat indicator: $_"
        throw
    }
}
