#Requires -Version 5.1

<#
.SYNOPSIS
    Microsoft Defender XDR API Client
.DESCRIPTION
    Manages authentication and provides methods for interacting with Defender XDR APIs
#>
class DefenderXDRClient {
    [string]$TenantId
    [string]$ClientId
    [string]$ApiAudience
    [string]$GraphBaseUri
    [datetime]$TokenExpiration
    [bool]$IsConnected

    hidden [string]$AccessToken

    DefenderXDRClient() {
        $this.GraphBaseUri = 'https://graph.microsoft.com'
        $this.ApiAudience = 'Graph'
        $this.IsConnected = $false
    }

    DefenderXDRClient([string]$tenantId, [string]$clientId) {
        $this.TenantId = $tenantId
        $this.ClientId = $clientId
        $this.GraphBaseUri = 'https://graph.microsoft.com'
        $this.ApiAudience = 'Graph'
        $this.IsConnected = $false
    }

    [bool] Connect([string]$clientSecret) {
        try {
            # This would implement the actual authentication logic
            # For now, it's a placeholder
            $this.AccessToken = "mock_token"
            $this.TokenExpiration = [datetime]::UtcNow.AddHours(1)
            $this.IsConnected = $true
            return $true
        }
        catch {
            $this.IsConnected = $false
            return $false
        }
    }

    [bool] IsTokenValid() {
        return $this.IsConnected -and $this.TokenExpiration -gt [datetime]::UtcNow
    }

    [void] Disconnect() {
        $this.AccessToken = $null
        $this.TokenExpiration = [datetime]::MinValue
        $this.IsConnected = $false
    }

    [object] InvokeApiRequest([string]$uri, [string]$method = 'GET', [hashtable]$body = $null) {
        if (-not $this.IsTokenValid()) {
            throw "Not connected or token expired. Please connect first."
        }

        # This would implement the actual API call
        # For now, return a mock response
        return @{ status = 'success' }
    }

    [DefenderAlert[]] GetAlerts([string]$filter = $null, [int]$top = 100) {
        $uri = "$($this.GraphBaseUri)/beta/security/alerts"
        if ($filter) {
            $uri += "?`$filter=$filter&`$top=$top"
        }
        else {
            $uri += "?`$top=$top"
        }

        $response = $this.InvokeApiRequest($uri)
        # Convert response to DefenderAlert objects
        return $response.value | ForEach-Object {
            $alert = [DefenderAlert]::new($_.id)
            $alert.Status = $_.status
            $alert.Severity = $_.severity
            $alert.Category = $_.category
            $alert.CreatedDateTime = [datetime]::Parse($_.createdDateTime)
            $alert.DisplayName = $_.title
            $alert.Description = $_.description
            $alert
        }
    }

    [DefenderIncident[]] GetIncidents([string]$filter = $null, [int]$top = 100) {
        $uri = "$($this.GraphBaseUri)/beta/security/incidents"
        if ($filter) {
            $uri += "?`$filter=$filter&`$top=$top"
        }
        else {
            $uri += "?`$top=$top"
        }

        $response = $this.InvokeApiRequest($uri)
        # Convert response to DefenderIncident objects
        return $response.value | ForEach-Object {
            $incident = [DefenderIncident]::new($_.id)
            $incident.Status = $_.status
            $incident.Severity = $_.severity
            $incident.CreatedDateTime = [datetime]::Parse($_.createdDateTime)
            $incident.DisplayName = $_.displayName
            $incident.Description = $_.description
            $incident.AssignedTo = $_.assignedTo
            $incident
        }
    }

    [DefenderQueryResult] RunHuntingQuery([string]$query) {
        $uri = "$($this.GraphBaseUri)/beta/security/runHuntingQuery"
        $body = @{ Query = $query }

        $response = $this.InvokeApiRequest($uri, 'POST', $body)
        $result = [DefenderQueryResult]::new($response.Results)
        $result.Schema = $response.Schema
        $result.Stats = $response.Stats
        return $result
    }
}

<#
.SYNOPSIS
    Configuration validator for Defender XDR operations
.DESCRIPTION
    Validates input parameters and configurations for Defender operations
#>
class DefenderValidator {
    static [void] ValidateAlertStatus([string]$status) {
        $validStatuses = @('new', 'inProgress', 'resolved')
        if ($status -notin $validStatuses) {
            throw "Invalid alert status '$status'. Must be one of: $($validStatuses -join ', ')"
        }
    }

    static [void] ValidateIncidentStatus([string]$status) {
        $validStatuses = @('active', 'resolved', 'redirected')
        if ($status -notin $validStatuses) {
            throw "Invalid incident status '$status'. Must be one of: $($validStatuses -join ', ')"
        }
    }

    static [void] ValidateIndicatorType([string]$indicatorType) {
        $validTypes = @('DomainName', 'IpAddress', 'Url', 'FileSha256', 'FileSha1', 'FileMd5', 'CertificateThumbprint', 'EmailSubject', 'EmailSender')
        if ($indicatorType -notin $validTypes) {
            throw "Invalid indicator type '$indicatorType'. Must be one of: $($validTypes -join ', ')"
        }
    }

    static [void] ValidateSeverity([string]$severity) {
        $validSeverities = @('Informational', 'Low', 'Medium', 'High')
        if ($severity -notin $validSeverities) {
            throw "Invalid severity '$severity'. Must be one of: $($validSeverities -join ', ')"
        }
    }

    static [void] ValidateEmail([string]$email) {
        $emailRegex = '^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$'
        if ($email -notmatch $emailRegex) {
            throw "Invalid email format: $email"
        }
    }

    static [void] ValidateUrl([string]$url) {
        try {
            $null = [System.Uri]::new($url)
        }
        catch {
            throw "Invalid URL format: $url"
        }
    }

    static [void] ValidateIpAddress([string]$ipAddress) {
        $ipRegex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if ($ipAddress -notmatch $ipRegex) {
            throw "Invalid IP address format: $ipAddress"
        }
    }
}