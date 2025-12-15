function Get-DefenderXDRCustomDetection {
    <#
    .SYNOPSIS
        Retrieve custom detection rules from Microsoft Defender XDR
    .DESCRIPTION
        Gets custom detections from Defender XDR using Defender Security APIs. Supports fetching all rules or a specific rule by ID.
        NOTE: Custom detection endpoints are Defender-specific; Microsoft Graph Security currently does not expose these objects.
    .PARAMETER Id
        Optional specific custom detection rule identifier to retrieve.
    .PARAMETER Top
        Number of items to return (server may cap). Default 50.
    .PARAMETER Filter
        Optional OData $filter string to narrow results (best-effort support).
    .PARAMETER All
        Retrieve all pages if the API returns a nextLink. May result in multiple requests.
    .EXAMPLE
        Get-DefenderXDRCustomDetection
        Lists custom detections (first page).
    .EXAMPLE
        Get-DefenderXDRCustomDetection -All
        Lists all custom detections by following pagination.
    .EXAMPLE
        Get-DefenderXDRCustomDetection -Id "12345abcd"
        Retrieves a specific custom detection by ID.
    .EXAMPLE
        Get-DefenderXDRCustomDetection -Top 100 -Filter "contains(displayName,'PowerShell')"
        Retrieves up to 100 detections filtered by display name.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$Top = 50,

        [Parameter(Mandatory = $false)]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [switch]$All,

        [Parameter(Mandatory = $false)]
        [string]$EndpointUri
    )

    begin {
        # Validate permissions: reading custom detections requires CustomDetection.ReadWrite.All
        Test-DefenderXDRPermission -RequiredPermissions @('CustomDetection.ReadWrite.All') -FunctionName $MyInvocation.MyCommand.Name
    }

    process {
        try {
            $graphCandidates = @(
                'https://graph.microsoft.com/beta/security/rules/detectionRules'
            )

            $baseCandidates = if ($EndpointUri) { @($EndpointUri) } else { $graphCandidates }

            $query = @{}
            if (-not $Id) {
                if ($Top) { $query['$top'] = [string]$Top }
                if ($Filter) { $query['$filter'] = $Filter }
            }

            foreach ($base in $baseCandidates) {
                $uri = if ($Id) { "$base/$Id" } else {
                    if ($query.Count -gt 0) {
                        $qs = ($query.GetEnumerator() | ForEach-Object { ("{0}={1}" -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value)) }) -join '&'
                        ('{0}?{1}' -f $base, $qs)
                    }
                    else { $base }
                }

                if ($null -ne $uri) { $uri = $uri.Trim() }
                $isValid = [System.Uri]::IsWellFormedUriString($uri, [System.UriKind]::Absolute)
                if (-not $isValid) {
                    Write-Verbose "Skipping invalid URI candidate: $uri"
                    continue
                }

                Write-Verbose "Querying custom detections via $uri"
                try {
                    $results = @()
                    $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET

                    if ($Id) {
                        return $response
                    }

                    if ($response.value) {
                        $results += $response.value
                        $next = $response.'@odata.nextLink' ?? $response.nextLink
                        if ($All) {
                            while ($next) {
                                Write-Verbose "Fetching next page: $next"
                                $page = Invoke-DefenderXDRRequest -Uri $next -Method GET
                                if ($page.value) { $results += $page.value }
                                $next = $page.'@odata.nextLink' ?? $page.nextLink
                            }
                        }
                        return $results
                    }
                    else {
                        # Some endpoints may return an array directly
                        if ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
                            return $response
                        }
                        return ,$response
                    }
                }
                catch {
                    $msg = $_.Exception.Message
                    if ($msg -match 'Tenant feature is not enabled') {
                        throw "Custom Detections API is disabled for this tenant. Enable the feature in Microsoft 365 Defender or request enablement from Microsoft, then retry."
                    }
                    Write-Verbose "Endpoint failed: $base - $msg"
                    continue
                }
            }

            throw "Failed to retrieve custom detections using known endpoints. Verify API permissions and availability."
        }
        catch {
            Write-Error "Failed to get custom detections: $_"
            throw
        }
    }
}
