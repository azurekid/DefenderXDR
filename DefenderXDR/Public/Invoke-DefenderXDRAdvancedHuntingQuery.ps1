function Invoke-DefenderXDRAdvancedHuntingQuery {
    <#
    .SYNOPSIS
        Execute an advanced hunting query in Microsoft Defender XDR
    .DESCRIPTION
        Runs a Kusto Query Language (KQL) query against Microsoft Defender XDR advanced hunting
    .PARAMETER Query
        The KQL query to execute
    .PARAMETER Timespan
        Time range for the query (ISO 8601 duration format, e.g., "P7D" for 7 days)
    .EXAMPLE
        Invoke-DefenderXDRAdvancedHuntingQuery -Query "DeviceProcessEvents | where FileName == 'powershell.exe' | limit 10"
    .EXAMPLE
        $query = @"
        DeviceNetworkEvents
        | where RemoteUrl contains "malicious"
        | summarize Count=count() by DeviceName
        "@
        Invoke-DefenderXDRAdvancedHuntingQuery -Query $query
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $false)]
        [string]$Timespan
    )

    try {
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/runHuntingQuery"
        
        $body = @{
            Query = $Query
        }

        if ($Timespan) {
            $body['Timespan'] = $Timespan
        }

        Write-Verbose "Executing advanced hunting query"
        $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
        
        # Parse and return results
        if ($response.results) {
            return $response.results
        }
        elseif ($response.Results) {
            return $response.Results
        }
        else {
            return $response
        }
    }
    catch {
        Write-Error "Failed to execute advanced hunting query: $_"
        throw
    }
}
