function Invoke-DefenderXDRRequest {
    <#
    .SYNOPSIS
        Internal function to make HTTP requests to Microsoft Defender APIs
    .DESCRIPTION
        Handles HTTP requests to Microsoft Graph API and Defender Endpoint API with error handling and token validation
    .PARAMETER Uri
        The URI endpoint to call
    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE)
    .PARAMETER Body
        Request body (will be converted to JSON)
    .PARAMETER ContentType
        Content type for the request
    .EXAMPLE
        Invoke-DefenderXDRRequest -Uri "https://graph.microsoft.com/v1.0/security/alerts" -Method GET
    .EXAMPLE
        Invoke-DefenderXDRRequest -Uri "https://api.securitycenter.microsoft.com/api/indicators" -Method GET
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE', 'PUT')]
        [string]$Method = 'GET',

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json'
    )

    # Check if we have a valid access token
    if (-not $script:AccessToken) {
        if (-not $script:ConnectionReminderDisplayed) {
            Write-Warning "You're not connected to Defender XDR yet. Run Connect-DefenderXDR (for example: Connect-DefenderXDR -TenantId <tenantId> -ClientId <clientId> -ClientSecret <secret>) and try again."
            $script:ConnectionReminderDisplayed = $true
        }
        return
    }

    # Check if token is expired
    if ($script:TokenExpiration -and (Get-Date) -ge $script:TokenExpiration) {
        throw "Access token has expired. Please run Connect-DefenderXDR again."
    }

    $headers = @{
        'Authorization' = "Bearer $script:AccessToken"
        'Content-Type'  = $ContentType
    }

    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $headers
    }

    if ($Body) {
        if ($Body -is [string]) {
            Write-Verbose "Using string body for request"
            $params['Body'] = $Body
        }
        else {
            Write-Verbose "Converting body object to JSON for request"
            $params['Body'] = $Body | ConvertTo-Json -Depth 10
        }
    }

    try {
        # Warn if token audience likely mismatches target host
        if ($script:ApiAudience) {
            try {
                $parsedUri = [System.Uri]$Uri
                $targetHost = $parsedUri.Host.ToLowerInvariant()
                if ($script:ApiAudience -eq 'Security' -and $targetHost -like '*graph.microsoft.com') {
                    Write-Warning "Token audience is Security but target is Graph ($targetHost). Consider connecting with -Audience Graph."
                }
                elseif ($script:ApiAudience -eq 'Graph' -and ($targetHost -like '*api.security.microsoft.com' -or $targetHost -like '*api.securitycenter.microsoft.com')) {
                    Write-Warning "Token audience is Graph but target is Defender Security API ($targetHost). Consider connecting with -Audience Security."
                }
            }
            catch {
                Write-Verbose "Unable to inspect host for audience warning: $($_.Exception.Message)"
            }
        }

        Write-Verbose "Making $Method request to: $Uri"
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.ErrorDetails.Message) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                $errorMessage = "$errorMessage - $($errorDetails.error.message)"
            }
            catch {
                $errorMessage = "$errorMessage - $($_.ErrorDetails.Message)"
            }
        }
        Write-Error "API request failed: $errorMessage"
        throw
    }
}
