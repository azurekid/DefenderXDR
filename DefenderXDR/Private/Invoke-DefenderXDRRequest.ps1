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
        throw "Not authenticated. Please run Connect-DefenderXDR first."
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
            $params['Body'] = $Body
        }
        else {
            $params['Body'] = $Body | ConvertTo-Json -Depth 10
        }
    }

    try {
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
