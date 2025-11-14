function Connect-DefenderXDR {
    <#
    .SYNOPSIS
        Connect to Microsoft Defender XDR using Microsoft Graph API
    .DESCRIPTION
        Authenticates to Microsoft Graph API to access Defender XDR resources.
        Supports multiple authentication methods including access token and interactive authentication.
    .PARAMETER AccessToken
        Pre-obtained access token for Microsoft Graph API
    .PARAMETER TenantId
        Azure AD Tenant ID
    .PARAMETER ClientId
        Azure AD Application (Client) ID
    .PARAMETER ClientSecret
        Azure AD Application Client Secret
    .PARAMETER Scopes
        Required permission scopes (for documentation purposes - used in future authentication methods)
    .EXAMPLE
        Connect-DefenderXDR -AccessToken "eyJ0eXAiOi..."
    .EXAMPLE
        Connect-DefenderXDR -TenantId "contoso.onmicrosoft.com" -ClientId "12345..." -ClientSecret "secret"
    #>
    [CmdletBinding(DefaultParameterSetName = 'AccessToken')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Scopes', Justification = 'Parameter reserved for future interactive authentication implementation')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]$ClientSecret,

        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @(
            'SecurityEvents.Read.All',
            'SecurityEvents.ReadWrite.All',
            'SecurityActions.Read.All',
            'SecurityActions.ReadWrite.All',
            'ThreatIndicators.ReadWrite.OwnedBy'
        )
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'AccessToken' {
                Write-Verbose "Connecting with provided access token"
                $script:AccessToken = $AccessToken
                
                # Decode token to get expiration (basic validation)
                try {
                    $tokenParts = $AccessToken.Split('.')
                    if ($tokenParts.Count -eq 3) {
                        $payload = $tokenParts[1]
                        # Add padding if needed
                        while ($payload.Length % 4 -ne 0) { $payload += '=' }
                        $payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
                        $tokenData = $payloadJson | ConvertFrom-Json
                        
                        if ($tokenData.exp) {
                            $script:TokenExpiration = [DateTimeOffset]::FromUnixTimeSeconds($tokenData.exp).LocalDateTime
                            Write-Verbose "Token expires at: $($script:TokenExpiration)"
                        }
                        
                        if ($tokenData.tid) {
                            $script:TenantId = $tokenData.tid
                        }
                    }
                }
                catch {
                    Write-Warning "Could not decode token information: $_"
                }
            }

            'ClientSecret' {
                Write-Verbose "Connecting with Client ID and Secret for tenant: $TenantId"
                
                # Get token using client credentials
                $body = @{
                    client_id     = $ClientId
                    client_secret = $ClientSecret
                    scope         = 'https://graph.microsoft.com/.default'
                    grant_type    = 'client_credentials'
                }

                $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                
                $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
                
                $script:AccessToken = $response.access_token
                $script:TenantId = $TenantId
                
                if ($response.expires_in) {
                    $script:TokenExpiration = (Get-Date).AddSeconds($response.expires_in)
                    Write-Verbose "Token expires at: $($script:TokenExpiration)"
                }
            }

            'Interactive' {
                Write-Warning "Interactive authentication requires MSAL.PS module or similar. Please use AccessToken or ClientSecret parameter sets."
                throw "Interactive authentication not yet implemented. Use -AccessToken or -ClientSecret parameters."
            }
        }

        # Test the connection
        $testUri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/alerts?`$top=1"
        $headers = @{
            'Authorization' = "Bearer $script:AccessToken"
        }
        
        try {
            $null = Invoke-RestMethod -Uri $testUri -Headers $headers -Method Get
            Write-Information "Successfully connected to Microsoft Defender XDR" -InformationAction Continue
            return $true
        }
        catch {
            Write-Error "Connection test failed. Please verify your permissions and token."
            $script:AccessToken = $null
            $script:TokenExpiration = $null
            throw
            return
        }
    }
    catch {
        Write-Error "Failed to connect to Defender XDR: $_"
        throw
    }
}
