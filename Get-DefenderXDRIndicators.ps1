function Get-DefenderXDRIndicators {
    <#
    .SYNOPSIS
        Retrieves threat intelligence indicators from Microsoft Defender XDR.
    
    .DESCRIPTION
        This function retrieves threat intelligence indicators from the Microsoft Defender for Endpoint API.
        It supports authentication using Azure AD app credentials and can filter indicators.
    
    .PARAMETER TenantId
        The Azure AD tenant ID.
    
    .PARAMETER AppId
        The Azure AD application (client) ID.
    
    .PARAMETER AppSecret
        The Azure AD application secret (SecureString).
    
    .PARAMETER IndicatorId
        Optional. The specific indicator ID to retrieve.
    
    .EXAMPLE
        $secret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
        Get-DefenderXDRIndicators -TenantId "contoso.onmicrosoft.com" -AppId "12345678-1234-1234-1234-123456789012" -AppSecret $secret
    
    .EXAMPLE
        $secret = ConvertTo-SecureString "your-app-secret" -AsPlainText -Force
        Get-DefenderXDRIndicators -TenantId "contoso.onmicrosoft.com" -AppId "12345678-1234-1234-1234-123456789012" -AppSecret $secret -IndicatorId "12345"
    
    .NOTES
        Requires an Azure AD application with appropriate permissions for Microsoft Defender for Endpoint API.
        Required API Permission: Ti.ReadWrite or Ti.ReadWrite.All
        
        Based on Microsoft Defender Endpoint API documentation:
        https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$AppId,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$AppSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$IndicatorId
    )
    
    begin {
        # Convert SecureString to plain text for API call
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppSecret)
        $appSecretPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        # Authentication endpoint
        $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        # API endpoint
        $apiBaseUrl = "https://api.securitycenter.microsoft.com/api"
        
        Write-Verbose "Authenticating to Azure AD..."
        
        # Get access token
        $authBody = @{
            client_id     = $AppId
            scope         = "https://api.securitycenter.microsoft.com/.default"
            client_secret = $appSecretPlainText
            grant_type    = "client_credentials"
        }
        
        try {
            $authResponse = Invoke-RestMethod -Method Post -Uri $authUrl -Body $authBody -ContentType "application/x-www-form-urlencoded"
            $token = $authResponse.access_token
            
            if (-not $token) {
                throw "Failed to retrieve access token"
            }
            
            Write-Verbose "Authentication successful"
        }
        catch {
            Write-Error "Authentication failed: $_"
            return
        }
        finally {
            # Clear sensitive data
            $appSecretPlainText = $null
        }
    }
    
    process {
        try {
            # Set up headers
            $headers = @{
                "Authorization" = "Bearer $token"
                "Content-Type"  = "application/json"
            }
            
            # Build API URL
            if ($IndicatorId) {
                $apiUrl = "$apiBaseUrl/indicators/$IndicatorId"
                Write-Verbose "Retrieving indicator with ID: $IndicatorId"
            }
            else {
                $apiUrl = "$apiBaseUrl/indicators"
                Write-Verbose "Retrieving all indicators"
            }
            
            # Make API call
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl -Headers $headers
            
            # Return results
            if ($IndicatorId) {
                return $response
            }
            else {
                return $response.value
            }
        }
        catch {
            Write-Error "Failed to retrieve indicators: $_"
            if ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $responseBody = $reader.ReadToEnd()
                Write-Error "API Response: $responseBody"
            }
        }
    }
}
