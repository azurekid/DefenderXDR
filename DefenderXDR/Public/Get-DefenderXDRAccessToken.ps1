function Get-DefenderXDRAccessToken {
    <#
    .SYNOPSIS
        Get the current access token information
    .DESCRIPTION
        Returns information about the current access token including expiration time
    .EXAMPLE
        Get-DefenderXDRAccessToken
    #>
    [CmdletBinding()]
    param ()

    if (-not $script:AccessToken) {
        Write-Warning "Not connected. Please run Connect-DefenderXDR first."
        return $null
    }

    $tokenInfo = [PSCustomObject]@{
        HasToken       = ($null -ne $script:AccessToken)
        TokenExpires   = $script:TokenExpiration
        IsExpired      = if ($script:TokenExpiration) { (Get-Date) -ge $script:TokenExpiration } else { $null }
        TenantId       = $script:TenantId
        MinutesRemaining = if ($script:TokenExpiration) { 
            [math]::Round((($script:TokenExpiration) - (Get-Date)).TotalMinutes, 2) 
        } else { 
            $null 
        }
    }

    return $tokenInfo
}
