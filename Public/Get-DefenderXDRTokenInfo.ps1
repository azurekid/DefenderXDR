function Get-DefenderXDRTokenInfo {
    <#
    .SYNOPSIS
        Show current Defender XDR token claims and audience
    .DESCRIPTION
        Decodes the in-memory access token and returns audience, tenant, expiry, roles/scopes, and basic identifiers to help diagnose permission issues.
    .EXAMPLE
        Get-DefenderXDRTokenInfo | Format-List
    #>
    [CmdletBinding()]
    param()

    if (-not $script:AccessToken) {
        throw "Not authenticated. Please run Connect-DefenderXDR first."
    }

    try {
        $parts = $script:AccessToken.Split('.')
        if ($parts.Count -ne 3) { throw 'Token format not recognized' }
        $payload = $parts[1]
        while ($payload.Length % 4 -ne 0) { $payload += '=' }
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        $claims = $json | ConvertFrom-Json

        $exp = $null
        if ($claims.exp) { $exp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$claims.exp).LocalDateTime }

        [pscustomobject]@{
            Audience         = $script:ApiAudience
            AudClaim         = $claims.aud
            TenantId         = $script:TenantId
            AppId            = $claims.appid
            ObjectId         = $claims.oid
            ExpiresAt        = $exp
            Roles            = $claims.roles
            Scopes           = $claims.scp
        }
    }
    catch {
        Write-Error "Failed to decode token: $_"
        throw
    }
}
