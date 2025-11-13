function Disconnect-DefenderXDR {
    <#
    .SYNOPSIS
        Disconnect from Microsoft Defender XDR
    .DESCRIPTION
        Clears the stored access token and authentication information
    .EXAMPLE
        Disconnect-DefenderXDR
    #>
    [CmdletBinding()]
    param ()

    $script:AccessToken = $null
    $script:TokenExpiration = $null
    $script:TenantId = $null

    Write-Verbose "Disconnected from Microsoft Defender XDR"
    Write-Host "Successfully disconnected from Microsoft Defender XDR" -ForegroundColor Green
}
