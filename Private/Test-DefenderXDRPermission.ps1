function Test-DefenderXDRPermission {
    <#
    .SYNOPSIS
        Validates that the access token contains required permissions
    .DESCRIPTION
        Decodes the JWT access token and checks if it contains the required permissions (roles).
        Supports both Application permissions and Delegated permissions.
    .PARAMETER RequiredPermissions
        Array of required permission strings (e.g., 'Ti.Read.All', 'SecurityEvents.Read.All')
        If multiple permissions are provided, any one of them is sufficient (OR logic)
    .PARAMETER FunctionName
        Name of the function requesting permission validation (for error messages)
    .EXAMPLE
        Test-DefenderXDRPermission -RequiredPermissions @('Ti.Read.All', 'Ti.ReadWrite') -FunctionName 'Get-DefenderXDRIndicator'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredPermissions,

        [Parameter(Mandatory = $true)]
        [string]$FunctionName
    )

    # Reset permission state for each validation
    $script:hasPermission = $false

    # Check if we have an access token
    if (-not $script:AccessToken) {
        if (-not $script:ConnectionReminderDisplayed) {
            Write-Warning "You're not connected to Defender XDR yet. Run Connect-DefenderXDR (for example: Connect-DefenderXDR -TenantId <tenantId> -ClientId <clientId> -ClientSecret <secret>) and try again."
            $script:ConnectionReminderDisplayed = $true
        }
        return
    }

    try {
        # Decode JWT token to get claims
        $tokenParts = $script:AccessToken.Split('.')
        if ($tokenParts.Count -ne 3) {
            Write-Warning "Unable to decode access token for permission validation"
            return $true  # Allow the request to proceed if we can't validate
        }

        $payload = $tokenParts[1]
        # Add padding if needed for Base64 decoding
        while ($payload.Length % 4 -ne 0) {
            $payload += '='
        }

        $payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        $tokenData = $payloadJson | ConvertFrom-Json

        # Get permissions from token
        # Application permissions are in 'roles' claim
        # Delegated permissions are in 'scp' claim (space-separated)
        $tokenPermissions = @()

        if ($tokenData.roles) {
            $tokenPermissions += $tokenData.roles
        }

        if ($tokenData.scp) {
            $tokenPermissions += $tokenData.scp -split ' '
        }

        if ($tokenPermissions.Count -eq 0) {
            Write-Warning "No permissions found in access token for $FunctionName. The token may not have the required scopes."
            Write-Warning "Required permissions: $($RequiredPermissions -join ', ')"
            return $true  # Allow the request to proceed, API will reject if permissions are insufficient
        }

        # Check if any of the required permissions exist in the token
        # Support wildcard matching: a token permission ending in .All can satisfy a requirement without .All
        # For example: Ti.ReadWrite.All satisfies Ti.ReadWrite
        $hasPermission = $false

        foreach ($required in $RequiredPermissions) {
            # Check for exact match first
            if ($tokenPermissions -contains $required) {
                Write-Verbose "Permission validated (exact match): $required"
                $hasPermission = $true
                break
            }

            # Check if token has a more permissive version (with .All suffix)
            # For example, if required is "Ti.ReadWrite", check if token has "Ti.ReadWrite.All"
            if (-not $required.EndsWith('.All')) {
                $permissiveVersion = "$required.All"
                if ($tokenPermissions -contains $permissiveVersion) {
                    Write-Verbose "Permission validated (permissive match): $permissiveVersion satisfies $required"
                    $hasPermission = $true
                    break
                }
            }
        }

        if ($hasPermission) {
            $script:hasPermission = $true
            Write-Verbose "Permission check passed for $FunctionName"
            return
        }

        $errorMessage = "Insufficient permissions for $FunctionName.`n"
        $errorMessage += "Required: One of the following permissions is needed: $($RequiredPermissions -join ' or ').`n"
        $errorMessage += "Token has: $($tokenPermissions -join ', ')"
        throw [System.UnauthorizedAccessException]::new($errorMessage)
    }
    catch {
        # If this is a permission error we threw, re-throw it to stop execution
        if ($_.Exception -is [System.UnauthorizedAccessException]) {
            throw
        }
        # Otherwise, it's an error in the validation process itself, allow the request to proceed
        Write-Warning "Unable to validate permissions for $FunctionName`: $_"
        return  # Allow the request to proceed if we can't validate
    }
}
