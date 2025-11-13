#Requires -Version 5.1

<#
.SYNOPSIS
    PowerShell module for Microsoft Defender XDR Threat Intelligence Indicator API
.DESCRIPTION
    This module provides cmdlets to manage Threat Intelligence Indicators in Microsoft Defender XDR
.NOTES
    Requires appropriate permissions in Microsoft Defender XDR
#>

# Module variables
$Script:DefenderXDRConnection = $null
$Script:DefenderXDRBaseUri = "https://api.securitycenter.microsoft.com/api"

#region Authentication Functions

<#
.SYNOPSIS
    Connect to Microsoft Defender XDR API
.DESCRIPTION
    Establishes a connection to the Microsoft Defender XDR API using application credentials
.PARAMETER TenantId
    The Azure AD Tenant ID
.PARAMETER AppId
    The Application (Client) ID
.PARAMETER AppSecret
    The Application Secret
.PARAMETER AccessToken
    Pre-obtained access token (alternative to AppId/AppSecret)
.EXAMPLE
    Connect-DefenderXDR -TenantId "contoso.onmicrosoft.com" -AppId "12345678-1234-1234-1234-123456789012" -AppSecret $secret
.EXAMPLE
    Connect-DefenderXDR -AccessToken $token
#>
function Connect-DefenderXDR {
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [string]$AppId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [SecureString]$AppSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Token')]
        [string]$AccessToken
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Credential') {
            # Get OAuth token
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $scope = "https://api.securitycenter.microsoft.com/.default"
            
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppSecret)
            $PlainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

            $body = @{
                client_id     = $AppId
                scope         = $scope
                client_secret = $PlainSecret
                grant_type    = "client_credentials"
            }

            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded"
            $AccessToken = $response.access_token
        }

        # Store connection information
        $Script:DefenderXDRConnection = @{
            AccessToken = $AccessToken
            ConnectedAt = Get-Date
        }

        Write-Verbose "Successfully connected to Microsoft Defender XDR API"
        return $true
    }
    catch {
        Write-Error "Failed to connect to Defender XDR: $_"
        return $false
    }
}

<#
.SYNOPSIS
    Disconnect from Microsoft Defender XDR API
.DESCRIPTION
    Clears the stored connection to the Microsoft Defender XDR API
.EXAMPLE
    Disconnect-DefenderXDR
#>
function Disconnect-DefenderXDR {
    [CmdletBinding()]
    param()

    $Script:DefenderXDRConnection = $null
    Write-Verbose "Disconnected from Microsoft Defender XDR API"
}

#endregion

#region Helper Functions

function Test-DefenderXDRConnection {
    if ($null -eq $Script:DefenderXDRConnection) {
        throw "Not connected to Defender XDR. Please run Connect-DefenderXDR first."
    }
    return $true
}

function Invoke-DefenderXDRRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [object]$Body
    )

    Test-DefenderXDRConnection | Out-Null

    $headers = @{
        'Authorization' = "Bearer $($Script:DefenderXDRConnection.AccessToken)"
        'Content-Type'  = 'application/json'
    }

    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $headers
    }

    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.ErrorDetails.Message) {
            $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
            $errorMessage = "$errorMessage - $($errorDetails.error.message)"
        }
        throw "API request failed: $errorMessage"
    }
}

#endregion

#region TI Indicator Functions

<#
.SYNOPSIS
    Get Threat Intelligence Indicators from Microsoft Defender XDR
.DESCRIPTION
    Retrieves one or more Threat Intelligence Indicators from Microsoft Defender XDR
.PARAMETER Id
    The ID of a specific indicator to retrieve
.PARAMETER IndicatorValue
    Filter by indicator value (IP, URL, Domain, etc.)
.PARAMETER IndicatorType
    Filter by indicator type
.EXAMPLE
    Get-DefenderXDRTIIndicator
.EXAMPLE
    Get-DefenderXDRTIIndicator -Id "12345"
.EXAMPLE
    Get-DefenderXDRTIIndicator -IndicatorValue "malicious.com"
#>
function Get-DefenderXDRTIIndicator {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById', ValueFromPipeline = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [ValidateSet('FileSha1', 'FileSha256', 'IpAddress', 'DomainName', 'Url', 'FileMd5')]
        [string]$IndicatorType
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $uri = "$Script:DefenderXDRBaseUri/indicators/$Id"
            $result = Invoke-DefenderXDRRequest -Uri $uri -Method Get
            return $result
        }
        else {
            $uri = "$Script:DefenderXDRBaseUri/indicators"
            
            # Build filter query
            $filterParts = @()
            if ($IndicatorValue) {
                $filterParts += "indicatorValue eq '$IndicatorValue'"
            }
            if ($IndicatorType) {
                $filterParts += "indicatorType eq '$IndicatorType'"
            }
            
            if ($filterParts.Count -gt 0) {
                $filter = $filterParts -join ' and '
                $uri += "?`$filter=$filter"
            }

            $result = Invoke-DefenderXDRRequest -Uri $uri -Method Get
            return $result.value
        }
    }
}

<#
.SYNOPSIS
    Create a new Threat Intelligence Indicator in Microsoft Defender XDR
.DESCRIPTION
    Submits a new Threat Intelligence Indicator to Microsoft Defender XDR
.PARAMETER IndicatorValue
    The value of the indicator (IP address, domain, URL, or file hash)
.PARAMETER IndicatorType
    The type of indicator
.PARAMETER Action
    The action to take when the indicator is detected
.PARAMETER Title
    Title for the indicator
.PARAMETER Description
    Description of the indicator
.PARAMETER Severity
    Severity level of the indicator
.PARAMETER RecommendedActions
    Recommended actions for the indicator
.PARAMETER ExpirationTime
    When the indicator should expire
.PARAMETER RbacGroupNames
    RBAC group names that can see this indicator
.EXAMPLE
    New-DefenderXDRTIIndicator -IndicatorValue "malicious.com" -IndicatorType DomainName -Action Block -Title "Malicious Domain" -Severity High
.EXAMPLE
    New-DefenderXDRTIIndicator -IndicatorValue "1.2.3.4" -IndicatorType IpAddress -Action Alert -Title "Suspicious IP" -Description "Known C2 server" -Severity Medium
#>
function New-DefenderXDRTIIndicator {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet('FileSha1', 'FileSha256', 'IpAddress', 'DomainName', 'Url', 'FileMd5')]
        [string]$IndicatorType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Alert', 'AlertAndBlock', 'Block', 'Allowed')]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity = 'Informational',

        [Parameter(Mandatory = $false)]
        [string]$RecommendedActions,

        [Parameter(Mandatory = $false)]
        [datetime]$ExpirationTime,

        [Parameter(Mandatory = $false)]
        [string[]]$RbacGroupNames
    )

    $body = @{
        indicatorValue = $IndicatorValue
        indicatorType  = $IndicatorType
        action         = $Action
        title          = $Title
        severity       = $Severity
    }

    if ($Description) { $body['description'] = $Description }
    if ($RecommendedActions) { $body['recommendedActions'] = $RecommendedActions }
    if ($ExpirationTime) { $body['expirationTime'] = $ExpirationTime.ToString('o') }
    if ($RbacGroupNames) { $body['rbacGroupNames'] = $RbacGroupNames }

    if ($PSCmdlet.ShouldProcess($IndicatorValue, "Create TI Indicator")) {
        $uri = "$Script:DefenderXDRBaseUri/indicators"
        $result = Invoke-DefenderXDRRequest -Uri $uri -Method Post -Body $body
        return $result
    }
}

<#
.SYNOPSIS
    Update a Threat Intelligence Indicator in Microsoft Defender XDR
.DESCRIPTION
    Updates an existing Threat Intelligence Indicator in Microsoft Defender XDR
.PARAMETER Id
    The ID of the indicator to update
.PARAMETER Action
    The action to take when the indicator is detected
.PARAMETER Title
    Title for the indicator
.PARAMETER Description
    Description of the indicator
.PARAMETER Severity
    Severity level of the indicator
.PARAMETER RecommendedActions
    Recommended actions for the indicator
.PARAMETER ExpirationTime
    When the indicator should expire
.EXAMPLE
    Set-DefenderXDRTIIndicator -Id "12345" -Action Block -Severity High
#>
function Set-DefenderXDRTIIndicator {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Alert', 'AlertAndBlock', 'Block', 'Allowed')]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [string]$RecommendedActions,

        [Parameter(Mandatory = $false)]
        [datetime]$ExpirationTime
    )

    process {
        $body = @{}

        if ($Action) { $body['action'] = $Action }
        if ($Title) { $body['title'] = $Title }
        if ($Description) { $body['description'] = $Description }
        if ($Severity) { $body['severity'] = $Severity }
        if ($RecommendedActions) { $body['recommendedActions'] = $RecommendedActions }
        if ($ExpirationTime) { $body['expirationTime'] = $ExpirationTime.ToString('o') }

        if ($body.Count -eq 0) {
            Write-Warning "No properties specified to update"
            return
        }

        if ($PSCmdlet.ShouldProcess($Id, "Update TI Indicator")) {
            $uri = "$Script:DefenderXDRBaseUri/indicators/$Id"
            $result = Invoke-DefenderXDRRequest -Uri $uri -Method Patch -Body $body
            return $result
        }
    }
}

<#
.SYNOPSIS
    Remove a Threat Intelligence Indicator from Microsoft Defender XDR
.DESCRIPTION
    Deletes a Threat Intelligence Indicator from Microsoft Defender XDR
.PARAMETER Id
    The ID of the indicator to delete
.EXAMPLE
    Remove-DefenderXDRTIIndicator -Id "12345"
.EXAMPLE
    Get-DefenderXDRTIIndicator -IndicatorValue "malicious.com" | Remove-DefenderXDRTIIndicator
#>
function Remove-DefenderXDRTIIndicator {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Id
    )

    process {
        if ($PSCmdlet.ShouldProcess($Id, "Delete TI Indicator")) {
            $uri = "$Script:DefenderXDRBaseUri/indicators/$Id"
            $result = Invoke-DefenderXDRRequest -Uri $uri -Method Delete
            return $result
        }
    }
}

<#
.SYNOPSIS
    Import multiple Threat Intelligence Indicators from a file
.DESCRIPTION
    Imports Threat Intelligence Indicators from a CSV file into Microsoft Defender XDR
.PARAMETER Path
    Path to the CSV file containing indicators
.EXAMPLE
    Import-DefenderXDRTIIndicator -Path "C:\indicators.csv"
.NOTES
    CSV file should have columns: IndicatorValue, IndicatorType, Action, Title, Description, Severity
#>
function Import-DefenderXDRTIIndicator {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $indicators = Import-Csv -Path $Path

    foreach ($indicator in $indicators) {
        $params = @{
            IndicatorValue = $indicator.IndicatorValue
            IndicatorType  = $indicator.IndicatorType
            Action         = $indicator.Action
            Title          = $indicator.Title
        }

        if ($indicator.Description) { $params['Description'] = $indicator.Description }
        if ($indicator.Severity) { $params['Severity'] = $indicator.Severity }
        if ($indicator.RecommendedActions) { $params['RecommendedActions'] = $indicator.RecommendedActions }
        if ($indicator.ExpirationTime) { $params['ExpirationTime'] = [datetime]$indicator.ExpirationTime }

        try {
            if ($PSCmdlet.ShouldProcess($indicator.IndicatorValue, "Import TI Indicator")) {
                New-DefenderXDRTIIndicator @params -WhatIf:$false
                Write-Verbose "Imported indicator: $($indicator.IndicatorValue)"
            }
        }
        catch {
            Write-Warning "Failed to import indicator $($indicator.IndicatorValue): $_"
        }
    }
}

<#
.SYNOPSIS
    Export Threat Intelligence Indicators to a file
.DESCRIPTION
    Exports Threat Intelligence Indicators from Microsoft Defender XDR to a CSV file
.PARAMETER Path
    Path where the CSV file should be saved
.EXAMPLE
    Export-DefenderXDRTIIndicator -Path "C:\indicators.csv"
#>
function Export-DefenderXDRTIIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $indicators = Get-DefenderXDRTIIndicator
    $indicators | Export-Csv -Path $Path -NoTypeInformation
    Write-Verbose "Exported $($indicators.Count) indicators to $Path"
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Connect-DefenderXDR',
    'Disconnect-DefenderXDR',
    'Get-DefenderXDRTIIndicator',
    'New-DefenderXDRTIIndicator',
    'Set-DefenderXDRTIIndicator',
    'Remove-DefenderXDRTIIndicator',
    'Import-DefenderXDRTIIndicator',
    'Export-DefenderXDRTIIndicator'
)
