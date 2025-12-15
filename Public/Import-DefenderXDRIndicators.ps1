function Import-DefenderXDRIndicators {
    <#
    .SYNOPSIS
        Import threat indicators in bulk to Microsoft Defender Endpoint
    .DESCRIPTION
        Imports multiple threat intelligence indicators to Microsoft Defender Endpoint API
        Based on: https://learn.microsoft.com/en-us/defender-endpoint/api/import-ti-indicators
    .PARAMETER Indicators
        Array of indicator objects to import. Each indicator should have properties like:
        indicatorValue, indicatorType, action, severity, title, description, etc.
    .PARAMETER IndicatorsJson
        JSON string containing the indicators to import
    .EXAMPLE
        $indicators = @(
            @{
                indicatorValue = "malicious.com"
                indicatorType = "DomainName"
                action = "Block"
                severity = "High"
                title = "Malicious domain"
                description = "Known phishing domain"
            },
            @{
                indicatorValue = "192.0.2.1"
                indicatorType = "IpAddress"
                action = "Alert"
                severity = "Medium"
                title = "Suspicious IP"
            }
        )
        Import-DefenderXDRIndicators -Indicators $indicators
    .EXAMPLE
        $json = Get-Content indicators.json -Raw
        Import-DefenderXDRIndicators -IndicatorsJson $json
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Objects')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Bulk import function that handles multiple indicators')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Objects')]
        [array]$Indicators,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [string]$IndicatorsJson
    )

    try {
        # Validate permissions
        Test-DefenderXDRPermission -RequiredPermissions @('Ti.ReadWrite') -FunctionName $MyInvocation.MyCommand.Name
        
        $baseUri = "https://api.securitycenter.microsoft.com/api"
        $uri = "$baseUri/indicators/import"

        # Prepare the body
        if ($PSCmdlet.ParameterSetName -eq 'Objects') {
            $body = @{
                Indicators = $Indicators
            }
        }
        else {
            # Parse JSON to validate it
            $parsedJson = $IndicatorsJson | ConvertFrom-Json
            $body = @{
                Indicators = $parsedJson
            }
        }

        if ($PSCmdlet.ShouldProcess("$($body.Indicators.Count) indicators", "Import to Defender Endpoint")) {
            Write-Verbose "Importing $($body.Indicators.Count) indicators"
            $response = Invoke-DefenderXDRRequest -Uri $uri -Method POST -Body $body
            Write-Verbose "Import completed successfully"
            return $response
        }
    }
    catch {
        Write-Error "Failed to import threat indicators: $_"
        throw
    }
}
