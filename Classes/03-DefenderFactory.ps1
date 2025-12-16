#Requires -Version 5.1

<#
.SYNOPSIS
    Example functions demonstrating class usage in Defender XDR module
.DESCRIPTION
    Shows how to use the Defender classes for enhanced functionality
#>

function New-DefenderAlert {
    <#
    .SYNOPSIS
        Creates a new DefenderAlert object
    .DESCRIPTION
        Factory function for creating DefenderAlert instances with validation
    .PARAMETER AlertId
        The alert ID
    .PARAMETER Title
        Alert title
    .PARAMETER Severity
        Alert severity
    .EXAMPLE
        $alert = New-DefenderAlert -AlertId "da123..." -Title "Suspicious Activity" -Severity "High"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AlertId,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Severity
    )

    [DefenderValidator]::ValidateSeverity($Severity)

    $alert = [DefenderAlert]::new($AlertId)
    $alert.DisplayName = $Title
    $alert.Severity = $Severity
    $alert.CreatedDateTime = [datetime]::UtcNow
    $alert.Status = 'new'

    return $alert
}

function New-DefenderIncident {
    <#
    .SYNOPSIS
        Creates a new DefenderIncident object
    .DESCRIPTION
        Factory function for creating DefenderIncident instances with validation
    .PARAMETER IncidentId
        The incident ID
    .PARAMETER Title
        Incident title
    .PARAMETER Severity
        Incident severity
    .EXAMPLE
        $incident = New-DefenderIncident -IncidentId "ic123..." -Title "Security Breach" -Severity "High"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Severity
    )

    [DefenderValidator]::ValidateSeverity($Severity)

    $incident = [DefenderIncident]::new($IncidentId)
    $incident.DisplayName = $Title
    $incident.Severity = $Severity
    $incident.CreatedDateTime = [datetime]::UtcNow
    $incident.Status = 'active'

    return $incident
}

function New-DefenderIndicator {
    <#
    .SYNOPSIS
        Creates a new DefenderIndicator object
    .DESCRIPTION
        Factory function for creating DefenderIndicator instances with validation
    .PARAMETER IndicatorValue
        The indicator value (IP, domain, hash, etc.)
    .PARAMETER IndicatorType
        Type of indicator
    .PARAMETER Action
        Action to take (Block, Alert, Allow)
    .PARAMETER Title
        Indicator title
    .PARAMETER Description
        Indicator description
    .EXAMPLE
        $indicator = New-DefenderIndicator -IndicatorValue "192.168.1.100" -IndicatorType "IpAddress" -Action "Block" -Title "Malicious IP"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IndicatorValue,

        [Parameter(Mandatory = $true)]
        [string]$IndicatorType,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$Severity = 'Medium'
    )

    [DefenderValidator]::ValidateIndicatorType($IndicatorType)
    [DefenderValidator]::ValidateSeverity($Severity)

    $indicator = [DefenderIndicator]::new($IndicatorValue, $IndicatorType)
    $indicator.Action = $Action
    $indicator.Title = $Title
    $indicator.Description = $Description
    $indicator.Severity = $Severity
    $indicator.CreatedDateTime = [datetime]::UtcNow

    return $indicator
}

function ConvertTo-DefenderAlert {
    <#
    .SYNOPSIS
        Converts a hashtable or API response to a DefenderAlert object
    .DESCRIPTION
        Helper function to convert API responses to typed objects
    .PARAMETER InputObject
        The hashtable or object to convert
    .EXAMPLE
        $apiResponse | ConvertTo-DefenderAlert
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject
    )

    process {
        $alert = [DefenderAlert]::new($InputObject.id)
        $alert.AlertId = $InputObject.id
        $alert.DisplayName = $InputObject.title
        $alert.Description = $InputObject.description
        $alert.Status = $InputObject.status
        $alert.Severity = $InputObject.severity
        $alert.Classification = $InputObject.classification
        $alert.Determination = $InputObject.determination
        $alert.Category = $InputObject.category
        $alert.ServiceSource = $InputObject.serviceSource
        $alert.CreatedDateTime = [datetime]::Parse($InputObject.createdDateTime)
        $alert.LastUpdateDateTime = [datetime]::Parse($InputObject.lastUpdateDateTime)

        $alert
    }
}

function ConvertTo-DefenderIncident {
    <#
    .SYNOPSIS
        Converts a hashtable or API response to a DefenderIncident object
    .DESCRIPTION
        Helper function to convert API responses to typed objects
    .PARAMETER InputObject
        The hashtable or object to convert
    .EXAMPLE
        $apiResponse | ConvertTo-DefenderIncident
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject
    )

    process {
        $incident = [DefenderIncident]::new($InputObject.id)
        $incident.IncidentId = $InputObject.id
        $incident.DisplayName = $InputObject.displayName
        $incident.Description = $InputObject.description
        $incident.Status = $InputObject.status
        $incident.Severity = $InputObject.severity
        $incident.Classification = $InputObject.classification
        $incident.Determination = $InputObject.determination
        $incident.AssignedTo = $InputObject.assignedTo
        $incident.CreatedDateTime = [datetime]::Parse($InputObject.createdDateTime)
        $incident.LastUpdateDateTime = [datetime]::Parse($InputObject.lastUpdateDateTime)

        $incident
    }
}