#Requires -Version 5.1

<#
.SYNOPSIS
    Base class for Microsoft Defender XDR entities
.DESCRIPTION
    Provides common properties and methods for all Defender entities
#>
class DefenderEntity {
    [string]$Id
    [datetime]$CreatedDateTime
    [datetime]$LastUpdateDateTime
    [string]$DisplayName
    [string]$Description

    DefenderEntity() {}

    DefenderEntity([string]$id) {
        $this.Id = $id
    }

    [void] UpdateLastModified() {
        $this.LastUpdateDateTime = [datetime]::UtcNow
    }

    [hashtable] ToHashtable() {
        return $this | ConvertTo-HashTable -AsHashTable
    }
}

<#
.SYNOPSIS
    Represents a Microsoft Defender Alert
.DESCRIPTION
    Alert entity with methods for status updates and comments
#>
class DefenderAlert : DefenderEntity {
    [string]$AlertId
    [string]$Status
    [string]$Severity
    [string]$Classification
    [string]$Determination
    [string]$Category
    [string]$ServiceSource
    [object[]]$Comments

    DefenderAlert() : base() {}

    DefenderAlert([string]$alertId) : base($alertId) {
        $this.AlertId = $alertId
    }

    [void] UpdateStatus([string]$newStatus) {
        $validStatuses = @('new', 'inProgress', 'resolved')
        if ($newStatus -notin $validStatuses) {
            throw "Invalid status. Must be one of: $($validStatuses -join ', ')"
        }
        $this.Status = $newStatus
        $this.UpdateLastModified()
    }

    [void] AddComment([string]$comment) {
        if (-not $this.Comments) {
            $this.Comments = @()
        }
        $this.Comments += @{
            Comment = $comment
            CreatedDateTime = [datetime]::UtcNow
        }
        $this.UpdateLastModified()
    }

    [void] SetClassification([string]$classification) {
        $validClassifications = @('unknown', 'falsePositive', 'truePositive')
        if ($classification -notin $validClassifications) {
            throw "Invalid classification. Must be one of: $($validClassifications -join ', ')"
        }
        $this.Classification = $classification
        $this.UpdateLastModified()
    }

    [void] SetDetermination([string]$determination) {
        $validDeterminations = @('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 'other')
        if ($determination -notin $validDeterminations) {
            throw "Invalid determination. Must be one of: $($validDeterminations -join ', ')"
        }
        $this.Determination = $determination
        $this.UpdateLastModified()
    }
}

<#
.SYNOPSIS
    Represents a Microsoft Defender Incident
.DESCRIPTION
    Incident entity with methods for status updates and assignment
#>
class DefenderIncident : DefenderEntity {
    [string]$IncidentId
    [string]$Status
    [string]$Severity
    [string]$Classification
    [string]$Determination
    [string]$AssignedTo
    [object[]]$Alerts
    [object[]]$Comments

    DefenderIncident() : base() {}

    DefenderIncident([string]$incidentId) : base($incidentId) {
        $this.IncidentId = $incidentId
    }

    [void] UpdateStatus([string]$newStatus) {
        $validStatuses = @('active', 'resolved', 'redirected')
        if ($newStatus -notin $validStatuses) {
            throw "Invalid status. Must be one of: $($validStatuses -join ', ')"
        }
        $this.Status = $newStatus
        $this.UpdateLastModified()
    }

    [void] AssignTo([string]$userPrincipalName) {
        $this.AssignedTo = $userPrincipalName
        $this.UpdateLastModified()
    }

    [void] AddComment([string]$comment) {
        if (-not $this.Comments) {
            $this.Comments = @()
        }
        $this.Comments += @{
            Comment = $comment
            CreatedDateTime = [datetime]::UtcNow
        }
        $this.UpdateLastModified()
    }

    [void] SetClassification([string]$classification) {
        $validClassifications = @('unknown', 'falsePositive', 'truePositive')
        if ($classification -notin $validClassifications) {
            throw "Invalid classification. Must be one of: $($validClassifications -join ', ')"
        }
        $this.Classification = $classification
        $this.UpdateLastModified()
    }

    [void] SetDetermination([string]$determination) {
        $validDeterminations = @('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 'other')
        if ($determination -notin $validDeterminations) {
            throw "Invalid determination. Must be one of: $($validDeterminations -join ', ')"
        }
        $this.Determination = $determination
        $this.UpdateLastModified()
    }
}

<#
.SYNOPSIS
    Represents a Microsoft Defender Threat Indicator
.DESCRIPTION
    Threat indicator entity with validation and expiration handling
#>
class DefenderIndicator : DefenderEntity {
    [string]$IndicatorValue
    [string]$IndicatorType
    [string]$Action
    [string]$Severity
    [datetime]$ExpirationDateTime
    [string]$Title
    [string]$Description

    DefenderIndicator() : base() {}

    DefenderIndicator([string]$indicatorValue, [string]$indicatorType) : base() {
        $this.IndicatorValue = $indicatorValue
        $this.IndicatorType = $indicatorType
        $this.ValidateIndicator()
    }

    [void] ValidateIndicator() {
        $validTypes = @('DomainName', 'IpAddress', 'Url', 'FileSha256', 'FileSha1', 'FileMd5', 'CertificateThumbprint', 'EmailSubject', 'EmailSender')
        if ($this.IndicatorType -notin $validTypes) {
            throw "Invalid indicator type. Must be one of: $($validTypes -join ', ')"
        }

        $validActions = @('Unknown', 'Allow', 'Block', 'Alert')
        if ($this.Action -and $this.Action -notin $validActions) {
            throw "Invalid action. Must be one of: $($validActions -join ', ')"
        }

        $validSeverities = @('Informational', 'Low', 'Medium', 'High')
        if ($this.Severity -and $this.Severity -notin $validSeverities) {
            throw "Invalid severity. Must be one of: $($validSeverities -join ', ')"
        }
    }

    [bool] IsExpired() {
        return $this.ExpirationDateTime -lt [datetime]::UtcNow
    }

    [void] SetExpiration([datetime]$expiration) {
        if ($expiration -le [datetime]::UtcNow) {
            throw "Expiration date must be in the future"
        }
        $this.ExpirationDateTime = $expiration
        $this.UpdateLastModified()
    }
}

<#
.SYNOPSIS
    Advanced Hunting Query Result
.DESCRIPTION
    Represents the result of an advanced hunting query with additional processing methods
#>
class DefenderQueryResult {
    [object[]]$Results
    [hashtable]$Schema
    [hashtable]$Stats

    DefenderQueryResult() {}

    DefenderQueryResult([object[]]$results) {
        $this.Results = $results
    }

    [int] Count() {
        return $this.Results.Count
    }

    [object[]] Where([scriptblock]$filter) {
        return $this.Results | Where-Object $filter
    }

    [object[]] Select([string[]]$properties) {
        return $this.Results | Select-Object $properties
    }

    [object[]] GroupBy([string]$property) {
        return $this.Results | Group-Object $property
    }

    [void] ExportToCsv([string]$path) {
        $this.Results | Export-Csv -Path $path -NoTypeInformation
    }

    [string] ToJson() {
        return $this.Results | ConvertTo-Json -Depth 10
    }
}