#Requires -Version 5.1

<#
.SYNOPSIS
    DefenderXDR PowerShell Module
.DESCRIPTION
    PowerShell module for managing Microsoft Defender XDR (Extended Detection and Response) 
    configurations through Microsoft Graph API
#>

# Get public and private function definition files
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
$Classes = @(Get-ChildItem -Path $PSScriptRoot\Classes\*.ps1 -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($Classes + $Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions (from Public and Classes directories)
$AllPublic = @($Public + $Classes)
Export-ModuleMember -Function $AllPublic.BaseName

# Also export specific class factory functions
Export-ModuleMember -Function 'New-DefenderAlert', 'New-DefenderIncident', 'New-DefenderIndicator', 'ConvertTo-DefenderAlert', 'ConvertTo-DefenderIncident'

# Export aliases
Export-ModuleMember -Alias 'Submit-DefenderXDRThreatIndicator'

# Module variables
$script:ModuleVersion = '1.0.0'
$script:GraphAPIVersion = 'beta'
$script:GraphAPIBetaVersion = 'beta'
$script:GraphBaseUri = 'https://graph.microsoft.com'
$script:AccessToken = $null
$script:TokenExpiration = $null
$script:TenantId = $null
$script:hasPermission = $false
$script:ConnectionReminderDisplayed = $false

Write-Verbose "DefenderXDR module loaded successfully"
