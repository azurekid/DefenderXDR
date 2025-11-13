@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'DefenderXDR.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d'

    # Author of this module
    Author = 'DefenderXDR Contributors'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) 2024. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell module for managing Microsoft Defender XDR Threat Intelligence Indicators via the API'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-DefenderXDR',
        'Disconnect-DefenderXDR',
        'Get-DefenderXDRTIIndicator',
        'New-DefenderXDRTIIndicator',
        'Set-DefenderXDRTIIndicator',
        'Remove-DefenderXDRTIIndicator',
        'Import-DefenderXDRTIIndicator',
        'Export-DefenderXDRTIIndicator'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module to help discovery
            Tags = @('Defender', 'XDR', 'Security', 'ThreatIntelligence', 'API', 'Microsoft')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/azurekid/DefenderXDR'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release with support for Threat Intelligence Indicator management'
        }
    }
}
