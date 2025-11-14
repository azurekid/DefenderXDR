# Changelog

All notable changes to the DefenderXDR PowerShell module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Renamed `Submit-DefenderXDRThreatIndicator` to `Set-DefenderXDRThreatIndicator` to better reflect its dual capability
- `Set-DefenderXDRThreatIndicator` now supports both creating new and updating existing threat indicators
  - Use without `-IndicatorId` to create a new indicator (requires `-IndicatorValue`, `-IndicatorType`, and `-Action`)
  - Use with `-IndicatorId` to update an existing indicator (all other parameters are optional)
- Added backward compatibility alias `Submit-DefenderXDRThreatIndicator` for existing scripts
- **Permission validation now uses warnings instead of errors**: When an access token has insufficient permissions, functions now display a warning message and allow the API call to proceed, letting the API return its own error if needed. This provides a more consistent user experience and prevents terminating errors during permission validation.

## [1.0.0] - 2025-11-13

### Added
- Initial release of DefenderXDR PowerShell module
- Authentication functions:
  - `Connect-DefenderXDR` - Connect using access token or client credentials
  - `Disconnect-DefenderXDR` - Disconnect and clear credentials
  - `Get-DefenderXDRAccessToken` - Get current token information
  
- Security Alerts management:
  - `Get-DefenderXDRAlert` - Retrieve security alerts with filtering
  - `Update-DefenderXDRAlert` - Update alert status, classification, and assignment
  - `New-DefenderXDRAlertComment` - Add comments to alerts
  
- Incident management:
  - `Get-DefenderXDRIncident` - Retrieve security incidents
  - `Update-DefenderXDRIncident` - Update incident properties
  - `New-DefenderXDRIncidentComment` - Add comments to incidents
  
- Threat Intelligence:
  - `Get-DefenderXDRThreatIntelligence` - Get threat indicators
  - `Set-DefenderXDRThreatIndicator` - Submit new or update existing threat indicators
  - `Remove-DefenderXDRThreatIndicator` - Remove threat indicators
  
- Security Posture:
  - `Get-DefenderXDRSecureScore` - Get Microsoft Secure Score
  - `Get-DefenderXDRSecureScoreControlProfile` - Get security control profiles
  
- Advanced Hunting:
  - `Invoke-DefenderXDRAdvancedHuntingQuery` - Execute KQL queries
  
- Comprehensive documentation and examples
- Support for PowerShell 5.1 and PowerShell 7+
- Error handling and verbose logging
- Token expiration management

### Security
- Secure credential handling
- Token-based authentication
- Support for Azure AD service principals

## [Unreleased]

### Added
- Defender Endpoint API support for threat indicators:
  - `Get-DefenderXDRIndicator` - Get threat indicators via Defender Endpoint API
  - `Import-DefenderXDRIndicators` - Bulk import threat indicators
  - `Remove-DefenderXDRIndicator` - Remove single threat indicator
  - `Remove-DefenderXDRIndicatorBatch` - Batch remove multiple threat indicators
- New example script (05-Defender-Endpoint-Indicators.ps1) demonstrating Defender Endpoint API usage
- **Permission validation for all API calls**: New `Test-DefenderXDRPermission` private function that validates access tokens contain required permissions before making API calls
- Comprehensive permission documentation in README with function-specific requirements

### Changed
- `Invoke-DefenderXDRRequest` now supports both Graph API and Defender Endpoint API endpoints
- Updated module to export 19 functions (increased from 15)
- All public functions now validate permissions before making API calls
- Enhanced error messages to indicate required vs. actual permissions in token
- **Fixed permission validation**: Permission matching now supports "permissive matching" where tokens with broader permissions (e.g., `Ti.ReadWrite.All`) can satisfy requirements for more specific permissions (e.g., `Ti.ReadWrite`)
- Improved error messages with better formatting and clearer guidance using `Write-Error` instead of `throw`

### Security
- **Improved security**: Access tokens are now validated for required permissions before API calls
- Clear error messages help users identify missing permissions quickly
- Supports both Application permissions (roles) and Delegated permissions (scp)

## [Planned]
- Interactive authentication using MSAL
- Certificate-based authentication
- Managed Identity support
- Additional security operations
- Export/import functionality for bulk operations
- Enhanced filtering capabilities
- Automated remediation actions
