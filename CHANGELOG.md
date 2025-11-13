# Changelog

All notable changes to the DefenderXDR PowerShell module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - `Submit-DefenderXDRThreatIndicator` - Submit new threat indicators
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
- Updated documentation with Defender Endpoint API examples

### Changed
- `Invoke-DefenderXDRRequest` now supports both Graph API and Defender Endpoint API endpoints
- Updated module to export 19 functions (increased from 15)

## [Planned]
- Interactive authentication using MSAL
- Certificate-based authentication
- Managed Identity support
- Additional security operations
- Export/import functionality for bulk operations
- Enhanced filtering capabilities
- Automated remediation actions
