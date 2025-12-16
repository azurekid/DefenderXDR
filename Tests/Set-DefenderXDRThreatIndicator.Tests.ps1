BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Set-DefenderXDRThreatIndicator' {
    Context 'Parameter Validation' {
        It 'requires IndicatorId parameter' {
            { Set-DefenderXDRThreatIndicator -Action Alert } | Should -Throw
        }

        It 'accepts IndicatorId parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'indicator-123' } }
            
            { Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action Alert } | Should -Not -Throw
        }

        It 'validates Action values' {
            $validActions = @('Alert', 'AlertAndBlock', 'Allowed')
            foreach ($action in $validActions) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'indicator-123' } }
                
                { Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action $action } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses PATCH method' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'PATCH'
                return @{ id = 'indicator-123' }
            }
            
            Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action Alert
        }

        It 'constructs URI with indicator ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'tiIndicators/indicator-456'
                return @{ id = 'indicator-456' }
            }
            
            Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-456' -Action AlertAndBlock
        }

        It 'only includes provided properties in body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.action | Should -Be 'Alert'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'severity'
                return @{ id = 'indicator-123' }
            }
            
            Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action Alert
        }

        It 'includes multiple update properties' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.action | Should -Be 'AlertAndBlock'
                $Body.severity | Should -Be 'High'
                $Body.description | Should -Be 'Updated description'
                return @{ id = 'indicator-123' }
            }
            
            Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action AlertAndBlock -Severity High -Description 'Updated description'
        }
    }

    Context 'Response Handling' {
        It 'returns updated indicator object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'indicator-123'
                    action = 'AlertAndBlock'
                    severity = 'High'
                }
            }
            
            $result = Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action AlertAndBlock -Severity High
            $result.action | Should -Be 'AlertAndBlock'
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatIndicators.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'ThreatIndicators.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'indicator-123' } }
            
            Set-DefenderXDRThreatIndicator -IndicatorId 'indicator-123' -Action Alert
        }
    }
}
