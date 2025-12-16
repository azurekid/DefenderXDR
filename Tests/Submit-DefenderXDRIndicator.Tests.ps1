BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Submit-DefenderXDRIndicator' {
    Context 'Parameter Validation' {
        It 'requires IndicatorValue parameter' {
            { Submit-DefenderXDRIndicator -IndicatorType IpAddress -Action Alert } | Should -Throw
        }

        It 'requires IndicatorType parameter' {
            { Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -Action Alert } | Should -Throw
        }

        It 'requires Action parameter' {
            { Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress } | Should -Throw
        }

        It 'validates IndicatorType values' {
            $validTypes = @('FileSha1', 'FileSha256', 'IpAddress', 'DomainName', 'Url')
            foreach ($type in $validTypes) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-indicator' } }
                
                { Submit-DefenderXDRIndicator -IndicatorValue 'test' -IndicatorType $type -Action Alert -Title 'Test' -Description 'Test' } | Should -Not -Throw
            }
        }

        It 'validates Action values' {
            $validActions = @('Alert', 'AlertAndBlock', 'Allowed')
            foreach ($action in $validActions) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-indicator' } }
                
                { Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action $action -Title 'Test' -Description 'Test' } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'posts to tiIndicators endpoint' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Uri | Should -Match 'security/tiIndicators'
                $Method | Should -Be 'POST'
                return @{ id = 'new-indicator' }
            }
            
            Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action Alert -Title 'Test' -Description 'Test'
        }

        It 'constructs request body with required properties' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.indicatorValue | Should -Be '1.2.3.4'
                $Body.indicatorType | Should -Be 'IpAddress'
                $Body.action | Should -Be 'Alert'
                $Body.title | Should -Be 'Test Indicator'
                $Body.description | Should -Be 'Test Description'
                return @{ id = 'new-indicator' }
            }
            
            Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action Alert -Title 'Test Indicator' -Description 'Test Description'
        }

        It 'includes optional properties when provided' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.severity | Should -Be 'High'
                $Body.expirationDateTime | Should -Not -BeNullOrEmpty
                $Body.recommendedActions | Should -Be 'Block this IP'
                return @{ id = 'new-indicator' }
            }
            
            Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action Alert -Title 'Test' -Description 'Test' -Severity High -ExpirationDateTime (Get-Date).AddDays(30) -RecommendedActions 'Block this IP'
        }
    }

    Context 'Response Handling' {
        It 'returns created indicator object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'indicator-123'
                    indicatorValue = '1.2.3.4'
                    indicatorType = 'IpAddress'
                    action = 'Alert'
                }
            }
            
            $result = Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action Alert -Title 'Test' -Description 'Test'
            $result.id | Should -Be 'indicator-123'
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatIndicators.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'ThreatIndicators.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'new-indicator' } }
            
            Submit-DefenderXDRIndicator -IndicatorValue '1.2.3.4' -IndicatorType IpAddress -Action Alert -Title 'Test' -Description 'Test'
        }
    }
}
