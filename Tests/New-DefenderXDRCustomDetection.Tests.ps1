BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'New-DefenderXDRCustomDetection' {
    Context 'Parameter Validation' {
        It 'requires DisplayName parameter' {
            { New-DefenderXDRCustomDetection -Description 'test' -Query 'test' -Severity High } | Should -Throw
        }

        It 'requires Description parameter' {
            { New-DefenderXDRCustomDetection -DisplayName 'test' -Query 'test' -Severity High } | Should -Throw
        }

        It 'requires Query parameter' {
            { New-DefenderXDRCustomDetection -DisplayName 'test' -Description 'test' -Severity High } | Should -Throw
        }

        It 'requires Severity parameter' {
            { New-DefenderXDRCustomDetection -DisplayName 'test' -Description 'test' -Query 'test' } | Should -Throw
        }

        It 'validates Severity values' {
            $validSeverities = @('Informational', 'Low', 'Medium', 'High')
            foreach ($severity in $validSeverities) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }
                
                { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'DeviceProcessEvents | take 10' -Severity $severity } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs proper request body with nested objects' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method, $Body)
                $Method | Should -Be 'POST'
                $Body.displayName | Should -Be 'Test Rule'
                $Body.isEnabled | Should -Not -BeNullOrEmpty
                $Body.queryCondition | Should -Not -BeNullOrEmpty
                $Body.queryCondition.queryText | Should -Be 'DeviceProcessEvents | take 10'
                $Body.schedule | Should -Not -BeNullOrEmpty
                $Body.detectionAction | Should -Not -BeNullOrEmpty
                $Body.detectionAction.alertTemplate | Should -Not -BeNullOrEmpty
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test Rule' -Description 'Test Description' -Query 'DeviceProcessEvents | take 10' -Severity High
        }

        It 'posts to correct Graph endpoint' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'graph.microsoft.com/beta/security/rules/detectionRules'
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Medium
        }

        It 'converts FrequencyMinutes to schedule period correctly' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.schedule.period | Should -Match '^\d+H$'
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Low -FrequencyMinutes 120
        }

        It 'includes alertTemplate with required properties' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.detectionAction.alertTemplate.title | Should -Not -BeNullOrEmpty
                $Body.detectionAction.alertTemplate.description | Should -Not -BeNullOrEmpty
                $Body.detectionAction.alertTemplate.severity | Should -Match '^(informational|low|medium|high)$'
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Desc' -Query 'test' -Severity High -Category 'Execution'
        }
    }

    Context 'Optional Parameters' {
        It 'includes Category when provided' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.detectionAction.alertTemplate.category | Should -Be 'Execution'
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Category 'Execution'
        }

        It 'includes RecommendedActions when provided' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.detectionAction.alertTemplate.recommendedActions | Should -Be 'Isolate device'
                return @{ id = 'new-rule' }
            }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -RecommendedActions 'Isolate device'
        }
    }

    Context 'Response Handling' {
        It 'returns created detection rule object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'new-rule-123'
                    displayName = 'Test Rule'
                    isEnabled = $true
                }
            }
            
            $result = New-DefenderXDRCustomDetection -DisplayName 'Test Rule' -Description 'Test' -Query 'test' -Severity High
            $result.id | Should -Be 'new-rule-123'
        }
    }

    Context 'Permission Validation' {
        It 'validates CustomDetection.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'CustomDetection.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }
            
            New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
        }
    }
}
