BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Update-DefenderXDRCustomDetection' {
    Context 'Parameter Validation' {
        It 'requires Id parameter' {
            { Update-DefenderXDRCustomDetection -DisplayName 'Updated' } | Should -Throw
        }

        It 'accepts Id parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'rule-123' } }
            
            { Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated' } | Should -Not -Throw
        }

        It 'validates SchedulePeriod values' {
            $validPeriods = @('1H', '2H', '4H', '8H', '12H', '24H')
            foreach ($period in $validPeriods) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'rule-123' } }
                
                { Update-DefenderXDRCustomDetection -Id 'rule-123' -SchedulePeriod $period } | Should -Not -Throw
            }
        }

        It 'validates AlertSeverity values' {
            $validSeverities = @('Informational', 'Low', 'Medium', 'High')
            foreach ($severity in $validSeverities) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'rule-123' } }
                
                { Update-DefenderXDRCustomDetection -Id 'rule-123' -AlertSeverity $severity } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses PATCH method' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'PATCH'
                return @{ id = 'rule-123' }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated'
        }

        It 'constructs URI with rule ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'detectionRules/rule-123'
                return @{ id = 'rule-123' }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated'
        }

        It 'only includes provided parameters in body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.displayName | Should -Be 'Updated Name'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'description'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'queryCondition'
                return @{ id = 'rule-123' }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated Name'
        }

        It 'constructs nested objects correctly for updates' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.queryCondition.queryText | Should -Be 'DeviceProcessEvents | take 20'
                $Body.schedule.period | Should -Be '2H'
                $Body.detectionAction.alertTemplate.title | Should -Be 'New Title'
                return @{ id = 'rule-123' }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -QueryText 'DeviceProcessEvents | take 20' -SchedulePeriod '2H' -AlertTitle 'New Title'
        }
    }

    Context 'Response Handling' {
        It 'returns updated detection rule object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'rule-123'
                    displayName = 'Updated Rule'
                    isEnabled = $false
                }
            }
            
            $result = Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated Rule' -Enabled $false
            $result.displayName | Should -Be 'Updated Rule'
            $result.isEnabled | Should -Be $false
        }
    }

    Context 'Enabling/Disabling Rules' {
        It 'can enable a rule' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.isEnabled | Should -Be $true
                return @{ id = 'rule-123'; isEnabled = $true }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -Enabled $true
        }

        It 'can disable a rule' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.isEnabled | Should -Be $false
                return @{ id = 'rule-123'; isEnabled = $false }
            }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -Enabled $false
        }
    }

    Context 'Permission Validation' {
        It 'validates CustomDetection.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'CustomDetection.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'rule-123' } }
            
            Update-DefenderXDRCustomDetection -Id 'rule-123' -DisplayName 'Updated'
        }
    }
}
