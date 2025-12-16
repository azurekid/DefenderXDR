BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRCustomDetection' {
    Context 'Parameter Validation' {
        It 'accepts Id parameter for specific detection rule' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ id = 'rule-123' } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRCustomDetection -Id 'rule-123' } | Should -Not -Throw
            }
        }

        It 'accepts Top parameter for pagination' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRCustomDetection -Top 100 } | Should -Not -Throw
            }
        }

        It 'accepts Filter parameter' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRCustomDetection -Filter "isEnabled eq true" } | Should -Not -Throw
            }
        }

        It 'accepts All switch for pagination' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRCustomDetection -All } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses beta endpoint for detection rules' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/rules/detectionRules'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRCustomDetection
            }
        }

        It 'constructs URI with rule ID correctly' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'detectionRules/rule-456'
                    return @{ id = 'rule-456' }
                }
                
                Get-DefenderXDRCustomDetection -Id 'rule-456'
            }
        }

        It 'applies OData query parameters' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri, $Method)
                    $Uri | Should -Match '\%24top=50'
                    $Uri | Should -Match '\%24filter='
                    return @{ value = @() }
                }
                
                Get-DefenderXDRCustomDetection -Top 50 -Filter "isEnabled eq true"
            }
        }
    }

    Context 'Response Handling' {
        It 'returns detection rule object for single rule' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        id = 'rule-123'
                        displayName = 'Test Detection Rule'
                        isEnabled = $true
                        queryCondition = @{ queryText = 'DeviceProcessEvents | take 10' }
                    }
                }
                
                $result = Get-DefenderXDRCustomDetection -Id 'rule-123'
                $result.id | Should -Be 'rule-123'
                $result.isEnabled | Should -Be $true
            }
        }

        It 'returns array of detection rules for list query' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{ id = 'rule-1'; displayName = 'Rule 1' }
                            @{ id = 'rule-2'; displayName = 'Rule 2' }
                        )
                    }
                }
                
                $result = Get-DefenderXDRCustomDetection
                $result.Count | Should -Be 2
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates CustomDetection permissions' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'CustomDetection.ReadWrite.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRCustomDetection
            }
        }
    }
}
