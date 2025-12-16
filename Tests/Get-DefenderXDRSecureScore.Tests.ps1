BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRSecureScore' {
    Context 'Parameter Validation' {
        It 'accepts no parameters for current secure score' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ currentScore = 100 } }
                
                { Get-DefenderXDRSecureScore } | Should -Not -Throw
            }
        }

        It 'accepts Top parameter for history' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                { Get-DefenderXDRSecureScore -Top 30 } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs URI for secure score' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/secureScores'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRSecureScore
            }
        }

        It 'applies OData top parameter' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match '\$top=30'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRSecureScore -Top 30
            }
        }
    }

    Context 'Response Handling' {
        It 'returns secure score data' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{
                                id = '1'
                                currentScore = 150.5
                                maxScore = 300
                                createdDateTime = '2024-01-01T00:00:00Z'
                            },
                            @{
                                id = '2'
                                currentScore = 200.0
                                maxScore = 300
                                createdDateTime = '2024-01-02T00:00:00Z'
                            }
                        )
                    }
                }
                
                $result = Get-DefenderXDRSecureScore
                $result | Should -BeOfType [System.Collections.IEnumerable]
                $result.Count | Should -Be 2
                $result.Count | Should -Be 2
                $result.Count | Should -Be 2
                $result[0].currentScore | Should -Be 150.5
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityEvents.Read.All permission' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'SecurityEvents.Read.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRSecureScore
            }
        }
    }
}
