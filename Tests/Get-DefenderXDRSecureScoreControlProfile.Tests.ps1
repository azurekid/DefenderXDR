BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRSecureScoreControlProfile' {
    Context 'Parameter Validation' {
        It 'accepts no parameters to list all control profiles' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                { Get-DefenderXDRSecureScoreControlProfile } | Should -Not -Throw
            }
        }

        It 'accepts ControlId parameter for specific control profile' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'control-123' } }
                
                { Get-DefenderXDRSecureScoreControlProfile -ControlId 'control-123' } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs URI for control profiles list' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/secureScoreControlProfiles'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRSecureScoreControlProfile
            }
        }

        It 'constructs URI for specific control profile by ID' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'secureScoreControlProfiles/control-456'
                    return @{ id = 'control-456' }
                }
                
                Get-DefenderXDRSecureScoreControlProfile -ControlId 'control-456'
            }
        }
    }

    Context 'Response Handling' {
        It 'returns control profile object for single profile' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        id = 'control-123'
                        title = 'Enable MFA'
                        maxScore = 10
                        implementationCost = 'low'
                    }
                }
                
                $result = Get-DefenderXDRSecureScoreControlProfile -ControlId 'control-123'
                $result.title | Should -Be 'Enable MFA'
            }
        }

        It 'returns array of control profiles for list query' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{ id = '1'; title = 'Control 1' }
                            @{ id = '2'; title = 'Control 2' }
                        )
                    }
                }
                
                $result = Get-DefenderXDRSecureScoreControlProfile
                $result.Count | Should -Be 2
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
                
                Get-DefenderXDRSecureScoreControlProfile
            }
        }
    }
}
