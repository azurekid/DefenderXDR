BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRThreatIntelligence' {
    Context 'Parameter Validation' {
        It 'accepts IndicatorId parameter' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'ti-123' } }
                
                { Get-DefenderXDRThreatIntelligence -IndicatorId 'ti-123' } | Should -Not -Throw
            }
        }

        It 'accepts Filter parameter' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                { Get-DefenderXDRThreatIntelligence -Filter "threatType eq 'Malware'" } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs URI for threat intelligence' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/tiIndicators'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRThreatIntelligence
            }
        }

        It 'applies filter for specific indicator value' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match '\$filter='
                    return @{ value = @() }
                }
                
                Get-DefenderXDRThreatIntelligence -Filter "indicatorValue eq '1.2.3.4'"
            }
        }
    }

    Context 'Response Handling' {
        It 'returns threat intelligence data' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{
                                id = 'ti-123'
                                indicatorValue = '1.2.3.4'
                                threatType = 'Malware'
                            }
                        )
                    }
                }
                
                $result = Get-DefenderXDRThreatIntelligence -Filter "indicatorValue eq '1.2.3.4'"
                $result | Should -BeOfType [System.Collections.IEnumerable]
                $result.Count | Should -Be 3
                $result.indicatorValue | Should -Be '1.2.3.4'
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatIndicators.Read.All permission' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'ThreatIndicators.Read.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRThreatIntelligence
            }
        }
    }
}
