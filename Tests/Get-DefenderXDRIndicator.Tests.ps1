BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRIndicator' {
    Context 'Parameter Validation' {
        It 'accepts IndicatorId parameter' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = '12345' } }
                
                { Get-DefenderXDRIndicator -IndicatorId '12345' } | Should -Not -Throw
            }
        }

        It 'accepts Top parameter for pagination' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                { Get-DefenderXDRIndicator -Top 100 } | Should -Not -Throw
            }
        }
    }

    Context 'Dual API Support' {
        It 'uses Defender Endpoint API when audience is Security' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Security'
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'api.securitycenter.microsoft.com/api/indicators'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIndicator
            }
        }

        It 'uses Microsoft Graph API when audience is Graph' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Graph'
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/tiIndicators'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIndicator
            }
        }

        It 'constructs URI correctly without duplication' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Security'
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    # Should not have /indicators/indicators
                    $Uri | Should -Not -Match 'indicators/indicators'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIndicator
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs URI for single indicator by ID' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Graph'
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'tiIndicators/indicator-123'
                    return @{ id = 'indicator-123' }
                }
                
                Get-DefenderXDRIndicator -IndicatorId 'indicator-123'
            }
        }

        It 'applies OData top parameter' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Graph'
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match '\$top=100'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIndicator -Top 100
            }
        }
    }

    Context 'Response Handling' {
        It 'returns indicator object for single indicator' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        id = 'indicator-123'
                        indicatorValue = '1.2.3.4'
                        indicatorType = 'IpAddress'
                    }
                }
                
                $result = Get-DefenderXDRIndicator -IndicatorId 'indicator-123'
                $result.id | Should -Be 'indicator-123'
            }
        }

        It 'returns array of indicators for list query' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{ id = '1'; indicatorValue = '1.2.3.4' }
                            @{ id = '2'; indicatorValue = 'evil.com' }
                        )
                    }
                }
                
                $result = Get-DefenderXDRIndicator
                $result.Count | Should -Be 2
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatIndicators permissions for Graph API' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Graph'
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'ThreatIndicators.Read.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRIndicator
            }
        }

        It 'validates Ti permissions for Security API' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                $script:ApiAudience = 'Security'
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'Ti.ReadWrite'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRIndicator
            }
        }
    }
}
