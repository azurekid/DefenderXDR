BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRIncident' {
    Context 'Parameter Validation' {
        It 'accepts IncidentId parameter' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ id = '12345' } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRIncident -IncidentId '12345' } | Should -Not -Throw
            }
        }

        It 'accepts Filter parameter' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRIncident -Filter "status eq 'active'" } | Should -Not -Throw
            }
        }

        It 'accepts pagination parameters' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRIncident -Top 50 -Skip 10 } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses beta endpoint for incidents' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/incidents'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIncident
            }
        }

        It 'constructs URI with incident ID correctly' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/incidents/incident-123'
                    return @{ id = 'incident-123' }
                }
                
                Get-DefenderXDRIncident -IncidentId 'incident-123'
            }
        }

        It 'applies OData query parameters' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match '\$top=100'
                    $Uri | Should -Match '\$skip=50'
                    $Uri | Should -Match '\$orderby=createdDateTime'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRIncident -Top 100 -Skip 50 -OrderBy 'createdDateTime'
            }
        }
    }

    Context 'Response Handling' {
        It 'returns incident object for single incident' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        id = 'incident-123'
                        displayName = 'Test Incident'
                        severity = 'high'
                        status = 'active'
                    }
                }
                
                $result = Get-DefenderXDRIncident -IncidentId 'incident-123'
                $result.id | Should -Be 'incident-123'
                $result.severity | Should -Be 'high'
            }
        }

        It 'returns array of incidents for list query' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{ id = '1'; displayName = 'Incident 1' }
                            @{ id = '2'; displayName = 'Incident 2' }
                        )
                    }
                }
                
                $result = Get-DefenderXDRIncident
                $result.Count | Should -Be 2
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityIncident permissions' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'SecurityIncident.Read.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRIncident
            }
        }
    }
}
