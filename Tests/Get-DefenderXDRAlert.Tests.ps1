BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRAlert' {
    Context 'Parameter Validation' {
        It 'accepts AlertId parameter' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ id = '12345' } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRAlert -AlertId '12345' } | Should -Not -Throw
            }
        }

        It 'accepts Filter parameter' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRAlert -Filter "severity eq 'high'" } | Should -Not -Throw
            }
        }

        It 'accepts Top parameter for pagination' {
            InModuleScope DefenderXDR {
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                Mock Test-DefenderXDRPermission { }
                
                { Get-DefenderXDRAlert -Top 50 } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'constructs correct URI for listing alerts' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/alerts_v2'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRAlert
            }
        }

        It 'constructs correct URI for specific alert by ID' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match 'security/alerts_v2/test-alert-id'
                    return @{ id = 'test-alert-id' }
                }
                
                Get-DefenderXDRAlert -AlertId 'test-alert-id'
            }
        }

        It 'applies OData query parameters correctly' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    param($Uri)
                    $Uri | Should -Match '\$filter=severity eq ''high'''
                    $Uri | Should -Match '\$top=25'
                    return @{ value = @() }
                }
                
                Get-DefenderXDRAlert -Filter "severity eq 'high'" -Top 25
            }
        }
    }

    Context 'Response Handling' {
        It 'returns alert object for single alert query' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        id = 'alert-123'
                        severity = 'high'
                        title = 'Test Alert'
                    }
                }
                
                $result = Get-DefenderXDRAlert -AlertId 'alert-123'
                $result.id | Should -Be 'alert-123'
            }
        }

        It 'returns array of alerts for list query' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { 
                    return @{
                        value = @(
                            @{ id = 'alert-1'; severity = 'high' }
                            @{ id = 'alert-2'; severity = 'medium' }
                        )
                    }
                }
                
                $result = Get-DefenderXDRAlert
                $result.Count | Should -Be 2
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates required permissions before API call' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    # Function requires SecurityEvents.Read.All or SecurityEvents.ReadWrite.All
                    $RequiredPermissions | Should -Contain 'SecurityEvents.Read.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @() } }
                
                Get-DefenderXDRAlert
            }
        }
    }
}
