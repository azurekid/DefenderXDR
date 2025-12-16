BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Invoke-DefenderXDRAdvancedHuntingQuery' {
    Context 'Parameter Validation' {
        It 'requires Query parameter' {
            { Invoke-DefenderXDRAdvancedHuntingQuery } | Should -Throw
        }

        It 'accepts Query parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ Results = @() } }
            
            { Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10' } | Should -Not -Throw
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses POST method for advanced hunting' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'POST'
                return @{ Results = @() }
            }
            
            Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
        }

        It 'constructs Graph API URI for advanced hunting' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            $script:ApiAudience = 'Graph'
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'graph.microsoft.com/.*security/runHuntingQuery'
                return @{ Results = @() }
            }
            
            Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
        }

        It 'constructs Security API URI when using Security audience' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            $script:ApiAudience = 'Security'
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'api.security(center)?.microsoft.com'
                return @{ Results = @() }
            }
            
            Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
        }

        It 'includes query in request body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.Query | Should -Be 'DeviceProcessEvents | take 10'
                return @{ Results = @() }
            }
            
            Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
        }
    }

    Context 'Response Handling' {
        It 'returns Results array from response' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    Results = @(
                        @{ DeviceName = 'PC1'; ProcessName = 'cmd.exe' }
                        @{ DeviceName = 'PC2'; ProcessName = 'powershell.exe' }
                    )
                }
            }
            
            $result = Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
            $result.Count | Should -Be 2
            $result[0].DeviceName | Should -Be 'PC1'
        }

        It 'handles empty result set' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{ Results = @() }
            }
            
            $result = Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | where 1 == 0'
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'KQL Query Validation' {
        It 'accepts valid KQL syntax' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ Results = @() } }
            
            $validQueries = @(
                'DeviceProcessEvents | take 10'
                'DeviceNetworkEvents | where RemoteIP startswith "192.168"'
                'AlertEvidence | summarize count() by AlertId'
            )
            
            foreach ($query in $validQueries) {
                { Invoke-DefenderXDRAdvancedHuntingQuery -Query $query } | Should -Not -Throw
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatHunting permissions' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'ThreatHunting.Read.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ Results = @() } }
            
            Invoke-DefenderXDRAdvancedHuntingQuery -Query 'DeviceProcessEvents | take 10'
        }
    }
}
