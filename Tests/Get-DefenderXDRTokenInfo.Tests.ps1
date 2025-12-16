BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRTokenInfo' {
    Context 'Functionality' {
        It 'returns token information when connected' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIl0sImF1ZCI6Imh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbSIsImV4cCI6OTk5OTk5OTk5OX0.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result | Should -Not -BeNullOrEmpty
            }
        }

        It 'decodes JWT token payload' {
            InModuleScope DefenderXDR {
                # Mock JWT with known payload
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIl0sImF1ZCI6Imh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbSJ9.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result.roles | Should -Contain 'SecurityAlert.Read.All'
            }
        }

        It 'shows token expiration information' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzI3MzYwMDB9.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result.ExpiresAt | Should -Not -BeNullOrEmpty
            }
        }

        It 'returns warning when not connected' {
            InModuleScope DefenderXDR {
                $script:AccessToken = $null
                
                { Get-DefenderXDRTokenInfo } | Should -Throw
            }
        }
    }

    Context 'Token Properties' {
        It 'extracts audience from token' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20ifQ.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result.AudClaim | Should -Be 'https://graph.microsoft.com'
            }
        }

        It 'extracts roles from token' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIiwiU2VjdXJpdHlJbmNpZGVudC5SZWFkLkFsbCJdfQ.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result.Roles.Count | Should -Be 2
            }
        }

        It 'extracts scopes from delegated token' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY3AiOiJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIFNlY3VyaXR5SW5jaWRlbnQuUmVhZC5BbGwifQ.test'
                
                $result = Get-DefenderXDRTokenInfo
                $result.Scopes | Should -Be 'SecurityAlert.Read.All SecurityIncident.Read.All'
            }
        }
    }
}
