BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Connect-DefenderXDR' {
    BeforeEach {
        # Clean up any existing connection
        if (Get-Module DefenderXDR) {
            Remove-Module DefenderXDR -Force
            Import-Module $manifestPath -Force
        }
    }

    Context 'Parameter Validation' {
        It 'requires TenantId parameter' {
            { Connect-DefenderXDR -ClientId 'test' -ClientSecret 'test' } | Should -Throw
        }

        It 'requires ClientId parameter' {
            { Connect-DefenderXDR -TenantId 'test' -ClientSecret 'test' } | Should -Throw
        }

        It 'requires ClientSecret parameter' {
            { Connect-DefenderXDR -TenantId 'test' -ClientId 'test' } | Should -Throw
        }

        It 'accepts valid Audience values' {
            $validAudiences = @('Graph', 'Security')
            foreach ($audience in $validAudiences) {
                { Connect-DefenderXDR -TenantId 'test' -ClientId 'test' -ClientSecret 'test' -Audience $audience -WhatIf } | Should -Not -Throw
            }
        }
    }

    Context 'Authentication Flow' {
        It 'attempts to acquire token with valid credentials' {
            Mock Invoke-RestMethod { 
                return @{
                    access_token = 'mock_token_12345'
                    expires_in = 3600
                    token_type = 'Bearer'
                }
            }

            { Connect-DefenderXDR -TenantId 'test-tenant' -ClientId 'test-client' -ClientSecret 'test-secret' -Audience Graph } | Should -Not -Throw
        }

        It 'handles invalid credentials gracefully' {
            Mock Invoke-RestMethod { throw 'Invalid client credentials' }

            { Connect-DefenderXDR -TenantId 'invalid' -ClientId 'invalid' -ClientSecret 'invalid' } | Should -Throw
        }
    }
}
