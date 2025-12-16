BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Get-DefenderXDRAccessToken' {
    Context 'Token Information' {
        It 'returns token info when connected' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'test-token-12345'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                $script:TenantId = 'test-tenant-id'
                
                $result = Get-DefenderXDRAccessToken
                $result.HasToken | Should -Be $true
                $result.TokenExpires | Should -BeOfType [DateTime]
                $result.IsExpired | Should -Be $false
                $result.TenantId | Should -Be 'test-tenant-id'
                $result.MinutesRemaining | Should -BeGreaterThan 0
            }
        }

        It 'returns null and warning when not connected' {
            InModuleScope DefenderXDR {
                $script:AccessToken = $null
                
                $result = Get-DefenderXDRAccessToken
                $result | Should -BeNullOrEmpty
            }
        }

        It 'does not expose actual token in output' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'secret-token-value'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                
                $result = Get-DefenderXDRAccessToken
                # The result should be an object, not the raw token
                $result | Should -BeOfType [PSCustomObject]
                $result.HasToken | Should -Be $true
                # The actual token value should not be in the output
                $result.PSObject.Properties.Name | Should -Not -Contain 'Token'
                $result.PSObject.Properties.Name | Should -Not -Contain 'AccessToken'
            }
        }
    }

    Context 'Token Expiration' {
        It 'shows token not expired when valid' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'valid-token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                
                $result = Get-DefenderXDRAccessToken
                $result.IsExpired | Should -Be $false
                $result.MinutesRemaining | Should -BeGreaterThan 0
            }
        }

        It 'shows token expired when past expiration' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'expired-token'
                $script:TokenExpiration = (Get-Date).AddHours(-1)
                
                $result = Get-DefenderXDRAccessToken
                $result.IsExpired | Should -Be $true
                $result.MinutesRemaining | Should -BeLessThan 0
            }
        }
        
        It 'calculates minutes remaining correctly' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'test-token'
                $script:TokenExpiration = (Get-Date).AddMinutes(30)
                
                $result = Get-DefenderXDRAccessToken
                $result.MinutesRemaining | Should -BeGreaterThan 29
                $result.MinutesRemaining | Should -BeLessThan 31
            }
        }
    }
}
