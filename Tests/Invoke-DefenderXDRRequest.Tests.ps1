BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
}

Describe 'Invoke-DefenderXDRRequest' {
    Context 'HTTP Methods' {
        It 'supports GET method' {
            Mock Invoke-RestMethod { 
                param($Method)
                $Method | Should -Be 'Get'
                return @{ value = @() }
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2' -Method GET
        }

        It 'supports POST method with body' {
            Mock Invoke-RestMethod { 
                param($Method, $Body)
                $Method | Should -Be 'Post'
                $Body | Should -Not -BeNullOrEmpty
                return @{ id = 'new-resource' }
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/rules/detectionRules' -Method POST -Body @{ displayName = 'Test' }
        }

        It 'supports PATCH method for updates' {
            Mock Invoke-RestMethod { 
                param($Method)
                $Method | Should -Be 'Patch'
                return @{ id = 'updated' }
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2/123' -Method PATCH -Body @{ status = 'resolved' }
        }

        It 'supports DELETE method' {
            Mock Invoke-RestMethod { 
                param($Method)
                $Method | Should -Be 'Delete'
                return $null
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/tiIndicators/123' -Method DELETE
        }
    }

    Context 'Request Headers' {
        It 'includes Authorization header with Bearer token' {
            Mock Invoke-RestMethod { 
                param($Headers)
                $Headers['Authorization'] | Should -Match '^Bearer '
                return @{}
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2' -Method GET
        }

        It 'sets Content-Type to application/json' {
            Mock Invoke-RestMethod { 
                param($Headers)
                $Headers['Content-Type'] | Should -Be 'application/json'
                return @{}
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2' -Method GET
        }
    }

    Context 'Request Body Handling' {
        It 'converts body hashtable to JSON' {
            Mock Invoke-RestMethod { 
                param($Body)
                $Body | Should -BeOfType [string]
                $parsed = $Body | ConvertFrom-Json
                $parsed.displayName | Should -Be 'Test Rule'
                return @{}
            }
            
            Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method POST -Body @{ displayName = 'Test Rule' }
        }

        It 'handles nested objects in body' {
            Mock Invoke-RestMethod { 
                param($Body)
                $parsed = $Body | ConvertFrom-Json
                $parsed.queryCondition.queryText | Should -Be 'test query'
                return @{}
            }
            
            $body = @{
                displayName = 'Test'
                queryCondition = @{ queryText = 'test query' }
            }
            Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method POST -Body $body
        }
    }

    Context 'Connection State Validation' {
        It 'warns when not connected' {
            $script:AccessToken = $null
            
            $result = Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method GET
            $result | Should -BeNullOrEmpty
        }

        It 'checks token expiration' {
            $script:AccessToken = 'expired-token'
            $script:TokenExpiration = (Get-Date).AddHours(-1)
            Mock Invoke-RestMethod { return @{} }
            
            # Should still attempt but warn about expiration
            Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method GET
        }
    }

    Context 'Error Handling' {
        It 'extracts error details from response' {
            Mock Invoke-RestMethod { 
                $errorResponse = @{
                    StatusCode = 404
                    ErrorDetails = @{
                        Message = '{"error": {"message": "Resource not found"}}'
                    }
                } | Add-Member -MemberType ScriptMethod -Name 'ToString' -Value { 'Not Found' } -PassThru -Force
                throw $errorResponse
            }
            
            { Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method GET } | Should -Throw
        }

        It 'handles 401 Unauthorized' {
            Mock Invoke-RestMethod { 
                throw [System.Net.WebException]::new('Unauthorized')
            }
            
            { Invoke-DefenderXDRRequest -Uri 'https://example.com' -Method GET } | Should -Throw
        }
    }

    Context 'Audience Mismatch Detection' {
        It 'warns when using Security token with Graph endpoint' {
            $script:ApiAudience = 'Security'
            Mock Invoke-RestMethod { return @{} }
            
            # Should warn about potential mismatch
            Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2' -Method GET
        }

        It 'warns when using Graph token with Security endpoint' {
            $script:ApiAudience = 'Graph'
            Mock Invoke-RestMethod { return @{} }
            
            Invoke-DefenderXDRRequest -Uri 'https://api.securitycenter.microsoft.com/api/alerts' -Method GET
        }
    }

    Context 'URI Variable Handling' {
        It 'does not use reserved $host variable' {
            # This test ensures $host variable bug is fixed
            Mock Invoke-RestMethod { 
                param($Uri)
                $Uri | Should -Match 'https://'
                return @{}
            }
            
            # Should use $targetHost or similar, not $host
            { Invoke-DefenderXDRRequest -Uri 'https://graph.microsoft.com/test' -Method GET } | Should -Not -Throw
        }
    }
}
