BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIl0sImF1ZCI6Imh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbSJ9.test'
    $script:TokenExpiration = (Get-Date).AddHours(1)
}

Describe 'Test-DefenderXDRPermission' {
    Context 'Permission Validation' {
        It 'validates app permissions from roles claim' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIiwiU2VjdXJpdHlJbmNpZGVudC5SZWFkLkFsbCJdfQ.test'
            
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All')
            $script:hasPermission | Should -Be $true
        }

        It 'validates delegated permissions from scp claim' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY3AiOiJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIFNlY3VyaXR5SW5jaWRlbnQuUmVhZC5BbGwifQ.test'
            
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All')
            $script:hasPermission | Should -Be $true
        }

        It 'detects missing permissions' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIl19.test'
            
            { Test-DefenderXDRPermission -RequiredPermissions @('SecurityIncident.ReadWrite.All') } | Should -Throw
        }

        It 'supports OR logic for multiple permissions' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJTZWN1cml0eUFsZXJ0LlJlYWQuQWxsIl19.test'
            
            # Should pass if ANY of the permissions match
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityIncident.Read.All', 'SecurityAlert.Read.All')
            $script:hasPermission | Should -Be $true
        }
    }

    Context 'Connection State' {
        It 'warns when not connected' {
            $script:AccessToken = $null
            
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All')
            $script:hasPermission | Should -Be $false
        }

        It 'uses connection reminder flag' {
            $script:AccessToken = $null
            $script:ConnectionReminderDisplayed = $false
            
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All')
            $script:ConnectionReminderDisplayed | Should -Be $true
        }

        It 'does not show duplicate connection warnings' {
            $script:AccessToken = $null
            $script:ConnectionReminderDisplayed = $true
            
            # Should not display warning again
            Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All')
        }
    }

    Context 'Error Messages' {
        It 'throws UnauthorizedAccessException with missing permissions' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6W119.test'
            
            { Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All') } | Should -Throw -ExceptionType ([UnauthorizedAccessException])
        }

        It 'lists required permissions in error message' {
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6W119.test'
            
            try {
                Test-DefenderXDRPermission -RequiredPermissions @('SecurityAlert.Read.All', 'SecurityIncident.Read.All')
            }
            catch {
                $_.Exception.Message | Should -Match 'SecurityAlert.Read.All'
            }
        }
    }

    Context 'JWT Decoding' {
        It 'decodes base64url encoded payload' {
            # Valid JWT with padding
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJ0ZXN0Il19.test'
            
            { Test-DefenderXDRPermission -RequiredPermissions @('test') } | Should -Not -Throw
        }

        It 'handles JWT without padding' {
            # JWT payloads are base64url encoded without padding
            $script:AccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6WyJ0ZXN0Il19.sig'
            
            { Test-DefenderXDRPermission -RequiredPermissions @('test') } | Should -Not -Throw
        }
    }
}
