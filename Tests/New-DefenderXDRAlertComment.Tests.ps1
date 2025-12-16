BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'New-DefenderXDRAlertComment' {
    Context 'Parameter Validation' {
        It 'requires AlertId parameter' {
            { New-DefenderXDRAlertComment -Comment 'Test comment' } | Should -Throw
        }

        It 'requires Comment parameter' {
            { New-DefenderXDRAlertComment -AlertId 'alert-123' } | Should -Throw
        }

        It 'accepts both required parameters' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ value = 'Comment added' } }
            
            { New-DefenderXDRAlertComment -AlertId 'alert-123' -Comment 'Test comment' } | Should -Not -Throw
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses POST method for comments' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'POST'
                return @{ value = 'Comment added' }
            }
            
            New-DefenderXDRAlertComment -AlertId 'alert-123' -Comment 'Test comment'
        }

        It 'constructs URI with alert ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'alerts_v2/alert-789/comments'
                return @{ value = 'Comment added' }
            }
            
            New-DefenderXDRAlertComment -AlertId 'alert-789' -Comment 'Test comment'
        }

        It 'includes comment in request body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.comment | Should -Be 'This is a test comment'
                return @{ value = 'Comment added' }
            }
            
            New-DefenderXDRAlertComment -AlertId 'alert-123' -Comment 'This is a test comment'
        }
    }

    Context 'Response Handling' {
        It 'returns success indicator' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{ value = 'Comment added successfully' }
            }
            
            $result = New-DefenderXDRAlertComment -AlertId 'alert-123' -Comment 'Test'
            $result.value | Should -Be 'Comment added successfully'
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityAlert.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'SecurityAlert.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ value = 'Comment added' } }
            
            New-DefenderXDRAlertComment -AlertId 'alert-123' -Comment 'Test'
        }
    }
}
