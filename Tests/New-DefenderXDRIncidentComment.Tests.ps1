BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'New-DefenderXDRIncidentComment' {
    Context 'Parameter Validation' {
        It 'requires IncidentId parameter' {
            { New-DefenderXDRIncidentComment -Comment 'Test comment' } | Should -Throw
        }

        It 'requires Comment parameter' {
            { New-DefenderXDRIncidentComment -IncidentId 'incident-123' } | Should -Throw
        }

        It 'accepts both required parameters' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ value = 'Comment added' } }
            
            { New-DefenderXDRIncidentComment -IncidentId 'incident-123' -Comment 'Test comment' } | Should -Not -Throw
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
            
            New-DefenderXDRIncidentComment -IncidentId 'incident-123' -Comment 'Test comment'
        }

        It 'constructs URI with incident ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'incidents/incident-789/comments'
                return @{ value = 'Comment added' }
            }
            
            New-DefenderXDRIncidentComment -IncidentId 'incident-789' -Comment 'Test comment'
        }

        It 'includes comment in request body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.comment | Should -Be 'This is a test comment for incident'
                return @{ value = 'Comment added' }
            }
            
            New-DefenderXDRIncidentComment -IncidentId 'incident-123' -Comment 'This is a test comment for incident'
        }
    }

    Context 'Response Handling' {
        It 'returns success indicator' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{ value = 'Comment added successfully' }
            }
            
            $result = New-DefenderXDRIncidentComment -IncidentId 'incident-123' -Comment 'Test'
            $result.value | Should -Be 'Comment added successfully'
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityIncident.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'SecurityIncident.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ value = 'Comment added' } }
            
            New-DefenderXDRIncidentComment -IncidentId 'incident-123' -Comment 'Test'
        }
    }
}
