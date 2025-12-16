BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Update-DefenderXDRAlert' {
    Context 'Parameter Validation' {
        It 'requires AlertId parameter' {
            { Update-DefenderXDRAlert -Status New } | Should -Throw
        }

        It 'accepts AlertId parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'alert-123' } }
            
            { Update-DefenderXDRAlert -AlertId 'alert-123' -Status New } | Should -Not -Throw
        }

        It 'validates Status values' {
            $validStatuses = @('New', 'InProgress', 'Resolved')
            foreach ($status in $validStatuses) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'alert-123' } }
                
                { Update-DefenderXDRAlert -AlertId 'alert-123' -Status $status } | Should -Not -Throw
            }
        }

        It 'validates Classification values' {
            $validClassifications = @('TruePositive', 'FalsePositive', 'BenignPositive')
            foreach ($classification in $validClassifications) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'alert-123' } }
                
                { Update-DefenderXDRAlert -AlertId 'alert-123' -Classification $classification } | Should -Not -Throw
            }
        }

        It 'validates Determination values' {
            $validDeterminations = @('MultiStagedAttack', 'MaliciousUserActivity', 'CompromisedAccount', 'Malware', 'Phishing', 'UnwantedSoftware', 'Other', 'NotAvailable')
            foreach ($determination in $validDeterminations) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'alert-123' } }
                
                { Update-DefenderXDRAlert -AlertId 'alert-123' -Determination $determination } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses PATCH method' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'PATCH'
                return @{ id = 'alert-123' }
            }
            
            Update-DefenderXDRAlert -AlertId 'alert-123' -Status InProgress
        }

        It 'constructs URI with alert ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'alerts_v2/alert-456'
                return @{ id = 'alert-456' }
            }
            
            Update-DefenderXDRAlert -AlertId 'alert-456' -Status Resolved
        }

        It 'only includes provided properties in body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.status | Should -Be 'resolved'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'classification'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'determination'
                return @{ id = 'alert-123' }
            }
            
            Update-DefenderXDRAlert -AlertId 'alert-123' -Status Resolved
        }

        It 'includes all specified properties in update' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.status | Should -Be 'resolved'
                $Body.classification | Should -Be 'truePositive'
                $Body.determination | Should -Be 'malware'
                $Body.assignedTo | Should -Be 'analyst@contoso.com'
                return @{ id = 'alert-123' }
            }
            
            Update-DefenderXDRAlert -AlertId 'alert-123' -Status Resolved -Classification TruePositive -Determination Malware -AssignedTo 'analyst@contoso.com'
        }
    }

    Context 'Response Handling' {
        It 'returns updated alert object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'alert-123'
                    status = 'resolved'
                    classification = 'truePositive'
                }
            }
            
            $result = Update-DefenderXDRAlert -AlertId 'alert-123' -Status Resolved -Classification TruePositive
            $result.status | Should -Be 'resolved'
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityAlert.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'SecurityAlert.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'alert-123' } }
            
            Update-DefenderXDRAlert -AlertId 'alert-123' -Status New
        }
    }
}
