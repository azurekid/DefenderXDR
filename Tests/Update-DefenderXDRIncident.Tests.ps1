BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Update-DefenderXDRIncident' {
    Context 'Parameter Validation' {
        It 'requires IncidentId parameter' {
            { Update-DefenderXDRIncident -Status Active } | Should -Throw
        }

        It 'accepts IncidentId parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'incident-123' } }
            
            { Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Active } | Should -Not -Throw
        }

        It 'validates Status values' {
            $validStatuses = @('Active', 'Resolved', 'Redirected')
            foreach ($status in $validStatuses) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'incident-123' } }
                
                { Update-DefenderXDRIncident -IncidentId 'incident-123' -Status $status } | Should -Not -Throw
            }
        }

        It 'validates Classification values' {
            $validClassifications = @('TruePositive', 'FalsePositive', 'BenignPositive')
            foreach ($classification in $validClassifications) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'incident-123' } }
                
                { Update-DefenderXDRIncident -IncidentId 'incident-123' -Classification $classification } | Should -Not -Throw
            }
        }

        It 'validates Determination values' {
            $validDeterminations = @('MultiStagedAttack', 'MaliciousUserActivity', 'CompromisedAccount', 'Malware', 'Phishing', 'SecurityTesting', 'UnwantedSoftware', 'Other')
            foreach ($determination in $validDeterminations) {
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'incident-123' } }
                
                { Update-DefenderXDRIncident -IncidentId 'incident-123' -Determination $determination } | Should -Not -Throw
            }
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses PATCH method' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'PATCH'
                return @{ id = 'incident-123' }
            }
            
            Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Active
        }

        It 'constructs URI with incident ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'incidents/incident-456'
                return @{ id = 'incident-456' }
            }
            
            Update-DefenderXDRIncident -IncidentId 'incident-456' -Status Resolved
        }

        It 'only includes provided properties in body' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.status | Should -Be 'active'
                $Body.PSObject.Properties.Name | Should -Not -Contain 'classification'
                return @{ id = 'incident-123' }
            }
            
            Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Active
        }

        It 'includes all specified properties in update' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Body)
                $Body.status | Should -Be 'resolved'
                $Body.classification | Should -Be 'truePositive'
                $Body.determination | Should -Be 'malware'
                $Body.assignedTo | Should -Be 'analyst@contoso.com'
                return @{ id = 'incident-123' }
            }
            
            Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Resolved -Classification TruePositive -Determination Malware -AssignedTo 'analyst@contoso.com'
        }
    }

    Context 'Response Handling' {
        It 'returns updated incident object' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                return @{
                    id = 'incident-123'
                    status = 'resolved'
                    classification = 'truePositive'
                    determination = 'malware'
                }
            }
            
            $result = Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Resolved -Classification TruePositive -Determination Malware
            $result.status | Should -Be 'resolved'
        }
    }

    Context 'Permission Validation' {
        It 'validates SecurityIncident.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'SecurityIncident.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return @{ id = 'incident-123' } }
            
            Update-DefenderXDRIncident -IncidentId 'incident-123' -Status Active
        }
    }
}
