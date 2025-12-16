BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Remove-DefenderXDRCustomDetection' {
    Context 'Parameter Validation' {
        It 'requires Id parameter' {
            { Remove-DefenderXDRCustomDetection } | Should -Throw
        }

        It 'accepts Id parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            { Remove-DefenderXDRCustomDetection -Id 'rule-123' -Confirm:$false } | Should -Not -Throw
        }

        It 'supports pipeline input by property name' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            $inputObject = [PSCustomObject]@{ Id = 'rule-456' }
            { $inputObject | Remove-DefenderXDRCustomDetection -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Microsoft Graph Security API Compliance' {
        It 'uses DELETE method' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri, $Method)
                $Method | Should -Be 'DELETE'
                return $true
            }
            
            Remove-DefenderXDRCustomDetection -Id 'rule-123' -Confirm:$false
        }

        It 'constructs URI with rule ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'detectionRules/rule-789'
                return $true
            }
            
            Remove-DefenderXDRCustomDetection -Id 'rule-789' -Confirm:$false
        }

        It 'returns 204 No Content on success' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                # DELETE returns no content on success
                return $true
            }
            
            $result = Remove-DefenderXDRCustomDetection -Id 'rule-123' -Confirm:$false
            $result | Should -Be $true
        }
    }

    Context 'ShouldProcess Support' {
        It 'supports -WhatIf parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                throw "Should not be called with -WhatIf"
            }
            
            { Remove-DefenderXDRCustomDetection -Id 'rule-123' -WhatIf } | Should -Not -Throw
        }

        It 'has high confirm impact' {
            $command = Get-Command Remove-DefenderXDRCustomDetection
            $command.Parameters['Confirm'].Attributes.ConfirmImpact | Should -Be 'High'
        }
    }

    Context 'Permission Validation' {
        It 'validates CustomDetection.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'CustomDetection.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            Remove-DefenderXDRCustomDetection -Id 'rule-123' -Confirm:$false
        }
    }
}
