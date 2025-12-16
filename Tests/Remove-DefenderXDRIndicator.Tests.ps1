BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Remove-DefenderXDRIndicator' {
    Context 'Parameter Validation' {
        It 'requires IndicatorId parameter' {
            { Remove-DefenderXDRIndicator } | Should -Throw
        }

        It 'accepts IndicatorId parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            { Remove-DefenderXDRIndicator -IndicatorId '12345' -Confirm:$false } | Should -Not -Throw
        }

        It 'supports pipeline input' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            $inputObject = [PSCustomObject]@{ IndicatorId = '12345' }
            { $inputObject | Remove-DefenderXDRIndicator -Confirm:$false } | Should -Not -Throw
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
            
            Remove-DefenderXDRIndicator -IndicatorId '12345' -Confirm:$false
        }

        It 'constructs URI with indicator ID' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                param($Uri)
                $Uri | Should -Match 'tiIndicators/indicator-789'
                return $true
            }
            
            Remove-DefenderXDRIndicator -IndicatorId 'indicator-789' -Confirm:$false
        }
    }

    Context 'ShouldProcess Support' {
        It 'supports -WhatIf parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Invoke-DefenderXDRRequest { 
                throw "Should not be called with -WhatIf"
            }
            
            { Remove-DefenderXDRIndicator -IndicatorId '12345' -WhatIf } | Should -Not -Throw
        }

        It 'has high confirm impact' {
            $command = Get-Command Remove-DefenderXDRIndicator
            $command.Parameters['Confirm'].Attributes.ConfirmImpact | Should -Be 'High'
        }
    }

    Context 'Permission Validation' {
        It 'validates ThreatIndicators.ReadWrite.All permission' {
            Mock Test-DefenderXDRPermission { 
                param($RequiredPermissions)
                $RequiredPermissions | Should -Contain 'ThreatIndicators.ReadWrite.All'
                $script:hasPermission = $true
            }
            Mock Invoke-DefenderXDRRequest { return $true }
            
            Remove-DefenderXDRIndicator -IndicatorId '12345' -Confirm:$false
        }
    }
}
