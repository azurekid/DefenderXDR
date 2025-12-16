BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force

    $script:AccessToken = 'mock_token'
    $script:TokenExpiration = (Get-Date).AddHours(1)
    $script:hasPermission = $true
}

Describe 'Remove-DefenderXDRIndicatorBatch' {
    Context 'Parameter Validation' {
        It 'requires IndicatorIds parameter' {
            { Remove-DefenderXDRIndicatorBatch } | Should -Throw
        }

        It 'accepts IndicatorIds array' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Remove-DefenderXDRIndicator { return $true }
            
            { Remove-DefenderXDRIndicatorBatch -IndicatorIds @('id1', 'id2') -Confirm:$false } | Should -Not -Throw
        }

        It 'accepts pipeline input' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Remove-DefenderXDRIndicator { return $true }
            
            $ids = @('id1', 'id2', 'id3')
            { $ids | Remove-DefenderXDRIndicatorBatch -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Batch Processing' {
        It 'removes multiple indicators' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Remove-DefenderXDRIndicator { return $true }
            
            $ids = @('indicator-1', 'indicator-2', 'indicator-3')
            $result = Remove-DefenderXDRIndicatorBatch -IndicatorIds $ids -Confirm:$false
            
            Should -Invoke Remove-DefenderXDRIndicator -Times 3
        }

        It 'continues on individual indicator failure' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Remove-DefenderXDRIndicator { 
                param($IndicatorId)
                if ($IndicatorId -eq 'indicator-2') { throw 'API Error' }
                return $true
            }
            
            $ids = @('indicator-1', 'indicator-2', 'indicator-3')
            Remove-DefenderXDRIndicatorBatch -IndicatorIds $ids -Confirm:$false -ErrorAction SilentlyContinue
            
            Should -Invoke Remove-DefenderXDRIndicator -Times 3
        }
    }

    Context 'ShouldProcess Support' {
        It 'supports -WhatIf parameter' {
            Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
            Mock Remove-DefenderXDRIndicator { 
                throw "Should not be called with -WhatIf"
            }
            
            $ids = @('indicator-1', 'indicator-2')
            { Remove-DefenderXDRIndicatorBatch -IndicatorIds $ids -WhatIf } | Should -Not -Throw
        }

        It 'has high confirm impact' {
            $command = Get-Command Remove-DefenderXDRIndicatorBatch
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
            Mock Remove-DefenderXDRIndicator { return $true }
            
            Remove-DefenderXDRIndicatorBatch -IndicatorIds @('id1') -Confirm:$false
        }
    }
}
