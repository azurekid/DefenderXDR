BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Import-DefenderXDRIndicators' {
    Context 'Parameter Validation' {
        It 'requires Indicators parameter' {
            InModuleScope DefenderXDR {
                { Import-DefenderXDRIndicators } | Should -Throw
            }
        }

        It 'accepts Indicators parameter' {
            InModuleScope DefenderXDR {
                Mock Test-DefenderXDRPermission { }
                Mock Submit-DefenderXDRIndicator { return @{ id = 'indicator-1' } }
                
                $indicators = @(@{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert' })
                { Import-DefenderXDRIndicators -Indicators $indicators } | Should -Not -Throw
            }
        }
    }

    Context 'Batch Processing' {
        It 'processes indicators from array' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ value = @(@{ id = 'indicator-1' }) } }
                
                $indicators = @(
                    @{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert'; title = 'Test'; description = 'Test' }
                )
                $result = Import-DefenderXDRIndicators -Indicators $indicators
                $result.value.Count | Should -Be 1
            }
        }

        It 'processes multiple indicators' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { return @{ value = @(@{ id = 'indicator-1' }, @{ id = 'indicator-2' }, @{ id = 'indicator-3' }) } }
                
                $indicators = @(
                    @{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert'; title = 'Test'; description = 'Test' }
                    @{ indicatorValue = 'evil.com'; indicatorType = 'DomainName'; action = 'AlertAndBlock'; title = 'Test'; description = 'Test' }
                    @{ indicatorValue = 'bad.exe'; indicatorType = 'FileSha256'; action = 'AlertAndBlock'; title = 'Test'; description = 'Test' }
                )
                $result = Import-DefenderXDRIndicators -Indicators $indicators
                $result.value.Count | Should -Be 3
            }
        }
    }

    Context 'Batch Processing' {
        It 'calls Invoke-DefenderXDRRequest for bulk import' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { 
                    return @{ value = @(@{ id = 'indicator-1' }) }
                } -Verifiable
                
                $indicators = @(
                    @{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert'; title = 'Test'; description = 'Test' }
                )
                Import-DefenderXDRIndicators -Indicators $indicators
                Should -Invoke Invoke-DefenderXDRRequest -Times 1
            }
        }

        It 'imports multiple indicators' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { $script:hasPermission = $true }
                Mock Invoke-DefenderXDRRequest { 
                    return @{ value = @(@{ id = 'indicator-1' }, @{ id = 'indicator-2' }) }
                }
                
                $indicators = @(
                    @{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert'; title = 'Test'; description = 'Test' }
                    @{ indicatorValue = 'evil.com'; indicatorType = 'DomainName'; action = 'Alert'; title = 'Test'; description = 'Test' }
                )
                $result = Import-DefenderXDRIndicators -Indicators $indicators
                $result.value.Count | Should -Be 2
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates Ti.ReadWrite permission' {
            InModuleScope DefenderXDR {
                $script:hasPermission = $true
                Mock Test-DefenderXDRPermission { 
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'Ti.ReadWrite'
                }
                Mock Invoke-DefenderXDRRequest { return @{ value = @(@{ id = 'indicator-1' }) } }
                
                $indicators = @(@{ indicatorValue = '1.2.3.4'; indicatorType = 'IpAddress'; action = 'Alert'; title = 'Test'; description = 'Test' })
                Import-DefenderXDRIndicators -Indicators $indicators
            }
        }
    }
}
