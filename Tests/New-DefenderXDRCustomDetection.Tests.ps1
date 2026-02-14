BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'New-DefenderXDRCustomDetection' {
    Context 'Parameter Validation' {
        It 'has DisplayName as mandatory parameter' {
            $cmd = Get-Command New-DefenderXDRCustomDetection
            $cmd.Parameters['DisplayName'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
        }

        It 'has Description as mandatory parameter' {
            $cmd = Get-Command New-DefenderXDRCustomDetection
            $cmd.Parameters['Description'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
        }

        It 'has Query as mandatory parameter' {
            $cmd = Get-Command New-DefenderXDRCustomDetection
            $cmd.Parameters['Query'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
        }

        It 'has Severity as mandatory parameter' {
            $cmd = Get-Command New-DefenderXDRCustomDetection
            $cmd.Parameters['Severity'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
        }

        It 'rejects empty DisplayName' {
            { New-DefenderXDRCustomDetection -DisplayName '' -Description 'test' -Query 'test' -Severity High } | Should -Throw
        }

        It 'validates Severity accepts only valid values' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)

                $validSeverities = @('Informational', 'Low', 'Medium', 'High')
                foreach ($severity in $validSeverities) {
                    Mock Test-DefenderXDRPermission { }
                    Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }

                    { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'DeviceProcessEvents | take 10' -Severity $severity } | Should -Not -Throw
                }
            }
        }

        It 'rejects invalid Severity value' {
            { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity 'Critical' } | Should -Throw
        }

        It 'validates Category accepts only valid Defender categories' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }

                { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Category 'Execution' } | Should -Not -Throw
            }
        }

        It 'rejects invalid Category value' {
            { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Category 'General' } | Should -Throw
        }

        It 'validates Period accepts only valid period strings' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }

                foreach ($p in @('1H', '2H', '4H', '8H', '12H', '24H')) {
                    { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Period $p } | Should -Not -Throw
                }
            }
        }

        It 'rejects invalid Period value' {
            { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Period '3H' } | Should -Throw
        }

        It 'validates MitreTechniques format rejects invalid IDs' {
            { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -MitreTechniques @('INVALID') } | Should -Throw
        }

        It 'accepts valid MITRE technique IDs' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }

                { New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -MitreTechniques @('T1059', 'T1059.001') } | Should -Not -Throw
            }
        }
    }

    Context 'Request Body - Graph API Schema Compliance' {
        It 'schedule.period is a single string, not an array' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.schedule.period | Should -BeOfType [string]
                    $Body.schedule.period | Should -Be '24H'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Period '24H'
            }
        }

        It 'maps FrequencyMinutes 60 to period 1H as a single string' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.schedule.period | Should -BeOfType [string]
                    $Body.schedule.period | Should -Be '1H'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -FrequencyMinutes 60
            }
        }

        It 'maps FrequencyMinutes 120 to period 2H' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.schedule.period | Should -Be '2H'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Low -FrequencyMinutes 120
            }
        }

        It 'maps FrequencyMinutes 720 to period 12H' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.schedule.period | Should -Be '12H'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Low -FrequencyMinutes 720
            }
        }

        It '-Period takes precedence over -FrequencyMinutes' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.schedule.period | Should -Be '12H'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Period '12H' -FrequencyMinutes 60
            }
        }

        It 'mitreTechniques serializes as empty array, not null' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    # Verify JSON serialization produces [] not null
                    # This is what the Graph API actually receives
                    $json = $Body | ConvertTo-Json -Depth 10
                    $json | Should -Match '"mitreTechniques":\s*\[\s*\]'
                    $json | Should -Not -Match '"mitreTechniques":\s*null'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
            }
        }

        It 'mitreTechniques includes provided techniques' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $mt = $Body.detectionAction.alertTemplate.mitreTechniques
                    $mt | Should -Contain 'T1059.001'
                    $mt | Should -Contain 'T1105'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -MitreTechniques @('T1059.001', 'T1105')
            }
        }

        It 'category defaults to SuspiciousActivity when not provided' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.detectionAction.alertTemplate.category | Should -Be 'SuspiciousActivity'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
            }
        }

        It 'category uses provided value' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.detectionAction.alertTemplate.category | Should -Be 'Execution'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High -Category 'Execution'
            }
        }

        It 'alertTemplate contains all required fields' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $at = $Body.detectionAction.alertTemplate
                    $at.title              | Should -Not -BeNullOrEmpty
                    $at.description        | Should -Not -BeNullOrEmpty
                    $at.severity           | Should -Match '^(informational|low|medium|high)$'
                    $at.category           | Should -Not -BeNullOrEmpty
                    $at.Keys               | Should -Contain 'recommendedActions'
                    $at.Keys               | Should -Contain 'mitreTechniques'
                    $at.Keys               | Should -Contain 'impactedAssets'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Desc' -Query 'test' -Severity High
            }
        }

        It 'detectionAction includes organizationalScope and responseActions' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.detectionAction.Keys | Should -Contain 'organizationalScope'
                    $Body.detectionAction.Keys | Should -Contain 'responseActions'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
            }
        }

        It 'auto-detects deviceId impactedAsset for Device* table queries' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $assets = $Body.detectionAction.alertTemplate.impactedAssets
                    $assets.Count | Should -Be 1
                    $assets[0].identifier | Should -Be 'deviceId'
                    $assets[0].'@odata.type' | Should -Be '#microsoft.graph.security.impactedDeviceAsset'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'DeviceProcessEvents | take 1' -Severity High
            }
        }

        It 'sets empty impactedAssets for non-Device table queries' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.detectionAction.alertTemplate.impactedAssets.Count | Should -Be 0
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'CloudAppEvents | take 1' -Severity High
            }
        }

        It 'severity is lowercased in the body' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $Body.detectionAction.alertTemplate.severity | Should -BeExactly 'high'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
            }
        }

        It 'body serializes to valid JSON matching Graph API schema' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method, $Body)
                    $json = $Body | ConvertTo-Json -Depth 10
                    $parsed = $json | ConvertFrom-Json

                    # Top-level
                    $parsed.displayName | Should -Not -BeNullOrEmpty
                    $parsed.PSObject.Properties.Name | Should -Contain 'isEnabled'

                    # queryCondition
                    $parsed.queryCondition.queryText | Should -Not -BeNullOrEmpty

                    # schedule
                    $parsed.schedule.period | Should -Match '^\d+H$'

                    # detectionAction.alertTemplate
                    $parsed.detectionAction.alertTemplate.title    | Should -Not -BeNullOrEmpty
                    $parsed.detectionAction.alertTemplate.severity | Should -Match '^(informational|low|medium|high)$'
                    $parsed.detectionAction.alertTemplate.category | Should -Not -BeNullOrEmpty

                    # mitreTechniques is array (not null)
                    $json | Should -Match '"mitreTechniques":\s*\['

                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test Rule' -Description 'Test Desc' -Query 'DeviceProcessEvents | take 1' -Severity Medium -Category Execution
            }
        }
    }

    Context 'API Endpoint' {
        It 'posts to Graph beta security detectionRules endpoint' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri)
                    $Uri | Should -Be 'https://graph.microsoft.com/beta/security/rules/detectionRules'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Medium
            }
        }

        It 'uses EndpointUri override when provided' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri)
                    $Uri | Should -Be 'https://custom.endpoint.com/api/rules'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Medium -EndpointUri 'https://custom.endpoint.com/api/rules'
            }
        }

        It 'sends POST method' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    param($Uri, $Method)
                    $Method | Should -Be 'POST'
                    return @{ id = 'new-rule' }
                }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity Medium
            }
        }
    }

    Context 'Response Handling' {
        It 'returns created detection rule object' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission { }
                Mock Invoke-DefenderXDRRequest {
                    return @{
                        id          = 'new-rule-123'
                        displayName = 'Test Rule'
                        isEnabled   = $true
                    }
                }

                $result = New-DefenderXDRCustomDetection -DisplayName 'Test Rule' -Description 'Test' -Query 'test' -Severity High
                $result.id | Should -Be 'new-rule-123'
            }
        }
    }

    Context 'Permission Validation' {
        It 'validates CustomDetection.ReadWrite.All permission' {
            InModuleScope DefenderXDR {
                $script:AccessToken = 'mock_token'
                $script:TokenExpiration = (Get-Date).AddHours(1)
                Mock Test-DefenderXDRPermission {
                    param($RequiredPermissions)
                    $RequiredPermissions | Should -Contain 'CustomDetection.ReadWrite.All'
                }
                Mock Invoke-DefenderXDRRequest { return @{ id = 'new-rule' } }

                New-DefenderXDRCustomDetection -DisplayName 'Test' -Description 'Test' -Query 'test' -Severity High
            }
        }
    }
}
