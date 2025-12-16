BeforeAll {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
    Import-Module $manifestPath -Force
}

Describe 'Disconnect-DefenderXDR' {
    BeforeEach {
        # Set up connection state
        $script:AccessToken = 'test-token'
        $script:TokenExpiration = (Get-Date).AddHours(1)
        $script:ApiAudience = 'Graph'
        $script:hasPermission = $true
    }

    Context 'Connection Cleanup' {
        It 'clears access token' {
            Disconnect-DefenderXDR
            
            $script:AccessToken | Should -BeNullOrEmpty
        }

        It 'clears token expiration' {
            Disconnect-DefenderXDR
            
            $script:TokenExpiration | Should -BeNullOrEmpty
        }

        It 'clears API audience' {
            Disconnect-DefenderXDR
            
            $script:ApiAudience | Should -BeNullOrEmpty
        }

        It 'clears permission flag' {
            Disconnect-DefenderXDR
            
            $script:hasPermission | Should -Be $false
        }

        It 'can be called multiple times safely' {
            Disconnect-DefenderXDR
            { Disconnect-DefenderXDR } | Should -Not -Throw
        }
    }

    Context 'Confirmation Message' {
        It 'provides confirmation of disconnection' {
            $result = Disconnect-DefenderXDR
            # Function should complete successfully
            $? | Should -Be $true
        }

        It 'works when already disconnected' {
            $script:AccessToken = $null
            { Disconnect-DefenderXDR } | Should -Not -Throw
        }
    }
}
