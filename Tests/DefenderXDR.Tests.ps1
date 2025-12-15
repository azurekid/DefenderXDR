$testsFolder = Split-Path -Parent $PSCommandPath
$projectRoot = Split-Path -Parent $testsFolder
$manifestPath = Join-Path $projectRoot 'DefenderXDR.psd1'
$publicFolder = Join-Path $projectRoot 'Public'
$publicFunctionFiles = Get-ChildItem -Path $publicFolder -Filter '*.ps1' -File | Select-Object -ExpandProperty BaseName

Describe 'DefenderXDR module quality checks' {
    BeforeAll {
        Import-Module $manifestPath -Force -ErrorAction Stop
        $script:moduleUnderTest = Get-Module DefenderXDR -ErrorAction Stop
        $script:exportedFunctions = @($script:moduleUnderTest.ExportedFunctions.Keys)
    }

    AfterAll {
        Remove-Module DefenderXDR -Force -ErrorAction SilentlyContinue
    }

    It 'imports the module without error' {
        $script:moduleUnderTest | Should -Not -BeNullOrEmpty
    }

    It 'exports at least one public function' {
        $script:exportedFunctions.Count | Should -BeGreaterThan 0
    }

    Context 'Public folder coverage' {
        foreach ($functionName in $publicFunctionFiles | Sort-Object) {
            It "$functionName is exported via the manifest" {
                $script:exportedFunctions | Should -Contain $functionName
            }
        }
    }

    Context 'Exported function metadata' {
        foreach ($functionName in $script:exportedFunctions | Sort-Object) {
            It "$functionName is available as a command" {
                Get-Command -Name $functionName -Module $script:moduleUnderTest.Name -ErrorAction Stop | Should -Not -BeNullOrEmpty
            }

            It "$functionName includes comment-based help" {
                $help = Get-Help -Name $functionName -ErrorAction Stop
                $help | Should -Not -BeNullOrEmpty
                $help.Synopsis.Trim() | Should -Not -BeNullOrEmpty
            }
        }
    }
}
