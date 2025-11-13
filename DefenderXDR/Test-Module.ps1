#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the DefenderXDR module structure and functionality
.DESCRIPTION
    This script performs basic validation tests on the DefenderXDR module
    without requiring actual API credentials. It validates:
    - Module loads correctly
    - All expected functions are exported
    - Help documentation is available
    - Parameter validation works
#>

[CmdletBinding()]
param()

# Test results
$testResults = @()

function Test-Result {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )
    
    $result = [PSCustomObject]@{
        Test    = $TestName
        Result  = if ($Passed) { "PASS" } else { "FAIL" }
        Message = $Message
    }
    
    $script:testResults += $result
    
    if ($Passed) {
        Write-Host "[PASS] $TestName" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $TestName - $Message" -ForegroundColor Red
    }
}

Write-Host "`n=== DefenderXDR Module Validation Tests ===`n" -ForegroundColor Cyan

# Test 1: Module file exists
$modulePath = Join-Path $PSScriptRoot "DefenderXDR.psd1"
$moduleExists = Test-Path $modulePath
Test-Result -TestName "Module manifest exists" -Passed $moduleExists -Message $(if (-not $moduleExists) { "DefenderXDR.psd1 not found" })

# Test 2: Module imports successfully
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    Test-Result -TestName "Module imports successfully" -Passed $true
} catch {
    Test-Result -TestName "Module imports successfully" -Passed $false -Message $_.Exception.Message
    return
}

# Test 3: Expected functions are exported
$expectedFunctions = @(
    'Connect-DefenderXDR',
    'Disconnect-DefenderXDR',
    'Get-DefenderXDRTIIndicator',
    'New-DefenderXDRTIIndicator',
    'Set-DefenderXDRTIIndicator',
    'Remove-DefenderXDRTIIndicator',
    'Import-DefenderXDRTIIndicator',
    'Export-DefenderXDRTIIndicator'
)

$exportedCommands = Get-Command -Module DefenderXDR
$allFunctionsExported = $true
$missingFunctions = @()

foreach ($funcName in $expectedFunctions) {
    if ($funcName -notin $exportedCommands.Name) {
        $allFunctionsExported = $false
        $missingFunctions += $funcName
    }
}

$message = if (-not $allFunctionsExported) { "Missing: $($missingFunctions -join ', ')" } else { "" }
Test-Result -TestName "All expected functions exported ($($expectedFunctions.Count) functions)" -Passed $allFunctionsExported -Message $message

# Test 4: Each function has help documentation
$functionsWithHelp = 0
foreach ($funcName in $expectedFunctions) {
    $help = Get-Help $funcName -ErrorAction SilentlyContinue
    if ($help -and $help.Synopsis) {
        $functionsWithHelp++
    }
}
$allHaveHelp = $functionsWithHelp -eq $expectedFunctions.Count
Test-Result -TestName "All functions have help documentation" -Passed $allHaveHelp -Message "($functionsWithHelp/$($expectedFunctions.Count) have help)"

# Test 5: Connect-DefenderXDR has required parameters
$connectCmd = Get-Command Connect-DefenderXDR
$hasRequiredParams = ($connectCmd.Parameters.ContainsKey('TenantId') -and 
                      $connectCmd.Parameters.ContainsKey('AppId') -and
                      $connectCmd.Parameters.ContainsKey('AppSecret') -and
                      $connectCmd.Parameters.ContainsKey('AccessToken'))
Test-Result -TestName "Connect-DefenderXDR has required parameters" -Passed $hasRequiredParams

# Test 6: New-DefenderXDRTIIndicator validates indicator types
$newCmd = Get-Command New-DefenderXDRTIIndicator
$indicatorTypeParam = $newCmd.Parameters['IndicatorType']
$hasValidation = $null -ne ($indicatorTypeParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] })
Test-Result -TestName "New-DefenderXDRTIIndicator validates indicator types" -Passed ([bool]$hasValidation)

# Test 7: New-DefenderXDRTIIndicator validates actions
$actionParam = $newCmd.Parameters['Action']
$hasActionValidation = $null -ne ($actionParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] })
Test-Result -TestName "New-DefenderXDRTIIndicator validates actions" -Passed ([bool]$hasActionValidation)

# Test 8: New-DefenderXDRTIIndicator supports ShouldProcess (WhatIf)
$supportsShouldProcess = $newCmd.Parameters.Keys -contains 'WhatIf'
Test-Result -TestName "New-DefenderXDRTIIndicator supports WhatIf" -Passed $supportsShouldProcess

# Test 9: Remove-DefenderXDRTIIndicator supports ShouldProcess
$removeCmd = Get-Command Remove-DefenderXDRTIIndicator
$removeSupportsShouldProcess = $removeCmd.Parameters.Keys -contains 'WhatIf'
Test-Result -TestName "Remove-DefenderXDRTIIndicator supports WhatIf" -Passed $removeSupportsShouldProcess

# Test 10: Module metadata is valid
$moduleInfo = Get-Module DefenderXDR
$hasValidMetadata = ($moduleInfo.Version -and 
                     $moduleInfo.Description -and
                     $moduleInfo.Author)
Test-Result -TestName "Module has valid metadata" -Passed $hasValidMetadata

# Test 11: Sample CSV file exists
$sampleCsvPath = Join-Path $PSScriptRoot "sample-indicators.csv"
$sampleCsvExists = Test-Path $sampleCsvPath
Test-Result -TestName "Sample CSV file exists" -Passed $sampleCsvExists

# Test 12: README.md exists
$readmePath = Join-Path $PSScriptRoot "README.md"
$readmeExists = Test-Path $readmePath
Test-Result -TestName "README.md exists" -Passed $readmeExists

# Test 13: Examples.md exists
$examplesPath = Join-Path $PSScriptRoot "Examples.md"
$examplesExists = Test-Path $examplesPath
Test-Result -TestName "Examples.md exists" -Passed $examplesExists

# Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
$passCount = ($testResults | Where-Object { $_.Result -eq "PASS" }).Count
$failCount = ($testResults | Where-Object { $_.Result -eq "FAIL" }).Count
$totalCount = $testResults.Count

Write-Host "Total Tests: $totalCount" -ForegroundColor White
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

# Display results table
Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
$testResults | Format-Table -AutoSize

# Exit code
if ($failCount -gt 0) {
    Write-Host "`nSome tests failed. Please review the results above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll tests passed successfully! ✓" -ForegroundColor Green
    exit 0
}
