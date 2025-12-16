#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Validation script to ensure classes follow PowerShell community standards
.DESCRIPTION
    Tests that the DefenderXDR module classes work correctly with standard PowerShell syntax
#>

using module ./DefenderXDR.psd1

Write-Host "`n=== DefenderXDR Class Standard Compliance Test ===" -ForegroundColor Cyan

$testsPassed = 0
$testsFailed = 0

function Test-ClassConstructor {
    param([string]$TestName, [scriptblock]$Test)
    
    try {
        & $Test
        Write-Host "✓ $TestName" -ForegroundColor Green
        $script:testsPassed++
    }
    catch {
        Write-Host "✗ $TestName - $_" -ForegroundColor Red
        $script:testsFailed++
    }
}

Write-Host "`nTesting DefenderAlert class..." -ForegroundColor Yellow
Test-ClassConstructor "DefenderAlert empty constructor" {
    $alert = [DefenderAlert]::new()
    if ($null -eq $alert) { throw "Constructor returned null" }
}

Test-ClassConstructor "DefenderAlert with ID" {
    $alert = [DefenderAlert]::new('test-id')
    if ($alert.AlertId -ne 'test-id') { throw "AlertId not set correctly" }
}

Test-ClassConstructor "DefenderAlert full constructor" {
    $alert = [DefenderAlert]::new('test-id', 'Test Title', 'High')
    if ($alert.Severity -ne 'High') { throw "Severity not set correctly" }
}

Test-ClassConstructor "DefenderAlert UpdateStatus method" {
    $alert = [DefenderAlert]::new('test-id')
    $alert.UpdateStatus('inProgress')
    if ($alert.Status -ne 'inProgress') { throw "Status not updated" }
}

Test-ClassConstructor "DefenderAlert AddComment method" {
    $alert = [DefenderAlert]::new('test-id')
    $alert.AddComment('Test comment')
    if ($alert.Comments.Count -ne 1) { throw "Comment not added" }
}

Write-Host "`nTesting DefenderIncident class..." -ForegroundColor Yellow
Test-ClassConstructor "DefenderIncident empty constructor" {
    $incident = [DefenderIncident]::new()
    if ($null -eq $incident) { throw "Constructor returned null" }
}

Test-ClassConstructor "DefenderIncident with ID" {
    $incident = [DefenderIncident]::new('inc-id')
    if ($incident.IncidentId -ne 'inc-id') { throw "IncidentId not set correctly" }
}

Test-ClassConstructor "DefenderIncident full constructor" {
    $incident = [DefenderIncident]::new('inc-id', 'Test Incident', 'Medium')
    if ($incident.Severity -ne 'Medium') { throw "Severity not set correctly" }
}

Test-ClassConstructor "DefenderIncident AssignTo method" {
    $incident = [DefenderIncident]::new('inc-id')
    $incident.AssignTo('user@example.com')
    if ($incident.AssignedTo -ne 'user@example.com') { throw "Assignment failed" }
}

Write-Host "`nTesting DefenderIndicator class..." -ForegroundColor Yellow
Test-ClassConstructor "DefenderIndicator empty constructor" {
    $indicator = [DefenderIndicator]::new()
    if ($null -eq $indicator) { throw "Constructor returned null" }
}

Test-ClassConstructor "DefenderIndicator with value and type" {
    $indicator = [DefenderIndicator]::new('192.168.1.1', 'IpAddress')
    if ($indicator.IndicatorValue -ne '192.168.1.1') { throw "IndicatorValue not set" }
}

Test-ClassConstructor "DefenderIndicator full constructor" {
    $indicator = [DefenderIndicator]::new('malicious.com', 'DomainName', 'Block', 'High')
    if ($indicator.Action -ne 'Block') { throw "Action not set correctly" }
}

Write-Host "`nTesting DefenderQueryResult class..." -ForegroundColor Yellow
Test-ClassConstructor "DefenderQueryResult empty constructor" {
    $result = [DefenderQueryResult]::new()
    if ($null -eq $result) { throw "Constructor returned null" }
}

Test-ClassConstructor "DefenderQueryResult with data" {
    $data = @(@{ Name = 'Test' })
    $result = [DefenderQueryResult]::new($data)
    if ($result.Count() -ne 1) { throw "Data not loaded correctly" }
}

Test-ClassConstructor "DefenderQueryResult Where method" {
    $data = @(@{ Name = 'Test1' }, @{ Name = 'Test2' })
    $result = [DefenderQueryResult]::new($data)
    $filtered = $result.Where({ $_.Name -eq 'Test1' })
    if ($filtered.Count -ne 1) { throw "Where method failed" }
}

Write-Host "`nTesting DefenderValidator class..." -ForegroundColor Yellow
Test-ClassConstructor "ValidateSeverity with valid input" {
    [DefenderValidator]::ValidateSeverity('High')
}

Test-ClassConstructor "ValidateSeverity rejects invalid input" {
    try {
        [DefenderValidator]::ValidateSeverity('Invalid')
        throw "Should have thrown exception"
    }
    catch {
        if ($_.Exception.Message -notlike "*Invalid severity*") {
            throw "Wrong exception message"
        }
    }
}

Test-ClassConstructor "ValidateIpAddress with valid input" {
    [DefenderValidator]::ValidateIpAddress('192.168.1.1')
}

Test-ClassConstructor "ValidateEmail with valid input" {
    [DefenderValidator]::ValidateEmail('user@example.com')
}

Write-Host "`nTesting DefenderXDRClient class..." -ForegroundColor Yellow
Test-ClassConstructor "DefenderXDRClient empty constructor" {
    $client = [DefenderXDRClient]::new()
    if ($null -eq $client) { throw "Constructor returned null" }
}

Test-ClassConstructor "DefenderXDRClient with parameters" {
    $client = [DefenderXDRClient]::new('tenant-id', 'client-id')
    if ($client.TenantId -ne 'tenant-id') { throw "TenantId not set" }
}

# Summary
Write-Host "`n=== Test Results ===" -ForegroundColor Cyan
Write-Host "Tests Passed: $testsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Red' })

if ($testsFailed -eq 0) {
    Write-Host "`n✓ All tests passed! Classes follow PowerShell community standards." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`n✗ Some tests failed. Please review the implementation." -ForegroundColor Red
    exit 1
}
