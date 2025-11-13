# Test script for Get-DefenderXDRIndicators function
# This script validates the function structure and parameters

Write-Host "Testing Get-DefenderXDRIndicators function..." -ForegroundColor Cyan

# Import the function
. ./Get-DefenderXDRIndicators.ps1

Write-Host "`n✓ Function loaded successfully" -ForegroundColor Green

# Test 1: Verify function exists
Write-Host "`nTest 1: Verifying function exists..." -ForegroundColor Yellow
$function = Get-Command Get-DefenderXDRIndicators -ErrorAction SilentlyContinue
if ($function) {
    Write-Host "✓ Function Get-DefenderXDRIndicators exists" -ForegroundColor Green
} else {
    Write-Host "✗ Function Get-DefenderXDRIndicators not found" -ForegroundColor Red
    exit 1
}

# Test 2: Verify function has correct parameters
Write-Host "`nTest 2: Verifying function parameters..." -ForegroundColor Yellow
$parameters = $function.Parameters.Keys
$requiredParams = @('TenantId', 'AppId', 'AppSecret')
$optionalParams = @('IndicatorId')

foreach ($param in $requiredParams) {
    if ($parameters -contains $param) {
        Write-Host "✓ Required parameter '$param' exists" -ForegroundColor Green
    } else {
        Write-Host "✗ Required parameter '$param' missing" -ForegroundColor Red
        exit 1
    }
}

foreach ($param in $optionalParams) {
    if ($parameters -contains $param) {
        Write-Host "✓ Optional parameter '$param' exists" -ForegroundColor Green
    } else {
        Write-Host "✗ Optional parameter '$param' missing" -ForegroundColor Red
        exit 1
    }
}

# Test 3: Verify help documentation exists
Write-Host "`nTest 3: Verifying help documentation..." -ForegroundColor Yellow
$help = Get-Help Get-DefenderXDRIndicators -ErrorAction SilentlyContinue
if ($help) {
    Write-Host "✓ Help documentation exists" -ForegroundColor Green
    if ($help.Synopsis) {
        Write-Host "✓ Synopsis exists: $($help.Synopsis)" -ForegroundColor Green
    }
    if ($help.Description) {
        Write-Host "✓ Description exists" -ForegroundColor Green
    }
    if ($help.examples.example.Count -gt 0) {
        Write-Host "✓ Examples exist (Count: $($help.examples.example.Count))" -ForegroundColor Green
    }
} else {
    Write-Host "✗ Help documentation not found" -ForegroundColor Red
    exit 1
}

# Test 4: Verify parameter types
Write-Host "`nTest 4: Verifying parameter types..." -ForegroundColor Yellow
$tenantIdParam = $function.Parameters['TenantId']
if ($tenantIdParam.ParameterType.Name -eq 'String') {
    Write-Host "✓ TenantId is String type" -ForegroundColor Green
} else {
    Write-Host "✗ TenantId type incorrect" -ForegroundColor Red
    exit 1
}

$appIdParam = $function.Parameters['AppId']
if ($appIdParam.ParameterType.Name -eq 'String') {
    Write-Host "✓ AppId is String type" -ForegroundColor Green
} else {
    Write-Host "✗ AppId type incorrect" -ForegroundColor Red
    exit 1
}

$appSecretParam = $function.Parameters['AppSecret']
if ($appSecretParam.ParameterType.Name -eq 'SecureString') {
    Write-Host "✓ AppSecret is SecureString type" -ForegroundColor Green
} else {
    Write-Host "✗ AppSecret type incorrect" -ForegroundColor Red
    exit 1
}

# Test 5: Verify mandatory parameters
Write-Host "`nTest 5: Verifying mandatory parameters..." -ForegroundColor Yellow
$mandatoryParams = @('TenantId', 'AppId', 'AppSecret')
foreach ($paramName in $mandatoryParams) {
    $param = $function.Parameters[$paramName]
    $isMandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } | Select-Object -ExpandProperty Mandatory
    if ($isMandatory) {
        Write-Host "✓ Parameter '$paramName' is mandatory" -ForegroundColor Green
    } else {
        Write-Host "✗ Parameter '$paramName' should be mandatory" -ForegroundColor Red
        exit 1
    }
}

# Test 6: Verify IndicatorId is optional
Write-Host "`nTest 6: Verifying optional parameters..." -ForegroundColor Yellow
$indicatorIdParam = $function.Parameters['IndicatorId']
$isMandatory = $indicatorIdParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } | Select-Object -ExpandProperty Mandatory
if (-not $isMandatory) {
    Write-Host "✓ Parameter 'IndicatorId' is optional" -ForegroundColor Green
} else {
    Write-Host "✗ Parameter 'IndicatorId' should be optional" -ForegroundColor Red
    exit 1
}

Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "All tests passed successfully!" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Cyan
