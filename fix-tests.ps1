$testFiles = Get-ChildItem -Path ./Tests -Filter *.Tests.ps1 | 
    Where-Object { $_.Name -notin @("Get-DefenderXDRAccessToken.Tests.ps1", "Get-DefenderXDRAlert.Tests.ps1", "DefenderXDR.Tests.ps1") }

$totalFiles = $testFiles.Count
$counter = 0

foreach ($file in $testFiles) {
    $counter++
    Write-Host "[$counter/$totalFiles] Processing: $($file.Name)" -ForegroundColor Cyan
    
    $content = Get-Content -Path $file.FullName -Raw
    
    # Skip if already has InModuleScope
    if ($content -match "InModuleScope DefenderXDR") {
        Write-Host "  Already has InModuleScope, skipping" -ForegroundColor Yellow
        continue
    }
    
    # Replace BeforeAll to remove script scope variable assignments
    $content = $content -replace '(?s)BeforeAll \{[^}]+\}', @"
BeforeAll {
    `$projectRoot = Split-Path -Parent `$PSScriptRoot
    `$manifestPath = Join-Path `$projectRoot ''DefenderXDR.psd1''
    Import-Module `$manifestPath -Force
}
"@
    
    # Wrap each It block content with InModuleScope
    $content = [regex]::Replace($content, '(?ms)(        It ''[^'']+'' \{)\s*(.*?)(\n        \})', {
        param($match)
        $itDeclaration = $match.Groups[1].Value
        $itContent = $match.Groups[2].Value
        $closingBrace = $match.Groups[3].Value
        
        # Check if content already has InModuleScope or if it''s just a simple parameter validation test
        if ($itContent -match "InModuleScope" -or $itContent -notmatch "(Mock|`\$script:|Get-DefenderXDR|Connect-DefenderXDR|Disconnect-DefenderXDR|Invoke-DefenderXDR|New-DefenderXDR|Update-DefenderXDR|Remove-DefenderXDR|Submit-DefenderXDR|Import-DefenderXDR|Set-DefenderXDR|Test-DefenderXDR)") {
            return $match.Value
        }
        
        # Indent the content
        $indentedContent = ($itContent -split "`n" | ForEach-Object { "    $_" }) -join "`n"
        
        return "$itDeclaration`n            InModuleScope DefenderXDR {$indentedContent`n            }$closingBrace"
    })
    
    # Save the file
    Set-Content -Path $file.FullName -Value $content -NoNewline
    Write-Host "  Fixed!" -ForegroundColor Green
}

Write-Host "`nCompleted processing $totalFiles files" -ForegroundColor Green
