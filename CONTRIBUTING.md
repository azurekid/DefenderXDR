# Contributing to DefenderXDR

Thank you for your interest in contributing to the DefenderXDR PowerShell module! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful and professional in all interactions. We aim to create a welcoming environment for all contributors.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- PowerShell version and OS information
- Module version

### Suggesting Enhancements

Enhancement suggestions are welcome! Please create an issue with:
- A clear description of the enhancement
- Use cases and benefits
- Any potential drawbacks or concerns

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

### Prerequisites

- PowerShell 7.x (recommended for development)
- Git
- PSScriptAnalyzer module
- Pester module (for testing)

### Clone and Setup

```powershell
# Clone your fork
git clone https://github.com/YOUR-USERNAME/DefenderXDR.git
cd DefenderXDR

# Install development dependencies
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Install-Module -Name Pester -Scope CurrentUser -Force
```

## Coding Standards

### PowerShell Style Guide

Follow these conventions:

1. **Naming Conventions**
   - Use PascalCase for function names
   - Use approved PowerShell verbs (Get, Set, New, Remove, etc.)
   - Prefix all functions with `DefenderXDR`

2. **Function Structure**
   ```powershell
   function Verb-DefenderXDRNoun {
       <#
       .SYNOPSIS
           Brief description
       .DESCRIPTION
           Detailed description
       .PARAMETER ParameterName
           Parameter description
       .EXAMPLE
           Example usage
       #>
       [CmdletBinding()]
       param (
           [Parameter(Mandatory = $true)]
           [string]$ParameterName
       )

       # Implementation
   }
   ```

3. **Comment-Based Help**
   - Every function must have help documentation
   - Include .SYNOPSIS, .DESCRIPTION, .PARAMETER, and .EXAMPLE
   - Provide at least one example

4. **Error Handling**
   - Use try-catch blocks for error handling
   - Write meaningful error messages
   - Use Write-Error for errors
   - Use Write-Warning for warnings
   - Use Write-Verbose for detailed logging

5. **Parameter Validation**
   - Use ValidateSet for enumerated values
   - Use Mandatory = $true for required parameters
   - Provide default values where appropriate

### Code Quality

Run PSScriptAnalyzer before submitting:

```powershell
Invoke-ScriptAnalyzer -Path ./DefenderXDR -Recurse -Severity Warning,Error
```

All code must pass PSScriptAnalyzer without warnings or errors.

### Testing

While comprehensive tests are not yet implemented, you should:

1. Test your code manually
2. Verify it works with different parameter combinations
3. Test error scenarios
4. Document your testing approach in the PR

Future: We plan to add Pester tests. Contributions to the test suite are welcome!

## Adding New Functions

When adding a new function:

1. Create the function file in the appropriate directory:
   - `DefenderXDR/Public/` for exported functions
   - `DefenderXDR/Private/` for internal helper functions

2. Follow the naming convention: `Verb-DefenderXDRNoun.ps1`

3. Add the function to the manifest's `FunctionsToExport` array in `DefenderXDR.psd1`

4. Add documentation to README.md

5. Create an example script in `Examples/` if applicable

6. Update CHANGELOG.md

### Example: Adding a New Function

```powershell
# File: DefenderXDR/Public/Get-DefenderXDRNewFeature.ps1

function Get-DefenderXDRNewFeature {
    <#
    .SYNOPSIS
        Brief description
    .DESCRIPTION
        Detailed description
    .PARAMETER ParameterName
        Parameter description
    .EXAMPLE
        Get-DefenderXDRNewFeature -ParameterName "value"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    try {
        $uri = "$script:GraphBaseUri/$script:GraphAPIVersion/security/newfeature"
        $response = Invoke-DefenderXDRRequest -Uri $uri -Method GET
        return $response
    }
    catch {
        Write-Error "Failed to get new feature: $_"
        throw
    }
}
```

Then update `DefenderXDR.psd1`:

```powershell
FunctionsToExport = @(
    'Connect-DefenderXDR',
    # ... existing functions ...
    'Get-DefenderXDRNewFeature'  # Add your new function
)
```

## Documentation

### README Updates

When adding features, update README.md with:
- Function description
- Usage examples
- Any new prerequisites or configuration

### CHANGELOG Updates

Follow the Keep a Changelog format:

```markdown
## [Unreleased]

### Added
- New function `Get-DefenderXDRNewFeature` for retrieving new feature data

### Changed
- Improved error handling in `Get-DefenderXDRAlert`

### Fixed
- Fixed issue with token expiration in `Connect-DefenderXDR`
```

## Git Workflow

### Commit Messages

Use clear, descriptive commit messages:

```
Add Get-DefenderXDRThreatActors function

- Implement new function to retrieve threat actor information
- Add parameter validation and error handling
- Include example in documentation
```

### Branch Naming

- Feature branches: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`

## Review Process

All pull requests will be reviewed for:

1. **Code Quality**
   - Follows PowerShell best practices
   - Passes PSScriptAnalyzer
   - Proper error handling
   - Consistent with existing code style

2. **Documentation**
   - Comment-based help is complete
   - README is updated if needed
   - CHANGELOG is updated
   - Examples are provided if applicable

3. **Functionality**
   - Code works as expected
   - Doesn't break existing functionality
   - Handles edge cases

## Questions?

If you have questions about contributing, please:
- Check existing issues and documentation
- Open a new issue for discussion
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to DefenderXDR! 🎉
