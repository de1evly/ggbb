$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$file = Join-Path (Split-Path $PSScriptRoot) 'install.ps1'
[System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
Write-Host 'PowerShell installer syntax OK.'
