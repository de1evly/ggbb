$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$file = Join-Path (Split-Path $PSScriptRoot) 'install.ps1'
[System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
# Also parse the generated launcher literal, which ParseFile only sees as text.
$source = Get-Content $file -Raw
$launcher = [regex]::Match($source, '(?s)\$launcher = @''\r?\n(.*?)\r?\n''@').Groups[1].Value
if (-not $launcher) { throw 'Launcher literal not found.' }
[System.Management.Automation.Language.Parser]::ParseInput($launcher, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
Write-Host 'PowerShell installer syntax OK.'
