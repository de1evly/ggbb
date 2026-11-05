param([Parameter(Mandatory=$true)][string]$InstallDir)
$ErrorActionPreference = 'Stop'
$current = Get-Content (Join-Path $InstallDir 'current.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$bin = Join-Path $current.source 'bin/zapret2'
# --dry-run parses native CLI arguments and exits before opening WinDivert.
# It does NOT verify Lua execution, driver loading, or bypass on a provider.
foreach ($profile in @('alt1', 'alt2', 'alt3', 'alt4')) {
    $argumentsJson = & $current.python -c 'import json,sys; from pathfinder.packet_profiles import build_args; print(json.dumps(build_args(sys.argv[1],sys.argv[2])))' $bin $profile
    if ($LASTEXITCODE -ne 0) { throw 'Cannot generate packet arguments.' }
    $nativeArguments = @($argumentsJson | ConvertFrom-Json)
    & (Join-Path $bin 'winws2.exe') --dry-run @nativeArguments
    if ($LASTEXITCODE -ne 0) { throw "winws2 rejected $profile (exit $LASTEXITCODE)." }
}
Write-Host 'Four native ALT command lines parsed; no packet driver was opened.'
