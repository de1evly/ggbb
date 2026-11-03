#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Repository = 'de1evly/ggbb',
    [string]$Ref = 'main',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'PathfinderApp'),
    [string]$LocalSource = '',
    [switch]$PrivateRepository,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This installer supports Windows 10/11.' }
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Invalid repository name.' }
if ($Ref -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Use a branch, tag, or commit without slashes.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$utf8 = New-Object System.Text.UTF8Encoding($false)
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$staging = Join-Path $InstallDir ('staging-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null

function Invoke-GitHubJson([string]$Endpoint) {
    if (-not $PrivateRepository) {
        return Invoke-RestMethod "https://api.github.com/$Endpoint" -Headers @{Accept='application/vnd.github+json'; 'User-Agent'='Pathfinder-Installer'}
    }
    $response = & gh api $Endpoint 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('GitHub request failed. Run gh auth login first. ' + ($response | Out-String)) }
    return (($response | Out-String) | ConvertFrom-Json)
}

try {
    if ($LocalSource) {
        $LocalSource = (Resolve-Path $LocalSource).Path
        if (-not (Test-Path (Join-Path $LocalSource 'pathfinder\__main__.py'))) { throw 'LocalSource is not Pathfinder.' }
        foreach ($folder in @('pathfinder', 'extension')) {
            if (Test-Path (Join-Path $LocalSource $folder)) {
                Copy-Item (Join-Path $LocalSource $folder) $staging -Recurse
            }
        }
        foreach ($file in @('README.md', 'LICENSE', 'install.ps1')) {
            if (Test-Path (Join-Path $LocalSource $file)) { Copy-Item (Join-Path $LocalSource $file) $staging }
        }
        Get-ChildItem $staging -Directory -Recurse -Filter '__pycache__' | Remove-Item -Recurse -Force
        $revision = 'local-' + [Guid]::NewGuid().ToString('N')
    } else {
        if ($PrivateRepository -and -not (Get-Command gh -ErrorAction SilentlyContinue)) {
            throw 'Private repository access requires GitHub CLI. Install it with: winget install --id GitHub.cli -e ; then run gh auth login.'
        }
        $commit = Invoke-GitHubJson "repos/$Repository/commits/$Ref"
        $revision = $commit.sha
        if ($revision -notmatch '^[0-9a-f]{40}$') { throw 'Invalid commit SHA.' }
        $tree = Invoke-GitHubJson "repos/$Repository/git/trees/${revision}?recursive=1"
        if ($tree.truncated -or $tree.tree.Count -gt 200) { throw 'Unexpected repository tree size.' }
        Write-Host "Downloading $Repository at $revision ..."
        foreach ($entry in $tree.tree) {
            if ($entry.type -ne 'blob') { continue }
            if ($entry.mode -notin @('100644', '100755')) { throw 'Links are not supported.' }
            if ($entry.path -notmatch '^[A-Za-z0-9_./-]+$' -or $entry.path -match '(^|/)\.\.(/|$)' -or $entry.path.StartsWith('/')) { throw 'Unsafe repository path.' }
            $destination = Join-Path $staging $entry.path
            New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
            if ($PrivateRepository) {
                $blob = Invoke-GitHubJson "repos/$Repository/git/blobs/$($entry.sha)"
                if ($blob.encoding -ne 'base64') { throw 'Unexpected blob encoding.' }
                $bytes = [Convert]::FromBase64String($blob.content)
            } else {
                Invoke-WebRequest "https://raw.githubusercontent.com/$Repository/$revision/$($entry.path)" -UseBasicParsing -OutFile $destination
                $bytes = [IO.File]::ReadAllBytes($destination)
            }
            $prefix = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
            $sha = [Security.Cryptography.SHA1]::Create()
            try { $actual = ([BitConverter]::ToString($sha.ComputeHash([byte[]]($prefix + $bytes)))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
            if ($actual -ne $entry.sha) { throw 'Git blob hash mismatch.' }
            [IO.File]::WriteAllBytes($destination, $bytes)
        }
    }
    if (-not (Test-Path (Join-Path $staging 'pathfinder\__main__.py'))) { throw 'Downloaded source is incomplete.' }

    # Portable Python; hashes from the official Windows release manifest:
    # https://www.python.org/ftp/python/3.14.10/windows-3.14.10.json
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($architecture) {
        'AMD64' { $arch = 'amd64'; $expected = 'b553e7dac884469b40e0740bb527271c3378f700b427e0485835f1bb6424361c' }
        'ARM64' { $arch = 'arm64'; $expected = '5faf08027ec9d0ae7c346465464aa66bbc2f3b54a37d696c54024825ea29d02d' }
        default { throw '64-bit Windows is required.' }
    }
    $runtime = Join-Path $InstallDir "python-3.14.10-$arch"
    if (-not (Test-Path (Join-Path $runtime 'python.exe'))) {
        $download = Join-Path $staging 'python.zip'
        Write-Host 'Downloading portable Python from python.org ...'
        Invoke-WebRequest "https://www.python.org/ftp/python/3.14.10/python-3.14.10-embeddable-$arch.zip" -UseBasicParsing -OutFile $download
        if ((Get-FileHash $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Python SHA256 mismatch.' }
        $runtimeStaging = Join-Path $staging 'runtime'
        Expand-Archive $download $runtimeStaging
        if (-not (Test-Path (Join-Path $runtimeStaging 'python.exe'))) { throw 'Python archive is incomplete.' }
        Move-Item $runtimeStaging $runtime
        Remove-Item $download
    }
    $versions = Join-Path $InstallDir 'versions'
    New-Item -ItemType Directory -Force -Path $versions | Out-Null
    $source = Join-Path $versions $revision
    if (-not (Test-Path $source)) { Move-Item $staging $source }
    $pythonExe = Join-Path $runtime 'python.exe'
    [IO.File]::WriteAllText((Join-Path $runtime 'python314._pth'), "python314.zip`n.`n$source`n", $utf8)
    & $pythonExe -c 'import ssl, sqlite3, pathfinder'
    if ($LASTEXITCODE -ne 0) { throw 'Runtime check failed.' }
    Write-Host 'Pathfinder runtime ready.'
    $current = @{python = $pythonExe; source = $source; revision = $revision} | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $InstallDir 'current.json'), $current, $utf8)
    $launcher = @'
#requires -Version 5.1
param([switch]$NoProxy, [switch]$RestoreProxy)
$ErrorActionPreference = 'Stop'
$current = Get-Content (Join-Path $PSScriptRoot 'current.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($RestoreProxy) {
    & $current.python -m pathfinder restore-proxy
} elseif ($NoProxy) {
    & $current.python -m pathfinder ui
} else {
    & $current.python -m pathfinder ui --activate
}
'@
    [IO.File]::WriteAllText((Join-Path $InstallDir 'pathfinder.ps1'), $launcher, $utf8)
    $cmd = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0pathfinder.ps1`" %*`r`n"
    [IO.File]::WriteAllText((Join-Path $InstallDir 'Pathfinder.cmd'), $cmd, [Text.Encoding]::ASCII)
    Write-Host "Installed: $InstallDir"
    Write-Host "Launch: $InstallDir\Pathfinder.cmd"
    if (-not $NoLaunch) { & (Join-Path $InstallDir 'Pathfinder.cmd') }
} finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
}
