param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [string]$Scanner,

    [switch]$AllowMissingReplacements,

    [switch]$Experimental
)

$ErrorActionPreference = 'Stop'
$expectedPackageHash = '93c5bc40010b58db0de29bd4eac3b87fa48d6c0e140c620208b1cd3d6722b499'
$expectedBusyBoxHash = 'afe7768285d5bd415fc2440a74bdf6e3c828cd1aca8dd2b36fcdf9b4cc8054bf'
$expectedPackageVersion = 'mingw-w64-clang-aarch64-busybox 1.38.0.git.e7299058-1'
$expectedReplacementCount = if ($Experimental) { 84 } else { 59 }
$expectedRetainedCount = if ($Experimental) { 53 } else { 78 }

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Path is not a PE file"
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "$Path has an invalid PE header"
    }

    [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$packageName = 'mingw-w64-clang-aarch64-busybox-1.38.0.git.e7299058-1-any.pkg.tar.zst'
$packagePath = Join-Path $repoRoot "arm64-busybox\$packageName"
$busyboxPath = Join-Path $rootPath 'clangarm64\bin\busybox.exe'
$replacementPath = Join-Path $rootPath 'etc\arm64-busybox-replacements.tsv'
$retainedPath = Join-Path $rootPath 'etc\arm64-busybox-retained-paths.tsv'
$aliasesPath = Join-Path $rootPath 'etc\arm64-busybox-aliases.txt'
$mapPath = Join-Path $rootPath 'clangarm64\share\busybox\arm64-payload-map.json'

$packageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $packagePath).Hash.ToLowerInvariant()
if ($packageHash -ne $expectedPackageHash) {
    throw "Unexpected package SHA-256: $packageHash"
}

$busyboxHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $busyboxPath).Hash.ToLowerInvariant()
if ($busyboxHash -ne $expectedBusyBoxHash) {
    throw "Unexpected busybox.exe SHA-256: $busyboxHash"
}
if ((Get-PeMachine -Path $busyboxPath) -ne 0xAA64) {
    throw "$busyboxPath is not ARM64"
}

$replacements = @(Import-Csv -Delimiter "`t" -LiteralPath $replacementPath)
if ($replacements.Count -ne $expectedReplacementCount) {
    throw "Expected $expectedReplacementCount replacements, found $($replacements.Count)"
}

$aliases = @(Get-Content -LiteralPath $aliasesPath)
if ($aliases.Count -ne $expectedReplacementCount) {
    throw "Expected $expectedReplacementCount aliases, found $($aliases.Count)"
}

$replacementFiles = [Collections.Generic.List[string]]::new()
foreach ($replacement in $replacements) {
    $path = Join-Path $rootPath $replacement.path.Replace('/', '\')
    if (-not [IO.File]::Exists($path)) {
        if ($AllowMissingReplacements) {
            continue
        }
        throw "Missing replacement $path"
    }
    $machine = Get-PeMachine -Path $path
    if ($machine -ne 0xAA64) {
        throw "$($replacement.path) has PE machine 0x$($machine.ToString('X4')), expected 0xAA64"
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($hash -ne $expectedBusyBoxHash) {
        throw "$($replacement.path) is not the exact packaged busybox.exe"
    }
    $expectedAlias = [IO.Path]::GetFileName($replacement.path)
    if ($aliases -notcontains $expectedAlias) {
        throw "$expectedAlias is missing from the post-install alias list"
    }
    $replacementFiles.Add($replacement.path)
}

$retained = @(Import-Csv -Delimiter "`t" -LiteralPath $retainedPath)
if ($retained.Count -ne $expectedRetainedCount) {
    throw "Expected $expectedRetainedCount retained paths, found $($retained.Count)"
}
foreach ($path in $replacementFiles) {
    if ($retained.path -contains $path) {
        throw "$path is both replaced and retained"
    }
}

$map = Get-Content -LiteralPath $mapPath -Raw | ConvertFrom-Json
if ($map.baseline.sourcePullRequest -ne 'https://github.com/crutkas/build-extra/pull/1' -or
    $map.baseline.sourceCommit -ne '9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19' -or
    $map.summary.directArm64CandidateCount -ne 84 -or
    $map.summary.architectureGapCount -ne 53) {
    throw 'The installed package map does not match the fork-local 84-candidate/53-gap input'
}

$packageVersionsPath = Join-Path $rootPath 'etc\package-versions.txt'
if (Test-Path -LiteralPath $packageVersionsPath) {
    $packageVersions = Get-Content -LiteralPath $packageVersionsPath
    if ($packageVersions -notcontains $expectedPackageVersion) {
        throw "$packageVersionsPath does not record $expectedPackageVersion"
    }
}

if ($Scanner) {
    $scannerPath = (Resolve-Path -LiteralPath $Scanner).Path
    $scannerInput = Join-Path ([IO.Path]::GetTempPath()) "arm64-busybox-scanner-$PID.txt"
    try {
        $replacementFiles | Set-Content -LiteralPath $scannerInput -Encoding ascii
        $rows = @(
            & $scannerPath -ArchitectureOnly -Root $rootPath -FileList $scannerInput
        )
        if ($rows.Count -ne $replacementFiles.Count) {
            throw "The fork-local scanner found $($rows.Count) of $($replacementFiles.Count) replacement PEs"
        }
        foreach ($row in $rows) {
            $fields = $row -split "`t"
            if ($fields.Count -ne 3 -or $fields[1] -ne 'arm64' -or $fields[2] -ne '0xAA64') {
                throw "Unexpected scanner row: $row"
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $scannerInput -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Validated $($replacementFiles.Count) ARM64 BusyBox replacement PEs and $expectedRetainedCount retained paths"
