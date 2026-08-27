$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot "arm64-vim\install.ps1"
$sourceLock = Join-Path $repoRoot "arm64-vim\input-lock.json"
$scanner = Join-Path $repoRoot "pe-imports.ps1"
$distributionChecker = Join-Path $PSScriptRoot "check-arm64-vim-distributions.ps1"
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-vim-integration-$PID"
$binaryAsset = "mingw-w64-clang-aarch64-vim-9.2.0858-1-any.pkg.tar.zst"
$runtimeAsset = "mingw-w64-clang-aarch64-vim-runtime-9.2.0858-1-any.pkg.tar.zst"
$replacementNames = @("ex", "rview", "rvim", "view", "vim", "vimdiff", "xxd")
$windowsTar = Join-Path ([Environment]::GetFolderPath("System")) "tar.exe"
if (-not (Test-Path -LiteralPath $windowsTar -PathType Leaf)) {
    throw "Windows tar.exe is required"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Write-Pe([string]$Path, [uint16]$Machine) {
    $bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int32]0x80).CopyTo($bytes, 0x3c)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Write-PkgInfo([string]$Path, [string]$Name, [string]$Description, [string[]]$Depends) {
    $lines = @(
        "pkgname = $Name"
        "pkgbase = mingw-w64-vim"
        "xdata = pkgtype=split"
        "pkgver = 9.2.0858-1"
        "pkgdesc = $Description"
        "url = https://www.vim.org"
        "arch = any"
        "license = spdx:Vim"
    )
    foreach ($dependency in $Depends) {
        $lines += "depend = $dependency"
    }
    foreach ($dependency in @(
        "mingw-w64-clang-aarch64-cc",
        "mingw-w64-clang-aarch64-gettext-runtime",
        "mingw-w64-clang-aarch64-libiconv",
        "mingw-w64-clang-aarch64-make"
    )) {
        $lines += "makedepend = $dependency"
    }
    $lines | Set-Content -Encoding ascii -LiteralPath $Path
    @(
        "pkgbase = mingw-w64-vim"
        "pkgver = 9.2.0858-1"
        "pkgarch = any"
    ) | Set-Content -Encoding ascii -LiteralPath (Join-Path (Split-Path -Parent $Path) ".BUILDINFO")
}

function New-PackageFixtures([string]$Directory) {
    $binaryRoot = Join-Path $Directory "binary-root"
    $runtimeRoot = Join-Path $Directory "runtime-root"
    New-Item -ItemType Directory -Force -Path $binaryRoot, $runtimeRoot | Out-Null
    Write-PkgInfo (Join-Path $binaryRoot ".PKGINFO") `
        "mingw-w64-clang-aarch64-vim" `
        "Vi Improved native Win32 console binaries for Git for Windows (mingw-w64)" `
        @(
            "mingw-w64-clang-aarch64-gettext-runtime",
            "mingw-w64-clang-aarch64-libiconv",
            "mingw-w64-clang-aarch64-vim-runtime=9.2.0858-1"
        )
    foreach ($name in $replacementNames) {
        Write-Pe (Join-Path $binaryRoot "clangarm64\bin\$name.exe") 0xAA64
    }
    New-Item -ItemType Directory -Force -Path (
        Join-Path $binaryRoot "clangarm64\share\licenses\vim"
    ) | Out-Null
    "Vim license" | Set-Content -Encoding ascii -LiteralPath (
        Join-Path $binaryRoot "clangarm64\share\licenses\vim\LICENSE"
    )
    Write-PkgInfo (Join-Path $runtimeRoot ".PKGINFO") `
        "mingw-w64-clang-aarch64-vim-runtime" `
        "Runtime files, syntax definitions, and help for Vim (mingw-w64)" @()
    foreach ($relative in @(
        "clangarm64\share\vim\vim92\syntax\syntax.vim",
        "clangarm64\share\vim\vim92\git-for-windows.vim",
        "clangarm64\share\man\man1\vim.1.gz",
        "clangarm64\share\man\man1\xxd.1.gz",
        "clangarm64\share\licenses\vim-runtime\LICENSE"
    )) {
        $path = Join-Path $runtimeRoot $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
        $relative | Set-Content -Encoding ascii -LiteralPath $path
    }
    & $windowsTar -cf (Join-Path $Directory $binaryAsset) -C $binaryRoot .
    if ($LASTEXITCODE -ne 0) { throw "Could not create binary fixture" }
    & $windowsTar -cf (Join-Path $Directory $runtimeAsset) -C $runtimeRoot .
    if ($LASTEXITCODE -ne 0) { throw "Could not create runtime fixture" }
    return @{
        BinaryRoot = $binaryRoot
        RuntimeRoot = $runtimeRoot
    }
}

function New-AdmittedLock([string]$Directory) {
    $data = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
    $data.status = "admitted"
    $data.release.repository = $data.source.repository
    $data.release.releaseId = 1
    $data.release.tag = "test-only"
    $data.release.tagObjectSha = "1" * 40
    $data.release.tagMessage = "synthetic test tag"
    $data.release.peeledCommit = $data.source.commit
    $data.release.url = "https://example.invalid/test-only"
    $data.release.publishedAt = "2026-08-27T00:00:00Z"
    $data.release.body.bytes = 0
    $data.release.body.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $data.release.audit.status = "passed"
    $data.release.audit.evidence = "synthetic-test-only"
    $data.expected.distributionBytesDelta.installer = 0
    $data.expected.distributionBytesDelta.portable = 0
    $id = 10
    foreach ($asset in $data.release.assets) {
        if ($asset.role -eq "evidence") {
            $asset.name = "synthetic-vim-evidence.zip"
        }
        $asset.assetId = $id++
        $asset.url = "https://example.invalid/$($asset.name)"
        if ($asset.role -eq "package") {
            $path = Join-Path $Directory $asset.name
            $asset.bytes = (Get-Item -LiteralPath $path).Length
            $asset.sha256 = Get-Sha256 $path
        } else {
            $path = Join-Path $Directory $asset.name
            "synthetic evidence" | Set-Content -Encoding ascii -LiteralPath $path
            $asset.bytes = (Get-Item -LiteralPath $path).Length
            $asset.sha256 = Get-Sha256 $path
        }
    }
    return $data
}

function Save-Lock($Data, [string]$Path) {
    $Data | ConvertTo-Json -Depth 20 | Set-Content -Encoding ascii -LiteralPath $Path
}

function New-Root([string]$Path) {
    foreach ($name in $replacementNames) {
        Write-Pe (Join-Path $Path "usr\bin\$name.exe") 0x8664
    }
    $vimTutor = Join-Path $Path "usr\bin\vimtutor"
    "#!/bin/sh`necho vimtutor" | Set-Content -Encoding ascii -LiteralPath $vimTutor
    Write-Pe (Join-Path $Path "clangarm64\bin\libiconv-2.dll") 0xAA64
    Write-Pe (Join-Path $Path "clangarm64\bin\libintl-8.dll") 0xAA64
    New-Item -ItemType Directory -Force -Path (Join-Path $Path "etc") | Out-Null
    return $vimTutor
}

function Invoke-Stage([string]$Root, [string]$Lock, [string]$Packages) {
    Invoke-ProductionInstaller @(
        "-Phase", "Stage", "-Root", $Root, "-Lock", $Lock,
        "-Scanner", $scanner, "-TestMode", "-PackageDirectory", $Packages,
        "-RequireAdmission"
    )
}

function Invoke-ProductionInstaller([string[]]$Arguments) {
    $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $installer @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }
    return $output
}

function Assert-Fails([scriptblock]$Action, [string]$Pattern) {
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Expected failure matching '$Pattern', got: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected failure matching '$Pattern'"
}

function New-Case([string]$Name) {
    $directory = Join-Path $trash $Name
    $packages = Join-Path $directory "packages"
    $root = Join-Path $directory "root"
    New-Item -ItemType Directory -Force -Path $packages, $root | Out-Null
    $trees = New-PackageFixtures $packages
    $lock = New-AdmittedLock $packages
    $lockPath = Join-Path $directory "lock.json"
    Save-Lock $lock $lockPath
    return @{
        Directory = $directory
        Packages = $packages
        Root = $root
        Trees = $trees
        Lock = $lock
        LockPath = $lockPath
    }
}

try {
    New-Item -ItemType Directory -Force -Path $trash | Out-Null

    $unresolvedRoot = Join-Path $trash "unresolved"
    New-Item -ItemType Directory -Force -Path $unresolvedRoot | Out-Null
    $unresolvedData = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
    $unresolvedData.status = "unresolved"
    foreach ($field in @(
        "repository", "releaseId", "tag", "tagObjectSha", "tagMessage",
        "peeledCommit", "url", "publishedAt"
    )) {
        $unresolvedData.release.$field = $null
    }
    $unresolvedData.release.body.bytes = $null
    $unresolvedData.release.body.sha256 = $null
    foreach ($asset in $unresolvedData.release.assets) {
        $asset.assetId = $null
        $asset.url = $null
        if ($asset.role -eq "evidence") {
            $asset.name = $null
        }
    }
    $unresolvedLock = Join-Path $trash "unresolved.json"
    Save-Lock $unresolvedData $unresolvedLock
    Assert-Fails {
        Invoke-ProductionInstaller @(
            "-Phase", "Probe", "-Root", $unresolvedRoot, "-Lock", $unresolvedLock,
            "-Scanner", $scanner, "-RequireAdmission"
        )
    } "public immutable release locator is unresolved"
    Assert-Fails {
        Invoke-ProductionInstaller @(
            "-Phase", "Probe", "-Root", $unresolvedRoot, "-Lock", $sourceLock,
            "-Scanner", $scanner, "-RequireAdmission"
        )
    } "requires explicit measurement mode"

    $case = New-Case "size"
    $case.Lock.release.assets[0].bytes++
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Unexpected asset size"

    $case = New-Case "hash"
    $case.Lock.release.assets[0].sha256 = "0" * 64
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Unexpected asset SHA-256"

    $case = New-Case "pkginfo"
    (Get-Content -LiteralPath (Join-Path $case.Trees.BinaryRoot ".PKGINFO")) `
        -replace "^arch = any$", "arch = aarch64" |
        Set-Content -Encoding ascii -LiteralPath (Join-Path $case.Trees.BinaryRoot ".PKGINFO")
    Remove-Item -LiteralPath (Join-Path $case.Packages $binaryAsset)
    & $windowsTar -cf (Join-Path $case.Packages $binaryAsset) -C $case.Trees.BinaryRoot .
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Unexpected .PKGINFO field 'arch'"

    $case = New-Case "wrong-machine"
    Write-Pe (Join-Path $case.Trees.BinaryRoot "clangarm64\bin\vim.exe") 0x8664
    Remove-Item -LiteralPath (Join-Path $case.Packages $binaryAsset)
    & $windowsTar -cf (Join-Path $case.Packages $binaryAsset) -C $case.Trees.BinaryRoot .
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "vim.exe is not an ARM64 PE"

    $case = New-Case "extra-pe"
    Write-Pe (Join-Path $case.Trees.BinaryRoot "clangarm64\bin\extra.exe") 0xAA64
    Remove-Item -LiteralPath (Join-Path $case.Packages $binaryAsset)
    & $windowsTar -cf (Join-Path $case.Packages $binaryAsset) -C $case.Trees.BinaryRoot .
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "undeclared member"

    $case = New-Case "missing-pe"
    Remove-Item -LiteralPath (Join-Path $case.Trees.BinaryRoot "clangarm64\bin\xxd.exe")
    Remove-Item -LiteralPath (Join-Path $case.Packages $binaryAsset)
    & $windowsTar -cf (Join-Path $case.Packages $binaryAsset) -C $case.Trees.BinaryRoot .
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "replacement set is incomplete"

    $case = New-Case "duplicate-member"
    $archive = Join-Path $case.Packages $binaryAsset
    Remove-Item -LiteralPath $archive
    & $windowsTar -cf $archive -C $case.Trees.BinaryRoot .PKGINFO `
        clangarm64/bin/vim.exe clangarm64/bin/vim.exe
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Duplicate or case-colliding archive member"

    $case = New-Case "traversal"
    $archive = Join-Path $case.Packages $binaryAsset
    Remove-Item -LiteralPath $archive
    $stream = [IO.File]::Create($archive)
    try {
        $writer = [System.Formats.Tar.TarWriter]::new($stream, $false)
        try {
            $entry = [System.Formats.Tar.PaxTarEntry]::new(
                [System.Formats.Tar.TarEntryType]::RegularFile,
                "../escape"
            )
            $entry.DataStream = [IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes("escape"))
            $writer.WriteEntry($entry)
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Unsafe archive member"

    $case = New-Case "canonical-alias"
    $archive = Join-Path $case.Packages $binaryAsset
    Remove-Item -LiteralPath $archive
    $stream = [IO.File]::Create($archive)
    try {
        $writer = [System.Formats.Tar.TarWriter]::new($stream, $false)
        try {
            $entry = [System.Formats.Tar.PaxTarEntry]::new(
                [System.Formats.Tar.TarEntryType]::RegularFile,
                "clangarm64/bin/./vim.exe"
            )
            $entry.DataStream = [IO.MemoryStream]::new([byte[]]::new(1))
            $writer.WriteEntry($entry)
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "Unsafe archive member"

    $case = New-Case "symlink"
    $archive = Join-Path $case.Packages $binaryAsset
    Remove-Item -LiteralPath $archive
    $stream = [IO.File]::Create($archive)
    try {
        $writer = [System.Formats.Tar.TarWriter]::new($stream, $false)
        try {
            $entry = [System.Formats.Tar.PaxTarEntry]::new(
                [System.Formats.Tar.TarEntryType]::SymbolicLink,
                "clangarm64/bin/vim.exe"
            )
            $entry.LinkName = "clangarm64/bin/xxd.exe"
            $writer.WriteEntry($entry)
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    $case.Lock = New-AdmittedLock $case.Packages
    Save-Lock $case.Lock $case.LockPath
    Assert-Fails { Invoke-Stage $case.Root $case.LockPath $case.Packages } "symbolic link"

    $case = New-Case "dependency"
    Invoke-Stage $case.Root $case.LockPath $case.Packages
    New-Root $case.Root | Out-Null
    Remove-Item -LiteralPath (Join-Path $case.Root "clangarm64\bin\libiconv-2.dll")
    Assert-Fails {
        Invoke-ProductionInstaller @(
            "-Phase", "Finalize", "-Root", $case.Root, "-Lock", $case.LockPath,
            "-Scanner", $scanner, "-RequireAdmission", "-TestMode"
        )
    } "Missing native Vim dependency"

    $case = New-Case "layer-overlap"
    Invoke-Stage $case.Root $case.LockPath $case.Packages
    New-Root $case.Root | Out-Null
    "usr/bin/vim.exe`tbusybox" | Set-Content -Encoding ascii -LiteralPath (
        Join-Path $case.Root "etc\arm64-busybox-replacements.tsv"
    )
    Assert-Fails {
        Invoke-ProductionInstaller @(
            "-Phase", "Finalize", "-Root", $case.Root, "-Lock", $case.LockPath,
            "-Scanner", $scanner, "-RequireAdmission", "-TestMode"
        )
    } "overlap the BusyBox layer"

    $case = New-Case "success"
    Invoke-Stage $case.Root $case.LockPath $case.Packages
    $vimTutor = New-Root $case.Root
    $vimTutorHash = Get-Sha256 $vimTutor
    Invoke-ProductionInstaller @(
        "-Phase", "Finalize", "-Root", $case.Root, "-Lock", $case.LockPath,
        "-Scanner", $scanner, "-RequireAdmission", "-TestMode"
    ) | Out-Null
    if ((Get-Sha256 $vimTutor) -ne $vimTutorHash) {
        throw "vimtutor changed"
    }
    foreach ($name in $replacementNames) {
        $path = Join-Path $case.Root "usr\bin\$name.exe"
        if (-not (Test-Path -LiteralPath $path) -or
            [BitConverter]::ToUInt16([IO.File]::ReadAllBytes($path), 0x84) -ne 0xAA64) {
            throw "$name.exe was not replaced by ARM64"
        }
    }
    $provenance = Get-Content -Raw -LiteralPath (
        Join-Path $case.Root "etc\arm64-vim-provenance.json"
    ) | ConvertFrom-Json
    if (@($provenance.files |
            Where-Object sourcePackage -eq "mingw-w64-clang-aarch64-vim" |
            Where-Object peMachine -eq "0xAA64").Count -ne 7 -or
        @($provenance.dependencyClosure |
            Where-Object sourceInput -eq "base").Count -ne 2 -or
        $provenance.retained[0].destinationPath -ne "usr/bin/vimtutor") {
        throw "The provenance manifest does not describe the exact replacement contract"
    }

    $unchanged = Join-Path $trash "unchanged-product.bin"
    "unchanged" | Set-Content -Encoding ascii -LiteralPath $unchanged
    $distributionReport = Join-Path $trash "distribution.json"
    & $distributionChecker -Lock $sourceLock `
        -BaseInstaller $unchanged -IntegratedInstaller $unchanged `
        -BasePortable $unchanged -IntegratedPortable $unchanged `
        -BaseMinGit $unchanged -IntegratedMinGit $unchanged `
        -BaseBusyBoxMinGit $unchanged -IntegratedBusyBoxMinGit $unchanged `
        -Output $distributionReport
    if ($LASTEXITCODE -ne 0 -or
        (Get-Content -Raw -LiteralPath $distributionReport | ConvertFrom-Json).mode -ne "measurement") {
        throw "The measurement distribution impact check failed"
    }

    Write-Host "ARM64 Vim fail-closed integration checks passed"
} finally {
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
