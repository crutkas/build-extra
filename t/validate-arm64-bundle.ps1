Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$validator = Join-Path $repoRoot "validate-arm64-bundle.ps1"

function Invoke-CheckedGit {
    $output = & git -C $repoRoot @args
    if ($LASTEXITCODE -ne 0) {
        throw "git $($args -join ' ') failed with exit $LASTEXITCODE"
    }
    return ($output | Out-String).Trim()
}

# Hard-coded SHAs are absent from a shallow CI clone, so derive both commits
# here. The unreachable one pins its identity and dates explicitly so the
# object never depends on ambient Git config, which a clean CI runner lacks.
$script:reachableBuildCommit = Invoke-CheckedGit rev-parse HEAD
$script:unreachableBuildCommit = & {
    $names = @(
        "GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE",
        "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME",
        "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")
    $previous = @{}
    foreach ($name in $names) {
        $previous[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    try {
        foreach ($name in @("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")) {
            [Environment]::SetEnvironmentVariable($name, "1700000000 +0000")
        }
        foreach ($name in @("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")) {
            [Environment]::SetEnvironmentVariable($name, "ARM64 validator test")
        }
        foreach ($name in @("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")) {
            [Environment]::SetEnvironmentVariable(
                $name, "validator-test@example.com")
        }
        $tree = Invoke-CheckedGit rev-parse "HEAD^{tree}"
        Invoke-CheckedGit commit-tree -m "synthetic unreachable commit" $tree
    } finally {
        foreach ($name in $names) {
            # Restoring a previously unset variable to $null would leave it as
            # an empty string, which Git rejects as an empty ident.
            if ($null -eq $previous[$name]) {
                Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
            } else {
                [Environment]::SetEnvironmentVariable($name, $previous[$name])
            }
        }
    }
}
if ($script:unreachableBuildCommit -notmatch "^[0-9a-f]{40}$" -or
    [string]::Equals(
        $script:unreachableBuildCommit,
        $script:reachableBuildCommit,
        [StringComparison]::Ordinal)) {
    throw "Synthetic unreachable commit was not created"
}
# Prove the fixture really is unreachable from every ref in this repository.
& git -C $repoRoot merge-base --is-ancestor `
    $script:unreachableBuildCommit HEAD 2>$null
if ($LASTEXITCODE -eq 0) {
    throw "Synthetic unreachable commit is reachable from HEAD"
}
if (@(Invoke-CheckedGit for-each-ref --contains `
        $script:unreachableBuildCommit --format="%(refname)" |
    Where-Object { $_.Length -gt 0 }).Count -ne 0) {
    throw "Synthetic unreachable commit is reachable from a ref"
}
$utf8 = [Text.UTF8Encoding]::new($false)
$suite = Join-Path ([IO.Path]::GetTempPath()) (
    "arm64-bundle-validator-tests-" + [Guid]::NewGuid().ToString("N"))
$passed = 0

function Set-UInt16 {
    param([byte[]]$Bytes, [int]$Offset, [uint16]$Value)
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 2)
}

function Set-UInt32 {
    param([byte[]]$Bytes, [int]$Offset, [uint32]$Value)
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 4)
}

function Set-UInt64 {
    param([byte[]]$Bytes, [int]$Offset, [uint64]$Value)
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 8)
}

function New-TestPe {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][uint16] $Machine,
        [string[]] $Imports = @(),
        [switch] $AnyCpu,
        [Nullable[uint32]] $PseudoFlag
    )

    $isPe32 = $Machine -eq 0x014c
    $optionalSize = if ($isPe32) { 0xe0 } else { 0xf0 }
    $directoryOffset = if ($isPe32) { 96 } else { 112 }
    [byte[]]$bytes = [byte[]]::new(0x600)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    Set-UInt32 $bytes 60 0x80
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    Set-UInt16 $bytes 0x84 $Machine
    Set-UInt16 $bytes 0x86 1
    Set-UInt16 $bytes 0x94 $optionalSize
    Set-UInt16 $bytes 0x96 0x22
    $optional = 0x98
    Set-UInt16 $bytes $optional $(if ($isPe32) { 0x10b } else { 0x20b })
    if ($isPe32) {
        Set-UInt32 $bytes ($optional + 28) 0x400000
    } else {
        Set-UInt64 $bytes ($optional + 24) 0x140000000
    }
    Set-UInt32 $bytes ($optional + 32) 0x1000
    Set-UInt32 $bytes ($optional + 36) 0x200
    Set-UInt32 $bytes ($optional + 56) 0x2000
    Set-UInt32 $bytes ($optional + 60) 0x200
    Set-UInt16 $bytes ($optional + 68) 3
    Set-UInt32 $bytes (
        $optional + $(if ($isPe32) { 92 } else { 108 })) 16
    $section = $optional + $optionalSize
    [Array]::Copy(
        [Text.Encoding]::ASCII.GetBytes(".rdata"),
        0,
        $bytes,
        $section,
        6)
    Set-UInt32 $bytes ($section + 8) 0x400
    Set-UInt32 $bytes ($section + 12) 0x1000
    Set-UInt32 $bytes ($section + 16) 0x400
    Set-UInt32 $bytes ($section + 20) 0x200

    if ($Imports.Count -ne 0) {
        Set-UInt32 $bytes ($optional + $directoryOffset + 8) 0x1000
        Set-UInt32 $bytes ($optional + $directoryOffset + 12) 0x100
        for ($index = 0; $index -lt $Imports.Count; $index++) {
            $descriptor = 0x200 + ($index * 20)
            $thunkOffset = 0x260 + ($index * 0x10)
            $nameOffset = 0x300 + ($index * 0x30)
            $thunkRva = 0x1000 + $thunkOffset - 0x200
            Set-UInt32 $bytes $descriptor $thunkRva
            Set-UInt32 $bytes ($descriptor + 12) (
                0x1000 + $nameOffset - 0x200)
            Set-UInt32 $bytes ($descriptor + 16) $thunkRva
            if ($isPe32) {
                Set-UInt32 $bytes $thunkOffset 0x80000001
            } else {
                Set-UInt64 $bytes $thunkOffset (
                    [Convert]::ToUInt64("8000000000000001", 16))
            }
            $nameBytes = [Text.Encoding]::ASCII.GetBytes($Imports[$index])
            [Array]::Copy($nameBytes, 0, $bytes, $nameOffset, $nameBytes.Length)
        }
    }
    if ($AnyCpu) {
        Set-UInt32 $bytes ($optional + $directoryOffset + 112) 0x1100
        Set-UInt32 $bytes ($optional + $directoryOffset + 116) 72
        Set-UInt32 $bytes 0x300 72
        Set-UInt32 $bytes 0x308 0x1180
        Set-UInt32 $bytes 0x30c 24
        Set-UInt32 $bytes 0x310 1
        Set-UInt32 $bytes 0x380 0x424a5342
        Set-UInt16 $bytes 0x384 2
        Set-UInt16 $bytes 0x386 5
        Set-UInt32 $bytes 0x38c 4
        [Array]::Copy(
            [byte[]](0x76, 0x34, 0, 0),
            0,
            $bytes,
            0x390,
            4)
        Set-UInt16 $bytes 0x396 0
    }
    if ($null -ne $PseudoFlag) {
        Set-UInt32 $bytes 0x380 0
        Set-UInt32 $bytes 0x384 0
        Set-UInt32 $bytes 0x388 1
        Set-UInt32 $bytes 0x38c 0x100
        Set-UInt32 $bytes 0x390 0x200
        Set-UInt32 $bytes 0x394 ([uint32]$PseudoFlag)
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Write-Json {
    param([string]$Path, $Value)
    $json = ($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
    [IO.File]::WriteAllText(
        $Path,
        ($json + "`n"),
        $utf8)
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.
        ToLowerInvariant()
}

function Get-TextSha256 {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($utf8.GetBytes($Text)) | ForEach-Object {
            $_.ToString("x2")
        }) -join ""
    } finally {
        $sha.Dispose()
    }
}

function Get-RootInventorySha256 {
    param([string]$Root)
    $members = @()
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        $path = [IO.Path]::GetRelativePath($Root, $item.FullName).
            Replace("\", "/")
        if ($path -ieq "preview-evidence" -or
            $path.StartsWith(
                "preview-evidence/",
                [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        if ($item.PSIsContainer) {
            $members += [ordered]@{
                path = $path
                line = "directory`t$path`t0`t-`n"
            }
        } else {
            $hash = Get-Sha256 $item.FullName
            $members += [ordered]@{
                path = $path
                line = "file`t$path`t$($item.Length)`t$hash`n"
            }
        }
    }
    $lines = @($members |
        Sort-Object { $_.path } |
        ForEach-Object { $_.line }) -join ""
    return Get-TextSha256 $lines
}

function Copy-Identity {
    param($LockInput)
    return [ordered]@{
        id = $LockInput.id
        release = $LockInput.release
        asset = $LockInput.asset
        package = $LockInput.package
        archiveMembers = @()
    }
}

function New-ArchiveMember {
    param(
        [string]$SourceMember,
        [string]$Type,
        [long]$Bytes,
        $Sha256,
        [bool]$Selected,
        $DestinationPath,
        $LinkTarget = $null
    )
    return [ordered]@{
        sourceMember = $SourceMember
        type = $Type
        bytes = $Bytes
        sha256 = $Sha256
        selected = $Selected
        destinationPath = $DestinationPath
        linkTarget = $LinkTarget
    }
}

function New-FinalMember {
    param($ArchiveMember, [string]$InputId)
    return [ordered]@{
        destinationPath = $ArchiveMember.destinationPath
        inputId = $InputId
        sourceMember = $ArchiveMember.sourceMember
        type = $ArchiveMember.type
        bytes = $ArchiveMember.bytes
        sha256 = $ArchiveMember.sha256
        linkTarget = $ArchiveMember.linkTarget
    }
}

function New-PayloadEntry {
    param(
        [string]$Path,
        [string]$Type,
        [long]$Bytes,
        $Sha256,
        $Architecture,
        $Machine,
        $Personality,
        [object[]]$Imports,
        $ClrFlags,
        $LinkTarget = $null
    )
    # The validator owns classification; the producer manifest carries only
    # scope, identity and ownership. The classification arguments are accepted
    # so existing fixtures stay readable, but they are deliberately dropped.
    return [ordered]@{
        path = $Path
        type = $Type
        bytes = $Bytes
        sha256 = $Sha256
        linkTarget = $LinkTarget
    }
}

function New-TestFixture {
    param([string]$Name)

    $fixtureRoot = Join-Path $suite $Name
    $payloadRoot = Join-Path $fixtureRoot "root"
    $toolRoot = Join-Path $fixtureRoot "tools"
    [void](New-Item -ItemType Directory -Path (
        Join-Path $payloadRoot "bin") -Force)
    [void](New-Item -ItemType Directory -Path (
        Join-Path $payloadRoot "usr\bin") -Force)
    [void](New-Item -ItemType Directory -Path (
        Join-Path $payloadRoot "preview-evidence") -Force)
    [void](New-Item -ItemType Directory -Path (
        Join-Path $toolRoot "opt\bin") -Force)
    $gitPath = Join-Path $payloadRoot "bin\git.exe"
    $bashPath = Join-Path $payloadRoot "usr\bin\bash.exe"
    $gpgPath = Join-Path $payloadRoot "usr\bin\gpg.exe"
    $sshPath = Join-Path $payloadRoot "usr\bin\ssh.exe"
    $noticePath = Join-Path $payloadRoot "notice.txt"
    New-TestPe $gitPath 0xaa64
    New-TestPe $bashPath 0xa641 -Imports @("msys-2.0.dll")
    New-TestPe $gpgPath 0xaa64
    New-TestPe $sshPath 0xaa64
    [IO.File]::WriteAllText($noticePath, "synthetic payload`n", $utf8)
    $objdumpPath = Join-Path $toolRoot `
        "opt\bin\aarch64-pc-cygwin-objdump.exe"
    $nmPath = Join-Path $toolRoot "opt\bin\aarch64-pc-cygwin-nm.exe"
    Copy-Item -LiteralPath $script:fakeTool -Destination $objdumpPath
    Copy-Item -LiteralPath $script:fakeTool -Destination $nmPath

    $native = [ordered]@{
        id = "native"
        role = "base-bundle"
        status = "resolved"
        resolution = [ordered]@{ method = "github-release" }
        release = [ordered]@{
            repository = "crutkas/native-package"
            tag = "v1.0.0"
            targetCommit = "1111111111111111111111111111111111111111"
        }
        asset = [ordered]@{
            url = "https://github.com/crutkas/native-package/releases/download/v1.0.0/native.pkg.tar.zst"
            name = "native.pkg.tar.zst"
            bytes = 100
            sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
        }
        package = [ordered]@{
            name = "native-package"
            version = "1.0.0-1"
            personality = "mingw"
            provides = @("bin/git.exe")
        }
        overlay = [ordered]@{
            enabled = $true
            destination = "."
            include = @("bin", "bin/*", "notice.txt")
            exclude = @()
            mappings = @()
        }
    }
    $msys = [ordered]@{
        id = "msys"
        role = "payload"
        status = "resolved"
        resolution = [ordered]@{ method = "github-release" }
        release = [ordered]@{
            repository = "crutkas/msys-package"
            tag = "v1.0.0"
            targetCommit = "2222222222222222222222222222222222222222"
        }
        asset = [ordered]@{
            url = "https://github.com/crutkas/msys-package/releases/download/v1.0.0/msys.pkg.tar.zst"
            name = "msys.pkg.tar.zst"
            bytes = 200
            sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
        }
        package = [ordered]@{
            name = "msys-package"
            version = "1.0.0-1"
            personality = "mixed"
            provides = @(
                "usr/bin/bash.exe",
                "usr/bin/gpg.exe",
                "usr/bin/ssh.exe"
            )
        }
        overlay = [ordered]@{
            enabled = $true
            destination = "."
            include = @("usr", "usr/*", "usr/bin/*")
            exclude = @()
            mappings = @()
        }
    }
    $tools = [ordered]@{
        id = "binutils"
        role = "validation-tool"
        status = "resolved"
        resolution = [ordered]@{ method = "github-release" }
        release = [ordered]@{
            repository = "crutkas/MSYS2-packages"
            tag = "binutils-2.44.50-2"
            targetCommit = "3333333333333333333333333333333333333333"
        }
        asset = [ordered]@{
            url = "https://github.com/crutkas/MSYS2-packages/releases/download/binutils-2.44.50-2/binutils.pkg.tar.zst"
            name = "binutils.pkg.tar.zst"
            bytes = 300
            sha256 = "3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b"
        }
        package = [ordered]@{
            name = "mingw-w64-cross-cygwinarm64-binutils"
            version = "2.44.50-2"
            personality = "tool"
            provides = @(
                "opt/bin/aarch64-pc-cygwin-ld.exe",
                "opt/bin/aarch64-pc-cygwin-nm.exe",
                "opt/bin/aarch64-pc-cygwin-objdump.exe"
            )
        }
        overlay = [ordered]@{
            enabled = $false
            destination = $null
            include = @()
            exclude = @()
            mappings = @()
        }
    }
    $collector = [ordered]@{
        id = "collector"
        role = "validation-tool"
        status = "resolved"
        resolution = [ordered]@{ method = "github-raw-commit" }
        release = [ordered]@{
            repository = "crutkas/runtime-collector"
            targetCommit = "5555555555555555555555555555555555555555"
            sourcePath = "collect-runtime-evidence.ps1"
        }
        asset = [ordered]@{
            url = "https://raw.githubusercontent.com/crutkas/runtime-collector/5555555555555555555555555555555555555555/collect-runtime-evidence.ps1"
            name = "collect-runtime-evidence.ps1"
            bytes = 1234
            sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
        }
        package = $null
        overlay = [ordered]@{
            enabled = $false
            destination = $null
            include = @()
            exclude = @()
            mappings = @()
        }
    }
    $sourceLockPath = Join-Path $payloadRoot `
        "preview-evidence\source-lock.json"
    [IO.File]::WriteAllText(
        $sourceLockPath,
        "{`"schemaVersion`":1,`"richIntegrationLock`":true}`n",
        $utf8)
    $lock = [ordered]@{
        schemaVersion = 1
        sourceLock = [ordered]@{
            path = "preview-evidence/source-lock.json"
            sha256 = Get-Sha256 $sourceLockPath
        }
        sourceDateEpoch = 1787846400
        nativeShellClosure = @("bin/git.exe")
        inputs = @($tools, $collector, $msys, $native)
    }

    $nativeProvenance = Copy-Identity $native
    $nativeDirectory = New-ArchiveMember "bin" "directory" 0 $null $true "bin"
    $nativeFile = New-ArchiveMember "bin/git.exe" "file" `
        ([IO.FileInfo]::new($gitPath).Length) (Get-Sha256 $gitPath) `
        $true "bin/git.exe"
    $noticeFile = New-ArchiveMember "notice.txt" "file" `
        ([IO.FileInfo]::new($noticePath).Length) (Get-Sha256 $noticePath) `
        $true "notice.txt"
    $nativeProvenance.archiveMembers = @(
        $nativeDirectory, $nativeFile, $noticeFile)

    $msysProvenance = Copy-Identity $msys
    $usrDirectory = New-ArchiveMember "usr" "directory" 0 $null $true "usr"
    $usrBinDirectory = New-ArchiveMember "usr/bin" "directory" 0 $null `
        $true "usr/bin"
    $msysFile = New-ArchiveMember "usr/bin/bash.exe" "file" `
        ([IO.FileInfo]::new($bashPath).Length) (Get-Sha256 $bashPath) `
        $true "usr/bin/bash.exe"
    $gpgFile = New-ArchiveMember "usr/bin/gpg.exe" "file" `
        ([IO.FileInfo]::new($gpgPath).Length) (Get-Sha256 $gpgPath) `
        $true "usr/bin/gpg.exe"
    $sshFile = New-ArchiveMember "usr/bin/ssh.exe" "file" `
        ([IO.FileInfo]::new($sshPath).Length) (Get-Sha256 $sshPath) `
        $true "usr/bin/ssh.exe"
    $msysProvenance.archiveMembers = @(
        $usrDirectory, $usrBinDirectory, $msysFile, $gpgFile, $sshFile)

    $toolProvenance = Copy-Identity $tools
    $toolProvenance.archiveMembers = @(
        (New-ArchiveMember "opt/bin/aarch64-pc-cygwin-ld.exe" "file" 1887140 `
            "075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f" `
            $false $null),
        (New-ArchiveMember "opt/bin/aarch64-pc-cygwin-nm.exe" "file" `
            1257877 `
            "80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a" `
            $false $null),
        (New-ArchiveMember "opt/bin/aarch64-pc-cygwin-objdump.exe" "file" `
            2887699 `
            "bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e" `
            $false $null)
    )
    $collectorProvenance = Copy-Identity $collector
    $collectorProvenance.archiveMembers = @(
            (New-ArchiveMember "collect-runtime-evidence.ps1" "file" 1234 `
                "5555555555555555555555555555555555555555555555555555555555555555" `
                $false $null)
    )
    $snapshot = [ordered]@{
        log = [ordered]@{
            bytes = 155150
            sha256 = "925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8"
        }
        database = [ordered]@{
            files = 1178
            bytes = 170275
            canonicalManifestSha256 =
                "93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34"
        }
    }
    $provenance = [ordered]@{
        schemaVersion = 1
        lockSha256 = ("0" * 64)
        sourceDateEpoch = 1787846400
        nativeShellClosure = @("bin/git.exe")
        assembler = [ordered]@{
            repository = "crutkas/bundle-assembler"
            commit = "4444444444444444444444444444444444444444"
        }
        inputs = @(
            $toolProvenance,
            $collectorProvenance,
            $msysProvenance,
            $nativeProvenance)
        overlayOrder = @("native", "msys")
        replacements = @()
        finalMembers = @(
            (New-FinalMember $nativeDirectory "native"),
            (New-FinalMember $nativeFile "native"),
            (New-FinalMember $noticeFile "native"),
            (New-FinalMember $usrDirectory "msys"),
            (New-FinalMember $usrBinDirectory "msys"),
            (New-FinalMember $msysFile "msys"),
            (New-FinalMember $gpgFile "msys"),
            (New-FinalMember $sshFile "msys")
        )
        pseudoReloc = [ordered]@{
            scanner = [ordered]@{
                repository = "crutkas/MSYS2-packages"
                commit = "3356eec1411983cc252b04afac32bca5f3b8d824"
                path = ".ci/check-aarch64-pseudo-relocs.ps1"
                bytes = 10569
                sha256 =
                    "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9"
            }
            toolInputId = "binutils"
            objdumpMember = "opt/bin/aarch64-pc-cygwin-objdump.exe"
            nmMember = "opt/bin/aarch64-pc-cygwin-nm.exe"
            linkerMember = "opt/bin/aarch64-pc-cygwin-ld.exe"
            candidates = @()
        }
    }
    $assembly = [ordered]@{
        schemaVersion = 1
        previewId = "synthetic-preview"
        sourceLockSha256 = ("0" * 64)
        lockSha256 = ("0" * 64)
        provenanceSha256 = ("0" * 64)
        payloadManifestSha256 = ("0" * 64)
        rootInventorySha256 = ("0" * 64)
        staticReportSha256 = ("0" * 64)
        host = [ordered]@{
            os = "Windows"
            architecture = "ARM64"
            processArchitecture = "ARM64"
        }
        observedUtc = "2026-08-27T16:00:00Z"
        externalObservation = [ordered]@{
            rootPath = "C:\msys64"
            authoritative = $false
            usedAsInput = $false
            cutoffUtc = "2026-08-27T15:55:35Z"
            before = $snapshot
            after = $snapshot
            commands = @(
                "enumerate-database-manifest",
                "hash-database-manifest",
                "hash-package-log",
                "stat-package-log")
        }
    }
    $payload = [ordered]@{
        schemaVersion = 1
        lockSha256 = ("0" * 64)
        provenanceSha256 = ("0" * 64)
        scope = [ordered]@{
            root = "."
            excludedPrefixes = @("preview-evidence/")
        }
        entries = @(
            (New-PayloadEntry "bin" "directory" 0 $null $null $null `
                $null @() $null),
            (New-PayloadEntry "bin/git.exe" "file" `
                ([IO.FileInfo]::new($gitPath).Length) (Get-Sha256 $gitPath) `
                "arm64" "0xAA64" "mingw" @() $null),
            (New-PayloadEntry "notice.txt" "file" `
                ([IO.FileInfo]::new($noticePath).Length) `
                (Get-Sha256 $noticePath) "non-pe" $null "none" @() $null),
            (New-PayloadEntry "usr" "directory" 0 $null $null $null `
                $null @() $null),
            (New-PayloadEntry "usr/bin" "directory" 0 $null $null $null `
                $null @() $null),
            (New-PayloadEntry "usr/bin/bash.exe" "file" `
                ([IO.FileInfo]::new($bashPath).Length) (Get-Sha256 $bashPath) `
                "arm64ec" "0xA641" "msys" @("msys-2.0.dll") $null),
            (New-PayloadEntry "usr/bin/gpg.exe" "file" `
                ([IO.FileInfo]::new($gpgPath).Length) (Get-Sha256 $gpgPath) `
                "arm64" "0xAA64" "mingw" @() $null),
            (New-PayloadEntry "usr/bin/ssh.exe" "file" `
                ([IO.FileInfo]::new($sshPath).Length) (Get-Sha256 $sshPath) `
                "arm64" "0xAA64" "mingw" @() $null)
        )
    }
    $fixture = [ordered]@{
        Base = $fixtureRoot
        Root = $payloadRoot
        ToolRoot = $toolRoot
        LockPath = Join-Path $payloadRoot `
            "preview-evidence\bundle-lock.v1.json"
        SourceLockPath = $sourceLockPath
        ProvenancePath = Join-Path $fixtureRoot "bundle-provenance.json"
        PayloadPath = Join-Path $fixtureRoot "payload-manifest.json"
        AssemblyPath = Join-Path $fixtureRoot "assembly-run-evidence.json"
        RuntimePath = Join-Path $fixtureRoot "runtime-evidence.json"
        ReportPath = Join-Path $fixtureRoot "validation-report.json"
        StaticReportPath = Join-Path $fixtureRoot "static-report.json"
        Classification = @{
            "bin/git.exe" = [ordered]@{
                architecture = "arm64"
                personality = "none"
            }
            "usr/bin/bash.exe" = [ordered]@{
                architecture = "arm64ec"
                personality = "msys"
            }
            "usr/bin/gpg.exe" = [ordered]@{
                architecture = "arm64"
                personality = "mingw"
            }
            "usr/bin/ssh.exe" = [ordered]@{
                architecture = "arm64"
                personality = "mingw"
            }
        }
        Lock = $lock
        Provenance = $provenance
        Payload = $payload
        Assembly = $assembly
        Runtime = $null
    }
    $fixture.Runtime = New-RuntimeEvidence $fixture
    Sync-DigestGraph $fixture
    return $fixture
}

function New-RuntimeEvidence {
    param($Fixture)

    $scenarios = @()
    $scenarioRoles = [ordered]@{
        "Git Bash" = "msys"
        "Git" = "mingw"
        "SSH" = "mingw"
        "GPG" = "mingw"
        "hook" = "msys"
        "submodule" = "mingw"
        "rebase" = "msys"
        "git-svn" = "msys"
    }
    $scenarioOperations = [ordered]@{
        "Git Bash" = "git-bash-startup"
        "Git" = "git-command"
        "SSH" = "ssh-command"
        "GPG" = "gpg-command"
        "hook" = "git-hook"
        "submodule" = "git-submodule"
        "rebase" = "git-rebase"
        "git-svn" = "git-svn"
    }
    $scenarioCommands = [ordered]@{
        "Git Bash" = @(
            "usr/bin/bash.exe", "--noprofile", "--norc", "-lc", "exit 0")
        "Git" = @("bin/git.exe", "--version")
        "SSH" = @("usr/bin/ssh.exe", "-V")
        "GPG" = @("usr/bin/gpg.exe", "--version")
        "hook" = @(
            "usr/bin/bash.exe", "--noprofile", "--norc", "-lc", "exit 0")
        "submodule" = @(
            "bin/git.exe", "submodule", "status", "--recursive")
        "rebase" = @(
            "usr/bin/bash.exe", "--noprofile", "--norc", "-lc",
            "git rebase --show-current-patch")
        "git-svn" = @(
            "usr/bin/bash.exe", "--noprofile", "--norc", "-lc",
            "git svn --version")
    }
    $index = 0
    foreach ($name in $scenarioRoles.Keys) {
        $personality = $scenarioRoles[$name]
        $relative = $scenarioCommands[$name][0]
        $path = Join-Path $Fixture.Root $relative
        $hash = Get-Sha256 $path
        $start = "2026-08-27T16:{0:D2}:00Z" -f $index
        $end = "2026-08-27T16:{0:D2}:01Z" -f $index
        $traceStart = [DateTimeOffset]::Parse($start).AddSeconds(-1).
            ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                [Globalization.CultureInfo]::InvariantCulture)
        $traceEnd = [DateTimeOffset]::Parse($end).AddSeconds(1).
            ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                [Globalization.CultureInfo]::InvariantCulture)
        $process = [ordered]@{
            instanceId = "instance-$index"
            parentInstanceId = $null
            processId = 1000 + $index
            startUtc = $start
            endUtc = $end
            role = "role"
            path = $path
            sha256 = $hash
            architecture = if ($personality -ceq "msys") {
                "arm64ec"
            } else {
                "arm64"
            }
            personality = $personality
            modulesComplete = $true
            modules = @(
                [ordered]@{
                    path = $path
                    sha256 = $hash
                    architecture = if ($personality -ceq "msys") {
                        "arm64ec"
                    } else {
                        "arm64"
                    }
                    personality = $personality
                }
            )
        }
        $scenarios += [ordered]@{
            id = $name
            status = "pass"
            reason = $null
            command = @($path) + @($scenarioCommands[$name] |
                Select-Object -Skip 1)
            behavior = [ordered]@{
                operation = $scenarioOperations[$name]
                passed = $true
                exitCode = 0
            }
            trace = [ordered]@{
                complete = $true
                processEventsComplete = $true
                imageLoadEventsComplete = $true
                processTreeComplete = $true
                lostEvents = 0
                startUtc = $traceStart
                endUtc = $traceEnd
                processes = @($process)
            }
        }
        $index++
    }
    return [ordered]@{
        schemaVersion = 1
        previewId = "synthetic-preview"
        admissionMode = "Final"
        sourceLockSha256 = ("0" * 64)
        lockSha256 = ("0" * 64)
        provenanceSha256 = ("0" * 64)
        payloadManifestSha256 = ("0" * 64)
        rootInventorySha256 = ("0" * 64)
        staticReportSha256 = ("0" * 64)
        validator = [ordered]@{
            repository = "crutkas/build-extra"
            commit = $script:validatorCommit
            path = "validate-arm64-bundle.ps1"
            bytes = $script:validatorBytes
            sha256 = $script:validatorSha256
            mode = "Runtime"
        }
        host = [ordered]@{
            os = "Windows"
            architecture = "ARM64"
        }
        collector = [ordered]@{
            inputId = "collector"
            repository = "crutkas/runtime-collector"
            commit = "5555555555555555555555555555555555555555"
            sourcePath = "collect-runtime-evidence.ps1"
            url = "https://raw.githubusercontent.com/crutkas/runtime-collector/5555555555555555555555555555555555555555/collect-runtime-evidence.ps1"
            bytes = 1234
            sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
            method = "ETW-Kernel-Process-ImageLoad"
        }
        collectedUtc = "2026-08-27T17:00:00Z"
        scenarios = $scenarios
    }
}

function Sync-DigestGraph {
    param($Fixture)

    Write-Json $Fixture.LockPath $Fixture.Lock
    $Fixture.Provenance.lockSha256 = Get-Sha256 $Fixture.LockPath
    Write-Json $Fixture.ProvenancePath $Fixture.Provenance
    $Fixture.Payload.lockSha256 = Get-Sha256 $Fixture.LockPath
    $Fixture.Payload.provenanceSha256 = Get-Sha256 $Fixture.ProvenancePath
    Write-Json $Fixture.PayloadPath $Fixture.Payload
    # The static report is an input to Runtime, so generate it before the
    # evidence documents that must bind its digest.
    & pwsh -NoProfile -File $validator -Mode Preview `
        -Root $Fixture.Root -Lock $Fixture.LockPath `
        -Provenance $Fixture.ProvenancePath `
        -PayloadManifest $Fixture.PayloadPath `
        -ToolRoot $Fixture.ToolRoot `
        -Report $Fixture.StaticReportPath *> $null
    $staticReportSha256 = if (
        Test-Path -LiteralPath $Fixture.StaticReportPath) {
        Get-Sha256 $Fixture.StaticReportPath
    } else {
        ("0" * 64)
    }
    $sourceLockSha256 = Get-Sha256 $Fixture.SourceLockPath
    $Fixture.Assembly.sourceLockSha256 = $sourceLockSha256
    $Fixture.Assembly.lockSha256 = Get-Sha256 $Fixture.LockPath
    $Fixture.Assembly.provenanceSha256 = Get-Sha256 $Fixture.ProvenancePath
    $Fixture.Assembly.payloadManifestSha256 = Get-Sha256 $Fixture.PayloadPath
    $Fixture.Assembly.rootInventorySha256 =
        Get-RootInventorySha256 $Fixture.Root
    $Fixture.Assembly.staticReportSha256 = $staticReportSha256
    Write-Json $Fixture.AssemblyPath $Fixture.Assembly
    $Fixture.Runtime.sourceLockSha256 = $sourceLockSha256
    $Fixture.Runtime.lockSha256 = Get-Sha256 $Fixture.LockPath
    $Fixture.Runtime.provenanceSha256 = Get-Sha256 $Fixture.ProvenancePath
    $Fixture.Runtime.payloadManifestSha256 = Get-Sha256 $Fixture.PayloadPath
    $Fixture.Runtime.rootInventorySha256 =
        Get-RootInventorySha256 $Fixture.Root
    $Fixture.Runtime.staticReportSha256 = $staticReportSha256
    Write-Json $Fixture.RuntimePath $Fixture.Runtime
}

function Update-PayloadFile {
    param(
        $Fixture,
        [string]$Path,
        [string]$Architecture,
        [string]$Machine,
        [string]$Personality,
        [object[]]$Imports,
        $ClrFlags
    )

    $full = Join-Path $Fixture.Root $Path.Replace("/", "\")
    $hash = Get-Sha256 $full
    $bytes = [IO.FileInfo]::new($full).Length
    $payloadEntry = @($Fixture.Payload.entries |
        Where-Object path -CEQ $Path)[0]
    $payloadEntry.bytes = $bytes
    $payloadEntry.sha256 = $hash
    $final = @($Fixture.Provenance.finalMembers |
        Where-Object destinationPath -CEQ $Path)[0]
    $final.bytes = $bytes
    $final.sha256 = $hash
    $input = @($Fixture.Provenance.inputs |
        Where-Object id -CEQ $final.inputId)[0]
    $archive = @($input.archiveMembers |
        Where-Object sourceMember -CEQ $final.sourceMember)[0]
    $archive.bytes = $bytes
    $archive.sha256 = $hash
    $Fixture.Classification[$Path] = [ordered]@{
        architecture = $Architecture
        personality = $Personality
    }

    $Fixture.Provenance.pseudoReloc.candidates = @(
        $Fixture.Payload.entries |
            Where-Object {
                $_.type -ceq "file" -and
                $null -ne $Fixture.Classification[$_.path] -and
                $Fixture.Classification[$_.path].architecture -ceq "arm64" -and
                $Fixture.Classification[$_.path].personality -ceq "msys"
            } |
            ForEach-Object {
                $owner = @($Fixture.Provenance.finalMembers |
                    Where-Object destinationPath -CEQ $_.path)[0]
                [ordered]@{
                    destinationPath = $_.path
                    inputId = $owner.inputId
                    sourceMember = $owner.sourceMember
                }
            } |
            Sort-Object destinationPath)

    foreach ($scenario in $Fixture.Runtime.scenarios) {
        if ($null -eq $scenario.trace) {
            continue
        }
        foreach ($process in $scenario.trace.processes) {
            if ($process.path -ieq $full) {
                $process.sha256 = $hash
                $process.architecture = $Architecture
                $process.personality = $Personality
            }
            foreach ($module in $process.modules) {
                if ($module.path -ieq $full) {
                    $module.sha256 = $hash
                    $module.architecture = $Architecture
                    $module.personality = $Personality
                }
            }
        }
    }
}

function Add-PayloadLink {
    param(
        $Fixture,
        [ValidateSet("symlink", "hardlink")][string]$Type
    )

    $targetPath = Join-Path $Fixture.Root "notice.txt"
    $name = if ($Type -ceq "symlink") {
        "notice-symlink.txt"
    } else {
        "notice-hardlink.txt"
    }
    $linkPath = Join-Path $Fixture.Root $name
    if ($Type -ceq "symlink") {
        [void](New-Item -ItemType SymbolicLink -Path $linkPath `
            -Target $targetPath)
    } else {
        [void](New-Item -ItemType HardLink -Path $linkPath `
            -Target $targetPath)
    }
    $hash = Get-Sha256 $targetPath
    $bytes = [IO.FileInfo]::new($targetPath).Length
    $lockInput = @($Fixture.Lock.inputs |
        Where-Object id -CEQ "native")[0]
    $lockInput.overlay.include = @(
        "bin", "bin/*", $name, "notice.txt") |
        Sort-Object
    $provenanceInput = @($Fixture.Provenance.inputs |
        Where-Object id -CEQ "native")[0]
    $archive = New-ArchiveMember $name $Type $bytes $hash $true `
        $name "notice.txt"
    $provenanceInput.archiveMembers = @(
        $provenanceInput.archiveMembers + $archive |
            Sort-Object { $_.sourceMember })
    $final = New-FinalMember $archive "native"
    $Fixture.Provenance.finalMembers = @(
        $Fixture.Provenance.finalMembers + $final |
            Sort-Object { $_.destinationPath })
    $payload = New-PayloadEntry $name $Type $bytes $hash `
        "non-pe" $null "none" @() $null "notice.txt"
    $Fixture.Payload.entries = @(
        $Fixture.Payload.entries + $payload |
            Sort-Object { $_.path })
}

function Set-UnresolvedScenariosExcept {
    param($Fixture, [string]$Keep)
    foreach ($scenario in $Fixture.Runtime.scenarios) {
        if ($scenario.id -cne $Keep) {
            $scenario.status = "unresolved"
            $scenario.reason = "Synthetic preview blocker"
            $scenario.behavior = $null
            $scenario.trace = $null
        }
    }
    $Fixture.Runtime.admissionMode = "Preview"
}

function Invoke-Validator {
    param(
        $Fixture,
        [ValidateSet("Preview", "Final", "Runtime")][string]$Mode,
        [string]$RootOverride,
        [string]$RuntimeOverride,
        [string]$ReportOverride,
        [string]$ValidatorOverride,
        [string]$NmMode = "absent",
        [switch]$OmitRuntime,
        [switch]$OmitStaticReport,
        [string]$StaticReportOverride
    )

    $rootArgument = if ($PSBoundParameters.ContainsKey("RootOverride")) {
        $RootOverride
    } else {
        $Fixture.Root
    }
    $reportArgument = if ($PSBoundParameters.ContainsKey("ReportOverride")) {
        $ReportOverride
    } else {
        $Fixture.ReportPath
    }
    $validatorArgument = if (
        $PSBoundParameters.ContainsKey("ValidatorOverride")) {
        $ValidatorOverride
    } elseif ($Mode -ceq "Runtime") {
        $script:runtimeValidator
    } else {
        $validator
    }
    if ($Mode -ceq "Runtime" -and -not $OmitStaticReport -and
        -not $PSBoundParameters.ContainsKey("StaticReportOverride") -and
        -not (Test-Path -LiteralPath $Fixture.StaticReportPath)) {
        # Runtime consumes a real prior static report, so produce one from the
        # same inputs first.
        $staticArguments = @(
            "-NoProfile", "-File", $validator,
            "-Mode", "Preview",
            "-Root", $rootArgument,
            "-Lock", $Fixture.LockPath,
            "-Provenance", $Fixture.ProvenancePath,
            "-PayloadManifest", $Fixture.PayloadPath,
            "-ToolRoot", $Fixture.ToolRoot,
            "-Report", $Fixture.StaticReportPath)
        $previousStaticMode = $env:FAKE_NM_MODE
        $env:FAKE_NM_MODE = $NmMode
        try {
            & pwsh @staticArguments *> $null
        } finally {
            $env:FAKE_NM_MODE = $previousStaticMode
        }
    }
    $arguments = @(
        "-NoProfile",
        "-File", $validatorArgument,
        "-Mode", $Mode,
        "-Root", $rootArgument,
        "-Lock", $Fixture.LockPath,
        "-Provenance", $Fixture.ProvenancePath,
        "-PayloadManifest", $Fixture.PayloadPath,
        "-ToolRoot", $Fixture.ToolRoot,
        "-Report", $reportArgument
    )
    if ($Mode -ceq "Runtime") {
        $arguments += @("-AssemblyEvidence", $Fixture.AssemblyPath)
        if (-not $OmitStaticReport) {
            $staticArgument = if (
                $PSBoundParameters.ContainsKey("StaticReportOverride")) {
                $StaticReportOverride
            } else {
                $Fixture.StaticReportPath
            }
            $arguments += @("-StaticReport", $staticArgument)
        }
        if (-not $OmitRuntime) {
            $runtimeArgument = if (
                $PSBoundParameters.ContainsKey("RuntimeOverride")) {
                $RuntimeOverride
            } else {
                $Fixture.RuntimePath
            }
            $arguments += @("-RuntimeEvidence", $runtimeArgument)
        }
    } elseif ($PSBoundParameters.ContainsKey("RuntimeOverride")) {
        $arguments += @("-RuntimeEvidence", $RuntimeOverride)
    }
    if ($Mode -cne "Runtime" -and
        $PSBoundParameters.ContainsKey("StaticReportOverride")) {
        $arguments += @("-StaticReport", $StaticReportOverride)
    }
    $previousMode = $env:FAKE_NM_MODE
    $env:FAKE_NM_MODE = $NmMode
    try {
        $output = (& pwsh @arguments 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    } finally {
        $env:FAKE_NM_MODE = $previousMode
    }
    $report = $null
    if (Test-Path -LiteralPath $reportArgument -PathType Leaf) {
        try {
            $report = Get-Content -LiteralPath $reportArgument -Raw |
                ConvertFrom-Json
        } catch {
            $report = $null
        }
    }
    return [ordered]@{
        Code = $code
        Output = $output
        Report = $report
    }
}

function Assert-Result {
    param(
        [string]$Name,
        $Result,
        [int]$ExpectedCode,
        [string]$ExpectedText,
        [Nullable[bool]]$ReadyForFinal
    )

    if ($Result.Code -ne $ExpectedCode) {
        throw "$Name expected exit $ExpectedCode, got $($Result.Code): $($Result.Output)"
    }
    if ($null -eq $Result.Report -or
        [int]$Result.Report.exitCode -ne $ExpectedCode) {
        throw "$Name did not emit the expected deterministic report"
    }
    if (-not [string]::IsNullOrEmpty($ExpectedText) -and
        $Result.Output -cnotlike "*$ExpectedText*") {
        throw "$Name did not report '$ExpectedText': $($Result.Output)"
    }
    if ($null -ne $ReadyForFinal -and
        [bool]$Result.Report.readyForFinal -ne [bool]$ReadyForFinal) {
        throw "$Name readyForFinal differs from expected"
    }
    $script:passed++
}

function Invoke-Case {
    param(
        [string]$Name,
        [ValidateSet("Preview", "Final", "Runtime")][string]$Mode,
        [scriptblock]$Mutate,
        [int]$ExpectedCode,
        [string]$ExpectedText = "",
        [Nullable[bool]]$ReadyForFinal,
        [string]$NmMode = "absent",
        [string]$RootOverride,
        [string]$RuntimeOverride,
        [string]$ValidatorOverride,
        [switch]$SkipSync,
        [switch]$OmitStaticReport,
        [string]$StaticReportOverride
    )

    $fixture = New-TestFixture $Name
    if ($null -ne $Mutate) {
        & $Mutate $fixture
    }
    if (-not $SkipSync) {
        Sync-DigestGraph $fixture
    }
    $invoke = @{
        Fixture = $fixture
        Mode = $Mode
        NmMode = $NmMode
    }
    if ($PSBoundParameters.ContainsKey("RootOverride")) {
        $invoke.RootOverride = $RootOverride
    }
    if ($PSBoundParameters.ContainsKey("RuntimeOverride")) {
        $invoke.RuntimeOverride = $RuntimeOverride
    }
    if ($PSBoundParameters.ContainsKey("ValidatorOverride")) {
        $invoke.ValidatorOverride = $ValidatorOverride
    }
    if ($OmitStaticReport) {
        $invoke.OmitStaticReport = $true
    }
    if ($PSBoundParameters.ContainsKey("StaticReportOverride")) {
        $invoke.StaticReportOverride = $StaticReportOverride
    }
    $result = Invoke-Validator @invoke
    Assert-Result $Name $result $ExpectedCode $ExpectedText $ReadyForFinal
    return [ordered]@{
        Fixture = $fixture
        Result = $result
    }
}

try {
    [void](New-Item -ItemType Directory -Path $suite)
    $runtimeRepo = Join-Path $suite "validator-repo"
    [void](New-Item -ItemType Directory -Path (
        Join-Path $runtimeRepo "arm64-validation") -Force)
    Copy-Item -LiteralPath $validator -Destination (
        Join-Path $runtimeRepo "validate-arm64-bundle.ps1")
    Copy-Item -LiteralPath (
        Join-Path $repoRoot "arm64-validation\check-aarch64-pseudo-relocs.ps1") `
        -Destination (Join-Path $runtimeRepo `
            "arm64-validation\check-aarch64-pseudo-relocs.ps1")
    Copy-Item -LiteralPath (
        Join-Path $repoRoot "arm64-x64-payload-baseline.txt") `
        -Destination (Join-Path $runtimeRepo `
            "arm64-x64-payload-baseline.txt")
    & git -C $runtimeRepo init --quiet
    & git -C $runtimeRepo config user.name "ARM64 validator test"
    & git -C $runtimeRepo config user.email "validator-test@example.com"
    & git -C $runtimeRepo config core.autocrlf false
    & git -C $runtimeRepo branch -M crutkas-validator-test
    & git -C $runtimeRepo remote add origin `
        "https://github.com/crutkas/build-extra.git"
    & git -C $runtimeRepo add -- validate-arm64-bundle.ps1 `
        arm64-validation/check-aarch64-pseudo-relocs.ps1 `
        arm64-x64-payload-baseline.txt
    & git -C $runtimeRepo commit --quiet -m "Create validator fixture"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not commit the runtime validator fixture"
    }
    $script:runtimeValidator = Join-Path $runtimeRepo `
        "validate-arm64-bundle.ps1"
    $script:validatorCommit = (& git -C $runtimeRepo rev-parse HEAD).Trim()
    & git -C $runtimeRepo update-ref `
        refs/remotes/origin/crutkas-validator-test $script:validatorCommit
    $validatorTree = (& git -C $runtimeRepo rev-parse "HEAD^{tree}").Trim()
    $script:validatorOtherCommit = (& git -C $runtimeRepo commit-tree `
        $validatorTree -p $script:validatorCommit -m "Other branch fixture").Trim()
    & git -C $runtimeRepo update-ref `
        refs/remotes/origin/crutkas-other-test $script:validatorOtherCommit
    $script:validatorDanglingCommit = (& git -C $runtimeRepo commit-tree `
        $validatorTree -m "Dangling fixture").Trim()
    $script:validatorBytes = [IO.FileInfo]::new(
        $script:runtimeValidator).Length
    $script:validatorSha256 = Get-Sha256 $script:runtimeValidator
    if ($LASTEXITCODE -ne 0 -or
        $script:validatorCommit -cnotmatch "^[0-9a-f]{40}$") {
        throw "Could not identify the validator checkout commit"
    }
    $fakeToolSource = @'
using System;
using System.IO;

public static class FakeArm64Tool
{
    public static int Main(string[] args)
    {
        string name = Path.GetFileName(
            System.Reflection.Assembly.GetExecutingAssembly().Location);
        if (name.IndexOf("objdump", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            if (args.Length > 0 && args[0] == "-f")
            {
                Console.WriteLine("file format pei-aarch64-little");
                Console.WriteLine("architecture: aarch64");
                return 0;
            }
            if (args.Length > 0 && args[0] == "-h")
            {
                Console.WriteLine(
                    "  0 .rdata 00000400 0000000140001000 " +
                    "0000000140001000 00000200");
                return 0;
            }
            return 1;
        }
        string mode = Environment.GetEnvironmentVariable("FAKE_NM_MODE");
        if (mode == "v2")
        {
            Console.WriteLine(
                "0000000140001180 D __RUNTIME_PSEUDO_RELOC_LIST__");
            Console.WriteLine(
                "0000000140001198 D __RUNTIME_PSEUDO_RELOC_LIST_END__");
        }
        else if (mode == "empty")
        {
            Console.WriteLine(
                "0000000140001180 D __RUNTIME_PSEUDO_RELOC_LIST__");
            Console.WriteLine(
                "0000000140001180 D __RUNTIME_PSEUDO_RELOC_LIST_END__");
        }
        else if (mode == "v1")
        {
            Console.WriteLine(
                "0000000140001180 D __RUNTIME_PSEUDO_RELOC_LIST__");
            Console.WriteLine(
                "0000000140001188 D __RUNTIME_PSEUDO_RELOC_LIST_END__");
        }
        else if (mode == "malformed")
        {
            Console.WriteLine(
                "0000000140001180 D __RUNTIME_PSEUDO_RELOC_LIST__");
            Console.WriteLine(
                "0000000140001183 D __RUNTIME_PSEUDO_RELOC_LIST_END__");
        }
        return 0;
    }
}
'@
    $script:fakeTool = Join-Path $suite "fake-arm64-tool.exe"
    $fakeToolSourcePath = Join-Path $suite "fake-arm64-tool.cs"
    [IO.File]::WriteAllText($fakeToolSourcePath, $fakeToolSource, $utf8)
    & powershell.exe -NoProfile -Command @"
`$ErrorActionPreference = 'Stop'
Add-Type -Path '$fakeToolSourcePath' -OutputAssembly '$script:fakeTool' -OutputType ConsoleApplication
"@
    if ($LASTEXITCODE -ne 0 -or
        -not [IO.File]::Exists($script:fakeTool)) {
        throw "Could not compile the deterministic fake pseudo-reloc tools"
    }
    $pseudoValidatorRoot = Join-Path $suite "pseudo-validator"
    [void](New-Item -ItemType Directory -Path (
        Join-Path $pseudoValidatorRoot "arm64-validation") -Force)
    $script:pseudoValidator = Join-Path $pseudoValidatorRoot `
        "validate-arm64-bundle.ps1"
    $fakeToolBytes = [IO.FileInfo]::new($script:fakeTool).Length
    $fakeToolSha256 = Get-Sha256 $script:fakeTool
    $pseudoValidatorText = [IO.File]::ReadAllText($validator).
        Replace("2887699", [string]$fakeToolBytes).
        Replace(
            "bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e",
            $fakeToolSha256).
        Replace("1257877", [string]$fakeToolBytes).
        Replace(
            "80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a",
            $fakeToolSha256)
    [IO.File]::WriteAllText(
        $script:pseudoValidator, $pseudoValidatorText, $utf8)
    Copy-Item -LiteralPath (
        Join-Path $repoRoot "arm64-validation\check-aarch64-pseudo-relocs.ps1") `
        -Destination (Join-Path $pseudoValidatorRoot `
            "arm64-validation\check-aarch64-pseudo-relocs.ps1")
    Copy-Item -LiteralPath (
        Join-Path $repoRoot "arm64-x64-payload-baseline.txt") `
        -Destination (Join-Path $pseudoValidatorRoot `
            "arm64-x64-payload-baseline.txt")

    $tokens = $null
    $parseErrors = $null
    $validatorAst = [Management.Automation.Language.Parser]::ParseFile(
        $validator, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "Validator helper regression could not parse the validator"
    }
    foreach ($helperName in @(
        "Test-OrdinalStringEqual",
        "Test-OrdinalStringSequenceEqual",
        "Throw-ValidationError",
        "Assert-PropertyOrder")) {
        $helper = @($validatorAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                [string]::Equals(
                    $node.Name,
                    $helperName,
                    [StringComparison]::Ordinal)
        }, $true))
        if ($helper.Count -ne 1) {
            throw "Validator is missing the exact '$helperName' helper"
        }
        . ([scriptblock]::Create($helper[0].Extent.Text))
    }
    $boundaryLeft = @(
        "schemaVersion`0sourceLock",
        "sourceDateEpoch")
    $boundaryRight = @(
        "schemaVersion",
        "sourceLock`0sourceDateEpoch")
    if (-not [string]::Equals(
            [string]::Join("`0", $boundaryLeft),
            [string]::Join("`0", $boundaryRight),
            [StringComparison]::Ordinal)) {
        throw "Boundary regression did not construct a joined-string collision"
    }
    if (Test-OrdinalStringSequenceEqual $boundaryLeft $boundaryRight) {
        throw "Ordinal sequence equality collapsed array element boundaries"
    }
    $propertyObject = [pscustomobject][ordered]@{
        "schemaVersion`0sourceLock" = 1
        sourceDateEpoch = 1787846400
    }
    $propertyOrderRejected = $false
    try {
        Assert-PropertyOrder $propertyObject $boundaryRight `
            "property boundary regression" 20
    } catch {
        $propertyOrderRejected = [string]::Equals(
            [string]$_.Exception.Data["Category"],
            "ordering",
            [StringComparison]::Ordinal)
    }
    if (-not $propertyOrderRejected) {
        throw "Property order comparison collapsed property boundaries"
    }
    $passed++

    Invoke-Case "preview-pass" Preview $null 0 "" $true | Out-Null
    Invoke-Case "final-pass" Final $null 0 "" $true | Out-Null
    Invoke-Case "runtime-pass" Runtime $null 0 "" $true | Out-Null

    Invoke-Case "producer-classification-field-rejected" Preview {
        param($f)
        @($f.Payload.entries |
            Where-Object path -CEQ "bin/git.exe")[0]["architecture"] = "arm64"
    } 20 "payload manifest entry" $null | Out-Null

    Invoke-Case "runtime-missing-static-report" Runtime $null 40 `
        "-StaticReport is required only for -Mode Runtime" $null `
        -OmitStaticReport | Out-Null

    Invoke-Case "static-report-rejected-in-static-mode" Preview $null 20 `
        "-StaticReport applies only to -Mode Runtime" $null `
        -StaticReportOverride "does-not-matter.json" | Out-Null

    $tamperedStatic = Invoke-Case "runtime-tampered-static-report" Runtime {
        param($f)
        Sync-DigestGraph $f
        $report = Get-Content -LiteralPath $f.StaticReportPath -Raw |
            ConvertFrom-Json
        $report.digests.rootInventorySha256 = ("a" * 64)
        Write-Json $f.StaticReportPath $report
    } 40 "does not bind this run" $null -SkipSync
    $tamperedStatic | Out-Null

    Invoke-Case "runtime-static-report-digest-unbound" Runtime {
        param($f)
        Sync-DigestGraph $f
        $f.Runtime.staticReportSha256 = ("b" * 64)
        Write-Json $f.RuntimePath $f.Runtime
    } 40 "staticReportSha256 does not match its bound input" $null `
        -SkipSync | Out-Null

    $classificationCase = Invoke-Case "static-report-owns-classification" `
        Preview $null 0 "" $true
    $classificationReport = $classificationCase.Result.Report
    $gitClassification = @($classificationReport.classifications |
        Where-Object path -CEQ "bin/git.exe")[0]
    $bashClassification = @($classificationReport.classifications |
        Where-Object path -CEQ "usr/bin/bash.exe")[0]
    if ($null -eq $gitClassification -or
        $gitClassification.architecture -cne "arm64" -or
        $gitClassification.machine -cne "0xAA64" -or
        $null -eq $bashClassification -or
        $bashClassification.architecture -cne "arm64ec" -or
        $bashClassification.machine -cne "0xA641" -or
        $bashClassification.personality -cne "msys" -or
        @($bashClassification.imports) -cnotcontains "msys-2.0.dll") {
        throw "Static report does not carry authoritative classifications"
    }
    if ($null -eq $classificationReport.digests.rootInventorySha256 -or
        $classificationReport.digests.rootInventorySha256.Length -ne 64) {
        throw "Static report does not carry the root inventory digest"
    }
    $script:passed++


    Invoke-Case "runtime-amd64-assembly-host" Runtime {
        param($f)
        $f.Assembly.host.architecture = "AMD64"
        $f.Assembly.host.processArchitecture = "AMD64"
    } 0 "" $true | Out-Null

    $ignoredRuntime = Join-Path $suite "does-not-exist.json"
    Invoke-Case "static-ignores-runtime" Preview $null 0 "" $true `
        -RuntimeOverride $ignoredRuntime | Out-Null

    Invoke-Case "raw-base-bundle-mapping" Preview {
        param($f)
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $input.role = "base-bundle"
        $input.resolution.method = "github-raw-commit"
        $input.release = [ordered]@{
            repository = "crutkas/native-package"
            targetCommit = "1111111111111111111111111111111111111111"
            sourcePath = "fixtures/native.pkg"
        }
        $input.asset.url =
            "https://raw.githubusercontent.com/crutkas/native-package/1111111111111111111111111111111111111111/fixtures/native.pkg"
        $input.asset.name = "native.pkg"
        $input.package = $null
        $input.overlay.mappings = @(
            [ordered]@{
                sourceMember = "bin/git.exe"
                destinationPath = "bin/git.exe"
            }
        )
        $provenanceInput = @($f.Provenance.inputs |
            Where-Object id -CEQ "native")[0]
        $provenanceInput.release = $input.release
        $provenanceInput.asset = $input.asset
        $provenanceInput.package = $null
    } 0 "" $true | Out-Null

    $rawBuildExtraMutation = {
        param($f)
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $input.resolution.method = "github-raw-commit"
        $input.release = [ordered]@{
            repository = "crutkas/build-extra"
            targetCommit = $script:reachableBuildCommit
            sourcePath = "fixtures/native.pkg"
        }
        $input.asset.url =
            "https://raw.githubusercontent.com/crutkas/build-extra/$script:reachableBuildCommit/fixtures/native.pkg"
        $input.asset.name = "native.pkg"
        $input.package = $null
        $provenanceInput = @($f.Provenance.inputs |
            Where-Object id -CEQ "native")[0]
        $provenanceInput.release = $input.release
        $provenanceInput.asset = $input.asset
        $provenanceInput.package = $null
    }
    Invoke-Case "raw-build-extra-reachable-commit" Preview `
        $rawBuildExtraMutation 0 "" $true | Out-Null
    Invoke-Case "raw-build-extra-nonexistent-commit" Preview {
        param($f)
        & $rawBuildExtraMutation $f
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $input.release.targetCommit = ("a" * 40)
        $input.asset.url =
            "https://raw.githubusercontent.com/crutkas/build-extra/$('a' * 40)/fixtures/native.pkg"
    } 20 "does not resolve to a local commit object" $null | Out-Null
    Invoke-Case "raw-build-extra-unreachable-commit" Preview {
        param($f)
        & $rawBuildExtraMutation $f
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $input.release.targetCommit = $script:unreachableBuildCommit
        $input.asset.url =
            "https://raw.githubusercontent.com/crutkas/build-extra/$script:unreachableBuildCommit/fixtures/native.pkg"
    } 20 "not reachable from the checked-out authoritative" $null | Out-Null

    $derivedTreeMutation = {
        param($f)
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $input.role = "base-bundle"
        $input.resolution = [ordered]@{
            method = "derived-tree"
            build = [ordered]@{
                repository = "crutkas/build-extra"
                commit = $script:reachableBuildCommit
            }
            sdkSource = $null
            manifest = [ordered]@{
                path = "preview-evidence/base-tree-manifest.v1.json"
                sha256 = ("0" * 64)
            }
        }
        $input.release = $null
        $input.asset = $null
        $input.package = $null
        $provenanceInput = @($f.Provenance.inputs |
            Where-Object id -CEQ "native")[0]
        $provenanceInput.release = $null
        $provenanceInput.asset = $null
        $provenanceInput.package = $null
        $manifestPath = Join-Path $f.Root `
            "preview-evidence\base-tree-manifest.v1.json"
        Write-Json $manifestPath ([ordered]@{
            schemaVersion = 1
            entries = @($provenanceInput.archiveMembers | ForEach-Object {
                [ordered]@{
                    path = $_.sourceMember
                    type = $_.type
                    bytes = $_.bytes
                    sha256 = $_.sha256
                    linkTarget = $_.linkTarget
                }
            })
        })
        $input.resolution.manifest.sha256 = Get-Sha256 $manifestPath
    }
    Invoke-Case "derived-tree-base-accepted" Preview $derivedTreeMutation 0 `
        "" $true | Out-Null

    Invoke-Case "derived-tree-nonexistent-commit-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            resolution.build.commit = ("a" * 40)
    } 20 "does not resolve to a local commit object" $null | Out-Null

    Invoke-Case "derived-tree-unreachable-commit-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            resolution.build.commit = $script:unreachableBuildCommit
    } 20 "not reachable from the checked-out authoritative" $null | Out-Null

    Invoke-Case "derived-tree-manifest-hash-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            resolution.manifest.sha256 = ("1" * 64)
    } 20 "base tree manifest does not match its exact file bytes" $null |
        Out-Null

    Invoke-Case "derived-tree-extra-member-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        $input = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $manifestPath = Join-Path $f.Root `
            "preview-evidence\base-tree-manifest.v1.json"
        $document = Get-Content -Raw $manifestPath | ConvertFrom-Json
        $document.entries = @($document.entries) + [ordered]@{
            path = "zz-extra.txt"
            type = "file"
            bytes = 1
            sha256 = ("2" * 64)
            linkTarget = $null
        }
        Write-Json $manifestPath $document
        $input.resolution.manifest.sha256 = Get-Sha256 $manifestPath
    } 20 "does not cover its base tree manifest exactly" $null | Out-Null

    Invoke-Case "derived-tree-fake-asset-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].asset =
            [ordered]@{
                url = "https://github.com/crutkas/native-package/releases/download/v1.0.0/native.pkg.tar.zst"
                name = "native.pkg.tar.zst"
                bytes = 100
                sha256 = ("3" * 64)
            }
    } 20 "must set asset to null" $null | Out-Null

    Invoke-Case "derived-tree-payload-role-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].role = "payload"
    } 20 "only derive a tree for a base-bundle role" $null | Out-Null

    Invoke-Case "derived-tree-foreign-build-repository-rejected" Preview {
        param($f)
        & $derivedTreeMutation $f
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            resolution.build.repository = "crutkas/other-repo"
    } 20 "must be crutkas/build-extra" $null | Out-Null

    Invoke-Case "base-sorts-after-payload-but-applies-first" Preview $null 0 `
        "" $true | Out-Null

    Invoke-Case "non-base-first-overlay-order-rejected" Preview {
        param($f)
        $f.Provenance.overlayOrder = @("msys", "native")
    } 20 "must start with the one base-bundle" $null | Out-Null

    $undeclaredHardlinkFixture = New-TestFixture "undeclared-hardlink"
    [void](New-Item -ItemType HardLink `
        -Path (Join-Path $undeclaredHardlinkFixture.Root "notice.txt") `
        -Target (Join-Path $undeclaredHardlinkFixture.Base "outside.txt") `
        -ErrorAction SilentlyContinue)
    $outsideTarget = Join-Path $undeclaredHardlinkFixture.Base "outside.txt"
    [IO.File]::WriteAllText($outsideTarget, "synthetic payload`n", $utf8)
    Remove-Item -LiteralPath (
        Join-Path $undeclaredHardlinkFixture.Root "notice.txt") -Force
    [void](New-Item -ItemType HardLink `
        -Path (Join-Path $undeclaredHardlinkFixture.Root "notice.txt") `
        -Target $outsideTarget)
    Sync-DigestGraph $undeclaredHardlinkFixture
    $undeclaredHardlinkResult = Invoke-Validator `
        $undeclaredHardlinkFixture Preview
    Assert-Result "undeclared-hardlink" $undeclaredHardlinkResult 20 `
        "shares its file identity outside Root" $null

    $internalHardlinkFixture = New-TestFixture "undeclared-internal-hardlink"
    [void](New-Item -ItemType HardLink `
        -Path (Join-Path $internalHardlinkFixture.Root "notice-alias.txt") `
        -Target (Join-Path $internalHardlinkFixture.Root "notice.txt"))
    Sync-DigestGraph $internalHardlinkFixture
    $internalHardlinkResult = Invoke-Validator `
        $internalHardlinkFixture Preview
    Assert-Result "undeclared-internal-hardlink" $internalHardlinkResult 20 `
        "undeclared hardlink name or file identity" $null

    Invoke-Case "trailing-space-member-rejected" Preview {
        param($f)
        @($f.Provenance.inputs | Where-Object id -CEQ "native")[0].
            archiveMembers[2].sourceMember = "notice.txt "
    } 20 "component ending in a dot or space" $null | Out-Null

    Invoke-Case "trailing-dot-member-rejected" Preview {
        param($f)
        @($f.Provenance.inputs | Where-Object id -CEQ "native")[0].
            archiveMembers[2].sourceMember = "notice.txt."
    } 20 "component ending in a dot or space" $null | Out-Null

    $streamFixture = New-TestFixture "alternate-data-stream"
    Set-Content -LiteralPath (Join-Path $streamFixture.Root "notice.txt") `
        -Stream "evil" -Value "hidden payload"
    Sync-DigestGraph $streamFixture
    $streamResult = Invoke-Validator $streamFixture Preview
    Assert-Result "alternate-data-stream" $streamResult 20 `
        "alternate data stream" $null

    $directoryStreamFixture = New-TestFixture "directory-alternate-data-stream"
    $directoryStreamPath = Join-Path $directoryStreamFixture.Root "bin"
    $directoryStreamSupported = $false
    try {
        Set-Content -LiteralPath $directoryStreamPath -Stream "evil" `
            -Value "hidden directory payload" -ErrorAction Stop
        $directoryStreamSupported = $true
    } catch {
        if ($_.Exception.Message -notmatch "(?i)(not supported|not valid)") {
            throw
        }
    }
    if ($directoryStreamSupported) {
        Sync-DigestGraph $directoryStreamFixture
        $directoryStreamResult = Invoke-Validator `
            $directoryStreamFixture Preview
        Assert-Result "directory-alternate-data-stream" `
            $directoryStreamResult 20 "alternate data stream" $null
    }

    Invoke-Case "source-lock-hash-mismatch" Preview {
        param($f)
        [IO.File]::WriteAllText(
            $f.SourceLockPath,
            "{`"changed`":true}`n",
            $utf8)
    } 20 "sourceLock does not match its exact file bytes" $null | Out-Null

    $missingRuntimeFixture = New-TestFixture "runtime-evidence-required"
    $missingRuntimeResult = Invoke-Validator $missingRuntimeFixture Runtime `
        -OmitRuntime
    Assert-Result "runtime-evidence-required" $missingRuntimeResult 40 `
        "-RuntimeEvidence is required only for -Mode Runtime" $null

    $unsafeReportFixture = New-TestFixture "unsafe-report"
    $unsafeReportFixture.ReportPath = Join-Path $unsafeReportFixture.Root `
        "bin\git.exe"
    $payloadHashBefore = Get-Sha256 $unsafeReportFixture.ReportPath
    $unsafeReportResult = Invoke-Validator $unsafeReportFixture Preview
    if ($unsafeReportResult.Code -ne 10 -or
        $unsafeReportResult.Output -cnotlike
            "*Report must be outside the staged payload Root*" -or
        (Get-Sha256 $unsafeReportFixture.ReportPath) -cne $payloadHashBefore) {
        throw "unsafe-report did not reject the output path without mutation"
    }
    $passed++

    $writeFailureFixture = New-TestFixture "report-write-failure"
    $reportDirectory = Join-Path $writeFailureFixture.Base "report-directory"
    [void](New-Item -ItemType Directory -Path $reportDirectory)
    $writeFailureResult = Invoke-Validator $writeFailureFixture Preview `
        -ReportOverride $reportDirectory
    if ($writeFailureResult.Code -ne 10 -or
        $writeFailureResult.Output -cnotlike
            "*Could not write validation report*") {
        throw "report-write-failure did not force a nonzero exit"
    }
    $passed++

    $checkoutReportFixture = New-TestFixture "checkout-report"
    $scannerDependency = Join-Path $repoRoot `
        "arm64-validation\check-aarch64-pseudo-relocs.ps1"
    $scannerHashBefore = Get-Sha256 $scannerDependency
    $checkoutReportResult = Invoke-Validator $checkoutReportFixture Preview `
        -ReportOverride $scannerDependency
    if ($checkoutReportResult.Code -ne 10 -or
        $checkoutReportResult.Output -cnotlike
            "*validator input or dependency*" -or
        (Get-Sha256 $scannerDependency) -cne $scannerHashBefore) {
        throw "checkout-report did not protect a validator dependency"
    }
    $passed++

    $gitReportFixture = New-TestFixture "git-metadata-report"
    $gitDirectory = (& git -C $repoRoot rev-parse --absolute-git-dir).Trim()
    $gitHeadPath = Join-Path $gitDirectory "HEAD"
    $gitHeadHashBefore = Get-Sha256 $gitHeadPath
    $gitReportResult = Invoke-Validator $gitReportFixture Preview `
        -ReportOverride $gitHeadPath
    if ($gitReportResult.Code -ne 10 -or
        $gitReportResult.Output -cnotlike
            "*inside the validator checkout*" -or
        (Get-Sha256 $gitHeadPath) -cne $gitHeadHashBefore) {
        throw "git-metadata-report did not protect worktree metadata"
    }
    $passed++

    $deterministic = Invoke-Case "deterministic-report" Preview $null 0 "" `
        $true
    $firstReport = [IO.File]::ReadAllBytes($deterministic.Fixture.ReportPath)
    $second = Invoke-Validator $deterministic.Fixture Preview
    if ($second.Code -ne 0 -or
        [Convert]::ToBase64String($firstReport) -cne
        [Convert]::ToBase64String(
            [IO.File]::ReadAllBytes($deterministic.Fixture.ReportPath))) {
        throw "deterministic-report changed across identical runs"
    }
    $passed++

    Invoke-Case "baseline-x64-preview" Preview {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "usr/bin/bash.exe" "x64" "0x8664" `
            "mingw" @() $null
    } 0 "" $false | Out-Null

    Invoke-Case "final-x64-rejected" Final {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "usr/bin/bash.exe" "x64" "0x8664" `
            "mingw" @() $null
    } 30 "Final admission rejects all x64" $null | Out-Null

    Invoke-Case "unexpected-x64-rejected" Preview {
        param($f)
        $path = Join-Path $f.Root "bin\git.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "bin/git.exe" "x64" "0x8664" `
            "mingw" @() $null
    } 30 "Preview rejects unexpected x64" $null | Out-Null

    Invoke-Case "malformed-pe-rejected" Preview {
        param($f)
        [IO.File]::WriteAllBytes(
            (Join-Path $f.Root "bin\git.exe"),
            [byte[]](0x4d, 0x5a, 0, 0))
        Update-PayloadFile $f "bin/git.exe" "arm64" "0xAA64" `
            "mingw" @() $null
    } 30 "DOS header is truncated" $null | Out-Null

    Invoke-Case "truncated-section-rejected-before-architecture" Preview {
        param($f)
        $path = Join-Path $f.Root "bin\git.exe"
        New-TestPe $path 0xaa64
        $bytes = [IO.File]::ReadAllBytes($path)
        Set-UInt32 $bytes (0x98 + 0xf0 + 16) 0x1000
        [IO.File]::WriteAllBytes($path, $bytes)
        Update-PayloadFile $f "bin/git.exe" "arm64" "0xAA64" `
            "mingw" @() $null
    } 30 "section 0 exceeds the file" $null | Out-Null

    Invoke-Case "clr-anycpu-accepted" Preview {
        param($f)
        $path = Join-Path $f.Root "bin\git.exe"
        New-TestPe $path 0x014c -AnyCpu
        Update-PayloadFile $f "bin/git.exe" "anycpu" "0x014C" `
            "managed" @() 1
    } 0 "" $false | Out-Null

    $arm64Ec = Invoke-Case "arm64ec-classified" Preview {
        param($f)
        $path = Join-Path $f.Root "bin\git.exe"
        New-TestPe $path 0xa641
        Update-PayloadFile $f "bin/git.exe" "arm64ec" "0xA641" `
            "mingw" @() $null
    } 0 "" $false
    if (@($arm64Ec.Result.Report.classifications |
        Where-Object architecture -CEQ "arm64ec").Count -lt 1) {
        throw "arm64ec-classified did not emit the ARM64EC classification"
    }
    $passed++

    Invoke-Case "native-x86-rejected" Preview {
        param($f)
        $path = Join-Path $f.Root "bin\git.exe"
        New-TestPe $path 0x014c
        Update-PayloadFile $f "bin/git.exe" "x86" "0x014C" `
            "mingw" @() $null
    } 30 "forbidden x86 or unknown" $null | Out-Null

    Invoke-Case "mixed-msys-cygwin-rejected" Preview {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0xaa64 -Imports @(
            "msys-2.0.dll", "cygwin1.dll")
        Update-PayloadFile $f "usr/bin/bash.exe" "arm64" "0xAA64" `
            "msys" @("cygwin1.dll", "msys-2.0.dll") $null
    } 30 "mixes MSYS and Cygwin imports" $null | Out-Null

    Invoke-Case "archive-omission-rejected" Preview {
        param($f)
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        $input.archiveMembers = @($input.archiveMembers |
            Where-Object sourceMember -CNE "bin/git.exe")
    } 20 "finalMembers omit or add" $null | Out-Null

    Invoke-Case "archive-hash-mismatch-rejected" Preview {
        param($f)
        $wrong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        @($input.archiveMembers |
            Where-Object sourceMember -CEQ "bin/git.exe")[0].sha256 = $wrong
        @($f.Provenance.finalMembers |
            Where-Object destinationPath -CEQ "bin/git.exe")[0].sha256 = $wrong
    } 20 "bytes/hash do not match its archive member" $null | Out-Null

    Invoke-Case "traversal-rejected" Preview {
        param($f)
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        @($input.archiveMembers |
            Where-Object sourceMember -CEQ "bin/git.exe")[0].
            destinationPath = "../git.exe"
    } 20 "traversal" $null | Out-Null

    Invoke-Case "drive-member-path-rejected" Preview {
        param($f)
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        $input.archiveMembers[0].sourceMember = "C:/bin"
    } 20 "normalized relative slash path" $null | Out-Null

    Invoke-Case "preview-evidence-source-rejected" Preview {
        param($f)
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        @($input.archiveMembers |
            Where-Object sourceMember -CEQ "notice.txt")[0].sourceMember =
            "preview-evidence/notice.txt"
    } 20 "excluded preview-evidence prefix" $null | Out-Null

    Invoke-Case "preview-evidence-output-excluded" Preview {
        param($f)
        $directory = Join-Path $f.Root "preview-evidence"
        [IO.File]::WriteAllText(
            (Join-Path $directory "collector.log"),
            "non-authoritative output",
            $utf8)
    } 0 "" $true | Out-Null

    $uncFixture = New-TestFixture "unc-root"
    $uncResult = Invoke-Validator $uncFixture Preview `
        -RootOverride "\\server\share"
    Assert-Result "unc-root" $uncResult 20 "UNC or device" $null

    $deviceFixture = New-TestFixture "device-root"
    $deviceResult = Invoke-Validator $deviceFixture Preview `
        -RootOverride "\\?\C:\validator"
    Assert-Result "device-root" $deviceResult 20 "UNC or device" $null

    $sharedFixture = New-TestFixture "shared-root"
    $sharedResult = Invoke-Validator $sharedFixture Preview `
        -RootOverride "C:\msys64"
    Assert-Result "shared-root" $sharedResult 20 "cannot be C:\msys64" $null

    $reparseFixture = New-TestFixture "reparse-root"
    $reparseTarget = Join-Path $reparseFixture.Base "reparse-target"
    [void](New-Item -ItemType Directory -Path $reparseTarget)
    [void](New-Item -ItemType Junction `
        -Path (Join-Path $reparseFixture.Root "linked") `
        -Target $reparseTarget)
    Sync-DigestGraph $reparseFixture
    $reparseResult = Invoke-Validator $reparseFixture Preview
    Assert-Result "reparse-root" $reparseResult 20 "reparse point" $null

    Invoke-Case "safe-payload-hardlink" Preview {
        param($f)
        Add-PayloadLink $f "hardlink"
    } 0 "" $true | Out-Null

    Invoke-Case "safe-payload-symlink" Preview {
        param($f)
        Add-PayloadLink $f "symlink"
    } 0 "" $true | Out-Null

    $escapingFixture = New-TestFixture "escaping-symlink"
    $externalTarget = Join-Path $escapingFixture.Base "outside.txt"
    [IO.File]::WriteAllText($externalTarget, "outside`n", $utf8)
    [void](New-Item -ItemType SymbolicLink `
        -Path (Join-Path $escapingFixture.Root "escape.txt") `
        -Target $externalTarget)
    Sync-DigestGraph $escapingFixture
    $escapingResult = Invoke-Validator $escapingFixture Preview
    Assert-Result "escaping-symlink" $escapingResult 20 `
        "broken or escapes Root" $null

    $undeclaredFixture = New-TestFixture "undeclared-symlink"
    [void](New-Item -ItemType SymbolicLink `
        -Path (Join-Path $undeclaredFixture.Root "undeclared.txt") `
        -Target (Join-Path $undeclaredFixture.Root "notice.txt"))
    Sync-DigestGraph $undeclaredFixture
    $undeclaredResult = Invoke-Validator $undeclaredFixture Preview
    Assert-Result "undeclared-symlink" $undeclaredResult 20 `
        "member counts differ" $null

    Invoke-Case "case-collision-rejected" Preview {
        param($f)
        $copy = [ordered]@{}
        foreach ($property in $f.Payload.entries[1].GetEnumerator()) {
            $copy[$property.Key] = $property.Value
        }
        $copy.path = "bin/GIT.exe"
        $f.Payload.entries = @($f.Payload.entries + $copy)
    } 20 "case collision" $null | Out-Null

    Invoke-Case "duplicate-input-id-rejected" Preview {
        param($f)
        $f.Lock.inputs += [ordered]@{
            id = "native"
            role = "payload"
            status = "unresolved"
            resolution = $null
            release = $null
            asset = $null
            package = $null
            overlay = $null
        }
    } 20 "lock.inputs contains a duplicate or case collision" $null | Out-Null

    Invoke-Case "invalid-input-id-rejected" Preview {
        param($f)
        $f.Lock.inputs += [ordered]@{
            id = "native_alias"
            role = "payload"
            status = "unresolved"
            resolution = $null
            release = $null
            asset = $null
            package = $null
            overlay = $null
        }
    } 20 "lock input id is invalid, duplicate, or case-colliding" $null |
        Out-Null

    Invoke-Case "duplicate-asset-url-rejected" Preview {
        param($f)
        $source = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $target = @($f.Lock.inputs | Where-Object id -CEQ "msys")[0]
        $target.release.repository = $source.release.repository
        $target.release.tag = $source.release.tag
        $target.asset.name = $source.asset.name
        $target.asset.url = $source.asset.url
    } 20 "duplicate or case-colliding URL" $null | Out-Null

    Invoke-Case "duplicate-asset-name-rejected" Preview {
        param($f)
        $target = @($f.Lock.inputs | Where-Object id -CEQ "msys")[0]
        $target.asset.name = "native.pkg.tar.zst"
        $target.asset.url =
            "https://github.com/crutkas/msys-package/releases/download/v1.0.0/native.pkg.tar.zst"
    } 20 "duplicate or case-colliding asset name" $null | Out-Null

    Invoke-Case "duplicate-asset-hash-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "msys")[0].asset.sha256 =
            @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
                asset.sha256
    } 20 "duplicate or case-colliding asset hash" $null | Out-Null

    Invoke-Case "unofficial-repository-rejected" Preview {
        param($f)
        $target = @($f.Lock.inputs | Where-Object id -CEQ "msys")[0]
        $target.release.repository = "attacker/msys-package"
        $target.asset.url =
            "https://github.com/attacker/msys-package/releases/download/v1.0.0/msys.pkg.tar.zst"
    } 20 "is not on the immutable input allowlist" $null | Out-Null

    Invoke-Case "asset-url-repository-mismatch-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "msys")[0].asset.url =
            "https://github.com/crutkas/native-package/releases/download/v1.0.0/msys.pkg.tar.zst"
    } 20 "asset" $null | Out-Null

    Invoke-Case "overlay-destination-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            overlay.destination = "stage"
    } 20 "does not enforce overlay.destination" $null | Out-Null

    Invoke-Case "missing-provide-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            package.provides = @(
            "bin/git.exe", "bin/missing.exe")
    } 20 "missing expected provide" $null | Out-Null

    Invoke-Case "missing-native-closure-member" Preview {
        param($f)
        $f.Lock.nativeShellClosure += "usr/bin/missing.dll"
        $f.Provenance.nativeShellClosure += "usr/bin/missing.dll"
    } 20 "native shell closure member is missing" $null | Out-Null

    Invoke-Case "mutable-provenance-field-rejected" Preview {
        param($f)
        $f.Provenance.host = [ordered]@{
            os = "Windows"
            architecture = "ARM64"
        }
    } 20 "provenance properties must be exactly" $null | Out-Null

    Invoke-Case "winner-ownership-rejected" Preview {
        param($f)
        @($f.Provenance.finalMembers |
            Where-Object destinationPath -CEQ "bin/git.exe")[0].inputId = "msys"
    } 20 "not the exact archive winner" $null | Out-Null

    $addCollision = {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            overlay.include = @(
            "bin", "bin/*", "notice.txt", "usr")
        $input = @($f.Provenance.inputs | Where-Object id -CEQ "native")[0]
        $collided = New-ArchiveMember "usr" "directory" 0 $null $true "usr"
        $input.archiveMembers = @(
            $input.archiveMembers + $collided |
                Sort-Object { $_.sourceMember })
        # overlayOrder applies native before msys, so msys overlays last
        # and owns the colliding destination.
        $winner = @($f.Provenance.finalMembers |
            Where-Object destinationPath -CEQ "usr")[0]
        $winner.inputId = "msys"
        $f.Provenance.replacements = @(
            [ordered]@{
                destinationPath = "usr"
                replacedInputId = "native"
                replacedSourceMember = "usr"
                winnerInputId = "msys"
                winnerSourceMember = "usr"
            }
        )
    }
    Invoke-Case "explicit-overlay-collision" Preview $addCollision 0 "" `
        $true | Out-Null
    Invoke-Case "missing-overlay-replacement" Preview {
        param($f)
        & $addCollision $f
        $f.Provenance.replacements = @()
    } 20 "explicitly account for every collision" $null | Out-Null

    $unresolvedMutation = {
        param($f)
        $f.Lock.inputs += [ordered]@{
            id = "ncurses-runtime"
            role = "payload"
            status = "unresolved"
            resolution = $null
            release = $null
            asset = $null
            package = $null
            overlay = $null
        }
    }
    Invoke-Case "unresolved-preview" Preview $unresolvedMutation 0 "" `
        $false | Out-Null
    Invoke-Case "unresolved-final" Final $unresolvedMutation 20 `
        "Final admission rejects unresolved" $null | Out-Null

    Invoke-Case "mutation-risk-rejected-with-fresh-digests" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands = @(
            "pacman -Sw --noconfirm bash")
    } 40 "exactly the four read-only operations" $null | Out-Null

    Invoke-Case "full-path-pacman-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands = @(
            "C:\msys64\usr\bin\pacman.exe -Sw bash")
    } 40 "exactly the four read-only operations" $null | Out-Null

    Invoke-Case "readonly-observation-accepted" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands = @(
            "enumerate-database-manifest",
            "hash-database-manifest",
            "hash-package-log",
            "stat-package-log")
    } 0 "" $true | Out-Null

    Invoke-Case "unknown-observation-operation-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands[3] = "delete-package-log"
    } 40 "outside the read-only set" $null | Out-Null

    Invoke-Case "observation-command-order-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands = @(
            "hash-database-manifest",
            "enumerate-database-manifest",
            "hash-package-log",
            "stat-package-log")
    } 40 "outside the read-only set" $null | Out-Null

    Invoke-Case "observation-command-duplicate-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands[3] = "hash-package-log"
    } 40 "outside the read-only set" $null | Out-Null

    Invoke-Case "external-observation-change-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.after = [ordered]@{
            log = [ordered]@{
                bytes = 155151
                sha256 =
                    "925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8"
            }
            database = $f.Assembly.externalObservation.before.database
        }
    } 40 "before/after snapshots differ" $null | Out-Null

    Invoke-Case "runtime-digest-mismatch" Runtime {
        param($f)
        Sync-DigestGraph $f
        $f.Runtime.lockSha256 =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        Write-Json $f.RuntimePath $f.Runtime
    } 40 "lockSha256 does not match its bound input" $null `
        -SkipSync | Out-Null

    Invoke-Case "runtime-x64-payload-blocks-admission" Runtime {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "usr/bin/bash.exe" "x64" "0x8664" `
            "mingw" @() $null
        $f.Runtime.admissionMode = "Preview"
    } 40 "static state that is readyForFinal" $null | Out-Null

    # Reaches the runtime PROCESS policy, which the payload-level x64 cases
    # never get to because the readyForFinal gate fires first.
    Invoke-Case "runtime-non-pe-process" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object id -CEQ "Git")[0]
        $notice = Join-Path $f.Root "notice.txt"
        $scenario.trace.processes[0].path = $notice
        $scenario.trace.processes[0].sha256 = Get-Sha256 $notice
        $scenario.trace.processes[0].architecture = "non-pe"
        $scenario.trace.processes[0].personality = "none"
    } 40 "violates architecture/personality policy" $null | Out-Null

    Invoke-Case "runtime-x64-module" Runtime {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "usr/bin/bash.exe" "x64" "0x8664" `
            "mingw" @() $null
        Set-UnresolvedScenariosExcept $f "Git"
        $git = @($f.Runtime.scenarios | Where-Object id -CEQ "Git")[0]
        $git.trace.processes[0].modules = @(
            [ordered]@{
                path = $path
                sha256 = Get-Sha256 $path
                architecture = "x64"
                personality = "mingw"
            }
        )
    } 40 "static state that is readyForFinal" $null | Out-Null

    Invoke-Case "runtime-non-pe-module" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object id -CEQ "Git")[0]
        $notice = Join-Path $f.Root "notice.txt"
        $scenario.trace.processes[0].modules = @(
            [ordered]@{
                path = $notice
                sha256 = Get-Sha256 $notice
                architecture = "non-pe"
                personality = "none"
            }
        )
    } 40 "violates architecture/personality policy" $null | Out-Null

    Invoke-Case "runtime-incomplete-etw" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.imageLoadEventsComplete = $false
    } 40 "incomplete or lossy ETW evidence" $null | Out-Null

    Invoke-Case "runtime-lost-etw-events" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.lostEvents = 1
    } 40 "incomplete or lossy ETW evidence" $null | Out-Null

    Invoke-Case "runtime-sampling-collector-rejected" Runtime {
        param($f)
        $f.Runtime.collector.method = "Process.Modules"
    } 40 "resolved raw-commit validation-tool input" $null | Out-Null

    Invoke-Case "runtime-collector-input-rejected" Runtime {
        param($f)
        $f.Runtime.collector.inputId = "binutils"
    } 40 "resolved raw-commit validation-tool input" $null | Out-Null

    Invoke-Case "runtime-collector-self-attestation-rejected" Runtime {
        param($f)
        $f.Runtime.collector.sha256 = ("6" * 64)
    } 40 "differs from its canonical lock input" $null | Out-Null

    Invoke-Case "runtime-validator-commit-rejected" Runtime {
        param($f)
        $f.Runtime.validator.commit =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    } 40 "must equal the checked-out authoritative branch HEAD" $null | Out-Null

    Invoke-Case "runtime-validator-dangling-commit-rejected" Runtime {
        param($f)
        $f.Runtime.validator.commit = $script:validatorDanglingCommit
    } 40 "must equal the checked-out authoritative branch HEAD" $null | Out-Null

    Invoke-Case "runtime-validator-other-branch-rejected" Runtime {
        param($f)
        $f.Runtime.validator.commit = $script:validatorOtherCommit
    } 40 "must equal the checked-out authoritative branch HEAD" $null | Out-Null

    Invoke-Case "runtime-incomplete-modules" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].modulesComplete = $false
    } 40 "module trace is incomplete" $null | Out-Null

    Invoke-Case "runtime-command-vector-mismatch" Runtime {
        param($f)
        $f.Runtime.scenarios[0].command[0] =
            (Join-Path $f.Root "bin\git.exe")
    } 40 "closed required argument vector" $null | Out-Null

    Invoke-Case "runtime-soft-hyphen-bash-command-rejected" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object {
            [string]::Equals(
                $_.id, "Git Bash", [StringComparison]::Ordinal)
        })[0]
        $tampered = Join-Path $f.Root (
            "usr\bin\ba" + [char]0x00ad + "sh.exe")
        $scenario.command[0] = $tampered
        if (-not [string]::Equals(
                $scenario.command[0],
                $tampered,
                [StringComparison]::Ordinal)) {
            throw "Soft-hyphen command regression did not preserve the mutation"
        }
    } 40 "collation-ignorable character U+00AD" $null | Out-Null

    Invoke-Case "runtime-soft-hyphen-personality-rejected" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object {
            [string]::Equals(
                $_.id, "Git Bash", [StringComparison]::Ordinal)
        })[0]
        $tampered = "m" + [char]0x00ad + "sys"
        $scenario.trace.processes[0].personality = $tampered
        $scenario.trace.processes[0].modules[0].personality = $tampered
        if (-not [string]::Equals(
                $scenario.trace.processes[0].personality,
                $tampered,
                [StringComparison]::Ordinal)) {
            throw "Soft-hyphen personality regression did not preserve the mutation"
        }
    } 40 "collation-ignorable character U+00AD" $null | Out-Null

    Invoke-Case "soft-hyphen-payload-path-rejected" Preview {
        param($f)
        $tampered = "bin/gi" + [char]0x00ad + "t.exe"
        @($f.Payload.entries |
            Where-Object path -CEQ "bin/git.exe")[0].path = $tampered
    } 20 "collation-ignorable character U+00AD" $null | Out-Null

    Invoke-Case "zero-width-joiner-payload-path-rejected" Preview {
        param($f)
        $tampered = "bin/gi" + [char]0x200d + "t.exe"
        @($f.Payload.entries |
            Where-Object path -CEQ "bin/git.exe")[0].path = $tampered
    } 20 "collation-ignorable character U+200D" $null | Out-Null

    # U+034F and U+0001 are collation-ignorable but are NOT category Format,
    # which a category-based screen would miss.
    Invoke-Case "grapheme-joiner-payload-path-rejected" Preview {
        param($f)
        $tampered = "bin/gi" + [char]0x034f + "t.exe"
        @($f.Payload.entries |
            Where-Object path -CEQ "bin/git.exe")[0].path = $tampered
    } 20 "collation-ignorable character U+034F" $null | Out-Null

    Invoke-Case "control-character-payload-path-rejected" Preview {
        param($f)
        $tampered = "bin/gi" + [char]0x0001 + "t.exe"
        @($f.Payload.entries |
            Where-Object path -CEQ "bin/git.exe")[0].path = $tampered
    } 20 "collation-ignorable character U+0001" $null | Out-Null

    Invoke-Case "variation-selector-repository-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "msys")[0].
            release.repository = "crutkas/msys" + [char]0xfe0f + "-package"
    } 20 "collation-ignorable character U+FE0F" $null | Out-Null

    Invoke-Case "same-input-destination-collision-rejected" Preview {
        param($f)
        # Two members of one input resolving to a single destination would make
        # the overlay winner depend on an unstable sort. The archive-member
        # destination rule rejects the construction before it can arise; the
        # explicit same-input guard backs that up.
        $lockInput = @($f.Lock.inputs | Where-Object id -CEQ "native")[0]
        $lockInput.overlay.mappings = @(
            [ordered]@{
                sourceMember = "notice.txt"
                destinationPath = "bin/git.exe"
            }
        )
    } 20 "does not enforce overlay.destination" $null | Out-Null

    Invoke-Case "runtime-soft-hyphen-repository-rejected" Runtime {
        param($f)
        $tampered = "crutkas/bu" + [char]0x00ad + "ild-extra"
        $f.Runtime.validator.repository = $tampered
        if (-not [string]::Equals(
                $f.Runtime.validator.repository,
                $tampered,
                [StringComparison]::Ordinal)) {
            throw "Soft-hyphen repository regression did not preserve the mutation"
        }
    } 40 "collation-ignorable character U+00AD" $null | Out-Null

    Invoke-Case "runtime-command-boundary-collapse-rejected" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object {
            [string]::Equals(
                $_.id, "Git Bash", [StringComparison]::Ordinal)
        })[0]
        $collapsedArguments = [string]::Join(
            "`0", [string[]]@($scenario.command | Select-Object -Skip 1))
        $scenario.command = @($scenario.command[0], $collapsedArguments)
        if ($scenario.command.Count -ne 2 -or
            -not [string]::Equals(
                $scenario.command[1],
                $collapsedArguments,
                [StringComparison]::Ordinal)) {
            throw "Command boundary regression did not preserve the mutation"
        }
    } 40 "collation-ignorable character U+0000" $null | Out-Null

    # A NUL-free collapse still has to fail on the count/element comparison
    # rather than on the collation screen.
    Invoke-Case "runtime-command-space-collapse-rejected" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object {
            [string]::Equals(
                $_.id, "Git Bash", [StringComparison]::Ordinal)
        })[0]
        $collapsed = [string]::Join(
            " ", [string[]]@($scenario.command | Select-Object -Skip 1))
        $scenario.command = @($scenario.command[0], $collapsed)
    } 40 "closed required argument vector" $null | Out-Null

    Invoke-Case "runtime-command-argument-wrong" Runtime {
        param($f)
        $git = @($f.Runtime.scenarios | Where-Object id -CEQ "Git")[0]
        $git.command[1] = "status"
    } 40 "closed required argument vector" $null | Out-Null

    Invoke-Case "runtime-command-argument-missing" Runtime {
        param($f)
        $submodule = @($f.Runtime.scenarios |
            Where-Object id -CEQ "submodule")[0]
        $submodule.command = @($submodule.command | Select-Object -SkipLast 1)
    } 40 "closed required argument vector" $null | Out-Null

    Invoke-Case "runtime-process-outside-trace" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].endUtc =
            "2026-08-27T16:00:03Z"
    } 40 "lies outside its trace interval" $null | Out-Null

    Invoke-Case "runtime-wrong-role-personality" Runtime {
        param($f)
        $scenario = @($f.Runtime.scenarios | Where-Object id -CEQ "Git")[0]
        $bash = Join-Path $f.Root "usr\bin\bash.exe"
        $hash = Get-Sha256 $bash
        $process = $scenario.trace.processes[0]
        $process.path = $bash
        $process.sha256 = $hash
        $process.architecture = "arm64ec"
        $process.personality = "msys"
        $process.modules[0].path = $bash
        $process.modules[0].sha256 = $hash
        $process.modules[0].architecture = "arm64ec"
        $process.modules[0].personality = "msys"
    } 40 "role process must be mingw" $null | Out-Null

    Invoke-Case "static-cygwin-personality" Preview {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0xaa64 -Imports @("cygwin1.dll")
        Update-PayloadFile $f "usr/bin/bash.exe" "arm64" "0xAA64" `
            "cygwin" @("cygwin1.dll") $null
    } 30 "forbidden Cygwin personality" $null | Out-Null

    Invoke-Case "runtime-cygwin-personality" Runtime {
        param($f)
        $process = $f.Runtime.scenarios[0].trace.processes[0]
        $process.personality = "cygwin"
        $process.modules[0].personality = "cygwin"
    } 40 "identity is not authoritative" $null | Out-Null

    Invoke-Case "runtime-external-module" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].modules[0].path =
            "C:\external\module.dll"
    } 40 "outside the staged root and trusted Windows" $null | Out-Null

    Invoke-Case "runtime-windows-temp-module-rejected" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].modules[0].path =
            "C:\Windows\Temp\synthetic-module.dll"
    } 40 "outside the trusted Windows system directories" $null | Out-Null

    Invoke-Case "runtime-windows-tasks-module-rejected" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].modules[0].path =
            "C:\Windows\Tasks\synthetic-module.dll"
    } 40 "outside the trusted Windows system directories" $null | Out-Null

    Invoke-Case "runtime-final-unresolved-scenario" Runtime {
        param($f)
        $scenario = $f.Runtime.scenarios[0]
        $scenario.status = "unresolved"
        $scenario.reason = "Not available"
        $scenario.behavior = $null
        $scenario.trace = $null
    } 40 "only Preview admission" $null | Out-Null

    Invoke-Case "runtime-preview-unresolved-scenario" Runtime {
        param($f)
        $f.Runtime.admissionMode = "Preview"
        $scenario = $f.Runtime.scenarios[0]
        $scenario.status = "unresolved"
        $scenario.reason = "Not available in Preview"
        $scenario.behavior = $null
        $scenario.trace = $null
    } 0 "" $true | Out-Null

    Invoke-Case "detected-personality-target-selection" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "native")[0].
            package.personality = "mixed"
    } 0 "" $true | Out-Null

    Invoke-Case "tool-package-binding-rejected" Preview {
        param($f)
        @($f.Lock.inputs | Where-Object id -CEQ "binutils")[0].asset.sha256 =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    } 20 "not bound to the pinned immutable package" $null | Out-Null

    Invoke-Case "tool-member-hash-rejected" Preview {
        param($f)
        $input = @($f.Provenance.inputs |
            Where-Object id -CEQ "binutils")[0]
        @($input.archiveMembers |
            Where-Object {
                $_.sourceMember -ceq "opt/bin/aarch64-pc-cygwin-nm.exe"
            })[0].sha256 =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    } 20 "pinned tool package member identity is incorrect" $null | Out-Null

    Invoke-Case "pseudo-reloc-fake-tools-rejected" Preview {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0xaa64 -Imports @("msys-2.0.dll") -PseudoFlag 64
        Update-PayloadFile $f "usr/bin/bash.exe" "arm64" "0xAA64" `
            "msys" @("msys-2.0.dll") $null
    } 10 "does not match its verified archive record" $null `
        -NmMode "v2" | Out-Null

    $pseudoProofMutation = {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0xaa64 -Imports @("msys-2.0.dll") -PseudoFlag 64
        Update-PayloadFile $f "usr/bin/bash.exe" "arm64" "0xAA64" `
            "msys" @("msys-2.0.dll") $null
        $toolInput = @($f.Provenance.inputs |
            Where-Object id -CEQ "binutils")[0]
        foreach ($memberName in @(
            "opt/bin/aarch64-pc-cygwin-nm.exe",
            "opt/bin/aarch64-pc-cygwin-objdump.exe")) {
            $member = @($toolInput.archiveMembers |
                Where-Object sourceMember -CEQ $memberName)[0]
            $member.bytes = $fakeToolBytes
            $member.sha256 = $fakeToolSha256
        }
    }
    Invoke-Case "pseudo-reloc-absent-proof-rejected" Preview `
        $pseudoProofMutation 30 "explicit parsed empty table or scalar64 v2" `
        $null -NmMode "absent" -ValidatorOverride $script:pseudoValidator |
        Out-Null
    Invoke-Case "pseudo-reloc-explicit-empty-accepted" Preview `
        $pseudoProofMutation 0 "" $true -NmMode "empty" `
        -ValidatorOverride $script:pseudoValidator | Out-Null
    Invoke-Case "pseudo-reloc-scalar64-v2-accepted" Preview `
        $pseudoProofMutation 0 "" $true -NmMode "v2" `
        -ValidatorOverride $script:pseudoValidator | Out-Null
    Invoke-Case "pseudo-reloc-v1-proof-rejected" Preview `
        $pseudoProofMutation 30 "pseudo-reloc policy rejected" `
        $null -NmMode "v1" -ValidatorOverride $script:pseudoValidator |
        Out-Null
    Invoke-Case "pseudo-reloc-malformed-proof-rejected" Preview `
        $pseudoProofMutation 10 "pseudo-reloc scanner failed" $null `
        -NmMode "malformed" -ValidatorOverride $script:pseudoValidator |
        Out-Null

    $scannerFixture = New-TestFixture "scanner-unit"
    $scannerPath = Join-Path $repoRoot `
        "arm64-validation\check-aarch64-pseudo-relocs.ps1"
    $scannerCandidate = Join-Path $scannerFixture.Root "usr\bin\bash.exe"
    New-TestPe $scannerCandidate 0xaa64 -Imports @("msys-2.0.dll") `
        -PseudoFlag 64
    $scannerOutput = Join-Path $scannerFixture.Base "scanner-v2.json"
    $env:FAKE_NM_MODE = "v2"
    try {
        & pwsh -NoProfile -File $scannerPath `
            -PePath $scannerCandidate `
            -OutputPath $scannerOutput `
            -Objdump (Join-Path $scannerFixture.ToolRoot `
                "opt\bin\aarch64-pc-cygwin-objdump.exe") `
            -Nm (Join-Path $scannerFixture.ToolRoot `
                "opt\bin\aarch64-pc-cygwin-nm.exe") *> $null
        $scannerExit = $LASTEXITCODE
    } finally {
        $env:FAKE_NM_MODE = $null
    }
    $scannerReport = Get-Content -LiteralPath $scannerOutput -Raw |
        ConvertFrom-Json
    if ($scannerExit -ne 0 -or $scannerReport.result -cne "pass" -or
        @($scannerReport.flags).Count -ne 1 -or
        [long]$scannerReport.flags[0] -ne 64) {
        throw "Pseudo-reloc scanner did not accept the synthetic scalar64 v2 table"
    }
    $emptyTable = Join-Path $scannerFixture.Base "empty-table.bin"
    $v1Table = Join-Path $scannerFixture.Base "v1-table.bin"
    $malformedTable = Join-Path $scannerFixture.Base "malformed-table.bin"
    [IO.File]::WriteAllBytes($emptyTable, [byte[]]::new(0))
    [IO.File]::WriteAllBytes($v1Table, [byte[]]::new(8))
    [IO.File]::WriteAllBytes($malformedTable, [byte[]]::new(3))
    & pwsh -NoProfile -File $scannerPath -TablePath $emptyTable `
        -OutputPath (Join-Path $scannerFixture.Base "empty.json") *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Pseudo-reloc scanner rejected an empty table"
    }
    & pwsh -NoProfile -File $scannerPath -TablePath $v1Table `
        -OutputPath (Join-Path $scannerFixture.Base "v1.json") *> $null
    if ($LASTEXITCODE -ne 1) {
        throw "Pseudo-reloc scanner did not reject a nonempty v1 table"
    }
    & pwsh -NoProfile -File $scannerPath -TablePath $malformedTable `
        -OutputPath (Join-Path $scannerFixture.Base "malformed.json") *> $null
    if ($LASTEXITCODE -ne 2) {
        throw "Pseudo-reloc scanner did not fail closed on a malformed table"
    }
    $passed++

    foreach ($schema in Get-ChildItem -LiteralPath (
        Join-Path $repoRoot "arm64-validation\schemas") -Filter "*.json") {
        $null = Get-Content -LiteralPath $schema.FullName -Raw |
            ConvertFrom-Json -Depth 100
    }
    $passed++

    # ConvertFrom-Json accepts a dangling $ref, so resolve every local and
    # cross-file reference explicitly.
    $schemaDirectory = Join-Path $repoRoot "arm64-validation\schemas"
    $schemaObjects = @{}
    foreach ($schema in Get-ChildItem -LiteralPath $schemaDirectory `
        -Filter "*.json") {
        $schemaObjects[$schema.Name] = Get-Content -LiteralPath `
            $schema.FullName -Raw | ConvertFrom-Json -Depth 100
    }
    function Resolve-SchemaPointer {
        param($Document, [string]$Pointer)
        $cursor = $Document
        foreach ($token in @($Pointer.TrimStart("#").Trim("/").Split("/"))) {
            if ([string]::IsNullOrEmpty($token)) {
                continue
            }
            $name = $token.Replace("~1", "/").Replace("~0", "~")
            $property = $cursor.PSObject.Properties[$name]
            if ($null -eq $property) {
                return $null
            }
            $cursor = $property.Value
        }
        return $cursor
    }
    function Get-SchemaRef {
        param($Node)
        if ($Node -is [Management.Automation.PSCustomObject]) {
            foreach ($property in $Node.PSObject.Properties) {
                if ($property.Name -ceq "`$ref") {
                    [string]$property.Value
                } else {
                    Get-SchemaRef $property.Value
                }
            }
        } elseif ($Node -is [object[]]) {
            foreach ($element in $Node) {
                Get-SchemaRef $element
            }
        }
    }
    foreach ($name in $schemaObjects.Keys) {
        foreach ($reference in @(Get-SchemaRef $schemaObjects[$name])) {
            $parts = $reference.Split("#", 2)
            $targetName = if ([string]::IsNullOrEmpty($parts[0])) {
                $name
            } else {
                $parts[0]
            }
            if (-not $schemaObjects.ContainsKey($targetName)) {
                throw "Schema '$name' references unknown file '$targetName'"
            }
            if ($parts.Count -eq 2 -and $parts[1].Length -gt 0 -and
                $null -eq (Resolve-SchemaPointer `
                    $schemaObjects[$targetName] $parts[1])) {
                throw "Schema '$name' has an unresolvable `$ref '$reference'"
            }
        }
    }
    foreach ($required in @("release", "rawCommit", "asset", "package",
        "sha256", "commit", "relativePath", "baseTreeManifest")) {
        if ($null -eq $schemaObjects["common-v1.schema.json"].
            '$defs'.PSObject.Properties[$required]) {
            throw "common-v1.schema.json is missing `$defs/$required"
        }
    }
    $passed++

    $workflow = [IO.File]::ReadAllText((Join-Path $repoRoot `
        ".github\workflows\validate-arm64-bundle.yml"))
    foreach ($required in @(
        'ref: ${{ github.event.pull_request.head.ref }}',
        'EXPECTED_BRANCH: ${{ github.event.pull_request.head.ref }}',
        'EXPECTED_SHA: ${{ github.event.pull_request.head.sha }}',
        '$branch = Invoke-Git symbolic-ref --quiet --short HEAD',
        '$head = Invoke-Git rev-parse HEAD',
        '$tracking = Invoke-Git rev-parse "refs/remotes/origin/$branch"',
        '[StringComparison]::Ordinal')) {
        if (-not $workflow.Contains(
                $required, [StringComparison]::Ordinal)) {
            throw "Workflow does not pin and verify the immutable PR head: $required"
        }
    }
    if ($workflow.Contains(
            'ref: ${{ github.ref }}', [StringComparison]::Ordinal)) {
        throw "Workflow attaches the pull request merge commit instead of its head"
    }
    $passed++

    $manifestPath = Join-Path $repoRoot `
        "arm64-payload-architecture-v2.55.0.4.tsv"
    $normalized = [IO.File]::ReadAllText($manifestPath).Replace("`r`n", "`n")
    if ((Get-TextSha256 $normalized) -cne
        "ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a") {
        throw "Authoritative architecture manifest hash changed"
    }
    $rows = @($normalized.TrimEnd("`n").Split("`n") | Select-Object -Skip 1)
    $counts = @{}
    foreach ($row in $rows) {
        $architecture = $row.Split("`t")[1]
        $counts[$architecture] = 1 + [int]$counts[$architecture]
    }
    if ($rows.Count -ne 732 -or $counts.arm64 -ne 209 -or
        $counts.x64 -ne 432 -or $counts.anycpu -ne 90 -or
        $counts.x86 -ne 1) {
        throw "Authoritative architecture manifest counts changed"
    }
    $passed++

    Write-Host "validate-arm64-bundle tests passed: $passed"
} finally {
    if (Test-Path -LiteralPath $suite) {
        Remove-Item -LiteralPath $suite -Recurse -Force
    }
}
