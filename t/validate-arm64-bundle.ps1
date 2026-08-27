Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$validator = Join-Path $repoRoot "validate-arm64-bundle.ps1"
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
    return [ordered]@{
        path = $Path
        type = $Type
        bytes = $Bytes
        sha256 = $Sha256
        architecture = $Architecture
        machine = $Machine
        personality = $Personality
        imports = @($Imports)
        clrFlags = $ClrFlags
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
    $noticePath = Join-Path $payloadRoot "notice.txt"
    New-TestPe $gitPath 0xaa64
    New-TestPe $bashPath 0xa641 -Imports @("msys-2.0.dll")
    [IO.File]::WriteAllText($noticePath, "synthetic payload`n", $utf8)
    $objdumpPath = Join-Path $toolRoot `
        "opt\bin\aarch64-pc-cygwin-objdump.exe"
    $nmPath = Join-Path $toolRoot "opt\bin\aarch64-pc-cygwin-nm.exe"
    Copy-Item -LiteralPath $script:fakeTool -Destination $objdumpPath
    Copy-Item -LiteralPath $script:fakeTool -Destination $nmPath

    $native = [ordered]@{
        id = "native"
        role = "payload"
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
            provides = @("usr/bin/bash.exe")
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
        inputs = @($tools, $msys, $native)
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
    $msysProvenance.archiveMembers = @(
        $usrDirectory, $usrBinDirectory, $msysFile)

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
        inputs = @($toolProvenance, $msysProvenance, $nativeProvenance)
        overlayOrder = @("msys", "native")
        replacements = @()
        finalMembers = @(
            (New-FinalMember $nativeDirectory "native"),
            (New-FinalMember $nativeFile "native"),
            (New-FinalMember $noticeFile "native"),
            (New-FinalMember $usrDirectory "msys"),
            (New-FinalMember $usrBinDirectory "msys"),
            (New-FinalMember $msysFile "msys")
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
            commands = @()
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
                "arm64ec" "0xA641" "msys" @("msys-2.0.dll") $null)
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
    $index = 0
    foreach ($name in $scenarioRoles.Keys) {
        $personality = $scenarioRoles[$name]
        $relative = if ($personality -ceq "msys") {
            "usr\bin\bash.exe"
        } else {
            "bin\git.exe"
        }
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
            command = @($path, "--synthetic-test")
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
            repository = "crutkas/runtime-collector"
            commit = "5555555555555555555555555555555555555555"
            path = "collect-runtime-evidence.ps1"
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
    $sourceLockSha256 = Get-Sha256 $Fixture.SourceLockPath
    $Fixture.Assembly.sourceLockSha256 = $sourceLockSha256
    $Fixture.Assembly.lockSha256 = Get-Sha256 $Fixture.LockPath
    $Fixture.Assembly.provenanceSha256 = Get-Sha256 $Fixture.ProvenancePath
    $Fixture.Assembly.payloadManifestSha256 = Get-Sha256 $Fixture.PayloadPath
    $Fixture.Assembly.rootInventorySha256 =
        Get-RootInventorySha256 $Fixture.Root
    Write-Json $Fixture.AssemblyPath $Fixture.Assembly
    $Fixture.Runtime.sourceLockSha256 = $sourceLockSha256
    $Fixture.Runtime.lockSha256 = Get-Sha256 $Fixture.LockPath
    $Fixture.Runtime.provenanceSha256 = Get-Sha256 $Fixture.ProvenancePath
    $Fixture.Runtime.payloadManifestSha256 = Get-Sha256 $Fixture.PayloadPath
    $Fixture.Runtime.rootInventorySha256 =
        Get-RootInventorySha256 $Fixture.Root
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
    $payloadEntry.architecture = $Architecture
    $payloadEntry.machine = $Machine
    $payloadEntry.personality = $Personality
    $payloadEntry.imports = @($Imports)
    $payloadEntry.clrFlags = $ClrFlags
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

    $Fixture.Provenance.pseudoReloc.candidates = @(
        $Fixture.Payload.entries |
            Where-Object {
                $_.type -ceq "file" -and
                $_.architecture -ceq "arm64" -and
                $_.personality -ceq "msys"
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
        [string]$NmMode = "absent",
        [switch]$OmitRuntime
    )

    $rootArgument = if ($PSBoundParameters.ContainsKey("RootOverride")) {
        $RootOverride
    } else {
        $Fixture.Root
    }
    $arguments = @(
        "-NoProfile",
        "-File", $(if ($Mode -ceq "Runtime") {
            $script:runtimeValidator
        } else {
            $validator
        }),
        "-Mode", $Mode,
        "-Root", $rootArgument,
        "-Lock", $Fixture.LockPath,
        "-Provenance", $Fixture.ProvenancePath,
        "-PayloadManifest", $Fixture.PayloadPath,
        "-ToolRoot", $Fixture.ToolRoot,
        "-Report", $Fixture.ReportPath
    )
    if ($Mode -ceq "Runtime") {
        $arguments += @("-AssemblyEvidence", $Fixture.AssemblyPath)
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
    $previousMode = $env:FAKE_NM_MODE
    $env:FAKE_NM_MODE = $NmMode
    try {
        $output = (& pwsh @arguments 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    } finally {
        $env:FAKE_NM_MODE = $previousMode
    }
    $report = $null
    if (Test-Path -LiteralPath $Fixture.ReportPath) {
        try {
            $report = Get-Content -LiteralPath $Fixture.ReportPath -Raw |
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
        [switch]$SkipSync
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

    Invoke-Case "preview-pass" Preview $null 0 "" $true | Out-Null
    Invoke-Case "final-pass" Final $null 0 "" $true | Out-Null
    Invoke-Case "runtime-pass" Runtime $null 0 "" $true | Out-Null

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
        # overlayOrder applies msys before native, so native overlays last
        # and owns the colliding destination.
        $winner = @($f.Provenance.finalMembers |
            Where-Object destinationPath -CEQ "usr")[0]
        $winner.inputId = "native"
        $f.Provenance.replacements = @(
            [ordered]@{
                destinationPath = "usr"
                replacedInputId = "msys"
                replacedSourceMember = "usr"
                winnerInputId = "native"
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
    } 40 "forbidden pacman command" $null | Out-Null

    Invoke-Case "full-path-pacman-rejected" Runtime {
        param($f)
        $f.Assembly.externalObservation.commands = @(
            "C:\msys64\usr\bin\pacman.exe -Sw bash")
    } 40 "forbidden pacman command" $null | Out-Null

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

    Invoke-Case "runtime-x64-process" Runtime {
        param($f)
        $path = Join-Path $f.Root "usr\bin\bash.exe"
        New-TestPe $path 0x8664
        Update-PayloadFile $f "usr/bin/bash.exe" "x64" "0x8664" `
            "mingw" @() $null
        $f.Runtime.admissionMode = "Preview"
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
    } 40 "runtime module" $null | Out-Null

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
    } 40 "immutable crutkas ETW collector" $null | Out-Null

    Invoke-Case "runtime-validator-commit-rejected" Runtime {
        param($f)
        $f.Runtime.validator.commit =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    } 40 "does not match the committed executable" $null | Out-Null

    Invoke-Case "runtime-incomplete-modules" Runtime {
        param($f)
        $f.Runtime.scenarios[0].trace.processes[0].modulesComplete = $false
    } 40 "module trace is incomplete" $null | Out-Null

    Invoke-Case "runtime-command-vector-mismatch" Runtime {
        param($f)
        $f.Runtime.scenarios[0].command[0] =
            (Join-Path $f.Root "bin\git.exe")
    } 40 "command does not start with its role process" $null | Out-Null

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
    } 40 "outside the staged root and C:\Windows" $null | Out-Null

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
