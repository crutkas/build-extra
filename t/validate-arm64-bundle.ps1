Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$validator = Join-Path $root "validate-arm64-bundle.ps1"
$peImports = Join-Path $root "pe-imports.ps1"
$trash = Join-Path ([IO.Path]::GetTempPath()) "validate-arm64-bundle-$PID"

function Write-Json {
    param([string]$Path, [object]$Value)

    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path,
        ($Value | ConvertTo-Json -Depth 30) + "`n", $utf8)
}

function Set-UInt16 {
    param([byte[]]$Bytes, [int]$Offset, [uint16]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-UInt32 {
    param([byte[]]$Bytes, [int]$Offset, [uint32]$Value)
    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function New-TestPe {
    param(
        [string]$Path,
        [ValidateSet("arm64", "x64", "x86", "anycpu")]
        [string]$Architecture,
        [ValidateSet("mingw", "msys")]
        [string]$Personality = "mingw"
    )

    $bytes = New-Object byte[] 768
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    Set-UInt32 $bytes 0x3c 0x40
    $bytes[0x40] = 0x50
    $bytes[0x41] = 0x45

    $machine = switch ($Architecture) {
        "arm64" { 0xaa64 }
        "x64" { 0x8664 }
        default { 0x014c }
    }
    Set-UInt16 $bytes 0x44 $machine
    Set-UInt16 $bytes 0x46 1
    Set-UInt16 $bytes 0x54 0xf0
    $optional = 0x58
    $magic = if ($Architecture -in @("x86", "anycpu")) { 0x10b } else { 0x20b }
    Set-UInt16 $bytes $optional $magic
    $dataDirectory = if ($magic -eq 0x10b) { $optional + 96 } else { $optional + 112 }

    $section = $optional + 0xf0
    Set-UInt32 $bytes ($section + 8) 0x200
    Set-UInt32 $bytes ($section + 12) 0x1000
    Set-UInt32 $bytes ($section + 16) 0x200
    Set-UInt32 $bytes ($section + 20) 0x200

    if ($Personality -eq "msys") {
        Set-UInt32 $bytes ($dataDirectory + 8) 0x1000
        Set-UInt32 $bytes ($dataDirectory + 12) 40
        Set-UInt32 $bytes (0x200 + 12) 0x1040
        $name = [Text.Encoding]::ASCII.GetBytes("msys-2.0.dll`0")
        $name.CopyTo($bytes, 0x240)
    }

    if ($Architecture -eq "anycpu") {
        Set-UInt32 $bytes ($dataDirectory + 112) 0x1080
        Set-UInt32 $bytes ($dataDirectory + 116) 72
        Set-UInt32 $bytes (0x280 + 16) 1
    }

    $directory = Split-Path -Parent $Path
    [void](New-Item -ItemType Directory -Force -Path $directory)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function New-PayloadRoot {
    param([string]$Path, [switch]$X64Bash, [switch]$UnexpectedX64)

    [void](New-Item -ItemType Directory -Force -Path $Path)
    New-TestPe (Join-Path $Path "bin\git.exe") arm64 mingw
    New-TestPe (Join-Path $Path "bin\ssh.exe") arm64 mingw
    New-TestPe (Join-Path $Path "bin\gpg.exe") arm64 mingw
    New-TestPe (Join-Path $Path "bin\submodule.exe") arm64 mingw
    New-TestPe (Join-Path $Path "bin\helper.dll") arm64 mingw
    New-TestPe (Join-Path $Path "usr\bin\bash.exe") `
        $(if ($X64Bash) { "x64" } else { "arm64" }) msys
    New-TestPe (Join-Path $Path "usr\bin\hook.exe") arm64 msys
    New-TestPe (Join-Path $Path "usr\bin\rebase.exe") arm64 msys
    New-TestPe (Join-Path $Path "usr\bin\git-svn.exe") arm64 msys
    New-TestPe (Join-Path $Path "bin\managed.dll") anycpu mingw
    if ($UnexpectedX64) {
        New-TestPe (Join-Path $Path "bin\unexpected-x64.exe") x64 mingw
    }
    [IO.File]::WriteAllText((Join-Path $Path "readme.txt"), "fixture`n")
}

function Add-MalformedPe {
    param([string]$Path)

    $bytes = New-Object byte[] 90
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    Set-UInt32 $bytes 0x3c 0x40
    $bytes[0x40] = 0x50
    $bytes[0x41] = 0x45
    Set-UInt16 $bytes 0x44 0xaa64
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-TestArchitecture {
    param([string]$Path, [string]$RelativePath)

    $line = & $peImports -ArchitectureOnly -Root $Path -Path $RelativePath
    if (-not $line) {
        return $null
    }
    $fields = ([string]$line).Split("`t")
    $kind = $fields[1]
    $personality = if ($kind -eq "anycpu") {
        "managed"
    } elseif ($RelativePath -like "usr/*") {
        "msys"
    } else {
        "mingw"
    }
    return [ordered]@{
        kind = $kind
        machine = $fields[2]
        personality = $personality
    }
}

function New-Contracts {
    param(
        [string]$CasePath,
        [ValidateSet("preview", "final")]
        [string]$Mode,
        [string[]]$UnresolvedScenarios = @(),
        [switch]$UnresolvedInputs
    )

    $payloadRoot = Join-Path $CasePath "root"
    $contractRoot = Join-Path $CasePath "contract"
    [void](New-Item -ItemType Directory -Force -Path $contractRoot)

    $baseInput = [ordered]@{
        id = "base"
        role = "base-bundle"
        status = "resolved"
        resolution = "test-fixture"
        release = [ordered]@{
            repository = "crutkas/test-fixtures"
            tag = "v1"
            targetCommit = "1111111111111111111111111111111111111111"
        }
        asset = [ordered]@{
            url = "https://github.com/crutkas/test-fixtures/releases/download/v1/base.zip"
            name = "base.zip"
            bytes = 1
            sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
        }
        package = [ordered]@{
            name = "test-base"
            version = "1"
            personality = "mixed"
            provides = @()
        }
        overlay = [ordered]@{
            enabled = $true
            destination = ""
            include = @("*")
            exclude = @()
        }
    }
    $inputs = @($baseInput)
    if ($UnresolvedInputs) {
        foreach ($id in @("ncurses-runtime", "ncurses-devel", "readline", "bash")) {
            $inputs += [ordered]@{
                id = $id
                role = "runtime"
                status = "unresolved"
                resolution = $null
                release = $null
                asset = $null
                package = $null
                overlay = $null
            }
        }
    }
    $lockObject = [ordered]@{
        schemaVersion = 1
        inputs = $inputs
    }
    $lockPath = Join-Path $contractRoot "lock.json"
    Write-Json $lockPath $lockObject
    $lockHash = (Get-FileHash $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $members = @()
    $payloadEntries = @()
    foreach ($item in Get-ChildItem -LiteralPath $payloadRoot -Force -Recurse |
        Sort-Object { $_.FullName.Substring($payloadRoot.Length).Replace("\", "/") }) {
        $relative = $item.FullName.Substring($payloadRoot.Length).TrimStart("\").Replace("\", "/")
        $type = if ($item.PSIsContainer) { "directory" } else { "file" }
        $member = [ordered]@{
            sourceMember = $relative
            destinationPath = $relative
            type = $type
            replacesSourceInput = $null
        }
        $entry = [ordered]@{
            path = $relative
            type = $type
            sourceInput = "base"
            sourcePackage = "test-base"
            sourceMember = $relative
        }
        if ($type -eq "file") {
            $hash = (Get-FileHash $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $member.bytes = $item.Length
            $member.sha256 = $hash
            $entry.bytes = $item.Length
            $entry.sha256 = $hash
            $entry.architecture = Get-TestArchitecture $payloadRoot $relative
        } else {
            $entry.bytes = 0
            $entry.sha256 = $null
            $entry.architecture = $null
        }
        $members += $member
        $payloadEntries += $entry
    }

    $provenanceObject = [ordered]@{
        schemaVersion = 1
        lockSha256 = $lockHash
        assemblerCommit = "3333333333333333333333333333333333333333"
        host = [ordered]@{
            os = "windows"
            architecture = "arm64"
        }
        createdAt = "2026-08-27T15:00:00Z"
        inputs = @([ordered]@{
            id = "base"
            status = "verified"
            release = $baseInput.release
            asset = $baseInput.asset
            package = [ordered]@{
                name = "test-base"
                version = "1"
                personality = "mixed"
            }
        })
        overlayOrder = @([ordered]@{
            index = 0
            inputId = "base"
            members = $members
        })
        scanner = [ordered]@{
            script = [ordered]@{
                path = "validate-arm64-bundle.ps1"
                sha256 = (Get-FileHash $validator -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            candidates = @([ordered]@{
                tool = "pe-imports"
                path = "pe-imports.ps1"
                sha256 = (Get-FileHash $peImports -Algorithm SHA256).Hash.ToLowerInvariant()
            })
        }
        externalObservations = @([ordered]@{
            id = "shared-msys64-observation"
            authoritative = $false
            cutoff = "2026-08-27T15:55:35Z"
            before = [ordered]@{
                log = [ordered]@{
                    bytes = 155150
                    sha256 = "925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8"
                }
                database = [ordered]@{
                    files = 1178
                    manifestSha256 = "93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34"
                }
            }
            after = [ordered]@{
                log = [ordered]@{
                    bytes = 155150
                    sha256 = "925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8"
                }
                database = [ordered]@{
                    files = 1178
                    manifestSha256 = "93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34"
                }
            }
            commands = @("Get-ChildItem -Recurse")
        })
    }
    $provenancePath = Join-Path $contractRoot "provenance.json"
    Write-Json $provenancePath $provenanceObject
    $provenanceHash = (Get-FileHash $provenancePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $payloadObject = [ordered]@{
        schemaVersion = 1
        lockSha256 = $lockHash
        provenanceSha256 = $provenanceHash
        entries = $payloadEntries
    }
    $payloadPath = Join-Path $contractRoot "payload.json"
    Write-Json $payloadPath $payloadObject
    $payloadHash = (Get-FileHash $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $entryByPath = @{}
    foreach ($entry in $payloadEntries) {
        $entryByPath[$entry.path] = $entry
    }
    function New-Module {
        $entry = $entryByPath["bin/helper.dll"]
        return [ordered]@{
            path = "C:\bundle\bin\helper.dll"
            payloadPath = "bin/helper.dll"
            origin = "payload"
            sha256 = $entry.sha256
            architecture = $entry.architecture
        }
    }
    function New-Process {
        param([string]$Role, [string]$PayloadPath)
        $entry = $entryByPath[$PayloadPath]
        $script:nextProcessId++
        return [ordered]@{
            role = $Role
            processId = $script:nextProcessId
            parentProcessId = 0
            startedAt = "2026-08-27T15:00:00Z"
            endedAt = "2026-08-27T15:00:01Z"
            path = "C:\bundle\$($PayloadPath.Replace('/', '\'))"
            payloadPath = $PayloadPath
            sha256 = $entry.sha256
            architecture = $entry.architecture
            modulesComplete = $true
            modules = @(New-Module)
        }
    }

    $scenarioSpecs = [ordered]@{
        "git-bash" = @([pscustomobject]@{ role = "shell"; path = "usr/bin/bash.exe" })
        "git" = @([pscustomobject]@{ role = "git"; path = "bin/git.exe" })
        "ssh" = @([pscustomobject]@{ role = "ssh"; path = "bin/ssh.exe" })
        "gpg" = @([pscustomobject]@{ role = "gpg"; path = "bin/gpg.exe" })
        "hook" = @(
            [pscustomobject]@{ role = "git"; path = "bin/git.exe" },
            [pscustomobject]@{ role = "hook"; path = "usr/bin/hook.exe" }
        )
        "submodule" = @(
            [pscustomobject]@{ role = "git"; path = "bin/git.exe" },
            [pscustomobject]@{ role = "submodule"; path = "bin/submodule.exe" }
        )
        "rebase" = @(
            [pscustomobject]@{ role = "git"; path = "bin/git.exe" },
            [pscustomobject]@{ role = "rebase"; path = "usr/bin/rebase.exe" }
        )
        "git-svn" = @(
            [pscustomobject]@{ role = "git"; path = "bin/git.exe" },
            [pscustomobject]@{ role = "git-svn"; path = "usr/bin/git-svn.exe" }
        )
    }
    $scenarios = @()
    $script:nextProcessId = 100
    foreach ($id in $scenarioSpecs.Keys) {
        if ($UnresolvedScenarios -contains $id) {
            $scenarios += [ordered]@{
                id = $id
                status = "unresolved"
                reason = "fixture unresolved"
                processes = @()
            }
            continue
        }
        $processes = @()
        foreach ($spec in $scenarioSpecs[$id]) {
            $processes += New-Process $spec.role $spec.path
        }
        $scenarios += [ordered]@{
            id = $id
            status = "passed"
            command = @($id, "--fixture")
            exitCode = 0
            traceComplete = $true
            processes = $processes
        }
    }

    $evidenceObject = [ordered]@{
        schemaVersion = 1
        mode = $Mode
        lockSha256 = $lockHash
        provenanceSha256 = $provenanceHash
        payloadSha256 = $payloadHash
        host = [ordered]@{
            os = "windows"
            architecture = "arm64"
            nativeArchitecture = "arm64"
        }
        createdAt = "2026-08-27T15:01:00Z"
        collector = [ordered]@{
            repository = "crutkas/msys2-woarm64-build"
            commit = "4444444444444444444444444444444444444444"
            path = "collect-runtime-evidence.ps1"
            sha256 = "5555555555555555555555555555555555555555555555555555555555555555"
            method = "etw-kernel-process-image-load"
        }
        scenarios = $scenarios
    }
    $evidencePath = Join-Path $contractRoot "evidence.json"
    Write-Json $evidencePath $evidenceObject

    return [pscustomobject]@{
        root = $payloadRoot
        lock = $lockPath
        provenance = $provenancePath
        payload = $payloadPath
        evidence = $evidencePath
        report = Join-Path $contractRoot "report.json"
    }
}

function Invoke-Validator {
    param([object]$Contracts, [string]$Mode)

    $output = Join-Path (Split-Path -Parent $Contracts.report) "validator-output.txt"
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator `
        -Mode $Mode `
        -Root $Contracts.root `
        -Lock $Contracts.lock `
        -Provenance $Contracts.provenance `
        -PayloadManifest $Contracts.payload `
        -RuntimeEvidence $Contracts.evidence `
        -Report $Contracts.report *> $output
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldErrorAction
    return $exitCode
}

function Assert-Exit {
    param([int]$Actual, [int]$Expected, [string]$Label)
    if ($Actual -ne $Expected) {
        throw "$Label exited $Actual, expected $Expected"
    }
}

try {
    Remove-Item -LiteralPath $trash -Recurse -Force -ErrorAction SilentlyContinue
    [void](New-Item -ItemType Directory -Force -Path $trash)

    $case = Join-Path $trash "final-success"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    Assert-Exit (Invoke-Validator $contracts Final) 0 "final success"
    $report = Get-Content $contracts.report -Raw | ConvertFrom-Json
    if ($report.status -ne "passed" -or -not $report.readyForFinal -or
        $report.payload.architectures.arm64 -ne 9 -or
        $report.payload.architectures.anycpu -ne 1) {
        throw "Final success report is incorrect"
    }

    $case = Join-Path $trash "preview-unresolved"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case preview `
        -UnresolvedScenarios @("git-bash", "rebase", "git-svn") -UnresolvedInputs
    Assert-Exit (Invoke-Validator $contracts Preview) 0 "preview unresolved"
    $report = Get-Content $contracts.report -Raw | ConvertFrom-Json
    if ($report.readyForFinal -or $report.unresolved.inputs.Count -ne 4 -or
        $report.unresolved.scenarios.Count -ne 3) {
        throw "Preview unresolved state is not reported truthfully"
    }

    $case = Join-Path $trash "known-x64-preview"
    New-PayloadRoot (Join-Path $case "root") -X64Bash
    $contracts = New-Contracts $case preview -UnresolvedScenarios @("git-bash")
    Assert-Exit (Invoke-Validator $contracts Preview) 0 "known x64 preview"
    $report = Get-Content $contracts.report -Raw | ConvertFrom-Json
    if ($report.payload.architectures.x64 -ne 1 -or
        $report.payload.x64Paths -notcontains "usr/bin/bash.exe") {
        throw "Preview did not report the known x64 payload"
    }

    $case = Join-Path $trash "unexpected-x64"
    New-PayloadRoot (Join-Path $case "root") -UnexpectedX64
    $contracts = New-Contracts $case preview
    Assert-Exit (Invoke-Validator $contracts Preview) 3 "unexpected x64"

    $case = Join-Path $trash "foreign-module"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    $evidence = Get-Content $contracts.evidence -Raw | ConvertFrom-Json
    $evidence.scenarios[1].processes[0].modules[0].architecture.kind = "x64"
    $evidence.scenarios[1].processes[0].modules[0].architecture.machine = "0x8664"
    Write-Json $contracts.evidence $evidence
    Assert-Exit (Invoke-Validator $contracts Final) 4 "foreign runtime module"

    $case = Join-Path $trash "wrong-personality"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    $evidence = Get-Content $contracts.evidence -Raw | ConvertFrom-Json
    $evidence.scenarios[0].processes[0].architecture.personality = "cygwin"
    Write-Json $contracts.evidence $evidence
    Assert-Exit (Invoke-Validator $contracts Final) 4 "wrong runtime personality"

    $case = Join-Path $trash "unmanifested"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    [IO.File]::WriteAllText((Join-Path $contracts.root "unmanifested.txt"), "bad")
    Assert-Exit (Invoke-Validator $contracts Final) 2 "unmanifested archive member"

    $case = Join-Path $trash "malformed-pe"
    New-PayloadRoot (Join-Path $case "root")
    Add-MalformedPe (Join-Path $case "root\bin\malformed")
    $contracts = New-Contracts $case final
    Assert-Exit (Invoke-Validator $contracts Final) 1 "malformed PE scanner failure"

    $case = Join-Path $trash "ownership"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    $payload = Get-Content $contracts.payload -Raw | ConvertFrom-Json
    $payload.entries[0].sourcePackage = "wrong-owner"
    Write-Json $contracts.payload $payload
    Assert-Exit (Invoke-Validator $contracts Final) 2 "wrong package ownership"

    $case = Join-Path $trash "external-mutation"
    New-PayloadRoot (Join-Path $case "root")
    $contracts = New-Contracts $case final
    $provenance = Get-Content $contracts.provenance -Raw | ConvertFrom-Json
    $provenance.externalObservations[0].after.database.files = 1179
    $provenance.externalObservations[0].commands = @("pacman -Sw package")
    Write-Json $contracts.provenance $provenance
    Assert-Exit (Invoke-Validator $contracts Final) 2 "external mutation evidence"

    Write-Host "validate-arm64-bundle tests passed"
} finally {
    if (-not $env:KEEP_ARM64_VALIDATOR_TRASH) {
        Remove-Item -LiteralPath $trash -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Kept test data at $trash"
    }
}
