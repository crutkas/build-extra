param(
    [string]$RuntimeCache
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$module = Join-Path $root "arm64-native-shell\NativeShell.psm1"
$script = Join-Path $root "arm64-native-shell\install.ps1"
$filterScript = Join-Path $root "arm64-native-shell\filter-file-list.ps1"
$lockPath = Join-Path $root "arm64-native-shell\locks\native-shell-closure-v1.json"
$ownershipPath = Join-Path $root "arm64-native-shell\legacy-package-ownership.tsv"
$trash = Join-Path ([IO.Path]::GetTempPath()) "check-arm64-native-shell-$PID"
Import-Module $module -Force

function Assert-Equal {
    param(
        [object]$Expected,
        [object]$Actual,
        [string]$Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Assert-Throws {
    param(
        [scriptblock]$Action,
        [string]$Pattern
    )

    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Expected '$Pattern', got '$($_.Exception.Message)'"
        }
        return
    }
    throw "Expected failure matching '$Pattern'"
}

function Copy-Object([object]$Value) {
    return $Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
}

try {
    $null = New-Item -ItemType Directory -Path $trash
    $lock = Read-NativeShellLock $lockPath
    if ([IO.File]::ReadAllText(
        (Join-Path $root "arm64-native-shell\install.sh")) -notmatch
        '-Mode "\$mode"') {
        throw "Materialization does not pass the selected admission mode"
    }
    $installerRelease = [IO.File]::ReadAllText(
        (Join-Path $root "installer\release.sh"))
    Assert-Equal 1 ([regex]::Matches(
        $installerRelease, '#define SOURCE_DIR').Count) `
        "Installer can emit more than one SOURCE_DIR define"
    if ($installerRelease -notmatch
        'source_dir=".*NATIVE_SHELL_STAGE' -and
        $installerRelease -notmatch
        'source_dir=.*NATIVE_SHELL_STAGE') {
        throw "Installer does not select the staged source root"
    }
    $a527Expected = @{
        "a527-headers" = @(528366622, 9319013,
            "263f8f7e3614ac41337ce3a223f2bb26b6459aef6f34670525cdd4c03ec3ae21")
        "a527-windows-default-manifest" = @(528366618, 4743,
            "33861708e7f981b4eef5b93ef135ab3a43d2757533f64df6f61a146d823c355f")
        "a527-sysroot" = @(528366621, 86822,
            "e30609e09eab2fa07aba2e6196b05f34e5e9107abc4ab8832966684758c743ca")
        "a527-runtime" = @(528366620, 9893043,
            "158c505f45025a466950faa7c85c9fd85e9d32384dd27b53586ffc75d71ca78e")
        "a527-runtime-devel" = @(528366619, 4426157,
            "c18b51e483991770b8e06cc2d8f7002d06784d3071ac213a8fee24bb831267d1")
    }
    foreach ($entry in $a527Expected.GetEnumerator()) {
        $runtimeInput = $lock.inputs | Where-Object id -eq $entry.Key
        Assert-Equal $entry.Value[0] $runtimeInput.asset.id `
            "A527 asset ID changed for $($entry.Key)"
        Assert-Equal $entry.Value[1] $runtimeInput.asset.expectedBytes `
            "A527 asset size changed for $($entry.Key)"
        Assert-Equal $entry.Value[2] $runtimeInput.asset.sha256 `
            "A527 asset hash changed for $($entry.Key)"
        Assert-Equal "msysarm64-runtime-pr10-a527-20260824" `
            $runtimeInput.identity.tag "A527 release tag changed for $($entry.Key)"
        Assert-Equal "3f92608bfeea71102da9ee093c4db1d67f513a5c" `
            $runtimeInput.identity.commit "A527 producer commit changed for $($entry.Key)"
    }
    $binutilsInput = $lock.inputs | Where-Object id -eq "fixed-binutils"
    Assert-Equal "3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b" `
        $binutilsInput.asset.sha256 "Fixed binutils package hash changed"
    Assert-Equal "075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f" `
        $binutilsInput.linker.sha256 "Fixed linker hash changed"
    Assert-Equal "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9" `
        $lock.pseudoRelocGate.script.sha256 "Pseudo-reloc scanner hash changed"
    $unresolved = @(Test-NativeShellLock $lock Preview)
    Assert-Equal 4 $unresolved.Count "Unexpected unresolved input count"
    Assert-Equal "unresolved" $lock.authoritativeGate.status `
        "Authoritative gate must remain fail-closed until its committed handoff"
    Assert-NativeShellSetEqual @(
        "bash", "ncurses-devel", "ncurses-runtime", "readline"
    ) @($unresolved.id) "Unresolved native shell inputs"
    foreach ($lockInput in @($lock.inputs | Where-Object status -eq "unresolved")) {
        foreach ($field in @("identity", "asset", "package", "overlay")) {
            if ($null -ne $lockInput.$field) {
                throw "Unresolved input '$($lockInput.id)' partially pins $field"
            }
        }
        if ($null -eq $lockInput.admission) {
            throw "Unresolved input '$($lockInput.id)' lost its admission contract"
        }
    }
    $ncursesAdmission = ($lock.inputs | Where-Object id -eq "ncurses-runtime").admission
    Assert-Equal "6.6.20260822-1" $ncursesAdmission.pkgver `
        "Ncurses admission version changed"
    Assert-Equal 13 $ncursesAdmission.requiredPayloadShape.peCount `
        "Ncurses required PE count changed"
    Assert-Equal 3 $ncursesAdmission.requiredPayloadShape.symlinkCount `
        "Ncurses required symlink count changed"
    Assert-NativeShellSetEqual @("usr/bin/msys-ncurses++w6.dll") @(
        $ncursesAdmission.requiredPayloadShape.forbiddenDestinations
    ) "Ncurses forbidden omitted destination"
    Assert-Equal 1 @($ncursesAdmission.omittedLegacyMembers).Count `
        "Ncurses guarded deletion count changed"
    $omittedNcurses = $ncursesAdmission.omittedLegacyMembers[0]
    Assert-Equal "usr/bin/msys-ncurses++w6.dll" $omittedNcurses.path `
        "Ncurses omitted legacy member changed"
    Assert-Equal "remove-after-zero-reverse-imports" `
        $omittedNcurses.finalDisposition "Ncurses guarded deletion policy changed"
    Assert-Equal "post-overlay-all-files" $omittedNcurses.proofScope `
        "Ncurses reverse-import proof scope changed"
    $bashAdmission = ($lock.inputs | Where-Object id -eq "bash").admission
    Assert-Equal "5.2.037" $bashAdmission.pkgver "Bash admission version changed"
    Assert-Equal 3 $bashAdmission.pkgrel "Bash admission pkgrel changed"
    Assert-Equal "aarch64" $bashAdmission.requiredResolvedArchitecture `
        "Bash resolved package architecture changed"
    Assert-Equal "copy-of-bash.exe-not-link" $bashAdmission.shellAlias.semantics `
        "Bash sh.exe alias semantics changed"
    Assert-Throws { $null = Test-NativeShellLock $lock Final } `
        "Native shell closure unresolved"

    $partial = Copy-Object $lock
    ($partial.inputs | Where-Object id -eq "bash").identity = @{ repository = "invalid" }
    Assert-Throws { $null = Test-NativeShellLock $partial Preview } `
        "must keep identity null"

    $unboundGate = Copy-Object $lock
    $unboundGate.authoritativeGate.status = "resolved"
    Assert-Throws { $null = Test-NativeShellLock $unboundGate Preview } `
        "Resolved authoritative gate is missing identity"

    $emptyClosure = Copy-Object $lock
    $emptyClosure.nativeShellClosure = @()
    Assert-Throws { $null = Test-NativeShellLock $emptyClosure Preview } `
        "must not be empty"

    $variantMapping = Copy-Object $lock
    ($variantMapping.inputs | Where-Object id -eq "gcc-libs").overlay.mappings[0] |
        Add-Member -NotePropertyName variants -NotePropertyValue @("portable")
    Assert-Throws { $null = Test-NativeShellLock $variantMapping Preview } `
        "Variant-scoped"

    $collision = Copy-Object $lock
    ($collision.inputs | Where-Object id -eq "gcc-libs").overlay.mappings[0].destination =
        "usr/bin/msys-2.0.dll"
    Assert-Throws { $null = Test-NativeShellLock $collision Preview } `
        "Duplicate payload ownership"

    $crossHost = Copy-Object $lock
    ($crossHost.inputs | Where-Object id -eq "gcc-libs").overlay.mappings[0].source =
        "opt/bin/aarch64-pc-cygwin-objdump.exe"
    Assert-Throws { $null = Test-NativeShellLock $crossHost Preview } `
        "forbidden cross-host source"

    $wrongDestination = Copy-Object $lock
    ($wrongDestination.inputs | Where-Object id -eq "gcc-libs").overlay.mappings[0].destination =
        "clangarm64/bin/legacy-bypass.dll"
    Assert-Throws { $null = Test-NativeShellLock $wrongDestination Preview } `
        "outside the native shell payload roots"

    $disabledOverlay = Copy-Object $lock
    ($disabledOverlay.inputs | Where-Object id -eq "gcc-libs").overlay.enabled = $false
    Assert-Throws { $null = Test-NativeShellLock $disabledOverlay Preview } `
        "enabled state"

    foreach ($path in @(
        "../escape", "usr/../escape", "/absolute", "C:/absolute",
        "\\server\share", "usr\bin\bash.exe", "usr//bin/bash.exe",
        "CON", "usr/bin/NUL.txt", "usr/bin/file`:stream",
        "usr/bin/trailing.", "usr/bin/trailing ", "usr/bin/file*"
    )) {
        Assert-Throws { $null = Assert-NativeShellRelativePath $path "test path" } "Unsafe"
    }
    Assert-Throws {
        Assert-NativeShellLinkTarget "usr/bin/bash" "../../../outside"
    } "escapes"
    Assert-NativeShellLinkTarget "usr/bin/bash" "../lib/bash"

    $source = Join-Path $trash "package"
    $null = New-Item -ItemType Directory -Path (
        Join-Path $source "opt\aarch64-pc-msys\bin") -Force
    @(
        "pkgname = fixture-native",
        "pkgbase = fixture-native",
        "pkgver = 1-1",
        "arch = x86_64"
    ) | Set-Content -Encoding ascii -LiteralPath (Join-Path $source ".PKGINFO")
    [IO.File]::WriteAllBytes(
        (Join-Path $source "opt\aarch64-pc-msys\bin\fixture.dat"),
        [byte[]](1, 2, 3, 4)
    )
    $null = New-Item -ItemType HardLink `
        -Path (Join-Path $source "opt\aarch64-pc-msys\bin\hard-fixture.dat") `
        -Target (Join-Path $source "opt\aarch64-pc-msys\bin\fixture.dat")
    $null = New-Item -ItemType SymbolicLink `
        -Path (Join-Path $source "opt\aarch64-pc-msys\bin\sym fixture.dat") `
        -Target "fixture.dat"
    $archive = Join-Path $trash "fixture.pkg.tar"
    & tar.exe -cf $archive -C $source `
        .PKGINFO `
        opt/aarch64-pc-msys/bin/fixture.dat `
        opt/aarch64-pc-msys/bin/hard-fixture.dat `
        "opt/aarch64-pc-msys/bin/sym fixture.dat"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create fixture package"
    }
    $fixture = [pscustomobject]@{
        id = "fixture"
        asset = [pscustomobject]@{
            expectedBytes = (Get-Item $archive).Length
            sha256 = Get-NativeShellSha256 $archive
            format = "pkg.tar"
        }
        package = [pscustomobject]@{
            name = "fixture-native"
            base = "fixture-native"
            version = "1-1"
            architecture = "x86_64"
            payloadMembers = 3
            provides = @()
            depends = @()
        }
        sealedMembers = @(
            [pscustomobject]@{
                path = "opt/aarch64-pc-msys/bin/fixture.dat"
                bytes = 4
                sha256 = Get-NativeShellSha256 (
                    Join-Path $source "opt\aarch64-pc-msys\bin\fixture.dat")
            }
        )
        overlay = [pscustomobject]@{
            enabled = $true
            mappings = @(
                [pscustomobject]@{
                    source = "opt/aarch64-pc-msys/bin/fixture.dat"
                    destination = "usr/share/fixture.dat"
                    allowOverwrite = $false
                    content = "data"
                },
                [pscustomobject]@{
                    source = "opt/aarch64-pc-msys/bin/hard-fixture.dat"
                    destination = "usr/share/hard-fixture.dat"
                    allowOverwrite = $false
                    content = "hardlink"
                    sourceLinkTarget = "opt/aarch64-pc-msys/bin/fixture.dat"
                    linkTarget = "usr/share/fixture.dat"
                },
                [pscustomobject]@{
                    source = "opt/aarch64-pc-msys/bin/sym fixture.dat"
                    destination = "usr/share/sym fixture.dat"
                    allowOverwrite = $false
                    content = "symlink"
                    sourceLinkTarget = "fixture.dat"
                    linkTarget = "fixture.dat"
                }
            )
        }
    }
    $extract = Join-Path $trash "extract"
    $verified = Test-NativeShellResolvedInput $fixture $archive $extract
    Assert-Equal 3 $verified.payloadMembers.Count "Unexpected fixture payload count"
    Assert-Equal 4 @($verified.archiveMembers).Count `
        "Archive provenance does not cover every member"
    $hardMember = @($verified.archiveMembers |
        Where-Object sourceMember -eq "opt/aarch64-pc-msys/bin/hard-fixture.dat")[0]
    Assert-Equal "hardlink" $hardMember.type "Hardlink archive type changed"
    Assert-Equal "opt/aarch64-pc-msys/bin/fixture.dat" $hardMember.linkTarget `
        "Hardlink archive target changed"
    $symMember = @($verified.archiveMembers |
        Where-Object sourceMember -eq "opt/aarch64-pc-msys/bin/sym fixture.dat")[0]
    Assert-Equal "symlink" $symMember.type "Symlink archive type changed"
    Assert-Equal "opt/aarch64-pc-msys/bin/fixture.dat" $symMember.linkTarget `
        "Symlink archive target changed"
    Assert-Equal $hardMember.sha256 $symMember.sha256 `
        "Archive links do not preserve target hash semantics"
    $badSeal = Copy-Object $fixture
    $badSeal.sealedMembers[0].sha256 = "0" * 64
    Assert-Throws {
        $null = Test-NativeShellResolvedInput $badSeal $archive (
            Join-Path $trash "bad-seal-extract")
    } "Sealed member identity mismatch"

    $badSize = Copy-Object $fixture
    $badSize.asset.expectedBytes++
    Assert-Throws {
        $null = Test-NativeShellResolvedInput $badSize $archive
    } "size mismatch"
    $badHash = Copy-Object $fixture
    $badHash.asset.sha256 = "0" * 64
    Assert-Throws {
        $null = Test-NativeShellResolvedInput $badHash $archive
    } "SHA-256 mismatch"
    $badMetadata = Copy-Object $fixture
    $badMetadata.package.name = "wrong-name"
    Assert-Throws {
        $null = Test-NativeShellResolvedInput $badMetadata $archive
    } "pkgname"
    $badMembers = Copy-Object $fixture
    $badMembers.package.payloadMembers = 2
    Assert-Throws {
        $null = Test-NativeShellResolvedInput $badMembers $archive
    } "member count mismatch"

    & {
        . $script -FunctionsOnly
        $transactionPayload = Join-Path $trash "transaction-payload"
        $transactionExtract = Join-Path $trash "transaction-extract"
        $transactionRoot = Join-Path $trash "transaction-work"
        $null = New-Item -ItemType Directory -Force -Path $transactionPayload
        $null = New-Item -ItemType Directory -Force -Path $transactionExtract
        $null = New-Item -ItemType Directory -Force -Path $transactionRoot
        Assert-Throws {
            Assert-PathOutsideRoot (Join-Path $transactionPayload "metadata.json") `
                $transactionPayload "Test metadata"
        } "cannot be inside the payload root"
        Assert-Throws {
            $null = Assert-PrivatePath ([IO.Path]::GetPathRoot($transactionPayload)) `
                "Test path"
        } "cannot use a filesystem root"
        $privateTarget = Join-Path $trash "private-target"
        $privateLink = Join-Path $trash "private-link"
        $null = New-Item -ItemType Directory -Path $privateTarget
        $null = New-Item -ItemType SymbolicLink -Path $privateLink -Target $privateTarget
        Assert-Throws {
            $null = Assert-PrivatePath (Join-Path $privateLink "child") "Test path"
        } "cannot traverse a link or junction"
        [IO.File]::WriteAllText(
            (Join-Path $transactionPayload "remove.dat"), "remove-original")
        [IO.File]::WriteAllText(
            (Join-Path $transactionPayload "replace.dat"), "replace-original")
        [IO.File]::WriteAllText(
            (Join-Path $transactionExtract "replace-source.dat"), "replace-new")
        [IO.File]::WriteAllText(
            (Join-Path $transactionExtract "create-source.dat"), "create-new")
        $metadataExisting = Join-Path $trash "existing-metadata.json"
        $metadataNew = Join-Path $trash "new-metadata.json"
        [IO.File]::WriteAllText($metadataExisting, "metadata-original")
        $transactionPlan = @(
            [pscustomobject]@{
                input = "fixture"
                source = "replace-source.dat"
                destination = "replace.dat"
                content = "data"
            },
            [pscustomobject]@{
                input = "fixture"
                source = "create-source.dat"
                destination = "create.dat"
                content = "data"
            }
        )
        $transactionLegacy = @(
            [pscustomobject]@{
                path = "remove.dat"
                finalDisposition = "remove"
            }
        )
        Assert-Throws {
            Invoke-OverlayTransaction @{} $transactionPayload $transactionPlan `
                $transactionLegacy @() @{ fixture = $transactionExtract } `
                $transactionRoot @($metadataExisting, $metadataNew) {
                    [IO.File]::WriteAllText($metadataExisting, "metadata-new")
                    [IO.File]::WriteAllText($metadataNew, "metadata-created")
                    throw "forced rollback"
                }
        } "forced rollback"
        Assert-Equal "remove-original" (
            [IO.File]::ReadAllText((Join-Path $transactionPayload "remove.dat"))) `
            "Rollback did not restore a removed payload file"
        Assert-Equal "replace-original" (
            [IO.File]::ReadAllText((Join-Path $transactionPayload "replace.dat"))) `
            "Rollback did not restore an overwritten payload file"
        if (Test-Path -LiteralPath (Join-Path $transactionPayload "create.dat")) {
            throw "Rollback did not remove a newly created payload file"
        }
        Assert-Equal "metadata-original" ([IO.File]::ReadAllText($metadataExisting)) `
            "Rollback did not restore existing metadata"
        if (Test-Path -LiteralPath $metadataNew) {
            throw "Rollback did not remove newly created metadata"
        }
    }

    $reverseRoot = Join-Path $trash "reverse-imports"
    $null = New-Item -ItemType Directory -Path $reverseRoot
    $consumer = Join-Path $reverseRoot "consumer.exe"
    Copy-Item -LiteralPath (Get-Process -Id $PID).Path -Destination $consumer
    $consumerClassification = Get-NativeShellPeClassification $consumer "consumer.exe"
    $importName = @($consumerClassification.imports | Sort-Object -CaseSensitive)[0]
    if (-not $importName) {
        throw "The reverse-import test fixture has no imports"
    }
    [IO.File]::WriteAllText((Join-Path $reverseRoot $importName), "target")
    Assert-Throws {
        Assert-NativeShellNoReverseImports $reverseRoot $importName $importName
    } "is still imported by: consumer.exe"
    Remove-Item -Force -LiteralPath $consumer
    Assert-NativeShellNoReverseImports $reverseRoot $importName $importName

    $wrongLocator = Copy-Object $lock
    ($wrongLocator.inputs | Where-Object id -eq "a527-runtime").asset.url =
        ($wrongLocator.inputs | Where-Object id -eq "a527-runtime").asset.url.Replace(
            "github.com/crutkas/", "github.com/not-the-owner/")
    Assert-Throws { $null = Test-NativeShellLock $wrongLocator Preview } `
        "does not match its repository"

    $payloadRoot = Join-Path $trash "payload"
    $null = New-Item -ItemType Directory -Path $payloadRoot
    Assert-Throws {
        $null = Test-NativeShellOverlayPlan $lock $payloadRoot
    } "Expected replacement is missing"

    $previewReport = Join-Path $trash "preview.json"
    & $script -Mode Preview -Lock $lockPath -Report $previewReport -Quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Preview lock validation failed"
    }
    $report = Get-Content -Raw $previewReport | ConvertFrom-Json
    Assert-Equal "blocked" $report.state "Preview did not report blocked state"
    Assert-Equal 4 @($report.unresolved).Count "Preview unresolved report changed"
    if ($null -ne $report.PSObject.Properties["remainingX64"]) {
        throw "Lock-only Preview falsely reported a remaining x64 count"
    }
    $previewList = @(
        "usr/bin/chattr.exe`nusr/bin/bash.exe`n" |
            pwsh.exe -NoProfile -File $filterScript `
                -Mode Preview -Variant portable -Lock $lockPath `
                -WarningAction SilentlyContinue
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Preview file-list reconciliation rejected unresolved shell packages"
    }
    Assert-NativeShellSetEqual @(
        "usr/bin/bash.exe",
        "usr/bin/msys-2.0.dll",
        "usr/bin/msys-gcc_s-seh-1.dll",
        "usr/share/licenses/msys2-runtime-arm64/COPYING",
        "usr/share/licenses/msys2-runtime-arm64/COPYING.LIB",
        "usr/share/licenses/msys2-runtime-arm64/COPYING.LIBGLOSS",
        "usr/share/licenses/msys2-runtime-arm64/COPYING.NEWLIB",
        "usr/share/licenses/msys2-runtime-arm64/COPYING3",
        "usr/share/licenses/msys2-runtime-arm64/COPYING3.LIB"
    ) $previewList "Preview file-list reconciliation"

    $one = Join-Path $trash "canonical-1.json"
    $two = Join-Path $trash "canonical-2.json"
    $canonical = [ordered]@{
        schemaVersion = 1
        sourceDateEpoch = $lock.sourceDateEpoch
        inputs = @("a527-runtime", "gcc-libs")
    }
    Write-NativeShellCanonicalJson $canonical $one
    Write-NativeShellCanonicalJson $canonical $two
    Assert-Equal (Get-NativeShellSha256 $one) (Get-NativeShellSha256 $two) `
        "Canonical provenance output is not deterministic"

    $sourceLockCopy = Join-Path $trash "source-lock.json"
    [IO.File]::WriteAllBytes(
        $sourceLockCopy, [IO.File]::ReadAllBytes($lockPath))
    Assert-Equal (Get-NativeShellSha256 $lockPath) (
        Get-NativeShellSha256 $sourceLockCopy) "Source lock copy changed exact bytes"
    $baseTreeRoot = Join-Path $trash "base-tree"
    $null = New-Item -ItemType Directory -Path (
        Join-Path $baseTreeRoot "usr\bin") -Force
    [IO.File]::WriteAllText(
        (Join-Path $baseTreeRoot "usr\bin\base.dat"), "base")
    $null = New-Item -ItemType HardLink `
        -Path (Join-Path $baseTreeRoot "usr\bin\hard.dat") `
        -Target (Join-Path $baseTreeRoot "usr\bin\base.dat")
    $null = New-Item -ItemType SymbolicLink `
        -Path (Join-Path $baseTreeRoot "usr\bin\sym.dat") -Target "base.dat"
    $baseManifestOne = Get-NativeShellTreeManifest $baseTreeRoot
    $baseManifestTwo = Get-NativeShellTreeManifest $baseTreeRoot
    $baseManifestOnePath = Join-Path $trash "base-manifest-1.json"
    $baseManifestTwoPath = Join-Path $trash "base-manifest-2.json"
    Write-NativeShellCanonicalJson $baseManifestOne $baseManifestOnePath
    Write-NativeShellCanonicalJson $baseManifestTwo $baseManifestTwoPath
    Assert-Equal (Get-NativeShellSha256 $baseManifestOnePath) (
        Get-NativeShellSha256 $baseManifestTwoPath) `
        "Pre-overlay base manifest is not deterministic"
    Assert-Equal "file" @($baseManifestOne.entries |
        Where-Object path -eq "usr/bin/base.dat")[0].type `
        "Base manifest did not choose an ordinal hardlink target"
    Assert-Equal "usr/bin/base.dat" @($baseManifestOne.entries |
        Where-Object path -eq "usr/bin/hard.dat")[0].linkTarget `
        "Base manifest hardlink target changed"
    Assert-Equal "usr/bin/base.dat" @($baseManifestOne.entries |
        Where-Object path -eq "usr/bin/sym.dat")[0].linkTarget `
        "Base manifest symlink target changed"
    $syntheticInventories = @{}
    foreach ($lockInput in @($lock.inputs | Where-Object status -eq "resolved")) {
        $members = @(
            foreach ($mapping in @($lockInput.overlay.mappings)) {
                [ordered]@{
                    sourceMember = [string]$mapping.source
                    type = "file"
                    bytes = 1
                    sha256 = "1" * 64
                    linkTarget = $null
                }
            }
        )
        $memberPaths = @{}
        foreach ($member in $members) {
            $memberPaths[[string]$member.sourceMember] = $true
        }
        foreach ($mapping in @($lockInput.overlay.mappings)) {
            $parent = [string]$mapping.source
            while ($parent.Contains("/")) {
                $parent = $parent.Substring(0, $parent.LastIndexOf("/"))
                if (-not $memberPaths.ContainsKey($parent)) {
                    $members += [ordered]@{
                        sourceMember = $parent
                        type = "directory"
                        bytes = 0
                        sha256 = $null
                        linkTarget = $null
                    }
                    $memberPaths[$parent] = $true
                }
            }
        }
        $members = @(Sort-NativeShellOrdinal `
            -InputObject $members -Property {
                param($member) $member["sourceMember"]
            })
        if ($lockInput.id -eq "fixed-binutils") {
            $members += @(
                "opt/bin/aarch64-pc-cygwin-ld.exe",
                "opt/bin/aarch64-pc-cygwin-nm.exe",
                "opt/bin/aarch64-pc-cygwin-objdump.exe"
            ) | ForEach-Object {
                [ordered]@{
                    sourceMember = $_
                    type = "file"
                    bytes = 1
                    sha256 = "2" * 64
                    linkTarget = $null
                }
            }
        } elseif ($members.Count -eq 0) {
            $members = @([ordered]@{
                sourceMember = "usr/share/$($lockInput.id).dat"
                type = "file"
                bytes = 1
                sha256 = "3" * 64
                linkTarget = $null
            })
        }
        $syntheticInventories[[string]$lockInput.id] = $members
    }
    $baseEntries = @(
        [ordered]@{
            path = "usr"
            type = "directory"
            bytes = 0
            sha256 = $null
            linkTarget = $null
        },
        [ordered]@{
            path = "usr/base.dat"
            type = "file"
            bytes = 1
            sha256 = "4" * 64
            linkTarget = $null
        },
        [ordered]@{
            path = "usr/share"
            type = "directory"
            bytes = 0
            sha256 = $null
            linkTarget = $null
        },
        [ordered]@{
            path = "usr/share/licenses"
            type = "directory"
            bytes = 0
            sha256 = $null
            linkTarget = $null
        },
        [ordered]@{
            path = "usr/remove.dat"
            type = "file"
            bytes = 1
            sha256 = "5" * 64
            linkTarget = $null
        }
    )
    $baseEntries = @(Sort-NativeShellOrdinal `
        -InputObject $baseEntries -Property { param($entry) $entry["path"] })
    $adapterOne = New-NativeShellAdapterLock $lock (
        Get-NativeShellSha256 $sourceLockCopy) $syntheticInventories `
        ("6" * 64) $baseEntries @("usr/remove.dat")
    $adapterTwo = New-NativeShellAdapterLock $lock (
        Get-NativeShellSha256 $sourceLockCopy) $syntheticInventories `
        ("6" * 64) $baseEntries @("usr/remove.dat")
    $adapterOnePath = Join-Path $trash "adapter-1.json"
    $adapterTwoPath = Join-Path $trash "adapter-2.json"
    Write-NativeShellCanonicalJson $adapterOne $adapterOnePath
    Write-NativeShellCanonicalJson $adapterTwo $adapterTwoPath
    Assert-Equal (Get-NativeShellSha256 $adapterOnePath) (
        Get-NativeShellSha256 $adapterTwoPath) "Adapter derivation is not deterministic"
    Assert-Equal "schemaVersion,sourceLock,sourceDateEpoch,nativeShellClosure,inputs" (
        @($adapterOne.Keys) -join ",") `
        "Adapter property order changed"
    Assert-Equal (Get-NativeShellSha256 $sourceLockCopy) `
        $adapterOne.sourceLock.sha256 "Adapter does not bind exact source lock bytes"
    $stackBase = @($adapterOne.inputs | Where-Object id -eq "stack-base")[0]
    Assert-Equal "base-bundle" $stackBase.role "Stack base adapter role changed"
    Assert-Equal "derived-tree" $stackBase.resolution.method `
        "Stack base resolution method changed"
    Assert-Equal "be0217cb572704f27ea04c9abde8bb992b8ef0c0" `
        $stackBase.resolution.build.commit "Stack base build commit changed"
    Assert-Equal $null $stackBase.resolution.sdkSource `
        "Stack base guessed an SDK source identity"
    Assert-Equal ("6" * 64) $stackBase.resolution.manifest.sha256 `
        "Stack base manifest binding changed"
    Assert-Equal 0 @($stackBase.overlay.mappings |
        Where-Object sourceMember -eq "usr/remove.dat").Count `
        "Removed base member remained selected"
    $sortedIds = @($adapterOne.inputs.id)
    $expectedIds = @($sortedIds | Sort-Object -CaseSensitive)
    Assert-Equal ($expectedIds -join "`0") ($sortedIds -join "`0") `
        "Adapter inputs are not ordinally sorted"
    $adapterRuntime = @($adapterOne.inputs | Where-Object id -eq "a527-runtime")[0]
    Assert-Equal "payload" $adapterRuntime.role "Shipped adapter input role changed"
    Assert-NativeShellSetEqual @($adapterRuntime.overlay.mappings.destinationPath) `
        @($adapterRuntime.package.provides) "Payload package provides"
    Assert-Equal 1 @($adapterRuntime.overlay.mappings |
        Where-Object {
            $_.destinationPath -eq "usr/share/licenses/msys2-runtime-arm64"
        }).Count `
        "New nested payload directory lacks native ownership"
    Assert-Equal 0 @($adapterRuntime.overlay.mappings |
        Where-Object destinationPath -eq "usr/share/licenses").Count `
        "Native overlay replaced an existing base directory"
    $adapterBinutils = @($adapterOne.inputs | Where-Object id -eq "fixed-binutils")[0]
    Assert-Equal "mingw-w64-cross-cygwinarm64-binutils" `
        $adapterBinutils.package.name "Fixed binutils package identity changed"
    Assert-NativeShellSetEqual @(
        "opt/bin/aarch64-pc-cygwin-ld.exe",
        "opt/bin/aarch64-pc-cygwin-nm.exe",
        "opt/bin/aarch64-pc-cygwin-objdump.exe"
    ) @($adapterBinutils.package.provides) "Fixed binutils tool provides"
    foreach ($input in @($adapterOne.inputs | Where-Object status -eq "unresolved")) {
        foreach ($field in @("resolution", "release", "asset", "package", "overlay")) {
            if ($null -ne $input.$field) {
                throw "Adapter unresolved input '$($input.id)' populated $field"
            }
        }
    }

    & {
    . $script -FunctionsOnly
    Assert-Throws {
        Assert-NativeShellAssemblerCommit "not-a-commit"
    } "lowercase 40-character"
    $fakeRoot = Join-Path $trash "validator-root"
    $fakeTool = Join-Path $trash "validator-tools"
    $null = New-Item -ItemType Directory -Path $fakeRoot
    $null = New-Item -ItemType Directory -Path $fakeTool
    $fakeLock = Join-Path $trash "validator-lock.json"
    $fakeProvenance = Join-Path $trash "validator-provenance.json"
    $fakePayload = Join-Path $trash "validator-payload.json"
    $fakeAssembly = Join-Path $trash "validator-assembly.json"
    $fakeRuntime = Join-Path $trash "validator-runtime.json"
    foreach ($path in @(
        $fakeLock, $fakeProvenance, $fakePayload, $fakeAssembly, $fakeRuntime
    )) {
        [IO.File]::WriteAllText($path, "$([IO.Path]::GetFileName($path))`n")
    }
    [IO.File]::WriteAllText(
        $fakeLock,
        (@{
            sourceLock = @{ sha256 = "1" * 64 }
            nativeShellClosure = @("usr/bin/bash.exe")
            inputs = @(@{
                id = "stack-base"
                status = "resolved"
                resolution = @{
                    method = "derived-tree"
                    manifest = @{ sha256 = "3" * 64 }
                }
            })
        } | ConvertTo-Json -Depth 10))
    [IO.File]::WriteAllText(
        $fakeRuntime, "{`"admissionMode`":`"Final`"}`n")
    $fakeValidator = Join-Path $trash "fake-validator.ps1"
    @'
param(
    [string]$Mode, [string]$Root, [string]$Lock, [string]$Provenance,
    [string]$PayloadManifest, [string]$ToolRoot, [string]$Report,
    [string]$AssemblyEvidence, [string]$RuntimeEvidence, [string]$StaticReport
)
if ($env:NATIVE_SHELL_FAKE_REPORT -eq "noop") { exit 0 }
function hash($path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}
if ($Mode -eq "Runtime") {
    $staticHash = hash $StaticReport
    foreach ($evidence in @($AssemblyEvidence, $RuntimeEvidence)) {
        if ((Get-Content -Raw $evidence |
            ConvertFrom-Json).staticReportSha256 -cne $staticHash) {
            throw "Runtime evidence does not bind StaticReport"
        }
    }
}
$reportedMode = if ($env:NATIVE_SHELL_FAKE_REPORT -eq "wrong-mode") {
    "Preview"
} else {
    $Mode
}
$lockHash = if ($env:NATIVE_SHELL_FAKE_REPORT -eq "wrong-digest") {
    "0" * 64
} else {
    hash $Lock
}
$digests = [ordered]@{
    sourceLockSha256 = "1" * 64
    baseTreeManifestSha256 = "3" * 64
    lockSha256 = $lockHash
    provenanceSha256 = hash $Provenance
    payloadManifestSha256 = hash $PayloadManifest
    rootInventorySha256 = "2" * 64
    assemblyEvidenceSha256 = $(if ($Mode -eq "Runtime") {
        hash $AssemblyEvidence
    } else { $null })
    runtimeEvidenceSha256 = $(if ($Mode -eq "Runtime") {
        hash $RuntimeEvidence
    } else { $null })
    staticReportSha256 = $(if ($Mode -eq "Runtime") {
        if ($env:NATIVE_SHELL_FAKE_REPORT -eq "wrong-static-digest") {
            "0" * 64
        } else {
            hash $StaticReport
        }
    } else { $null })
}
$admissionMode = if ($Mode -eq "Runtime") {
    (Get-Content -Raw $RuntimeEvidence | ConvertFrom-Json).admissionMode
} else {
    $Mode
}
$remainingX64 = [Collections.Generic.List[string]]::new()
if ($admissionMode -eq "Preview") {
    $remainingX64.Add("usr/bin/bash.exe")
}
$classifications = @([ordered]@{
    path = "usr/bin/bash.exe"
    architecture = "arm64"
    machine = "0xAA64"
    personality = "msys"
    imports = @("msys-2.0.dll")
    clrFlags = $null
    inputId = "bash"
    sourceMember = "usr/bin/bash.exe"
})
if ($env:NATIVE_SHELL_FAKE_REPORT -eq "empty-classifications") {
    $classifications = @()
} elseif ($env:NATIVE_SHELL_FAKE_REPORT -eq "wrong-classification") {
    $classifications[0].architecture = "x64"
    $classifications[0].machine = "0x8664"
}
$pseudoReloc = @([ordered]@{
    path = "usr/bin/bash.exe"
    result = "pass"
    tableFormat = "none"
    recordCount = 0
    flags = @()
    objdumpMember = "opt/bin/aarch64-pc-cygwin-objdump.exe"
    objdumpSha256 = "4" * 64
    nmMember = "opt/bin/aarch64-pc-cygwin-nm.exe"
    nmSha256 = "5" * 64
})
if ($env:NATIVE_SHELL_FAKE_REPORT -eq "bad-pseudo-reloc") {
    $pseudoReloc[0].tableFormat = "v2"
    $pseudoReloc[0].recordCount = 1
    $pseudoReloc[0].flags = @(21)
}
[ordered]@{
    schemaVersion = 1
    mode = $reportedMode
    admissionMode = $admissionMode
    result = "pass"
    exitCode = 0
    readyForFinal = $admissionMode -eq "Final"
    digests = $digests
    summary = [ordered]@{
        unresolvedInputs = 0
        remainingX64 = $remainingX64.Count
    }
    unresolvedInputs = @()
    nativeShellClosure = @([ordered]@{
        path = "usr/bin/bash.exe"
        architecture = "arm64"
        personality = "msys"
    })
    remainingX64 = $remainingX64
    classifications = $classifications
    pseudoReloc = $pseudoReloc
    runtime = $null
    errors = @()
} | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8NoBOM -LiteralPath $Report
exit 0
'@ | Set-Content -Encoding utf8NoBOM -LiteralPath $fakeValidator
    $fakeReport = Join-Path $trash "validator-report.json"
    $env:NATIVE_SHELL_FAKE_REPORT = "pass"
    $null = Invoke-NativeShellValidator $fakeValidator Preview $fakeRoot `
        $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
        $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    $env:NATIVE_SHELL_FAKE_REPORT = "empty-classifications"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "lacks authoritative classification"
    $env:NATIVE_SHELL_FAKE_REPORT = "wrong-classification"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "not authoritative ARM64 MSYS"
    $env:NATIVE_SHELL_FAKE_REPORT = "bad-pseudo-reloc"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "non-authoritative pseudo-reloc"
    $env:NATIVE_SHELL_FAKE_REPORT = "pass"
    $env:NATIVE_SHELL_FAKE_REPORT = "noop"
    [IO.File]::WriteAllText($fakeReport, "stale")
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "did not write a fresh report"
    $env:NATIVE_SHELL_FAKE_REPORT = "wrong-mode"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "successful Final admission"
    $env:NATIVE_SHELL_FAKE_REPORT = "wrong-digest"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    } "digest 'lockSha256'"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Runtime $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport `
            $fakeAssembly
    } "supplied together"
    $env:NATIVE_SHELL_FAKE_REPORT = "pass"
    $null = Invoke-NativeShellValidator $fakeValidator Final $fakeRoot `
        $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeReport
    $staticReportHash = Get-NativeShellSha256 $fakeReport
    [IO.File]::WriteAllText(
        $fakeAssembly,
        "{`"staticReportSha256`":`"$staticReportHash`"}`n")
    [IO.File]::WriteAllText(
        $fakeRuntime,
        "{`"admissionMode`":`"Final`",`"staticReportSha256`":`"$staticReportHash`"}`n")
    $fakeRuntimeReport = Join-Path $trash "validator-runtime-report.json"
    $null = Invoke-NativeShellValidator $fakeValidator Runtime $fakeRoot `
        $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeRuntimeReport `
        $fakeAssembly $fakeRuntime $fakeReport
    $env:NATIVE_SHELL_FAKE_REPORT = "wrong-static-digest"
    Assert-Throws {
        $null = Invoke-NativeShellValidator $fakeValidator Runtime $fakeRoot `
            $fakeLock $fakeProvenance $fakePayload $fakeTool $fakeRuntimeReport `
            $fakeAssembly $fakeRuntime $fakeReport
    } "digest 'staticReportSha256'"
    $env:NATIVE_SHELL_FAKE_REPORT = "pass"
    $ownershipRoot = Join-Path $trash "base-ownership-root"
    $null = New-Item -ItemType Directory -Path (
        Join-Path $ownershipRoot "usr\share\licenses\new-package") -Force
    [IO.File]::WriteAllText((Join-Path $ownershipRoot "usr\base.dat"), "base")
    [IO.File]::WriteAllText((Join-Path $ownershipRoot "usr\replace.dat"), "new")
    [IO.File]::WriteAllText(
        (Join-Path $ownershipRoot "usr\share\licenses\new-package\COPYING"),
        "license")
    $baseHash = Get-NativeShellSha256 (
        Join-Path $ownershipRoot "usr\base.dat")
    $oldHash = "7" * 64
    $newHash = Get-NativeShellSha256 (
        Join-Path $ownershipRoot "usr\replace.dat")
    $ownershipAdapter = [pscustomobject][ordered]@{
        sourceDateEpoch = 1
        nativeShellClosure = @("usr/replace.dat")
        inputs = @(
            [pscustomobject][ordered]@{
                id = "a-overlay"
                role = "payload"
                status = "resolved"
                release = [ordered]@{ repository = "crutkas/test"; tag = "v1"; targetCommit = "1" * 40 }
                asset = [ordered]@{ url = "https://github.com/crutkas/test/releases/download/v1/a"; name = "a"; bytes = 1; sha256 = "8" * 64 }
                package = $null
                overlay = [ordered]@{
                    mappings = @(
                        [ordered]@{
                            sourceMember = "license-dir"
                            destinationPath = "usr/share/licenses/new-package"
                        },
                        [ordered]@{
                            sourceMember = "license-dir/COPYING"
                            destinationPath = "usr/share/licenses/new-package/COPYING"
                        },
                        [ordered]@{
                            sourceMember = "new.dat"
                            destinationPath = "usr/replace.dat"
                        }
                    )
                }
            },
            [pscustomobject][ordered]@{
                id = "stack-base"
                role = "base-bundle"
                status = "resolved"
                release = $null
                asset = $null
                package = $null
                overlay = [ordered]@{
                    mappings = @(
                        [ordered]@{ sourceMember = "usr"; destinationPath = "usr" },
                        [ordered]@{ sourceMember = "usr/base.dat"; destinationPath = "usr/base.dat" },
                        [ordered]@{ sourceMember = "usr/replace.dat"; destinationPath = "usr/replace.dat" },
                        [ordered]@{ sourceMember = "usr/share"; destinationPath = "usr/share" },
                        [ordered]@{ sourceMember = "usr/share/licenses"; destinationPath = "usr/share/licenses" }
                    )
                }
            }
        )
    }
    $baseArchive = @(
        [ordered]@{ sourceMember = "usr"; type = "directory"; bytes = 0; sha256 = $null; linkTarget = $null },
        [ordered]@{ sourceMember = "usr/base.dat"; type = "file"; bytes = 4; sha256 = $baseHash; linkTarget = $null },
        [ordered]@{ sourceMember = "usr/removed.dat"; type = "file"; bytes = 1; sha256 = ("9" * 64); linkTarget = $null },
        [ordered]@{ sourceMember = "usr/replace.dat"; type = "file"; bytes = 3; sha256 = $oldHash; linkTarget = $null },
        [ordered]@{ sourceMember = "usr/share"; type = "directory"; bytes = 0; sha256 = $null; linkTarget = $null },
        [ordered]@{ sourceMember = "usr/share/licenses"; type = "directory"; bytes = 0; sha256 = $null; linkTarget = $null }
    )
    $ownershipProvenance = New-NativeShellProvenance `
        $ownershipAdapter ("a" * 64) @(
            [ordered]@{
                id = "a-overlay"
                archiveMembers = @(
                    [ordered]@{
                        sourceMember = "license-dir"
                        type = "directory"
                        bytes = 0
                        sha256 = $null
                        linkTarget = $null
                    },
                    [ordered]@{
                        sourceMember = "license-dir/COPYING"
                        type = "file"
                        bytes = 7
                        sha256 = Get-NativeShellSha256 (
                            Join-Path $ownershipRoot "usr\share\licenses\new-package\COPYING")
                        linkTarget = $null
                    },
                    [ordered]@{
                        sourceMember = "new.dat"
                        type = "file"
                        bytes = 3
                        sha256 = $newHash
                        linkTarget = $null
                    }
                )
            },
            [ordered]@{ id = "stack-base"; archiveMembers = $baseArchive }
        ) ([ordered]@{
            repository = "crutkas/build-extra"
            commit = "be0217cb572704f27ea04c9abde8bb992b8ef0c0"
        }) $ownershipRoot ([pscustomobject]@{
            pseudoRelocGate = [pscustomobject]@{
                script = [pscustomobject]@{
                    repository = "crutkas/MSYS2-packages"
                    commit = "3" * 40
                    path = "scanner.ps1"
                    bytes = 1
                    sha256 = "b" * 64
                }
            }
        })
    Assert-Equal "stack-base,a-overlay" (
        @($ownershipProvenance.overlayOrder) -join ",") `
        "Native overlay does not follow the base tree"
    Assert-Equal "be0217cb572704f27ea04c9abde8bb992b8ef0c0" `
        $ownershipProvenance.assembler.commit `
        "Provenance assembler identity changed"
    Assert-Equal 1 @($ownershipProvenance.replacements).Count `
        "Base replacement provenance changed"
    Assert-Equal "stack-base" $ownershipProvenance.replacements[0].replacedInputId `
        "Base replacement loser changed"
    Assert-Equal "a-overlay" @($ownershipProvenance.finalMembers |
        Where-Object destinationPath -eq "usr/replace.dat")[0].inputId `
        "Native overlay did not win final ownership"
    $newDirectoryOwner = @($ownershipProvenance.finalMembers |
        Where-Object {
            $_.destinationPath -eq "usr/share/licenses/new-package"
        })[0]
    Assert-Equal "a-overlay" $newDirectoryOwner.inputId `
        "New nested directory lacks native provenance ownership"
    Assert-Equal "directory" $newDirectoryOwner.type `
        "New nested directory provenance type changed"
    Assert-Equal $false @($ownershipProvenance.inputs |
        Where-Object id -eq "stack-base")[0].archiveMembers[2].selected `
        "Removed base member was selected"
    $generatedPayload = New-PayloadManifest `
        ("a" * 64) ("b" * 64) $ownershipRoot `
        @($ownershipProvenance.finalMembers)
    Assert-Equal 7 @($generatedPayload.entries).Count `
        "Generated payload does not cover the materialized root"
    Assert-Equal "directory" @($generatedPayload.entries |
        Where-Object path -eq "usr/share/licenses/new-package")[0].type `
        "Payload does not inventory the new nested directory"
    foreach ($entry in $generatedPayload.entries) {
        Assert-Equal "path,type,bytes,sha256,linkTarget" (
            @($entry.Keys) -join ",") `
            "Payload entry contains producer-supplied classification fields"
    }
    Remove-Item Env:NATIVE_SHELL_FAKE_REPORT
    }

    $ownership = @(Import-Csv -Delimiter "`t" -LiteralPath $ownershipPath)
    Assert-Equal $lock.legacyBaseline.ownershipRows $ownership.Count `
        "Legacy ownership row count changed"
    Assert-Equal $lock.legacyBaseline.ownershipBytes (Get-Item $ownershipPath).Length `
        "Legacy ownership byte count changed"
    Assert-Equal $lock.legacyBaseline.ownershipSha256 (
        Get-NativeShellSha256 $ownershipPath) "Legacy ownership hash changed"
    Assert-Equal 1 @($ownership | Where-Object finalDisposition -eq "replace").Count `
        "Runtime replacement count changed"
    Assert-Equal 32 @($ownership | Where-Object finalDisposition -eq "remove").Count `
        "Runtime removal count changed"
    Assert-Equal 1 @($ownership | Where-Object {
        $_.finalDisposition -eq "remove-after-zero-reverse-imports"
    }).Count "Guarded legacy removal count changed"
    Assert-Equal 6894 @(
        $ownership | Where-Object finalDisposition -eq "pending-final-package"
    ).Count "Pending final ownership count changed"
    if ($ownership | Where-Object { $_.kind -in @("link", "hardlink") -and -not $_.linkTarget }) {
        throw "Legacy link ownership is missing an exact target"
    }

    Assert-NativeShellSetEqual @(
        "arm64-busybox", "dos2unix", "gawk", "vim", "win32-openssh-client"
    ) @($lock.collisionPolicy.knownDisjointOwners) "Disjoint payload owners"
    Assert-NativeShellSetEqual @(
        "shell-startup", "pty-terminal", "quoting", "globbing", "utf8",
        "pipes", "signals", "fork", "spawn", "git-init", "git-commit",
        "git-hooks", "git-local-clone"
    ) @($lock.smokeContract) "Native smoke contract"
    Assert-Equal "msys-2.0.dll" $lock.authoritativeGate.requiredPersonalityImport `
        "Required MSYS personality import changed"
    Assert-NativeShellSetEqual @("cygwin1.dll") @(
        $lock.authoritativeGate.forbiddenImports) "Forbidden runtime personality"
    Assert-Equal "0xAA64" $lock.authoritativeGate.requiredMachine `
        "Required PE machine changed"
    Assert-Equal "empty-or-scalar64-only" $lock.pseudoRelocGate.allowedResult `
        "Pseudo-reloc acceptance changed"
    Assert-NativeShellSetEqual @(64) @($lock.pseudoRelocGate.allowedFlags) `
        "Pseudo-reloc flags changed"

    $validationOnly = @(
        $lock.inputs |
            Where-Object { $_.status -eq "resolved" -and $_.shipPolicy -eq "forbidden" }
    )
    foreach ($lockInput in $validationOnly) {
        if ($lockInput.overlay.enabled -or @($lockInput.overlay.mappings).Count -ne 0) {
            throw "Validation-only input '$($lockInput.id)' can enter the payload"
        }
    }

    $bash = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($bash) {
        & $bash.Source -c "ARCH=x86_64 ./arm64-native-shell/install.sh"
        if ($LASTEXITCODE -ne 0) {
            throw "The native shell integration changed non-ARM64 behavior"
        }
        & $bash.Source -c @'
actual=$(printf "usr/bin/a\nusr/bin/b\n" |
    ARCH=x86_64 GFW_ARM64_NATIVE_SHELL=1 \
    ./arm64-native-shell/prepare-file-list.sh portable \
    native-shell-non-arm-test-$$)
test "$actual" = "$(printf "usr/bin/a\nusr/bin/b")" &&
test ! -e native-shell-non-arm-test-$$
'@
        if ($LASTEXITCODE -ne 0) {
            throw "The native shell staging changed non-ARM64 file lists"
        }
        & $bash.Source -c @'
actual=$(printf "usr/bin/a\nusr/bin/b\n" |
    ARCH=x86_64 GFW_ARM64_NATIVE_SHELL=preview \
    ./arm64-native-shell/prepare-file-list.sh portable \
    native-shell-non-arm-preview-test-$$)
test "$actual" = "$(printf "usr/bin/a\nusr/bin/b")" &&
test ! -e native-shell-non-arm-preview-test-$$
'@
        if ($LASTEXITCODE -ne 0) {
            throw "Preview staging changed non-ARM64 file lists"
        }
        & $bash.Source -c @'
output=$(ARCH=aarch64 GFW_ARM64_NATIVE_SHELL=preview \
    ./arm64-native-shell/install.sh --materialize 2>&1) &&
exit 1
case "$output" in
*"GFW_ARM64_NATIVE_SHELL_CACHE is required"*) ;;
*) printf '%s\n' "$output" >&2; exit 1;;
esac
'@
        if ($LASTEXITCODE -ne 0) {
            throw "Preview materialization did not preserve Preview admission"
        }
        & $bash.Source -c @'
actual=$(printf "usr/bin/a\nusr/bin/b\n" |
    ARCH=aarch64 GFW_ARM64_NATIVE_SHELL=0 \
    ./arm64-native-shell/prepare-file-list.sh portable \
    native-shell-disabled-test-$$)
test "$actual" = "$(printf "usr/bin/a\nusr/bin/b")" &&
test ! -e native-shell-disabled-test-$$
'@
        if ($LASTEXITCODE -ne 0) {
            throw "Disabled native shell staging is not a no-op"
        }
    }

    if ($RuntimeCache) {
        $runtimeWork = Join-Path $trash "runtime-validation"
        $runtimeReport = Join-Path $trash "runtime-validation.json"
        & $script `
            -Mode Preview `
            -Lock $lockPath `
            -Cache $RuntimeCache `
            -Work $runtimeWork `
            -Report $runtimeReport `
            -DownloadResolved `
            -Quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Immutable a527 runtime validation failed"
        }
        $runtimeResult = Get-Content -Raw $runtimeReport | ConvertFrom-Json
        Assert-Equal 5 @($runtimeResult.verifiedInputs).Count `
            "Not all a527 runtime inputs were verified"
    }

    Write-Host "Native ARM64 shell integration checks passed"
} finally {
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
