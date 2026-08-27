[CmdletBinding()]
param(
    [ValidateSet("Preview", "Final")]
    [string]$Mode = "Preview",

    [string]$Lock = (Join-Path $PSScriptRoot "locks\native-shell-closure-v1.json"),

    [string]$Root,

    [string]$Cache,

    [string]$Work,

    [string]$Validator,

    [string]$AssemblerCommit,

    [string]$AssemblyEvidence,

    [string]$RuntimeEvidence,

    [string]$Provenance,

    [string]$PayloadManifest,

    [string]$Report,

    [string[]]$ValidateInput,

    [switch]$DownloadResolved,

    [switch]$LockOnly,

    [switch]$FunctionsOnly,

    [switch]$Quiet,

    [string]$Tar
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "NativeShell.psm1") -Force

function Assert-PrivatePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $expanded = [IO.Path]::GetFullPath($Path)
    if ($expanded.Equals([IO.Path]::GetPathRoot($expanded),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose cannot use a filesystem root"
    }
    $cursor = [IO.Path]::GetPathRoot($expanded)
    $relative = [IO.Path]::GetRelativePath($cursor, $expanded)
    foreach ($segment in $relative.Split(
        [IO.Path]::DirectorySeparatorChar,
        [StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $segment
        $item = Get-Item -Force -LiteralPath $cursor -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            break
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Purpose cannot traverse a link or junction: '$cursor'"
        }
    }
    $full = $expanded.TrimEnd("\")
    $shared = [IO.Path]::GetFullPath("C:\msys64").TrimEnd("\")
    if ($full.Equals($shared, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith("$shared\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose cannot use the shared C:\msys64 root"
    }
    return $full
}

function Assert-PathOutsideRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose cannot be inside the payload root"
    }
}

function Assert-NativeShellPathsDisjoint {
    param([Parameter(Mandatory = $true)][string[]]$Paths)

    for ($left = 0; $left -lt $Paths.Count; $left++) {
        $leftPath = [IO.Path]::GetFullPath($Paths[$left]).TrimEnd("\")
        for ($right = $left + 1; $right -lt $Paths.Count; $right++) {
            $rightPath = [IO.Path]::GetFullPath($Paths[$right]).TrimEnd("\")
            if ($leftPath.Equals($rightPath, [StringComparison]::OrdinalIgnoreCase) -or
                $leftPath.StartsWith(
                    "$rightPath\", [StringComparison]::OrdinalIgnoreCase) -or
                $rightPath.StartsWith(
                    "$leftPath\", [StringComparison]::OrdinalIgnoreCase)) {
                throw "Native shell integration paths must be private and disjoint"
            }
        }
    }
}

function Assert-NativeShellAssemblerCommit {
    param([Parameter(Mandatory = $true)][string]$Commit)

    if ($Commit -cnotmatch "^[0-9a-f]{40}$") {
        throw "AssemblerCommit must be a lowercase 40-character commit"
    }
    $git = Get-Command git.exe, git -CommandType Application `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $git) {
        return
    }
    $repository = Split-Path -Parent $PSScriptRoot
    $inside = @(& $git.Source -C $repository rev-parse `
        --is-inside-work-tree 2>$null)
    if ($LASTEXITCODE -ne 0 -or $inside.Count -ne 1 -or
        [string]$inside[0] -cne "true") {
        return
    }
    & $git.Source -C $repository cat-file -e "$Commit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "AssemblerCommit is not available in the product checkout"
    }
    foreach ($relative in @(
        "arm64-native-shell/install.ps1",
        "arm64-native-shell/NativeShell.psm1"
    )) {
        $committed = @(& $git.Source -C $repository rev-parse "$Commit`:$relative" 2>$null)
        $current = @(& $git.Source -C $repository hash-object `
            "--path=$relative" (Join-Path $repository $relative.Replace("/", "\")) 2>$null)
        if ($LASTEXITCODE -ne 0 -or $committed.Count -ne 1 -or
            $current.Count -ne 1 -or
            [string]$committed[0] -cne [string]$current[0]) {
            throw "AssemblerCommit does not contain the current '$relative' bytes"
        }
    }
}

function Get-InputArchive {
    param(
        [Parameter(Mandatory = $true)][object]$PackageInput,
        [Parameter(Mandatory = $true)][string]$CachePath,
        [switch]$Download
    )

    $archive = Join-Path $CachePath ([string]$PackageInput.asset.name)
    if (Test-Path -LiteralPath $archive) {
        return $archive
    }
    if (-not $Download) {
        throw "Missing cached immutable input '$($PackageInput.id)': $archive"
    }

    $temporary = "$archive.download-$PID"
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -Force -LiteralPath $temporary
    }
    Invoke-WebRequest -UseBasicParsing -Uri $PackageInput.asset.url -OutFile $temporary
    $item = Get-Item -LiteralPath $temporary
    if ($item.Length -ne [int64]$PackageInput.asset.expectedBytes) {
        Remove-Item -Force -LiteralPath $temporary
        throw "Downloaded asset size mismatch for '$($PackageInput.id)'"
    }
    if ((Get-NativeShellSha256 $temporary) -ne [string]$PackageInput.asset.sha256) {
        Remove-Item -Force -LiteralPath $temporary
        throw "Downloaded asset SHA-256 mismatch for '$($PackageInput.id)'"
    }
    Move-Item -LiteralPath $temporary -Destination $archive
    return $archive
}

function Get-LegacyOwnership {
    param([Parameter(Mandatory = $true)][object]$LockObject)

    $path = Join-Path $PSScriptRoot ([string]$LockObject.legacyBaseline.ownership)
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing legacy ownership manifest: $path"
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne [int64]$LockObject.legacyBaseline.ownershipBytes -or
        (Get-NativeShellSha256 $path) -ne [string]$LockObject.legacyBaseline.ownershipSha256) {
        throw "Legacy ownership manifest identity mismatch"
    }
    $rows = @(Import-Csv -Delimiter "`t" -LiteralPath $path)
    if ($rows.Count -ne [int]$LockObject.legacyBaseline.ownershipRows) {
        throw "Legacy ownership manifest row count mismatch"
    }
    return $rows
}

function New-PayloadManifest {
    param(
        [Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][string]$ProvenanceSha256,
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][object[]]$FinalMembers
    )

    $owners = @{}
    foreach ($member in $FinalMembers) {
        $owners[[string]$member.destinationPath] = $member
    }
    $payloadRows = @(
        Get-ChildItem -Force -Recurse -LiteralPath $PayloadRoot |
            ForEach-Object {
                [ordered]@{
                    item = $_
                    relative = [IO.Path]::GetRelativePath(
                        $PayloadRoot, $_.FullName).Replace("\", "/")
                }
            } |
            Where-Object {
                $_.relative -ine "preview-evidence" -and
                -not $_.relative.StartsWith(
                    "preview-evidence/", [StringComparison]::OrdinalIgnoreCase)
            }
    )
    $payloadRows = @(Sort-NativeShellOrdinal `
        -InputObject $payloadRows -Property { param($row) $row.relative })
    $entries = @(
        $payloadRows | ForEach-Object {
                $relative = [string]$_.relative
                $item = $_.item
                if (-not $owners.ContainsKey($relative)) {
                    throw "Materialized payload member has no archive owner: '$relative'"
                }
                $owner = $owners[$relative]
                $type = [string]$owner.type
                $contentPath = $item.FullName
                if ($type -in @("symlink", "hardlink")) {
                    $contentPath = Join-Path $PayloadRoot (
                        [string]$owner.linkTarget).Replace("/", "\")
                }
                [ordered]@{
                    path = $relative
                    type = $type
                    bytes = $(if ($type -eq "directory") { 0 } else {
                        [long](Get-Item -Force -LiteralPath $contentPath).Length
                    })
                    sha256 = $(if ($type -eq "directory") { $null } else {
                        Get-NativeShellSha256 $contentPath
                    })
                    linkTarget = $owner.linkTarget
                }
        }
    )
    if ($entries.Count -ne $FinalMembers.Count) {
        throw "Payload inventory and final archive ownership counts differ"
    }
    return [ordered]@{
        schemaVersion = 1
        lockSha256 = $LockSha256
        provenanceSha256 = $ProvenanceSha256
        scope = [ordered]@{
            root = "."
            excludedPrefixes = @("preview-evidence/")
        }
        entries = @($entries)
    }
}

function New-NativeShellProvenance {
    param(
        [Parameter(Mandatory = $true)][object]$Adapter,
        [Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][object[]]$Validated,
        [Parameter(Mandatory = $true)][object]$Assembler,
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][object]$RichLock
    )

    $validatedById = @{}
    foreach ($entry in $Validated) {
        $validatedById[[string]$entry.id] = $entry
    }
    $selected = [Collections.Generic.List[object]]::new()
    $inputs = @(
        foreach ($input in @($Adapter.inputs | Where-Object status -eq "resolved")) {
            $verified = $validatedById[[string]$input.id]
            if ($null -eq $verified) {
                throw "Resolved adapter input '$($input.id)' was not validated"
            }
            $mappingBySource = @{}
            foreach ($mapping in @($input.overlay.mappings)) {
                $mappingBySource[[string]$mapping.sourceMember] =
                    [string]$mapping.destinationPath
            }
            $archiveMembers = @(
                foreach ($member in @($verified.archiveMembers)) {
                    $isSelected = $input.role -ne "validation-tool" -and
                        $mappingBySource.ContainsKey([string]$member.sourceMember)
                    $destination = $(if ($isSelected) {
                        $mappingBySource[[string]$member.sourceMember]
                    } else {
                        $null
                    })
                    $row = [ordered]@{
                        sourceMember = [string]$member.sourceMember
                        type = [string]$member.type
                        bytes = [long]$member.bytes
                        sha256 = $member.sha256
                        selected = $isSelected
                        destinationPath = $destination
                        linkTarget = $member.linkTarget
                    }
                    if ($isSelected) {
                        $finalLinkTarget = $member.linkTarget
                        if ($member.type -in @("symlink", "hardlink")) {
                            if (-not $mappingBySource.ContainsKey(
                                [string]$member.linkTarget)) {
                                throw "Selected archive link target is not explicitly mapped: " +
                                    "'$($member.sourceMember)'"
                            }
                            $finalLinkTarget =
                                $mappingBySource[[string]$member.linkTarget]
                        }
                        $selected.Add([ordered]@{
                            destinationPath = $destination
                            inputId = [string]$input.id
                            sourceMember = [string]$member.sourceMember
                            type = [string]$member.type
                            bytes = [long]$member.bytes
                            sha256 = $member.sha256
                            linkTarget = $finalLinkTarget
                        })
                    }
                    $row
                }
            )
            [ordered]@{
                id = [string]$input.id
                release = $input.release
                asset = $input.asset
                package = $input.package
                archiveMembers = @($archiveMembers)
            }
        }

    )
    $overlayOrder = @("stack-base") + @(
        $Adapter.inputs |
            Where-Object {
                $_.status -eq "resolved" -and $_.role -eq "payload"
            } |
            ForEach-Object { [string]$_.id }
    )
    $order = @{}
    for ($index = 0; $index -lt $overlayOrder.Count; $index++) {
        $order[$overlayOrder[$index]] = $index
    }
    $selectedByDestination = @{}
    foreach ($member in $selected) {
        $key = ([string]$member.destinationPath).ToLowerInvariant()
        if (-not $selectedByDestination.ContainsKey($key)) {
            $selectedByDestination[$key] = @()
        }
        $selectedByDestination[$key] += $member
    }
    $replacements = [Collections.Generic.List[object]]::new()
    $finalMembers = @(
        foreach ($key in $selectedByDestination.Keys) {
            $candidates = @($selectedByDestination[$key])
            for ($index = 1; $index -lt $candidates.Count; $index++) {
                $value = $candidates[$index]
                $cursor = $index
                while ($cursor -gt 0 -and
                    $order[[string]$candidates[$cursor - 1].inputId] -gt
                        $order[[string]$value.inputId]) {
                    $candidates[$cursor] = $candidates[$cursor - 1]
                    $cursor--
                }
                $candidates[$cursor] = $value
            }
            $winner = $candidates[-1]
            foreach ($loser in @($candidates | Select-Object -First (
                [Math]::Max(0, $candidates.Count - 1)))) {
                $replacements.Add([ordered]@{
                    destinationPath = $winner.destinationPath
                    replacedInputId = $loser.inputId
                    replacedSourceMember = $loser.sourceMember
                    winnerInputId = $winner.inputId
                    winnerSourceMember = $winner.sourceMember
                })
            }
            $winner
        }
    )
    $finalMembers = @(Sort-NativeShellOrdinal `
        -InputObject $finalMembers -Property {
            param($member) $member["destinationPath"]
        })
    $finalMap = @{}
    foreach ($member in $finalMembers) {
        $key = ([string]$member.destinationPath).ToLowerInvariant()
        if ($finalMap.ContainsKey($key)) {
            throw "Adapter payload mappings collide at '$($member.destinationPath)'"
        }
        $finalMap[$key] = $member
    }
    $rootMembers = @(
        Get-ChildItem -Force -Recurse -LiteralPath $PayloadRoot |
            ForEach-Object {
                [IO.Path]::GetRelativePath(
                    $PayloadRoot, $_.FullName).Replace("\", "/")
            } |
            Where-Object {
                $_ -ine "preview-evidence" -and
                -not $_.StartsWith(
                    "preview-evidence/", [StringComparison]::OrdinalIgnoreCase)
            }
    )
    $unowned = @($rootMembers | Where-Object {
        -not $finalMap.ContainsKey($_.ToLowerInvariant())
    })
    if ($unowned.Count -ne 0) {
        throw "Canonical validator adapter cannot represent $($unowned.Count) " +
            "staged baseline members; first unowned path: '$($unowned[0])'"
    }
    $candidateRows = @(
        foreach ($member in $finalMembers) {
            if ($member.type -ne "file") {
                continue
            }
            $path = Join-Path $PayloadRoot $member.destinationPath.Replace("/", "\")
            $classification = Get-NativeShellPeClassification $path $member.destinationPath
            if ($classification.architecture -eq "arm64" -and
                $classification.personality -eq "msys") {
                [ordered]@{
                    destinationPath = $member.destinationPath
                    inputId = $member.inputId
                    sourceMember = $member.sourceMember
                }
            }
        }
    )
    return [ordered]@{
        schemaVersion = 1
        lockSha256 = $LockSha256
        sourceDateEpoch = [long]$Adapter.sourceDateEpoch
        nativeShellClosure = @($Adapter.nativeShellClosure)
        assembler = [ordered]@{
            repository = [string]$Assembler.repository
            commit = [string]$Assembler.commit
        }
        inputs = @($inputs)
        overlayOrder = $overlayOrder
        replacements = @(Sort-NativeShellOrdinal `
            -InputObject @($replacements | ForEach-Object { $_ }) -Property {
                param($replacement)
                "$($replacement['destinationPath'])`0" +
                    "$($replacement['replacedInputId'])`0" +
                    "$($replacement['replacedSourceMember'])"
            })
        finalMembers = $finalMembers
        pseudoReloc = [ordered]@{
            scanner = $RichLock.pseudoRelocGate.script
            toolInputId = "fixed-binutils"
            objdumpMember = "opt/bin/aarch64-pc-cygwin-objdump.exe"
            nmMember = "opt/bin/aarch64-pc-cygwin-nm.exe"
            linkerMember = "opt/bin/aarch64-pc-cygwin-ld.exe"
            candidates = @(Sort-NativeShellOrdinal `
                -InputObject $candidateRows -Property {
                    param($candidate) $candidate["destinationPath"]
                })
        }
    }
}

function Test-NativeShellValidationReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet("Preview", "Final", "Runtime")]
        [string]$ExpectedMode,
        [Parameter(Mandatory = $true)][ValidateSet("Preview", "Final")]
        [string]$ExpectedAdmissionMode,
        [Parameter(Mandatory = $true)][int]$ProcessExitCode,
        [Parameter(Mandatory = $true)][hashtable]$ExpectedDigests,
        [string[]]$ExpectedUnresolved = @(),
        [string[]]$ExpectedClosure = @()
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Authoritative validator did not write a fresh report"
    }
    $report = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 100
    foreach ($field in @(
        "schemaVersion", "mode", "admissionMode", "result", "exitCode",
        "readyForFinal", "digests", "summary", "unresolvedInputs",
        "nativeShellClosure", "remainingX64", "classifications",
        "pseudoReloc", "runtime", "errors"
    )) {
        if ($null -eq $report.PSObject.Properties[$field]) {
            throw "Authoritative validator report is missing '$field'"
        }
    }
    if ($report.schemaVersion -ne 1 -or $report.mode -cne $ExpectedMode -or
        $report.admissionMode -cne $ExpectedAdmissionMode -or
        $report.result -cne "pass" -or
        [int]$report.exitCode -ne 0 -or $ProcessExitCode -ne 0) {
        throw "Authoritative validator report did not record a successful $ExpectedMode admission"
    }
    foreach ($digest in $ExpectedDigests.GetEnumerator()) {
        if ($null -eq $report.digests.PSObject.Properties[$digest.Key] -or
            [string]$report.digests.($digest.Key) -cne [string]$digest.Value) {
            throw "Authoritative validator report digest '$($digest.Key)' does not match"
        }
    }
    if (@($report.errors).Count -ne 0 -or
        @($report.nativeShellClosure).Count -eq 0 -or
        [int]$report.summary.unresolvedInputs -ne
            @($report.unresolvedInputs).Count -or
        [int]$report.summary.remainingX64 -ne @($report.remainingX64).Count -or
        (@($report.unresolvedInputs) -join "`0") -cne
            (@($ExpectedUnresolved) -join "`0")) {
        throw "Authoritative validator report summary does not match its exact blockers " +
            "(unresolved=$(@($report.unresolvedInputs).Count)/" +
            "$([int]$report.summary.unresolvedInputs), expected=" +
            "$(@($ExpectedUnresolved).Count), x64=" +
            "$(@($report.remainingX64).Count)/$([int]$report.summary.remainingX64))"
    }
    if ($ExpectedAdmissionMode -eq "Final") {
        if (@($report.unresolvedInputs).Count -ne 0 -or
            @($report.remainingX64).Count -ne 0 -or
            -not [bool]$report.readyForFinal) {
            throw "Authoritative validator report did not prove Final readiness"
        }
        $classificationByPath = @{}
        foreach ($classification in @($report.classifications)) {
            $classificationByPath[[string]$classification.path] = $classification
        }
        $closureByPath = @{}
        foreach ($closure in @($report.nativeShellClosure)) {
            $closureByPath[[string]$closure.path] = $closure
        }
        foreach ($path in $ExpectedClosure) {
            if (-not $classificationByPath.ContainsKey($path) -or
                -not $closureByPath.ContainsKey($path)) {
                throw "Final report lacks authoritative classification for closure '$path'"
            }
            $classification = $classificationByPath[$path]
            $closure = $closureByPath[$path]
            if ([string]$classification.architecture -cne "arm64" -or
                [string]$classification.machine -cne "0xAA64" -or
                [string]$classification.personality -cne "msys" -or
                @($classification.imports) -cnotcontains "msys-2.0.dll" -or
                @($classification.imports) -ccontains "cygwin1.dll" -or
                [string]$closure.architecture -cne "arm64" -or
                [string]$closure.personality -cne "msys") {
                throw "Final report closure '$path' is not authoritative ARM64 MSYS"
            }
        }
        $detected = @(Sort-NativeShellOrdinal -InputObject @(
            $report.classifications |
                Where-Object {
                    $_.architecture -ceq "arm64" -and
                    $_.personality -ceq "msys"
                } |
                ForEach-Object { [string]$_.path }
        ) -Property { param($path) $path })
        $pseudoRows = @(Sort-NativeShellOrdinal `
            -InputObject @($report.pseudoReloc) -Property {
                param($row) [string]$row.path
            })
        if ($detected.Count -ne $pseudoRows.Count) {
            throw "Final report does not cover every ARM64 MSYS pseudo-reloc candidate"
        }
        for ($index = 0; $index -lt $detected.Count; $index++) {
            $row = $pseudoRows[$index]
            if ([string]$row.path -cne $detected[$index] -or
                [string]$row.result -cne "pass" -or
                ([long]$row.recordCount -ne 0 -and
                    ([string]$row.tableFormat -cne "v2" -or
                        @($row.flags).Count -eq 0 -or
                        @($row.flags | Where-Object { [long]$_ -ne 64 }).Count -ne 0))) {
                throw "Final report has non-authoritative pseudo-reloc evidence"
            }
        }
    } elseif ([bool]$report.readyForFinal -or
        @($report.remainingX64).Count -eq 0) {
        throw "Authoritative Preview report falsely claims Final readiness or zero x64"
    }
    return $report
}

function Invoke-NativeShellValidator {
    param(
        [Parameter(Mandatory = $true)][string]$ValidatorPath,
        [Parameter(Mandatory = $true)][ValidateSet("Preview", "Final", "Runtime")]
        [string]$ValidationMode,
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$AdapterPath,
        [Parameter(Mandatory = $true)][string]$ProvenancePath,
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$ToolPath,
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [string]$AssemblyPath,
        [string]$RuntimePath,
        [string]$StaticReportPath
    )

    if (($AssemblyPath -or $RuntimePath) -and
        (-not $AssemblyPath -or -not $RuntimePath)) {
        throw "AssemblyEvidence and RuntimeEvidence must be supplied together"
    }
    if ($ValidationMode -ne "Runtime" -and
        ($AssemblyPath -or $RuntimePath -or $StaticReportPath)) {
        throw "Static validation must not read runtime evidence or reports"
    }
    if ($ValidationMode -eq "Runtime" -and
        (-not $AssemblyPath -or -not $RuntimePath -or -not $StaticReportPath)) {
        throw "Runtime validation requires AssemblyEvidence, RuntimeEvidence, and StaticReport"
    }
    if (Test-Path -LiteralPath $ReportPath) {
        Remove-Item -Force -LiteralPath $ReportPath
    }
    $arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ValidatorPath,
        "-Mode", $ValidationMode,
        "-Root", $RootPath,
        "-Lock", $AdapterPath,
        "-Provenance", $ProvenancePath,
        "-PayloadManifest", $PayloadPath,
        "-ToolRoot", $ToolPath,
        "-Report", $ReportPath
    )
    if ($ValidationMode -eq "Runtime") {
        $arguments += @(
            "-AssemblyEvidence", $AssemblyPath,
            "-RuntimeEvidence", $RuntimePath,
            "-StaticReport", $StaticReportPath
        )
    }
    & pwsh.exe @arguments
    $validatorExit = $LASTEXITCODE
    $adapter = Get-Content -Raw -LiteralPath $AdapterPath |
        ConvertFrom-Json -Depth 100
    $baseInput = @($adapter.inputs |
        Where-Object { $_.resolution.method -eq "derived-tree" })[0]
    $digests = @{
        sourceLockSha256 = [string]$adapter.sourceLock.sha256
        baseTreeManifestSha256 = [string]$baseInput.resolution.manifest.sha256
        lockSha256 = Get-NativeShellSha256 $AdapterPath
        provenanceSha256 = Get-NativeShellSha256 $ProvenancePath
        payloadManifestSha256 = Get-NativeShellSha256 $PayloadPath
    }
    if ($ValidationMode -eq "Runtime") {
        $digests.assemblyEvidenceSha256 = Get-NativeShellSha256 $AssemblyPath
        $digests.runtimeEvidenceSha256 = Get-NativeShellSha256 $RuntimePath
        $digests.staticReportSha256 = Get-NativeShellSha256 $StaticReportPath
    }
    $admissionMode = if ($ValidationMode -eq "Runtime") {
        [string](
            (Get-Content -Raw -LiteralPath $RuntimePath |
                ConvertFrom-Json -Depth 100).admissionMode)
    } else {
        $ValidationMode
    }
    $unresolved = @($adapter.inputs |
        Where-Object status -eq "unresolved" |
        ForEach-Object { [string]$_.id })
    return Test-NativeShellValidationReport `
        $ReportPath $ValidationMode $admissionMode $validatorExit $digests `
        $unresolved @($adapter.nativeShellClosure)
}

function Invoke-OverlayTransaction {
    param(
        [Parameter(Mandatory = $true)][object]$LockObject,
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][object[]]$Plan,
        [Parameter(Mandatory = $true)][object[]]$Legacy,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$GuardedRemovals,
        [Parameter(Mandatory = $true)][hashtable]$ExtractRoots,
        [Parameter(Mandatory = $true)][string]$TransactionRoot,
        [Parameter(Mandatory = $true)][string[]]$MetadataPaths,
        [Parameter(Mandatory = $true)][scriptblock]$Validate
    )

    $backup = Join-Path $TransactionRoot "backup"
    $null = New-Item -ItemType Directory -Path $backup
    $changed = [Collections.Generic.List[object]]::new()
    try {
        $metadataIndex = 0
        foreach ($metadataPath in $MetadataPaths) {
            $metadataIndex++
            $fullMetadataPath = [IO.Path]::GetFullPath($metadataPath)
            $backupPath = Join-Path $backup "metadata\$metadataIndex"
            $existed = Test-Path -LiteralPath $fullMetadataPath
            if ($existed) {
                $null = New-Item -ItemType Directory -Force -Path (
                    Split-Path -Parent $backupPath)
                Copy-Item -Force -LiteralPath $fullMetadataPath -Destination $backupPath
            }
            $changed.Add([ordered]@{
                destination = $fullMetadataPath
                backup = $backupPath
                existed = $existed
            })
        }
        foreach ($legacyEntry in $Legacy | Where-Object { $_.finalDisposition -eq "remove" }) {
            $destination = Join-Path $PayloadRoot ([string]$legacyEntry.path).Replace("/", "\")
            if (-not (Test-Path -LiteralPath $destination)) {
                continue
            }
            $backupPath = Join-Path $backup ([string]$legacyEntry.path).Replace("/", "\")
            $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $backupPath)
            Copy-Item -Force -LiteralPath $destination -Destination $backupPath
            Remove-Item -Force -LiteralPath $destination
            $changed.Add([ordered]@{
                destination = $destination
                backup = $backupPath
                existed = $true
            })
        }
        $planByDestination = @(Sort-NativeShellOrdinal `
            -InputObject $Plan -Property { param($entry) $entry.destination })
        $orderedPlan = @(
            @($planByDestination |
                Where-Object content -notin @("symlink", "hardlink")) +
            @($planByDestination |
                Where-Object content -in @("symlink", "hardlink"))
        )
        foreach ($entry in $orderedPlan) {
            $destination = Join-Path $PayloadRoot ([string]$entry.destination).Replace("/", "\")
            $backupPath = Join-Path $backup ([string]$entry.destination).Replace("/", "\")
            if (Test-Path -LiteralPath $destination) {
                $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $backupPath)
                Copy-Item -Force -LiteralPath $destination -Destination $backupPath
            }
            $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination)
            if ($entry.content -eq "symlink") {
                if (Test-Path -LiteralPath $destination) {
                    Remove-Item -Force -LiteralPath $destination
                }
                $null = New-Item -ItemType SymbolicLink -Path $destination `
                    -Target ([string]$entry.linkTarget)
            } elseif ($entry.content -eq "hardlink") {
                if (Test-Path -LiteralPath $destination) {
                    Remove-Item -Force -LiteralPath $destination
                }
                $target = Join-Path $PayloadRoot ([string]$entry.linkTarget).Replace("/", "\")
                $null = New-Item -ItemType HardLink -Path $destination -Target $target
            } else {
                $source = Join-Path $ExtractRoots[[string]$entry.input] (
                    [string]$entry.source).Replace("/", "\")
                Copy-Item -Force -LiteralPath $source -Destination $destination
            }
            $changed.Add([ordered]@{
                destination = $destination
                backup = $backupPath
                existed = Test-Path -LiteralPath $backupPath
            })
        }
        foreach ($guarded in $GuardedRemovals) {
            $destination = Join-Path $PayloadRoot (
                [string]$guarded.path).Replace("/", "\")
            if (-not (Test-Path -LiteralPath $destination)) {
                continue
            }
            Assert-NativeShellNoReverseImports $PayloadRoot (
                [string]$guarded.path) ([string]$guarded.requiredImportName)
            $backupPath = Join-Path $backup ([string]$guarded.path).Replace("/", "\")
            $null = New-Item -ItemType Directory -Force -Path (
                Split-Path -Parent $backupPath)
            Copy-Item -Force -LiteralPath $destination -Destination $backupPath
            Remove-Item -Force -LiteralPath $destination
            if (Test-Path -LiteralPath $destination) {
                throw "Guarded legacy removal survived overlay: '$($guarded.path)'"
            }
            $changed.Add([ordered]@{
                destination = $destination
                backup = $backupPath
                existed = $true
            })
        }
        & $Validate
    } catch {
        for ($index = $changed.Count - 1; $index -ge 0; $index--) {
            $entry = $changed[$index]
            if ($entry.existed) {
                Copy-Item -Force -LiteralPath $entry.backup -Destination $entry.destination
            } elseif (Test-Path -LiteralPath $entry.destination) {
                Remove-Item -Force -LiteralPath $entry.destination
            }
        }
        $evidenceRoot = Join-Path $PayloadRoot "preview-evidence"
        if (Test-Path -LiteralPath $evidenceRoot) {
            Remove-Item -Recurse -Force -LiteralPath $evidenceRoot
        }
        throw
    }
}

if ($FunctionsOnly) {
    return
}

$lockPath = (Resolve-Path -LiteralPath $Lock).Path
$lockObject = Read-NativeShellLock $lockPath
$unresolved = @(Test-NativeShellLock $lockObject $Mode)
$previewReport = [ordered]@{
    schemaVersion = 1
    mode = $Mode
    state = $(if ($unresolved.Count -or
        $lockObject.authoritativeGate.status -ne "resolved") {
        "blocked"
    } else {
        "ready"
    })
    unresolved = @($unresolved)
    authoritativeGate = [ordered]@{
        status = $lockObject.authoritativeGate.status
        unresolvedFields = @(
            if ($lockObject.authoritativeGate.status -eq "unresolved") {
                $lockObject.authoritativeGate.unresolvedFields
            } else {
                @()
            }
        )
    }
}

if ($LockOnly) {
    if ($Report) {
        Write-NativeShellCanonicalJson $previewReport $Report
    }
    if (-not $Quiet) {
        $previewReport | ConvertTo-Json -Depth 20
    }
    exit 0
}

if ($Mode -eq "Preview" -and -not $DownloadResolved) {
    if ($Report) {
        Write-NativeShellCanonicalJson $previewReport $Report
    }
    if (-not $Quiet) {
        $previewReport | ConvertTo-Json -Depth 20
    }
    exit 0
}

if (-not $Cache) {
    throw "-Cache is required when immutable inputs are validated"
}
$cachePath = Assert-PrivatePath $Cache "The immutable input cache"
$null = New-Item -ItemType Directory -Force -Path $cachePath

$selectedIds = if ($ValidateInput) {
    @($ValidateInput)
} elseif ($Root) {
    @(
        $lockObject.inputs |
            Where-Object status -eq "resolved" |
            ForEach-Object id
    )
} elseif ($Mode -eq "Final") {
    @($lockObject.finalRequiredInputs)
} else {
    @(
        $lockObject.inputs |
            Where-Object { $_.status -eq "resolved" -and $_.identity.tag -eq "msysarm64-runtime-pr10-a527-20260824" } |
            ForEach-Object id
    )
}
$inputById = @{}
foreach ($lockInput in @($lockObject.inputs)) {
    $inputById[[string]$lockInput.id] = $lockInput
}
foreach ($id in $selectedIds) {
    if (-not $inputById.ContainsKey([string]$id) -or
        $inputById[[string]$id].status -ne "resolved") {
        throw "Cannot validate unresolved or unknown input '$id'"
    }
}

if ($Root) {
    foreach ($value in @(
        @($Root, "-Root"),
        @($Work, "-Work"),
        @($Validator, "-Validator"),
        @($AssemblerCommit, "-AssemblerCommit"),
        @($Provenance, "-Provenance"),
        @($PayloadManifest, "-PayloadManifest"),
        @($Report, "-Report")
    )) {
        if (-not $value[0]) {
            throw "$($value[1]) is required for product materialization"
        }
    }
    $rootPath = Assert-PrivatePath $Root "The payload root"
    Assert-NativeShellAssemblerCommit $AssemblerCommit
    $workPath = Assert-PrivatePath $Work "The extraction work root"
    $validatorPath = Assert-PrivatePath (
        (Resolve-Path -LiteralPath $Validator).Path) "The authoritative validator"
    $validatorItem = Get-Item -Force -LiteralPath $validatorPath
    if ($validatorItem.PSIsContainer -or
        $validatorItem.Name -ne [IO.Path]::GetFileName(
            [string]$lockObject.authoritativeGate.identity.path) -or
        $validatorItem.Length -ne
            [int64]$lockObject.authoritativeGate.identity.bytes -or
        (Get-NativeShellSha256 $validatorPath) -ne
            [string]$lockObject.authoritativeGate.identity.sha256) {
        throw "Authoritative ARM64 payload validator identity mismatch"
    }
    if (($AssemblyEvidence -or $RuntimeEvidence) -and
        (-not $AssemblyEvidence -or -not $RuntimeEvidence)) {
        throw "AssemblyEvidence and RuntimeEvidence must be supplied together"
    }
    $assemblyEvidencePath = $(if ($AssemblyEvidence) {
        Assert-PrivatePath (
            (Resolve-Path -LiteralPath $AssemblyEvidence).Path) "The assembly evidence"
    } else {
        $null
    })
    $runtimeEvidencePath = $(if ($RuntimeEvidence) {
        Assert-PrivatePath (
            (Resolve-Path -LiteralPath $RuntimeEvidence).Path) "The runtime evidence"
    } else {
        $null
    })
    $provenancePath = Assert-PrivatePath $Provenance "The provenance output"
    $payloadManifestPath = Assert-PrivatePath $PayloadManifest (
        "The payload manifest output")
    $reportPath = Assert-PrivatePath $Report "The validator report output"
    $runtimeReportPath = $(if ($AssemblyEvidence) {
        Assert-PrivatePath "$Report.runtime.json" "The runtime validator report output"
    } else {
        $null
    })
    foreach ($pathAndPurpose in @(
        @($cachePath, "The immutable input cache"),
        @($workPath, "The extraction work root"),
        @($validatorPath, "The authoritative validator"),
        @($assemblyEvidencePath, "The assembly evidence"),
        @($runtimeEvidencePath, "The runtime evidence"),
        @($provenancePath, "The provenance output"),
        @($payloadManifestPath, "The payload manifest output"),
        @($reportPath, "The validator report output"),
        @($runtimeReportPath, "The runtime validator report output")
    )) {
        if ($pathAndPurpose[0]) {
            Assert-PathOutsideRoot $pathAndPurpose[0] $rootPath $pathAndPurpose[1]
        }
    }
    $metadataPaths = @(
        $provenancePath, $payloadManifestPath, $reportPath,
        $assemblyEvidencePath, $runtimeEvidencePath, $runtimeReportPath
    ) | Where-Object { $_ }
    $metadataSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($metadataPath in $metadataPaths) {
        if (-not $metadataSet.Add($metadataPath)) {
            throw "Native shell evidence and report paths must be distinct"
        }
    }
    $allPaths = @(
        $rootPath, $cachePath, $workPath, $validatorPath,
        $provenancePath, $payloadManifestPath, $reportPath,
        $assemblyEvidencePath, $runtimeEvidencePath, $runtimeReportPath
    ) | Where-Object { $_ }
    Assert-NativeShellPathsDisjoint $allPaths
    foreach ($metadataPath in $metadataPaths) {
        Assert-PathOutsideRoot $metadataPath $workPath "A metadata output"
    }
    if (Test-Path -LiteralPath $workPath) {
        throw "Materialization work root must be fresh: '$workPath'"
    }
    $null = New-Item -ItemType Directory -Path $workPath
} else {
    $workPath = if ($Work) {
        Assert-PrivatePath $Work "The extraction work root"
    } else {
        Join-Path ([IO.Path]::GetTempPath()) "arm64-native-shell-$PID"
    }
    if (Test-Path -LiteralPath $workPath) {
        throw "Validation work root must be fresh: '$workPath'"
    }
    $null = New-Item -ItemType Directory -Path $workPath
}

$validated = [Collections.Generic.List[object]]::new()
$extractRoots = @{}
foreach ($id in $selectedIds) {
    $selectedInput = $inputById[[string]$id]
    $archive = Get-InputArchive $selectedInput $cachePath -Download:$DownloadResolved
    $extract = if ($selectedInput.asset.format -in @("pkg.tar.zst", "pkg.tar", "zip")) {
        Join-Path $workPath "extract\$id"
    } else {
        $null
    }
    $result = Test-NativeShellResolvedInput $selectedInput $archive $extract $Tar
    $validated.Add($result)
    if ($extract) {
        $extractRoots[[string]$id] = $extract
    }
}

if ($Mode -eq "Preview" -and -not $Root) {
    $previewValidated = @(Sort-NativeShellOrdinal `
        -InputObject @($validated | ForEach-Object { $_ }) `
        -Property { param($entry) $entry.id })
    $previewReport.verifiedInputs = @(
        $previewValidated |
            ForEach-Object {
                [ordered]@{
                    id = $_.id
                    bytes = $_.bytes
                    sha256 = $_.sha256
                    payloadMembers = @($_.payloadMembers).Count
                }
            }
    )
    if ($Report) {
        Write-NativeShellCanonicalJson $previewReport $Report
    }
    if (-not $Quiet) {
        $previewReport | ConvertTo-Json -Depth 20
    }
    exit 0
}

$legacy = Get-LegacyOwnership $lockObject
$guardedRemovals = [Collections.Generic.List[object]]::new()
foreach ($lockInput in @($lockObject.inputs | Where-Object status -eq "resolved")) {
    $admissionProperty = $lockInput.PSObject.Properties["admission"]
    if (-not $admissionProperty -or $null -eq $admissionProperty.Value) {
        continue
    }
    $omittedProperty = $admissionProperty.Value.PSObject.Properties[
        "omittedLegacyMembers"]
    if (-not $omittedProperty) {
        continue
    }
    foreach ($omitted in @($omittedProperty.Value)) {
        $matches = @($legacy | Where-Object {
            [string]$_.path -ceq [string]$omitted.path
        })
        if ($matches.Count -ne 1 -or
            [string]$matches[0].finalDisposition -ne
                "remove-after-zero-reverse-imports" -or
            [string]$matches[0].kind -ne [string]$omitted.kind -or
            [int64]$matches[0].bytes -ne [int64]$omitted.bytes -or
            [string]$matches[0].sha256 -cne [string]$omitted.sha256) {
            throw "Guarded legacy removal does not match ownership: '$($omitted.path)'"
        }
        $guardedPath = Join-Path $rootPath ([string]$omitted.path).Replace("/", "\")
        if (-not (Test-Path -LiteralPath $guardedPath)) {
            throw "Guarded legacy removal is missing: '$($omitted.path)'"
        }
        $guardedRemovals.Add($omitted)
    }
}
$pending = @($legacy | Where-Object { $_.finalDisposition -eq "pending-final-package" })
if ($Mode -eq "Final" -and $pending.Count -ne 0) {
    throw "Legacy ownership still awaits final package mappings: $($pending.Count) paths"
}
foreach ($entry in $legacy | Where-Object {
    $_.finalDisposition -in @(
        "remove", "remove-after-zero-reverse-imports", "replace")
}) {
    $path = Join-Path $rootPath ([string]$entry.path).Replace("/", "\")
    if (-not (Test-Path -LiteralPath $path)) {
        if ($entry.finalDisposition -eq "replace") {
            throw "Locked legacy replacement is missing: '$($entry.path)'"
        }
        continue
    }
    $item = Get-Item -Force -LiteralPath $path
    if ($entry.kind -ne "pe" -or
        $item.Length -ne [int64]$entry.bytes -or
        (Get-NativeShellSha256 $path) -ne [string]$entry.sha256) {
        throw "Locked legacy payload identity mismatch: '$($entry.path)'"
    }
}

$plan = @(Test-NativeShellOverlayPlan $lockObject $rootPath)
$mapped = @{}
foreach ($entry in $plan) {
    $mapped[[string]$entry.destination] = $true
}
foreach ($entry in $legacy | Where-Object { $_.finalDisposition -eq "replace" }) {
    if (-not $mapped.ContainsKey([string]$entry.path)) {
        throw "Legacy replacement is not owned by a native input: '$($entry.path)'"
    }
}
foreach ($entry in $legacy | Where-Object { $_.finalDisposition -eq "remove" }) {
    if ($mapped.ContainsKey([string]$entry.path)) {
        throw "Legacy removal unexpectedly has a native owner: '$($entry.path)'"
    }
}
foreach ($guardedEntry in $legacy | Where-Object {
    $_.finalDisposition -eq "remove-after-zero-reverse-imports"
}) {
    if ($mapped.ContainsKey([string]$guardedEntry.path)) {
        throw "Guarded legacy removal unexpectedly has a native owner: '$($guardedEntry.path)'"
    }
}
foreach ($entry in $legacy | Where-Object { $_.finalDisposition -eq "retain-data" }) {
    if ($entry.kind -eq "pe") {
        throw "Legacy PE cannot be retained as data: '$($entry.path)'"
    }
}

$lockHash = Get-NativeShellSha256 $lockPath

$transaction = Join-Path $workPath "transaction"
$null = New-Item -ItemType Directory -Path $transaction
$evidenceRoot = Join-Path $rootPath "preview-evidence"
$sourceLockPath = Join-Path $evidenceRoot "source-lock.json"
$baseManifestPath = Join-Path $evidenceRoot "base-tree-manifest.v1.json"
$adapterPath = Join-Path $evidenceRoot "bundle-lock.v1.json"
if (Test-Path -LiteralPath $evidenceRoot) {
    throw "Preview evidence directory must be fresh: '$evidenceRoot'"
}
$baseManifestObject = Get-NativeShellTreeManifest $rootPath
try {
    $null = New-Item -ItemType Directory -Path $evidenceRoot
    Write-NativeShellCanonicalJson $baseManifestObject $baseManifestPath
    $baseManifestHash = Get-NativeShellSha256 $baseManifestPath
    [IO.File]::WriteAllBytes($sourceLockPath, [IO.File]::ReadAllBytes($lockPath))
    if ((Get-NativeShellSha256 $sourceLockPath) -ne $lockHash) {
        throw "Copied source lock bytes do not match the rich product lock"
    }
    $archiveMembers = @{}
    foreach ($entry in $validated) {
        $archiveMembers[[string]$entry.id] = @($entry.archiveMembers)
    }
    $guardedRemovalPaths = @($guardedRemovals |
        ForEach-Object { [string]$_.path })
    $removedBasePaths = @($legacy |
        Where-Object {
            $_.finalDisposition -eq "remove" -or
            ($_.finalDisposition -eq "remove-after-zero-reverse-imports" -and
                $guardedRemovalPaths -ccontains [string]$_.path)
        } |
        ForEach-Object { [string]$_.path })
    $adapterObject = New-NativeShellAdapterLock `
        $lockObject $lockHash $archiveMembers $baseManifestHash `
        @($baseManifestObject.entries) $removedBasePaths
    Write-NativeShellCanonicalJson $adapterObject $adapterPath
    $adapterHash = Get-NativeShellSha256 $adapterPath
    $baseValidated = [ordered]@{
        id = "stack-base"
        archiveMembers = @($baseManifestObject.entries | ForEach-Object {
            [ordered]@{
                sourceMember = [string]$_.path
                type = [string]$_.type
                bytes = [long]$_.bytes
                sha256 = $_.sha256
                linkTarget = $_.linkTarget
            }
        })
    }
    $validatedForProvenance = @($validated) + @($baseValidated)
} catch {
    if (Test-Path -LiteralPath $evidenceRoot) {
        Remove-Item -Recurse -Force -LiteralPath $evidenceRoot
    }
    throw
}
$transactionMetadata = @(
    $provenancePath, $payloadManifestPath, $reportPath, $runtimeReportPath
) | Where-Object { $_ }
Invoke-OverlayTransaction $lockObject $rootPath $plan $legacy @($guardedRemovals) `
    $extractRoots $transaction @(
   $transactionMetadata
) {
   $provenanceObject = New-NativeShellProvenance `
       $adapterObject $adapterHash @($validatedForProvenance) `
       ([ordered]@{
           repository = "crutkas/build-extra"
           commit = $AssemblerCommit
       }) $rootPath $lockObject
   Write-NativeShellCanonicalJson $provenanceObject $provenancePath
   $provenanceHash = Get-NativeShellSha256 $provenancePath
   $payloadObject = New-PayloadManifest `
       $adapterHash $provenanceHash $rootPath @($provenanceObject.finalMembers)
   Write-NativeShellCanonicalJson $payloadObject $payloadManifestPath

   $toolRoot = $extractRoots["fixed-binutils"]
   $null = Invoke-NativeShellValidator `
       $validatorPath $Mode $rootPath $adapterPath $provenancePath `
       $payloadManifestPath $toolRoot $reportPath
   if ($assemblyEvidencePath) {
       $null = Invoke-NativeShellValidator `
           $validatorPath Runtime $rootPath $adapterPath $provenancePath `
           $payloadManifestPath $toolRoot $runtimeReportPath `
           $assemblyEvidencePath $runtimeEvidencePath $reportPath
   }
}
