[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Preview", "Final", "Runtime")]
    [string] $Mode,

    [Parameter(Mandatory = $true)]
    [Alias("PortableRoot")]
    [string] $Root,

    [Parameter(Mandatory = $true)]
    [Alias("LockPath")]
    [string] $Lock,

    [Parameter(Mandatory = $true)]
    [Alias("ProvenancePath")]
    [string] $Provenance,

    [Parameter(Mandatory = $true)]
    [Alias("PayloadManifestPath")]
    [string] $PayloadManifest,

    [Alias("AssemblyEvidencePath")]
    [string] $AssemblyEvidence,

    [Alias("RuntimeEvidencePath")]
    [string] $RuntimeEvidence,

    [Alias("StaticReportPath")]
    [string] $StaticReport,

    [string] $ToolRoot,

    [Parameter(Mandatory = $true)]
    [Alias("OutputPath")]
    [string] $Report
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ExitScanner = 10
$script:ExitContract = 20
$script:ExitStatic = 30
$script:ExitRuntime = 40
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:PathComparer = [StringComparer]::OrdinalIgnoreCase
$script:InvariantCompareInfo =
    [Globalization.CultureInfo]::InvariantCulture.CompareInfo
$script:ScannerRelativePath = "arm64-validation/check-aarch64-pseudo-relocs.ps1"
# Closed read-only vocabulary for describing the shared C:\msys64 root. Any
# other value, including every pacman invocation, is rejected outright.
$script:ReadOnlyObservationOperations = @(
    "enumerate-database-manifest",
    "hash-database-manifest",
    "hash-package-log",
    "stat-package-log")
$script:ScannerRepository = "crutkas/MSYS2-packages"
$script:ScannerCommit = "3356eec1411983cc252b04afac32bca5f3b8d824"
$script:ScannerSourcePath = ".ci/check-aarch64-pseudo-relocs.ps1"
$script:ScannerBytes = 10569
$script:ScannerSha256 =
    "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9"
$script:ToolPackageName = "mingw-w64-cross-cygwinarm64-binutils"
$script:ToolPackageVersion = "2.44.50-2"
$script:ToolPackageSha256 =
    "3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b"
$script:ObjdumpMember = "opt/bin/aarch64-pc-cygwin-objdump.exe"
$script:NmMember = "opt/bin/aarch64-pc-cygwin-nm.exe"
$script:LinkerMember = "opt/bin/aarch64-pc-cygwin-ld.exe"
$script:ObjdumpBytes = 2887699
$script:ObjdumpSha256 =
    "bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e"
$script:NmBytes = 1257877
$script:NmSha256 =
    "80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a"
$script:LinkerBytes = 1887140
$script:LinkerSha256 =
    "075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f"
$script:RequiredScenarios = [ordered]@{
    "Git Bash" = "msys"
    "Git" = "mingw"
    "SSH" = "mingw"
    "GPG" = "mingw"
    "hook" = "msys"
    "submodule" = "mingw"
    "rebase" = "msys"
    "git-svn" = "msys"
}

function Test-OrdinalStringEqual {
    param(
        [AllowNull()] $Left,
        [AllowNull()] $Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $null -eq $Left -and $null -eq $Right
    }
    if ($Left -isnot [string] -or $Right -isnot [string]) {
        return $false
    }
    return [string]::Equals(
        $Left, $Right, [StringComparison]::Ordinal)
}

function Test-OrdinalStringInCollection {
    param(
        [AllowNull()] $Value,
        [AllowNull()] $Candidates
    )

    foreach ($candidate in @($Candidates)) {
        if (Test-OrdinalStringEqual $Value $candidate) {
            return $true
        }
    }
    return $false
}

function Test-OrdinalStringSequenceEqual {
    param(
        [AllowNull()] $Left,
        [AllowNull()] $Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $null -eq $Left -and $null -eq $Right
    }
    $leftValues = @($Left)
    $rightValues = @($Right)
    if ($leftValues.Count -ne $rightValues.Count) {
        return $false
    }
    for ($index = 0; $index -lt $leftValues.Count; $index++) {
        if (-not (Test-OrdinalStringEqual `
                $leftValues[$index] $rightValues[$index])) {
            return $false
        }
    }
    return $true
}

function Assert-PropertyOrder {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string[]] $Names,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if (-not (Test-OrdinalStringSequenceEqual `
            @($Object.PSObject.Properties.Name) $Names)) {
        Throw-ValidationError $ExitCode "ordering" (
            "$Context properties are not in canonical order")
    }
}
$script:RequiredOperations = [ordered]@{
    "Git Bash" = "git-bash-startup"
    "Git" = "git-command"
    "SSH" = "ssh-command"
    "GPG" = "gpg-command"
    "hook" = "git-hook"
    "submodule" = "git-submodule"
    "rebase" = "git-rebase"
    "git-svn" = "git-svn"
}
$script:RequiredCommandContracts = [ordered]@{
    "Git Bash" = [ordered]@{
        executable = "usr/bin/bash.exe"
        arguments = @("--noprofile", "--norc", "-lc", "exit 0")
    }
    "Git" = [ordered]@{
        executable = "bin/git.exe"
        arguments = @("--version")
    }
    "SSH" = [ordered]@{
        executable = "usr/bin/ssh.exe"
        arguments = @("-V")
    }
    "GPG" = [ordered]@{
        executable = "usr/bin/gpg.exe"
        arguments = @("--version")
    }
    "hook" = [ordered]@{
        executable = "usr/bin/bash.exe"
        arguments = @("--noprofile", "--norc", "-lc", "exit 0")
    }
    "submodule" = [ordered]@{
        executable = "bin/git.exe"
        arguments = @("submodule", "status", "--recursive")
    }
    "rebase" = [ordered]@{
        executable = "usr/bin/bash.exe"
        arguments = @(
            "--noprofile", "--norc", "-lc", "git rebase --show-current-patch")
    }
    "git-svn" = [ordered]@{
        executable = "usr/bin/bash.exe"
        arguments = @("--noprofile", "--norc", "-lc", "git svn --version")
    }
}

function Assert-EvidenceRelativePath {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Context
    )

    if ($Value -isnot [string] -or
        -not $Value.StartsWith(
            "preview-evidence/",
            [StringComparison]::Ordinal) -or
        $Value.Contains("\") -or $Value.Contains(":") -or
        $Value.StartsWith("/") -or $Value.Contains("//") -or
        $Value.EndsWith("/")) {
        Throw-ValidationError $script:ExitContract "path" (
            "$Context must be a normalized path under preview-evidence/")
    }
    foreach ($component in $Value.Split("/")) {
        if (Test-OrdinalStringInCollection $component @("", ".", "..")) {
            Throw-ValidationError $script:ExitContract "path" (
                "$Context contains traversal")
        }
    }
}
$script:SafeReportPath = $null
$script:AuthoritativeCheckout = $null
$script:ReportData = [ordered]@{
    schemaVersion = 1
    mode = $Mode
    admissionMode = if (Test-OrdinalStringEqual $Mode "Runtime") {
        $null
    } else {
        $Mode
    }
    result = "error"
    exitCode = $script:ExitScanner
    readyForFinal = $false
    digests = [ordered]@{
        sourceLockSha256 = $null
        baseTreeManifestSha256 = $null
        lockSha256 = $null
        provenanceSha256 = $null
        payloadManifestSha256 = $null
        rootInventorySha256 = $null
        assemblyEvidenceSha256 = $null
        runtimeEvidenceSha256 = $null
        staticReportSha256 = $null
    }
    summary = [ordered]@{
        resolvedInputs = 0
        unresolvedInputs = 0
        payloadMembers = 0
        peFiles = 0
        remainingX64 = 0
        pseudoRelocCandidates = 0
        runtimeScenarios = 0
    }
    unresolvedInputs = @()
    nativeShellClosure = @()
    remainingX64 = @()
    classifications = @()
    pseudoReloc = @()
    runtime = $null
    errors = @()
}

function Throw-ValidationError {
    param(
        [Parameter(Mandatory = $true)][int] $ExitCode,
        [Parameter(Mandatory = $true)][string] $Category,
        [Parameter(Mandatory = $true)][string] $Message
    )

    $exception = [IO.InvalidDataException]::new($Message)
    $exception.Data["ExitCode"] = $ExitCode
    $exception.Data["Category"] = $Category
    throw $exception
}

function Assert-StaticReportContract {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $SourceLockSha256,
        [Parameter(Mandatory = $true)][string] $LockSha256,
        [Parameter(Mandatory = $true)][string] $ProvenanceSha256,
        [Parameter(Mandatory = $true)][string] $PayloadManifestSha256,
        [Parameter(Mandatory = $true)][string] $RootInventorySha256
    )

    $document = Read-JsonDocument $Path "static report" $script:ExitRuntime
    $object = $document.Object
    Assert-ExactProperties $object @(
        "schemaVersion", "mode", "admissionMode", "result", "exitCode",
        "readyForFinal", "digests", "summary", "unresolvedInputs",
        "nativeShellClosure", "remainingX64", "classifications", "pseudoReloc",
        "runtime", "errors") "static report" $script:ExitRuntime
    Assert-SchemaVersion $object "static report" $script:ExitRuntime
    $mode = Get-RequiredProperty $object "mode" "static report" `
        $script:ExitRuntime
    if ((-not (Test-OrdinalStringInCollection ($mode) (@("Preview", "Final"))))) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report must come from a Preview or Final run")
    }
    if ((-not (Test-OrdinalStringEqual ($object.admissionMode) ($mode))) -or
        $object.readyForFinal -isnot [bool] -or
        ((Test-OrdinalStringEqual ($mode) ("Final")) -and $object.readyForFinal -ne $true) -or
        $null -ne $object.runtime) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report mode fields do not describe a successful static run")
    }
    if ((-not (Test-OrdinalStringEqual ((Get-RequiredProperty $object "result" "static report" `
            $script:ExitRuntime)) ("pass"))) -or
        [int](Get-RequiredProperty $object "exitCode" "static report" `
            $script:ExitRuntime) -ne 0) {
        Throw-ValidationError $script:ExitRuntime "provenance" (
            "static report must record a successful static validation")
    }
    $digests = Get-RequiredProperty $object "digests" "static report" `
        $script:ExitRuntime
    Assert-ExactProperties $digests @(
        "sourceLockSha256", "baseTreeManifestSha256", "lockSha256",
        "provenanceSha256", "payloadManifestSha256", "rootInventorySha256",
        "assemblyEvidenceSha256", "runtimeEvidenceSha256",
        "staticReportSha256") "static report.digests" $script:ExitRuntime
    foreach ($pair in @(
        @("sourceLockSha256", $SourceLockSha256),
        @("lockSha256", $LockSha256),
        @("provenanceSha256", $ProvenanceSha256),
        @("payloadManifestSha256", $PayloadManifestSha256),
        @("rootInventorySha256", $RootInventorySha256))) {
        $actual = Get-RequiredProperty $digests $pair[0] `
            "static report.digests" $script:ExitRuntime
        if ((-not (Test-OrdinalStringEqual ([string]$actual) ($pair[1])))) {
            Throw-ValidationError $script:ExitRuntime "digest" (
                "static report.digests.$($pair[0]) does not bind this run")
        }
    }
    if ($null -ne $digests.baseTreeManifestSha256) {
        Assert-LowerSha256 $digests.baseTreeManifestSha256 `
            "static report.digests.baseTreeManifestSha256" $script:ExitRuntime
    }
    if ($null -ne $digests.assemblyEvidenceSha256 -or
        $null -ne $digests.runtimeEvidenceSha256 -or
        $null -ne $digests.staticReportSha256) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report cannot carry downstream runtime digests")
    }
    Assert-ExactProperties $object.summary @(
        "resolvedInputs", "unresolvedInputs", "payloadMembers", "peFiles",
        "remainingX64", "pseudoRelocCandidates", "runtimeScenarios") `
        "static report.summary" $script:ExitRuntime
    foreach ($name in @(
        "resolvedInputs", "unresolvedInputs", "payloadMembers", "peFiles",
        "remainingX64", "pseudoRelocCandidates", "runtimeScenarios")) {
        Assert-JsonInteger $object.summary.$name "static report.summary.$name" `
            0 $script:ExitRuntime
    }
    Assert-JsonArray $object.unresolvedInputs `
        "static report.unresolvedInputs" $script:ExitRuntime
    Assert-JsonArray $object.nativeShellClosure `
        "static report.nativeShellClosure" $script:ExitRuntime
    Assert-JsonArray $object.remainingX64 `
        "static report.remainingX64" $script:ExitRuntime
    Assert-JsonArray $object.pseudoReloc `
        "static report.pseudoReloc" $script:ExitRuntime
    Assert-JsonArray $object.errors "static report.errors" $script:ExitRuntime
    if (@($object.errors).Count -ne 0 -or
        [long]$object.summary.unresolvedInputs -ne
            @($object.unresolvedInputs).Count -or
        [long]$object.summary.remainingX64 -ne
            @($object.remainingX64).Count -or
        [long]$object.summary.pseudoRelocCandidates -ne
            @($object.pseudoReloc).Count -or
        [long]$object.summary.runtimeScenarios -ne 0) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report summary or error counts are inconsistent")
    }
    foreach ($id in @($object.unresolvedInputs)) {
        if ($id -isnot [string] -or
            $id -cnotmatch "^[a-z0-9][a-z0-9.-]*$") {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "static report unresolved input ID is invalid")
        }
    }
    foreach ($path in @($object.remainingX64)) {
        Assert-NormalizedPath $path "static report remainingX64 path" `
            -ExitCode $script:ExitRuntime
    }
    foreach ($row in @($object.nativeShellClosure)) {
        Assert-ExactProperties $row @(
            "path", "architecture", "personality") `
            "static report nativeShellClosure row" $script:ExitRuntime
        Assert-NormalizedPath $row.path `
            "static report nativeShellClosure path" `
            -ExitCode $script:ExitRuntime
        if ((-not (Test-OrdinalStringInCollection ($row.architecture) (@(
                "arm64", "arm64ec", "anycpu", "x64", "x86", "unknown",
                "non-pe")))) -or
            (-not (Test-OrdinalStringInCollection ($row.personality) (@(
                "msys", "mingw", "managed", "cygwin", "none"))))) {
            Throw-ValidationError $script:ExitRuntime "classification" (
                "static report nativeShellClosure classification is invalid")
        }
    }
    $classifications = @(Get-RequiredProperty $object "classifications" `
        "static report" $script:ExitRuntime)
    Assert-JsonArray $object.classifications `
        "static report.classifications" $script:ExitRuntime
    if ($classifications.Count -eq 0) {
        Throw-ValidationError $script:ExitRuntime "classification" (
            "static report must carry the authoritative classifications")
    }
    Assert-SortedUnique $classifications { param($item) [string]$item.path } `
        "static report.classifications" $script:ExitRuntime
    foreach ($row in $classifications) {
        Assert-ExactProperties $row @(
            "path", "architecture", "machine", "personality", "imports",
            "clrFlags", "inputId", "sourceMember") `
            "static report classification" $script:ExitRuntime
        Assert-NormalizedPath $row.path "static report classification.path" `
            -ExitCode $script:ExitRuntime
        Assert-NormalizedPath $row.sourceMember `
            "static report classification.sourceMember" `
            -ExitCode $script:ExitRuntime
        Assert-JsonArray $row.imports `
            "static report classification.imports" $script:ExitRuntime
        if ((-not (Test-OrdinalStringInCollection ($row.architecture) (@(
                "arm64", "arm64ec", "anycpu", "x64", "x86", "unknown",
                "non-pe")))) -or
            (-not (Test-OrdinalStringInCollection ($row.personality) (@(
                "msys", "mingw", "managed", "cygwin", "none")))) -or
            ($null -ne $row.machine -and
                ($row.machine -isnot [string] -or
                    $row.machine -cnotmatch "^0x[0-9A-F]{4}$")) -or
            ($null -ne $row.clrFlags -and
                ($row.clrFlags -isnot [int] -and
                    $row.clrFlags -isnot [long])) -or
            $row.inputId -isnot [string] -or
            $row.inputId -cnotmatch "^[a-z0-9][a-z0-9.-]*$") {
            Throw-ValidationError $script:ExitRuntime "classification" (
                "static report classification is malformed")
        }
        foreach ($import in @($row.imports)) {
            if ($import -isnot [string] -or
                [string]::IsNullOrWhiteSpace($import)) {
                Throw-ValidationError $script:ExitRuntime "classification" (
                    "static report classification import is malformed")
            }
        }
    }
    if ([long]$object.summary.payloadMembers -lt $classifications.Count) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report payload member count is smaller than classifications")
    }
    $peCount = @($classifications |
        Where-Object {
            -not (Test-OrdinalStringEqual $_.architecture "non-pe")
        }).Count
    if ([long]$object.summary.peFiles -ne $peCount) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "static report PE classification count is inconsistent")
    }
    foreach ($row in @($object.pseudoReloc)) {
        Assert-ExactProperties $row @(
            "path", "result", "tableFormat", "recordCount", "flags",
            "objdumpMember", "objdumpSha256", "nmMember", "nmSha256") `
            "static report pseudoReloc row" $script:ExitRuntime
        Assert-NormalizedPath $row.path "static report pseudoReloc.path" `
            -ExitCode $script:ExitRuntime
        Assert-JsonInteger $row.recordCount `
            "static report pseudoReloc.recordCount" 0 $script:ExitRuntime
        Assert-JsonArray $row.flags "static report pseudoReloc.flags" `
            $script:ExitRuntime
        if ((-not (Test-OrdinalStringEqual ($row.result) ("pass"))) -or
            (-not (Test-OrdinalStringInCollection ($row.tableFormat) (@("empty", "v2")))) -or
            (-not (Test-OrdinalStringEqual ($row.objdumpMember) ($script:ObjdumpMember))) -or
            (-not (Test-OrdinalStringEqual ($row.objdumpSha256) ($script:ObjdumpSha256))) -or
            (-not (Test-OrdinalStringEqual ($row.nmMember) ($script:NmMember))) -or
            (-not (Test-OrdinalStringEqual ($row.nmSha256) ($script:NmSha256))) -or
            ((Test-OrdinalStringEqual ($row.tableFormat) ("empty")) -and
                ([long]$row.recordCount -ne 0 -or
                    @($row.flags).Count -ne 0)) -or
            ((Test-OrdinalStringEqual ($row.tableFormat) ("v2")) -and
                (@($row.flags).Count -ne [long]$row.recordCount -or
                    @($row.flags | Where-Object {
                        ($_ -isnot [int] -and $_ -isnot [long]) -or
                        [long]$_ -ne 64
                    }).
                        Count -ne 0))) {
            Throw-ValidationError $script:ExitRuntime "pseudo-reloc" (
                "static report pseudo-reloc proof is not positive")
        }
    }
    return [ordered]@{
        Sha256 = $document.Sha256
        Mode = $mode
        Classifications = $classifications
    }
}

function Write-ValidationReport {
    param(
        [Parameter(Mandatory = $true)][int] $ExitCode,
        [Parameter(Mandatory = $true)][string] $Result
    )

    $script:ReportData.exitCode = $ExitCode
    $script:ReportData.result = $Result
    if ($null -eq $script:SafeReportPath) {
        [Console]::Error.WriteLine(
            "Validation report destination was not safe to write")
        return $false
    }
    $temporaryPath = $null
    try {
        $parent = [IO.Path]::GetDirectoryName($script:SafeReportPath)
        $json = $script:ReportData | ConvertTo-Json -Depth 100
        $temporaryPath = Join-Path $parent (
            ".arm64-validation-report-" + [Guid]::NewGuid().ToString("N") +
            ".tmp")
        [IO.File]::WriteAllText($temporaryPath, "$json`n", $script:Utf8NoBom)
        [IO.File]::Move($temporaryPath, $script:SafeReportPath, $true)
        return $true
    } catch {
        [Console]::Error.WriteLine(
            "Could not write validation report '$Report': $($_.Exception.Message)")
        return $false
    } finally {
        if ($null -ne $temporaryPath -and
            [IO.File]::Exists($temporaryPath)) {
            try {
                [IO.File]::Delete($temporaryPath)
            } catch {
                [Console]::Error.WriteLine(
                    "Could not remove temporary validation report: " +
                    $_.Exception.Message)
            }
        }
    }
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string] $Parent,
        [Parameter(Mandatory = $true)][string] $Candidate
    )

    $prefix = $Parent.TrimEnd("\") + "\"
    return $script:PathComparer.Equals($Candidate, $Parent.TrimEnd("\")) -or
        $Candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Initialize-SafeReportPath {
    $reportPath = [IO.Path]::GetFullPath($Report)
    if ($Report -match "^(?i)(\\\\|//|\\\\[?.]\\)" -or
        $reportPath -notmatch "^[A-Za-z]:\\") {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report must be a local drive-qualified path")
    }
    if ($reportPath.Substring(3).Contains(":")) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report cannot address an alternate data stream")
    }
    if (Test-PathWithin "C:\msys64" $reportPath) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report cannot be written under C:\msys64")
    }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd("\")
    if (Test-PathWithin $rootFull $reportPath) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report must be outside the staged payload Root")
    }
    if (-not [string]::IsNullOrWhiteSpace($ToolRoot)) {
        $toolFull = [IO.Path]::GetFullPath($ToolRoot).TrimEnd("\")
        if (Test-PathWithin $toolFull $reportPath) {
            Throw-ValidationError $script:ExitScanner "report" (
                "Report must be outside ToolRoot")
        }
    }
    $protectedFiles = @(
        $Lock, $Provenance, $PayloadManifest, $AssemblyEvidence,
        $RuntimeEvidence, $StaticReport, $PSCommandPath,
        (Join-Path (Split-Path -Parent $PSCommandPath) `
            $script:ScannerRelativePath),
        (Join-Path (Split-Path -Parent $PSCommandPath) `
            "arm64-x64-payload-baseline.txt"))
    foreach ($commandName in @("git", "pwsh")) {
        $command = Get-Command $commandName -CommandType Application `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $command) {
            $protectedFiles += $command.Source
        }
    }
    $fsutil = Join-Path $env:SystemRoot "System32\fsutil.exe"
    $protectedFiles += $fsutil
    foreach ($inputPath in $protectedFiles) {
        if (-not [string]::IsNullOrWhiteSpace($inputPath) -and
            $script:PathComparer.Equals(
                $reportPath, [IO.Path]::GetFullPath($inputPath))) {
            Throw-ValidationError $script:ExitScanner "report" (
                "Report cannot overwrite a validator input or dependency")
        }
    }
    # The whole validator checkout is authoritative, not just the entry script,
    # so no report may land anywhere inside it.
    $checkoutRoot = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath($PSCommandPath))
    $gitTop = @(& git -C $checkoutRoot rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -eq 0 -and $gitTop.Count -eq 1) {
        $checkoutRoot = [IO.Path]::GetFullPath($gitTop[0].Trim())
    }
    $protectedDirectories = @($checkoutRoot)
    foreach ($argument in @("--absolute-git-dir", "--git-common-dir")) {
        $gitDirectory = @(& git -C $checkoutRoot rev-parse $argument 2>$null)
        if ($LASTEXITCODE -eq 0 -and $gitDirectory.Count -eq 1) {
            $protectedDirectories += [IO.Path]::GetFullPath(
                $gitDirectory[0].Trim())
        }
    }
    if (@($protectedDirectories | Where-Object {
        -not [string]::IsNullOrEmpty($_) -and
        (Test-PathWithin $_ $reportPath)
    }).Count -ne 0) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report cannot be written inside the validator checkout")
    }
    $parent = [IO.Path]::GetDirectoryName($reportPath)
    if ([string]::IsNullOrEmpty($parent)) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report must have a parent directory")
    }
    [void][IO.Directory]::CreateDirectory($parent)
    $cursor = [IO.DirectoryInfo]::new($parent)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-ValidationError $script:ExitScanner "report" (
                "Report destination has a reparse-point ancestor")
        }
        $cursor = $cursor.Parent
    }
    if ([IO.File]::Exists($reportPath) -and
        (([IO.FileInfo]::new($reportPath).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report destination is a reparse point")
    }
    if ([IO.File]::Exists($reportPath)) {
        foreach ($name in @(Get-HardlinkNames $reportPath `
            "Report destination")) {
            if (@($protectedDirectories | Where-Object {
                Test-PathWithin $_ $name
            }).Count -ne 0 -or
                @($protectedFiles | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_) -and
                        $script:PathComparer.Equals(
                            $name, [IO.Path]::GetFullPath($_))
                }).Count -ne 0 -or
                (Test-PathWithin $rootFull $name) -or
                (-not [string]::IsNullOrWhiteSpace($ToolRoot) -and
                    (Test-PathWithin $toolFull $name))) {
                Throw-ValidationError $script:ExitScanner "report" (
                    "Report destination shares a protected file identity")
            }
        }
    }
    $script:SafeReportPath = $reportPath
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($stream) | ForEach-Object {
            $_.ToString("x2")
        }) -join ""
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string] $Text)

    $bytes = $script:Utf8NoBom.GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($bytes) | ForEach-Object {
            $_.ToString("x2")
        }) -join ""
    } finally {
        $sha.Dispose()
    }
}

function Test-Property {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string] $Name
    )

    return $null -ne $Object.PSObject.Properties[$Name]
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if (-not (Test-Property $Object $Name)) {
        Throw-ValidationError $ExitCode "schema" "$Context is missing '$Name'"
    }
    return $Object.$Name
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string[]] $Names,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    $actual = @($Object.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count -or
        @($Names | Where-Object {
            -not (Test-OrdinalStringInCollection $_ $actual)
        }).Count -ne 0) {
        Throw-ValidationError $ExitCode "schema" (
            "$Context properties must be exactly: $($Names -join ', ')")
    }
}

# Culture-sensitive string equality collapses 322 characters, only 43 of which
# are category Format, so screen them by asking the invariant collator itself
# whether a character compares equal to nothing. Applied at the single point
# where JSON enters the validator; security-significant comparisons also use
# ordinal equality.
function Assert-ComparisonSafeString {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [Parameter(Mandatory = $true)][int] $ExitCode
    )

    foreach ($character in $Value.ToCharArray()) {
        if ([int]$character -ge 0x20 -and [int]$character -le 0x7E) {
            continue
        }
        if ($script:InvariantCompareInfo.Compare(
                [string]$character,
                "",
                [Globalization.CompareOptions]::None) -eq 0) {
            Throw-ValidationError $ExitCode "schema" (
                ("$Context contains collation-ignorable character " +
                 ("U+{0:X4}" -f [int]$character)))
        }
    }
}

function Assert-JsonPropertyNames {
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory = $true)][string] $Context,
        [Parameter(Mandatory = $true)][int] $ExitCode
    )

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            Assert-ComparisonSafeString $property.Name `
                "$Context property name" $ExitCode
            if (-not $names.Add($property.Name)) {
                Throw-ValidationError $ExitCode "schema" (
                    "$Context contains a duplicate or case-colliding JSON " +
                    "property '$($property.Name)'")
            }
            Assert-JsonPropertyNames $property.Value `
                "$Context.$($property.Name)" $ExitCode
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-JsonPropertyNames $item "$Context[$index]" $ExitCode
            $index++
        }
    } elseif ($Element.ValueKind -eq
        [System.Text.Json.JsonValueKind]::String) {
        Assert-ComparisonSafeString $Element.GetString() $Context $ExitCode
    }
}

function Read-JsonDocument {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Name,
        [int] $ExitCode = $script:ExitContract
    )

    try {
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        $bytes = [IO.File]::ReadAllBytes($resolved)
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $json = [System.Text.Json.JsonDocument]::Parse($text)
        try {
            Assert-JsonPropertyNames $json.RootElement $Name $ExitCode
        } finally {
            $json.Dispose()
        }
        $object = $text | ConvertFrom-Json -Depth 100 -DateKind String
        return [ordered]@{
            Path = $resolved
            Sha256 = Get-FileSha256 $resolved
            Bytes = $bytes
            Text = $text
            Object = $object
        }
    } catch {
        if ($_.Exception.Data.Contains("ExitCode")) {
            throw
        }
        Throw-ValidationError $ExitCode "schema" (
            "Could not read $Name '$Path': $($_.Exception.Message)")
    }
}

function Assert-SchemaVersion {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ((Get-RequiredProperty $Object "schemaVersion" $Context $ExitCode) -ne 1) {
        Throw-ValidationError $ExitCode "schema" (
            "$Context schemaVersion must be 1")
    }
}

function Assert-LowerSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ($Value -isnot [string] -or
        $Value -cnotmatch "^[0-9a-f]{64}$") {
        Throw-ValidationError $ExitCode "schema" (
            "$Context must be a lowercase SHA-256")
    }
}

function Assert-LowerCommit {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ($Value -isnot [string] -or
        $Value -cnotmatch "^[0-9a-f]{40}$") {
        Throw-ValidationError $ExitCode "schema" (
            "$Context must be a full lowercase commit ID")
    }
}

function Assert-JsonArray {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ($Value -isnot [Array]) {
        Throw-ValidationError $ExitCode "schema" "$Context must be an array"
    }
}

function Assert-JsonInteger {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [long] $Minimum = [long]::MinValue,
        [int] $ExitCode = $script:ExitContract
    )

    if (($Value -isnot [int] -and $Value -isnot [long]) -or
        [long]$Value -lt $Minimum) {
        Throw-ValidationError $ExitCode "schema" (
            "$Context must be an integer greater than or equal to $Minimum")
    }
}

function Assert-UtcTimestamp {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    [DateTimeOffset] $parsed = [DateTimeOffset]::MinValue
    if ($Value -isnot [string] -or
        $Value -cnotmatch "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$" -or
        -not [DateTimeOffset]::TryParse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref] $parsed)) {
        Throw-ValidationError $ExitCode "schema" (
            "$Context must be an ISO 8601 UTC timestamp")
    }
}

function Assert-NoPlaceholder {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Context
    )

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
        $Value -match "(?i)(placeholder|example|todo|tbd|unresolved|changeme)" -or
        $Value -match "^0+$") {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context contains an empty or placeholder value")
    }
}

function Assert-NormalizedPath {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Context,
        [switch] $AllowDot,
        [switch] $AllowWildcards,
        [int] $ExitCode = $script:ExitContract
    )

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
        Throw-ValidationError $ExitCode "path" "$Context must be a path"
    }
    if ($AllowDot -and (Test-OrdinalStringEqual ($Value) ("."))) {
        return
    }
    if ((-not (Test-OrdinalStringEqual ($Value) ($Value.Normalize([Text.NormalizationForm]::FormC)))) -or
        $Value.Contains("\") -or $Value.StartsWith("/") -or
        $Value.StartsWith("//") -or $Value -match "^[A-Za-z]:" -or
        $Value -match "^(?i)(\\\\[?.]\\|//[?.]/)" -or
        $Value.Contains(":") -or $Value.Contains("`0") -or
        $Value.EndsWith("/") -or $Value.Contains("//")) {
        Throw-ValidationError $ExitCode "path" (
            "$Context is not a normalized relative slash path: '$Value'")
    }
    foreach ($component in $Value.Split("/")) {
        if (Test-OrdinalStringInCollection $component @("", ".", "..")) {
            Throw-ValidationError $ExitCode "path" (
                "$Context contains traversal or an empty component: '$Value'")
        }
        if (-not $AllowWildcards -and $component.IndexOfAny(@("*", "?")) -ge 0) {
            Throw-ValidationError $ExitCode "path" (
                "$Context contains wildcard characters: '$Value'")
        }
        # Win32 strips trailing dots and spaces from the final component, so
        # such a name would be enumerated verbatim but opened as a different
        # file.
        if ($component.EndsWith(".") -or
            [char]::IsWhiteSpace($component[$component.Length - 1])) {
            Throw-ValidationError $ExitCode "path" (
                "$Context has a component ending in a dot or space: '$Value'")
        }
    }
    if ($script:PathComparer.Equals($Value, "preview-evidence") -or
        $Value.StartsWith(
            "preview-evidence/",
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-ValidationError $ExitCode "path" (
            "$Context cannot use the excluded preview-evidence prefix")
    }
}

function Assert-SortedUnique {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Items,
        [Parameter(Mandatory = $true)][scriptblock] $Selector,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    $seen = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $previous = $null
    foreach ($item in $Items) {
        $value = [string](& $Selector $item)
        if (-not $seen.Add($value)) {
            Throw-ValidationError $ExitCode "collision" (
                "$Context contains a duplicate or case collision: '$value'")
        }
        if ($null -ne $previous -and
            [StringComparer]::Ordinal.Compare($previous, $value) -ge 0) {
            Throw-ValidationError $ExitCode "ordering" (
                "$Context must be ordinally sorted: '$previous', '$value'")
        }
        $previous = $value
    }
}

function Sort-OrdinalBy {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Items,
        [Parameter(Mandatory = $true)][scriptblock] $Selector
    )

    $result = @($Items)
    for ($index = 1; $index -lt $result.Count; $index++) {
        $value = $result[$index]
        $valueKey = [string](& $Selector $value)
        $position = $index - 1
        while ($position -ge 0 -and
            [StringComparer]::Ordinal.Compare(
                [string](& $Selector $result[$position]),
                $valueKey) -gt 0) {
            $result[$position + 1] = $result[$position]
            $position--
        }
        $result[$position + 1] = $value
    }
    return $result
}

function Assert-LocalSafeRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ($Path -match "^(?i)(\\\\|//)" -or
        $Path -match "^(?i)\\\\[?.]\\") {
        Throw-ValidationError $ExitCode "path" (
            "$Context cannot be a UNC or device path")
    }
    # Root arrives on the command line rather than through the JSON
    # chokepoint, but it is joined into expected command vectors, so it must
    # be screened for collation-ignorable characters too.
    Assert-ComparisonSafeString $Path $Context $ExitCode
    try {
        $full = [IO.Path]::GetFullPath($Path).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
    } catch {
        Throw-ValidationError $ExitCode "path" (
            "$Context is not a valid local path: $($_.Exception.Message)")
    }
    if ($full -notmatch "^[A-Za-z]:\\") {
        Throw-ValidationError $ExitCode "path" (
            "$Context must be a drive-qualified local Windows path")
    }
    if ($script:PathComparer.Equals($full, "C:\msys64") -or
        $full.StartsWith(
            "C:\msys64\",
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-ValidationError $ExitCode "path" (
            "$Context cannot be C:\msys64 or a descendant")
    }
    if (-not [IO.Directory]::Exists($full)) {
        Throw-ValidationError $ExitCode "path" (
            "$Context does not exist or is not a directory: '$full'")
    }

    $cursor = [IO.DirectoryInfo]::new($full)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-ValidationError $ExitCode "reparse" (
                "$Context has a reparse-point ancestor: '$($cursor.FullName)'")
        }
        $cursor = $cursor.Parent
    }
    return $full
}

function Test-PatternMatch {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $Patterns
    )

    foreach ($pattern in $Patterns) {
        # WildcardPattern's CultureInvariant option selects a culture; it does
        # not make matching ordinal. A pattern with no wildcard short-circuits
        # to a linguistic comparison, which would collapse collation-ignorable
        # characters and let an include list admit a member it never names.
        if (-not [Management.Automation.WildcardPattern]::
                ContainsWildcardCharacters($pattern)) {
            if ([string]::Equals(
                    $Path, $pattern, [StringComparison]::Ordinal)) {
                return $true
            }
            continue
        }
        $expression = "^"
        foreach ($piece in $pattern.ToCharArray()) {
            $expression += switch ($piece) {
                "*" { "[\s\S]*" }
                "?" { "[\s\S]" }
                default { [regex]::Escape([string]$piece) }
            }
        }
        $expression += "$"
        if ([regex]::IsMatch(
                $Path,
                $expression,
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            return $true
        }
    }
    return $false
}

function Assert-AllowlistedRepository {
    param(
        [Parameter(Mandatory = $true)] $Repository,
        [Parameter(Mandatory = $true)][string] $Context
    )

    Assert-NoPlaceholder $Repository $Context
    if ($Repository -cnotmatch "^crutkas/[A-Za-z0-9_.-]+$" -and
        (-not (Test-OrdinalStringEqual ($Repository) ("git-for-windows/git"))) -and
        (-not (Test-OrdinalStringEqual ($Repository) ("ip7z/7zip")))) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context is not on the immutable input allowlist")
    }
}

function Get-AuthoritativeCheckout {
    param([int] $ExitCode = $script:ExitContract)

    if ($null -ne $script:AuthoritativeCheckout) {
        return $script:AuthoritativeCheckout
    }
    $start = Split-Path -Parent $PSCommandPath
    $root = @(& git -C $start rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or $root.Count -ne 1) {
        Throw-ValidationError $ExitCode "validator" (
            "could not identify the authoritative build-extra checkout")
    }
    $repositoryRoot = [IO.Path]::GetFullPath($root[0].Trim())
    $branch = @(& git -C $repositoryRoot symbolic-ref --quiet --short HEAD `
        2>$null)
    if ($LASTEXITCODE -ne 0 -or $branch.Count -ne 1 -or
        $branch[0].Trim() -cnotmatch "^crutkas(?:[-/].+)?$") {
        Throw-ValidationError $ExitCode "validator" (
            "validator checkout must use an attached crutkas branch")
    }
    $branchName = $branch[0].Trim()
    $originUrl = @(& git -C $repositoryRoot remote get-url origin 2>$null)
    if ($LASTEXITCODE -ne 0 -or $originUrl.Count -ne 1 -or
        $originUrl[0].Trim() -cnotmatch
            "^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)crutkas/build-extra(?:\.git)?$") {
        Throw-ValidationError $ExitCode "validator" (
            "validator checkout origin must be crutkas/build-extra")
    }
    $head = @(& git -C $repositoryRoot rev-parse --verify "HEAD^{commit}" `
        2>$null)
    $remoteRef = "refs/remotes/origin/$branchName"
    $remote = @(& git -C $repositoryRoot show-ref --verify --hash `
        $remoteRef 2>$null)
    if ($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or
        $remote.Count -ne 1) {
        Throw-ValidationError $ExitCode "validator" (
            "validator checkout lacks its matching origin/crutkas ref")
    }
    & git -C $repositoryRoot merge-base --is-ancestor `
        $head[0].Trim() $remoteRef 2>$null
    if ($LASTEXITCODE -ne 0) {
        Throw-ValidationError $ExitCode "validator" (
            "validator checkout HEAD is not reachable from its matching origin/crutkas ref")
    }
    $script:AuthoritativeCheckout = [ordered]@{
        Root = $repositoryRoot
        Branch = $branchName
        Head = $head[0].Trim()
        RemoteRef = $remoteRef
    }
    return $script:AuthoritativeCheckout
}

function Assert-AuthoritativeBuildCommit {
    param(
        [Parameter(Mandatory = $true)][string] $Commit,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    $checkout = Get-AuthoritativeCheckout $ExitCode
    & git -C $checkout.Root cat-file -e "$Commit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Throw-ValidationError $ExitCode "provenance" (
            "$Context does not resolve to a local commit object")
    }
    & git -C $checkout.Root merge-base --is-ancestor `
        $Commit $checkout.RemoteRef 2>$null
    if ($LASTEXITCODE -ne 0) {
        Throw-ValidationError $ExitCode "provenance" (
            "$Context is not reachable from the checked-out authoritative origin/crutkas ref")
    }
}

# A base bundle can be a tree this repository derives rather than an official
# release asset. It is made immutable by an exact pre-overlay manifest whose
# bytes the canonical lock binds, so no release/asset/package may be invented.
function Read-BaseTreeManifest {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)][string] $Context
    )

    $manifestPath = Join-Path $RootPath ($Manifest.path.Replace("/", "\"))
    if (-not [IO.File]::Exists($manifestPath) -or
        (([IO.FileInfo]::new($manifestPath).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Throw-ValidationError $script:ExitContract "digest" (
            "$Context base tree manifest is missing")
    }
    $document = Read-JsonDocument $manifestPath "base tree manifest"
    if ((-not (Test-OrdinalStringEqual ($document.Sha256) ($Manifest.sha256)))) {
        Throw-ValidationError $script:ExitContract "digest" (
            "$Context base tree manifest does not match its exact file bytes")
    }
    if ($document.Bytes.Length -lt 2 -or $document.Bytes[0] -eq 0xef -or
        $document.Text.Contains("`r") -or
        -not $document.Text.EndsWith("`n", [StringComparison]::Ordinal)) {
        Throw-ValidationError $script:ExitContract "serialization" (
            "base tree manifest must be UTF-8 without BOM, LF-only, with a final LF")
    }
    $object = $document.Object
    Assert-ExactProperties $object @("schemaVersion", "entries") `
        "base tree manifest"
    Assert-PropertyOrder $object @("schemaVersion", "entries") `
        "base tree manifest"
    Assert-SchemaVersion $object "base tree manifest"
    Assert-JsonArray $object.entries "base tree manifest.entries"
    $entries = @($object.entries)
    if ($entries.Count -eq 0) {
        Throw-ValidationError $script:ExitContract "archive" (
            "base tree manifest cannot be empty")
    }
    Assert-SortedUnique $entries { param($item) [string]$item.path } `
        "base tree manifest entries"
    foreach ($entry in $entries) {
        Assert-ExactProperties $entry @(
            "path", "type", "bytes", "sha256", "linkTarget") `
            "base tree manifest entry"
        Assert-NormalizedPath $entry.path "base tree manifest entry path"
        if ((-not (Test-OrdinalStringInCollection ($entry.type) (@(
            "file", "directory", "symlink", "hardlink"))))) {
            Throw-ValidationError $script:ExitContract "archive" (
                "base tree manifest entry '$($entry.path)' has an invalid type")
        }
        Assert-JsonInteger $entry.bytes `
            "base tree manifest entry '$($entry.path)'.bytes" 0
        if ((Test-OrdinalStringEqual ($entry.type) ("directory"))) {
            if ([long]$entry.bytes -ne 0 -or $null -ne $entry.sha256 -or
                $null -ne $entry.linkTarget) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "base tree manifest directory '$($entry.path)' must have bytes=0, sha256=null, linkTarget=null")
            }
        } else {
            Assert-LowerSha256 $entry.sha256 `
                "base tree manifest entry '$($entry.path)'.sha256"
            if ((Test-OrdinalStringEqual ($entry.type) ("file"))) {
                if ($null -ne $entry.linkTarget) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "base tree manifest file '$($entry.path)' must have linkTarget=null")
                }
            } else {
                Assert-NormalizedPath $entry.linkTarget `
                    "base tree manifest entry '$($entry.path)'.linkTarget"
            }
        }
    }
    return [ordered]@{
        Path = $Manifest.path
        Sha256 = $document.Sha256
        Entries = $entries
    }
}

function Assert-DerivedTreeIdentity {
    param(
        [Parameter(Mandatory = $true)] $Resolution,
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $Context
    )

    Assert-ExactProperties $Resolution @(
        "method", "build", "sdkSource", "manifest") "$Context.resolution"
    Assert-PropertyOrder $Resolution @(
        "method", "build", "sdkSource", "manifest") "$Context.resolution"
    Assert-ExactProperties $Resolution.build @("repository", "commit") `
        "$Context.resolution.build"
    if ((-not (Test-OrdinalStringEqual ($Resolution.build.repository) ("crutkas/build-extra")))) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.resolution.build.repository must be crutkas/build-extra")
    }
    Assert-LowerCommit $Resolution.build.commit `
        "$Context.resolution.build.commit"
    Assert-AuthoritativeBuildCommit $Resolution.build.commit `
        "$Context.resolution.build.commit"
    if ($null -ne $Resolution.sdkSource) {
        Assert-ExactProperties $Resolution.sdkSource @(
            "repository", "commit") "$Context.resolution.sdkSource"
        Assert-AllowlistedRepository $Resolution.sdkSource.repository `
            "$Context.resolution.sdkSource.repository"
        Assert-LowerCommit $Resolution.sdkSource.commit `
            "$Context.resolution.sdkSource.commit"
    }
    Assert-ExactProperties $Resolution.manifest @("path", "sha256") `
        "$Context.resolution.manifest"
    Assert-EvidenceRelativePath $Resolution.manifest.path `
        "$Context.resolution.manifest.path"
    if ((-not (Test-OrdinalStringEqual ($Resolution.manifest.path) ("preview-evidence/base-tree-manifest.v1.json")))) {
        Throw-ValidationError $script:ExitContract "path" (
            "$Context.resolution.manifest.path must be preview-evidence/base-tree-manifest.v1.json")
    }
    Assert-LowerSha256 $Resolution.manifest.sha256 `
        "$Context.resolution.manifest.sha256"
    return Read-BaseTreeManifest $RootPath $Resolution.manifest $Context
}

function Assert-ForkIdentity {
    param(
        [Parameter(Mandatory = $true)] $Resolution,
        [Parameter(Mandatory = $true)] $Release,
        [Parameter(Mandatory = $true)] $Asset,
        [Parameter(Mandatory = $true)][string] $Context
    )

    Assert-ExactProperties $Asset @("url", "name", "bytes", "sha256") `
        "$Context.asset"
    Assert-NoPlaceholder $Release.repository "$Context.release.repository"
    if ($Release.repository -cnotmatch "^crutkas/[A-Za-z0-9_.-]+$" -and
        (-not (Test-OrdinalStringEqual ($Release.repository) ("git-for-windows/git"))) -and
        (-not (Test-OrdinalStringEqual ($Release.repository) ("ip7z/7zip")))) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.release.repository is not on the immutable input allowlist")
    }
    Assert-LowerCommit $Release.targetCommit "$Context.release.targetCommit"
    Assert-NoPlaceholder $Asset.name "$Context.asset.name"
    Assert-LowerSha256 $Asset.sha256 "$Context.asset.sha256"
    if ($Asset.bytes -isnot [long] -and $Asset.bytes -isnot [int]) {
        Throw-ValidationError $script:ExitContract "schema" (
            "$Context.asset.bytes must be an integer")
    }
    if ([long]$Asset.bytes -le 0) {
        Throw-ValidationError $script:ExitContract "schema" (
            "$Context.asset.bytes must be positive")
    }
    [Uri] $uri = $null
    if ($Asset.url -isnot [string] -or
        -not [Uri]::TryCreate($Asset.url, [UriKind]::Absolute, [ref]$uri) -or
        (-not (Test-OrdinalStringEqual ($uri.Scheme) ("https")))) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.asset.url must be an immutable HTTPS URL")
    }
    if (-not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.asset.url cannot contain a query or fragment")
    }
    if ((Test-OrdinalStringEqual ($Resolution.method) ("github-release"))) {
        Assert-ExactProperties $Release @(
            "repository", "tag", "targetCommit") "$Context.release"
        Assert-NoPlaceholder $Release.tag "$Context.release.tag"
        $expectedPath = (
            "/$($Release.repository)/releases/download/" +
            "$($Release.tag)/$($Asset.name)")
        if ((-not (Test-OrdinalStringEqual ($uri.Host) ("github.com"))) -or
            (-not (Test-OrdinalStringEqual ([Uri]::UnescapeDataString($uri.AbsolutePath)) ($expectedPath)))) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "$Context.asset.url does not bind its repository, tag, and asset name")
        }
    } elseif ((Test-OrdinalStringEqual ($Resolution.method) ("github-raw-commit"))) {
        Assert-ExactProperties $Release @(
            "repository", "targetCommit", "sourcePath") "$Context.release"
        Assert-NormalizedPath $Release.sourcePath "$Context.release.sourcePath"
        $expectedPath = (
            "/$($Release.repository)/$($Release.targetCommit)/" +
            "$($Release.sourcePath)")
        if ((-not (Test-OrdinalStringEqual ($uri.Host) ("raw.githubusercontent.com"))) -or
            (-not (Test-OrdinalStringEqual ([Uri]::UnescapeDataString($uri.AbsolutePath)) ($expectedPath)))) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "$Context.asset.url does not bind its repository, commit, and sourcePath")
        }
        if ((Test-OrdinalStringEqual ($Release.repository) ("crutkas/build-extra"))) {
            Assert-AuthoritativeBuildCommit $Release.targetCommit `
                "$Context.release.targetCommit"
        }
    } else {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context uses an unsupported resolution method")
    }
}

function Test-IdentityEqual {
    param($Left, $Right)

    if ($null -eq $Left.asset -or $null -eq $Right.asset) {
        return (
            $null -eq $Left.asset -and $null -eq $Right.asset -and
            (Test-OrdinalStringEqual (($Left.release | ConvertTo-Json -Compress -Depth 20)) (($Right.release | ConvertTo-Json -Compress -Depth 20))) -and
            (Test-OrdinalStringEqual (($Left.package | ConvertTo-Json -Compress -Depth 20)) (($Right.package | ConvertTo-Json -Compress -Depth 20))))
    }
    return (
        (Test-OrdinalStringEqual (($Left.release | ConvertTo-Json -Compress -Depth 20)) (($Right.release | ConvertTo-Json -Compress -Depth 20))) -and
        (Test-OrdinalStringEqual ($Left.asset.url) ($Right.asset.url)) -and
        (Test-OrdinalStringEqual ($Left.asset.name) ($Right.asset.name)) -and
        [long]$Left.asset.bytes -eq [long]$Right.asset.bytes -and
        (Test-OrdinalStringEqual ($Left.asset.sha256) ($Right.asset.sha256)) -and
        (Test-OrdinalStringEqual (($Left.package | ConvertTo-Json -Compress -Depth 20)) (($Right.package | ConvertTo-Json -Compress -Depth 20))))
}

function Read-LockContract {
    param(
        [Parameter(Mandatory = $true)] $LockObject,
        [Parameter(Mandatory = $true)] $LockDocument,
        [Parameter(Mandatory = $true)][string] $RootPath
    )

    Assert-ExactProperties $LockObject @(
        "schemaVersion", "sourceLock", "sourceDateEpoch",
        "nativeShellClosure", "inputs") "lock"
    Assert-PropertyOrder $LockObject @(
        "schemaVersion", "sourceLock", "sourceDateEpoch",
        "nativeShellClosure", "inputs") "lock"
    Assert-SchemaVersion $LockObject "lock"
    if ($LockDocument.Bytes.Length -lt 2 -or
        $LockDocument.Bytes[0] -eq 0xef -or
        $LockDocument.Text.Contains("`r") -or
        -not $LockDocument.Text.EndsWith("`n", [StringComparison]::Ordinal)) {
        Throw-ValidationError $script:ExitContract "serialization" (
            "bundle lock must be UTF-8 without BOM, LF-only, with a final LF")
    }
    $expectedLockPath = Join-Path $RootPath `
        "preview-evidence\bundle-lock.v1.json"
    if (-not $script:PathComparer.Equals(
            $LockDocument.Path, $expectedLockPath)) {
        Throw-ValidationError $script:ExitContract "path" (
            "canonical bundle lock must be preview-evidence/bundle-lock.v1.json")
    }
    Assert-ExactProperties $LockObject.sourceLock @("path", "sha256") `
        "lock.sourceLock"
    Assert-PropertyOrder $LockObject.sourceLock @("path", "sha256") `
        "lock.sourceLock"
    Assert-EvidenceRelativePath $LockObject.sourceLock.path `
        "lock.sourceLock.path"
    if ((-not (Test-OrdinalStringEqual ($LockObject.sourceLock.path) ("preview-evidence/source-lock.json")))) {
        Throw-ValidationError $script:ExitContract "path" (
            "lock.sourceLock.path must be preview-evidence/source-lock.json")
    }
    Assert-LowerSha256 $LockObject.sourceLock.sha256 `
        "lock.sourceLock.sha256"
    $sourceLockPath = Join-Path $RootPath (
        $LockObject.sourceLock.path.Replace("/", "\"))
    if (-not [IO.File]::Exists($sourceLockPath) -or
        (([IO.FileInfo]::new($sourceLockPath).Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        (-not (Test-OrdinalStringEqual ((Get-FileSha256 $sourceLockPath)) ($LockObject.sourceLock.sha256)))) {
        Throw-ValidationError $script:ExitContract "digest" (
            "canonical bundle lock sourceLock does not match its exact file bytes")
    }
    Assert-JsonInteger $LockObject.sourceDateEpoch `
        "lock.sourceDateEpoch" 0
    Assert-JsonArray $LockObject.nativeShellClosure `
        "lock.nativeShellClosure"
    $closure = @($LockObject.nativeShellClosure)
    if ($closure.Count -eq 0) {
        Throw-ValidationError $script:ExitContract "schema" (
            "lock.nativeShellClosure cannot be empty")
    }
    $closureSet = [Collections.Generic.HashSet[string]]::new(
        $script:PathComparer)
    foreach ($path in $closure) {
        Assert-NormalizedPath $path "lock.nativeShellClosure path"
        if (-not $closureSet.Add($path)) {
            Throw-ValidationError $script:ExitContract "collision" (
                "lock.nativeShellClosure has a duplicate or case collision: '$path'")
        }
    }
    Assert-JsonArray $LockObject.inputs "lock.inputs"
    $inputs = @($LockObject.inputs)
    if ($inputs.Count -eq 0) {
        Throw-ValidationError $script:ExitContract "schema" (
            "lock.inputs cannot be empty")
    }
    $ids = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $urls = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $names = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $hashes = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $inputMap = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    $baseTrees = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal)
    $resolved = @()
    $unresolved = @()
    Assert-SortedUnique $inputs { param($item) [string]$item.id } `
        "lock.inputs"

    foreach ($input in $inputs) {
        Assert-ExactProperties $input @(
            "id", "role", "status", "resolution", "release", "asset",
            "package", "overlay") "lock input"
        Assert-PropertyOrder $input @(
            "id", "role", "status", "resolution", "release", "asset",
            "package", "overlay") "lock input"
        Assert-NoPlaceholder $input.id "lock input id"
        if ($input.id -cnotmatch "^[a-z0-9][a-z0-9.-]*$" -or
            -not $ids.Add($input.id)) {
            Throw-ValidationError $script:ExitContract "collision" (
                "lock input id is invalid, duplicate, or case-colliding: '$($input.id)'")
        }
        if ((-not (Test-OrdinalStringInCollection ($input.role) (@(
            "base-bundle", "payload", "validation-tool"))))) {
            Throw-ValidationError $script:ExitContract "schema" (
                "lock input '$($input.id)' has invalid role '$($input.role)'")
        }
        if ((Test-OrdinalStringEqual ($input.status) ("unresolved"))) {
            foreach ($field in @(
                "resolution", "release", "asset", "package", "overlay")) {
                if ($null -ne $input.$field) {
                    Throw-ValidationError $script:ExitContract "provenance" (
                        "unresolved input '$($input.id)' must set $field to null")
                }
            }
            $unresolved += $input.id
            $inputMap[$input.id] = $input
            continue
        }
        if ((-not (Test-OrdinalStringEqual ($input.status) ("resolved")))) {
            Throw-ValidationError $script:ExitContract "schema" (
                "lock input '$($input.id)' status must be resolved or unresolved")
        }
        foreach ($field in @("resolution", "overlay")) {
            if ($null -eq $input.$field) {
                Throw-ValidationError $script:ExitContract "provenance" (
                    "resolved input '$($input.id)' must define $field")
            }
        }
        if ((Test-OrdinalStringEqual ($input.resolution.method) ("derived-tree"))) {
            if ((-not (Test-OrdinalStringEqual ($input.role) ("base-bundle")))) {
                Throw-ValidationError $script:ExitContract "provenance" (
                    "resolved input '$($input.id)' may only derive a tree for a base-bundle role")
            }
            foreach ($field in @("release", "asset", "package")) {
                if ($null -ne $input.$field) {
                    Throw-ValidationError $script:ExitContract "provenance" (
                        "derived-tree input '$($input.id)' must set $field to null")
                }
            }
            $baseTrees[$input.id] = Assert-DerivedTreeIdentity `
                $input.resolution $RootPath "lock input '$($input.id)'"
        } else {
            foreach ($field in @("release", "asset")) {
                if ($null -eq $input.$field) {
                    Throw-ValidationError $script:ExitContract "provenance" (
                        "resolved input '$($input.id)' must define $field")
                }
            }
            Assert-ExactProperties $input.resolution @("method") `
                "lock input '$($input.id)'.resolution"
            if ((-not (Test-OrdinalStringInCollection ($input.resolution.method) (@(
                "github-release", "github-raw-commit"))))) {
                Throw-ValidationError $script:ExitContract "provenance" (
                    "resolved input '$($input.id)' has an unsupported resolution")
            }
            Assert-ForkIdentity $input.resolution $input.release $input.asset `
                "lock input '$($input.id)'"
            foreach ($set in @(
                @($urls, $input.asset.url, "URL"),
                @($names, $input.asset.name, "asset name"),
                @($hashes, $input.asset.sha256, "asset hash"))) {
                if (-not $set[0].Add([string]$set[1])) {
                    Throw-ValidationError $script:ExitContract "collision" (
                        "lock contains a duplicate or case-colliding $($set[2]): '$($set[1])'")
                }
            }
        }

        if ($null -ne $input.package) {
            Assert-ExactProperties $input.package @(
                "name", "version", "personality", "provides") `
                "lock input '$($input.id)'.package"
            Assert-NoPlaceholder $input.package.name `
                "lock input '$($input.id)'.package.name"
            Assert-NoPlaceholder $input.package.version `
                "lock input '$($input.id)'.package.version"
            if ((-not (Test-OrdinalStringInCollection ($input.package.personality) (@(
                "msys", "mingw", "managed", "mixed", "tool"))))) {
                Throw-ValidationError $script:ExitContract "schema" (
                    "lock input '$($input.id)' has invalid package personality")
            }
            $provides = @($input.package.provides)
            Assert-JsonArray $input.package.provides `
                "lock input '$($input.id)'.package.provides"
            if ($provides.Count -eq 0) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "lock input '$($input.id)' must declare expected provides")
            }
            Assert-SortedUnique $provides { param($item) [string]$item } `
                "lock input '$($input.id)'.package.provides"
            foreach ($provide in $provides) {
                Assert-NormalizedPath $provide `
                    "lock input '$($input.id)' expected provide"
            }
        }

        Assert-ExactProperties $input.overlay @(
            "enabled", "destination", "include", "exclude", "mappings") `
            "lock input '$($input.id)'.overlay"
        if ($input.overlay.enabled -isnot [bool]) {
            Throw-ValidationError $script:ExitContract "schema" (
                "lock input '$($input.id)'.overlay.enabled must be boolean")
        }
        $include = @($input.overlay.include)
        $exclude = @($input.overlay.exclude)
        $mappings = @($input.overlay.mappings)
        Assert-JsonArray $input.overlay.include `
            "lock input '$($input.id)'.overlay.include"
        Assert-JsonArray $input.overlay.exclude `
            "lock input '$($input.id)'.overlay.exclude"
        Assert-JsonArray $input.overlay.mappings `
            "lock input '$($input.id)'.overlay.mappings"
        if ((Test-OrdinalStringEqual ($input.role) ("validation-tool"))) {
            if ($input.overlay.enabled -or $null -ne $input.overlay.destination -or
                $include.Count -ne 0 -or $exclude.Count -ne 0 -or
                $mappings.Count -ne 0) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "validation-tool input '$($input.id)' must remain outside payload")
            }
        } else {
            if (-not $input.overlay.enabled -or
                $null -eq $input.overlay.destination -or
                $include.Count -eq 0) {
                Throw-ValidationError $script:ExitContract "overlay" (
                    "payload input '$($input.id)' must enable a destination and include set")
            }
            Assert-NormalizedPath $input.overlay.destination `
                "lock input '$($input.id)'.overlay.destination" -AllowDot
            if ((Test-OrdinalStringEqual ($input.resolution.method) ("derived-tree"))) {
                if ((-not (Test-OrdinalStringEqual ($input.overlay.destination) (".")))) {
                    Throw-ValidationError $script:ExitContract "overlay" (
                        "derived-tree input '$($input.id)' must overlay the destination root")
                }
                foreach ($mapping in $mappings) {
                    if ((-not (Test-OrdinalStringEqual ($mapping.sourceMember) ($mapping.destinationPath)))) {
                        Throw-ValidationError $script:ExitContract "overlay" (
                            "derived-tree input '$($input.id)' must use identity mappings")
                    }
                }
            }
            foreach ($list in @(
                @($include, "include"),
                @($exclude, "exclude"))) {
                Assert-SortedUnique @($list[0]) { param($item) [string]$item } `
                    "lock input '$($input.id)'.overlay.$($list[1])"
                foreach ($pattern in @($list[0])) {
                    Assert-NormalizedPath $pattern `
                        "lock input '$($input.id)'.overlay.$($list[1])" `
                        -AllowWildcards
                }
                Assert-SortedUnique $mappings {
                    param($item) [string]$item.sourceMember
                } "lock input '$($input.id)'.overlay.mappings"
                $mappingDestinations =
                    [Collections.Generic.HashSet[string]]::new($script:PathComparer)
                foreach ($mapping in $mappings) {
                    Assert-ExactProperties $mapping @(
                        "sourceMember", "destinationPath") `
                        "lock input '$($input.id)' overlay mapping"
                    Assert-NormalizedPath $mapping.sourceMember `
                        "overlay mapping sourceMember"
                    Assert-NormalizedPath $mapping.destinationPath `
                        "overlay mapping destinationPath"
                    $destination = $input.overlay.destination
                    if ((-not (Test-OrdinalStringEqual ($destination) ("."))) -and
                        (-not (Test-OrdinalStringEqual ($mapping.destinationPath) ($destination))) -and
                        -not $mapping.destinationPath.StartsWith(
                            "$destination/",
                            [StringComparison]::Ordinal)) {
                        Throw-ValidationError $script:ExitContract "overlay" (
                            "overlay mapping destination escapes overlay.destination")
                    }
                    if (-not $mappingDestinations.Add($mapping.destinationPath)) {
                        Throw-ValidationError $script:ExitContract "collision" (
                            "overlay mappings contain a destination collision")
                    }
                }
            }
        }
        $resolved += $input
        $inputMap[$input.id] = $input
    }
    $script:ReportData.summary.resolvedInputs = $resolved.Count
    $script:ReportData.summary.unresolvedInputs = $unresolved.Count
    $script:ReportData.unresolvedInputs = @($unresolved)
    return [ordered]@{
        Inputs = $inputs
        InputMap = $inputMap
        BaseTrees = $baseTrees
        Resolved = $resolved
        Unresolved = $unresolved
        SourceDateEpoch = [long]$LockObject.sourceDateEpoch
        NativeShellClosure = $closure
        SourceLock = $LockObject.sourceLock
    }
}

function Assert-ExternalObservation {
    param(
        [Parameter(Mandatory = $true)] $Observation,
        [int] $ExitCode = $script:ExitRuntime
    )

    Assert-ExactProperties $Observation @(
        "rootPath", "authoritative", "usedAsInput", "cutoffUtc", "before",
        "after", "commands") "assembly evidence.externalObservation" $ExitCode
    if ($Observation.authoritative -ne $false -or
        $Observation.usedAsInput -ne $false -or
        (-not (Test-OrdinalStringEqual ($Observation.rootPath) ("C:\msys64")))) {
        Throw-ValidationError $ExitCode "provenance" (
            "external observation must be non-authoritative and identify C:\msys64")
    }
    Assert-UtcTimestamp $Observation.cutoffUtc `
        "assembly evidence.externalObservation.cutoffUtc" $ExitCode
    foreach ($name in @("before", "after")) {
        $snapshot = $Observation.$name
        Assert-ExactProperties $snapshot @("log", "database") `
            "assembly evidence.externalObservation.$name" $ExitCode
        Assert-ExactProperties $snapshot.log @("bytes", "sha256") `
            "assembly evidence.externalObservation.$name.log" $ExitCode
        Assert-ExactProperties $snapshot.database @(
            "files", "bytes", "canonicalManifestSha256") `
            "assembly evidence.externalObservation.$name.database" $ExitCode
        Assert-JsonInteger $snapshot.log.bytes `
            "assembly evidence.externalObservation.$name.log.bytes" 0 $ExitCode
        Assert-JsonInteger $snapshot.database.files `
            "assembly evidence.externalObservation.$name.database.files" 0 $ExitCode
        Assert-JsonInteger $snapshot.database.bytes `
            "assembly evidence.externalObservation.$name.database.bytes" 0 $ExitCode
        Assert-LowerSha256 $snapshot.log.sha256 `
            "assembly evidence.externalObservation.$name.log.sha256" $ExitCode
        Assert-LowerSha256 $snapshot.database.canonicalManifestSha256 `
            "assembly evidence.externalObservation.$name.database.canonicalManifestSha256" `
            $ExitCode
    }
    Assert-JsonArray $Observation.commands `
        "assembly evidence.externalObservation.commands" $ExitCode
    if ([long]$Observation.before.log.bytes -ne
            [long]$Observation.after.log.bytes -or
        (-not (Test-OrdinalStringEqual ($Observation.before.log.sha256) ($Observation.after.log.sha256))) -or
        [long]$Observation.before.database.files -ne
            [long]$Observation.after.database.files -or
        [long]$Observation.before.database.bytes -ne
            [long]$Observation.after.database.bytes -or
        (-not (Test-OrdinalStringEqual ($Observation.before.database.canonicalManifestSha256) ($Observation.after.database.canonicalManifestSha256)))) {
        Throw-ValidationError $ExitCode "provenance" (
            "external observation before/after snapshots differ")
    }
    # The shared root may only be described by this exact ordered, unique
    # four-operation read-only sequence.
    $commands = @($Observation.commands)
    if ($commands.Count -ne $script:ReadOnlyObservationOperations.Count) {
        Throw-ValidationError $ExitCode "mutation-risk" (
            "external observation must record exactly the four read-only operations")
    }
    for ($index = 0; $index -lt $commands.Count; $index++) {
        if ($commands[$index] -isnot [string]) {
            Throw-ValidationError $ExitCode "schema" (
                "external observation commands must be strings")
        }
        if ((-not (Test-OrdinalStringEqual ($commands[$index]) ($script:ReadOnlyObservationOperations[$index])))) {
            Throw-ValidationError $ExitCode "mutation-risk" (
                "external observation records an operation outside the read-only set: '$($commands[$index])'")
        }
    }
}

function Read-ProvenanceContract {
    param(
        [Parameter(Mandatory = $true)] $ProvenanceObject,
        [Parameter(Mandatory = $true)] $LockContext,
        [Parameter(Mandatory = $true)][string] $LockSha256
    )

    Assert-ExactProperties $ProvenanceObject @(
        "schemaVersion", "lockSha256", "sourceDateEpoch",
        "nativeShellClosure", "assembler", "inputs", "overlayOrder",
        "replacements", "finalMembers", "pseudoReloc") "provenance"
    Assert-SchemaVersion $ProvenanceObject "provenance"
    Assert-LowerSha256 $ProvenanceObject.lockSha256 "provenance.lockSha256"
    if ((-not (Test-OrdinalStringEqual ($ProvenanceObject.lockSha256) ($LockSha256)))) {
        Throw-ValidationError $script:ExitContract "digest" (
            "provenance lockSha256 does not match the lock")
    }
    Assert-JsonInteger $ProvenanceObject.sourceDateEpoch `
        "provenance.sourceDateEpoch" 0
    Assert-JsonArray $ProvenanceObject.nativeShellClosure `
        "provenance.nativeShellClosure"
    if ([long]$ProvenanceObject.sourceDateEpoch -ne
            $LockContext.SourceDateEpoch -or
        -not (Test-OrdinalStringSequenceEqual `
            @($ProvenanceObject.nativeShellClosure) `
            @($LockContext.NativeShellClosure))) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "provenance must preserve sourceDateEpoch and nativeShellClosure from the lock")
    }
    Assert-ExactProperties $ProvenanceObject.assembler @(
        "repository", "commit") "provenance.assembler"
    if ($ProvenanceObject.assembler.repository -cnotmatch
        "^crutkas/[A-Za-z0-9_.-]+$") {
        Throw-ValidationError $script:ExitContract "provenance" (
            "provenance assembler must be an immutable crutkas fork identity")
    }
    Assert-LowerCommit $ProvenanceObject.assembler.commit `
        "provenance.assembler.commit"
    Assert-JsonArray $ProvenanceObject.inputs "provenance.inputs"
    $provenanceInputs = @($ProvenanceObject.inputs)
    $resolvedIds = @($LockContext.Resolved | ForEach-Object { $_.id })
    if ($provenanceInputs.Count -ne $resolvedIds.Count) {
        Throw-ValidationError $script:ExitContract "archive" (
            "provenance must contain every resolved lock input and no others")
    }
    $archiveByInput =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal)
    $selectedByDestination =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $provenanceInputIds = @()
    for ($index = 0; $index -lt $provenanceInputs.Count; $index++) {
        $entry = $provenanceInputs[$index]
        Assert-ExactProperties $entry @(
            "id", "release", "asset", "package", "archiveMembers") `
            "provenance.inputs[$index]"
        $provenanceInputIds += $entry.id
        if ((-not (Test-OrdinalStringEqual ($entry.id) ($resolvedIds[$index]))) -or
            -not $LockContext.InputMap.ContainsKey($entry.id)) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "provenance inputs must follow resolved lock input order")
        }
        $lockInput = $LockContext.InputMap[$entry.id]
        if (-not (Test-IdentityEqual $entry $lockInput)) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "provenance identity for '$($entry.id)' differs from the lock")
        }
        $members = @($entry.archiveMembers)
        Assert-JsonArray $entry.archiveMembers `
            "provenance input '$($entry.id)'.archiveMembers"
        if ($members.Count -eq 0) {
            Throw-ValidationError $script:ExitContract "archive" (
                "provenance input '$($entry.id)' has no archive members")
        }
        Assert-SortedUnique $members { param($item) [string]$item.sourceMember } `
            "provenance input '$($entry.id)' archiveMembers"
        $baseTree = $LockContext.BaseTrees[$entry.id]
        if ($null -ne $baseTree) {
            if ($members.Count -ne $baseTree.Entries.Count) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "provenance input '$($entry.id)' does not cover its base tree manifest exactly")
            }
            for ($position = 0; $position -lt $members.Count; $position++) {
                $expectedBase = $baseTree.Entries[$position]
                $actualBase = $members[$position]
                if ((-not (Test-OrdinalStringEqual ($actualBase.sourceMember) ($expectedBase.path))) -or
                    (-not (Test-OrdinalStringEqual ($actualBase.type) ($expectedBase.type))) -or
                    [long]$actualBase.bytes -ne [long]$expectedBase.bytes -or
                    (-not (Test-OrdinalStringEqual ($actualBase.sha256) ($expectedBase.sha256))) -or
                    (-not (Test-OrdinalStringEqual ($actualBase.linkTarget) ($expectedBase.linkTarget)))) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "provenance base member '$($actualBase.sourceMember)' does not match the base tree manifest")
                }
            }
        }
        $memberMap = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $mappingBySource =
            [Collections.Generic.Dictionary[string, object]]::new(
                [StringComparer]::OrdinalIgnoreCase)
        if ((-not (Test-OrdinalStringEqual ($lockInput.role) ("validation-tool")))) {
            foreach ($mapping in @($lockInput.overlay.mappings)) {
                $mappingBySource[$mapping.sourceMember.ToLowerInvariant()] =
                    $mapping.destinationPath
            }
        }
        foreach ($member in $members) {
            Assert-ExactProperties $member @(
                "sourceMember", "type", "bytes", "sha256", "selected",
                "destinationPath", "linkTarget") `
                "archive member '$($entry.id)'"
            Assert-NormalizedPath $member.sourceMember `
                "archive member '$($entry.id)'.sourceMember"
            if ((-not (Test-OrdinalStringInCollection ($member.type) (@(
                "file", "directory", "symlink", "hardlink")))) -or
                $member.selected -isnot [bool]) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "archive member '$($member.sourceMember)' has invalid type/selected")
            }
            if ((Test-OrdinalStringEqual ($member.type) ("file"))) {
                Assert-JsonInteger $member.bytes `
                    "archive member '$($member.sourceMember)'.bytes" 0
                Assert-LowerSha256 $member.sha256 `
                    "archive member '$($member.sourceMember)'.sha256"
                if ($null -ne $member.linkTarget) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "archive file '$($member.sourceMember)' must have linkTarget=null")
                }
            } elseif ((Test-OrdinalStringEqual ($member.type) ("directory"))) {
                Assert-JsonInteger $member.bytes `
                    "archive directory '$($member.sourceMember)'.bytes" 0
                if ([long]$member.bytes -ne 0 -or $null -ne $member.sha256) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "archive directory '$($member.sourceMember)' must have bytes=0 and sha256=null")
                }
                if ($null -ne $member.linkTarget) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "archive directory '$($member.sourceMember)' must have linkTarget=null")
                }
            } else {
                Assert-JsonInteger $member.bytes `
                    "archive link '$($member.sourceMember)'.bytes" 0
                Assert-LowerSha256 $member.sha256 `
                    "archive link '$($member.sourceMember)'.sha256"
                Assert-NormalizedPath $member.linkTarget `
                    "archive link '$($member.sourceMember)'.linkTarget"
            }

            $expectedSelected = $false
            $expectedDestination = $null
            if ((-not (Test-OrdinalStringEqual ($lockInput.role) ("validation-tool")))) {
                $expectedSelected = (
                    (Test-PatternMatch $member.sourceMember @($lockInput.overlay.include)) -and
                    -not (Test-PatternMatch $member.sourceMember @($lockInput.overlay.exclude)))
                if ($expectedSelected) {
                    $mappingKey = $member.sourceMember.ToLowerInvariant()
                    $expectedDestination = if (
                        $mappingBySource.ContainsKey($mappingKey)) {
                        $mappingBySource[$mappingKey]
                    } elseif ((Test-OrdinalStringEqual ($lockInput.overlay.destination) ("."))) {
                        $member.sourceMember
                    } else {
                        "$($lockInput.overlay.destination)/$($member.sourceMember)"
                    }
                }
            }
            if ($member.selected -ne $expectedSelected) {
                Throw-ValidationError $script:ExitContract "overlay" (
                    "archive member '$($member.sourceMember)' selection does not match include/exclude")
            }
            if ($expectedSelected) {
                Assert-NormalizedPath $member.destinationPath `
                    "archive member '$($member.sourceMember)'.destinationPath"
                if ((-not (Test-OrdinalStringEqual ($member.destinationPath) ($expectedDestination)))) {
                    Throw-ValidationError $script:ExitContract "overlay" (
                        "archive member '$($member.sourceMember)' does not enforce overlay.destination")
                }
                $key = $member.destinationPath.ToLowerInvariant()
                if (-not $selectedByDestination.ContainsKey($key)) {
                    $selectedByDestination[$key] = @()
                }
                $selectedByDestination[$key] += [ordered]@{
                    inputId = $entry.id
                    sourceMember = $member.sourceMember
                    destinationPath = $member.destinationPath
                    type = $member.type
                    bytes = [long]$member.bytes
                    sha256 = $member.sha256
                    linkTarget = $member.linkTarget
                }
            } elseif ($null -ne $member.destinationPath) {
                Throw-ValidationError $script:ExitContract "overlay" (
                    "unselected archive member '$($member.sourceMember)' must have destinationPath=null")
            }
            $memberMap[$member.sourceMember.ToLowerInvariant()] = $member
        }
        foreach ($member in $members | Where-Object {
            Test-OrdinalStringInCollection $_.type @("symlink", "hardlink")
        }) {
            $targetKey = $member.linkTarget.ToLowerInvariant()
            if (-not $memberMap.ContainsKey($targetKey) -or
                (Test-OrdinalStringEqual ($memberMap[$targetKey].type) ("directory")) -or
                [long]$memberMap[$targetKey].bytes -ne [long]$member.bytes -or
                (-not (Test-OrdinalStringEqual ($memberMap[$targetKey].sha256) ($member.sha256)))) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "archive link '$($member.sourceMember)' has an invalid target identity")
            }
            $visitedLinks = [Collections.Generic.HashSet[string]]::new(
                $script:PathComparer)
            $cursor = $member
            while (Test-OrdinalStringInCollection `
                    $cursor.type @("symlink", "hardlink")) {
                if (-not $visitedLinks.Add($cursor.sourceMember)) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "archive links contain a cycle")
                }
                $cursor = $memberMap[$cursor.linkTarget.ToLowerInvariant()]
            }
            if ($member.selected) {
                $target = $memberMap[$targetKey]
                if (-not $target.selected) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "selected archive link target is not selected")
                }
                $targetMappingKey = $target.sourceMember.ToLowerInvariant()
                $targetDestination = if (
                    $mappingBySource.ContainsKey($targetMappingKey)) {
                    $mappingBySource[$targetMappingKey]
                } elseif ((Test-OrdinalStringEqual ($lockInput.overlay.destination) ("."))) {
                    $target.sourceMember
                } else {
                    "$($lockInput.overlay.destination)/$($target.sourceMember)"
                }
                $candidateKey = $member.destinationPath.ToLowerInvariant()
                $candidate = @($selectedByDestination[$candidateKey] |
                    Where-Object {
                        (Test-OrdinalStringEqual ($_.inputId) ($entry.id)) -and
                        (Test-OrdinalStringEqual ($_.sourceMember) ($member.sourceMember))
                    })[0]
                $candidate.linkTarget = $targetDestination
            }
        }
        $archiveByInput[$entry.id] = $memberMap
    }

    $overlayOrder = @($ProvenanceObject.overlayOrder)
    Assert-JsonArray $ProvenanceObject.overlayOrder `
        "provenance.overlayOrder"
    $payloadInputs = @($LockContext.Resolved |
        Where-Object {
            -not (Test-OrdinalStringEqual $_.role "validation-tool")
        })
    $baseInputs = @($payloadInputs | Where-Object {
        Test-OrdinalStringEqual $_.role "base-bundle"
    })
    if ($baseInputs.Count -ne 1) {
        Throw-ValidationError $script:ExitContract "overlay" (
            "provenance.overlayOrder requires exactly one resolved base-bundle")
    }
    $payloadIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($payloadInput in $payloadInputs) {
        [void]$payloadIds.Add($payloadInput.id)
    }
    $orderedIds = [Collections.Generic.HashSet[string]]::new(
        $script:PathComparer)
    if ($overlayOrder.Count -ne $payloadIds.Count -or
        $overlayOrder.Count -eq 0 -or
        (-not (Test-OrdinalStringEqual ($overlayOrder[0]) ($baseInputs[0].id)))) {
        Throw-ValidationError $script:ExitContract "overlay" (
            "provenance.overlayOrder must start with the one base-bundle")
    }
    foreach ($id in $overlayOrder) {
        if ($id -isnot [string] -or -not $payloadIds.Contains($id) -or
            -not $orderedIds.Add($id)) {
            Throw-ValidationError $script:ExitContract "overlay" (
                "provenance.overlayOrder must contain each resolved payload input exactly once")
        }
    }
    $orderMap = [Collections.Generic.Dictionary[string, int]]::new(
        [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $overlayOrder.Count; $index++) {
        $orderMap[$overlayOrder[$index]] = $index
    }

    $expectedFinal =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $expectedReplacements =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal)
    foreach ($key in $selectedByDestination.Keys) {
        # A single input replacing itself is not a meaningful overlay, and an
        # unstable sort would otherwise pick an arbitrary winner among equal
        # keys and make the verdict non-deterministic.
        $collidingIds = @($selectedByDestination[$key] |
            Group-Object { [string]$_.inputId } |
            Where-Object Count -GT 1)
        if ($collidingIds.Count -ne 0) {
            Throw-ValidationError $script:ExitContract "overlay" (
                "input '$($collidingIds[0].Name)' selects two members for destination '$key'")
        }
        $candidates = @($selectedByDestination[$key] | Sort-Object -Stable {
            $orderMap[$_.inputId]
        })
        $winner = $candidates[-1]
        $expectedFinal[$key] = $winner
        foreach ($loser in @($candidates | Select-Object -First (
            [Math]::Max(0, $candidates.Count - 1)))) {
            $replacementKey = (
                "$key`0$($loser.inputId.ToLowerInvariant())`0" +
                "$($loser.sourceMember.ToLowerInvariant())")
            $expectedReplacements[$replacementKey] = [ordered]@{
                destinationPath = $winner.destinationPath
                replacedInputId = $loser.inputId
                replacedSourceMember = $loser.sourceMember
                winnerInputId = $winner.inputId
                winnerSourceMember = $winner.sourceMember
            }
        }
    }

    $finalMembers = @($ProvenanceObject.finalMembers)
    Assert-JsonArray $ProvenanceObject.finalMembers `
        "provenance.finalMembers"
    Assert-SortedUnique $finalMembers {
        param($item) [string]$item.destinationPath
    } "provenance.finalMembers"
    if ($finalMembers.Count -ne $expectedFinal.Count) {
        Throw-ValidationError $script:ExitContract "member" (
            "provenance finalMembers omit or add selected archive members")
    }
    $finalMap = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $finalMembers) {
        Assert-ExactProperties $member @(
            "destinationPath", "inputId", "sourceMember", "type", "bytes",
            "sha256", "linkTarget") "provenance final member"
        Assert-NormalizedPath $member.destinationPath `
            "provenance final member destinationPath"
        Assert-NormalizedPath $member.sourceMember `
            "provenance final member sourceMember"
        Assert-JsonInteger $member.bytes `
            "provenance final member '$($member.destinationPath)'.bytes" 0
        $key = $member.destinationPath.ToLowerInvariant()
        if (-not $expectedFinal.ContainsKey($key)) {
            Throw-ValidationError $script:ExitContract "member" (
                "provenance final member '$($member.destinationPath)' was not selected")
        }
        $expected = $expectedFinal[$key]
        if ((-not (Test-OrdinalStringEqual ($member.destinationPath) ($expected.destinationPath))) -or
            (-not (Test-OrdinalStringEqual ($member.inputId) ($expected.inputId))) -or
            (-not (Test-OrdinalStringEqual ($member.sourceMember) ($expected.sourceMember))) -or
            (-not (Test-OrdinalStringEqual ($member.type) ($expected.type))) -or
            [long]$member.bytes -ne $expected.bytes -or
            (-not (Test-OrdinalStringEqual ($member.sha256) ($expected.sha256))) -or
            (-not (Test-OrdinalStringEqual ($member.linkTarget) ($expected.linkTarget)))) {
            Throw-ValidationError $script:ExitContract "member" (
                "provenance final member '$($member.destinationPath)' is not the exact archive winner")
        }
        $finalMap[$key] = $member
    }

    $replacements = @($ProvenanceObject.replacements)
    Assert-JsonArray $ProvenanceObject.replacements `
        "provenance.replacements"
    Assert-SortedUnique $replacements {
        param($item)
        "$($item.destinationPath)`0$($item.replacedInputId)`0$($item.replacedSourceMember)"
    } "provenance.replacements"
    if ($replacements.Count -ne $expectedReplacements.Count) {
        Throw-ValidationError $script:ExitContract "ownership" (
            "provenance replacements do not explicitly account for every collision")
    }
    foreach ($replacement in $replacements) {
        Assert-ExactProperties $replacement @(
            "destinationPath", "replacedInputId", "replacedSourceMember",
            "winnerInputId", "winnerSourceMember") "provenance replacement"
        $key = (
            "$($replacement.destinationPath.ToLowerInvariant())`0" +
            "$($replacement.replacedInputId.ToLowerInvariant())`0" +
            "$($replacement.replacedSourceMember.ToLowerInvariant())")
        if (-not $expectedReplacements.ContainsKey($key)) {
            Throw-ValidationError $script:ExitContract "ownership" (
                "provenance contains an unexpected replacement record")
        }
        $expected = $expectedReplacements[$key]
        foreach ($field in @(
            "destinationPath", "replacedInputId", "replacedSourceMember",
            "winnerInputId", "winnerSourceMember")) {
            if ((-not (Test-OrdinalStringEqual ($replacement.$field) ($expected.$field)))) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "provenance replacement for '$($replacement.destinationPath)' is incorrect")
            }
        }
    }

    foreach ($resolvedInput in $LockContext.Resolved) {
        if ($null -eq $resolvedInput.package) {
            continue
        }
        $inputId = $resolvedInput.id
        $provided = if ((-not (Test-OrdinalStringEqual ($resolvedInput.role) ("validation-tool")))) {
            @($finalMembers |
                Where-Object {
                    Test-OrdinalStringEqual $_.inputId $inputId
                } |
                ForEach-Object destinationPath)
        } else {
            @($archiveByInput[$inputId].Values |
                Where-Object {
                    Test-OrdinalStringEqual $_.type "file"
                } |
                ForEach-Object sourceMember)
        }
        foreach ($expectedProvide in @($resolvedInput.package.provides)) {
            if (-not (Test-OrdinalStringInCollection `
                    $expectedProvide $provided)) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "input '$inputId' is missing expected provide '$expectedProvide'")
            }
        }
    }

    $pseudo = $ProvenanceObject.pseudoReloc
    Assert-ExactProperties $pseudo @(
        "scanner", "toolInputId", "objdumpMember", "nmMember",
        "linkerMember", "candidates") "provenance.pseudoReloc"
    Assert-ExactProperties $pseudo.scanner @(
        "repository", "commit", "path", "bytes", "sha256") `
        "provenance.pseudoReloc.scanner"
    if ((-not (Test-OrdinalStringEqual ($pseudo.scanner.repository) ($script:ScannerRepository))) -or
        (-not (Test-OrdinalStringEqual ($pseudo.scanner.commit) ($script:ScannerCommit))) -or
        (-not (Test-OrdinalStringEqual ($pseudo.scanner.path) ($script:ScannerSourcePath))) -or
        [long]$pseudo.scanner.bytes -ne $script:ScannerBytes -or
        (-not (Test-OrdinalStringEqual ($pseudo.scanner.sha256) ($script:ScannerSha256)))) {
        Throw-ValidationError $script:ExitContract "scanner" (
            "provenance pseudo-reloc scanner identity does not match the pinned source")
    }
    if (-not $LockContext.InputMap.ContainsKey($pseudo.toolInputId)) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc toolInputId does not exist in the lock")
    }
    $toolInput = $LockContext.InputMap[$pseudo.toolInputId]
    if ((-not (Test-OrdinalStringEqual ($toolInput.status) ("resolved"))) -or
        (-not (Test-OrdinalStringEqual ($toolInput.role) ("validation-tool"))) -or
        (-not (Test-OrdinalStringEqual ($toolInput.package.name) ($script:ToolPackageName))) -or
        (-not (Test-OrdinalStringEqual ($toolInput.package.version) ($script:ToolPackageVersion))) -or
        (-not (Test-OrdinalStringEqual ($toolInput.asset.sha256) ($script:ToolPackageSha256)))) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc tools are not bound to the pinned immutable package")
    }
    if ((-not (Test-OrdinalStringEqual ($pseudo.objdumpMember) ($script:ObjdumpMember))) -or
        (-not (Test-OrdinalStringEqual ($pseudo.nmMember) ($script:NmMember))) -or
        (-not (Test-OrdinalStringEqual ($pseudo.linkerMember) ($script:LinkerMember)))) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc member paths do not match the pinned tool package")
    }
    $toolMembers = $archiveByInput[$pseudo.toolInputId]
    foreach ($memberPath in @(
        $script:ObjdumpMember, $script:NmMember, $script:LinkerMember)) {
        if (-not $toolMembers.ContainsKey($memberPath.ToLowerInvariant()) -or
            (-not (Test-OrdinalStringEqual ($toolMembers[$memberPath.ToLowerInvariant()].type) ("file")))) {
            Throw-ValidationError $script:ExitContract "tool" (
                "pinned tool package is missing archive member '$memberPath'")
        }
    }
    foreach ($pin in @(
        @($script:ObjdumpMember, $script:ObjdumpBytes, $script:ObjdumpSha256),
        @($script:NmMember, $script:NmBytes, $script:NmSha256),
        @($script:LinkerMember, $script:LinkerBytes, $script:LinkerSha256))) {
        $member = $toolMembers[$pin[0].ToLowerInvariant()]
        if ([long]$member.bytes -ne [long]$pin[1] -or
            (-not (Test-OrdinalStringEqual ($member.sha256) ($pin[2])))) {
            Throw-ValidationError $script:ExitContract "tool" (
                "pinned tool package member identity is incorrect: '$($pin[0])'")
        }
    }
    $declaredCandidates = @($pseudo.candidates)
    Assert-JsonArray $pseudo.candidates `
        "provenance.pseudoReloc.candidates"
    Assert-SortedUnique $declaredCandidates {
        param($item) [string]$item.destinationPath
    } "provenance.pseudoReloc.candidates"
    foreach ($candidate in $declaredCandidates) {
        Assert-ExactProperties $candidate @(
            "destinationPath", "inputId", "sourceMember") `
            "provenance pseudo-reloc candidate"
    }

    return [ordered]@{
        ArchiveByInput = $archiveByInput
        FinalMembers = $finalMembers
        FinalMap = $finalMap
        PseudoReloc = $pseudo
        ToolInput = $toolInput
    }
}

function Read-UInt16 {
    param([byte[]]$Bytes, [int]$Offset, [string]$Context)
    if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "$Context is truncated at offset $Offset")
    }
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-UInt32 {
    param([byte[]]$Bytes, [int]$Offset, [string]$Context)
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "$Context is truncated at offset $Offset")
    }
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-UInt64 {
    param([byte[]]$Bytes, [int]$Offset, [string]$Context)
    if ($Offset -lt 0 -or $Offset + 8 -gt $Bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "$Context is truncated at offset $Offset")
    }
    return [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Convert-RvaToOffset {
    param(
        [uint32]$Rva,
        [object[]]$Sections,
        [int]$FileLength,
        [string]$Context
    )

    foreach ($section in $Sections) {
        [uint64]$span = [Math]::Max(
            [uint64]$section.virtualSize,
            [uint64]$section.rawSize)
        [uint64]$start = $section.virtualAddress
        [uint64]$end = $start + $span
        if ([uint64]$Rva -ge $start -and [uint64]$Rva -lt $end) {
            [uint64]$delta = [uint64]$Rva - $start
            if ($delta -ge [uint64]$section.rawSize) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "$Context RVA 0x$($Rva.ToString('x')) has no file-backed bytes")
            }
            [uint64]$offset = [uint64]$section.rawPointer + $delta
            if ($offset -ge [uint64]$FileLength) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "$Context RVA maps outside the file")
            }
            return [int]$offset
        }
    }
    Throw-ValidationError $script:ExitStatic "pe" (
        "$Context RVA 0x$($Rva.ToString('x')) is not contained in a section")
}

function Convert-RvaRangeToOffset {
    param(
        [uint32]$Rva,
        [uint32]$Size,
        [object[]]$Sections,
        [int]$FileLength,
        [string]$Context
    )

    $offset = Convert-RvaToOffset $Rva $Sections $FileLength $Context
    foreach ($section in $Sections) {
        [uint64]$start = $section.virtualAddress
        [uint64]$span = [Math]::Max(
            [uint64]$section.virtualSize,
            [uint64]$section.rawSize)
        if ([uint64]$Rva -ge $start -and
            [uint64]$Rva -lt $start + $span) {
            [uint64]$delta = [uint64]$Rva - $start
            if ($delta + [uint64]$Size -gt [uint64]$section.rawSize -or
                [uint64]$offset + [uint64]$Size -gt [uint64]$FileLength) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "$Context range is not fully file-backed by one section")
            }
            return $offset
        }
    }
    Throw-ValidationError $script:ExitStatic "pe" (
        "$Context range is not contained in a section")
}

function Read-AsciiZ {
    param([byte[]]$Bytes, [int]$Offset, [string]$Context)

    $end = $Offset
    while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) {
        if ($Bytes[$end] -gt 127) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "$Context contains a non-ASCII import name")
        }
        $end++
    }
    if ($end -eq $Bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "$Context import name is not null-terminated")
    }
    return [Text.Encoding]::ASCII.GetString($Bytes, $Offset, $end - $Offset)
}

function Get-PeClassification {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $DisplayPath
    )

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        return [ordered]@{
            architecture = "non-pe"
            machine = $null
            personality = "none"
            imports = @()
            clrFlags = $null
        }
    }
    if ($bytes.Length -lt 64) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "malformed MZ file '$DisplayPath': DOS header is truncated")
    }
    [uint32]$peOffset = Read-UInt32 $bytes 60 "PE '$DisplayPath'"
    if ($peOffset -lt 64 -or [uint64]$peOffset + 24 -gt $bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "malformed MZ file '$DisplayPath': invalid PE header offset")
    }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "malformed MZ file '$DisplayPath': missing PE signature")
    }
    [uint16]$machine = Read-UInt16 $bytes ($peOffset + 4) "PE '$DisplayPath'"
    [uint16]$sectionCount = Read-UInt16 $bytes ($peOffset + 6) "PE '$DisplayPath'"
    [uint16]$optionalSize = Read-UInt16 $bytes ($peOffset + 20) "PE '$DisplayPath'"
    [uint16]$characteristics = Read-UInt16 $bytes ($peOffset + 22) `
        "PE '$DisplayPath'"
    if (($characteristics -band 0x2) -eq 0) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' is not marked as an executable image")
    }
    if ($sectionCount -eq 0 -or $sectionCount -gt 96) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' has an invalid section count")
    }
    $optionalOffset = [int]$peOffset + 24
    $sectionOffset = $optionalOffset + [int]$optionalSize
    if ($optionalSize -lt 96 -or
        [uint64]$sectionOffset + ([uint64]$sectionCount * 40) -gt $bytes.Length) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' has a truncated optional header or section table")
    }
    [uint16]$magic = Read-UInt16 $bytes $optionalOffset "PE '$DisplayPath'"
    if ($magic -eq 0x10b) {
        $numberOfDirectoriesOffset = $optionalOffset + 92
        $directoryOffset = $optionalOffset + 96
    } elseif ($magic -eq 0x20b) {
        if ($optionalSize -lt 112) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' has a truncated PE32+ optional header")
        }
        $numberOfDirectoriesOffset = $optionalOffset + 108
        $directoryOffset = $optionalOffset + 112
    } else {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' has unknown optional-header magic")
    }
    if (($machine -eq 0x014c -and $magic -ne 0x10b) -or
        ($machine -in @(0xaa64, 0x8664, 0xa641) -and $magic -ne 0x20b)) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' machine and optional-header formats disagree")
    }
    [uint32]$sectionAlignment = Read-UInt32 $bytes ($optionalOffset + 32) `
        "PE '$DisplayPath'"
    [uint32]$fileAlignment = Read-UInt32 $bytes ($optionalOffset + 36) `
        "PE '$DisplayPath'"
    [uint32]$sizeOfImage = Read-UInt32 $bytes ($optionalOffset + 56) `
        "PE '$DisplayPath'"
    [uint32]$sizeOfHeaders = Read-UInt32 $bytes ($optionalOffset + 60) `
        "PE '$DisplayPath'"
    [uint16]$subsystem = Read-UInt16 $bytes ($optionalOffset + 68) `
        "PE '$DisplayPath'"
    if ($fileAlignment -lt 0x200 -or $fileAlignment -gt 0x10000 -or
        ($fileAlignment -band ($fileAlignment - 1)) -ne 0 -or
        $sectionAlignment -lt $fileAlignment -or
        ($sectionAlignment -band ($sectionAlignment - 1)) -ne 0 -or
        $sizeOfImage -eq 0 -or
        ($sizeOfImage % $sectionAlignment) -ne 0 -or
        $subsystem -eq 0) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' has invalid alignment, image size, or subsystem")
    }
    if ($sizeOfHeaders -eq 0 -or $sizeOfHeaders -gt $bytes.Length -or
        $sizeOfHeaders -lt $sectionOffset + ($sectionCount * 40)) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' has invalid SizeOfHeaders")
    }
    [uint32]$directoryCount = Read-UInt32 $bytes $numberOfDirectoriesOffset `
        "PE '$DisplayPath'"
    $availableDirectories = [Math]::Floor(
        ([int]$optionalSize - ($directoryOffset - $optionalOffset)) / 8)
    if ($directoryCount -gt $availableDirectories) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' data directories exceed the optional header")
    }
    $sections = @()
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $offset = $sectionOffset + ($index * 40)
        [uint32]$virtualSize = Read-UInt32 $bytes ($offset + 8) "PE '$DisplayPath'"
        [uint32]$virtualAddress = Read-UInt32 $bytes ($offset + 12) "PE '$DisplayPath'"
        [uint32]$rawSize = Read-UInt32 $bytes ($offset + 16) "PE '$DisplayPath'"
        [uint32]$rawPointer = Read-UInt32 $bytes ($offset + 20) "PE '$DisplayPath'"
        if ([uint64]$rawPointer + [uint64]$rawSize -gt $bytes.Length) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' section $index exceeds the file")
        }
        if ($rawSize -ne 0 -and $rawPointer -lt $sizeOfHeaders) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' section $index overlaps the headers")
        }
        if (($rawSize % $fileAlignment) -ne 0 -or
            ($rawSize -ne 0 -and ($rawPointer % $fileAlignment) -ne 0) -or
            ($virtualAddress % $sectionAlignment) -ne 0) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' section $index has invalid alignment")
        }
        if ([uint64]$virtualAddress +
            [Math]::Max([uint64]$virtualSize, [uint64]$rawSize) -gt
            [uint32]::MaxValue + [uint64]1) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' section $index virtual range overflows")
        }
        $sections += [ordered]@{
            virtualSize = $virtualSize
            virtualAddress = $virtualAddress
            rawSize = $rawSize
            rawPointer = $rawPointer
        }
    }
    $maximumImageEnd = [uint64]$sizeOfHeaders
    foreach ($section in $sections) {
        $sectionEnd = [uint64]$section.virtualAddress +
            [Math]::Max(
                [uint64]$section.virtualSize,
                [uint64]$section.rawSize)
        if ($sectionEnd -gt $maximumImageEnd) {
            $maximumImageEnd = $sectionEnd
        }
    }
    $minimumImageSize = [uint64](
        [Math]::Ceiling($maximumImageEnd / [double]$sectionAlignment) *
        $sectionAlignment)
    if ([uint64]$sizeOfImage -lt $minimumImageSize) {
        Throw-ValidationError $script:ExitStatic "pe" (
            "PE '$DisplayPath' SizeOfImage does not cover its sections")
    }
    for ($left = 0; $left -lt $sections.Count; $left++) {
        for ($right = $left + 1; $right -lt $sections.Count; $right++) {
            $leftSection = $sections[$left]
            $rightSection = $sections[$right]
            $leftVirtualEnd = [uint64]$leftSection.virtualAddress +
                [Math]::Max(
                    [uint64]$leftSection.virtualSize,
                    [uint64]$leftSection.rawSize)
            $rightVirtualEnd = [uint64]$rightSection.virtualAddress +
                [Math]::Max(
                    [uint64]$rightSection.virtualSize,
                    [uint64]$rightSection.rawSize)
            if ($leftVirtualEnd -gt $rightSection.virtualAddress -and
                $rightVirtualEnd -gt $leftSection.virtualAddress) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' has overlapping virtual sections")
            }
            if ($leftSection.rawSize -ne 0 -and
                $rightSection.rawSize -ne 0) {
                $leftRawEnd = [uint64]$leftSection.rawPointer +
                    $leftSection.rawSize
                $rightRawEnd = [uint64]$rightSection.rawPointer +
                    $rightSection.rawSize
                if ($leftRawEnd -gt $rightSection.rawPointer -and
                    $rightRawEnd -gt $leftSection.rawPointer) {
                    Throw-ValidationError $script:ExitStatic "pe" (
                        "PE '$DisplayPath' has overlapping raw sections")
                }
            }
        }
    }

    $imports = @()
    if ($directoryCount -gt 1) {
        [uint32]$importRva = Read-UInt32 $bytes ($directoryOffset + 8) `
            "PE '$DisplayPath'"
        [uint32]$importSize = Read-UInt32 $bytes ($directoryOffset + 12) `
            "PE '$DisplayPath'"
        if (($importRva -eq 0) -xor ($importSize -eq 0)) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' has an incomplete import directory")
        }
        if ($importRva -ne 0) {
            if ($importSize -lt 20) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' has an invalid import directory size")
            }
            $importOffset = Convert-RvaRangeToOffset $importRva $importSize `
                $sections $bytes.Length "PE '$DisplayPath' import directory"
            $terminated = $false
            for ($offset = $importOffset;
                $offset + 20 -le $importOffset + $importSize;
                $offset += 20) {
                $allZero = $true
                for ($byteIndex = 0; $byteIndex -lt 20; $byteIndex++) {
                    if ($bytes[$offset + $byteIndex] -ne 0) {
                        $allZero = $false
                        break
                    }
                }
                if ($allZero) {
                    $terminated = $true
                    break
                }
                [uint32]$nameRva = Read-UInt32 $bytes ($offset + 12) `
                    "PE '$DisplayPath' import descriptor"
                [uint32]$originalThunkRva = Read-UInt32 $bytes $offset `
                    "PE '$DisplayPath' import descriptor"
                [uint32]$firstThunkRva = Read-UInt32 $bytes ($offset + 16) `
                    "PE '$DisplayPath' import descriptor"
                if ($nameRva -eq 0) {
                    Throw-ValidationError $script:ExitStatic "pe" (
                        "PE '$DisplayPath' import descriptor has no name")
                }
                $thunkRva = if ($originalThunkRva -ne 0) {
                    $originalThunkRva
                } else {
                    $firstThunkRva
                }
                if ($thunkRva -eq 0) {
                    Throw-ValidationError $script:ExitStatic "pe" (
                        "PE '$DisplayPath' import descriptor has no thunk table")
                }
                $thunkSize = if ($magic -eq 0x20b) { 8 } else { 4 }
                $thunkOffset = Convert-RvaToOffset $thunkRva $sections `
                    $bytes.Length "PE '$DisplayPath' import thunk"
                $thunkTerminated = $false
                for ($thunkIndex = 0; $thunkIndex -lt 65536; $thunkIndex++) {
                    $entryOffset = $thunkOffset + ($thunkIndex * $thunkSize)
                    if ($entryOffset + $thunkSize -gt $bytes.Length) {
                        break
                    }
                    $thunkValue = if ($thunkSize -eq 8) {
                        Read-UInt64 $bytes $entryOffset `
                            "PE '$DisplayPath' import thunk"
                    } else {
                        [uint64](Read-UInt32 $bytes $entryOffset `
                            "PE '$DisplayPath' import thunk")
                    }
                    if ($thunkValue -eq 0) {
                        $thunkTerminated = $true
                        break
                    }
                }
                if (-not $thunkTerminated) {
                    Throw-ValidationError $script:ExitStatic "pe" (
                        "PE '$DisplayPath' import thunk table is not terminated")
                }
                $nameOffset = Convert-RvaToOffset $nameRva $sections `
                    $bytes.Length "PE '$DisplayPath' import name"
                $imports += (Read-AsciiZ $bytes $nameOffset `
                    "PE '$DisplayPath'").ToLowerInvariant()
            }
            if (-not $terminated) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' import directory is not terminated")
            }
        }
    }
    $importSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $uniqueImports = @()
    foreach ($import in $imports) {
        if ($importSet.Add($import)) {
            $uniqueImports += $import
        }
    }
    $imports = @(Sort-OrdinalBy $uniqueImports {
        param($item) [string]$item
    })

    $clrFlags = $null
    $hasClr = $false
    if ($directoryCount -gt 14) {
        [uint32]$clrRva = Read-UInt32 $bytes ($directoryOffset + 112) `
            "PE '$DisplayPath'"
        [uint32]$clrSize = Read-UInt32 $bytes ($directoryOffset + 116) `
            "PE '$DisplayPath'"
        if (($clrRva -eq 0) -xor ($clrSize -eq 0)) {
            Throw-ValidationError $script:ExitStatic "pe" (
                "PE '$DisplayPath' has an incomplete CLR directory")
        }
        if ($clrRva -ne 0) {
            if ($clrSize -lt 72) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' CLR header is too small")
            }
            $clrOffset = Convert-RvaRangeToOffset $clrRva $clrSize `
                $sections $bytes.Length "PE '$DisplayPath' CLR header"
            [uint32]$clrHeaderSize = Read-UInt32 $bytes $clrOffset `
                "PE '$DisplayPath' CLR header"
            if ($clrHeaderSize -lt 72 -or $clrHeaderSize -gt $clrSize -or
                [uint64]$clrOffset + $clrHeaderSize -gt $bytes.Length) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' CLR header size is invalid")
            }
            [uint32]$metadataRva = Read-UInt32 $bytes ($clrOffset + 8) `
                "PE '$DisplayPath' CLR metadata"
            [uint32]$metadataSize = Read-UInt32 $bytes ($clrOffset + 12) `
                "PE '$DisplayPath' CLR metadata"
            if ($metadataRva -eq 0 -or $metadataSize -lt 20) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' CLR metadata directory is invalid")
            }
            $metadataOffset = Convert-RvaRangeToOffset $metadataRva `
                $metadataSize $sections $bytes.Length `
                "PE '$DisplayPath' CLR metadata"
            if ((Read-UInt32 $bytes $metadataOffset `
                "PE '$DisplayPath' CLR metadata signature") -ne 0x424a5342) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' CLR metadata signature is invalid")
            }
            [uint32]$versionLength = Read-UInt32 $bytes `
                ($metadataOffset + 12) "PE '$DisplayPath' CLR metadata version"
            if ($versionLength -eq 0 -or
                [uint64]$metadataOffset + 16 + $versionLength + 4 -gt
                    [uint64]$metadataOffset + $metadataSize) {
                Throw-ValidationError $script:ExitStatic "pe" (
                    "PE '$DisplayPath' CLR metadata version is invalid")
            }
            $clrFlags = Read-UInt32 $bytes ($clrOffset + 16) `
                "PE '$DisplayPath' CLR flags"
            $hasClr = $true
        }
    }

    $architecture = switch ($machine) {
        0xaa64 { "arm64"; break }
        0x8664 { "x64"; break }
        0xa641 { "arm64ec"; break }
        0x014c {
            if ($hasClr -and ($clrFlags -band 0x1) -ne 0 -and
                ($clrFlags -band 0x2) -eq 0) {
                "anycpu"
            } else {
                "x86"
            }
            break
        }
        default { "unknown" }
    }
    $hasMsys = Test-OrdinalStringInCollection "msys-2.0.dll" $imports
    $hasCygwin = Test-OrdinalStringInCollection "cygwin1.dll" $imports
    if ($hasMsys -and $hasCygwin) {
        Throw-ValidationError $script:ExitStatic "personality" (
            "PE '$DisplayPath' mixes MSYS and Cygwin imports")
    }
    $personality = if ($hasClr) {
        "managed"
    } elseif ($hasMsys) {
        "msys"
    } elseif ($hasCygwin) {
        "cygwin"
    } else {
        "mingw"
    }
    return [ordered]@{
        architecture = $architecture
        machine = "0x{0:X4}" -f $machine
        personality = $personality
        imports = $imports
        clrFlags = $clrFlags
    }
}

# Get-ChildItem does not enumerate NTFS alternate data streams and
# Get-FileSha256 only hashes ::$DATA, so undeclared bytes could otherwise ride
# along inside an authoritative member.
function Assert-NoAlternateStream {
    param(
        [Parameter(Mandatory = $true)][string] $FullPath,
        [Parameter(Mandatory = $true)][string] $Relative
    )

    try {
        $streams = @(Get-Item -LiteralPath $FullPath -Stream * `
            -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match
            "(?i)(alternate data streams are not supported|provider does not support|stream parameter)") {
            return
        }
        Throw-ValidationError $script:ExitContract "stream" (
            "could not enumerate alternate data streams for payload member " +
            "'$Relative': $($_.Exception.Message)")
    }
    foreach ($stream in $streams) {
        if ((-not (Test-OrdinalStringEqual ([string]$stream.Stream) (":`$DATA")))) {
            Throw-ValidationError $script:ExitContract "stream" (
                "payload member '$Relative' carries alternate data stream '$($stream.Stream)'")
        }
    }
}

function Resolve-LinkTargetPath {
    param(
        [Parameter(Mandatory = $true)][string] $LinkDirectory,
        [Parameter(Mandatory = $true)][string] $Target,
        [Parameter(Mandatory = $true)][string] $Description
    )

    if ([string]::IsNullOrEmpty($Target)) {
        Throw-ValidationError $script:ExitContract "reparse" (
            "$Description has an empty link target")
    }
    if ([IO.Path]::IsPathFullyQualified($Target)) {
        return [IO.Path]::GetFullPath($Target)
    }
    if ([IO.Path]::IsPathRooted($Target)) {
        Throw-ValidationError $script:ExitContract "reparse" (
            "$Description uses a volume-relative link target")
    }
    return [IO.Path]::GetFullPath(
        [IO.Path]::Combine($LinkDirectory, $Target))
}

# PowerShell reports an empty Target for Windows hard links, so the shared
# file identity has to come from fsutil, which prints one volume-relative
# name per link.
function Get-HardlinkNames {
    param(
        [Parameter(Mandatory = $true)][string] $FullPath,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $fsutil = Join-Path $env:SystemRoot "System32\fsutil.exe"
    if (-not [IO.File]::Exists($fsutil)) {
        Throw-ValidationError $script:ExitContract "hardlink" (
            "$Description cannot be verified because fsutil.exe is unavailable")
    }
    $volume = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrEmpty($volume)) {
        Throw-ValidationError $script:ExitContract "hardlink" (
            "$Description has no resolvable volume")
    }
    $volume = $volume.TrimEnd("\", "/")
    $output = & $fsutil hardlink list $FullPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Throw-ValidationError $script:ExitContract "hardlink" (
            "$Description could not be enumerated by fsutil")
    }
    $names = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    foreach ($line in @($output)) {
        $text = ([string]$line).Trim()
        if ($text.Length -eq 0) {
            continue
        }
        $candidate = if ([IO.Path]::IsPathFullyQualified($text)) {
            $text
        } else {
            $volume + $text
        }
        [void]$names.Add([IO.Path]::GetFullPath($candidate))
    }
    if ($names.Count -eq 0 -or -not $names.Contains(
        [IO.Path]::GetFullPath($FullPath))) {
        Throw-ValidationError $script:ExitContract "hardlink" (
            "$Description returned an incomplete hardlink name set")
    }
    return @(Sort-OrdinalBy @($names) { param($item) [string]$item })
}

function Get-DeclaredFileIdentity {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)] $FinalMap
    )

    $visited = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
    $cursor = $Path
    while ($true) {
        if (-not $visited.Add($cursor) -or
            -not $FinalMap.ContainsKey($cursor.ToLowerInvariant())) {
            return $null
        }
        $member = $FinalMap[$cursor.ToLowerInvariant()]
        if ((Test-OrdinalStringEqual ($member.type) ("file"))) {
            return $member.destinationPath
        }
        if ((-not (Test-OrdinalStringEqual ($member.type) ("hardlink")))) {
            return $null
        }
        $cursor = [string]$member.linkTarget
    }
}

function Get-RootInventory {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $FinalMap
    )

    $members = @()
    $declaredIdentityGroups =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $FinalMap.Values) {
        if ((-not (Test-OrdinalStringInCollection ($member.type) (@("file", "hardlink"))))) {
            continue
        }
        $canonical = Get-DeclaredFileIdentity $member.destinationPath $FinalMap
        if ($null -eq $canonical) {
            Throw-ValidationError $script:ExitContract "hardlink" (
                "provenance file identity for '$($member.destinationPath)' is invalid")
        }
        $key = $canonical.ToLowerInvariant()
        if (-not $declaredIdentityGroups.ContainsKey($key)) {
            $declaredIdentityGroups[$key] =
                [Collections.Generic.HashSet[string]]::new($script:PathComparer)
        }
        [void]$declaredIdentityGroups[$key].Add($member.destinationPath)
    }
    Assert-NoAlternateStream $RootPath "."
    foreach ($item in Get-ChildItem -LiteralPath $RootPath -Force -Recurse) {
        $relative = [IO.Path]::GetRelativePath(
            $RootPath,
            $item.FullName).Replace("\", "/")
        if ($script:PathComparer.Equals($relative, "preview-evidence") -or
            $relative.StartsWith(
                "preview-evidence/",
                [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        Assert-NormalizedPath $relative "materialized root member"
        $isReparse = (
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        $linkTarget = $null
        $hardlinkTargets = @()
        $contentPath = $item.FullName
        if ($isReparse) {
            if ($item.PSIsContainer -or (-not (Test-OrdinalStringEqual ($item.LinkType) ("SymbolicLink")))) {
                Throw-ValidationError $script:ExitContract "reparse" (
                    "payload contains an undeclared or unsupported reparse point: '$relative'")
            }
            $targetFull = Resolve-LinkTargetPath `
                $item.DirectoryName ([string]$item.Target) `
                "payload symlink '$relative'"
            if (-not (Test-PathWithin $RootPath $targetFull) -or
                -not [IO.File]::Exists($targetFull)) {
                Throw-ValidationError $script:ExitContract "reparse" (
                    "payload symlink '$relative' is broken or escapes Root")
            }
            $linkTarget = [IO.Path]::GetRelativePath(
                $RootPath,
                $targetFull).Replace("\", "/")
            Assert-NormalizedPath $linkTarget `
                "payload symlink '$relative' linkTarget"
            $contentPath = $targetFull
            $type = "symlink"
        } elseif ($item.PSIsContainer) {
            $type = "directory"
        } else {
            $declared = $FinalMap[$relative.ToLowerInvariant()]
            $declaredType = if ($null -eq $declared) {
                $null
            } else {
                [string]$declared.type
            }
            $names = @(Get-HardlinkNames $item.FullName `
                "payload member '$relative'")
            $observedNames =
                [Collections.Generic.HashSet[string]]::new($script:PathComparer)
            foreach ($name in $names) {
                if (-not (Test-PathWithin $RootPath $name)) {
                    Throw-ValidationError $script:ExitContract "hardlink" (
                        "payload member '$relative' shares its file identity outside Root")
                }
                $observed = [IO.Path]::GetRelativePath(
                    $RootPath, $name).Replace("\", "/")
                Assert-NormalizedPath $observed `
                    "payload member '$relative' hardlink name"
                [void]$observedNames.Add($observed)
            }
            $canonical = if ($null -eq $declared) {
                $null
            } else {
                Get-DeclaredFileIdentity $relative $FinalMap
            }
            $expectedNames = if ($null -eq $canonical) {
                $null
            } else {
                $declaredIdentityGroups[$canonical.ToLowerInvariant()]
            }
            if ($names.Count -gt 1 -or (Test-OrdinalStringEqual ($declaredType) ("hardlink"))) {
                if ($null -eq $expectedNames -or
                    $expectedNames.Count -ne $observedNames.Count -or
                    @($observedNames | Where-Object {
                        -not $expectedNames.Contains($_)
                    }).Count -ne 0) {
                    Throw-ValidationError $script:ExitContract "hardlink" (
                        "payload member '$relative' has an undeclared hardlink name or file identity")
                }
            }
            if ((Test-OrdinalStringEqual ($declaredType) ("hardlink"))) {
                if ($names.Count -lt 2) {
                    Throw-ValidationError $script:ExitContract "hardlink" (
                        "payload hardlink '$relative' does not share a file identity")
                }
                $type = "hardlink"
                $hardlinkTargets = $names
            } else {
                $type = "file"
            }
        }
        Assert-NoAlternateStream $item.FullName $relative
        $members += [ordered]@{
            path = $relative
            type = $type
            bytes = if ((Test-OrdinalStringEqual ($type) ("directory"))) {
                [long]0
            } else {
                [long][IO.FileInfo]::new($contentPath).Length
            }
            sha256 = if ((Test-OrdinalStringEqual ($type) ("directory"))) {
                $null
            } else {
                Get-FileSha256 $contentPath
            }
            fullPath = $item.FullName
            linkTarget = $linkTarget
            hardlinkTargets = $hardlinkTargets
        }
    }
    $members = @(Sort-OrdinalBy $members {
        param($item) [string]$item.path
    })
    Assert-SortedUnique $members { param($item) [string]$item.path } `
        "materialized root members"
    $lines = foreach ($member in $members) {
        $hash = if ($null -eq $member.sha256) { "-" } else { $member.sha256 }
        "$($member.type)`t$($member.path)`t$($member.bytes)`t$hash`n"
    }
    return [ordered]@{
        Members = $members
        Sha256 = Get-TextSha256 ($lines -join "")
    }
}

function Read-PayloadContract {
    param(
        [Parameter(Mandatory = $true)] $PayloadObject,
        [Parameter(Mandatory = $true)][string] $LockSha256,
        [Parameter(Mandatory = $true)][string] $ProvenanceSha256,
        [Parameter(Mandatory = $true)] $ProvenanceContext,
        [Parameter(Mandatory = $true)][string] $RootPath
    )

    Assert-ExactProperties $PayloadObject @(
        "schemaVersion", "lockSha256", "provenanceSha256", "scope",
        "entries") "payload manifest"
    Assert-SchemaVersion $PayloadObject "payload manifest"
    Assert-LowerSha256 $PayloadObject.lockSha256 "payload manifest.lockSha256"
    Assert-LowerSha256 $PayloadObject.provenanceSha256 `
        "payload manifest.provenanceSha256"
    if ((-not (Test-OrdinalStringEqual ($PayloadObject.lockSha256) ($LockSha256))) -or
        (-not (Test-OrdinalStringEqual ($PayloadObject.provenanceSha256) ($ProvenanceSha256)))) {
        Throw-ValidationError $script:ExitContract "digest" (
            "payload manifest does not bind the exact lock and provenance")
    }
    Assert-ExactProperties $PayloadObject.scope @(
        "root", "excludedPrefixes") "payload manifest.scope"
    Assert-JsonArray $PayloadObject.scope.excludedPrefixes `
        "payload manifest.scope.excludedPrefixes"
    if ((-not (Test-OrdinalStringEqual ($PayloadObject.scope.root) ("."))) -or
        @($PayloadObject.scope.excludedPrefixes).Count -ne 1 -or
        (-not (Test-OrdinalStringEqual (@($PayloadObject.scope.excludedPrefixes)[0]) ("preview-evidence/")))) {
        Throw-ValidationError $script:ExitContract "scope" (
            "payload manifest scope must be root '.' excluding only preview-evidence/")
    }

    Assert-JsonArray $PayloadObject.entries "payload manifest.entries"
    $entries = @($PayloadObject.entries)
    Assert-SortedUnique $entries { param($item) [string]$item.path } `
        "payload manifest entries"
    $inventory = Get-RootInventory $RootPath $ProvenanceContext.FinalMap
    if ($entries.Count -ne $inventory.Members.Count -or
        $entries.Count -ne $ProvenanceContext.FinalMembers.Count) {
        Throw-ValidationError $script:ExitContract "member" (
            "payload manifest, root, and provenance member counts differ")
    }
    $classifications = @()
    $classificationMap =
        [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $entryMap = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        Assert-ExactProperties $entry @(
            "path", "type", "bytes", "sha256", "linkTarget") `
            "payload manifest entry"
        Assert-NormalizedPath $entry.path "payload manifest entry path"
        Assert-JsonInteger $entry.bytes `
            "payload manifest entry '$($entry.path)'.bytes" 0
        $actual = $inventory.Members[$index]
        if ((-not (Test-OrdinalStringEqual ($entry.path) ($actual.path))) -or (-not (Test-OrdinalStringEqual ($entry.type) ($actual.type)))) {
            Throw-ValidationError $script:ExitContract "member" (
                "payload manifest does not ordinally cover root member '$($actual.path)'")
        }
        $provenanceMember = $ProvenanceContext.FinalMap[
            $entry.path.ToLowerInvariant()]
        if ($null -eq $provenanceMember -or
            (-not (Test-OrdinalStringEqual ($provenanceMember.destinationPath) ($entry.path))) -or
            (-not (Test-OrdinalStringEqual ($provenanceMember.type) ($entry.type)))) {
            Throw-ValidationError $script:ExitContract "member" (
                "payload member '$($entry.path)' lacks exact final provenance ownership")
        }
        if ((Test-OrdinalStringEqual ($entry.type) ("directory"))) {
            if ([long]$entry.bytes -ne 0 -or $null -ne $entry.sha256 -or
                $null -ne $entry.linkTarget) {
                Throw-ValidationError $script:ExitContract "member" (
                    "directory '$($entry.path)' has invalid payload metadata")
            }
        } elseif ((Test-OrdinalStringInCollection ($entry.type) (@("file", "symlink", "hardlink")))) {
            if ((Test-OrdinalStringEqual ($entry.type) ("file")) -and $null -ne $entry.linkTarget) {
                Throw-ValidationError $script:ExitContract "member" (
                    "ordinary file '$($entry.path)' must have linkTarget=null")
            }
            if ((Test-OrdinalStringInCollection ($entry.type) (@("symlink", "hardlink")))) {
                Assert-NormalizedPath $entry.linkTarget `
                    "payload link '$($entry.path)'.linkTarget"
                if ((-not (Test-OrdinalStringEqual ($entry.linkTarget) ($provenanceMember.linkTarget))) -or
                    -not $entryMap.ContainsKey(
                        $entry.linkTarget.ToLowerInvariant()) -and
                @($entries | Where-Object {
                    Test-OrdinalStringEqual $_.path $entry.linkTarget
                }).
                    Count -ne 1) {
                    Throw-ValidationError $script:ExitContract "member" (
                        "payload link '$($entry.path)' target is not declared")
                }
                if ((Test-OrdinalStringEqual ($entry.type) ("symlink")) -and
                    (-not (Test-OrdinalStringEqual ($actual.linkTarget) ($entry.linkTarget)))) {
                    Throw-ValidationError $script:ExitContract "reparse" (
                        "payload symlink '$($entry.path)' target differs from provenance")
                }
                if ((Test-OrdinalStringEqual ($entry.type) ("hardlink"))) {
                    $expectedTargetFull = Join-Path $RootPath (
                        $entry.linkTarget.Replace("/", "\"))
                    if (@($actual.hardlinkTargets | Where-Object {
                        $script:PathComparer.Equals($_, $expectedTargetFull)
                    }).Count -eq 0) {
                        Throw-ValidationError $script:ExitContract "hardlink" (
                            "payload hardlink '$($entry.path)' does not share its declared file identity")
                    }
                }
            }
            if ([long]$entry.bytes -ne $actual.bytes -or
                (-not (Test-OrdinalStringEqual ($entry.sha256) ($actual.sha256))) -or
                [long]$provenanceMember.bytes -ne $actual.bytes -or
                (-not (Test-OrdinalStringEqual ($provenanceMember.sha256) ($actual.sha256)))) {
                Throw-ValidationError $script:ExitContract "member" (
                    "payload file '$($entry.path)' bytes/hash do not match its archive member")
            }
            # The validator alone owns classification; the payload manifest
            # carries no producer-supplied architecture to compare against.
            $classification = Get-PeClassification $actual.fullPath $entry.path
            $classificationRow = [ordered]@{
                path = $entry.path
                architecture = $classification.architecture
                machine = $classification.machine
                personality = $classification.personality
                imports = @($classification.imports)
                clrFlags = $classification.clrFlags
                inputId = $provenanceMember.inputId
                sourceMember = $provenanceMember.sourceMember
            }
            $classifications += $classificationRow
            $classificationMap[$entry.path.ToLowerInvariant()] =
                $classificationRow
        } else {
            Throw-ValidationError $script:ExitContract "member" (
                "payload entry '$($entry.path)' has invalid type")
        }
        $entryMap[$entry.path.ToLowerInvariant()] = $entry
    }
    $script:ReportData.summary.payloadMembers = $entries.Count
    $script:ReportData.summary.peFiles = @(
        $classifications |
            Where-Object {
                -not (Test-OrdinalStringEqual $_.architecture "non-pe")
            }).Count
    $script:ReportData.classifications = $classifications
    $script:ReportData.digests.rootInventorySha256 = $inventory.Sha256
    return [ordered]@{
        Entries = $entries
        EntryMap = $entryMap
        Inventory = $inventory
        Classifications = $classifications
        ClassificationMap = $classificationMap
    }
}

function Assert-PseudoReloc {
    param(
        [Parameter(Mandatory = $true)] $ProvenanceContext,
        [Parameter(Mandatory = $true)] $PayloadContext,
        [Parameter(Mandatory = $true)][string] $RootPath
    )

    $detected = @(Sort-OrdinalBy @($PayloadContext.Classifications |
        Where-Object {
            (Test-OrdinalStringEqual ($_.architecture) ("arm64")) -and (Test-OrdinalStringEqual ($_.personality) ("msys"))
        }) { param($item) [string]$item.path })
    $declared = @($ProvenanceContext.PseudoReloc.candidates)
    if ($detected.Count -ne $declared.Count) {
        Throw-ValidationError $script:ExitContract "candidate" (
            "pseudo-reloc candidates must be selected from detected ARM64 MSYS PEs")
    }
    for ($index = 0; $index -lt $detected.Count; $index++) {
        if ((-not (Test-OrdinalStringEqual ($declared[$index].destinationPath) ($detected[$index].path))) -or
            (-not (Test-OrdinalStringEqual ($declared[$index].inputId) ($detected[$index].inputId))) -or
            (-not (Test-OrdinalStringEqual ($declared[$index].sourceMember) ($detected[$index].sourceMember)))) {
            Throw-ValidationError $script:ExitContract "candidate" (
                "pseudo-reloc candidate '$($declared[$index].destinationPath)' " +
                "does not match detected payload personality/ownership")
        }
    }
    $script:ReportData.summary.pseudoRelocCandidates = $detected.Count
    if ($detected.Count -eq 0) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($ToolRoot)) {
        Throw-ValidationError $script:ExitScanner "tool" (
            "-ToolRoot is required when ARM64 MSYS pseudo-reloc candidates exist")
    }
    $toolRootPath = Assert-LocalSafeRoot $ToolRoot "ToolRoot" $script:ExitScanner
    if ($toolRootPath.StartsWith(
        "$RootPath\",
        [StringComparison]::OrdinalIgnoreCase) -or
        $RootPath.StartsWith(
            "$toolRootPath\",
            [StringComparison]::OrdinalIgnoreCase) -or
        $script:PathComparer.Equals($toolRootPath, $RootPath)) {
        Throw-ValidationError $script:ExitScanner "tool" (
            "ToolRoot and payload Root must be disjoint")
    }
    $repoRoot = Split-Path -Parent $PSCommandPath
    $scannerPath = Join-Path $repoRoot $script:ScannerRelativePath
    if (-not [IO.File]::Exists($scannerPath) -or
        [IO.FileInfo]::new($scannerPath).Length -ne $script:ScannerBytes -or
        (-not (Test-OrdinalStringEqual ((Get-FileSha256 $scannerPath)) ($script:ScannerSha256)))) {
        Throw-ValidationError $script:ExitScanner "scanner" (
            "committed pseudo-reloc scanner does not match its built-in pin")
    }
    $toolMembers = $ProvenanceContext.ArchiveByInput[
        $ProvenanceContext.PseudoReloc.toolInputId]
    $objdumpPath = Join-Path $toolRootPath (
        $script:ObjdumpMember.Replace("/", "\"))
    $nmPath = Join-Path $toolRootPath ($script:NmMember.Replace("/", "\"))
    foreach ($tool in @(
        @($objdumpPath, $script:ObjdumpMember),
        @($nmPath, $script:NmMember))) {
        if (-not [IO.File]::Exists($tool[0])) {
            Throw-ValidationError $script:ExitScanner "tool" (
                "ToolRoot is missing '$($tool[1])'")
        }
        $member = $toolMembers[$tool[1].ToLowerInvariant()]
        $actualBytes = [IO.FileInfo]::new($tool[0]).Length
        $actualHash = Get-FileSha256 $tool[0]
        if ($actualBytes -ne [long]$member.bytes -or
            (-not (Test-OrdinalStringEqual ($actualHash) ($member.sha256)))) {
            Throw-ValidationError $script:ExitScanner "tool" (
                "ToolRoot member '$($tool[1])' does not match its verified archive record")
        }
    }

    $results = @()
    $temporary = Join-Path ([IO.Path]::GetTempPath()) (
        "arm64-pseudo-reloc-" + [Guid]::NewGuid().ToString("N"))
    [void][IO.Directory]::CreateDirectory($temporary)
    try {
        for ($index = 0; $index -lt $detected.Count; $index++) {
            $candidate = $detected[$index]
            $candidatePath = Join-Path $RootPath (
                $candidate.path.Replace("/", "\"))
            $outputPath = Join-Path $temporary ("candidate-{0:D4}.json" -f $index)
            & pwsh -NoProfile -File $scannerPath `
                -PePath $candidatePath `
                -OutputPath $outputPath `
                -Objdump $objdumpPath `
                -Nm $nmPath
            $scannerExit = $LASTEXITCODE
            if (-not [IO.File]::Exists($outputPath)) {
                Throw-ValidationError $script:ExitScanner "scanner" (
                    "pseudo-reloc scanner emitted no report for '$($candidate.path)'")
            }
            try {
                $scannerReport = Get-Content -LiteralPath $outputPath -Raw |
                    ConvertFrom-Json -Depth 100
            } catch {
                Throw-ValidationError $script:ExitScanner "scanner" (
                    "pseudo-reloc scanner report is malformed for '$($candidate.path)'")
            }
            if ($scannerExit -eq 2 -or (Test-OrdinalStringEqual ($scannerReport.result) ("error"))) {
                Throw-ValidationError $script:ExitScanner "scanner" (
                    "pseudo-reloc scanner failed for '$($candidate.path)': " +
                    "$($scannerReport.error)")
            }
            if ($scannerExit -ne 0 -or (-not (Test-OrdinalStringEqual ($scannerReport.result) ("pass")))) {
                Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                    "pseudo-reloc policy rejected '$($candidate.path)'")
            }
            Assert-JsonInteger $scannerReport.record_count `
                "pseudo-reloc scanner record_count for '$($candidate.path)'" 0 `
                $script:ExitScanner
            Assert-JsonArray $scannerReport.flags `
                "pseudo-reloc scanner flags for '$($candidate.path)'" `
                $script:ExitScanner
            $flags = @($scannerReport.flags)
            if ((Test-OrdinalStringEqual ($scannerReport.table_format) ("empty"))) {
                if ([long]$scannerReport.record_count -ne 0 -or
                    $flags.Count -ne 0 -or
                    [long]$scannerReport.byte_length -ne 0) {
                    Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                        "empty pseudo-reloc proof is inconsistent for '$($candidate.path)'")
                }
            } elseif ((Test-OrdinalStringEqual ($scannerReport.table_format) ("v2"))) {
                if ($flags.Count -ne [long]$scannerReport.record_count) {
                    Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                        "pseudo-reloc v2 proof is incomplete for '$($candidate.path)'")
                }
                foreach ($flag in $flags) {
                    if (($flag -isnot [int] -and $flag -isnot [long]) -or
                        [long]$flag -ne 64) {
                        Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                            "ARM64 lane requires scalar64 pseudo-reloc flags for " +
                            "'$($candidate.path)'")
                    }
                }
            } else {
                Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                    "pseudo-reloc proof for '$($candidate.path)' must be an " +
                    "explicit parsed empty table or scalar64 v2 table")
            }
            $results += [ordered]@{
                path = $candidate.path
                result = "pass"
                tableFormat = $scannerReport.table_format
                recordCount = [long]$scannerReport.record_count
                flags = $flags
                objdumpMember = $script:ObjdumpMember
                objdumpSha256 =
                    $toolMembers[$script:ObjdumpMember.ToLowerInvariant()].sha256
                nmMember = $script:NmMember
                nmSha256 =
                    $toolMembers[$script:NmMember.ToLowerInvariant()].sha256
            }
        }
    } finally {
        if ([IO.Directory]::Exists($temporary)) {
            Remove-Item -LiteralPath $temporary -Recurse -Force
        }
    }
    $script:ReportData.pseudoReloc = $results
}

function Assert-StaticPolicy {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Preview", "Final")]
        [string] $AdmissionMode,
        [Parameter(Mandatory = $true)] $LockContext,
        [Parameter(Mandatory = $true)] $PayloadContext
    )

    $closureRows = @()
    foreach ($path in $LockContext.NativeShellClosure) {
        if (-not $PayloadContext.EntryMap.ContainsKey($path.ToLowerInvariant())) {
            Throw-ValidationError $script:ExitContract "closure" (
                "native shell closure member is missing from payload: '$path'")
        }
        $entry = $PayloadContext.EntryMap[$path.ToLowerInvariant()]
        if ((-not (Test-OrdinalStringEqual ($entry.type) ("file")))) {
            Throw-ValidationError $script:ExitContract "closure" (
                "native shell closure member is not a file: '$path'")
        }
        $classification =
            $PayloadContext.ClassificationMap[$path.ToLowerInvariant()]
        $closureRows += [ordered]@{
            path = $path
            architecture = $classification.architecture
            personality = $classification.personality
        }
    }
    $script:ReportData.nativeShellClosure = $closureRows

    $invalid = @($PayloadContext.Classifications | Where-Object {
        Test-OrdinalStringInCollection $_.architecture @("x86", "unknown")
    })
    if ($invalid.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "architecture" (
            "payload contains forbidden x86 or unknown PE architecture: " +
            (($invalid | ForEach-Object path) -join ", "))
    }
    $cygwin = @($PayloadContext.Classifications | Where-Object {
        Test-OrdinalStringEqual $_.personality "cygwin"
    })
    if ($cygwin.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "personality" (
            "payload contains forbidden Cygwin personality: " +
            (($cygwin | ForEach-Object path) -join ", "))
    }
    $x64 = @(Sort-OrdinalBy @($PayloadContext.Classifications |
        Where-Object {
            Test-OrdinalStringEqual $_.architecture "x64"
        } |
        ForEach-Object path) { param($item) [string]$item })
    $script:ReportData.remainingX64 = $x64
    $script:ReportData.summary.remainingX64 = $x64.Count
    if ((Test-OrdinalStringEqual ($AdmissionMode) ("Final")) -and $LockContext.Unresolved.Count -ne 0) {
        Throw-ValidationError $script:ExitContract "unresolved" (
            "Final admission rejects unresolved lock inputs: " +
            ($LockContext.Unresolved -join ", "))
    }
    if ((Test-OrdinalStringEqual ($AdmissionMode) ("Final")) -and $x64.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "architecture" (
            "Final admission rejects all x64 payload files: $($x64 -join ', ')")
    }
    $nonArm64Closure = @($closureRows | Where-Object {
        -not (Test-OrdinalStringEqual $_.architecture "arm64")
    })
    if ((Test-OrdinalStringEqual ($AdmissionMode) ("Final")) -and $nonArm64Closure.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "closure" (
            "Final admission requires ARM64 native shell closure members: " +
            (($nonArm64Closure | ForEach-Object path) -join ", "))
    }
    if ((Test-OrdinalStringEqual ($AdmissionMode) ("Preview")) -and $x64.Count -ne 0) {
        $baselinePath = Join-Path (Split-Path -Parent $PSCommandPath) `
            "arm64-x64-payload-baseline.txt"
        if (-not [IO.File]::Exists($baselinePath)) {
            Throw-ValidationError $script:ExitScanner "baseline" (
                "authoritative x64 baseline is missing")
        }
        $baseline = @([IO.File]::ReadAllLines($baselinePath) |
            ForEach-Object { $_.TrimEnd("`r") })
        Assert-SortedUnique $baseline { param($item) [string]$item } `
            "authoritative x64 baseline" $script:ExitScanner
        $allowed = [Collections.Generic.HashSet[string]]::new($script:PathComparer)
        foreach ($path in $baseline) {
            [void]$allowed.Add($path)
        }
        $unexpected = @($x64 | Where-Object { -not $allowed.Contains($_) })
        if ($unexpected.Count -ne 0) {
            Throw-ValidationError $script:ExitStatic "architecture" (
                "Preview rejects unexpected x64 payload files: " +
                ($unexpected -join ", "))
        }
    }
    $script:ReportData.readyForFinal = (
        $LockContext.Unresolved.Count -eq 0 -and $x64.Count -eq 0 -and
        $nonArm64Closure.Count -eq 0)
}

function Assert-AbsoluteObservedPath {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string] $Context
    )

    if ($Value -isnot [string] -or
        $Value -notmatch "^[A-Za-z]:\\" -or
        $Value -match "^(?i)\\\\[?.]\\" -or $Value.StartsWith("\\") -or
        $Value.Contains("..\") -or $Value.Contains("\..")) {
        Throw-ValidationError $script:ExitRuntime "runtime-path" (
            "$Context must be a normalized local absolute Windows path")
    }
    $full = [IO.Path]::GetFullPath($Value)
    if ((-not (Test-OrdinalStringEqual ($full) ($Value.TrimEnd("\"))))) {
        Throw-ValidationError $script:ExitRuntime "runtime-path" (
            "$Context is not canonical: '$Value'")
    }
    if ($script:PathComparer.Equals($full, "C:\msys64") -or
        $full.StartsWith(
            "C:\msys64\",
            [StringComparison]::OrdinalIgnoreCase)) {
        Throw-ValidationError $script:ExitRuntime "runtime-path" (
            "$Context cannot use shared C:\msys64")
    }
    return $full
}

function Get-ObservedClassification {
    param(
        [Parameter(Mandatory = $true)][string] $ObservedPath,
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $PayloadContext,
        [Parameter(Mandatory = $true)][string] $Context
    )

    $rootPrefix = "$RootPath\"
    if ($ObservedPath.StartsWith(
        $rootPrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $ObservedPath.Substring($rootPrefix.Length).Replace("\", "/")
        Assert-NormalizedPath $relative $Context `
            -ExitCode $script:ExitRuntime
        if (-not $PayloadContext.EntryMap.ContainsKey($relative.ToLowerInvariant())) {
            Throw-ValidationError $script:ExitRuntime "runtime-path" (
                "$Context is not in the payload manifest: '$ObservedPath'")
        }
        $entry = $PayloadContext.EntryMap[$relative.ToLowerInvariant()]
        if ((-not (Test-OrdinalStringEqual ($entry.type) ("file")))) {
            Throw-ValidationError $script:ExitRuntime "runtime-path" (
                "$Context does not reference a file")
        }
        return [ordered]@{
            Sha256 = $entry.sha256
            Architecture =
                $PayloadContext.ClassificationMap[
                    $relative.ToLowerInvariant()].architecture
            Personality =
                $PayloadContext.ClassificationMap[
                    $relative.ToLowerInvariant()].personality
        }
    }
    $trustedWindowsRoots = @(
        "C:\Windows\System32",
        "C:\Windows\SysArm32",
        "C:\Windows\WinSxS")
    if (@($trustedWindowsRoots | Where-Object {
        Test-PathWithin $_ $ObservedPath
    }).Count -ne 0) {
        if (-not [IO.File]::Exists($ObservedPath)) {
            Throw-ValidationError $script:ExitRuntime "runtime-path" (
                "$Context Windows system module does not exist")
        }
        $classification = Get-PeClassification $ObservedPath $ObservedPath
        return [ordered]@{
            Sha256 = Get-FileSha256 $ObservedPath
            Architecture = $classification.architecture
            Personality = $classification.personality
        }
    }
    if ($ObservedPath.StartsWith(
        "C:\Windows\",
        [StringComparison]::OrdinalIgnoreCase)) {
        Throw-ValidationError $script:ExitRuntime "external-module" (
            "$Context is outside the trusted Windows system directories: " +
            "'$ObservedPath'")
    }
    Throw-ValidationError $script:ExitRuntime "external-module" (
        "$Context is outside the staged root and trusted Windows system " +
        "directories: '$ObservedPath'")
}

function Assert-AssemblyEvidenceContract {
    param(
        [Parameter(Mandatory = $true)] $AssemblyObject,
        [Parameter(Mandatory = $true)][string] $SourceLockSha256,
        [Parameter(Mandatory = $true)][string] $LockSha256,
        [Parameter(Mandatory = $true)][string] $ProvenanceSha256,
        [Parameter(Mandatory = $true)][string] $PayloadSha256,
        [Parameter(Mandatory = $true)][string] $RootInventorySha256,
        [Parameter(Mandatory = $true)][string] $StaticReportSha256
    )

    Assert-ExactProperties $AssemblyObject @(
        "schemaVersion", "previewId", "sourceLockSha256", "lockSha256", "provenanceSha256",
        "payloadManifestSha256", "rootInventorySha256", "staticReportSha256",
        "host", "observedUtc", "externalObservation") "assembly evidence" `
        $script:ExitRuntime
    Assert-SchemaVersion $AssemblyObject "assembly evidence" $script:ExitRuntime
    if ($AssemblyObject.previewId -isnot [string] -or
        $AssemblyObject.previewId -cnotmatch
            "^[a-z0-9][a-z0-9.-]{0,127}$") {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "assembly evidence previewId must be a stable lowercase identifier")
    }
    foreach ($binding in @(
        @("sourceLockSha256", $SourceLockSha256),
        @("lockSha256", $LockSha256),
        @("provenanceSha256", $ProvenanceSha256),
        @("payloadManifestSha256", $PayloadSha256),
        @("rootInventorySha256", $RootInventorySha256),
        @("staticReportSha256", $StaticReportSha256))) {
        Assert-LowerSha256 $AssemblyObject.($binding[0]) `
            "assembly evidence.$($binding[0])" $script:ExitRuntime
        if ((-not (Test-OrdinalStringEqual ($AssemblyObject.($binding[0])) ($binding[1])))) {
            Throw-ValidationError $script:ExitRuntime "digest" (
                "assembly evidence $($binding[0]) does not match its bound input")
        }
    }
    Assert-ExactProperties $AssemblyObject.host @(
        "os", "architecture", "processArchitecture") `
        "assembly evidence.host" $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($AssemblyObject.host.os) ("Windows"))) -or
        (-not (Test-OrdinalStringInCollection ($AssemblyObject.host.architecture) (@("AMD64", "ARM64")))) -or
        (-not (Test-OrdinalStringInCollection ($AssemblyObject.host.processArchitecture) (@("AMD64", "ARM64"))))) {
        Throw-ValidationError $script:ExitRuntime "host" (
            "assembly evidence host/process architecture must be Windows AMD64 or ARM64")
    }
    Assert-UtcTimestamp $AssemblyObject.observedUtc `
        "assembly evidence.observedUtc" $script:ExitRuntime
    Assert-ExternalObservation $AssemblyObject.externalObservation `
        $script:ExitRuntime
    if ([DateTimeOffset]::Parse($AssemblyObject.observedUtc) -lt
        [DateTimeOffset]::Parse(
            $AssemblyObject.externalObservation.cutoffUtc)) {
        Throw-ValidationError $script:ExitRuntime "observation" (
            "assembly observation time precedes its pre-assembly cutoff")
    }
    return [ordered]@{
        PreviewId = $AssemblyObject.previewId
    }
}

function Assert-RuntimeContract {
    param(
        [Parameter(Mandatory = $true)] $RuntimeObject,
        [Parameter(Mandatory = $true)][string] $SourceLockSha256,
        [Parameter(Mandatory = $true)][string] $LockSha256,
        [Parameter(Mandatory = $true)][string] $ProvenanceSha256,
        [Parameter(Mandatory = $true)][string] $PayloadSha256,
        [Parameter(Mandatory = $true)] $LockContext,
        [Parameter(Mandatory = $true)] $ProvenanceContext,
        [Parameter(Mandatory = $true)] $PayloadContext,
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $AssemblyContext,
        [Parameter(Mandatory = $true)][string] $StaticReportSha256
    )

    Assert-ExactProperties $RuntimeObject @(
        "schemaVersion", "previewId", "admissionMode", "sourceLockSha256", "lockSha256",
        "provenanceSha256", "payloadManifestSha256", "rootInventorySha256",
        "staticReportSha256", "validator", "host", "collector",
        "collectedUtc", "scenarios") `
        "runtime evidence" $script:ExitRuntime
    Assert-SchemaVersion $RuntimeObject "runtime evidence" $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($RuntimeObject.previewId) ($AssemblyContext.PreviewId)))) {
        Throw-ValidationError $script:ExitRuntime "identity" (
            "runtime evidence previewId does not match assembly evidence")
    }
    if ((-not (Test-OrdinalStringInCollection ($RuntimeObject.admissionMode) (@("Preview", "Final"))))) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "runtime evidence admissionMode must be Preview or Final")
    }
    foreach ($digest in @(
        "lockSha256", "provenanceSha256", "payloadManifestSha256",
        "rootInventorySha256", "staticReportSha256")) {
        Assert-LowerSha256 $RuntimeObject.$digest "runtime evidence.$digest" `
            $script:ExitRuntime
    }
    foreach ($binding in @(
        @("sourceLockSha256", $SourceLockSha256),
        @("lockSha256", $LockSha256),
        @("provenanceSha256", $ProvenanceSha256),
        @("payloadManifestSha256", $PayloadSha256),
        @("rootInventorySha256", $PayloadContext.Inventory.Sha256),
        @("staticReportSha256", $StaticReportSha256))) {
        if ((-not (Test-OrdinalStringEqual ($RuntimeObject.($binding[0])) ($binding[1])))) {
            Throw-ValidationError $script:ExitRuntime "digest" (
                "runtime evidence $($binding[0]) does not match its bound input " +
                "(recorded=$($RuntimeObject.($binding[0])) actual=$($binding[1]))")
        }
    }
    Assert-ExactProperties $RuntimeObject.host @("os", "architecture") `
        "runtime evidence.host" $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($RuntimeObject.host.os) ("Windows"))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.host.architecture) ("ARM64")))) {
        Throw-ValidationError $script:ExitRuntime "host" (
            "runtime evidence host must be native Windows ARM64")
    }
    Assert-ExactProperties $RuntimeObject.validator @(
        "repository", "commit", "path", "bytes", "sha256", "mode") `
        "runtime evidence.validator" `
        $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($RuntimeObject.validator.repository) ("crutkas/build-extra"))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.validator.path) ("validate-arm64-bundle.ps1"))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.validator.mode) ("Runtime")))) {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "runtime evidence validator repository/mode is invalid")
    }
    Assert-LowerCommit $RuntimeObject.validator.commit `
        "runtime evidence.validator.commit" $script:ExitRuntime
    Assert-JsonInteger $RuntimeObject.validator.bytes `
        "runtime evidence.validator.bytes" 1 $script:ExitRuntime
    Assert-LowerSha256 $RuntimeObject.validator.sha256 `
        "runtime evidence.validator.sha256" $script:ExitRuntime
    $checkout = Get-AuthoritativeCheckout $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($RuntimeObject.validator.commit) ($checkout.Head)))) {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "runtime evidence validator commit must equal the checked-out " +
            "authoritative branch HEAD")
    }
    $claimedBlob = @(& git -C $checkout.Root rev-parse (
        "$($RuntimeObject.validator.commit):validate-arm64-bundle.ps1") 2>$null)
    $currentBlob = @(& git -C $checkout.Root hash-object $PSCommandPath 2>$null)
    $currentBytes = [IO.FileInfo]::new($PSCommandPath).Length
    $currentSha256 = Get-FileSha256 $PSCommandPath
    if ($LASTEXITCODE -ne 0 -or $claimedBlob.Count -ne 1 -or
        $currentBlob.Count -ne 1 -or
        (-not (Test-OrdinalStringEqual ($claimedBlob[0].Trim()) ($currentBlob[0].Trim()))) -or
        [long]$RuntimeObject.validator.bytes -ne $currentBytes -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.validator.sha256) ($currentSha256)))) {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "runtime evidence validator identity does not match the committed executable")
    }
    Assert-ExactProperties $RuntimeObject.collector @(
        "inputId", "repository", "commit", "sourcePath", "url", "bytes",
        "sha256", "method") `
        "runtime evidence.collector" $script:ExitRuntime
    if (-not $LockContext.InputMap.ContainsKey(
        [string]$RuntimeObject.collector.inputId)) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector inputId does not resolve in the canonical lock")
    }
    $collectorInput =
        $LockContext.InputMap[[string]$RuntimeObject.collector.inputId]
    if ((-not (Test-OrdinalStringEqual ($collectorInput.status) ("resolved"))) -or
        (-not (Test-OrdinalStringEqual ($collectorInput.role) ("validation-tool"))) -or
        (-not (Test-OrdinalStringEqual ($collectorInput.resolution.method) ("github-raw-commit"))) -or
        $null -eq $collectorInput.release -or
        $null -eq $collectorInput.asset -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.collector.method) ("ETW-Kernel-Process-ImageLoad")))) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector must bind a resolved raw-commit validation-tool input")
    }
    Assert-LowerCommit $RuntimeObject.collector.commit `
        "runtime evidence.collector.commit" $script:ExitRuntime
    Assert-NormalizedPath $RuntimeObject.collector.sourcePath `
        "runtime evidence.collector.sourcePath" -ExitCode $script:ExitRuntime
    Assert-LowerSha256 $RuntimeObject.collector.sha256 `
        "runtime evidence.collector.sha256" $script:ExitRuntime
    Assert-JsonInteger $RuntimeObject.collector.bytes `
        "runtime evidence.collector.bytes" 1 $script:ExitRuntime
    if ((-not (Test-OrdinalStringEqual ($RuntimeObject.collector.repository) ($collectorInput.release.repository))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.collector.commit) ($collectorInput.release.targetCommit))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.collector.sourcePath) ($collectorInput.release.sourcePath))) -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.collector.url) ($collectorInput.asset.url))) -or
        [long]$RuntimeObject.collector.bytes -ne
            [long]$collectorInput.asset.bytes -or
        (-not (Test-OrdinalStringEqual ($RuntimeObject.collector.sha256) ($collectorInput.asset.sha256)))) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector identity differs from its canonical lock input")
    }
    $collectorMembers =
        $ProvenanceContext.ArchiveByInput[$collectorInput.id]
    if ($null -eq $collectorMembers -or
        -not $collectorMembers.ContainsKey(
            $RuntimeObject.collector.sourcePath.ToLowerInvariant())) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector sourcePath is absent from provenance")
    }
    $collectorMember = $collectorMembers[
        $RuntimeObject.collector.sourcePath.ToLowerInvariant()]
    if ((-not (Test-OrdinalStringEqual ($collectorMember.type) ("file"))) -or
        $collectorMember.selected -ne $false -or
        $null -ne $collectorMember.destinationPath -or
        [long]$collectorMember.bytes -ne
            [long]$RuntimeObject.collector.bytes -or
        (-not (Test-OrdinalStringEqual ($collectorMember.sha256) ($RuntimeObject.collector.sha256)))) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector identity differs from its provenance archive member")
    }
    Assert-UtcTimestamp $RuntimeObject.collectedUtc `
        "runtime evidence.collectedUtc" $script:ExitRuntime

    Assert-JsonArray $RuntimeObject.scenarios `
        "runtime evidence.scenarios" $script:ExitRuntime
    $scenarios = @($RuntimeObject.scenarios)
    if ($scenarios.Count -ne $script:RequiredScenarios.Count) {
        Throw-ValidationError $script:ExitRuntime "scenario" (
            "runtime evidence must contain exactly the required scenarios")
    }
    $scenarioNames = [Collections.Generic.HashSet[string]]::new(
        $script:PathComparer)
    $instances = [Collections.Generic.HashSet[string]]::new(
        $script:PathComparer)
    $pidStarts = [Collections.Generic.HashSet[string]]::new(
        $script:PathComparer)
    $runtimeSummary = @()
    $expectedScenarioNames = @($script:RequiredScenarios.Keys)
    for ($scenarioIndex = 0;
        $scenarioIndex -lt $scenarios.Count;
        $scenarioIndex++) {
        $scenario = $scenarios[$scenarioIndex]
        Assert-ExactProperties $scenario @(
            "id", "status", "reason", "command", "behavior", "trace") `
            "runtime scenario" $script:ExitRuntime
        if (-not $scenarioNames.Add($scenario.id) -or
            -not (Test-OrdinalStringInCollection `
                $scenario.id @($script:RequiredScenarios.Keys))) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenario is unknown, duplicate, or case-colliding: '$($scenario.id)'")
        }
        if ((-not (Test-OrdinalStringEqual ($scenario.id) ($expectedScenarioNames[$scenarioIndex])))) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenarios must use the canonical order")
        }
        Assert-JsonArray $scenario.command `
            "runtime scenario '$($scenario.id)'.command" $script:ExitRuntime
        $command = @($scenario.command)
        if ($command.Count -eq 0 -or
            @($command | Where-Object {
                $_ -isnot [string] -or [string]::IsNullOrEmpty($_)
            }).Count -ne 0) {
            Throw-ValidationError $script:ExitRuntime "command" (
                "runtime scenario '$($scenario.id)' needs an exact command vector")
        }
        $commandContract = $script:RequiredCommandContracts[$scenario.id]
        $expectedCommand = @(
            (Join-Path $RootPath (
                $commandContract.executable.Replace("/", "\")))) +
            @($commandContract.arguments)
        if ($command.Count -ne $expectedCommand.Count) {
            Throw-ValidationError $script:ExitRuntime "command" (
                "runtime scenario '$($scenario.id)' command must match its " +
                "closed required argument vector")
        }
        for ($argumentIndex = 0;
            $argumentIndex -lt $expectedCommand.Count;
            $argumentIndex++) {
            if ((-not (Test-OrdinalStringEqual ($command[$argumentIndex]) ($expectedCommand[$argumentIndex])))) {
                Throw-ValidationError $script:ExitRuntime "command" (
                    "runtime scenario '$($scenario.id)' command must match its " +
                    "closed required argument vector")
            }
        }
        if ((Test-OrdinalStringEqual ($scenario.status) ("unresolved"))) {
            if ((-not (Test-OrdinalStringEqual ($RuntimeObject.admissionMode) ("Preview"))) -or
                $scenario.reason -isnot [string] -or
                [string]::IsNullOrWhiteSpace($scenario.reason) -or
                $null -ne $scenario.behavior -or $null -ne $scenario.trace) {
                Throw-ValidationError $script:ExitRuntime "scenario" (
                    "only Preview admission may carry a reason-only unresolved scenario")
            }
            $runtimeSummary += [ordered]@{
                id = $scenario.id
                status = "unresolved"
            }
            continue
        }
        if ((-not (Test-OrdinalStringEqual ($scenario.status) ("pass"))) -or $null -ne $scenario.reason) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenario '$($scenario.id)' must pass")
        }
        Assert-ExactProperties $scenario.behavior @(
            "operation", "passed", "exitCode") `
            "runtime scenario '$($scenario.id)'.behavior" $script:ExitRuntime
        Assert-JsonInteger $scenario.behavior.exitCode `
            "runtime scenario '$($scenario.id)'.behavior.exitCode" 0 `
            $script:ExitRuntime
        if ((-not (Test-OrdinalStringEqual ($scenario.behavior.operation) ($script:RequiredOperations[$scenario.id]))) -or
            $scenario.behavior.passed -ne $true -or
            [long]$scenario.behavior.exitCode -ne 0) {
            Throw-ValidationError $script:ExitRuntime "behavior" (
                "runtime scenario '$($scenario.id)' lacks its required successful behavior proof")
        }
        $trace = $scenario.trace
        Assert-ExactProperties $trace @(
            "complete", "processEventsComplete", "imageLoadEventsComplete",
            "processTreeComplete", "lostEvents", "startUtc", "endUtc",
            "processes") `
            "runtime scenario '$($scenario.id)'.trace" $script:ExitRuntime
        Assert-JsonInteger $trace.lostEvents `
            "runtime scenario '$($scenario.id)'.trace.lostEvents" 0 `
            $script:ExitRuntime
        if ($trace.complete -ne $true -or
            $trace.processEventsComplete -ne $true -or
            $trace.imageLoadEventsComplete -ne $true -or
            $trace.processTreeComplete -ne $true -or
            [long]$trace.lostEvents -ne 0) {
            Throw-ValidationError $script:ExitRuntime "trace" (
                "runtime scenario '$($scenario.id)' has incomplete or lossy ETW evidence")
        }
        Assert-UtcTimestamp $trace.startUtc `
            "runtime scenario '$($scenario.id)'.trace.startUtc" `
            $script:ExitRuntime
        Assert-UtcTimestamp $trace.endUtc `
            "runtime scenario '$($scenario.id)'.trace.endUtc" `
            $script:ExitRuntime
        if ([DateTimeOffset]::Parse($trace.endUtc) -le
            [DateTimeOffset]::Parse($trace.startUtc)) {
            Throw-ValidationError $script:ExitRuntime "trace" (
                "runtime scenario '$($scenario.id)' trace times are invalid")
        }
        Assert-JsonArray $trace.processes `
            "runtime scenario '$($scenario.id)'.trace.processes" `
            $script:ExitRuntime
        $processes = @($trace.processes)
        if ($processes.Count -eq 0) {
            Throw-ValidationError $script:ExitRuntime "trace" (
                "runtime scenario '$($scenario.id)' observed no processes")
        }
        $roleProcesses = @($processes | Where-Object {
            Test-OrdinalStringEqual $_.role "role"
        })
        if ($roleProcesses.Count -ne 1) {
            Throw-ValidationError $script:ExitRuntime "role" (
                "runtime scenario '$($scenario.id)' needs exactly one role process")
        }
        $scenarioInstances = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $parentLinks = @()
        foreach ($process in $processes) {
            Assert-ExactProperties $process @(
                "instanceId", "parentInstanceId", "processId", "startUtc",
                "endUtc", "role", "path", "sha256", "architecture", "personality",
                "modulesComplete", "modules") `
                "runtime process" $script:ExitRuntime
            if ($process.instanceId -isnot [string] -or
                [string]::IsNullOrWhiteSpace($process.instanceId) -or
                -not $instances.Add($process.instanceId) -or
                -not $scenarioInstances.Add($process.instanceId)) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime process instance IDs must be globally unique")
            }
            Assert-JsonInteger $process.processId `
                "runtime process '$($process.instanceId)'.processId" 1 `
                $script:ExitRuntime
            if ((-not (Test-OrdinalStringInCollection ($process.role) (@("role", "support"))))) {
                Throw-ValidationError $script:ExitRuntime "process" (
                    "runtime process '$($process.instanceId)' has invalid PID/role")
            }
            Assert-UtcTimestamp $process.startUtc `
                "runtime process '$($process.instanceId)'.startUtc" `
                $script:ExitRuntime
            Assert-UtcTimestamp $process.endUtc `
                "runtime process '$($process.instanceId)'.endUtc" `
                $script:ExitRuntime
            if ([DateTimeOffset]::Parse($process.endUtc) -le
                [DateTimeOffset]::Parse($process.startUtc) -or
                -not $pidStarts.Add(
                    "$($process.processId)`0$($process.startUtc)")) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime process PID/start identity is invalid or reused")
            }
            if ([DateTimeOffset]::Parse($process.startUtc) -lt
                    [DateTimeOffset]::Parse($trace.startUtc) -or
                [DateTimeOffset]::Parse($process.startUtc) -eq
                    [DateTimeOffset]::Parse($trace.startUtc) -or
                [DateTimeOffset]::Parse($process.endUtc) -gt
                    [DateTimeOffset]::Parse($trace.endUtc) -or
                [DateTimeOffset]::Parse($process.endUtc) -eq
                    [DateTimeOffset]::Parse($trace.endUtc)) {
                Throw-ValidationError $script:ExitRuntime "trace" (
                    "runtime process '$($process.instanceId)' lies outside its trace interval")
            }
            if ((Test-OrdinalStringEqual ($process.role) ("role"))) {
                if ($null -ne $process.parentInstanceId) {
                    Throw-ValidationError $script:ExitRuntime "instance" (
                        "runtime role process must have parentInstanceId=null")
                }
            } else {
                if ($process.parentInstanceId -isnot [string] -or
                    [string]::IsNullOrWhiteSpace($process.parentInstanceId)) {
                    Throw-ValidationError $script:ExitRuntime "instance" (
                        "runtime support process must identify its parent instance")
                }
                $parentLinks += [ordered]@{
                    child = $process.instanceId
                    parent = $process.parentInstanceId
                }
            }
            $observedPath = Assert-AbsoluteObservedPath $process.path `
                "runtime process '$($process.instanceId)'.path"
            $actual = Get-ObservedClassification $observedPath $RootPath `
                $PayloadContext "runtime process '$($process.instanceId)'"
            Assert-LowerSha256 $process.sha256 `
                "runtime process '$($process.instanceId)'.sha256" `
                $script:ExitRuntime
            if ((-not (Test-OrdinalStringEqual ($process.sha256) ($actual.Sha256))) -or
                (-not (Test-OrdinalStringEqual ($process.architecture) ($actual.Architecture))) -or
                (-not (Test-OrdinalStringEqual ($process.personality) ($actual.Personality)))) {
                Throw-ValidationError $script:ExitRuntime "process" (
                    "runtime process '$($process.instanceId)' identity is not authoritative")
            }
            if ((-not (Test-OrdinalStringInCollection ($process.architecture) (@(
                    "arm64", "arm64ec", "anycpu")))) -or
                (-not (Test-OrdinalStringInCollection ($process.personality) (@(
                    "msys", "mingw", "managed"))))) {
                Throw-ValidationError $script:ExitRuntime "architecture" (
                    "runtime process '$($process.instanceId)' violates architecture/personality policy")
            }
            if ($process.modulesComplete -ne $true) {
                Throw-ValidationError $script:ExitRuntime "trace" (
                    "runtime process '$($process.instanceId)' module trace is incomplete")
            }
            Assert-JsonArray $process.modules `
                "runtime process '$($process.instanceId)'.modules" `
                $script:ExitRuntime
            $modules = @($process.modules)
            if ($modules.Count -eq 0) {
                Throw-ValidationError $script:ExitRuntime "trace" (
                    "runtime process '$($process.instanceId)' has no image-load modules")
            }
            $modulePaths = [Collections.Generic.HashSet[string]]::new(
                $script:PathComparer)
            foreach ($module in $modules) {
                Assert-ExactProperties $module @(
                    "path", "sha256", "architecture", "personality") `
                    "runtime module" $script:ExitRuntime
                $modulePath = Assert-AbsoluteObservedPath $module.path `
                    "runtime module path"
                if (-not $modulePaths.Add($modulePath)) {
                    Throw-ValidationError $script:ExitRuntime "collision" (
                        "runtime process '$($process.instanceId)' repeats a module path")
                }
                $moduleActual = Get-ObservedClassification $modulePath `
                    $RootPath $PayloadContext "runtime module"
                Assert-LowerSha256 $module.sha256 "runtime module.sha256" `
                    $script:ExitRuntime
                if ((-not (Test-OrdinalStringEqual ($module.sha256) ($moduleActual.Sha256))) -or
                    (-not (Test-OrdinalStringEqual ($module.architecture) ($moduleActual.Architecture))) -or
                    (-not (Test-OrdinalStringEqual ($module.personality) ($moduleActual.Personality)))) {
                    Throw-ValidationError $script:ExitRuntime "module" (
                        "runtime module '$modulePath' identity is not authoritative")
                }
                if ((-not (Test-OrdinalStringInCollection ($module.architecture) (@(
                        "arm64", "arm64ec", "anycpu")))) -or
                    (-not (Test-OrdinalStringInCollection ($module.personality) (@(
                        "msys", "mingw", "managed"))))) {
                    Throw-ValidationError $script:ExitRuntime "architecture" (
                        "runtime module '$modulePath' violates architecture/personality policy")
                }
            }
        }
        foreach ($link in $parentLinks) {
            if (-not $scenarioInstances.Contains($link.parent) -or
                $script:PathComparer.Equals($link.child, $link.parent)) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime support process '$($link.child)' has an invalid parent")
            }
        }
        $parentByChild =
            [Collections.Generic.Dictionary[string, string]]::new(
                [StringComparer]::Ordinal)
        foreach ($link in $parentLinks) {
            $parentByChild[$link.child] = $link.parent
        }
        foreach ($link in $parentLinks) {
            $visited = [Collections.Generic.HashSet[string]]::new(
                $script:PathComparer)
            $cursor = $link.child
            while ($parentByChild.ContainsKey($cursor)) {
                if (-not $visited.Add($cursor)) {
                    Throw-ValidationError $script:ExitRuntime "instance" (
                        "runtime process tree contains a parent cycle")
                }
                $cursor = $parentByChild[$cursor]
            }
            if ((-not (Test-OrdinalStringEqual ($cursor) ($roleProcesses[0].instanceId)))) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime support process '$($link.child)' is not in the role process tree")
            }
        }
        $expectedPersonality = $script:RequiredScenarios[$scenario.id]
        if ((-not (Test-OrdinalStringEqual ($roleProcesses[0].personality) ($expectedPersonality)))) {
            Throw-ValidationError $script:ExitRuntime "role" (
                "runtime scenario '$($scenario.id)' role process must be $expectedPersonality")
        }
        if ((-not (Test-OrdinalStringEqual ($command[0]) ($roleProcesses[0].path)))) {
            Throw-ValidationError $script:ExitRuntime "command" (
                "runtime scenario '$($scenario.id)' command does not start with its role process")
        }
        $runtimeSummary += [ordered]@{
            id = $scenario.id
            status = "pass"
        }
    }
    foreach ($required in $script:RequiredScenarios.Keys) {
        if (-not $scenarioNames.Contains($required)) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime evidence is missing required scenario '$required'")
        }
    }
    $script:ReportData.summary.runtimeScenarios = $scenarios.Count
    $script:ReportData.runtime = [ordered]@{
        previewId = $RuntimeObject.previewId
        admissionMode = $RuntimeObject.admissionMode
        validator = [ordered]@{
            repository = $RuntimeObject.validator.repository
            commit = $RuntimeObject.validator.commit
            path = $RuntimeObject.validator.path
            bytes = [long]$RuntimeObject.validator.bytes
            sha256 = $RuntimeObject.validator.sha256
            mode = $RuntimeObject.validator.mode
        }
        scenarios = $runtimeSummary
    }
}

$exitCode = 0
try {
    Initialize-SafeReportPath
    if ($PSVersionTable.PSVersion -lt [Version]"7.5") {
        Throw-ValidationError $script:ExitScanner "runtime" (
            "validate-arm64-bundle.ps1 requires PowerShell 7.5 or newer")
    }
    if (Test-OrdinalStringEqual $Mode "Runtime") {
        if ([string]::IsNullOrWhiteSpace($AssemblyEvidence)) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "-AssemblyEvidence is required only for -Mode Runtime")
        }
        if ([string]::IsNullOrWhiteSpace($RuntimeEvidence)) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "-RuntimeEvidence is required only for -Mode Runtime")
        }
        if ([string]::IsNullOrWhiteSpace($StaticReport)) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "-StaticReport is required only for -Mode Runtime")
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($StaticReport)) {
        Throw-ValidationError $script:ExitContract "schema" (
            "-StaticReport applies only to -Mode Runtime")
    }

    $rootPath = Assert-LocalSafeRoot $Root "Root"
    $lockDocument = Read-JsonDocument $Lock "lock"
    $provenanceDocument = Read-JsonDocument $Provenance "provenance"
    $payloadDocument = Read-JsonDocument $PayloadManifest "payload manifest"
    $script:ReportData.digests.lockSha256 = $lockDocument.Sha256
    $script:ReportData.digests.provenanceSha256 = $provenanceDocument.Sha256
    $script:ReportData.digests.payloadManifestSha256 = $payloadDocument.Sha256

    $runtimeDocument = $null
    $assemblyDocument = $null
    $admissionMode = $Mode
    if (Test-OrdinalStringEqual $Mode "Runtime") {
        $assemblyDocument = Read-JsonDocument $AssemblyEvidence `
            "assembly evidence" $script:ExitRuntime
        $runtimeDocument = Read-JsonDocument $RuntimeEvidence `
            "runtime evidence" $script:ExitRuntime
        $script:ReportData.digests.assemblyEvidenceSha256 =
            $assemblyDocument.Sha256
        $script:ReportData.digests.runtimeEvidenceSha256 =
            $runtimeDocument.Sha256
        $admissionMode = Get-RequiredProperty $runtimeDocument.Object `
            "admissionMode" "runtime evidence" $script:ExitRuntime
        if ((-not (Test-OrdinalStringInCollection ($admissionMode) (@("Preview", "Final"))))) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "runtime evidence admissionMode must be Preview or Final")
        }
        $script:ReportData.admissionMode = $admissionMode
    }

    $lockContext = Read-LockContract `
        $lockDocument.Object $lockDocument $rootPath
    $script:ReportData.digests.sourceLockSha256 =
        $lockContext.SourceLock.sha256
    $baseTreeManifestSha256 = @(
        $lockContext.BaseTrees.Values |
            ForEach-Object { $_.Sha256 })
    $script:ReportData.digests.baseTreeManifestSha256 =
        if ($baseTreeManifestSha256.Count -eq 0) {
            $null
        } else {
            $baseTreeManifestSha256[0]
        }
    $provenanceContext = Read-ProvenanceContract `
        $provenanceDocument.Object $lockContext $lockDocument.Sha256
    $payloadContext = Read-PayloadContract `
        $payloadDocument.Object `
        $lockDocument.Sha256 `
        $provenanceDocument.Sha256 `
        $provenanceContext `
        $rootPath
    Assert-PseudoReloc $provenanceContext $payloadContext $rootPath
    Assert-StaticPolicy $admissionMode $lockContext $payloadContext

    if (Test-OrdinalStringEqual $Mode "Runtime") {
        if (-not $script:ReportData.readyForFinal) {
            Throw-ValidationError $script:ExitRuntime "admission" (
                "Runtime requires a static state that is readyForFinal")
        }
        $staticReportContext = Assert-StaticReportContract `
            $StaticReport `
            $lockContext.SourceLock.sha256 `
            $lockDocument.Sha256 `
            $provenanceDocument.Sha256 `
            $payloadDocument.Sha256 `
            $payloadContext.Inventory.Sha256
        $script:ReportData.digests.staticReportSha256 =
            $staticReportContext.Sha256
        $assemblyContext = Assert-AssemblyEvidenceContract `
            $assemblyDocument.Object `
            $lockContext.SourceLock.sha256 `
            $lockDocument.Sha256 `
            $provenanceDocument.Sha256 `
            $payloadDocument.Sha256 `
            $payloadContext.Inventory.Sha256 `
            $staticReportContext.Sha256
        Assert-RuntimeContract `
            $runtimeDocument.Object `
            $lockContext.SourceLock.sha256 `
            $lockDocument.Sha256 `
            $provenanceDocument.Sha256 `
            $payloadDocument.Sha256 `
            $lockContext `
            $provenanceContext `
            $payloadContext `
            $rootPath `
            $assemblyContext `
            $staticReportContext.Sha256
    }
    if (-not (Write-ValidationReport 0 "pass")) {
        $exitCode = $script:ExitScanner
    }
} catch {
    $exitCode = $script:ExitScanner
    $category = "internal"
    if ($_.Exception.Data.Contains("ExitCode")) {
        $exitCode = [int]$_.Exception.Data["ExitCode"]
        $category = [string]$_.Exception.Data["Category"]
    }
    $script:ReportData.errors = @([ordered]@{
        category = $category
        message = $_.Exception.Message
    })
    [Console]::Error.WriteLine($_.Exception.Message)
    [void](Write-ValidationReport $exitCode "fail")
}
exit $exitCode
