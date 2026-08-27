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
$script:ScannerRelativePath = "arm64-validation/check-aarch64-pseudo-relocs.ps1"
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

function Assert-PropertyOrder {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string[]] $Names,
        [Parameter(Mandatory = $true)][string] $Context,
        [int] $ExitCode = $script:ExitContract
    )

    if ((@($Object.PSObject.Properties.Name) -join "`0") -cne
        ($Names -join "`0")) {
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
        if ($component -in @("", ".", "..")) {
            Throw-ValidationError $script:ExitContract "path" (
                "$Context contains traversal")
        }
    }
}
$script:SafeReportPath = $null
$script:ReportData = [ordered]@{
    schemaVersion = 1
    mode = $Mode
    admissionMode = if ($Mode -eq "Runtime") { $null } else { $Mode }
    result = "error"
    exitCode = $script:ExitScanner
    readyForFinal = $false
    digests = [ordered]@{
        sourceLockSha256 = $null
        lockSha256 = $null
        provenanceSha256 = $null
        payloadManifestSha256 = $null
        rootInventorySha256 = $null
        assemblyEvidenceSha256 = $null
        runtimeEvidenceSha256 = $null
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
        return
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
    } catch {
        [Console]::Error.WriteLine(
            "Could not write validation report '$Report': $($_.Exception.Message)")
    } finally {
        if ($null -ne $temporaryPath -and
            [IO.File]::Exists($temporaryPath)) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string] $Parent,
        [Parameter(Mandatory = $true)][string] $Candidate
    )

    $prefix = $Parent.TrimEnd("\") + "\"
    return $Candidate -ieq $Parent.TrimEnd("\") -or
        $Candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Initialize-SafeReportPath {
    $reportPath = [IO.Path]::GetFullPath($Report)
    if ($Report -match "^(?i)(\\\\|//|\\\\[?.]\\)" -or
        $reportPath -notmatch "^[A-Za-z]:\\") {
        Throw-ValidationError $script:ExitScanner "report" (
            "Report must be a local drive-qualified path")
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
    foreach ($inputPath in @(
        $Lock, $Provenance, $PayloadManifest, $AssemblyEvidence,
        $RuntimeEvidence, $PSCommandPath)) {
        if (-not [string]::IsNullOrWhiteSpace($inputPath) -and
            $reportPath -ieq [IO.Path]::GetFullPath($inputPath)) {
            Throw-ValidationError $script:ExitScanner "report" (
                "Report cannot overwrite a validator input or executable")
        }
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

    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (@(Compare-Object $expected $actual -SyncWindow 0 -CaseSensitive).
        Count -ne 0) {
        Throw-ValidationError $ExitCode "schema" (
            "$Context properties must be exactly: $($Names -join ', ')")
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
    if ($AllowDot -and $Value -ceq ".") {
        return
    }
    if ($Value -cne $Value.Normalize([Text.NormalizationForm]::FormC) -or
        $Value.Contains("\") -or $Value.StartsWith("/") -or
        $Value.StartsWith("//") -or $Value -match "^[A-Za-z]:" -or
        $Value -match "^(?i)(\\\\[?.]\\|//[?.]/)" -or
        $Value.Contains(":") -or $Value.Contains("`0") -or
        $Value.EndsWith("/") -or $Value.Contains("//")) {
        Throw-ValidationError $ExitCode "path" (
            "$Context is not a normalized relative slash path: '$Value'")
    }
    foreach ($component in $Value.Split("/")) {
        if ($component -in @("", ".", "..")) {
            Throw-ValidationError $ExitCode "path" (
                "$Context contains traversal or an empty component: '$Value'")
        }
        if (-not $AllowWildcards -and $component.IndexOfAny(@("*", "?")) -ge 0) {
            Throw-ValidationError $ExitCode "path" (
                "$Context contains wildcard characters: '$Value'")
        }
    }
    if ($Value -ieq "preview-evidence" -or
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
    if ($full -ieq "C:\msys64" -or
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
        $wildcard = [Management.Automation.WildcardPattern]::new(
            $pattern,
            [Management.Automation.WildcardOptions]::CultureInvariant)
        if ($wildcard.IsMatch($Path)) {
            return $true
        }
    }
    return $false
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
        $Release.repository -cne "git-for-windows/git" -and
        $Release.repository -cne "ip7z/7zip") {
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
        $uri.Scheme -cne "https") {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.asset.url must be an immutable HTTPS URL")
    }
    if (-not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context.asset.url cannot contain a query or fragment")
    }
    if ($Resolution.method -ceq "github-release") {
        Assert-ExactProperties $Release @(
            "repository", "tag", "targetCommit") "$Context.release"
        Assert-NoPlaceholder $Release.tag "$Context.release.tag"
        $expectedPath = (
            "/$($Release.repository)/releases/download/" +
            "$($Release.tag)/$($Asset.name)")
        if ($uri.Host -cne "github.com" -or
            [Uri]::UnescapeDataString($uri.AbsolutePath) -cne $expectedPath) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "$Context.asset.url does not bind its repository, tag, and asset name")
        }
    } elseif ($Resolution.method -ceq "github-raw-commit") {
        Assert-ExactProperties $Release @(
            "repository", "targetCommit", "sourcePath") "$Context.release"
        Assert-NormalizedPath $Release.sourcePath "$Context.release.sourcePath"
        $expectedPath = (
            "/$($Release.repository)/$($Release.targetCommit)/" +
            "$($Release.sourcePath)")
        if ($uri.Host -cne "raw.githubusercontent.com" -or
            [Uri]::UnescapeDataString($uri.AbsolutePath) -cne $expectedPath) {
            Throw-ValidationError $script:ExitContract "provenance" (
                "$Context.asset.url does not bind its repository, commit, and sourcePath")
        }
    } else {
        Throw-ValidationError $script:ExitContract "provenance" (
            "$Context uses an unsupported resolution method")
    }
}

function Test-IdentityEqual {
    param($Left, $Right)

    return (
        ($Left.release | ConvertTo-Json -Compress -Depth 20) -ceq
            ($Right.release | ConvertTo-Json -Compress -Depth 20) -and
        $Left.asset.url -ceq $Right.asset.url -and
        $Left.asset.name -ceq $Right.asset.name -and
        [long]$Left.asset.bytes -eq [long]$Right.asset.bytes -and
        $Left.asset.sha256 -ceq $Right.asset.sha256 -and
        ($Left.package | ConvertTo-Json -Compress -Depth 20) -ceq
            ($Right.package | ConvertTo-Json -Compress -Depth 20))
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
    if ($LockDocument.Path -ine $expectedLockPath) {
        Throw-ValidationError $script:ExitContract "path" (
            "canonical bundle lock must be preview-evidence/bundle-lock.v1.json")
    }
    Assert-ExactProperties $LockObject.sourceLock @("path", "sha256") `
        "lock.sourceLock"
    Assert-PropertyOrder $LockObject.sourceLock @("path", "sha256") `
        "lock.sourceLock"
    Assert-EvidenceRelativePath $LockObject.sourceLock.path `
        "lock.sourceLock.path"
    if ($LockObject.sourceLock.path -cne "preview-evidence/source-lock.json") {
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
        (Get-FileSha256 $sourceLockPath) -cne
            $LockObject.sourceLock.sha256) {
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
    $inputMap = @{}
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
        if ($input.role -cnotin @(
            "base-bundle", "payload", "validation-tool")) {
            Throw-ValidationError $script:ExitContract "schema" (
                "lock input '$($input.id)' has invalid role '$($input.role)'")
        }
        if ($input.status -ceq "unresolved") {
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
        if ($input.status -cne "resolved") {
            Throw-ValidationError $script:ExitContract "schema" (
                "lock input '$($input.id)' status must be resolved or unresolved")
        }
        foreach ($field in @(
            "resolution", "release", "asset", "overlay")) {
            if ($null -eq $input.$field) {
                Throw-ValidationError $script:ExitContract "provenance" (
                    "resolved input '$($input.id)' must define $field")
            }
        }
        Assert-ExactProperties $input.resolution @("method") `
            "lock input '$($input.id)'.resolution"
        if ($input.resolution.method -cnotin @(
            "github-release", "github-raw-commit")) {
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

        if ($null -ne $input.package) {
            Assert-ExactProperties $input.package @(
                "name", "version", "personality", "provides") `
                "lock input '$($input.id)'.package"
            Assert-NoPlaceholder $input.package.name `
                "lock input '$($input.id)'.package.name"
            Assert-NoPlaceholder $input.package.version `
                "lock input '$($input.id)'.package.version"
            if ($input.package.personality -cnotin @(
                "msys", "mingw", "managed", "mixed", "tool")) {
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
        if ($input.role -ceq "validation-tool") {
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
                    if ($destination -cne "." -and
                        $mapping.destinationPath -cne $destination -and
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
        $Observation.rootPath -cne "C:\msys64") {
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
        $Observation.before.log.sha256 -cne
            $Observation.after.log.sha256 -or
        [long]$Observation.before.database.files -ne
            [long]$Observation.after.database.files -or
        [long]$Observation.before.database.bytes -ne
            [long]$Observation.after.database.bytes -or
        $Observation.before.database.canonicalManifestSha256 -cne
            $Observation.after.database.canonicalManifestSha256) {
        Throw-ValidationError $ExitCode "provenance" (
            "external observation before/after snapshots differ")
    }
    foreach ($command in @($Observation.commands)) {
        if ($command -isnot [string]) {
            Throw-ValidationError $ExitCode "schema" (
                "external observation commands must be strings")
        }
        if ($command -match
            "(?i)(^|[\\/\s`"''])pacman(?:\.exe)?(?=$|[\s`"''])") {
            Throw-ValidationError $ExitCode "mutation-risk" (
                "external observation records a forbidden pacman command: '$command'")
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
    if ($ProvenanceObject.lockSha256 -cne $LockSha256) {
        Throw-ValidationError $script:ExitContract "digest" (
            "provenance lockSha256 does not match the lock")
    }
    Assert-JsonInteger $ProvenanceObject.sourceDateEpoch `
        "provenance.sourceDateEpoch" 0
    Assert-JsonArray $ProvenanceObject.nativeShellClosure `
        "provenance.nativeShellClosure"
    if ([long]$ProvenanceObject.sourceDateEpoch -ne
            $LockContext.SourceDateEpoch -or
        (@($ProvenanceObject.nativeShellClosure) -join "`0") -cne
            (@($LockContext.NativeShellClosure) -join "`0")) {
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
    $archiveByInput = @{}
    $selectedByDestination = @{}
    $provenanceInputIds = @()
    for ($index = 0; $index -lt $provenanceInputs.Count; $index++) {
        $entry = $provenanceInputs[$index]
        Assert-ExactProperties $entry @(
            "id", "release", "asset", "package", "archiveMembers") `
            "provenance.inputs[$index]"
        $provenanceInputIds += $entry.id
        if ($entry.id -cne $resolvedIds[$index] -or
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
        $memberMap = @{}
        $mappingBySource = @{}
        if ($lockInput.role -cne "validation-tool") {
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
            if ($member.type -cnotin @(
                "file", "directory", "symlink", "hardlink") -or
                $member.selected -isnot [bool]) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "archive member '$($member.sourceMember)' has invalid type/selected")
            }
            if ($member.type -ceq "file") {
                Assert-JsonInteger $member.bytes `
                    "archive member '$($member.sourceMember)'.bytes" 0
                Assert-LowerSha256 $member.sha256 `
                    "archive member '$($member.sourceMember)'.sha256"
                if ($null -ne $member.linkTarget) {
                    Throw-ValidationError $script:ExitContract "archive" (
                        "archive file '$($member.sourceMember)' must have linkTarget=null")
                }
            } elseif ($member.type -ceq "directory") {
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
            if ($lockInput.role -cne "validation-tool") {
                $expectedSelected = (
                    (Test-PatternMatch $member.sourceMember @($lockInput.overlay.include)) -and
                    -not (Test-PatternMatch $member.sourceMember @($lockInput.overlay.exclude)))
                if ($expectedSelected) {
                    $mappingKey = $member.sourceMember.ToLowerInvariant()
                    $expectedDestination = if (
                        $mappingBySource.ContainsKey($mappingKey)) {
                        $mappingBySource[$mappingKey]
                    } elseif ($lockInput.overlay.destination -ceq ".") {
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
                if ($member.destinationPath -cne $expectedDestination) {
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
            $_.type -in @("symlink", "hardlink")
        }) {
            $targetKey = $member.linkTarget.ToLowerInvariant()
            if (-not $memberMap.ContainsKey($targetKey) -or
                $memberMap[$targetKey].type -ceq "directory" -or
                [long]$memberMap[$targetKey].bytes -ne [long]$member.bytes -or
                $memberMap[$targetKey].sha256 -cne $member.sha256) {
                Throw-ValidationError $script:ExitContract "archive" (
                    "archive link '$($member.sourceMember)' has an invalid target identity")
            }
            $visitedLinks = [Collections.Generic.HashSet[string]]::new(
                $script:PathComparer)
            $cursor = $member
            while ($cursor.type -in @("symlink", "hardlink")) {
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
                } elseif ($lockInput.overlay.destination -ceq ".") {
                    $target.sourceMember
                } else {
                    "$($lockInput.overlay.destination)/$($target.sourceMember)"
                }
                $candidateKey = $member.destinationPath.ToLowerInvariant()
                $candidate = @($selectedByDestination[$candidateKey] |
                    Where-Object {
                        $_.inputId -ceq $entry.id -and
                        $_.sourceMember -ceq $member.sourceMember
                    })[0]
                $candidate.linkTarget = $targetDestination
            }
        }
        $archiveByInput[$entry.id] = $memberMap
    }

    $overlayOrder = @($ProvenanceObject.overlayOrder)
    Assert-JsonArray $ProvenanceObject.overlayOrder `
        "provenance.overlayOrder"
    $payloadIds = @($LockContext.Resolved |
        Where-Object role -CNE "validation-tool" |
        ForEach-Object { $_.id })
    if (($overlayOrder -join "`0") -cne ($payloadIds -join "`0")) {
        Throw-ValidationError $script:ExitContract "overlay" (
            "provenance.overlayOrder must contain each resolved payload input in lock order")
    }
    $orderMap = @{}
    for ($index = 0; $index -lt $overlayOrder.Count; $index++) {
        $orderMap[$overlayOrder[$index]] = $index
    }

    $expectedFinal = @{}
    $expectedReplacements = @{}
    foreach ($key in $selectedByDestination.Keys) {
        $candidates = @($selectedByDestination[$key] | Sort-Object {
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
    $finalMap = @{}
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
        if ($member.destinationPath -cne $expected.destinationPath -or
            $member.inputId -cne $expected.inputId -or
            $member.sourceMember -cne $expected.sourceMember -or
            $member.type -cne $expected.type -or
            [long]$member.bytes -ne $expected.bytes -or
            $member.sha256 -cne $expected.sha256 -or
            $member.linkTarget -cne $expected.linkTarget) {
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
            if ($replacement.$field -cne $expected.$field) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "provenance replacement for '$($replacement.destinationPath)' is incorrect")
            }
        }
    }

    foreach ($input in $LockContext.Resolved) {
        if ($null -eq $input.package) {
            continue
        }
        $provided = if ($input.role -cne "validation-tool") {
            @($finalMembers |
                Where-Object inputId -CEQ $input.id |
                ForEach-Object destinationPath)
        } else {
            @($archiveByInput[$input.id].Values |
                Where-Object type -CEQ "file" |
                ForEach-Object sourceMember)
        }
        foreach ($expectedProvide in @($input.package.provides)) {
            if ($provided -cnotcontains $expectedProvide) {
                Throw-ValidationError $script:ExitContract "ownership" (
                    "input '$($input.id)' is missing expected provide '$expectedProvide'")
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
    if ($pseudo.scanner.repository -cne $script:ScannerRepository -or
        $pseudo.scanner.commit -cne $script:ScannerCommit -or
        $pseudo.scanner.path -cne $script:ScannerSourcePath -or
        [long]$pseudo.scanner.bytes -ne $script:ScannerBytes -or
        $pseudo.scanner.sha256 -cne $script:ScannerSha256) {
        Throw-ValidationError $script:ExitContract "scanner" (
            "provenance pseudo-reloc scanner identity does not match the pinned source")
    }
    if (-not $LockContext.InputMap.ContainsKey($pseudo.toolInputId)) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc toolInputId does not exist in the lock")
    }
    $toolInput = $LockContext.InputMap[$pseudo.toolInputId]
    if ($toolInput.status -cne "resolved" -or
        $toolInput.role -cne "validation-tool" -or
        $toolInput.package.name -cne $script:ToolPackageName -or
        $toolInput.package.version -cne $script:ToolPackageVersion -or
        $toolInput.asset.sha256 -cne $script:ToolPackageSha256) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc tools are not bound to the pinned immutable package")
    }
    if ($pseudo.objdumpMember -cne $script:ObjdumpMember -or
        $pseudo.nmMember -cne $script:NmMember -or
        $pseudo.linkerMember -cne $script:LinkerMember) {
        Throw-ValidationError $script:ExitContract "tool" (
            "pseudo-reloc member paths do not match the pinned tool package")
    }
    $toolMembers = $archiveByInput[$pseudo.toolInputId]
    foreach ($memberPath in @(
        $script:ObjdumpMember, $script:NmMember, $script:LinkerMember)) {
        if (-not $toolMembers.ContainsKey($memberPath.ToLowerInvariant()) -or
            $toolMembers[$memberPath.ToLowerInvariant()].type -cne "file") {
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
            $member.sha256 -cne $pin[2]) {
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
    $hasMsys = $imports -ccontains "msys-2.0.dll"
    $hasCygwin = $imports -ccontains "cygwin1.dll"
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
    $names = @()
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
        $names += [IO.Path]::GetFullPath($candidate)
    }
    return $names
}

function Get-RootInventory {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $FinalMap
    )

    $members = @()
    foreach ($item in Get-ChildItem -LiteralPath $RootPath -Force -Recurse) {
        $relative = [IO.Path]::GetRelativePath(
            $RootPath,
            $item.FullName).Replace("\", "/")
        if ($relative -ieq "preview-evidence" -or
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
            if ($item.PSIsContainer -or $item.LinkType -cne "SymbolicLink") {
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
            # Every name of a multiply linked file reports LinkType HardLink,
            # so provenance decides which name is the canonical file and which
            # is the declared alias.
            $declared = $FinalMap[$relative.ToLowerInvariant()]
            if ($null -ne $declared -and [string]$declared.type -ceq "hardlink") {
                $type = "hardlink"
                $hardlinkTargets = @(Get-HardlinkNames $item.FullName `
                    "payload hardlink '$relative'")
                if ($hardlinkTargets.Count -lt 2) {
                    Throw-ValidationError $script:ExitContract "hardlink" (
                        "payload hardlink '$relative' does not share a file identity")
                }
                foreach ($name in $hardlinkTargets) {
                    if (-not (Test-PathWithin $RootPath $name)) {
                        Throw-ValidationError $script:ExitContract "hardlink" (
                            "payload hardlink '$relative' shares its file identity outside Root")
                    }
                }
            } else {
                $type = "file"
            }
        }
        $members += [ordered]@{
            path = $relative
            type = $type
            bytes = if ($type -ceq "directory") {
                [long]0
            } else {
                [long][IO.FileInfo]::new($contentPath).Length
            }
            sha256 = if ($type -ceq "directory") {
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
    if ($PayloadObject.lockSha256 -cne $LockSha256 -or
        $PayloadObject.provenanceSha256 -cne $ProvenanceSha256) {
        Throw-ValidationError $script:ExitContract "digest" (
            "payload manifest does not bind the exact lock and provenance")
    }
    Assert-ExactProperties $PayloadObject.scope @(
        "root", "excludedPrefixes") "payload manifest.scope"
    Assert-JsonArray $PayloadObject.scope.excludedPrefixes `
        "payload manifest.scope.excludedPrefixes"
    if ($PayloadObject.scope.root -cne "." -or
        @($PayloadObject.scope.excludedPrefixes).Count -ne 1 -or
        @($PayloadObject.scope.excludedPrefixes)[0] -cne "preview-evidence/") {
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
    $entryMap = @{}
    for ($index = 0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        Assert-ExactProperties $entry @(
            "path", "type", "bytes", "sha256", "architecture", "machine",
            "personality", "imports", "clrFlags", "linkTarget") `
            "payload manifest entry"
        Assert-NormalizedPath $entry.path "payload manifest entry path"
        Assert-JsonInteger $entry.bytes `
            "payload manifest entry '$($entry.path)'.bytes" 0
        Assert-JsonArray $entry.imports `
            "payload manifest entry '$($entry.path)'.imports"
        $actual = $inventory.Members[$index]
        if ($entry.path -cne $actual.path -or $entry.type -cne $actual.type) {
            Throw-ValidationError $script:ExitContract "member" (
                "payload manifest does not ordinally cover root member '$($actual.path)'")
        }
        $provenanceMember = $ProvenanceContext.FinalMap[
            $entry.path.ToLowerInvariant()]
        if ($null -eq $provenanceMember -or
            $provenanceMember.destinationPath -cne $entry.path -or
            $provenanceMember.type -cne $entry.type) {
            Throw-ValidationError $script:ExitContract "member" (
                "payload member '$($entry.path)' lacks exact final provenance ownership")
        }
        if ($entry.type -ceq "directory") {
            if ([long]$entry.bytes -ne 0 -or $null -ne $entry.sha256 -or
                $null -ne $entry.architecture -or $null -ne $entry.machine -or
                $null -ne $entry.personality -or @($entry.imports).Count -ne 0 -or
                $null -ne $entry.clrFlags -or $null -ne $entry.linkTarget) {
                Throw-ValidationError $script:ExitContract "member" (
                    "directory '$($entry.path)' has invalid payload metadata")
            }
        } elseif ($entry.type -cin @("file", "symlink", "hardlink")) {
            if ($entry.type -ceq "file" -and $null -ne $entry.linkTarget) {
                Throw-ValidationError $script:ExitContract "member" (
                    "ordinary file '$($entry.path)' must have linkTarget=null")
            }
            if ($entry.type -cin @("symlink", "hardlink")) {
                Assert-NormalizedPath $entry.linkTarget `
                    "payload link '$($entry.path)'.linkTarget"
                if ($entry.linkTarget -cne $provenanceMember.linkTarget -or
                    -not $entryMap.ContainsKey(
                        $entry.linkTarget.ToLowerInvariant()) -and
                    @($entries | Where-Object path -CEQ $entry.linkTarget).
                        Count -ne 1) {
                    Throw-ValidationError $script:ExitContract "member" (
                        "payload link '$($entry.path)' target is not declared")
                }
                if ($entry.type -ceq "symlink" -and
                    $actual.linkTarget -cne $entry.linkTarget) {
                    Throw-ValidationError $script:ExitContract "reparse" (
                        "payload symlink '$($entry.path)' target differs from provenance")
                }
                if ($entry.type -ceq "hardlink") {
                    $expectedTargetFull = Join-Path $RootPath (
                        $entry.linkTarget.Replace("/", "\"))
                    if (@($actual.hardlinkTargets | Where-Object {
                        $_ -ieq $expectedTargetFull
                    }).Count -eq 0) {
                        Throw-ValidationError $script:ExitContract "hardlink" (
                            "payload hardlink '$($entry.path)' does not share its declared file identity")
                    }
                }
            }
            if ([long]$entry.bytes -ne $actual.bytes -or
                $entry.sha256 -cne $actual.sha256 -or
                [long]$provenanceMember.bytes -ne $actual.bytes -or
                $provenanceMember.sha256 -cne $actual.sha256) {
                Throw-ValidationError $script:ExitContract "member" (
                    "payload file '$($entry.path)' bytes/hash do not match its archive member")
            }
            $classification = Get-PeClassification $actual.fullPath $entry.path
            if ($entry.architecture -cne $classification.architecture -or
                $entry.machine -cne $classification.machine -or
                $entry.personality -cne $classification.personality -or
                (@($entry.imports) -join "`0") -cne
                    (@($classification.imports) -join "`0") -or
                $entry.clrFlags -ne $classification.clrFlags) {
                Throw-ValidationError $script:ExitStatic "classification" (
                    "payload classification for '$($entry.path)' is not authoritative")
            }
            $classifications += [ordered]@{
                path = $entry.path
                architecture = $classification.architecture
                machine = $classification.machine
                personality = $classification.personality
                imports = @($classification.imports)
                inputId = $provenanceMember.inputId
                sourceMember = $provenanceMember.sourceMember
            }
        } else {
            Throw-ValidationError $script:ExitContract "member" (
                "payload entry '$($entry.path)' has invalid type")
        }
        $entryMap[$entry.path.ToLowerInvariant()] = $entry
    }
    $script:ReportData.summary.payloadMembers = $entries.Count
    $script:ReportData.summary.peFiles = @(
        $classifications |
            Where-Object architecture -CNE "non-pe").Count
    $script:ReportData.classifications = $classifications
    $script:ReportData.digests.rootInventorySha256 = $inventory.Sha256
    return [ordered]@{
        Entries = $entries
        EntryMap = $entryMap
        Inventory = $inventory
        Classifications = $classifications
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
            $_.architecture -ceq "arm64" -and $_.personality -ceq "msys"
        }) { param($item) [string]$item.path })
    $declared = @($ProvenanceContext.PseudoReloc.candidates)
    if ($detected.Count -ne $declared.Count) {
        Throw-ValidationError $script:ExitContract "candidate" (
            "pseudo-reloc candidates must be selected from detected ARM64 MSYS PEs")
    }
    for ($index = 0; $index -lt $detected.Count; $index++) {
        if ($declared[$index].destinationPath -cne $detected[$index].path -or
            $declared[$index].inputId -cne $detected[$index].inputId -or
            $declared[$index].sourceMember -cne $detected[$index].sourceMember) {
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
        $toolRootPath -ieq $RootPath) {
        Throw-ValidationError $script:ExitScanner "tool" (
            "ToolRoot and payload Root must be disjoint")
    }
    $repoRoot = Split-Path -Parent $PSCommandPath
    $scannerPath = Join-Path $repoRoot $script:ScannerRelativePath
    if (-not [IO.File]::Exists($scannerPath) -or
        [IO.FileInfo]::new($scannerPath).Length -ne $script:ScannerBytes -or
        (Get-FileSha256 $scannerPath) -cne $script:ScannerSha256) {
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
            $actualHash -cne $member.sha256) {
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
            if ($scannerExit -eq 2 -or $scannerReport.result -ceq "error") {
                Throw-ValidationError $script:ExitScanner "scanner" (
                    "pseudo-reloc scanner failed for '$($candidate.path)': " +
                    "$($scannerReport.error)")
            }
            if ($scannerExit -ne 0 -or $scannerReport.result -cne "pass") {
                Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                    "pseudo-reloc policy rejected '$($candidate.path)'")
            }
            if ($scannerReport.table_format -ceq "v1" -and
                [long]$scannerReport.record_count -ne 0) {
                Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                    "pseudo-reloc v1 records are forbidden for '$($candidate.path)'")
            }
            if ($scannerReport.table_format -ceq "v2") {
                foreach ($flag in @($scannerReport.flags)) {
                    if ([long]$flag -ne 64) {
                        Throw-ValidationError $script:ExitStatic "pseudo-reloc" (
                            "ARM64 lane requires scalar64 pseudo-reloc flags for " +
                            "'$($candidate.path)'")
                    }
                }
            }
            $results += [ordered]@{
                path = $candidate.path
                result = "pass"
                tableFormat = $scannerReport.table_format
                recordCount = [long]$scannerReport.record_count
                flags = @($scannerReport.flags)
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
        if ($entry.type -cne "file") {
            Throw-ValidationError $script:ExitContract "closure" (
                "native shell closure member is not a file: '$path'")
        }
        $closureRows += [ordered]@{
            path = $path
            architecture = $entry.architecture
            personality = $entry.personality
        }
    }
    $script:ReportData.nativeShellClosure = $closureRows

    $invalid = @($PayloadContext.Classifications |
        Where-Object architecture -Cin @("x86", "unknown"))
    if ($invalid.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "architecture" (
            "payload contains forbidden x86 or unknown PE architecture: " +
            (($invalid | ForEach-Object path) -join ", "))
    }
    $cygwin = @($PayloadContext.Classifications |
        Where-Object personality -CEQ "cygwin")
    if ($cygwin.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "personality" (
            "payload contains forbidden Cygwin personality: " +
            (($cygwin | ForEach-Object path) -join ", "))
    }
    $x64 = @(Sort-OrdinalBy @($PayloadContext.Classifications |
        Where-Object architecture -CEQ "x64" |
        ForEach-Object path) { param($item) [string]$item })
    $script:ReportData.remainingX64 = $x64
    $script:ReportData.summary.remainingX64 = $x64.Count
    if ($AdmissionMode -ceq "Final" -and $LockContext.Unresolved.Count -ne 0) {
        Throw-ValidationError $script:ExitContract "unresolved" (
            "Final admission rejects unresolved lock inputs: " +
            ($LockContext.Unresolved -join ", "))
    }
    if ($AdmissionMode -ceq "Final" -and $x64.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "architecture" (
            "Final admission rejects all x64 payload files: $($x64 -join ', ')")
    }
    $nonArm64Closure = @($closureRows |
        Where-Object architecture -CNE "arm64")
    if ($AdmissionMode -ceq "Final" -and $nonArm64Closure.Count -ne 0) {
        Throw-ValidationError $script:ExitStatic "closure" (
            "Final admission requires ARM64 native shell closure members: " +
            (($nonArm64Closure | ForEach-Object path) -join ", "))
    }
    if ($AdmissionMode -ceq "Preview" -and $x64.Count -ne 0) {
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
    if ($full -cne $Value.TrimEnd("\")) {
        Throw-ValidationError $script:ExitRuntime "runtime-path" (
            "$Context is not canonical: '$Value'")
    }
    if ($full -ieq "C:\msys64" -or
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
        if ($entry.type -cne "file") {
            Throw-ValidationError $script:ExitRuntime "runtime-path" (
                "$Context does not reference a file")
        }
        return [ordered]@{
            Sha256 = $entry.sha256
            Architecture = $entry.architecture
            Personality = $entry.personality
        }
    }
    if ($ObservedPath.StartsWith(
        "C:\Windows\",
        [StringComparison]::OrdinalIgnoreCase)) {
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
    Throw-ValidationError $script:ExitRuntime "external-module" (
        "$Context is outside the staged root and C:\Windows: '$ObservedPath'")
}

function Assert-AssemblyEvidenceContract {
    param(
        [Parameter(Mandatory = $true)] $AssemblyObject,
        [Parameter(Mandatory = $true)][string] $SourceLockSha256,
        [Parameter(Mandatory = $true)][string] $LockSha256,
        [Parameter(Mandatory = $true)][string] $ProvenanceSha256,
        [Parameter(Mandatory = $true)][string] $PayloadSha256,
        [Parameter(Mandatory = $true)][string] $RootInventorySha256
    )

    Assert-ExactProperties $AssemblyObject @(
        "schemaVersion", "previewId", "sourceLockSha256", "lockSha256", "provenanceSha256",
        "payloadManifestSha256", "rootInventorySha256", "host",
        "observedUtc", "externalObservation") "assembly evidence" `
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
        @("rootInventorySha256", $RootInventorySha256))) {
        Assert-LowerSha256 $AssemblyObject.($binding[0]) `
            "assembly evidence.$($binding[0])" $script:ExitRuntime
        if ($AssemblyObject.($binding[0]) -cne $binding[1]) {
            Throw-ValidationError $script:ExitRuntime "digest" (
                "assembly evidence $($binding[0]) does not match its bound input")
        }
    }
    Assert-ExactProperties $AssemblyObject.host @(
        "os", "architecture", "processArchitecture") `
        "assembly evidence.host" $script:ExitRuntime
    if ($AssemblyObject.host.os -cne "Windows" -or
        $AssemblyObject.host.architecture -cnotin @("AMD64", "ARM64") -or
        $AssemblyObject.host.processArchitecture -cnotin @("AMD64", "ARM64")) {
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
        [Parameter(Mandatory = $true)] $PayloadContext,
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)] $AssemblyContext
    )

    Assert-ExactProperties $RuntimeObject @(
        "schemaVersion", "previewId", "admissionMode", "sourceLockSha256", "lockSha256",
        "provenanceSha256", "payloadManifestSha256", "rootInventorySha256",
        "validator", "host", "collector", "collectedUtc", "scenarios") `
        "runtime evidence" $script:ExitRuntime
    Assert-SchemaVersion $RuntimeObject "runtime evidence" $script:ExitRuntime
    if ($RuntimeObject.previewId -cne $AssemblyContext.PreviewId) {
        Throw-ValidationError $script:ExitRuntime "identity" (
            "runtime evidence previewId does not match assembly evidence")
    }
    if ($RuntimeObject.admissionMode -cnotin @("Preview", "Final")) {
        Throw-ValidationError $script:ExitRuntime "schema" (
            "runtime evidence admissionMode must be Preview or Final")
    }
    foreach ($digest in @(
        "lockSha256", "provenanceSha256", "payloadManifestSha256",
        "rootInventorySha256")) {
        Assert-LowerSha256 $RuntimeObject.$digest "runtime evidence.$digest" `
            $script:ExitRuntime
    }
    foreach ($binding in @(
        @("sourceLockSha256", $SourceLockSha256),
        @("lockSha256", $LockSha256),
        @("provenanceSha256", $ProvenanceSha256),
        @("payloadManifestSha256", $PayloadSha256),
        @("rootInventorySha256", $PayloadContext.Inventory.Sha256))) {
        if ($RuntimeObject.($binding[0]) -cne $binding[1]) {
            Throw-ValidationError $script:ExitRuntime "digest" (
                "runtime evidence $($binding[0]) does not match its bound input " +
                "(recorded=$($RuntimeObject.($binding[0])) actual=$($binding[1]))")
        }
    }
    Assert-ExactProperties $RuntimeObject.host @("os", "architecture") `
        "runtime evidence.host" $script:ExitRuntime
    if ($RuntimeObject.host.os -cne "Windows" -or
        $RuntimeObject.host.architecture -cne "ARM64") {
        Throw-ValidationError $script:ExitRuntime "host" (
            "runtime evidence host must be native Windows ARM64")
    }
    Assert-ExactProperties $RuntimeObject.validator @(
        "repository", "commit", "path", "bytes", "sha256", "mode") `
        "runtime evidence.validator" `
        $script:ExitRuntime
    if ($RuntimeObject.validator.repository -cne "crutkas/build-extra" -or
        $RuntimeObject.validator.path -cne "validate-arm64-bundle.ps1" -or
        $RuntimeObject.validator.mode -cne "Runtime") {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "runtime evidence validator repository/mode is invalid")
    }
    Assert-LowerCommit $RuntimeObject.validator.commit `
        "runtime evidence.validator.commit" $script:ExitRuntime
    Assert-JsonInteger $RuntimeObject.validator.bytes `
        "runtime evidence.validator.bytes" 1 $script:ExitRuntime
    Assert-LowerSha256 $RuntimeObject.validator.sha256 `
        "runtime evidence.validator.sha256" $script:ExitRuntime
    $repositoryRootResult = @(& git -C (Split-Path -Parent $PSCommandPath) `
        rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or $repositoryRootResult.Count -ne 1) {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "could not identify the validator repository checkout")
    }
    $repositoryRoot = $repositoryRootResult[0].Trim()
    $claimedBlob = @(& git -C $repositoryRoot rev-parse (
        "$($RuntimeObject.validator.commit):validate-arm64-bundle.ps1") 2>$null)
    $currentBlob = @(& git -C $repositoryRoot hash-object $PSCommandPath 2>$null)
    $currentBytes = [IO.FileInfo]::new($PSCommandPath).Length
    $currentSha256 = Get-FileSha256 $PSCommandPath
    if ($LASTEXITCODE -ne 0 -or $claimedBlob.Count -ne 1 -or
        $currentBlob.Count -ne 1 -or
        $claimedBlob[0].Trim() -cne $currentBlob[0].Trim() -or
        [long]$RuntimeObject.validator.bytes -ne $currentBytes -or
        $RuntimeObject.validator.sha256 -cne $currentSha256) {
        Throw-ValidationError $script:ExitRuntime "validator" (
            "runtime evidence validator identity does not match the committed executable")
    }
    Assert-ExactProperties $RuntimeObject.collector @(
        "repository", "commit", "path", "bytes", "sha256", "method") `
        "runtime evidence.collector" $script:ExitRuntime
    if ($RuntimeObject.collector.repository -cnotmatch
        "^crutkas/[A-Za-z0-9_.-]+$" -or
        $RuntimeObject.collector.method -cne
            "ETW-Kernel-Process-ImageLoad") {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector must be an immutable crutkas ETW collector")
    }
    Assert-LowerCommit $RuntimeObject.collector.commit `
        "runtime evidence.collector.commit" $script:ExitRuntime
    Assert-NormalizedPath $RuntimeObject.collector.path `
        "runtime evidence.collector.path" -ExitCode $script:ExitRuntime
    Assert-LowerSha256 $RuntimeObject.collector.sha256 `
        "runtime evidence.collector.sha256" $script:ExitRuntime
    Assert-JsonInteger $RuntimeObject.collector.bytes `
        "runtime evidence.collector.bytes" 1 $script:ExitRuntime
    if ([long]$RuntimeObject.collector.bytes -le 0) {
        Throw-ValidationError $script:ExitRuntime "collector" (
            "runtime collector byte count must be positive")
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
            -not $script:RequiredScenarios.Contains($scenario.id)) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenario is unknown, duplicate, or case-colliding: '$($scenario.id)'")
        }
        if ($scenario.id -cne $expectedScenarioNames[$scenarioIndex]) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenarios must use the canonical order")
        }
        if ($scenario.status -ceq "unresolved") {
            if ($RuntimeObject.admissionMode -cne "Preview" -or
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
        if ($scenario.status -cne "pass" -or $null -ne $scenario.reason) {
            Throw-ValidationError $script:ExitRuntime "scenario" (
                "runtime scenario '$($scenario.id)' must pass")
        }
        Assert-ExactProperties $scenario.behavior @(
            "operation", "passed", "exitCode") `
            "runtime scenario '$($scenario.id)'.behavior" $script:ExitRuntime
        Assert-JsonInteger $scenario.behavior.exitCode `
            "runtime scenario '$($scenario.id)'.behavior.exitCode" 0 `
            $script:ExitRuntime
        if ($scenario.behavior.operation -cne
                $script:RequiredOperations[$scenario.id] -or
            $scenario.behavior.passed -ne $true -or
            [long]$scenario.behavior.exitCode -ne 0) {
            Throw-ValidationError $script:ExitRuntime "behavior" (
                "runtime scenario '$($scenario.id)' lacks its required successful behavior proof")
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
        $roleProcesses = @($processes | Where-Object role -CEQ "role")
        if ($roleProcesses.Count -ne 1) {
            Throw-ValidationError $script:ExitRuntime "role" (
                "runtime scenario '$($scenario.id)' needs exactly one role process")
        }
        $scenarioInstances = [Collections.Generic.HashSet[string]]::new(
            $script:PathComparer)
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
            if ($process.role -cnotin @("role", "support")) {
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
            if ($process.role -ceq "role") {
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
            if ($process.sha256 -cne $actual.Sha256 -or
                $process.architecture -cne $actual.Architecture -or
                $process.personality -cne $actual.Personality) {
                Throw-ValidationError $script:ExitRuntime "process" (
                    "runtime process '$($process.instanceId)' identity is not authoritative")
            }
            if ($process.architecture -cnotin @(
                    "arm64", "arm64ec", "anycpu") -or
                $process.personality -cnotin @(
                    "msys", "mingw", "managed")) {
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
                if ($module.sha256 -cne $moduleActual.Sha256 -or
                    $module.architecture -cne $moduleActual.Architecture -or
                    $module.personality -cne $moduleActual.Personality) {
                    Throw-ValidationError $script:ExitRuntime "module" (
                        "runtime module '$modulePath' identity is not authoritative")
                }
                if ($module.architecture -cnotin @(
                        "arm64", "arm64ec", "anycpu") -or
                    $module.personality -cnotin @(
                        "msys", "mingw", "managed")) {
                    Throw-ValidationError $script:ExitRuntime "architecture" (
                        "runtime module '$modulePath' violates architecture/personality policy")
                }
            }
        }
        foreach ($link in $parentLinks) {
            if (-not $scenarioInstances.Contains($link.parent) -or
                $link.child -ieq $link.parent) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime support process '$($link.child)' has an invalid parent")
            }
        }
        $parentByChild = @{}
        foreach ($link in $parentLinks) {
            $parentByChild[$link.child.ToLowerInvariant()] = $link.parent
        }
        foreach ($link in $parentLinks) {
            $visited = [Collections.Generic.HashSet[string]]::new(
                $script:PathComparer)
            $cursor = $link.child
            while ($parentByChild.ContainsKey($cursor.ToLowerInvariant())) {
                if (-not $visited.Add($cursor)) {
                    Throw-ValidationError $script:ExitRuntime "instance" (
                        "runtime process tree contains a parent cycle")
                }
                $cursor = $parentByChild[$cursor.ToLowerInvariant()]
            }
            if ($cursor -cne $roleProcesses[0].instanceId) {
                Throw-ValidationError $script:ExitRuntime "instance" (
                    "runtime support process '$($link.child)' is not in the role process tree")
            }
        }
        $expectedPersonality = $script:RequiredScenarios[$scenario.id]
        if ($roleProcesses[0].personality -cne $expectedPersonality) {
            Throw-ValidationError $script:ExitRuntime "role" (
                "runtime scenario '$($scenario.id)' role process must be $expectedPersonality")
        }
        if ($command[0] -cne $roleProcesses[0].path) {
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
    if ($Mode -eq "Runtime") {
        if ([string]::IsNullOrWhiteSpace($AssemblyEvidence)) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "-AssemblyEvidence is required only for -Mode Runtime")
        }
        if ([string]::IsNullOrWhiteSpace($RuntimeEvidence)) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "-RuntimeEvidence is required only for -Mode Runtime")
        }
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
    if ($Mode -eq "Runtime") {
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
        if ($admissionMode -cnotin @("Preview", "Final")) {
            Throw-ValidationError $script:ExitRuntime "schema" (
                "runtime evidence admissionMode must be Preview or Final")
        }
        $script:ReportData.admissionMode = $admissionMode
    }

    $lockContext = Read-LockContract `
        $lockDocument.Object $lockDocument $rootPath
    $script:ReportData.digests.sourceLockSha256 =
        $lockContext.SourceLock.sha256
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

    if ($Mode -eq "Runtime") {
        $assemblyContext = Assert-AssemblyEvidenceContract `
            $assemblyDocument.Object `
            $lockContext.SourceLock.sha256 `
            $lockDocument.Sha256 `
            $provenanceDocument.Sha256 `
            $payloadDocument.Sha256 `
            $payloadContext.Inventory.Sha256
        Assert-RuntimeContract `
            $runtimeDocument.Object `
            $lockContext.SourceLock.sha256 `
            $lockDocument.Sha256 `
            $provenanceDocument.Sha256 `
            $payloadDocument.Sha256 `
            $payloadContext `
            $rootPath `
            $assemblyContext
    }
    Write-ValidationReport 0 "pass"
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
    Write-ValidationReport $exitCode "fail"
}
exit $exitCode
