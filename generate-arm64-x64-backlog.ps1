[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDatabaseRoot,

    [string]$Model,

    [string]$OwnershipOutput,

    [string]$ReportOutput,

    [switch]$ValidatePackageDatabaseOnly,

    [scriptblock]$ValidationOnlyAfterRead
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Model)) {
    $Model = Join-Path $PSScriptRoot "arm64-validation\backlog-model-v2.55.0.4.json"
}
if ([string]::IsNullOrWhiteSpace($OwnershipOutput)) {
    $OwnershipOutput = Join-Path $PSScriptRoot "arm64-x64-ownership-v2.55.0.4.tsv"
}
if ([string]::IsNullOrWhiteSpace($ReportOutput)) {
    $ReportOutput = Join-Path $PSScriptRoot "arm64-x64-backlog-v2.55.0.4.json"
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-NormalizedTextSha256 {
    param([string]$Path)

    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($bytes) | ForEach-Object {
            $_.ToString("x2")
        }) -join ""
    } finally {
        $sha.Dispose()
    }
}

function Get-Field {
    param([string[]]$Lines, [string]$Name)

    $index = [Array]::IndexOf($Lines, "%$Name%")
    if ($index -lt 0 -or $index + 1 -ge $Lines.Count) {
        return $null
    }
    return $Lines[$index + 1]
}

function Write-Utf8 {
    param([string]$Path, [string]$Content)

    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Assert-PackageDatabaseClean {
    param(
        [string]$RepositoryRoot,
        [string]$DatabaseRelative
    )

    [string[]]$changes = @(& git -C $RepositoryRoot status --porcelain=v1 `
        --untracked-files=all -- $DatabaseRelative)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect package database Git status"
    }
    if ($changes.Count -ne 0) {
        throw "Package database contains staged, unstaged, or untracked changes"
    }
}

function Confirm-PackageDatabaseAttestation {
    param(
        [string]$RepositoryRoot,
        [string]$DatabaseRelative,
        [string]$ExpectedCommit
    )

    Assert-PackageDatabaseClean $RepositoryRoot $DatabaseRelative
    $currentCommit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentCommit -cne $ExpectedCommit) {
        throw "Package database Git HEAD changed while it was being read"
    }
}

$fullPackageDatabaseRoot = [IO.Path]::GetFullPath($PackageDatabaseRoot)
if ($fullPackageDatabaseRoot -match "(?i)^c:\\msys64(?:\\|$)") {
    throw "Shared C:\msys64 cannot be used as ownership evidence"
}
$packageDatabase = (Resolve-Path -LiteralPath $PackageDatabaseRoot).Path
$modelObject = Get-Content -LiteralPath $Model -Raw | ConvertFrom-Json
if ($modelObject.schemaVersion -ne 1) {
    throw "Unsupported backlog model schemaVersion"
}

$repositoryRoot = (& git -C $packageDatabase rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Package database is not in a Git worktree"
}
$packageDatabaseCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or
    $packageDatabaseCommit -cne $modelObject.baseline.ownershipCommit) {
    throw "Package database commit '$packageDatabaseCommit' does not match '$($modelObject.baseline.ownershipCommit)'"
}
$databaseRelative = $packageDatabase.Substring($repositoryRoot.Length).
    TrimStart("\").Replace("\", "/")
if ($databaseRelative -cne $modelObject.baseline.ownershipDatabasePath) {
    throw "Package database path '$databaseRelative' does not match the model"
}
Assert-PackageDatabaseClean $repositoryRoot $databaseRelative
if ($ValidatePackageDatabaseOnly) {
    foreach ($file in Get-ChildItem -LiteralPath $packageDatabase -File -Recurse) {
        [void][IO.File]::ReadAllBytes($file.FullName)
    }
    if ($null -ne $ValidationOnlyAfterRead) {
        & $ValidationOnlyAfterRead
    }
    Confirm-PackageDatabaseAttestation $repositoryRoot $databaseRelative `
        $packageDatabaseCommit
    Write-Host "Package database attestation passed"
    return
}
if ($null -ne $ValidationOnlyAfterRead) {
    throw "-ValidationOnlyAfterRead requires -ValidatePackageDatabaseOnly"
}

$ownerByPath = New-Object "System.Collections.Generic.Dictionary[string,object]" `
    ([System.StringComparer]::Ordinal)
foreach ($directory in Get-ChildItem -LiteralPath $packageDatabase -Directory) {
    $descriptionPath = Join-Path $directory.FullName "desc"
    $filesPath = Join-Path $directory.FullName "files"
    if (-not (Test-Path -LiteralPath $descriptionPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $filesPath -PathType Leaf)) {
        continue
    }
    [string[]]$description = @(Get-Content -LiteralPath $descriptionPath)
    $packageName = Get-Field $description "NAME"
    $packageVersion = Get-Field $description "VERSION"
    if ([string]::IsNullOrWhiteSpace($packageName) -or
        [string]::IsNullOrWhiteSpace($packageVersion)) {
        throw "Package metadata is incomplete in '$($directory.Name)'"
    }
    [string[]]$fileRecords = @(Get-Content -LiteralPath $filesPath)
    $filesIndex = [Array]::IndexOf($fileRecords, "%FILES%")
    if ($filesIndex -lt 0) {
        continue
    }
    for ($recordIndex = $filesIndex + 1;
        $recordIndex -lt $fileRecords.Count;
        $recordIndex++) {
        $path = $fileRecords[$recordIndex]
        if ($path -match "^%[^%]+%$") {
            break
        }
        if ([string]::IsNullOrWhiteSpace($path) -or
            $path.EndsWith("/")) {
            continue
        }
        $owner = [pscustomobject]@{
            name = $packageName
            version = $packageVersion
        }
        if ($ownerByPath.ContainsKey($path)) {
            $ownerByPath[$path].Add($owner)
        } else {
            $owners = New-Object System.Collections.Generic.List[object]
            $owners.Add($owner)
            $ownerByPath.Add($path, $owners)
        }
    }
}
Confirm-PackageDatabaseAttestation $repositoryRoot $databaseRelative `
    $packageDatabaseCommit

$manifestPath = Join-Path $PSScriptRoot $modelObject.baseline.manifest
if ((Get-NormalizedTextSha256 $manifestPath) -cne $modelObject.baseline.manifestSha256) {
    throw "Authoritative architecture manifest SHA-256 changed"
}
$manifestX64 = @(Import-Csv -LiteralPath $manifestPath -Delimiter "`t" |
    Where-Object architecture -eq "x64")
if ($manifestX64.Count -ne [int]$modelObject.baseline.x64Count) {
    throw "Authoritative architecture manifest x64 count changed"
}

$baselinePath = Join-Path $PSScriptRoot $modelObject.baseline.x64Paths
$baselinePaths = @(Get-Content -LiteralPath $baselinePath)
$manifestPaths = @($manifestX64 | ForEach-Object path)
if ($baselinePaths.Count -ne $manifestPaths.Count -or
    @(Compare-Object $baselinePaths $manifestPaths -SyncWindow 0).Count -ne 0) {
    throw "x64 path baseline does not exactly match the authoritative manifest"
}

$ownershipRows = @()
foreach ($entry in $manifestX64) {
    if (-not $ownerByPath.ContainsKey($entry.path)) {
        throw "Unresolved package ownership for '$($entry.path)'"
    }
    if ($ownerByPath[$entry.path].Count -ne 1) {
        $names = @($ownerByPath[$entry.path] | ForEach-Object name) -join ", "
        throw "Ambiguous package ownership for '$($entry.path)': $names"
    }
    $owner = $ownerByPath[$entry.path][0]
    $ownershipRows += [pscustomobject]@{
        path = $entry.path
        sourcePackage = $owner.name
        sourceVersion = $owner.version
    }
}

$ownershipLines = New-Object System.Collections.Generic.List[string]
$ownershipLines.Add("path`tsourcePackage`tsourceVersion`townershipCommit")
foreach ($row in $ownershipRows) {
    $ownershipLines.Add("$($row.path)`t$($row.sourcePackage)`t$($row.sourceVersion)`t$packageDatabaseCommit")
}
Write-Utf8 $OwnershipOutput (($ownershipLines -join "`n") + "`n")

$claimedByPath = New-Object "System.Collections.Generic.Dictionary[string,object]" `
    ([System.StringComparer]::Ordinal)
$deltaResults = @()
foreach ($delta in $modelObject.deltas) {
    $selected = New-Object "System.Collections.Generic.SortedSet[string]" `
        ([System.StringComparer]::Ordinal)
    $explicitPaths = if ($delta.PSObject.Properties["paths"]) {
        @($delta.paths)
    } else { @() }
    foreach ($path in $explicitPaths) {
        [void]$selected.Add([string]$path)
    }
    $selectedPackages = if ($delta.PSObject.Properties["sourcePackages"]) {
        @($delta.sourcePackages)
    } else { @() }
    foreach ($packageName in $selectedPackages) {
        foreach ($row in $ownershipRows | Where-Object sourcePackage -CEQ $packageName) {
            [void]$selected.Add($row.path)
        }
    }
    if ($selected.Count -ne [int]$delta.expectedCount) {
        throw "Delta '$($delta.id)' selected $($selected.Count) paths, expected $($delta.expectedCount)"
    }
    foreach ($path in $selected) {
        if (-not $ownerByPath.ContainsKey($path) -or $manifestPaths -cnotcontains $path) {
            throw "Delta '$($delta.id)' selected unresolved path '$path'"
        }
        if ($claimedByPath.ContainsKey($path)) {
            throw "Delta overlap at '$path': '$($claimedByPath[$path].id)' and '$($delta.id)'"
        }
        $claimedByPath.Add($path, $delta)
    }
    $deltaResults += [ordered]@{
        id = $delta.id
        status = $delta.status
        resolution = $delta.resolution
        count = $selected.Count
        source = $delta.source
        immutableInput = if ($delta.PSObject.Properties["immutableInput"]) {
            $delta.immutableInput
        } else { "not-applicable" }
        paths = @($selected)
    }
}

$retainedReasons = @{}
$retainedPath = Join-Path $PSScriptRoot $modelObject.busyBoxRetained
foreach ($row in Import-Csv -LiteralPath $retainedPath -Delimiter "`t") {
    $retainedReasons[$row.path] = $row.reason
}

$packageDisposition = @{}
foreach ($rule in $modelObject.packageDispositions) {
    foreach ($packageName in $rule.sourcePackages) {
        if ($packageDisposition.ContainsKey($packageName)) {
            throw "Duplicate package disposition for '$packageName'"
        }
        $packageDisposition[$packageName] = $rule
    }
}

$pathResults = @()
foreach ($row in $ownershipRows) {
    if ($claimedByPath.ContainsKey($row.path)) {
        $delta = $claimedByPath[$row.path]
        $pathResults += [pscustomobject][ordered]@{
            path = $row.path
            sourcePackage = $row.sourcePackage
            sourceVersion = $row.sourceVersion
            state = "removed-or-replaced"
            delta = $delta.id
            deltaStatus = $delta.status
            action = $delta.resolution
            dependencyRemovalOpportunity = $null
            reason = $null
        }
        continue
    }

    $reason = if ($retainedReasons.ContainsKey($row.path)) {
        $retainedReasons[$row.path]
    } else { $null }
    if ($null -ne $reason) {
        if ($reason -match "not proven|known .* gap|does not observe") {
            $action = "busybox-semantic-proof"
        } elseif ($reason -match "^No exact ARM64 BusyBox applet$") {
            $action = "native-port"
        } else {
            $action = "dependency-removal"
        }
        $opportunity = $null
    } elseif ($packageDisposition.ContainsKey($row.sourcePackage)) {
        $rule = $packageDisposition[$row.sourcePackage]
        $action = $rule.action
        $opportunity = $rule.dependencyRemovalOpportunity
    } else {
        $action = "unresolved"
        $opportunity = $null
    }
    $pathResults += [pscustomobject][ordered]@{
        path = $row.path
        sourcePackage = $row.sourcePackage
        sourceVersion = $row.sourceVersion
        state = "remaining"
        delta = $null
        deltaStatus = $null
        action = $action
        dependencyRemovalOpportunity = $opportunity
        reason = $reason
    }
}

$greenRemoved = @($pathResults | Where-Object {
    $_.state -eq "removed-or-replaced" -and $_.deltaStatus -notlike "modeled-*"
}).Count
$modeledRemoved = @($pathResults | Where-Object {
    $_.state -eq "removed-or-replaced" -and $_.deltaStatus -like "modeled-*"
}).Count
$remaining = @($pathResults | Where-Object state -eq "remaining").Count
if ($greenRemoved -ne [int]$modelObject.expected.greenOrCandidateRemoved -or
    $modeledRemoved -ne [int]$modelObject.expected.modeledRemoved -or
    $remaining -ne [int]$modelObject.expected.remaining) {
    throw "Backlog totals changed: green=$greenRemoved modeled=$modeledRemoved remaining=$remaining"
}

$groups = @($pathResults | Where-Object state -eq "remaining" |
    Group-Object sourcePackage, action, dependencyRemovalOpportunity |
    Sort-Object @{ Expression = "Count"; Descending = $true }, Name)
$cumulative = 0
$recommendations = @()
for ($index = 0; $index -lt $groups.Count; $index++) {
    $group = $groups[$index]
    $first = $group.Group[0]
    $cumulative += $group.Count
    $recommendations += [ordered]@{
        rank = $index + 1
        sourcePackage = $first.sourcePackage
        sourceVersion = $first.sourceVersion
        count = $group.Count
        cumulative = $cumulative
        action = $first.action
        dependencyRemovalOpportunity = $first.dependencyRemovalOpportunity
        paths = @($group.Group | ForEach-Object path | Sort-Object)
    }
}

$modeledPathByName = @{}
foreach ($row in $pathResults | Where-Object deltaStatus -like "modeled-*") {
    $modeledPathByName[$row.path] = $row
}
$productScopes = @()
foreach ($product in $modelObject.productScopes.products) {
    $paths = if ($product.allModeledPaths) {
        @($modeledPathByName.Keys | Sort-Object)
    } else {
        @($product.paths)
    }
    if ($paths.Count -ne [int]$product.expectedCount) {
        throw "Product '$($product.id)' selected $($paths.Count) modeled paths, expected $($product.expectedCount)"
    }
    foreach ($path in $paths) {
        if (-not $modeledPathByName.ContainsKey($path)) {
            throw "Product '$($product.id)' selected non-modeled path '$path'"
        }
    }
    $byDelta = @($paths | ForEach-Object {
        $modeledPathByName[$_]
    } | Group-Object delta | Sort-Object Name | ForEach-Object {
        [ordered]@{
            delta = $_.Name
            count = $_.Count
        }
    })
    $productScopes += [ordered]@{
        id = $product.id
        count = $paths.Count
        byDelta = $byDelta
        paths = $paths
    }
}

$report = [ordered]@{
    schemaVersion = 1
    baseline = [ordered]@{
        manifest = $modelObject.baseline.manifest
        manifestSha256 = $modelObject.baseline.manifestSha256
        x64Count = $manifestX64.Count
        ownershipRepository = $modelObject.baseline.ownershipRepository
        ownershipCommit = $packageDatabaseCommit
        ownershipDatabasePath = $databaseRelative
        ownershipManifest = [IO.Path]::GetFileName($OwnershipOutput)
        ownershipManifestSha256 = Get-Sha256 $OwnershipOutput
    }
    summary = [ordered]@{
        greenOrCandidateRemoved = $greenRemoved
        modeledRemoved = $modeledRemoved
        remaining = $remaining
        allPathsOwned = $ownershipRows.Count -eq $manifestX64.Count
        overlapCount = 0
        unresolvedOwnershipCount = 0
    }
    deltas = $deltaResults
    productScopes = [ordered]@{
        source = $modelObject.productScopes.source
        products = $productScopes
    }
    recommendations = $recommendations
    paths = $pathResults
}
Write-Utf8 $ReportOutput (($report | ConvertTo-Json -Depth 20) + "`n")

Write-Host "ARM64 x64 backlog generated"
Write-Host "  green/candidate removed: $greenRemoved"
Write-Host "  modeled removed: $modeledRemoved"
Write-Host "  remaining: $remaining"
Write-Host "  ownership: $OwnershipOutput"
Write-Host "  report: $ReportOutput"
