Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$baselineManifest = Join-Path $root "arm64-payload-architecture-v2.55.0.4.tsv"
$baselinePaths = Join-Path $root "arm64-x64-payload-baseline.txt"
$ownershipPath = Join-Path $root "arm64-x64-ownership-v2.55.0.4.tsv"
$reportPath = Join-Path $root "arm64-x64-backlog-v2.55.0.4.json"
$modelPath = Join-Path $root "arm64-validation\backlog-model-v2.55.0.4.json"

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

function Assert-DatabaseValidation {
    param(
        [string]$PackageDatabaseRoot,
        [string]$Model,
        [bool]$ShouldPass,
        [string]$ExpectedError,
        [scriptblock]$AfterRead
    )

    $passed = $true
    $failure = $null
    $arguments = @{
        PackageDatabaseRoot = $PackageDatabaseRoot
        Model = $Model
        ValidatePackageDatabaseOnly = $true
    }
    if ($null -ne $AfterRead) {
        $arguments.ValidationOnlyAfterRead = $AfterRead
    }
    try {
        & (Join-Path $root "generate-arm64-x64-backlog.ps1") @arguments *> $null
    } catch {
        $passed = $false
        $failure = $_.Exception.Message
    }
    if ($passed -ne $ShouldPass) {
        $expectation = if ($ShouldPass) { "accepted" } else { "rejected" }
        throw "Package database was not $expectation"
    }
    if (-not $ShouldPass -and $failure -cnotlike "*$ExpectedError*") {
        throw "Package database rejection did not report '$ExpectedError': $failure"
    }
}

function Test-PackageDatabaseAttestation {
    $fixture = Join-Path ([IO.Path]::GetTempPath()) `
        ("arm64-backlog-db-" + [Guid]::NewGuid().ToString("N"))
    $databaseRelative = "var/lib/pacman/local"
    $database = Join-Path $fixture $databaseRelative
    $tracked = Join-Path $database "tracked"
    $untracked = Join-Path $database "untracked"
    $headMarker = Join-Path $fixture "head-marker"
    $model = Join-Path $fixture "model.json"
    $utf8 = New-Object Text.UTF8Encoding($false)

    try {
        [void](New-Item -ItemType Directory -Path $database)
        & git -C $fixture init --quiet
        & git -C $fixture config user.name "ARM64 backlog test"
        & git -C $fixture config user.email "arm64-backlog-test@example.com"
        & git -C $fixture config core.autocrlf false
        [IO.File]::WriteAllText($tracked, "clean`n", $utf8)
        & git -C $fixture add -- $databaseRelative
        & git -C $fixture commit --quiet -m "Create synthetic package database"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create synthetic package database"
        }
        $commit = (& git -C $fixture rev-parse HEAD).Trim()
        $fixtureModel = [ordered]@{
            schemaVersion = 1
            baseline = [ordered]@{
                ownershipCommit = $commit
                ownershipDatabasePath = $databaseRelative
            }
        }
        [IO.File]::WriteAllText(
            $model,
            (($fixtureModel | ConvertTo-Json -Depth 4) + "`n"),
            $utf8)

        Assert-DatabaseValidation $database $model $true

        [IO.File]::WriteAllText($tracked, "unstaged`n", $utf8)
        Assert-DatabaseValidation $database $model $false `
            "Package database contains staged, unstaged, or untracked changes"
        & git -C $fixture restore -- $databaseRelative

        [IO.File]::WriteAllText($tracked, "staged`n", $utf8)
        & git -C $fixture add -- $databaseRelative
        Assert-DatabaseValidation $database $model $false `
            "Package database contains staged, unstaged, or untracked changes"
        & git -C $fixture restore --staged --worktree -- $databaseRelative

        [IO.File]::WriteAllText($untracked, "untracked`n", $utf8)
        Assert-DatabaseValidation $database $model $false `
            "Package database contains staged, unstaged, or untracked changes"
        Remove-Item -LiteralPath $untracked

        $modifyAfterRead = {
            [IO.File]::WriteAllText($tracked, "post-read`n", $utf8)
        }.GetNewClosure()
        Assert-DatabaseValidation $database $model $false `
            "Package database contains staged, unstaged, or untracked changes" `
            $modifyAfterRead
        & git -C $fixture restore -- $databaseRelative

        $addAfterRead = {
            [IO.File]::WriteAllText($untracked, "post-read`n", $utf8)
        }.GetNewClosure()
        Assert-DatabaseValidation $database $model $false `
            "Package database contains staged, unstaged, or untracked changes" `
            $addAfterRead
        Remove-Item -LiteralPath $untracked

        $advanceHeadAfterRead = {
            [IO.File]::WriteAllText($headMarker, "move HEAD`n", $utf8)
            & git -C $fixture add -- "head-marker"
            & git -C $fixture commit --quiet -m "Move synthetic database HEAD"
        }.GetNewClosure()
        Assert-DatabaseValidation $database $model $false `
            "Package database Git HEAD changed while it was being read" `
            $advanceHeadAfterRead

        Assert-DatabaseValidation "C:\msys64" $model $false `
            "Shared C:\msys64 cannot be used as ownership evidence"
    } finally {
        if (Test-Path -LiteralPath $fixture) {
            Remove-Item -LiteralPath $fixture -Recurse -Force
        }
    }
}

Test-PackageDatabaseAttestation

$model = Get-Content -LiteralPath $modelPath -Raw | ConvertFrom-Json
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
$ownership = @(Import-Csv -LiteralPath $ownershipPath -Delimiter "`t")
$manifestX64 = @(Import-Csv -LiteralPath $baselineManifest -Delimiter "`t" |
    Where-Object architecture -eq "x64")
$x64Paths = @(Get-Content -LiteralPath $baselinePaths)

if ($model.schemaVersion -ne 1 -or $report.schemaVersion -ne 1) {
    throw "Backlog schemaVersion changed"
}
if ((Get-NormalizedTextSha256 $baselineManifest) -cne
    "ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a") {
    throw "Authoritative manifest SHA-256 changed"
}
if ($manifestX64.Count -ne 432 -or $x64Paths.Count -ne 432 -or
    $ownership.Count -ne 432 -or $report.paths.Count -ne 432) {
    throw "Authoritative x64 path count changed"
}

$ownershipPaths = @($ownership | ForEach-Object path)
$reportPaths = @($report.paths | ForEach-Object path)
foreach ($actual in @($x64Paths, $ownershipPaths, $reportPaths)) {
    if (@(Compare-Object $x64Paths $actual -SyncWindow 0).Count -ne 0) {
        throw "Backlog path set does not match the authoritative baseline"
    }
}
if (@($ownership | Where-Object {
    [string]::IsNullOrWhiteSpace($_.sourcePackage) -or
    [string]::IsNullOrWhiteSpace($_.sourceVersion) -or
    $_.ownershipCommit -cne "7a77c0c5ff81d1c979302c9cc49a62f26f68d17c"
}).Count -ne 0) {
    throw "Ownership report contains unresolved or unpinned rows"
}

$claimed = @{}
foreach ($delta in $report.deltas) {
    if ($delta.count -ne $delta.paths.Count) {
        throw "Delta '$($delta.id)' count does not match its paths"
    }
    foreach ($path in $delta.paths) {
        if ($claimed.ContainsKey($path)) {
            throw "Delta overlap at '$path'"
        }
        $claimed[$path] = $delta.id
    }
    if ($delta.status -eq "modeled-unresolved" -and $null -ne $delta.immutableInput) {
        throw "Modeled delta '$($delta.id)' contains a fake immutable pin"
    }
}

$expectedDeltas = @{
    "native-leaf-tools" = 11
    "busybox" = 59
    "win32-openssh" = 14
    "dos2unix" = 6
    "gawk" = 17
    "vim" = 7
    "msys2-runtime" = 31
    "ncurses" = 12
    "readline" = 1
    "bash" = 2
}
foreach ($id in $expectedDeltas.Keys) {
    $delta = @($report.deltas | Where-Object id -CEQ $id)
    if ($delta.Count -ne 1 -or $delta[0].count -ne $expectedDeltas[$id]) {
        throw "Delta '$id' does not match its expected count"
    }
}
if ($claimed.Count -ne 160 -or
    $report.summary.greenOrCandidateRemoved -ne 114 -or
    $report.summary.modeledRemoved -ne 46 -or
    $report.summary.remaining -ne 272 -or
    -not $report.summary.allPathsOwned -or
    $report.summary.overlapCount -ne 0 -or
    $report.summary.unresolvedOwnershipCount -ne 0) {
    throw "Backlog summary changed"
}

$busyBox = @($report.paths | Where-Object delta -CEQ "busybox")
$busyBoxCoreutils = @($busyBox | Where-Object sourcePackage -CEQ "coreutils")
$busyBoxCrossPackage = @($busyBox | Where-Object sourcePackage -CNE "coreutils")
if ($busyBoxCoreutils.Count -ne 54 -or $busyBoxCrossPackage.Count -ne 5) {
    throw "BusyBox ownership split changed"
}
$coreutils = @($report.paths | Where-Object sourcePackage -CEQ "coreutils")
if ($coreutils.Count -ne 108 -or
    @($coreutils | Where-Object state -eq "remaining").Count -ne 54) {
    throw "Coreutils ownership model changed"
}

$remaining = @($report.paths | Where-Object state -eq "remaining")
if (@($remaining | Where-Object action -eq "safe-busybox-substitution").Count -ne 0) {
    throw "An unproven remaining path is labeled as a safe BusyBox substitution"
}
if (@($report.recommendations | ForEach-Object count | Measure-Object -Sum).Sum -ne 272) {
    throw "Ranked recommendations do not cover every remaining path"
}

$expectedProducts = @{
    "installer" = 46
    "portable" = 46
    "mingit" = 13
    "busybox-mingit" = 9
}
foreach ($id in $expectedProducts.Keys) {
    $product = @($report.productScopes.products | Where-Object id -CEQ $id)
    if ($product.Count -ne 1 -or $product[0].count -ne $expectedProducts[$id] -or
        $product[0].paths.Count -ne $expectedProducts[$id]) {
        throw "Product scope '$id' changed"
    }
    foreach ($path in $product[0].paths) {
        $pathRow = @($report.paths | Where-Object path -CEQ $path)
        if ($pathRow.Count -ne 1 -or $pathRow[0].deltaStatus -notlike "modeled-*") {
            throw "Product scope '$id' contains non-modeled path '$path'"
        }
    }
}

Write-Host "ARM64 x64 backlog tests passed"
