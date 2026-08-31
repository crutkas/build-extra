[CmdletBinding()]
param(
    [string]$ModelPath,
    [string]$ArtifactsDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([string]::IsNullOrEmpty($ModelPath)) {
    $ModelPath = Join-Path $PSScriptRoot 'ledger-model-v2.55.0.4.json'
}
if ([string]::IsNullOrEmpty($ArtifactsDirectory)) {
    $ArtifactsDirectory = Join-Path $PSScriptRoot 'artifacts\v2.55.0.4'
}
$modulePath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot 'Arm64Ledger.psm1'))
$moduleStream = New-Object System.IO.FileStream(
    $modulePath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read)
try {
    if ($moduleStream.Length -gt 4194304) {
        throw 'Ledger module exceeds the bootstrap size limit'
    }
    $moduleBytes = New-Object byte[] ([int]$moduleStream.Length)
    $moduleOffset = 0
    while ($moduleOffset -lt $moduleBytes.Length) {
        $moduleRead = $moduleStream.Read(
            $moduleBytes,
            $moduleOffset,
            $moduleBytes.Length - $moduleOffset)
        if ($moduleRead -le 0) {
            throw 'Unexpected EOF while bootstrapping the ledger module'
        }
        $moduleOffset += $moduleRead
    }
} finally {
    $moduleStream.Dispose()
}
$moduleEncoding = New-Object System.Text.UTF8Encoding($false, $true)
$moduleText = $moduleEncoding.GetString($moduleBytes)
if ($moduleText.Length -gt 0 -and $moduleText[0] -eq [char]0xFEFF) {
    throw 'Ledger module must not contain a BOM'
}
$module = New-Module `
    -Name Arm64Ledger `
    -ScriptBlock ([ScriptBlock]::Create($moduleText))
Import-Module $module -Force -DisableNameChecking
$stableModuleBytes = Read-StableBytes -Path $modulePath
if (-not [System.Linq.Enumerable]::SequenceEqual(
    [byte[]]$moduleBytes, [byte[]]$stableModuleBytes)) {
    throw 'Ledger module changed during bootstrap'
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $false)]$Actual,
        [Parameter(Mandatory = $false)]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Actual -is [string] -and $Expected -is [string]) {
        if (-not [StringComparer]::Ordinal.Equals($Actual, $Expected)) {
            throw "$Context differs: expected '$Expected', found '$Actual'"
        }
        return
    }
    if ($Actual -ne $Expected) {
        throw "$Context differs: expected '$Expected', found '$Actual'"
    }
}

function Assert-Hex {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value.Length -ne $Length -or $Value -notmatch '^[0-9a-f]+$') {
        throw "$Context is not a lowercase $Length-character hex value"
    }
}

function Assert-ByteEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Actual,
        [Parameter(Mandatory = $true)][byte[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if (-not [System.Linq.Enumerable]::SequenceEqual(
        [byte[]]$Actual, [byte[]]$Expected)) {
        throw "$Context bytes are not canonical"
    }
}

function Read-CanonicalJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = Read-StableBytes -Path $Path
    if ($bytes.Length -eq 0 -or $bytes[-1] -ne 0x0A) {
        throw "JSON lacks final LF: $Path"
    }
    foreach ($value in $bytes) {
        if ($value -eq 0x0D) {
            throw "JSON contains CR: $Path"
        }
    }
    $value = ConvertFrom-StrictJsonBytes -Bytes $bytes
    Assert-ByteEqual `
        -Actual $bytes `
        -Expected (ConvertTo-CanonicalJsonBytes -Value $value) `
        -Context $Path
    return [ordered]@{
        bytes = $bytes
        value = $value
    }
}

function Get-DataRowsBytes {
    param([Parameter(Mandatory = $true)][object[]]$Rows)

    $builder = New-Object System.Text.StringBuilder
    foreach ($row in $Rows) {
        [void]$builder.Append(($row -join "`t"))
        [void]$builder.Append("`n")
    }
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return ,$encoding.GetBytes($builder.ToString())
}

function Get-StrictPathFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = Read-StableBytes -Path $Path
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $text = $encoding.GetString($bytes)
    if ($text.Length -eq 0 -or
        -not $text.EndsWith("`n", [StringComparison]::Ordinal) -or
        $text.Contains("`r") -or
        $text[0] -eq [char]0xFEFF) {
        throw 'Path list must be UTF-8 without BOM, LF-only, and final-LF'
    }
    $paths = $text.Substring(0, $text.Length - 1).Split("`n")
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    foreach ($pathValue in $paths) {
        Assert-Equal `
            (Normalize-ArchivePath -Path $pathValue) `
            $pathValue `
            'canonical path'
        if (-not $seen.Add($pathValue)) {
            throw "Duplicate path in x64 list: $pathValue"
        }
    }
    $sorted = Sort-Bytewise -Values $paths
    Assert-ByteEqual `
        -Actual $bytes `
        -Expected (Get-CanonicalPathSetBytes -Paths $sorted) `
        -Context 'x64 path list'
    return [ordered]@{
        bytes = $bytes
        paths = $sorted
    }
}

function Assert-ManifestSchema {
    param([Parameter(Mandatory = $true)]$Manifest)

    Assert-ObjectShape `
        -Object $Manifest `
        -Required @(
            'artifacts',
            'canonicalSerialization',
            'scanner',
            'schemaVersion',
            'sourceModel') `
        -Context 'manifest'
    Assert-Equal $Manifest.schemaVersion 1 'manifest.schemaVersion'
    Assert-ObjectShape `
        -Object $Manifest.canonicalSerialization `
        -Required @(
            'encoding',
            'jsonObjectKeys',
            'lineEndings',
            'pathOrder',
            'terminalLf') `
        -Context 'manifest.canonicalSerialization'
    Assert-Equal `
        $Manifest.canonicalSerialization.encoding `
        'UTF-8 without BOM' `
        'manifest encoding'
    Assert-Equal `
        $Manifest.canonicalSerialization.jsonObjectKeys `
        'UTF-8 bytewise ascending' `
        'manifest JSON ordering'
    Assert-Equal `
        $Manifest.canonicalSerialization.lineEndings `
        'LF' `
        'manifest line endings'
    Assert-Equal `
        $Manifest.canonicalSerialization.pathOrder `
        'UTF-8 bytewise ascending' `
        'manifest path ordering'
    Assert-Equal `
        $Manifest.canonicalSerialization.terminalLf `
        $true `
        'manifest terminal LF'
    foreach ($identityName in @('scanner', 'sourceModel')) {
        Assert-ObjectShape `
            -Object $Manifest[$identityName] `
            -Required @('gitBlobSha1', 'path', 'sha256') `
            -Context "manifest.$identityName"
        Assert-Hex `
            $Manifest[$identityName].gitBlobSha1 `
            40 `
            "manifest.$identityName.gitBlobSha1"
        Assert-Hex `
            $Manifest[$identityName].sha256 `
            64 `
            "manifest.$identityName.sha256"
    }
    if ($Manifest.artifacts -isnot [System.Array] -or
        $Manifest.artifacts.Count -eq 0) {
        throw 'manifest.artifacts must be a non-empty array'
    }
    $names = New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    foreach ($artifact in $Manifest.artifacts) {
        Assert-ObjectShape `
            -Object $artifact `
            -Required @('path', 'sha256', 'size') `
            -Context 'manifest artifact'
        if ($artifact.path -notmatch
            '^[a-z0-9][a-z0-9.-]*\.(?:json|tsv|txt)$' -or
            -not $names.Add($artifact.path)) {
            throw "Manifest artifact name is unsafe or duplicate: $($artifact.path)"
        }
        Assert-Hex $artifact.sha256 64 'manifest artifact sha256'
        if ($artifact.size -isnot [long] -or $artifact.size -le 0) {
            throw 'Manifest artifact size must be a positive integer'
        }
    }
}

function Assert-ProvenanceSchema {
    param(
        [Parameter(Mandatory = $true)]$Provenance,
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)][byte[]]$ModelBytes,
        [Parameter(Mandatory = $true)][byte[]]$ScannerBytes
    )

    Assert-ObjectShape `
        -Object $Provenance `
        -Required @(
            'apiEvidence',
            'archive',
            'ownership',
            'release',
            'scanner',
            'sourceModel') `
        -Context 'provenance'
    Assert-ObjectShape `
        -Object $Provenance.archive `
        -Required @('authenticatedDownloadCopies', 'tarSha256') `
        -Context 'provenance.archive'
    Assert-Equal `
        $Provenance.archive.authenticatedDownloadCopies `
        2 `
        'authenticated download copies'
    Assert-Hex `
        $Provenance.archive.tarSha256 64 'provenance archive TAR hash'
    Assert-ObjectShape `
        -Object $Provenance.apiEvidence `
        -Required @(
            'assetApiDigest',
            'assetCreatedAt',
            'assetUpdatedAt',
            'commitTree',
            'peeledCommit',
            'releaseCreatedAt',
            'releaseId',
            'releasePublishedAt',
            'tagObject') `
        -Context 'provenance.apiEvidence'
    Assert-Equal `
        $Provenance.apiEvidence.assetApiDigest `
        $Model.release.asset.apiDigest `
        'API asset digest'
    Assert-Equal `
        $Provenance.apiEvidence.assetCreatedAt `
        $Model.release.asset.createdAt `
        'API asset created timestamp'
    Assert-Equal `
        $Provenance.apiEvidence.assetUpdatedAt `
        $Model.release.asset.updatedAt `
        'API asset updated timestamp'
    Assert-Equal `
        $Provenance.apiEvidence.commitTree `
        $Model.release.peeledCommitTree `
        'API commit tree'
    Assert-Equal `
        $Provenance.apiEvidence.peeledCommit `
        $Model.release.peeledCommit `
        'API peeled commit'
    Assert-Equal `
        $Provenance.apiEvidence.releaseCreatedAt `
        $Model.release.createdAt `
        'API release created timestamp'
    Assert-Equal `
        $Provenance.apiEvidence.releasePublishedAt `
        $Model.release.publishedAt `
        'API release published timestamp'
    Assert-Equal `
        $Provenance.apiEvidence.releaseId `
        $Model.release.id `
        'API release ID'
    Assert-Equal `
        $Provenance.apiEvidence.tagObject `
        $Model.release.tagObject `
        'API tag object'
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes -Value $Provenance.release) `
        -Expected (ConvertTo-CanonicalJsonBytes -Value $Model.release) `
        -Context 'provenance release binding'

    Assert-ObjectShape `
        -Object $Provenance.ownership `
        -Required @(
            'canonicalMappingSha256',
            'commit',
            'databaseArchiveTarSha256',
            'databasePath',
            'databaseTree',
            'independentPrivateBareClones',
            'packageCount',
            'recordBlobCount',
            'repository',
            'rootTree') `
        -Context 'provenance.ownership'
    foreach ($name in @(
        'canonicalMappingSha256',
        'commit',
        'databaseArchiveTarSha256',
        'databasePath',
        'databaseTree',
        'packageCount',
        'recordBlobCount',
        'repository',
        'rootTree')) {
        Assert-Equal `
            $Provenance.ownership[$name] `
            $Model.ownership[$name] `
            "provenance ownership $name"
    }
    Assert-Equal `
        $Provenance.ownership.independentPrivateBareClones `
        2 `
        'independent ownership clone count'

    Assert-ObjectShape `
        -Object $Provenance.scanner `
        -Required @(
            'gitBlobSha1',
            'path',
            'referenceScanners',
            'sha256') `
        -Context 'provenance.scanner'
    Assert-Equal `
        $Provenance.scanner.path `
        $Model.scanner.path `
        'scanner path'
    Assert-Equal `
        $Provenance.scanner.sha256 `
        (Get-Sha256Hex -Bytes $ScannerBytes) `
        'scanner SHA-256'
    Assert-Equal `
        $Provenance.scanner.gitBlobSha1 `
        (Get-GitBlobSha1 -Bytes $ScannerBytes) `
        'scanner Git blob'
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes `
            -Value $Provenance.scanner.referenceScanners) `
        -Expected (ConvertTo-CanonicalJsonBytes `
            -Value $Model.scanner.referenceScanners) `
        -Context 'reference scanner binding'

    Assert-ObjectShape `
        -Object $Provenance.sourceModel `
        -Required @('gitBlobSha1', 'path', 'sha256') `
        -Context 'provenance.sourceModel'
    Assert-Equal `
        $Provenance.sourceModel.path `
        'arm64-validation/ledger-model-v2.55.0.4.json' `
        'source model path'
    Assert-Equal `
        $Provenance.sourceModel.sha256 `
        (Get-Sha256Hex -Bytes $ModelBytes) `
        'source model SHA-256'
    Assert-Equal `
        $Provenance.sourceModel.gitBlobSha1 `
        (Get-GitBlobSha1 -Bytes $ModelBytes) `
        'source model Git blob'
}

function Assert-ArchiveSummary {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]$Provenance
    )

    Assert-ObjectShape `
        -Object $Summary `
        -Required @(
            'architectureCounts',
            'hardlinkCount',
            'installedLinkPolicy',
            'linkCount',
            'memberCount',
            'peCount',
            'tarSha256',
            'typeCounts',
            'x64PathSha256',
            'zeroBlockCount') `
        -Context 'archive summary'
    Assert-ObjectShape `
        -Object $Summary.architectureCounts `
        -Required @('anycpu', 'arm64', 'x64', 'x86') `
        -Context 'archive architecture counts'
    foreach ($name in @('anycpu', 'arm64', 'x64', 'x86')) {
        Assert-Equal `
            $Summary.architectureCounts[$name] `
            $Model.archiveExpectations.architectureCounts[$name] `
            "archive architecture $name"
    }
    Assert-ObjectShape `
        -Object $Summary.typeCounts `
        -Required @('directory', 'file', 'hardlink', 'symlink') `
        -Context 'archive type counts'
    Assert-Equal `
        $Summary.hardlinkCount `
        $Model.archiveExpectations.hardlinkCount `
        'archive hardlink count'
    Assert-Equal `
        $Summary.typeCounts.hardlink `
        $Summary.hardlinkCount `
        'archive hardlink type count'
    Assert-Equal `
        $Summary.typeCounts.symlink `
        $Model.archiveExpectations.allowedAbsoluteSymlinks.Count `
        'archive symlink count'
    Assert-Equal `
        $Summary.linkCount `
        ($Summary.typeCounts.hardlink + $Summary.typeCounts.symlink) `
        'archive link total'
    Assert-Equal `
        $Summary.memberCount `
        $Model.archiveExpectations.memberCount `
        'archive member count'
    Assert-Equal `
        ($Summary.typeCounts.directory + $Summary.typeCounts.file +
            $Summary.typeCounts.hardlink + $Summary.typeCounts.symlink) `
        $Summary.memberCount `
        'archive type partition'
    Assert-Equal `
        $Summary.peCount `
        $Model.archiveExpectations.peCount `
        'archive PE count'
    Assert-Equal `
        $Summary.tarSha256 `
        $Provenance.archive.tarSha256 `
        'archive TAR hash binding'
    Assert-Equal `
        $Summary.x64PathSha256 `
        $Model.archiveExpectations.x64PathSha256 `
        'archive x64 path hash'
    if ($Summary.zeroBlockCount -lt 2) {
        throw 'Archive summary records fewer than two terminal zero blocks'
    }
    Assert-ObjectShape `
        -Object $Summary.installedLinkPolicy `
        -Required @(
            'absoluteTargetsAreExtractionPaths',
            'description',
            'links') `
        -Context 'installed-link policy'
    Assert-Equal `
        $Summary.installedLinkPolicy.absoluteTargetsAreExtractionPaths `
        $false `
        'installed-link extraction policy'
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes `
            -Value $Summary.installedLinkPolicy.links) `
        -Expected (ConvertTo-CanonicalJsonBytes `
            -Value $Model.archiveExpectations.allowedAbsoluteSymlinks) `
        -Context 'installed-link allowlist'
}

function Get-ProductExpectation {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]$Compilation
    )

    $rulePaths = New-OrdinalDictionary
    foreach ($rule in $Compilation.rules) {
        $rulePaths[$rule.id] = $rule.paths
    }
    $results = New-Object System.Collections.ArrayList
    foreach ($product in $Model.products) {
        $paths = New-Object 'System.Collections.Generic.HashSet[string]' (
            [StringComparer]::Ordinal)
        if ($product.Contains('ruleIds')) {
            foreach ($ruleId in $product.ruleIds) {
                foreach ($path in $rulePaths[$ruleId]) {
                    if (-not $paths.Add($path)) {
                        throw "Product expectation repeats path: $path"
                    }
                }
            }
        } else {
            foreach ($path in $product.paths) {
                if (-not $paths.Add($path)) {
                    throw "Product expectation repeats path: $path"
                }
            }
        }
        $pathArray = New-Object string[] $paths.Count
        $paths.CopyTo($pathArray)
        [void]$results.Add([ordered]@{
            id = $product.id
            pathCount = [long]$paths.Count
            paths = Sort-Bytewise -Values $pathArray
            status = 'projection-only-unresolved'
        })
    }
    return ,$results.ToArray()
}

function Assert-Backlog {
    param(
        [Parameter(Mandatory = $true)]$Backlog,
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]$Compilation,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Ownership
    )

    Assert-ObjectShape `
        -Object $Backlog `
        -Required @(
            'accounting',
            'baseline',
            'legacyOverlap',
            'notice',
            'paths',
            'products',
            'recommendations',
            'rules',
            'schemaVersion',
            'sourceRuleAudit') `
        -Context 'backlog'
    Assert-Equal $Backlog.schemaVersion 1 'backlog schemaVersion'
    Assert-ObjectShape `
        -Object $Backlog.accounting `
        -Required @(
            'admittedPathReduction',
            'evidenceBackedCandidate',
            'modeledUnresolved',
            'releasedX64Paths',
            'residual',
            'schedulingOnly') `
        -Context 'backlog accounting'
    Assert-Equal `
        $Backlog.accounting.admittedPathReduction `
        0 `
        'admitted reduction'
    Assert-Equal `
        $Backlog.accounting.schedulingOnly `
        $true `
        'scheduling-only flag'
    Assert-Equal `
        $Backlog.accounting.releasedX64Paths `
        $Model.expected.totalCount `
        'released x64 count'
    Assert-Equal `
        $Backlog.accounting.evidenceBackedCandidate `
        $Model.expected.evidenceBackedCandidateCount `
        'evidence candidate count'
    Assert-Equal `
        $Backlog.accounting.modeledUnresolved `
        $Model.expected.modeledCount `
        'modeled count'
    Assert-Equal `
        $Backlog.accounting.residual `
        $Model.expected.residualCount `
        'residual count'
    Assert-ObjectShape `
        -Object $Backlog.baseline `
        -Required @(
            'ownershipMappingSha256',
            'releaseAssetSha256',
            'x64PathSha256') `
        -Context 'backlog baseline'
    Assert-Equal `
        $Backlog.baseline.ownershipMappingSha256 `
        $Model.ownership.canonicalMappingSha256 `
        'backlog ownership hash'
    Assert-Equal `
        $Backlog.baseline.releaseAssetSha256 `
        $Model.release.asset.downloadSha256 `
        'backlog asset hash'
    Assert-Equal `
        $Backlog.baseline.x64PathSha256 `
        $Model.archiveExpectations.x64PathSha256 `
        'backlog x64 hash'
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes -Value $Backlog.legacyOverlap) `
        -Expected (ConvertTo-CanonicalJsonBytes -Value $Model.legacyOverlap) `
        -Context 'legacy overlap record'
    if ($Backlog.notice -notmatch '^This ledger is scheduling evidence only\.') {
        throw 'Backlog notice does not forbid reduction claims'
    }
    Assert-ObjectShape `
        -Object $Backlog.sourceRuleAudit `
        -Required @(
            'consumedPathCount',
            'sourceOverlapCount',
            'unconsumedPathCount') `
        -Context 'source rule audit'
    Assert-Equal `
        $Backlog.sourceRuleAudit.consumedPathCount `
        $Model.expected.totalCount `
        'source rule consumed count'
    Assert-Equal `
        $Backlog.sourceRuleAudit.sourceOverlapCount `
        $Model.expected.sourceOverlapCount `
        'source rule overlap count'
    Assert-Equal `
        $Backlog.sourceRuleAudit.unconsumedPathCount `
        0 `
        'source rule unconsumed count'
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes -Value $Backlog.rules) `
        -Expected (ConvertTo-CanonicalJsonBytes -Value $Compilation.rules) `
        -Context 'compiled source rules'

    if ($Backlog.paths -isnot [System.Array] -or
        $Backlog.paths.Count -ne $Model.expected.totalCount) {
        throw 'Backlog path table has the wrong count'
    }
    $pathSet = New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    foreach ($record in $Backlog.paths) {
        Assert-ObjectShape `
            -Object $record `
            -Required @(
                'action',
                'ledgerClass',
                'owner',
                'path',
                'ruleId',
                'version') `
            -Context 'backlog path'
        if (-not $pathSet.Add($record.path)) {
            throw "Backlog repeats path: $($record.path)"
        }
        if (-not $Ownership.Contains($record.path)) {
            throw "Backlog has unknown path: $($record.path)"
        }
        $owner = $Ownership[$record.path]
        $assignment = $Compilation.assignments[$record.path]
        foreach ($name in @('owner', 'version')) {
            Assert-Equal `
                $record[$name] $owner[$name] "backlog path $name"
        }
        foreach ($name in @('action', 'ledgerClass', 'ruleId')) {
            Assert-Equal `
                $record[$name] `
                $assignment[$name] `
                "backlog path $name"
        }
    }
    $expectedRecommendations = Get-LedgerRecommendations `
        -Ownership $Ownership `
        -Assignments $Compilation.assignments
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes `
            -Value $Backlog.recommendations) `
        -Expected (ConvertTo-CanonicalJsonBytes `
            -Value $expectedRecommendations) `
        -Context 'recommendations'
    if ($Backlog.recommendations.Count -ne
        $Model.expected.recommendationCount) {
        throw 'Recommendation count differs'
    }
    $recommendedPaths = New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $Backlog.recommendations.Count; $index++) {
        $recommendation = $Backlog.recommendations[$index]
        Assert-ObjectShape `
            -Object $recommendation `
            -Required @(
                'action',
                'owner',
                'pathCount',
                'paths',
                'rank',
                'version') `
            -Context 'recommendation'
        Assert-Equal `
            $recommendation.rank `
            ($index + 1) `
            'recommendation rank'
        Assert-Equal `
            $recommendation.pathCount `
            $recommendation.paths.Count `
            'recommendation path count'
        foreach ($path in $recommendation.paths) {
            if (-not $recommendedPaths.Add($path)) {
                throw "Recommendation repeats path: $path"
            }
            Assert-Equal `
                $Compilation.assignments[$path].ledgerClass `
                'residual' `
                'recommendation ledger class'
        }
    }
    Assert-Equal `
        $recommendedPaths.Count `
        $Model.expected.residualCount `
        'recommendation residual coverage'
    $expectedProducts = Get-ProductExpectation `
        -Model $Model `
        -Compilation $Compilation
    Assert-ByteEqual `
        -Actual (ConvertTo-CanonicalJsonBytes -Value $Backlog.products) `
        -Expected (ConvertTo-CanonicalJsonBytes -Value $expectedProducts) `
        -Context 'product scopes'
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$modelFullPath = [System.IO.Path]::GetFullPath($ModelPath)
$artifactsFullPath = [System.IO.Path]::GetFullPath($ArtifactsDirectory)
$scannerPath = $modulePath
foreach ($path in @($modelFullPath, $artifactsFullPath, $scannerPath)) {
    if (-not (Test-ContainedPath -Path $path -Root $repositoryRoot)) {
        throw "Checker input is outside the repository: $path"
    }
}
Assert-SafeExistingPath -Path $artifactsFullPath -Kind Directory | Out-Null
$modelBytes = Read-StableBytes -Path $modelFullPath
$scannerBytes = Read-StableBytes -Path $scannerPath
$model = ConvertFrom-StrictJsonBytes -Bytes $modelBytes
Assert-LedgerModel -Model $model
Assert-ByteEqual `
    -Actual $modelBytes `
    -Expected (ConvertTo-CanonicalJsonBytes -Value $model) `
    -Context 'source model'

$manifestRecord = Read-CanonicalJson `
    -Path (Join-Path $artifactsFullPath 'manifest.json')
$manifest = $manifestRecord.value
Assert-ManifestSchema -Manifest $manifest
Assert-Equal `
    $manifest.scanner.path `
    'arm64-validation/Arm64Ledger.psm1' `
    'manifest scanner path'
Assert-Equal `
    $manifest.scanner.sha256 `
    (Get-Sha256Hex -Bytes $scannerBytes) `
    'manifest scanner SHA-256'
Assert-Equal `
    $manifest.scanner.gitBlobSha1 `
    (Get-GitBlobSha1 -Bytes $scannerBytes) `
    'manifest scanner blob'
Assert-Equal `
    $manifest.sourceModel.path `
    'arm64-validation/ledger-model-v2.55.0.4.json' `
    'manifest model path'
Assert-Equal `
    $manifest.sourceModel.sha256 `
    (Get-Sha256Hex -Bytes $modelBytes) `
    'manifest model SHA-256'
Assert-Equal `
    $manifest.sourceModel.gitBlobSha1 `
    (Get-GitBlobSha1 -Bytes $modelBytes) `
    'manifest model blob'

$expectedArtifactNames = New-Object `
    'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($artifact in $manifest.artifacts) {
    [void]$expectedArtifactNames.Add($artifact.path)
    $path = Join-Path $artifactsFullPath $artifact.path
    Assert-SafeExistingPath `
        -Path $path `
        -Kind File `
        -AllowedRoot $artifactsFullPath | Out-Null
    $identity = Get-StableFileHash -Path $path
    Assert-Equal $identity.length $artifact.size "artifact $($artifact.path) size"
    Assert-Equal `
        $identity.sha256 `
        $artifact.sha256 `
        "artifact $($artifact.path) SHA-256"
}
foreach ($file in [System.IO.Directory]::GetFiles($artifactsFullPath)) {
    $name = [System.IO.Path]::GetFileName($file)
    if ($name -ne 'manifest.json' -and
        -not $expectedArtifactNames.Contains($name)) {
        throw "Unconsumed artifact file: $name"
    }
}
Assert-Equal `
    $expectedArtifactNames.Count `
    ([System.IO.Directory]::GetFiles($artifactsFullPath).Count - 1) `
    'artifact file count'

$provenanceRecord = Read-CanonicalJson `
    -Path (Join-Path $artifactsFullPath 'provenance.json')
$provenance = $provenanceRecord.value
Assert-ProvenanceSchema `
    -Provenance $provenance `
    -Model $model `
    -ModelBytes $modelBytes `
    -ScannerBytes $scannerBytes
$summaryRecord = Read-CanonicalJson `
    -Path (Join-Path $artifactsFullPath 'archive-summary.json')
Assert-ArchiveSummary `
    -Summary $summaryRecord.value `
    -Model $model `
    -Provenance $provenance

$x64 = Get-StrictPathFile `
    -Path (Join-Path $artifactsFullPath 'x64-paths.txt')
Assert-Equal $x64.paths.Count $model.expected.totalCount 'x64 path count'
Assert-Equal `
    (Get-Sha256Hex -Bytes $x64.bytes) `
    $model.archiveExpectations.x64PathSha256 `
    'x64 path hash'

$ownershipRows = ConvertFrom-StrictTsvBytes `
    -Bytes (Read-StableBytes `
        -Path (Join-Path $artifactsFullPath 'x64-ownership.tsv')) `
    -Header @('path', 'owner', 'version') `
    -KeyColumn 0
Assert-Equal `
    $ownershipRows.Count `
    $model.expected.totalCount `
    'ownership row count'
Assert-Equal `
    (Get-Sha256Hex -Bytes (Get-DataRowsBytes -Rows $ownershipRows)) `
    $model.ownership.canonicalMappingSha256 `
    'path-owner-version hash'
$ownership = New-OrdinalDictionary
for ($index = 0; $index -lt $ownershipRows.Count; $index++) {
    $row = $ownershipRows[$index]
    Assert-Equal $row[0] $x64.paths[$index] 'ownership path ordering'
    Assert-Equal `
        (Normalize-ArchivePath -Path $row[0]) `
        $row[0] `
        'ownership canonical path'
    if ([string]::IsNullOrEmpty($row[1]) -or
        [string]::IsNullOrEmpty($row[2])) {
        throw "Ownership row has empty owner/version: $($row[0])"
    }
    $ownership[$row[0]] = [ordered]@{
        owner = $row[1]
        version = $row[2]
    }
}
$compilation = Compile-LedgerRules -Model $model -Ownership $ownership

$sourceRows = ConvertFrom-StrictTsvBytes `
    -Bytes (Read-StableBytes `
        -Path (Join-Path $artifactsFullPath 'source-rules.tsv')) `
    -Header @(
        'path',
        'owner',
        'version',
        'ruleId',
        'ledgerClass',
        'action') `
    -KeyColumn 0
Assert-Equal `
    $sourceRows.Count `
    $model.expected.totalCount `
    'source-rule row count'
for ($index = 0; $index -lt $sourceRows.Count; $index++) {
    $row = $sourceRows[$index]
    Assert-Equal $row[0] $x64.paths[$index] 'source-rule path ordering'
    Assert-Equal $row[1] $ownership[$row[0]].owner 'source-rule owner'
    Assert-Equal $row[2] $ownership[$row[0]].version 'source-rule version'
    Assert-Equal `
        $row[3] $compilation.assignments[$row[0]].ruleId 'source-rule ID'
    Assert-Equal `
        $row[4] `
        $compilation.assignments[$row[0]].ledgerClass `
        'source-rule class'
    Assert-Equal `
        $row[5] $compilation.assignments[$row[0]].action 'source-rule action'
}

$peRows = ConvertFrom-StrictTsvBytes `
    -Bytes (Read-StableBytes `
        -Path (Join-Path $artifactsFullPath 'pe-manifest.tsv')) `
    -Header @(
        'path',
        'architecture',
        'machine',
        'size',
        'sha256',
        'archiveType',
        'owner',
        'version') `
    -KeyColumn 0
Assert-Equal $peRows.Count $model.archiveExpectations.peCount 'PE row count'
$peCounts = [ordered]@{
    anycpu = [long]0
    arm64 = [long]0
    x64 = [long]0
    x86 = [long]0
}
$peX64 = New-Object System.Collections.Generic.List[string]
$previousPath = $null
foreach ($row in $peRows) {
    Assert-Equal `
        (Normalize-ArchivePath -Path $row[0]) `
        $row[0] `
        'PE canonical path'
    if ($null -ne $previousPath) {
        $orderedPair = Sort-Bytewise -Values @($previousPath, $row[0])
        Assert-Equal $orderedPair[0] $previousPath 'PE bytewise ordering'
    }
    $previousPath = $row[0]
    if (-not $peCounts.Contains($row[1])) {
        throw "Unknown PE architecture: $($row[1])"
    }
    $expectedMachine = switch ($row[1]) {
        'arm64' { '0xAA64' }
        'x64' { '0x8664' }
        'anycpu' { '0x014C' }
        'x86' { '0x014C' }
    }
    Assert-Equal $row[2] $expectedMachine 'PE machine'
    [long]$size = 0
    if (-not [long]::TryParse(
        $row[3],
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$size) -or $size -le 0) {
        throw "PE size is malformed: $($row[0])"
    }
    Assert-Hex $row[4] 64 'PE SHA-256'
    if ($row[5] -ne 'file' -and $row[5] -ne 'hardlink') {
        throw "PE archive type is invalid: $($row[5])"
    }
    $peCounts[$row[1]]++
    if ($row[1] -eq 'x64') {
        $peX64.Add($row[0])
        Assert-Equal $row[6] $ownership[$row[0]].owner 'PE owner'
        Assert-Equal $row[7] $ownership[$row[0]].version 'PE version'
    } elseif ($row[6] -ne 'not-applicable' -or
        $row[7] -ne 'not-applicable') {
        throw "Non-x64 PE row carries ownership attribution: $($row[0])"
    }
}
foreach ($name in $peCounts.Keys) {
    Assert-Equal `
        $peCounts[$name] `
        $model.archiveExpectations.architectureCounts[$name] `
        "PE architecture count $name"
}
Assert-ByteEqual `
    -Actual (Get-CanonicalPathSetBytes -Paths $peX64.ToArray()) `
    -Expected $x64.bytes `
    -Context 'PE x64 set'

$linkRows = ConvertFrom-StrictTsvBytes `
    -Bytes (Read-StableBytes `
        -Path (Join-Path $artifactsFullPath 'archive-links.tsv')) `
    -Header @('path', 'type', 'target', 'policy', 'resolvedTarget') `
    -KeyColumn 0
Assert-Equal `
    $linkRows.Count `
    ($model.archiveExpectations.hardlinkCount +
        $model.archiveExpectations.allowedAbsoluteSymlinks.Count) `
    'link row count'
$installedLinks = New-OrdinalDictionary
foreach ($link in $model.archiveExpectations.allowedAbsoluteSymlinks) {
    $installedLinks[$link.path] = $link.target
}
$hardlinks = 0
$symlinks = 0
$linkPrevious = $null
foreach ($row in $linkRows) {
    Assert-Equal `
        (Normalize-ArchivePath -Path $row[0]) `
        $row[0] `
        'link canonical path'
    if ($null -ne $linkPrevious) {
        $orderedPair = Sort-Bytewise -Values @($linkPrevious, $row[0])
        Assert-Equal $orderedPair[0] $linkPrevious 'link bytewise ordering'
    }
    $linkPrevious = $row[0]
    if ($row[1] -eq 'hardlink') {
        $hardlinks++
        Assert-Equal $row[3] 'payload-internal' 'hardlink policy'
        Assert-Equal `
            (Normalize-ArchivePath -Path $row[2]) `
            $row[4] `
            'hardlink resolved target'
    } elseif ($row[1] -eq 'symlink') {
        $symlinks++
        if (-not $installedLinks.Contains($row[0])) {
            throw "Unknown installed absolute symlink: $($row[0])"
        }
        Assert-Equal `
            $row[2] $installedLinks[$row[0]] 'installed symlink target'
        Assert-Equal `
            $row[3] `
            'runtime-virtual-absolute' `
            'installed symlink policy'
        Assert-Equal `
            $row[4] `
            'not-applicable' `
            'installed symlink resolved target'
    } else {
        throw "Unknown archive link type: $($row[1])"
    }
}
Assert-Equal `
    $hardlinks `
    $model.archiveExpectations.hardlinkCount `
    'hardlink ledger count'
Assert-Equal `
    $symlinks `
    $model.archiveExpectations.allowedAbsoluteSymlinks.Count `
    'symlink ledger count'

$backlogRecord = Read-CanonicalJson `
    -Path (Join-Path $artifactsFullPath 'backlog.json')
Assert-Backlog `
    -Backlog $backlogRecord.value `
    -Model $model `
    -Compilation $compilation `
    -Ownership $ownership

foreach ($artifact in $manifest.artifacts) {
    $bytes = Read-StableBytes `
        -Path (Join-Path $artifactsFullPath $artifact.path)
    $text = (New-Object System.Text.UTF8Encoding($false, $true)).
        GetString($bytes)
    foreach ($forbidden in @(
        'C:\Users\',
        '\.copilot\',
        'copilot-worktrees',
        'session-state',
        'crutkas/git-sdk-arm64',
        '"pullRequest": 8')) {
        if ($text.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge
            0) {
            throw "Artifact $($artifact.path) contains forbidden identity: " +
                $forbidden
        }
    }
}

Write-Host (
    "PASS: $($model.expected.totalCount) x64 paths; " +
    "$($model.expected.ruleCount) disjoint rules; " +
    "$($model.expected.recommendationCount) ranked groups; " +
    "$($model.archiveExpectations.peCount) PEs; " +
    "$($model.archiveExpectations.hardlinkCount) hardlinks; " +
    "$($model.archiveExpectations.allowedAbsoluteSymlinks.Count) " +
    'installed-link metadata records')
