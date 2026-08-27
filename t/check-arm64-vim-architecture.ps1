param(
    [Parameter(Mandatory = $true)]
    [string]$Lock,

    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$Scanner,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$DistributionReport
)

$ErrorActionPreference = "Stop"
$data = Get-Content -Raw -LiteralPath $Lock | ConvertFrom-Json
$expected = @(
    "usr/bin/ex.exe",
    "usr/bin/rview.exe",
    "usr/bin/rvim.exe",
    "usr/bin/view.exe",
    "usr/bin/vim.exe",
    "usr/bin/vimdiff.exe",
    "usr/bin/xxd.exe"
)

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Assert-SetEqual([string[]]$Expected, [string[]]$Actual, [string]$Message) {
    $difference = Compare-Object @($Expected | Sort-Object -Unique) @($Actual | Sort-Object -Unique)
    if ($difference) {
        throw "$Message`: $($difference | Out-String)"
    }
}

Assert-Equal -7 $data.expected.architectureDelta.x64 "Unexpected locked x64 delta"
Assert-Equal 19 $data.expected.architectureDelta.arm64 "Unexpected locked ARM64 delta"
Assert-Equal 0 $data.expected.architectureDelta.unexpectedX64 "Unexpected x64 files are permitted"
Assert-SetEqual $expected @($data.expected.replacements) "Unexpected locked replacement paths"

$provenancePath = Join-Path $Root "etc\arm64-vim-provenance.json"
$report = [ordered]@{
    schemaVersion = 1
    inputId = $data.inputId
    mode = if ($data.status -eq "admitted") {
        "final"
    } elseif ($data.status -eq "measuring") {
        "measurement"
    } else {
        "preview"
    }
    admission = $data.status
    expectedArchitectureDelta = $data.expected.architectureDelta
    expectedDistributionBytesDelta = $data.expected.distributionBytesDelta
    replacements = @($expected)
    retained = @("usr/bin/vimtutor")
    observed = $null
    unresolved = @()
}

if ($data.status -eq "unresolved") {
    if (Test-Path -LiteralPath $provenancePath) {
        throw "Preview mode found materialized ARM64 Vim provenance"
    }
    foreach ($field in @(
        "repository", "releaseId", "tag", "tagObjectSha", "tagMessage",
        "peeledCommit", "url", "publishedAt"
    )) {
        if ($data.release.$field) {
            throw "Preview lock partially resolves release.$field"
        }
        $report.unresolved += "release.$field"
    }
    if ($null -ne $data.release.body.bytes -or $data.release.body.sha256) {
        throw "Preview lock partially resolves release.body"
    }
    $report.unresolved += "release.body.bytes"
    $report.unresolved += "release.body.sha256"
    foreach ($asset in $data.release.assets) {
        if ($asset.assetId -or $asset.url) {
            throw "Preview lock partially resolves $($asset.name)"
        }
        $assetLabel = if ($asset.name) { $asset.name } else { $asset.role }
        if (-not $asset.name) {
            $report.unresolved += "$assetLabel.name"
        }
        $report.unresolved += "$assetLabel.assetId"
        $report.unresolved += "$assetLabel.url"
    }
    foreach ($artifact in @("installer", "portable")) {
        if ($null -ne $data.expected.distributionBytesDelta.$artifact) {
            throw "Preview mode must not claim a measured $artifact byte delta"
        }
        $report.unresolved += "distributionBytesDelta.$artifact"
    }
} elseif ($data.status -in @("measuring", "admitted")) {
    if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
        throw "$($report.mode) mode is missing the ARM64 Vim provenance manifest"
    }
    if (-not $DistributionReport -or
        -not (Test-Path -LiteralPath $DistributionReport -PathType Leaf)) {
        throw "$($report.mode) mode is missing the verified distribution impact report"
    }
    $distribution = Get-Content -Raw -LiteralPath $DistributionReport | ConvertFrom-Json
    Assert-Equal $report.mode $distribution.mode "The distribution impact mode does not match"
    if ($data.status -eq "admitted") {
        foreach ($field in @("installer", "portable")) {
            if ($null -eq $data.expected.distributionBytesDelta.$field) {
                throw "Final mode is missing the measured $field byte delta"
            }
        }
        Assert-Equal ([int64]$data.expected.distributionBytesDelta.installer) `
            ([int64]$distribution.observedProductBytesDelta.installer) `
            "The installer byte delta was not verified"
        Assert-Equal ([int64]$data.expected.distributionBytesDelta.portable) `
            ([int64]$distribution.observedProductBytesDelta.portable) `
            "The Portable Git byte delta was not verified"
    }
    Assert-Equal 0 ([int64]$distribution.observedProductBytesDelta.mingit) `
        "MinGit changed"
    Assert-Equal 0 ([int64]$distribution.observedProductBytesDelta.busyboxMingit) `
        "BusyBox MinGit changed"
    $provenance = Get-Content -Raw -LiteralPath $provenancePath | ConvertFrom-Json
    Assert-Equal "final" $provenance.mode "The provenance manifest is not final"
    Assert-Equal $data.inputId $provenance.inputId "Unexpected provenance input"
    $allFiles = @($provenance.files) + @($provenance.dependencyClosure)
    $pePaths = @($allFiles | Where-Object peMachine -eq "0xAA64" |
        ForEach-Object destinationPath)
    $replacementPaths = @($provenance.files |
        Where-Object sourcePackage -eq "mingw-w64-clang-aarch64-vim" |
        Where-Object peMachine -eq "0xAA64" |
        ForEach-Object destinationPath)
    Assert-SetEqual $expected $replacementPaths "Final provenance has an unexpected PE replacement set"
    Assert-Equal 19 $pePaths.Count "Final provenance has an unexpected PE closure count"
    if (@($provenance.files | Where-Object destinationPath -eq "usr/bin/vimtutor").Count) {
        throw "Final provenance misclassifies vimtutor as a package file"
    }
    Assert-Equal "base" $provenance.retained[0].sourceInput "vimtutor is not retained from the base"

    $scanPaths = @($pePaths)
    $fileList = Join-Path ([IO.Path]::GetTempPath()) "arm64-vim-architecture-$PID.txt"
    try {
        $scanPaths | Set-Content -Encoding ascii -LiteralPath $fileList
        $rows = @(& $Scanner -ArchitectureOnly -Root $Root -FileList $fileList)
        if ($LASTEXITCODE -ne 0) {
            throw "The PE scanner failed"
        }
        Assert-Equal $scanPaths.Count $rows.Count "The scanner did not find every Vim PE"
        foreach ($row in $rows) {
            $fields = $row -split "`t"
            if ($fields.Count -ne 3 -or $fields[1] -ne "arm64" -or $fields[2] -ne "0xAA64") {
                throw "Final Vim payload contains a non-ARM64 PE: $row"
            }
        }
    } finally {
        Remove-Item -LiteralPath $fileList -ErrorAction SilentlyContinue
    }
    $report.observed = [ordered]@{
        replacementPeCount = $replacementPaths.Count
        closurePeCount = $pePaths.Count
        directlyScannedPeCount = $scanPaths.Count
        machine = "0xAA64"
        unexpectedX64 = 0
        provenanceFileCount = $allFiles.Count
    }
} else {
    throw "Unknown Vim admission status '$($data.status)'"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$jsonPath = Join-Path $OutputDirectory "arm64-vim-impact.json"
$markdownPath = Join-Path $OutputDirectory "arm64-vim-impact.md"
$report | ConvertTo-Json -Depth 10 | Set-Content -Encoding ascii -LiteralPath $jsonPath
@"
# Native ARM64 Vim payload impact

- Mode: $($report.mode)
- Admission: $($report.admission)
- Expected architecture delta: -7 x64 / +19 ARM64
- Unexpected x64 delta: 0
- Replacement PEs: 7
- Retained MSYS script: usr/bin/vimtutor
- Installer byte delta: $($data.expected.distributionBytesDelta.installer)
- Portable byte delta: $($data.expected.distributionBytesDelta.portable)
- MinGit byte delta: 0
- BusyBox MinGit byte delta: 0
- Unresolved contracts: $($report.unresolved.Count)
"@ | Set-Content -Encoding ascii -LiteralPath $markdownPath

Write-Host "ARM64 Vim $($report.mode) architecture contract passed"
