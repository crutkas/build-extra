[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
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

$script:Passed = 0

function Invoke-PassTest {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Body
    $script:Passed++
    Write-Host "ok $($script:Passed) - $Name"
}

function Invoke-FailureTest {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$MessagePattern,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $failed = $false
    try {
        & $Body
    } catch {
        $failed = $true
        if ($_.Exception.Message -notmatch $MessagePattern) {
            throw "Test '$Name' failed with unexpected message: " +
                $_.Exception.Message
        }
    }
    if (-not $failed) {
        throw "Test '$Name' did not fail"
    }
    $script:Passed++
    Write-Host "ok $($script:Passed) - $Name"
}

function Set-TarString {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $bytes = $encoding.GetBytes($Value)
    if ($bytes.Length -gt $Length) {
        throw 'Synthetic TAR field is too long'
    }
    [System.Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function Set-TarOctal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][long]$Value
    )

    $text = [Convert]::ToString($Value, 8).PadLeft($Length - 1, '0') +
        [char]0
    Set-TarString $Header $Offset $Length $text
}

function New-TarHeader {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][char]$Type,
        [byte[]]$Data = (New-Object byte[] 0),
        [string]$Target = ''
    )

    $header = New-Object byte[] 512
    Set-TarString $header 0 100 $Path
    Set-TarOctal $header 100 8 420
    Set-TarOctal $header 108 8 0
    Set-TarOctal $header 116 8 0
    Set-TarOctal $header 124 12 $Data.Length
    Set-TarOctal $header 136 12 0
    for ($index = 148; $index -lt 156; $index++) {
        $header[$index] = 0x20
    }
    $header[156] = [byte][char]$Type
    Set-TarString $header 157 100 $Target
    Set-TarString $header 257 6 'ustar'
    Set-TarString $header 263 2 '00'
    [long]$checksum = 0
    foreach ($value in $header) {
        $checksum += $value
    }
    $checksumText = [Convert]::ToString($checksum, 8).PadLeft(6, '0') +
        [char]0 + ' '
    Set-TarString $header 148 8 $checksumText
    return ,$header
}

function New-TarBytes {
    param([Parameter(Mandatory = $true)][object[]]$Members)

    $stream = New-Object System.IO.MemoryStream
    try {
        foreach ($member in $Members) {
            [byte[]]$data = New-Object byte[] 0
            if ($member.Contains('data')) {
                $data = [byte[]]$member.data
            }
            $target = if ($member.Contains('target')) {
                [string]$member.target
            } else {
                ''
            }
            $header = New-TarHeader `
                -Path $member.path `
                -Type ([char]$member.type) `
                -Data $data `
                -Target $target
            $stream.Write($header, 0, $header.Length)
            if ($data.Length -gt 0) {
                $stream.Write($data, 0, $data.Length)
                $padding = (512 - ($data.Length % 512)) % 512
                if ($padding -gt 0) {
                    $zeros = New-Object byte[] $padding
                    $stream.Write($zeros, 0, $zeros.Length)
                }
            }
        }
        $end = New-Object byte[] 1024
        $stream.Write($end, 0, $end.Length)
        return ,$stream.ToArray()
    } finally {
        $stream.Dispose()
    }
}

function Read-SyntheticTar {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [System.Collections.IDictionary]$AllowedLinks = $(New-OrdinalDictionary)
    )

    $stream = New-Object System.IO.MemoryStream(
        $Bytes, $false)
    try {
        return Read-TarPayload `
            -Stream $stream `
            -AllowedAbsoluteSymlinks $AllowedLinks
    } finally {
        $stream.Dispose()
    }
}

function New-PacmanTarResult {
    param(
        [string]$DescOverride,
        [string]$FilesOverride,
        [switch]$OmitFiles
    )

    $desc = if ($PSBoundParameters.ContainsKey('DescOverride')) {
        $DescOverride
    } else {
        @'
%NAME%
pkg

%VERSION%
1-1

%BASE%
pkg

%DESC%
test

%URL%
https://example.invalid/

%ARCH%
any

%BUILDDATE%
1

%INSTALLDATE%
1

%PACKAGER%
test

%LICENSE%
MIT

%SIZE%
1

%VALIDATION%
none

'@
    }
    $files = if ($PSBoundParameters.ContainsKey('FilesOverride')) {
        $FilesOverride
    } else {
        @'
%FILES%
usr/
usr/bin/
usr/bin/a.exe

'@
    }
    $desc = $desc.Replace("`r`n", "`n")
    $files = $files.Replace("`r`n", "`n")
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $fileBytes = [ordered]@{
        'ALPM_DB_VERSION' = $encoding.GetBytes("9`n")
        'pkg-1-1/desc' = $encoding.GetBytes($desc)
        'pkg-1-1/mtree' = $encoding.GetBytes("mtree`n")
    }
    $entries = [ordered]@{
        'ALPM_DB_VERSION' = [ordered]@{ kind = 'file' }
        'pkg-1-1' = [ordered]@{ kind = 'directory' }
        'pkg-1-1/desc' = [ordered]@{ kind = 'file' }
        'pkg-1-1/mtree' = [ordered]@{ kind = 'file' }
    }
    if (-not $OmitFiles) {
        $fileBytes['pkg-1-1/files'] = $encoding.GetBytes($files)
        $entries['pkg-1-1/files'] = [ordered]@{ kind = 'file' }
    }
    return [ordered]@{
        entries = $entries
        fileBytes = $fileBytes
        peByPath = New-OrdinalDictionary
        typeCounts = [ordered]@{
            directory = [long]1
            file = [long]$fileBytes.Count
            hardlink = [long]0
            symlink = [long]0
        }
    }
}

Invoke-PassTest 'valid TAR stream' {
    $result = Read-SyntheticTar (New-TarBytes @(
        [ordered]@{
            path = 'usr/bin/a'
            type = '0'
            data = [Text.Encoding]::ASCII.GetBytes('a')
        }))
    if ($result.memberCount -ne 1 -or $result.typeCounts.file -ne 1) {
        throw 'Valid TAR accounting differs'
    }
}

Invoke-FailureTest 'duplicate normalized TAR destination' 'Duplicate TAR destination' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = './usr/bin/a'; type = '0' },
        [ordered]@{ path = 'usr/bin/a'; type = '0' })))
}

Invoke-FailureTest 'TAR traversal' 'unsafe segment' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = '../escape'; type = '0' })))
}

Invoke-FailureTest 'TAR alternate data stream' 'Windows alias' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = 'usr/a:stream'; type = '0' })))
}

Invoke-FailureTest 'TAR device path' 'device name' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = 'usr/CON.txt'; type = '0' })))
}

Invoke-FailureTest 'TAR device member type' 'Unsupported TAR member type' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = 'usr/device'; type = '3' })))
}

Invoke-FailureTest 'TAR case collision' 'Case or Unicode TAR collision' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = 'usr/A'; type = '0' },
        [ordered]@{ path = 'usr/a'; type = '0' })))
}

Invoke-FailureTest 'TAR non-NFC path' 'not Unicode NFC' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{ path = "usr/e$([char]0x0301)"; type = '0' })))
}

Invoke-FailureTest 'TAR malformed checksum' 'checksum mismatch' {
    $bytes = New-TarBytes @(
        [ordered]@{ path = 'usr/a'; type = '0' })
    $bytes[0] = $bytes[0] -bxor 1
    [void](Read-SyntheticTar $bytes)
}

Invoke-FailureTest 'unreviewed absolute symlink' 'not installed-link policy' {
    [void](Read-SyntheticTar (New-TarBytes @(
        [ordered]@{
            path = 'dev/fd'
            type = '2'
            target = '/proc/self/fd'
        })))
}

Invoke-PassTest 'reviewed absolute symlink remains metadata' {
    $links = [ordered]@{ 'dev/fd' = '/proc/self/fd' }
    $result = Read-SyntheticTar `
        (New-TarBytes @(
            [ordered]@{
                path = 'dev/fd'
                type = '2'
                target = '/proc/self/fd'
            })) `
        $links
    if ($result.links.Count -ne 1 -or
        $result.links[0].policy -ne 'runtime-virtual-absolute' -or
        $result.links[0].resolvedTarget -ne '') {
        throw 'Installed-link metadata was resolved or changed'
    }
}

Invoke-PassTest 'payload hardlink resolves without materialization' {
    $result = Read-SyntheticTar (New-TarBytes @(
        [ordered]@{
            path = 'usr/a'
            type = '0'
            data = [Text.Encoding]::ASCII.GetBytes('a')
        },
        [ordered]@{
            path = 'usr/b'
            type = '1'
            target = 'usr/a'
        }))
    if ($result.typeCounts.hardlink -ne 1 -or
        $result.links[0].resolvedTarget -ne 'usr/a') {
        throw 'Hardlink accounting differs'
    }
}

Invoke-FailureTest 'duplicate JSON property' 'Duplicate JSON property' {
    $bytes = [Text.Encoding]::UTF8.GetBytes('{"a":1,"a":2}')
    [void](ConvertFrom-StrictJsonBytes -Bytes $bytes)
}

Invoke-FailureTest 'TSV field injection' 'control character' {
    [void](ConvertTo-CanonicalTsvBytes `
        -Header @('a') `
        -Rows @(,@("value`tother")))
}

Invoke-FailureTest 'duplicate TSV key' 'duplicate key' {
    $bytes = [Text.Encoding]::UTF8.GetBytes("path`nvalue`nvalue`n")
    [void](ConvertFrom-StrictTsvBytes `
        -Bytes $bytes `
        -Header @('path') `
        -KeyColumn 0)
}

Invoke-PassTest 'strict Pacman database record' {
    $database = ConvertFrom-PacmanTarResult `
        -TarResult (New-PacmanTarResult) `
        -ExpectedPackageCount 1 `
        -ExpectedRecordBlobCount 2
    if ($database.packages.pkg.paths.Count -ne 1 -or
        $database.packages.pkg.paths[0] -ne 'usr/bin/a.exe') {
        throw 'Strict Pacman record differs'
    }
}

$missingName = @'
%VERSION%
1-1

%BASE%
pkg

%DESC%
test

%URL%
https://example.invalid/

%ARCH%
any

%BUILDDATE%
1

%INSTALLDATE%
1

%PACKAGER%
test

%LICENSE%
MIT

%SIZE%
1

%VALIDATION%
none

'@
Invoke-FailureTest 'Pacman missing NAME' 'lacks section NAME' {
    [void](ConvertFrom-PacmanTarResult `
        -TarResult (New-PacmanTarResult -DescOverride $missingName) `
        -ExpectedPackageCount 1 `
        -ExpectedRecordBlobCount 2)
}

$duplicateName = (New-PacmanTarResult).fileBytes['pkg-1-1/desc']
$duplicateNameText = [Text.Encoding]::UTF8.GetString($duplicateName).
    Replace("%NAME%`npkg`n", "%NAME%`npkg`n`n%NAME%`npkg`n")
Invoke-FailureTest 'Pacman duplicate section' 'duplicate section: NAME' {
    [void](ConvertFrom-PacmanTarResult `
        -TarResult (New-PacmanTarResult `
            -DescOverride $duplicateNameText) `
        -ExpectedPackageCount 1 `
        -ExpectedRecordBlobCount 2)
}

Invoke-FailureTest 'Pacman missing files record' 'lacks files' {
    [void](ConvertFrom-PacmanTarResult `
        -TarResult (New-PacmanTarResult -OmitFiles) `
        -ExpectedPackageCount 1 `
        -ExpectedRecordBlobCount 2)
}

$duplicateFiles = @'
%FILES%
usr/bin/a.exe
usr/bin/a.exe

'@
Invoke-FailureTest 'Pacman duplicate file path' 'repeats path' {
    [void](ConvertFrom-PacmanTarResult `
        -TarResult (New-PacmanTarResult -FilesOverride $duplicateFiles) `
        -ExpectedPackageCount 1 `
        -ExpectedRecordBlobCount 2)
}

$modelPath = Join-Path $PSScriptRoot 'ledger-model-v2.55.0.4.json'
$model = ConvertFrom-StrictJsonFile -Path $modelPath
$duplicateModel = ConvertFrom-StrictJsonBytes `
    -Bytes (ConvertTo-CanonicalJsonBytes -Value $model)
$duplicateModel.rules[0].paths =
    @($duplicateModel.rules[0].paths) + $duplicateModel.rules[0].paths[0]
Invoke-FailureTest 'duplicate source-rule row' 'duplicate value' {
    Assert-LedgerModel -Model $duplicateModel
}

$ownershipBytes = Read-StableBytes `
    -Path (Join-Path $PSScriptRoot 'artifacts\v2.55.0.4\x64-ownership.tsv')
$ownershipRows = ConvertFrom-StrictTsvBytes `
    -Bytes $ownershipBytes `
    -Header @('path', 'owner', 'version') `
    -KeyColumn 0
$ownership = New-OrdinalDictionary
foreach ($row in $ownershipRows) {
    $ownership[$row[0]] = [ordered]@{
        owner = $row[1]
        version = $row[2]
    }
}
$unknownOwnership = New-OrdinalDictionary
foreach ($path in $ownership.Keys) {
    $unknownOwnership[$path] = [ordered]@{
        owner = $ownership[$path].owner
        version = $ownership[$path].version
    }
}
$unknownOwnership['usr/bin/bash.exe'].version = 'unknown-1'
Invoke-FailureTest 'unknown owner version' 'expected 46|owner selector was unconsumed' {
    [void](Compile-LedgerRules `
        -Model $model `
        -Ownership $unknownOwnership)
}

$testRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ('arm64-ledger-tests-' + [Guid]::NewGuid().ToString('N'))
$testIdentity = New-SafePrivateDirectory `
    -Path $testRoot `
    -ForbiddenRoots @((Join-Path $PSScriptRoot '..'), 'C:\msys64')
try {
    $target = Join-Path $testRoot 'target'
    $junction = Join-Path $testRoot 'junction'
    [void][System.IO.Directory]::CreateDirectory($target)
    [void](New-Item `
        -ItemType Junction `
        -Path $junction `
        -Target $target)
    Invoke-FailureTest 'reparse path rejection' 'Reparse points are forbidden' {
        [void](Assert-SafeExistingPath -Path $junction -Kind Directory)
    }
    Invoke-FailureTest 'reparse tree rejection' 'Tree contains a reparse point' {
        Assert-SafeTree -Root $testRoot
    }
    [System.IO.Directory]::Delete($junction)

    $allowed = Join-Path $testRoot 'allowed'
    $outside = Join-Path $testRoot 'outside'
    [void][System.IO.Directory]::CreateDirectory($allowed)
    [void][System.IO.Directory]::CreateDirectory($outside)
    $outsideFile = Join-Path $outside 'file'
    [System.IO.File]::WriteAllText($outsideFile, 'x')
    Invoke-FailureTest 'uncontained path rejection' 'outside its permitted root' {
        [void](Assert-SafeExistingPath `
            -Path $outsideFile `
            -Kind File `
            -AllowedRoot $allowed)
    }

    $race = Join-Path $testRoot 'race'
    $displaced = Join-Path $testRoot 'race-displaced'
    [void][System.IO.Directory]::CreateDirectory($race)
    $raceIdentity = Assert-SafeExistingPath -Path $race -Kind Directory
    [System.IO.Directory]::Move($race, $displaced)
    [void][System.IO.Directory]::CreateDirectory($race)
    Invoke-FailureTest 'restored-path identity race' 'identity changed' {
        Assert-IdentityUnchanged -Before $raceIdentity -Path $race
    }
} finally {
    Remove-SafePrivateDirectory `
        -Path $testRoot `
        -ExpectedIdentity $testIdentity
}

Write-Host "1..$script:Passed"
