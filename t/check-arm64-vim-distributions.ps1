param(
    [Parameter(Mandatory = $true)]
    [string]$Lock,
    [Parameter(Mandatory = $true)]
    [string]$BaseInstaller,
    [Parameter(Mandatory = $true)]
    [string]$IntegratedInstaller,
    [Parameter(Mandatory = $true)]
    [string]$BasePortable,
    [Parameter(Mandatory = $true)]
    [string]$IntegratedPortable,
    [Parameter(Mandatory = $true)]
    [string]$BaseMinGit,
    [Parameter(Mandatory = $true)]
    [string]$IntegratedMinGit,
    [Parameter(Mandatory = $true)]
    [string]$BaseBusyBoxMinGit,
    [Parameter(Mandatory = $true)]
    [string]$IntegratedBusyBoxMinGit,
    [string]$SevenZip,
    [Nullable[int64]]$BasePayloadBytes,
    [Nullable[int64]]$IntegratedPayloadBytes,
    [Parameter(Mandatory = $true)]
    [string]$Output
)

$ErrorActionPreference = "Stop"
$lockData = Get-Content -Raw -LiteralPath $Lock | ConvertFrom-Json

function Get-Delta([string]$Before, [string]$After) {
    return [int64]((Get-Item -LiteralPath $After).Length -
        (Get-Item -LiteralPath $Before).Length)
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Get-ArchivePayloadBytes([string]$Archive) {
    $output = @(& $SevenZip l -slt -- $Archive 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect Portable Git payload: $($output -join ' | ')"
    }
    [int64]$total = 0
    foreach ($line in $output) {
        if ($line -match "^Size = ([0-9]+)$") {
            $total += [int64]$Matches[1]
        }
    }
    return $total
}

function Assert-Between([int64]$Minimum, [int64]$Maximum, [int64]$Actual,
    [string]$Message) {
    if ($Actual -lt $Minimum -or $Actual -gt $Maximum) {
        throw "$Message (expected $Minimum..$Maximum, got '$Actual')"
    }
}

if ($SevenZip) {
    if ($null -ne $BasePayloadBytes -or $null -ne $IntegratedPayloadBytes) {
        throw "Specify SevenZip or explicit payload byte counts, not both"
    }
    $BasePayloadBytes = Get-ArchivePayloadBytes $BasePortable
    $IntegratedPayloadBytes = Get-ArchivePayloadBytes $IntegratedPortable
} elseif ($null -eq $BasePayloadBytes -or $null -eq $IntegratedPayloadBytes) {
    throw "SevenZip or explicit payload byte counts are required"
}

$observed = [ordered]@{
    portablePayload = [int64]$IntegratedPayloadBytes - [int64]$BasePayloadBytes
    installer = Get-Delta $BaseInstaller $IntegratedInstaller
    portable = Get-Delta $BasePortable $IntegratedPortable
    mingit = Get-Delta $BaseMinGit $IntegratedMinGit
    busyboxMingit = Get-Delta $BaseBusyBoxMinGit $IntegratedBusyBoxMinGit
}
if ($lockData.status -eq "admitted") {
    if ($null -eq $lockData.expected.distributionBytesDelta.portablePayload) {
        throw "Admitted Vim input is missing the measured payload byte delta"
    }
    Assert-Equal ([int64]$lockData.expected.distributionBytesDelta.portablePayload) `
        $observed.portablePayload "Unexpected Portable Git payload byte delta"
    Assert-Between ([int64]$lockData.expected.distributionBytesDelta.installerMinimum) `
        ([int64]$lockData.expected.distributionBytesDelta.installerMaximum) `
        $observed.installer "Unexpected compressed installer byte delta"
    Assert-Between ([int64]$lockData.expected.distributionBytesDelta.portableMinimum) `
        ([int64]$lockData.expected.distributionBytesDelta.portableMaximum) `
        $observed.portable "Unexpected compressed Portable Git byte delta"
} elseif ($lockData.status -eq "unresolved") {
    Assert-Equal 0 $observed.portablePayload "Unresolved Vim changed the payload size"
    Assert-Equal 0 $observed.installer "Unresolved Vim changed the installer size"
    Assert-Equal 0 $observed.portable "Unresolved Vim changed the Portable Git size"
} elseif ($lockData.status -ne "measuring") {
    throw "Unknown Vim admission status '$($lockData.status)'"
}
Assert-Equal 0 $observed.mingit "Vim changed MinGit"
Assert-Equal 0 $observed.busyboxMingit "Vim changed BusyBox MinGit"
Assert-Equal 0 ([int64]$lockData.expected.distributionBytesDelta.mingit) `
    "The lock permits a MinGit byte delta"
Assert-Equal 0 ([int64]$lockData.expected.distributionBytesDelta.busyboxMingit) `
    "The lock permits a BusyBox MinGit byte delta"

$report = [ordered]@{
    schemaVersion = 1
    mode = if ($lockData.status -eq "admitted") {
        "final"
    } elseif ($lockData.status -eq "measuring") {
        "measurement"
    } else {
        "preview"
    }
    admission = $lockData.status
    observedProductBytesDelta = $observed
}
$report | ConvertTo-Json -Depth 5 | Set-Content -Encoding ascii -LiteralPath $Output
Write-Host "ARM64 Vim distribution impact contract passed"
