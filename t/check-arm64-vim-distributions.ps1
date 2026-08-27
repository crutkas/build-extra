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

$observed = [ordered]@{
    installer = Get-Delta $BaseInstaller $IntegratedInstaller
    portable = Get-Delta $BasePortable $IntegratedPortable
    mingit = Get-Delta $BaseMinGit $IntegratedMinGit
    busyboxMingit = Get-Delta $BaseBusyBoxMinGit $IntegratedBusyBoxMinGit
}
if ($lockData.status -eq "admitted") {
    if ($null -eq $lockData.expected.distributionBytesDelta.installer -or
        $null -eq $lockData.expected.distributionBytesDelta.portable) {
        throw "Admitted Vim input is missing measured full-distribution byte deltas"
    }
    Assert-Equal ([int64]$lockData.expected.distributionBytesDelta.installer) `
        $observed.installer "Unexpected installer byte delta"
    Assert-Equal ([int64]$lockData.expected.distributionBytesDelta.portable) `
        $observed.portable "Unexpected Portable Git byte delta"
} elseif ($lockData.status -eq "unresolved") {
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
