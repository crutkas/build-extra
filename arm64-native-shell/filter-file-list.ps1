[CmdletBinding()]
param(
    [ValidateSet("installer", "portable", "mingit", "sdk")]
    [string]$Variant,

    [ValidateSet("Preview", "Final")]
    [string]$Mode = "Final",

    [string]$Lock = (Join-Path $PSScriptRoot "locks\native-shell-closure-v1.json")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "NativeShell.psm1") -Force

$lockObject = Read-NativeShellLock $Lock
$null = Test-NativeShellLock $lockObject $Mode
$ownershipPath = Join-Path $PSScriptRoot ([string]$lockObject.legacyBaseline.ownership)
$item = Get-Item -LiteralPath $ownershipPath
if ($item.Length -ne [int64]$lockObject.legacyBaseline.ownershipBytes -or
    (Get-NativeShellSha256 $ownershipPath) -ne
        [string]$lockObject.legacyBaseline.ownershipSha256) {
    throw "Legacy ownership manifest identity mismatch"
}
$ownership = @(Import-Csv -Delimiter "`t" -LiteralPath $ownershipPath)
if ($ownership.Count -ne [int]$lockObject.legacyBaseline.ownershipRows) {
    throw "Legacy ownership manifest row count mismatch"
}
if ($Mode -eq "Final" -and @($ownership |
    Where-Object finalDisposition -eq "pending-final-package").Count -ne 0) {
    throw "Legacy ownership still contains unresolved final package paths"
}

$remove = @{}
foreach ($entry in $ownership | Where-Object finalDisposition -eq "remove") {
    $remove[[string]$entry.path] = $true
}
$paths = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($line in ([Console]::In.ReadToEnd() -split "\r?\n")) {
    $path = $line.Trim()
    if ($path -and -not $remove.ContainsKey($path)) {
        $null = $paths.Add($path)
    }
}
foreach ($lockInput in $lockObject.inputs | Where-Object status -eq "resolved") {
    foreach ($mapping in @($lockInput.overlay.mappings)) {
        $null = $paths.Add([string]$mapping.destination)
    }
}
$lines = @(Sort-NativeShellOrdinal `
    -InputObject @($paths) -Property { param($path) $path })
if ($lines.Count -ne 0) {
    [Console]::Out.Write(($lines -join "`n") + "`n")
}
