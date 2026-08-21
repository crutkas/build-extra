param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$BusyBox,

    [Parameter(Mandatory = $true)]
    [string]$Shim,

    [Parameter(Mandatory = $true)]
    [string]$DefaultList,

    [Parameter(Mandatory = $true)]
    [string]$ExperimentalList,

    [Parameter(Mandatory = $true)]
    [string]$RetainedList,

    [ValidateSet(0, 1)]
    [int]$Experimental = 0,

    [ValidateSet(0, 1)]
    [int]$ForceCopy = 0
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$busyboxPath = (Resolve-Path -LiteralPath $BusyBox).Path
$shimPath = (Resolve-Path -LiteralPath $Shim).Path
$installedShimPath = Join-Path $rootPath 'clangarm64\bin\busybox-shim.exe'
$installedShimDirectory = Split-Path -Parent $installedShimPath
$shimHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $shimPath).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Force -Path $installedShimDirectory | Out-Null
if ($shimPath -ne $installedShimPath) {
    if ((Test-Path -LiteralPath $installedShimPath) -and
        ((Get-FileHash -Algorithm SHA256 -LiteralPath $installedShimPath).Hash.ToLowerInvariant() -eq $shimHash)) {
        # The installed shim already matches; avoid overwriting a live file.
    } else {
        Copy-Item -LiteralPath $shimPath -Destination $installedShimPath -Force
    }
}
$defaultPaths = @(Get-Content -LiteralPath $DefaultList)
$experimentalPaths = @(Get-Content -LiteralPath $ExperimentalList)
$selected = [Collections.Generic.List[object]]::new()

foreach ($path in $defaultPaths) {
    $selected.Add([pscustomobject]@{ Path = $path; Selection = 'default' })
}
if ($Experimental) {
    foreach ($path in $experimentalPaths) {
        $selected.Add([pscustomobject]@{ Path = $path; Selection = 'experimental' })
    }
}

$report = [Collections.Generic.List[object]]::new()
$aliases = [Collections.Generic.List[string]]::new()
foreach ($replacement in $selected) {
    $destination = Join-Path $rootPath $replacement.Path.Replace('/', '\')
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
    if (-not $ForceCopy) {
        try {
            New-Item -ItemType HardLink -Path $destination -Target $installedShimPath |
                Out-Null
        }
        catch {
            Copy-Item -LiteralPath $installedShimPath -Destination $destination
        }
    } else {
        Copy-Item -LiteralPath $installedShimPath -Destination $destination
    }

    $alias = [IO.Path]::GetFileName($replacement.Path)
    $aliases.Add($alias)
    $report.Add([pscustomobject]@{
        path = $replacement.Path
        applet = [IO.Path]::GetFileNameWithoutExtension($alias)
        selection = $replacement.Selection
    })
}

$etc = Join-Path $rootPath 'etc'
New-Item -ItemType Directory -Force -Path $etc | Out-Null
$report |
    ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
    ForEach-Object { $_ -replace '"', '' } |
    Set-Content -LiteralPath (Join-Path $etc 'arm64-busybox-replacements.tsv') -Encoding ascii
$aliases |
    Set-Content -LiteralPath (Join-Path $etc 'arm64-busybox-aliases.txt') -Encoding ascii

$retained = @(Import-Csv -Delimiter "`t" -LiteralPath $RetainedList)
if ($Experimental) {
    $retained = @($retained | Where-Object path -notin $experimentalPaths)
}
$retained |
    ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
    ForEach-Object { $_ -replace '"', '' } |
    Set-Content -LiteralPath (Join-Path $etc 'arm64-busybox-retained-paths.tsv') -Encoding ascii
