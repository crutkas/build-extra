param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$BusyBox,

    [Parameter(Mandatory = $true)]
    [string]$DefaultList,

    [Parameter(Mandatory = $true)]
    [string]$ExperimentalList,

    [Parameter(Mandatory = $true)]
    [string]$RetainedList,

    [ValidateSet(0, 1)]
    [int]$Experimental = 0
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$busyboxPath = (Resolve-Path -LiteralPath $BusyBox).Path
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
    try {
        New-Item -ItemType HardLink -Path $destination -Target $busyboxPath |
            Out-Null
    }
    catch {
        Copy-Item -LiteralPath $busyboxPath -Destination $destination
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
