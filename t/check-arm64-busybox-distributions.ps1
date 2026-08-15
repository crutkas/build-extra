param(
    [Parameter(Mandatory = $true)]
    [string]$ReleasedInstaller,

    [Parameter(Mandatory = $true)]
    [string]$BaseInstaller,

    [Parameter(Mandatory = $true)]
    [string]$IntegratedInstaller,

    [Parameter(Mandatory = $true)]
    [string]$ReleasedPortable,

    [Parameter(Mandatory = $true)]
    [string]$BasePortable,

    [Parameter(Mandatory = $true)]
    [string]$IntegratedPortable,

    [Parameter(Mandatory = $true)]
    [string]$ReleasedMinGit,

    [Parameter(Mandatory = $true)]
    [string]$BaseMinGit,

    [Parameter(Mandatory = $true)]
    [string]$IntegratedMinGit,

    [Parameter(Mandatory = $true)]
    [string]$ReleasedBusyBoxMinGit,

    [Parameter(Mandatory = $true)]
    [string]$BaseBusyBoxMinGit,

    [Parameter(Mandatory = $true)]
    [string]$IntegratedBusyBoxMinGit,

    [Parameter(Mandatory = $true)]
    [string]$OpenSshPackage,

    [Parameter(Mandatory = $true)]
    [string]$Scanner,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$defaultPaths = @(Get-Content -LiteralPath (Join-Path $repoRoot 'arm64-busybox\default-replacements.txt'))
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class FileStorageInfo
{
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_STANDARD_INFO
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)]
        public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)]
        public bool Directory;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle,
        int informationClass,
        out FILE_STANDARD_INFO info,
        uint bufferSize);
}
'@

function Get-FileStorage {
    param([Parameter(Mandatory = $true)][string]$Path)

    $handle = [FileStorageInfo]::CreateFileW(
        $Path,
        0,
        [FileStorageInfo]::FILE_SHARE_READ -bor
            [FileStorageInfo]::FILE_SHARE_WRITE -bor
            [FileStorageInfo]::FILE_SHARE_DELETE,
        [IntPtr]::Zero,
        [FileStorageInfo]::OPEN_EXISTING,
        [FileStorageInfo]::FILE_FLAG_OPEN_REPARSE_POINT -bor
            [FileStorageInfo]::FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        throw "Could not open $Path for storage measurement"
    }
    try {
        $handleInfo = [FileStorageInfo+BY_HANDLE_FILE_INFORMATION]::new()
        if (-not [FileStorageInfo]::GetFileInformationByHandle(
            $handle,
            [ref]$handleInfo
        )) {
            throw "Could not get the file ID for $Path"
        }
        $standardInfo = [FileStorageInfo+FILE_STANDARD_INFO]::new()
        if (-not [FileStorageInfo]::GetFileInformationByHandleEx(
            $handle,
            1,
            [ref]$standardInfo,
            [Runtime.InteropServices.Marshal]::SizeOf($standardInfo)
        )) {
            throw "Could not get the allocation size for $Path"
        }
        [pscustomobject]@{
            Id = '{0:X8}-{1:X8}-{2:X8}' -f
                $handleInfo.VolumeSerialNumber,
                $handleInfo.FileIndexHigh,
                $handleInfo.FileIndexLow
            Links = [int64]$handleInfo.NumberOfLinks
            LogicalBytes = [int64]$standardInfo.EndOfFile
            AllocatedBytes = [int64]$standardInfo.AllocationSize
        }
    }
    finally {
        $handle.Dispose()
    }
}

function Measure-Tree {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Product
    )

    $rootPath = (Resolve-Path -LiteralPath $Root).Path
    $productPath = (Resolve-Path -LiteralPath $Product).Path
    $files = @(Get-ChildItem -LiteralPath $rootPath -Recurse -Force -File)
    $unique = @{}
    [int64]$logicalBytes = 0
    foreach ($file in $files) {
        $storage = Get-FileStorage -Path $file.FullName
        $logicalBytes += $storage.LogicalBytes
        if (-not $unique.ContainsKey($storage.Id)) {
            $unique[$storage.Id] = $storage.AllocatedBytes
        }
    }
    [int64]$allocatedBytes = 0
    foreach ($value in $unique.Values) {
        $allocatedBytes += $value
    }

    $aliases = [Collections.Generic.List[object]]::new()
    foreach ($relativePath in $defaultPaths) {
        $path = Join-Path $rootPath $relativePath.Replace('/', '\')
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $aliases.Add((Get-FileStorage -Path $path))
        }
    }
    $busybox = Join-Path $rootPath 'clangarm64\bin\busybox.exe'
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($alias in $aliases) {
        $targets.Add($alias)
    }
    if (Test-Path -LiteralPath $busybox -PathType Leaf) {
        $targets.Add((Get-FileStorage -Path $busybox))
    }

    $aliasIds = @($aliases | ForEach-Object Id | Sort-Object -Unique)
    $targetIds = @($targets | ForEach-Object Id | Sort-Object -Unique)
    $targetAllocations = @{}
    [int64]$targetLogicalBytes = 0
    foreach ($target in $targets) {
        $targetLogicalBytes += $target.LogicalBytes
        if (-not $targetAllocations.ContainsKey($target.Id)) {
            $targetAllocations[$target.Id] = $target.AllocatedBytes
        }
    }
    [int64]$targetAllocatedBytes = 0
    foreach ($value in $targetAllocations.Values) {
        $targetAllocatedBytes += $value
    }

    [pscustomobject]@{
        Label = $Label
        ProductBytes = [int64](Get-Item -LiteralPath $productPath).Length
        TreeFiles = $files.Count
        TreeLogicalBytes = $logicalBytes
        TreeAllocatedBytes = $allocatedBytes
        TreeUniqueFileIds = $unique.Count
        AliasCount = $aliases.Count
        AliasUniqueFileIds = $aliasIds.Count
        AliasLinkCount = if ($aliases.Count) { ($aliases | Measure-Object Links -Maximum).Maximum } else { 0 }
        AliasAndBusyBoxCount = $targets.Count
        AliasAndBusyBoxUniqueFileIds = $targetIds.Count
        AliasAndBusyBoxLogicalBytes = $targetLogicalBytes
        AliasAndBusyBoxAllocatedBytes = $targetAllocatedBytes
    }
}

function Invoke-Product {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Arguments
    )

    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$File exited with code $($process.ExitCode)"
    }
}

function Assert-Git {
    param([Parameter(Mandatory = $true)][string]$Root)

    & (Join-Path $Root 'cmd\git.exe') version --build-options | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Git failed in $Root"
    }
}

function Assert-Integrated {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [switch]$AllowMissingReplacements,
        [switch]$MinGit
    )

    $busyBoxArguments = @{
        Root = $Root
        AllowMissingReplacements = $AllowMissingReplacements
    }
    & (Join-Path $PSScriptRoot 'check-arm64-busybox.ps1') @busyBoxArguments

    $openSshArguments = @{
        Package = $OpenSshPackage
        Scanner = $Scanner
        RuntimeRoot = $Root
    }
    if ($MinGit) {
        & (Join-Path $PSScriptRoot 'check-arm64-openssh-package.ps1') `
            @openSshArguments -MinGit
    } else {
        & (Join-Path $PSScriptRoot 'check-arm64-openssh-package.ps1') `
            @openSshArguments
    }
}

function Expand-Portable {
    param(
        [Parameter(Mandatory = $true)][string]$Product,
        [Parameter(Mandatory = $true)][string]$Destination,
        [switch]$ForceCopy
    )

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    $previous = $env:GFW_ARM64_BUSYBOX_FORCE_COPY
    try {
        if ($ForceCopy) {
            $env:GFW_ARM64_BUSYBOX_FORCE_COPY = '1'
        } else {
            Remove-Item Env:\GFW_ARM64_BUSYBOX_FORCE_COPY -ErrorAction SilentlyContinue
        }
        Invoke-Product -File $Product -Arguments "-o`"$Destination`" -y"
    }
    finally {
        if ($null -eq $previous) {
            Remove-Item Env:\GFW_ARM64_BUSYBOX_FORCE_COPY -ErrorAction SilentlyContinue
        } else {
            $env:GFW_ARM64_BUSYBOX_FORCE_COPY = $previous
        }
    }
}

$products = @{
    ReleasedInstaller = (Resolve-Path -LiteralPath $ReleasedInstaller).Path
    BaseInstaller = (Resolve-Path -LiteralPath $BaseInstaller).Path
    IntegratedInstaller = (Resolve-Path -LiteralPath $IntegratedInstaller).Path
    ReleasedPortable = (Resolve-Path -LiteralPath $ReleasedPortable).Path
    BasePortable = (Resolve-Path -LiteralPath $BasePortable).Path
    IntegratedPortable = (Resolve-Path -LiteralPath $IntegratedPortable).Path
    ReleasedMinGit = (Resolve-Path -LiteralPath $ReleasedMinGit).Path
    BaseMinGit = (Resolve-Path -LiteralPath $BaseMinGit).Path
    IntegratedMinGit = (Resolve-Path -LiteralPath $IntegratedMinGit).Path
    ReleasedBusyBoxMinGit = (Resolve-Path -LiteralPath $ReleasedBusyBoxMinGit).Path
    BaseBusyBoxMinGit = (Resolve-Path -LiteralPath $BaseBusyBoxMinGit).Path
    IntegratedBusyBoxMinGit = (Resolve-Path -LiteralPath $IntegratedBusyBoxMinGit).Path
}
$OpenSshPackage = (Resolve-Path -LiteralPath $OpenSshPackage).Path
$Scanner = (Resolve-Path -LiteralPath $Scanner).Path
$measurements = [Collections.Generic.List[object]]::new()
$lifecycle = [ordered]@{}
$installedRoot = Join-Path $outputPath 'installed-git'
$silentInstall = "/SILENT /VERYSILENT /NORESTART /SUPPRESSMSGBOXES /ALLOWDOWNGRADE=1 /TYPE=default /DIR=`"$installedRoot`" /LOG=installer-impact.log"

Invoke-Product -File $products.ReleasedInstaller -Arguments $silentInstall
Assert-Git -Root $installedRoot
$measurements.Add((Measure-Tree -Label 'installed-full-release' -Root $installedRoot -Product $products.ReleasedInstaller))
$uninstaller = Get-ChildItem -LiteralPath $installedRoot -Filter 'unins*.exe' |
    Select-Object -First 1
Invoke-Product -File $uninstaller.FullName -Arguments '/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES'
if (Test-Path -LiteralPath $installedRoot) {
    Remove-Item -LiteralPath $installedRoot -Recurse -Force
}

Invoke-Product -File $products.BaseInstaller -Arguments $silentInstall
Assert-Git -Root $installedRoot
$measurements.Add((Measure-Tree -Label 'installed-full-base' -Root $installedRoot -Product $products.BaseInstaller))

Invoke-Product -File $products.IntegratedInstaller -Arguments $silentInstall
Assert-Git -Root $installedRoot
Assert-Integrated -Root $installedRoot
$measurements.Add((Measure-Tree -Label 'installed-full-update-hardlinks' -Root $installedRoot -Product $products.IntegratedInstaller))

$repairTarget = Join-Path $installedRoot 'usr\bin\cat.exe'
Remove-Item -LiteralPath $repairTarget -Force
Invoke-Product -File $products.IntegratedInstaller -Arguments $silentInstall
Assert-Integrated -Root $installedRoot
$lifecycle.InstallerRepairRestoredAlias = Test-Path -LiteralPath $repairTarget
$measurements.Add((Measure-Tree -Label 'installed-full-repair-hardlinks' -Root $installedRoot -Product $products.IntegratedInstaller))

$uninstaller = Get-ChildItem -LiteralPath $installedRoot -Filter 'unins*.exe' |
    Select-Object -First 1
Invoke-Product -File $uninstaller.FullName -Arguments '/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES'
$lifecycle.InstallerUninstallRemovedAliases =
    -not (Test-Path -LiteralPath $repairTarget)
if (Test-Path -LiteralPath $installedRoot) {
    Remove-Item -LiteralPath $installedRoot -Recurse -Force
}

Invoke-Product -File $products.IntegratedInstaller -Arguments $silentInstall
Assert-Integrated -Root $installedRoot
$measurements.Add((Measure-Tree -Label 'installed-full-clean-hardlinks' -Root $installedRoot -Product $products.IntegratedInstaller))
$uninstaller = Get-ChildItem -LiteralPath $installedRoot -Filter 'unins*.exe' |
    Select-Object -First 1
Invoke-Product -File $uninstaller.FullName -Arguments '/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES'
if (Test-Path -LiteralPath $installedRoot) {
    Remove-Item -LiteralPath $installedRoot -Recurse -Force
}

$previousForceCopy = $env:GFW_ARM64_BUSYBOX_FORCE_COPY
try {
    $env:GFW_ARM64_BUSYBOX_FORCE_COPY = '1'
    Invoke-Product -File $products.IntegratedInstaller -Arguments $silentInstall
}
finally {
    if ($null -eq $previousForceCopy) {
        Remove-Item Env:\GFW_ARM64_BUSYBOX_FORCE_COPY -ErrorAction SilentlyContinue
    } else {
        $env:GFW_ARM64_BUSYBOX_FORCE_COPY = $previousForceCopy
    }
}
Assert-Integrated -Root $installedRoot
$measurements.Add((Measure-Tree -Label 'installed-full-compact-copy-fallback' -Root $installedRoot -Product $products.IntegratedInstaller))
$uninstaller = Get-ChildItem -LiteralPath $installedRoot -Filter 'unins*.exe' |
    Select-Object -First 1
Invoke-Product -File $uninstaller.FullName -Arguments '/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES'
if (Test-Path -LiteralPath $installedRoot) {
    Remove-Item -LiteralPath $installedRoot -Recurse -Force
}

$releasedPortableRoot = Join-Path $outputPath 'portable-release'
$basePortableRoot = Join-Path $outputPath 'portable-base'
$integratedPortableRoot = Join-Path $outputPath 'portable-integrated'
$fallbackPortableRoot = Join-Path $outputPath 'portable-copy-fallback'
Expand-Portable -Product $products.ReleasedPortable -Destination $releasedPortableRoot
Assert-Git -Root $releasedPortableRoot
$measurements.Add((Measure-Tree -Label 'extracted-portable-release' -Root $releasedPortableRoot -Product $products.ReleasedPortable))
Expand-Portable -Product $products.BasePortable -Destination $basePortableRoot
Assert-Git -Root $basePortableRoot
$measurements.Add((Measure-Tree -Label 'extracted-portable-base' -Root $basePortableRoot -Product $products.BasePortable))
Expand-Portable -Product $products.IntegratedPortable -Destination $integratedPortableRoot
Assert-Git -Root $integratedPortableRoot
Assert-Integrated -Root $integratedPortableRoot
$measurements.Add((Measure-Tree -Label 'extracted-portable-hardlinks' -Root $integratedPortableRoot -Product $products.IntegratedPortable))
Expand-Portable -Product $products.IntegratedPortable -Destination $fallbackPortableRoot -ForceCopy
Assert-Git -Root $fallbackPortableRoot
Assert-Integrated -Root $fallbackPortableRoot
$measurements.Add((Measure-Tree -Label 'extracted-portable-compact-copy-fallback' -Root $fallbackPortableRoot -Product $products.IntegratedPortable))
$lifecycle.PortableExtractionPreservedAliases =
    (Test-Path -LiteralPath (Join-Path $integratedPortableRoot 'usr\bin\cat.exe'))

foreach ($item in @(
    @{ Label = 'standard-mingit-release'; Product = $products.ReleasedMinGit; Directory = 'mingit-release'; Integrated = $false },
    @{ Label = 'standard-mingit-base'; Product = $products.BaseMinGit; Directory = 'mingit-base'; Integrated = $false },
    @{ Label = 'standard-mingit-integrated'; Product = $products.IntegratedMinGit; Directory = 'mingit-integrated'; Integrated = $true },
    @{ Label = 'busybox-mingit-release'; Product = $products.ReleasedBusyBoxMinGit; Directory = 'busybox-mingit-release'; Integrated = $false },
    @{ Label = 'busybox-mingit-base'; Product = $products.BaseBusyBoxMinGit; Directory = 'busybox-mingit-base'; Integrated = $false },
    @{ Label = 'busybox-mingit-integrated'; Product = $products.IntegratedBusyBoxMinGit; Directory = 'busybox-mingit-integrated'; Integrated = $true }
)) {
    $root = Join-Path $outputPath $item.Directory
    Expand-Archive -LiteralPath $item.Product -DestinationPath $root
    Assert-Git -Root $root
    if ($item.Integrated) {
        Assert-Integrated -Root $root -AllowMissingReplacements -MinGit
    }
    $measurements.Add((Measure-Tree -Label $item.Label -Root $root -Product $item.Product))
}

foreach ($required in 'InstallerRepairRestoredAlias',
    'InstallerUninstallRemovedAliases',
    'PortableExtractionPreservedAliases') {
    if (-not $lifecycle[$required]) {
        throw "Lifecycle check failed: $required"
    }
}

$hardlinkLabels = 'installed-full-update-hardlinks',
    'installed-full-repair-hardlinks',
    'installed-full-clean-hardlinks',
    'extracted-portable-hardlinks'
foreach ($label in $hardlinkLabels) {
    $measurement = $measurements | Where-Object Label -eq $label
    if ($measurement.AliasCount -ne 59 -or
        $measurement.AliasUniqueFileIds -ne 1 -or
        $measurement.AliasLinkCount -lt 60 -or
        $measurement.AliasAndBusyBoxUniqueFileIds -ne 2) {
        throw "Hardlink validation failed for $label"
    }
}

$fallbackLabels = 'installed-full-compact-copy-fallback',
    'extracted-portable-compact-copy-fallback'
foreach ($label in $fallbackLabels) {
    $measurement = $measurements | Where-Object Label -eq $label
    if ($measurement.AliasCount -ne 59 -or
        $measurement.AliasUniqueFileIds -ne 59 -or
        $measurement.AliasAndBusyBoxUniqueFileIds -ne 60 -or
        $measurement.AliasAndBusyBoxAllocatedBytes -gt 2MB) {
        throw "Compact copy fallback validation failed for $label"
    }
}

$deltas = [Collections.Generic.List[object]]::new()
function Add-Delta {
    param(
        [Parameter(Mandatory = $true)][string]$Artifact,
        [Parameter(Mandatory = $true)][string]$Comparison,
        [Parameter(Mandatory = $true)][string]$Before,
        [Parameter(Mandatory = $true)][string]$After
    )

    $beforeMeasurement = $measurements | Where-Object Label -eq $Before
    $afterMeasurement = $measurements | Where-Object Label -eq $After
    if (-not $beforeMeasurement -or -not $afterMeasurement) {
        throw "Missing delta measurement for $Artifact $Comparison"
    }
    $deltas.Add([pscustomobject]@{
        Artifact = $Artifact
        Comparison = $Comparison
        ProductBytes = [int64]($afterMeasurement.ProductBytes - $beforeMeasurement.ProductBytes)
        TreeLogicalBytes = [int64]($afterMeasurement.TreeLogicalBytes - $beforeMeasurement.TreeLogicalBytes)
        TreeAllocatedBytes = [int64]($afterMeasurement.TreeAllocatedBytes - $beforeMeasurement.TreeAllocatedBytes)
    })
}

foreach ($comparison in @(
    @{ Name = 'release-to-leaf'; BeforeSuffix = 'release'; AfterSuffix = 'base' },
    @{ Name = 'release-to-combined'; BeforeSuffix = 'release'; AfterSuffix = 'integrated' },
    @{ Name = 'leaf-to-combined'; BeforeSuffix = 'base'; AfterSuffix = 'integrated' }
)) {
    Add-Delta -Artifact 'installer' -Comparison $comparison.Name `
        -Before "installed-full-$($comparison.BeforeSuffix)" `
        -After $(if ($comparison.AfterSuffix -eq 'integrated') {
            'installed-full-clean-hardlinks'
        } else {
            "installed-full-$($comparison.AfterSuffix)"
        })
    Add-Delta -Artifact 'portable' -Comparison $comparison.Name `
        -Before "extracted-portable-$($comparison.BeforeSuffix)" `
        -After $(if ($comparison.AfterSuffix -eq 'integrated') {
            'extracted-portable-hardlinks'
        } else {
            "extracted-portable-$($comparison.AfterSuffix)"
        })
    Add-Delta -Artifact 'mingit' -Comparison $comparison.Name `
        -Before "standard-mingit-$($comparison.BeforeSuffix)" `
        -After "standard-mingit-$($comparison.AfterSuffix)"
    Add-Delta -Artifact 'busybox-mingit' -Comparison $comparison.Name `
        -Before "busybox-mingit-$($comparison.BeforeSuffix)" `
        -After "busybox-mingit-$($comparison.AfterSuffix)"
}

$result = [ordered]@{
    SchemaVersion = 2
    Baselines = [ordered]@{
        ReleasedPayload = 'v2.55.0.windows.4 via crutkas/build-extra#1@9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19'
        LeafTools = 'crutkas-arm64-native-leaf-tools@39ffc22208aa99e287a9f433431fb9a56f443b62'
    }
    Measurements = $measurements
    Deltas = $deltas
    Lifecycle = $lifecycle
}
$jsonPath = Join-Path $outputPath 'arm64-combined-distribution-impact.json'
$result | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $jsonPath -Encoding utf8

$markdownPath = Join-Path $outputPath 'arm64-combined-distribution-impact.md'
$lines = [Collections.Generic.List[string]]::new()
$lines.Add('Released payload: v2.55.0.windows.4 via crutkas/build-extra#1@9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19')
$lines.Add('Leaf-tools baseline: crutkas-arm64-native-leaf-tools@39ffc22208aa99e287a9f433431fb9a56f443b62')
$lines.Add('')
$lines.Add('| Payload | Download bytes | Tree logical | Tree allocated | Aliases | Alias IDs | Alias links | Alias + BusyBox logical | Alias + BusyBox allocated | Alias + BusyBox IDs |')
$lines.Add('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
foreach ($measurement in $measurements) {
    $lines.Add(
        "| $($measurement.Label) | $($measurement.ProductBytes) | " +
        "$($measurement.TreeLogicalBytes) | $($measurement.TreeAllocatedBytes) | " +
        "$($measurement.AliasCount) | $($measurement.AliasUniqueFileIds) | " +
        "$($measurement.AliasLinkCount) | $($measurement.AliasAndBusyBoxLogicalBytes) | " +
        "$($measurement.AliasAndBusyBoxAllocatedBytes) | " +
        "$($measurement.AliasAndBusyBoxUniqueFileIds) |"
    )
}
$lines.Add('')
$lines.Add('| Artifact | Comparison | Download delta | Tree logical delta | Tree allocated delta |')
$lines.Add('| --- | --- | ---: | ---: | ---: |')
foreach ($delta in $deltas) {
    $lines.Add(
        "| $($delta.Artifact) | $($delta.Comparison) | " +
        "$($delta.ProductBytes) | $($delta.TreeLogicalBytes) | " +
        "$($delta.TreeAllocatedBytes) |"
    )
}
$lines.Add('')
$lines.Add("Installer repair restored alias: $($lifecycle.InstallerRepairRestoredAlias)")
$lines.Add("Installer uninstall removed aliases: $($lifecycle.InstallerUninstallRemovedAliases)")
$lines.Add("Portable extraction preserved aliases: $($lifecycle.PortableExtractionPreservedAliases)")
$lines | Set-Content -LiteralPath $markdownPath -Encoding utf8
Get-Content -LiteralPath $markdownPath
