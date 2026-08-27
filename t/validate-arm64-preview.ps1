# t/validate-arm64-preview.ps1 - focused tests for validate-arm64-preview.ps1.
#
# The tests do not need Pester.  They synthesize minimal PE images and the
# JSON input chain on disk, invoke the validator through pwsh and compare the
# exit code and the emitted evidence against the expected outcome.
#
#   pwsh -NoProfile -File t/validate-arm64-preview.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$script:TestRoot = Split-Path -Parent $PSCommandPath
$script:RepoRoot = Split-Path -Parent $script:TestRoot
$script:Validator = Join-Path $script:RepoRoot 'validate-arm64-preview.ps1'
$script:Trash = Join-Path $script:TestRoot '.trash-validate-arm64-preview'
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

$script:KindLock = 'git-for-windows/arm64-preview-lock'
$script:KindProvenance = 'git-for-windows/arm64-preview-provenance'
$script:KindPayload = 'git-for-windows/arm64-preview-payload-manifest'
$script:KindRuntime = 'git-for-windows/arm64-preview-runtime-evidence'

function Write-TestResult {
    param([string]$Name, [string]$Status, [string]$Detail)

    if ($Status -eq 'ok') {
        $script:Passed++
        Write-Host "ok   - $Name"
    } elseif ($Status -eq 'skip') {
        $script:Skipped++
        Write-Host "skip - $Name ($Detail)"
    } else {
        $script:Failed++
        Write-Host "FAIL - $Name"
        if ($Detail) { Write-Host "       $Detail" }
    }
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-FileSha256Hex {
    param([string]$Path)
    return Get-Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path))
}

function Write-JsonFile {
    param([string]$Path, $Value)

    $json = $Value | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($Path, $json + "`n", [System.Text.UTF8Encoding]::new($false))
}

function Set-UInt16 {
    param([byte[]]$Buffer, [int]$Offset, [int]$Value)

    $bytes = [System.BitConverter]::GetBytes([uint16]$Value)
    [System.Array]::Copy($bytes, 0, $Buffer, $Offset, 2)
}

function Set-UInt32 {
    param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)

    $bytes = [System.BitConverter]::GetBytes([uint32]$Value)
    [System.Array]::Copy($bytes, 0, $Buffer, $Offset, 4)
}

function New-NativePeFile {
    param([string]$Path, [int]$Machine, [byte]$Filler = 0)

    $buffer = [byte[]]::new(1024)
    if ($Filler -ne 0) {
        for ($index = 0x300; $index -lt $buffer.Length; $index++) { $buffer[$index] = $Filler }
    }
    $buffer[0] = 0x4D
    $buffer[1] = 0x5A
    Set-UInt32 -Buffer $buffer -Offset 0x3C -Value 0x80
    $buffer[0x80] = 0x50
    $buffer[0x81] = 0x45
    Set-UInt16 -Buffer $buffer -Offset 0x84 -Value $Machine
    Set-UInt16 -Buffer $buffer -Offset 0x86 -Value 1
    Set-UInt16 -Buffer $buffer -Offset 0x94 -Value 0xF0
    Set-UInt16 -Buffer $buffer -Offset 0x98 -Value 0x20B
    Set-UInt32 -Buffer $buffer -Offset 0x104 -Value 16
    $directory = Split-Path -Parent $Path
    if (-not [System.IO.Directory]::Exists($directory)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    [System.IO.File]::WriteAllBytes($Path, $buffer)
}

function New-ClrPeFile {
    param([string]$Path, [uint32]$Flags, [int]$Machine = 0x014C)

    $buffer = [byte[]]::new(1024)
    $buffer[0] = 0x4D
    $buffer[1] = 0x5A
    Set-UInt32 -Buffer $buffer -Offset 0x3C -Value 0x80
    $buffer[0x80] = 0x50
    $buffer[0x81] = 0x45
    Set-UInt16 -Buffer $buffer -Offset 0x84 -Value $Machine
    Set-UInt16 -Buffer $buffer -Offset 0x86 -Value 1
    Set-UInt16 -Buffer $buffer -Offset 0x94 -Value 0xE0
    Set-UInt16 -Buffer $buffer -Offset 0x98 -Value 0x10B
    Set-UInt32 -Buffer $buffer -Offset 0xF4 -Value 16
    Set-UInt32 -Buffer $buffer -Offset 0x168 -Value 0x2000
    Set-UInt32 -Buffer $buffer -Offset 0x16C -Value 72
    $name = [System.Text.Encoding]::ASCII.GetBytes('.text')
    [System.Array]::Copy($name, 0, $buffer, 0x178, $name.Length)
    Set-UInt32 -Buffer $buffer -Offset 0x180 -Value 0x1000
    Set-UInt32 -Buffer $buffer -Offset 0x184 -Value 0x2000
    Set-UInt32 -Buffer $buffer -Offset 0x188 -Value 0x200
    Set-UInt32 -Buffer $buffer -Offset 0x18C -Value 0x200
    Set-UInt32 -Buffer $buffer -Offset 0x200 -Value 72
    Set-UInt32 -Buffer $buffer -Offset 0x210 -Value $Flags
    $directory = Split-Path -Parent $Path
    if (-not [System.IO.Directory]::Exists($directory)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    [System.IO.File]::WriteAllBytes($Path, $buffer)
}

function Get-OwnerOf {
    param([string]$Path)
    return [string](Get-Acl -LiteralPath $Path).Owner
}

function Get-DiskEntries {
    param([string]$Root)

    $prefix = [System.IO.Path]::GetFullPath($Root)
    if (-not $prefix.EndsWith('\')) { $prefix += '\' }
    $entries = @()
    foreach ($item in (Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
        $isLink = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        $isDirectory = ($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0
        if ($isDirectory -and -not $isLink) { continue }
        $full = [System.IO.Path]::GetFullPath($item.FullName)
        $relative = $full.Substring($prefix.Length) -replace '\\', '/'
        if ($relative.StartsWith('preview-evidence/', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($isLink) {
            $entries += [pscustomobject]@{
                Path = $relative; Type = 'symlink'; Bytes = [long]0; Sha256 = $null
                LinkTarget = ([string]$item.LinkTarget -replace '\\', '/'); Owner = (Get-OwnerOf -Path $full)
            }
        } else {
            $entries += [pscustomobject]@{
                Path = $relative; Type = 'file'; Bytes = [long]$item.Length
                Sha256 = (Get-FileSha256Hex -Path $full); LinkTarget = $null; Owner = (Get-OwnerOf -Path $full)
            }
        }
    }
    $sorted = [object[]]$entries
    $comparer = [System.Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.Path, $b.Path) }
    if ($sorted.Count -gt 1) { [System.Array]::Sort($sorted, $comparer) }
    return $sorted
}

function Get-RootInventorySha256 {
    param([string]$Root)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($entry in (Get-DiskEntries -Root $Root)) {
        $sha = if ($entry.Type -eq 'file') { $entry.Sha256 } else { '-' }
        $target = if ($entry.Type -eq 'file') { '-' } else { $entry.LinkTarget }
        if ([string]::IsNullOrEmpty($target)) { $target = '-' }
        [void]$builder.Append("$($entry.Path)`t$($entry.Type)`t$($entry.Bytes)`t$sha`t$target`n")
    }
    return Get-Sha256Hex -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function New-Scenario {
    param(
        [string]$Name,
        [scriptblock]$Populate,
        [string[]]$Closure,
        [object[]]$Packages,
        [scriptblock]$Archives,
        [scriptblock]$MutateLock,
        [scriptblock]$MutateProvenance,
        [scriptblock]$MutateManifest,
        [string]$RawLock,
        [string]$RawProvenance,
        [string]$RawManifest
    )

    $base = Join-Path $script:Trash $Name
    if ([System.IO.Directory]::Exists($base)) { Remove-Item -LiteralPath $base -Recurse -Force }
    $root = Join-Path $base 'root'
    [void][System.IO.Directory]::CreateDirectory($root)
    & $Populate $root

    if ($null -eq $Packages) {
        $Packages = @([ordered]@{ name = 'git'; slot = 'mingw-w64-clang-aarch64-git'; resolved = $true; version = '2.55.0.4' })
    }
    $lock = [ordered]@{
        schemaVersion     = 1
        kind              = $script:KindLock
        previewId         = "test-$Name"
        nativeShellClosure = @($Closure)
        packages          = @($Packages)
    }
    if ($MutateLock) { & $MutateLock $lock }
    $evidenceRoot = Join-Path $root 'preview-evidence'
    [void][IO.Directory]::CreateDirectory($evidenceRoot)
    $lockPath = Join-Path $evidenceRoot 'bundle-lock.v1.json'
    if ($RawLock) {
        [System.IO.File]::WriteAllText($lockPath, $RawLock, [System.Text.UTF8Encoding]::new($false))
    } else {
        Write-JsonFile -Path $lockPath -Value $lock
    }
    $lockBytes = [System.IO.File]::ReadAllBytes($lockPath)

    $files = @()
    foreach ($entry in (Get-DiskEntries -Root $root)) {
        $files += [ordered]@{
            path       = $entry.Path
            type       = $entry.Type
            bytes      = $entry.Bytes
            sha256     = $entry.Sha256
            linkTarget = $entry.LinkTarget
            owner      = $entry.Owner
        }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        kind          = $script:KindPayload
        previewId     = "test-$Name"
        scope         = [ordered]@{ root = '.'; excludedPrefixes = @('preview-evidence/') }
        lock          = [ordered]@{ bytes = [long]$lockBytes.Length; sha256 = (Get-Sha256Hex -Bytes $lockBytes) }
        files         = @($files)
    }
    if ($Archives) { $manifest['archives'] = @(& $Archives $root) }
    if ($MutateManifest) { & $MutateManifest $manifest }
    $manifestPath = Join-Path $evidenceRoot 'payload-manifest.v1.json'
    if ($RawManifest) {
        [System.IO.File]::WriteAllText($manifestPath, $RawManifest, [System.Text.UTF8Encoding]::new($false))
    } else {
        Write-JsonFile -Path $manifestPath -Value $manifest
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)

    $helper = Join-Path $script:RepoRoot 'pe-imports.ps1'
    $provenance = [ordered]@{
        schemaVersion = 1; kind = $script:KindProvenance; previewId = "test-$Name"
        lock = [ordered]@{ path = 'bundle-lock.v1.json'; sha256 = (Get-Sha256Hex -Bytes $lockBytes) }
        payload = [ordered]@{ path = 'payload-manifest.v1.json'; sha256 = (Get-Sha256Hex -Bytes $manifestBytes) }
        assembler = [ordered]@{ repository = 'crutkas/msys2-woarm64-build'; commit = ('1' * 40) }
        validator = [ordered]@{
            repository = 'crutkas/build-extra'; commit = ('2' * 40)
            files = @(
                [ordered]@{ path = 'validate-arm64-preview.ps1'; bytes = [long](Get-Item $script:Validator).Length; sha256 = (Get-FileSha256Hex $script:Validator) },
                [ordered]@{ path = 'pe-imports.ps1'; bytes = [long](Get-Item $helper).Length; sha256 = (Get-FileSha256Hex $helper) }
            )
        }
        inputs = @()
    }
    if ($MutateProvenance) { & $MutateProvenance $provenance }
    $provenancePath = Join-Path $evidenceRoot 'deterministic-provenance.v1.json'
    if ($RawProvenance) { [IO.File]::WriteAllText($provenancePath, $RawProvenance, [Text.UTF8Encoding]::new($false)) }
    else { Write-JsonFile $provenancePath $provenance }
    $provenanceBytes = [IO.File]::ReadAllBytes($provenancePath)

    return [pscustomobject]@{
        Name           = $Name
        Base           = $base
        Root           = $root
        LockPath       = $lockPath
        ProvenancePath = $provenancePath
        ManifestPath   = $manifestPath
        OutputPath     = (Join-Path $evidenceRoot 'validation-evidence.v1.json')
        RuntimePath    = (Join-Path $evidenceRoot 'runtime-evidence.v1.json')
        LockSha256     = (Get-Sha256Hex -Bytes $lockBytes)
        ProvenanceSha256 = (Get-Sha256Hex -Bytes $provenanceBytes)
        ManifestSha256 = (Get-FileSha256Hex -Path $manifestPath)
    }
}

function Invoke-Validator {
    param([string[]]$Arguments)

    $output = & pwsh -NoProfile -File $script:Validator @Arguments 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = (($output | ForEach-Object { [string]$_ }) -join "`n")
    }
}

function Invoke-Static {
    param($Scenario, [string]$Mode)

    if ([IO.File]::Exists($Scenario.LockPath)) {
        [void](New-RuntimeEvidenceFile -Scenario $Scenario -Mode $Mode)
    }
    return Invoke-Validator -Arguments @(
        '-Mode', $Mode,
        '-PortableRoot', $Scenario.Root,
        '-LockPath', $Scenario.LockPath,
        '-ProvenancePath', $Scenario.ProvenancePath,
        '-PayloadManifestPath', $Scenario.ManifestPath,
        '-RuntimeEvidencePath', $Scenario.RuntimePath,
        '-OutputPath', $Scenario.OutputPath
    )
}

function Invoke-Runtime {
    param($Scenario, [string]$RuntimePath, [string]$Mode = 'preview')

    return Invoke-Validator -Arguments @(
        '-Mode', $Mode,
        '-PortableRoot', $Scenario.Root,
        '-LockPath', $Scenario.LockPath,
        '-ProvenancePath', $Scenario.ProvenancePath,
        '-PayloadManifestPath', $Scenario.ManifestPath,
        '-RuntimeEvidencePath', $RuntimePath,
        '-OutputPath', $Scenario.OutputPath
    )
}

function Get-Evidence {
    param($Scenario)

    if (-not [System.IO.File]::Exists($Scenario.OutputPath)) { return $null }
    return (Get-Content -LiteralPath $Scenario.OutputPath -Raw | ConvertFrom-Json)
}

function Test-HasViolation {
    param($Evidence, [string]$Code)

    if ($null -eq $Evidence) { return $false }
    foreach ($violation in @($Evidence.violations)) {
        if ($violation.code -ceq $Code) { return $true }
    }
    return $false
}

function Assert-Case {
    param([string]$Name, [scriptblock]$Body)

    if ($env:VALIDATOR_TEST_FILTER -and $Name -notmatch $env:VALIDATOR_TEST_FILTER) { return }
    try {
        $problem = & $Body
        if ([string]::IsNullOrEmpty($problem)) {
            Write-TestResult -Name $Name -Status 'ok'
        } elseif ($problem -like 'SKIP:*') {
            Write-TestResult -Name $Name -Status 'skip' -Detail $problem.Substring(5)
        } else {
            Write-TestResult -Name $Name -Status 'fail' -Detail $problem
        }
    } catch {
        Write-TestResult -Name $Name -Status 'fail' -Detail $_.Exception.Message
    }
}

function New-RuntimeEvidenceFile {
    param($Scenario, [string]$FileName, [string]$Mode = 'preview', [scriptblock]$Mutate, [string]$RawText)

    $path = $Scenario.RuntimePath
    if ($RawText) {
        [System.IO.File]::WriteAllText($path, $RawText, [System.Text.UTF8Encoding]::new($false))
        return $path
    }
    $now = [datetimeoffset]::UtcNow
    $evidence = [ordered]@{
        schemaVersion = 1
        kind          = $script:KindRuntime
        previewId     = "test-$($Scenario.Name)"
        mode          = $Mode
        binding       = [ordered]@{
            lockSha256            = $Scenario.LockSha256
            provenanceSha256      = $Scenario.ProvenanceSha256
            payloadManifestSha256 = $Scenario.ManifestSha256
            rootInventorySha256   = (Get-RootInventorySha256 -Root $Scenario.Root)
        }
        collection    = [ordered]@{
            method           = 'etw-image-load'
            complete         = $true
            droppedEvents    = 0
            startedAt        = $now.AddMinutes(-5).ToString('o')
            completedAt      = $now.AddMinutes(-1).ToString('o')
            hostArchitecture = 'arm64'
        }
        smokes        = @(
            [ordered]@{ name = 'shell'; command = 'bash -lc true'; exitCode = 0; succeeded = $true; processPid = 1001 },
            [ordered]@{ name = 'git'; command = 'git version'; exitCode = 0; succeeded = $true; processPid = 1002 }
        )
        processes     = @()
        modules       = @()
    }
    $modulePaths = @()
    foreach ($relative in @($Scenario | ForEach-Object {
        $lockDocument = Get-Content -LiteralPath $_.LockPath -Raw | ConvertFrom-Json
        @($lockDocument.nativeShellClosure)
    })) {
        $full = Join-Path $Scenario.Root ($relative -replace '/', '\')
        if (-not [IO.File]::Exists($full)) { continue }
        $bytes = [IO.File]::ReadAllBytes($full)
        if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { continue }
        if ($relative -eq 'bin/bash.exe') { continue }
        $facts = Get-EntryFacts -Root $Scenario.Root -Relative $relative
        $architecture = if ($relative -eq 'bin/bash.exe' -and $Scenario.Name -match 'closure-x64|runtime-x64-process') { 'x64' } else { 'arm64' }
        $evidence.modules += [ordered]@{
            path = $relative; payloadPath = $relative; origin = 'payload'
            architecture = $architecture; bytes = $facts.Bytes; sha256 = $facts.Sha256
        }
        $modulePaths += $relative
    }
    if ($modulePaths.Count -eq 0 -and [IO.File]::Exists((Join-Path $Scenario.Root 'bin\msys-2.0.dll'))) {
        $relative = 'bin/msys-2.0.dll'
        $facts = Get-EntryFacts -Root $Scenario.Root -Relative $relative
        $evidence.modules += [ordered]@{
            path = $relative; payloadPath = $relative; origin = 'payload'
            architecture = 'arm64'; bytes = $facts.Bytes; sha256 = $facts.Sha256
        }
        $modulePaths += $relative
    }
    $processPath = if ([IO.File]::Exists((Join-Path $Scenario.Root 'bin\bash.exe'))) { 'bin/bash.exe' } else { @($evidence.modules)[0].path }
    $processArchitecture = if ($Scenario.Name -match 'closure-x64|runtime-x64-process') { 'x64' } else { 'arm64' }
    $evidence.processes = @(
        [ordered]@{ pid = 1001; path = $processPath; architecture = $processArchitecture; modulesComplete = $true; modules = @($modulePaths) },
        [ordered]@{ pid = 1002; path = $processPath; architecture = $processArchitecture; modulesComplete = $true; modules = @($modulePaths) }
    )
    if ($Mutate) { & $Mutate $evidence $Scenario }
    Write-JsonFile -Path $path -Value $evidence
    return $path
}

function New-ZipArchiveFile {
    param([string]$Path, [hashtable]$Entries)

    $directory = Split-Path -Parent $Path
    if (-not [System.IO.Directory]::Exists($directory)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    if ([System.IO.File]::Exists($Path)) { Remove-Item -LiteralPath $Path -Force }
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue
    $archive = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in ($Entries.Keys | Sort-Object)) {
            $entry = $archive.CreateEntry($name)
            $stream = $entry.Open()
            try {
                $bytes = [System.Text.Encoding]::ASCII.GetBytes([string]$Entries[$name])
                $stream.Write($bytes, 0, $bytes.Length)
            } finally {
                $stream.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Get-EntryFacts {
    param([string]$Root, [string]$Relative)

    $full = Join-Path $Root ($Relative -replace '/', '\')
    return [pscustomobject]@{
        Bytes  = [long](Get-Item -LiteralPath $full).Length
        Sha256 = (Get-FileSha256Hex -Path $full)
    }
}

$script:PopulateArm64 = {
    param($root)
    New-NativePeFile -Path (Join-Path $root 'bin\bash.exe') -Machine 0xAA64
    New-NativePeFile -Path (Join-Path $root 'bin\msys-2.0.dll') -Machine 0xAA64 -Filler 0x11
    New-ClrPeFile -Path (Join-Path $root 'clangarm64\bin\helper.dll') -Flags 0x1
    [System.IO.File]::WriteAllText((Join-Path $root 'README.txt'), "not a pe`n")
}

$script:PopulateWithX64 = {
    param($root)
    & $script:PopulateArm64 $root
    New-NativePeFile -Path (Join-Path $root 'tools\legacy.exe') -Machine 0x8664
}

$script:PopulateX64Shell = {
    param($root)
    New-NativePeFile -Path (Join-Path $root 'bin\bash.exe') -Machine 0x8664
    New-NativePeFile -Path (Join-Path $root 'bin\msys-2.0.dll') -Machine 0xAA64 -Filler 0x11
    [System.IO.File]::WriteAllText((Join-Path $root 'README.txt'), "not a pe`n")
}

$script:Closure = @('bin/bash.exe', 'bin/msys-2.0.dll')
$script:UnresolvedPackages = @(
    [ordered]@{ name = 'git'; slot = 'mingw-w64-clang-aarch64-git'; resolved = $true; version = '2.55.0.4' },
    [ordered]@{ name = 'git-lfs'; slot = 'mingw-w64-clang-aarch64-git-lfs'; resolved = $false }
)

if ([System.IO.Directory]::Exists($script:Trash)) { Remove-Item -LiteralPath $script:Trash -Recurse -Force }
[void][System.IO.Directory]::CreateDirectory($script:Trash)

Assert-Case -Name 'preview accepts native arm64 plus AnyCPU payload' -Body {
    $scenario = New-Scenario -Name 'preview-clean' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    $evidence = Get-Evidence -Scenario $scenario
    if ($run.ExitCode -ne 0) { return "expected exit 0, got $($run.ExitCode): $($run.Output) $(@($evidence.violations) | ConvertTo-Json -Compress)" }
    if ($null -eq $evidence) { return 'no evidence was written' }
    if (-not $evidence.ready) { return 'evidence does not claim readiness' }
    if ($evidence.result -cne 'pass') { return "unexpected result '$($evidence.result)'" }
    if ($evidence.peInventory.counts.arm64 -ne 2) { return "expected 2 arm64 binaries, got $($evidence.peInventory.counts.arm64)" }
    if ($evidence.peInventory.clrCounts.anycpu -ne 1) { return 'expected exactly one AnyCPU assembly' }
    if ($evidence.portableRoot.inventoryAlgorithm -cne 'gfw-arm64-preview-root-inventory-v1') { return 'inventory algorithm not documented in evidence' }
    $expectedInventory = Get-RootInventorySha256 -Root $scenario.Root
    if ($evidence.portableRoot.inventorySha256 -cne $expectedInventory) { return 'canonical root inventory hash disagrees with the documented algorithm' }
    if ($evidence.bindings.lock.sha256 -cne $scenario.LockSha256) { return 'lock input binding is not recorded' }
    if ($null -eq $evidence.validator.commit -or $null -eq $evidence.portableRoot.entries) {
        return 'passing evidence is an incomplete no-op document'
    }
    if ($null -eq $evidence.runtime -or $evidence.runtime.complete -ne $true) { return 'passing evidence is missing complete runtime claims' }
    return $null
}

Assert-Case -Name 'preview reports broader x64 content without failing' -Body {
    $scenario = New-Scenario -Name 'preview-broader-x64' -Populate $script:PopulateWithX64 -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 0) { return "expected exit 0, got $($run.ExitCode): $($run.Output)" }
    $evidence = Get-Evidence -Scenario $scenario
    if (@($evidence.broaderNonCompliantBinaries) -notcontains 'tools/legacy.exe') { return 'the broader x64 binary was not reported' }
    if ($evidence.peInventory.counts.x64 -ne 1) { return 'the x64 binary was not counted' }
    return $null
}

Assert-Case -Name 'final rejects broader x64 content' -Body {
    $scenario = New-Scenario -Name 'final-broader-x64' -Populate $script:PopulateWithX64 -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    $evidence = Get-Evidence -Scenario $scenario
    if (-not (Test-HasViolation -Evidence $evidence -Code 'payload-architecture-violation')) { return 'missing payload-architecture-violation' }
    if ($evidence.ready) { return 'a failed run must not claim readiness' }
    return $null
}

Assert-Case -Name 'final accepts a fully arm64 payload' -Body {
    $scenario = New-Scenario -Name 'final-clean' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 0) { return "expected exit 0, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'preview rejects an x64 native shell closure entry' -Body {
    $scenario = New-Scenario -Name 'closure-x64' -Populate $script:PopulateX64Shell -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'closure-architecture-violation')) { return 'missing closure-architecture-violation' }
    return $null
}

Assert-Case -Name 'a payload sha256 mismatch is a content failure' -Body {
    $scenario = New-Scenario -Name 'sha-mismatch' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].sha256 = ('a' * 64)
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-sha256-mismatch')) { return 'missing payload-sha256-mismatch' }
    return $null
}

Assert-Case -Name 'a payload byte count mismatch is a content failure' -Body {
    $scenario = New-Scenario -Name 'bytes-mismatch' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].bytes = 12345
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-bytes-mismatch')) { return 'missing payload-bytes-mismatch' }
    return $null
}

Assert-Case -Name 'a declared type that disagrees with disk is a content failure' -Body {
    $scenario = New-Scenario -Name 'type-mismatch' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].type = 'symlink'
        $manifest.files[0].bytes = 0
        $manifest.files[0].sha256 = $null
        $manifest.files[0].linkTarget = 'bin/bash.exe'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-type-mismatch')) { return 'missing payload-type-mismatch' }
    return $null
}

Assert-Case -Name 'a preparation executable in the payload is a content failure' -Body {
    $scenario = New-Scenario -Name 'preparation-tool' -Populate {
        param($root)
        & $script:PopulateArm64 $root
        New-NativePeFile (Join-Path $root 'tools\objdump.exe') 0xAA64
    } -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'preparation-tool-in-payload')) { return 'missing preparation-tool-in-payload' }
    return $null
}

Assert-Case -Name 'a malformed symlink declaration is an input contract failure' -Body {
    $scenario = New-Scenario -Name 'malformed-link' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].type = 'symlink'
        $manifest.files[0].linkTarget = 'bin/other.exe'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    if ([System.IO.File]::Exists($scenario.OutputPath)) { return 'evidence must not be written for malformed input' }
    return $null
}

Assert-Case -Name 'a traversing link target is rejected' -Body {
    $scenario = New-Scenario -Name 'link-traversal' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].type = 'symlink'
        $manifest.files[0].bytes = 0
        $manifest.files[0].sha256 = $null
        $manifest.files[0].linkTarget = '../outside/bash.exe'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'a broken provenance to lock digest binding is rejected' -Body {
    $scenario = New-Scenario -Name 'binding-provenance' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateProvenance {
        param($provenance)
        $provenance.lock.sha256 = ('b' * 64)
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'a broken provenance to payload manifest digest binding is rejected' -Body {
    $scenario = New-Scenario -Name 'binding-manifest' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateProvenance {
        param($provenance)
        $provenance.payload.sha256 = ('c' * 64)
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'a manifest entry missing on disk is a content failure' -Body {
    $scenario = New-Scenario -Name 'missing-on-disk' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files = @($manifest.files) + @([ordered]@{
            path = 'bin/ghost.exe'; type = 'file'; bytes = 10; sha256 = ('d' * 64); linkTarget = $null; owner = $manifest.files[0].owner
        })
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-file-missing-on-disk')) { return 'missing payload-file-missing-on-disk' }
    return $null
}

Assert-Case -Name 'an undeclared disk entry is a content failure' -Body {
    $scenario = New-Scenario -Name 'extra-on-disk' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files = @($manifest.files | Where-Object { $_.path -ne 'README.txt' })
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-extra-disk-entry')) { return 'missing payload-extra-disk-entry' }
    return $null
}

Assert-Case -Name 'duplicate paths are rejected case insensitively' -Body {
    $scenario = New-Scenario -Name 'duplicate-path' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $clone = [ordered]@{}
        foreach ($key in $manifest.files[0].Keys) { $clone[$key] = $manifest.files[0][$key] }
        $clone.path = $clone.path.ToUpperInvariant()
        $manifest.files = @($manifest.files) + @($clone)
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'malformed JSON is rejected' -Body {
    $scenario = New-Scenario -Name 'malformed-json' -Populate $script:PopulateArm64 -Closure $script:Closure -RawManifest '{ "schemaVersion": 1,'
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'an unknown document kind is rejected' -Body {
    $scenario = New-Scenario -Name 'unknown-kind' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.kind = 'git-for-windows/something-else'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'an unexpected schema version is rejected' -Body {
    $scenario = New-Scenario -Name 'schema-version' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateLock {
        param($lock)
        $lock.schemaVersion = 2
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'placeholder values are rejected' -Body {
    $scenario = New-Scenario -Name 'placeholder' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.files[0].owner = 'TBD'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'unknown manifest members are rejected' -Body {
    $scenario = New-Scenario -Name 'unknown-member' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest['notes'] = 'unexpected'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'preview reports unresolved packages as structurally valid but not ready' -Body {
    $scenario = New-Scenario -Name 'unresolved-preview' -Populate $script:PopulateArm64 -Closure $script:Closure -Packages $script:UnresolvedPackages
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 2) { return "expected exit 2, got $($run.ExitCode): $($run.Output)" }
    $evidence = Get-Evidence -Scenario $scenario
    if ($null -eq $evidence) { return 'preview must still write evidence when it is not ready' }
    if ($evidence.ready) { return 'preview must never claim readiness with unresolved packages' }
    if ($evidence.result -cne 'not-ready') { return "unexpected result '$($evidence.result)'" }
    if (@($evidence.unresolvedPackages).Count -ne 1) { return 'the unresolved package was not reported' }
    return $null
}

Assert-Case -Name 'final rejects unresolved packages' -Body {
    $scenario = New-Scenario -Name 'unresolved-final' -Populate $script:PopulateArm64 -Closure $script:Closure -Packages $script:UnresolvedPackages
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'package-unresolved')) { return 'missing package-unresolved' }
    return $null
}

Assert-Case -Name 'a closure entry outside the payload manifest is a content failure' -Body {
    $scenario = New-Scenario -Name 'closure-missing' -Populate $script:PopulateArm64 -Closure @('bin/bash.exe', 'bin/absent.exe')
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'closure-entry-missing')) { return 'missing closure-entry-missing' }
    return $null
}

Assert-Case -Name 'a closure entry that is not a PE image is a content failure' -Body {
    $scenario = New-Scenario -Name 'closure-not-pe' -Populate $script:PopulateArm64 -Closure @('bin/bash.exe', 'README.txt')
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'closure-entry-not-pe')) { return 'missing closure-entry-not-pe' }
    return $null
}

Assert-Case -Name 'a missing -Mode is a usage error' -Body {
    $scenario = New-Scenario -Name 'usage-mode' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Validator -Arguments @(
        '-PortableRoot', $scenario.Root,
        '-LockPath', $scenario.LockPath,
        '-ProvenancePath', $scenario.ProvenancePath,
        '-PayloadManifestPath', $scenario.ManifestPath,
        '-OutputPath', $scenario.OutputPath
    )
    if ($run.ExitCode -ne 64) { return "expected exit 64, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'an unknown -Mode is a usage error' -Body {
    $scenario = New-Scenario -Name 'usage-bad-mode' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode 'audit'
    if ($run.ExitCode -ne 64) { return "expected exit 64, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'evidence below the portable root is a usage error' -Body {
    $scenario = New-Scenario -Name 'usage-output' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Validator -Arguments @(
        '-Mode', 'preview',
        '-PortableRoot', $scenario.Root,
        '-LockPath', $scenario.LockPath,
        '-ProvenancePath', $scenario.ProvenancePath,
        '-PayloadManifestPath', $scenario.ManifestPath,
        '-OutputPath', (Join-Path $scenario.Root 'evidence.json')
    )
    if ($run.ExitCode -ne 64) { return "expected exit 64, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'runtime evidence must use its exact required path' -Body {
    $scenario = New-Scenario -Name 'usage-runtime-arg' -Populate $script:PopulateArm64 -Closure $script:Closure
    $run = Invoke-Validator -Arguments @(
        '-Mode', 'preview',
        '-PortableRoot', $scenario.Root,
        '-LockPath', $scenario.LockPath,
        '-ProvenancePath', $scenario.ProvenancePath,
        '-PayloadManifestPath', $scenario.ManifestPath,
        '-RuntimeEvidencePath', $scenario.ManifestPath,
        '-OutputPath', $scenario.OutputPath
    )
    if ($run.ExitCode -ne 64) { return "expected exit 64, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'a missing input file is an input contract failure' -Body {
    $scenario = New-Scenario -Name 'missing-input' -Populate $script:PopulateArm64 -Closure $script:Closure
    Remove-Item -LiteralPath $scenario.LockPath -Force
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'malformed PE scanner failure propagates as nonzero' -Body {
    $scenario = New-Scenario -Name 'scanner-failure' -Populate {
        param($root)
        & $script:PopulateArm64 $root
        $bytes = [byte[]]::new(90)
        $bytes[0] = 0x4d; $bytes[1] = 0x5a
        [BitConverter]::GetBytes([int]64).CopyTo($bytes, 0x3c)
        [IO.File]::WriteAllBytes((Join-Path $root 'bin\malformed.exe'), $bytes)
    } -Closure $script:Closure
    $run = Invoke-Static -Scenario $scenario -Mode preview
    if ($run.ExitCode -ne 70) { return "expected exit 70, got $($run.ExitCode): $($run.Output)" }
    if ($null -ne (Get-Evidence -Scenario $scenario)) { return 'scanner failure must not emit passing evidence' }
    return $null
}

Assert-Case -Name 'evidence write failure propagates as nonzero' -Body {
    $scenario = New-Scenario -Name 'write-failure' -Populate $script:PopulateArm64 -Closure $script:Closure
    [void][IO.Directory]::CreateDirectory($scenario.OutputPath)
    [IO.File]::WriteAllText((Join-Path $scenario.OutputPath 'blocker'), 'x')
    $run = Invoke-Static -Scenario $scenario -Mode preview
    if ($run.ExitCode -eq 0) { return 'missing evidence output was allowed to pass' }
    if ([IO.File]::Exists($scenario.OutputPath)) { return 'unexpected evidence file exists' }
    return $null
}

Assert-Case -Name 'missing runtime evidence fails closed without stale output' -Body {
    $scenario = New-Scenario -Name 'missing-runtime' -Populate $script:PopulateArm64 -Closure $script:Closure
    [IO.File]::WriteAllText($scenario.OutputPath, '{"result":"pass"}')
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $scenario.RuntimePath
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    if ([IO.File]::Exists($scenario.OutputPath)) { return 'stale/no-op evidence survived missing runtime evidence' }
    return $null
}

Assert-Case -Name 'payload scope must exclude only preview evidence' -Body {
    $scenario = New-Scenario -Name 'scope-mismatch' -Populate $script:PopulateArm64 -Closure $script:Closure -MutateManifest {
        param($manifest)
        $manifest.scope.excludedPrefixes = @('other/')
    }
    $run = Invoke-Static -Scenario $scenario -Mode preview
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'runtime mode binding mismatch is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-mode-binding' -Populate $script:PopulateArm64 -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -Mode final -Mutate {
        param($evidence, $context)
        $facts = Get-EntryFacts $context.Root 'bin/msys-2.0.dll'
        $evidence.smokes = @(
            [ordered]@{ name = 'shell'; command = 'shell'; exitCode = 0; succeeded = $true; processPid = 1 },
            [ordered]@{ name = 'git'; command = 'git'; exitCode = 0; succeeded = $true; processPid = 1 }
        )
        $evidence.processes = @([ordered]@{ pid = 1; path = 'bin/bash.exe'; architecture = 'arm64'; modulesComplete = $true; modules = @('bin/msys-2.0.dll') })
        $evidence.modules = @([ordered]@{ path = 'bin/msys-2.0.dll'; payloadPath = 'bin/msys-2.0.dll'; origin = 'payload'; architecture = 'arm64'; bytes = $facts.Bytes; sha256 = $facts.Sha256 })
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath -Mode preview
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

$script:ZipEntries = @{ 'data/one.txt' = 'one'; 'data/two.txt' = 'two' }

$script:PopulateZip = {
    param($root)
    & $script:PopulateArm64 $root
    New-ZipArchiveFile -Path (Join-Path $root 'packages\sample.zip') -Entries $script:ZipEntries
}

$script:DeclareZip = {
    param($root)
    $archivePath = Join-Path $root 'packages\sample.zip'
    $owner = Get-OwnerOf -Path $archivePath
    $members = @()
    foreach ($name in ($script:ZipEntries.Keys | Sort-Object)) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes([string]$script:ZipEntries[$name])
        $members += [ordered]@{
            path = $name; type = 'file'; bytes = [long]$bytes.Length
            sha256 = (Get-Sha256Hex -Bytes $bytes); linkTarget = $null; owner = $owner
        }
    }
    @([ordered]@{
        path    = 'packages/sample.zip'
        format  = 'zip'
        bytes   = [long](Get-Item -LiteralPath $archivePath).Length
        sha256  = (Get-FileSha256Hex -Path $archivePath)
        owner   = $owner
        members = $members
    })
}

Assert-Case -Name 'zip archive members are validated against the archive' -Body {
    $scenario = New-Scenario -Name 'archive-zip-ok' -Populate $script:PopulateZip -Closure $script:Closure -Archives $script:DeclareZip
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 0) { return "expected exit 0, got $($run.ExitCode): $($run.Output)" }
    $evidence = Get-Evidence -Scenario $scenario
    if ($evidence.archiveChecks.declared -ne 1) { return 'the archive was not accounted for' }
    if (@($evidence.archiveChecks.archives)[0].verifiedMembers -ne 2) { return 'not every archive member was verified' }
    return $null
}

Assert-Case -Name 'an archive member digest mismatch is a content failure' -Body {
    $scenario = New-Scenario -Name 'archive-zip-sha' -Populate $script:PopulateZip -Closure $script:Closure -Archives $script:DeclareZip -MutateManifest {
        param($manifest)
        $manifest.archives[0].members[0].sha256 = ('e' * 64)
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'archive-member-sha256-mismatch')) { return 'missing archive-member-sha256-mismatch' }
    return $null
}

Assert-Case -Name 'an undeclared archive member is a content failure' -Body {
    $scenario = New-Scenario -Name 'archive-zip-extra' -Populate $script:PopulateZip -Closure $script:Closure -Archives $script:DeclareZip -MutateManifest {
        param($manifest)
        $manifest.archives[0].members = @($manifest.archives[0].members | Where-Object { $_.path -ne 'data/two.txt' })
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'archive-member-extra')) { return 'missing archive-member-extra' }
    return $null
}

Assert-Case -Name 'an archive whose format cannot be confirmed is rejected' -Body {
    $scenario = New-Scenario -Name 'archive-zip-format' -Populate $script:PopulateZip -Closure $script:Closure -Archives $script:DeclareZip -MutateManifest {
        param($manifest)
        $manifest.archives[0].format = 'tar.gz'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'archive-format-mismatch')) { return 'missing archive-format-mismatch' }
    return $null
}

Assert-Case -Name 'an unsupported archive format is rejected' -Body {
    $scenario = New-Scenario -Name 'archive-unsupported' -Populate $script:PopulateZip -Closure $script:Closure -Archives $script:DeclareZip -MutateManifest {
        param($manifest)
        $manifest.archives[0].format = 'sevenzip'
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'final'
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    if ($null -ne (Get-Evidence -Scenario $scenario)) { return 'unsupported input format must not emit evidence' }
    return $null
}

$script:PopulateRuntime = {
    param($root)
    & $script:PopulateArm64 $root
    New-NativePeFile -Path (Join-Path $root 'cmd\git.exe') -Machine 0xAA64 -Filler 0x22
}

$script:PopulateRuntimeX64 = {
    param($root)
    & $script:PopulateRuntime $root
    New-NativePeFile -Path (Join-Path $root 'bin\x64dep.dll') -Machine 0x8664
}

function Set-RuntimeBaseline {
    param($Evidence, $Scenario, [string[]]$ExtraModules)

    $modules = @()
    $modulePaths = @('bin/msys-2.0.dll')
    if ($null -ne $ExtraModules) { $modulePaths += @($ExtraModules | Where-Object { $_ }) }
    foreach ($path in $modulePaths) {
        $facts = Get-EntryFacts -Root $Scenario.Root -Relative $path
        $architecture = if ($path -eq 'bin/x64dep.dll') { 'x64' } else { 'arm64' }
        $modules += [ordered]@{ path = $path; payloadPath = $path; origin = 'payload'; architecture = $architecture; bytes = $facts.Bytes; sha256 = $facts.Sha256 }
    }
    $Evidence.smokes = @(
        [ordered]@{ name = 'shell'; command = 'bash -lc true'; exitCode = 0; succeeded = $true; processPid = 1001 },
        [ordered]@{ name = 'git'; command = 'git version'; exitCode = 0; succeeded = $true; processPid = 1002 }
    )
    $Evidence.processes = @(
        [ordered]@{ pid = 1001; path = 'bin/bash.exe'; architecture = 'arm64'; modulesComplete = $true; modules = @($modulePaths) },
        [ordered]@{ pid = 1002; path = 'cmd/git.exe'; architecture = 'arm64'; modulesComplete = $true; modules = @('bin/msys-2.0.dll') }
    )
    $Evidence.modules = @($modules)
}

Assert-Case -Name 'runtime evidence from a complete arm64 collection is accepted' -Body {
    $scenario = New-Scenario -Name 'runtime-ok' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 0) { return "expected exit 0, got $($run.ExitCode): $($run.Output)" }
    $evidence = Get-Evidence -Scenario $scenario
    if ($evidence.mode -cne 'preview') { return 'the evidence does not record preview mode' }
    if ($evidence.runtime.method -cne 'etw-image-load') { return 'the collection method was not recorded' }
    if ($evidence.runtime.reverifiedBinaries -lt 3) { return 'not every observed binary was reverified' }
    if ($evidence.bindings.runtimeEvidence.sha256.Length -ne 64) { return 'the runtime evidence input binding is missing' }
    return $null
}

Assert-Case -Name 'an x64 runtime module is a content failure' -Body {
    $scenario = New-Scenario -Name 'runtime-x64-module' -Populate $script:PopulateRuntimeX64 -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context -ExtraModules @('bin/x64dep.dll')
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-architecture-violation')) { return 'missing runtime-architecture-violation' }
    return $null
}

Assert-Case -Name 'an x64 runtime process is a content failure' -Body {
    $scenario = New-Scenario -Name 'runtime-x64-process' -Populate $script:PopulateX64Shell -Closure @('bin/msys-2.0.dll')
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        $facts = Get-EntryFacts -Root $context.Root -Relative 'bin/msys-2.0.dll'
        $evidence.smokes = @(
            [ordered]@{ name = 'shell'; command = 'bash -lc true'; exitCode = 0; succeeded = $true; processPid = 1001 },
            [ordered]@{ name = 'git'; command = 'git version'; exitCode = 0; succeeded = $true; processPid = 1002 }
        )
        $evidence.processes = @(
            [ordered]@{ pid = 1001; path = 'bin/bash.exe'; architecture = 'x64'; modulesComplete = $true; modules = @('bin/msys-2.0.dll') },
            [ordered]@{ pid = 1002; path = 'bin/bash.exe'; architecture = 'x64'; modulesComplete = $true; modules = @('bin/msys-2.0.dll') }
        )
        $evidence.modules = @(
            [ordered]@{ path = 'bin/msys-2.0.dll'; payloadPath = 'bin/msys-2.0.dll'; origin = 'payload'; architecture = 'arm64'; bytes = $facts.Bytes; sha256 = $facts.Sha256 }
        )
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-architecture-violation')) { return 'missing runtime-architecture-violation' }
    return $null
}

Assert-Case -Name 'an incomplete runtime collection is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-incomplete' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.collection.complete = $false
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-collection-incomplete')) { return 'missing runtime-collection-incomplete' }
    return $null
}

Assert-Case -Name 'dropped runtime events are rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-dropped' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.collection.droppedEvents = 5
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-collection-dropped-events')) { return 'missing runtime-collection-dropped-events' }
    return $null
}

Assert-Case -Name 'sampled runtime collection is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-sampled' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.collection['samplingIntervalMs'] = 25
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-sampling-not-allowed')) { return 'missing runtime-sampling-not-allowed' }
    return $null
}

Assert-Case -Name 'a failed runtime smoke test is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-smoke' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.smokes[1].succeeded = $false
        $evidence.smokes[1].exitCode = 127
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-smoke-failed')) { return 'missing runtime-smoke-failed' }
    return $null
}

Assert-Case -Name 'an unresolved runtime module reference is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-unresolved-module' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.processes[0].modules = @('bin/msys-2.0.dll', 'bin/missing.dll')
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'runtime-process-module-unresolved')) { return 'missing runtime-process-module-unresolved' }
    return $null
}

Assert-Case -Name 'runtime evidence bound to foreign inputs is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-binding' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -Mutate {
        param($evidence, $context)
        Set-RuntimeBaseline -Evidence $evidence -Scenario $context
        $evidence.binding.rootInventorySha256 = ('f' * 64)
    }
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    if ([System.IO.File]::Exists($scenario.OutputPath)) { return 'evidence must not be written for an unbound runtime document' }
    return $null
}

Assert-Case -Name 'malformed runtime evidence is rejected' -Body {
    $scenario = New-Scenario -Name 'runtime-malformed' -Populate $script:PopulateRuntime -Closure $script:Closure
    $runtimePath = New-RuntimeEvidenceFile -Scenario $scenario -FileName 'runtime.json' -RawText '{ "schemaVersion": 1, "kind": '
    $run = Invoke-Runtime -Scenario $scenario -RuntimePath $runtimePath
    if ($run.ExitCode -ne 65) { return "expected exit 65, got $($run.ExitCode): $($run.Output)" }
    return $null
}

Assert-Case -Name 'a link target that disagrees with disk is a content failure' -Body {
    $scenario = New-Scenario -Name 'link-target-mismatch' -Populate {
        param($root)
        & $script:PopulateArm64 $root
        try {
            New-Item -ItemType SymbolicLink -Path (Join-Path $root 'bin\sh.exe') -Target 'bash.exe' -ErrorAction Stop | Out-Null
        } catch {
        }
    } -Closure $script:Closure -MutateManifest {
        param($manifest)
        foreach ($file in $manifest.files) {
            if ($file.type -eq 'symlink') { $file.linkTarget = 'zsh.exe' }
        }
    }
    $hasLink = $false
    foreach ($entry in (Get-DiskEntries -Root $scenario.Root)) {
        if ($entry.Type -eq 'symlink') { $hasLink = $true }
    }
    if (-not $hasLink) {
        Write-TestResult -Name 'a link target that disagrees with disk is a content failure' -Status 'skip' -Detail 'symbolic links cannot be created in this session'
        return $null
    }
    $run = Invoke-Static -Scenario $scenario -Mode 'preview'
    if ($run.ExitCode -ne 3) { return "expected exit 3, got $($run.ExitCode): $($run.Output)" }
    if (-not (Test-HasViolation -Evidence (Get-Evidence -Scenario $scenario) -Code 'payload-link-target-mismatch')) { return 'missing payload-link-target-mismatch' }
    return $null
}

if (-not $env:VALIDATOR_TEST_KEEP_TRASH -and [System.IO.Directory]::Exists($script:Trash)) {
    Remove-Item -LiteralPath $script:Trash -Recurse -Force
}

Write-Host ''
Write-Host "passed: $($script:Passed)  failed: $($script:Failed)  skipped: $($script:Skipped)"
if ($script:Failed -gt 0) { exit 1 }
exit 0
