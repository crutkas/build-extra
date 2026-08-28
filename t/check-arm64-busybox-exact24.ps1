param(
    [string]$ControlRoot,

    [string]$CandidateRoot,

    [string]$OutputDirectory,

    [string]$FrozenSourcePath,

    [switch]$DataOnly
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$validationRoot = Join-Path $repoRoot 'arm64-validation'
$sourcePath = Join-Path $validationRoot 'busybox-exact24-source-v2.55.0.4.tsv'
$dispositionPath = Join-Path $validationRoot 'busybox-exact24-disposition-v2.55.0.4.tsv'
$provenancePath = Join-Path $validationRoot 'busybox-exact24-provenance-v2.55.0.4.json'
$residualPath = Join-Path $validationRoot 'busybox-residual-coreutils-v2.55.0.4.txt'
$experimentalPath = Join-Path $repoRoot 'arm64-busybox\experimental-replacements.txt'
$defaultPath = Join-Path $repoRoot 'arm64-busybox\default-replacements.txt'

function Assert-Sequence {
    param(
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Actual.Count -ne $Expected.Count) {
        throw "$Label count is $($Actual.Count), expected $($Expected.Count)"
    }
    for ($i = 0; $i -lt $Actual.Count; $i++) {
        if ([string]$Actual[$i] -cne [string]$Expected[$i]) {
            throw "$Label differs at row $($i + 1): '$($Actual[$i])' != '$($Expected[$i])'"
        }
    }
}

function Get-ByteSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    finally {
        $sha.Dispose()
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Path is not a PE file"
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "$Path has an invalid PE header"
    }
    '0x{0:X4}' -f [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

$source = @(Import-Csv -Delimiter "`t" -LiteralPath $sourcePath)
$dispositions = @(Import-Csv -Delimiter "`t" -LiteralPath $dispositionPath)
$provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
$residual = @(Get-Content -LiteralPath $residualPath)
$experimental = @(Get-Content -LiteralPath $experimentalPath)
$defaults = @(Get-Content -LiteralPath $defaultPath)
$derived = @($experimental | Where-Object { $_ -cne 'usr/bin/awk.exe' })

if ($defaults.Count -ne 59 -or $experimental.Count -ne 25 -or
    ($defaults | Sort-Object -Unique).Count -ne 59 -or
    ($experimental | Sort-Object -Unique).Count -ne 25) {
    throw 'Frozen PR #4 must retain 59 default and 25 experimental paths'
}
Assert-Sequence @($source.path) $derived 'exact24 source paths'
Assert-Sequence @($dispositions.path) $derived 'exact24 disposition paths'
if ($source.Count -ne 24 -or $dispositions.Count -ne 24) {
    throw 'The exact24 inputs must contain exactly 24 rows'
}
if (@($source | Where-Object { [string]::IsNullOrWhiteSpace($_.sourceReason) }).Count) {
    throw 'Every exact24 source row must carry its frozen reason'
}
for ($i = 0; $i -lt $source.Count; $i++) {
    if ($source[$i].sourceReason -cne $dispositions[$i].reason) {
        throw "$($source[$i].path) changed its frozen reason"
    }
}

$safe = @($dispositions | Where-Object disposition -CEQ 'safe')
$blocked = @($dispositions | Where-Object disposition -CEQ 'blocked')
if ($safe.Count -ne 0 -or $blocked.Count -ne 24) {
    throw "Expected 0 safe and 24 blocked dispositions, found $($safe.Count) and $($blocked.Count)"
}
foreach ($row in $dispositions) {
    if ($defaults -contains $row.path) {
        throw "$($row.path) was promoted despite its blocked disposition"
    }
    if ($experimental -notcontains $row.path) {
        throw "$($row.path) no longer remains experimental"
    }
    if ($row.controlPackage -cne 'coreutils' -or $row.controlVersion -cne '8.32-5' -or
        $row.controlArchitecture -cne 'x64' -or $row.controlMachine -cne '0x8664' -or
        $row.candidatePackage -cne 'mingw-w64-clang-aarch64-busybox' -or
        $row.candidateVersion -cne '1.38.0.git.e7299058-1' -or
        $row.candidateArchitecture -cne 'arm64' -or $row.candidateMachine -cne '0xAA64') {
        throw "$($row.path) has an unexpected architecture or package mapping"
    }
    if ($row.controlSha256 -notmatch '^[0-9a-f]{64}$' -or
        $row.candidateSha256 -notmatch '^[0-9a-f]{64}$') {
        throw "$($row.path) has an invalid SHA-256 mapping"
    }
}

$requiredAreas = 'command-dispatch', 'argv', 'env', 'exit', 'stdin', 'stdout',
    'stderr', 'binary', 'text', 'filesystem', 'link', 'permission', 'time',
    'locale', 'terminal', 'signal', 'identity', 'durability', 'randomization',
    'option'
$actualAreas = @($dispositions.proofAreas -split ',' | Sort-Object -Unique)
foreach ($area in $requiredAreas) {
    if ($actualAreas -notcontains $area) {
        throw "The exact24 proof mapping does not cover $area"
    }
}

if ($residual.Count -ne 54 -or ($residual | Sort-Object -Unique).Count -ne 54) {
    throw 'The residual coreutils path list must contain 54 unique paths'
}
foreach ($path in $source.path) {
    if ($residual -notcontains $path) {
        throw "$path is missing from the residual coreutils list"
    }
}
foreach ($path in $defaults) {
    if ($residual -contains $path) {
        throw "$path is both a default replacement and residual coreutils"
    }
}
if ($residual -contains 'usr/bin/awk.exe') {
    throw 'The separately-owned gawk path must not be in residual coreutils'
}

if ($provenance.schemaVersion -ne 1 -or
    $provenance.source.repository -cne 'crutkas/build-extra' -or
    $provenance.source.pullRequest -ne 12 -or
    $provenance.source.head -cne '3ef6d935092dc6ab2e376bcd0ffc74fa52dac39d' -or
    $provenance.source.gitBlob -cne '7ceb6596e7258e5420a9c86fd9ef9d2aa8519aec' -or
    $provenance.source.sha256 -cne 'aef5aaefb1ee5ad67ccdfc5fc8469005dcbf6e26615a3ad05c0704056ca16f46' -or
    $provenance.control.repository -cne 'crutkas/build-extra' -or
    $provenance.control.pullRequest -ne 4 -or
    $provenance.control.head -cne '50de8f12409d8cc8e16aef190629073db1a8606d' -or
    $provenance.control.workflowRun -ne 31771293786 -or
    $provenance.control.artifact.id -ne 9208307139 -or
    $provenance.control.artifact.sha256 -cne 'e4208e3d92172011475644d7afb2c207ae971a64e615f5330c5f6079001ded03' -or
    $provenance.result.safePaths -ne 0 -or
    $provenance.result.blockedPaths -ne 24 -or
    $provenance.result.residualCoreutilsPaths -ne 54) {
    throw 'The exact24 provenance pin changed'
}

if ($FrozenSourcePath) {
    $frozenBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $FrozenSourcePath).Path)
    if ((Get-ByteSha256 $frozenBytes) -cne $provenance.source.sha256) {
        throw 'The fetched frozen PR #12 source blob has an unexpected SHA-256'
    }
    $frozen = @(Import-Csv -Delimiter "`t" -LiteralPath $FrozenSourcePath)
    $frozenDerived = @($frozen | Where-Object {
        $_.path -cne 'usr/bin/awk.exe' -and
        $_.reason -cne 'No exact ARM64 BusyBox applet' -and
        $_.reason -cne 'BusyBox does not replace support libraries or extensions'
    })
    Assert-Sequence @($frozenDerived.path) @($source.path) 'frozen PR #12 derived paths'
    Assert-Sequence @($frozenDerived.reason) @($source.sourceReason) 'frozen PR #12 derived reasons'
    $coreutilsStart = [Array]::IndexOf($frozen.path, 'usr/bin/chmod.exe')
    $coreutilsEnd = [Array]::IndexOf($frozen.path, 'usr/lib/coreutils/libstdbuf.dll')
    if ($coreutilsStart -lt 0 -or $coreutilsEnd -lt $coreutilsStart) {
        throw 'The frozen PR #12 coreutils range is missing'
    }
    $frozenResidual = @(
        $frozen[$coreutilsStart..$coreutilsEnd] | ForEach-Object path
    )
    Assert-Sequence $frozenResidual $residual 'frozen PR #12 residual coreutils paths'
}

$packagePath = Join-Path $repoRoot $provenance.candidate.packageFile.Replace('/', '\')
$checkedInShim = Join-Path $repoRoot 'arm64-busybox\busybox-shim.exe'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $packagePath).Hash.ToLowerInvariant() -cne
        $provenance.candidate.packageSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $checkedInShim).Hash.ToLowerInvariant() -cne
        $provenance.candidate.shimSha256) {
    throw 'Frozen PR #4 package bytes or compact shim changed'
}

Write-Host 'Validated exact24 provenance, 0 safe paths, 24 blockers, and 54 residual coreutils paths'
if ($DataOnly) {
    exit 0
}
if (-not $ControlRoot -or -not $CandidateRoot -or -not $OutputDirectory) {
    throw 'ControlRoot, CandidateRoot, and OutputDirectory are required without -DataOnly'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::Arm64) {
    throw 'The executable proof must run on native ARM64 Windows'
}

$controlRootPath = (Resolve-Path -LiteralPath $ControlRoot).Path
$candidateRootPath = (Resolve-Path -LiteralPath $CandidateRoot).Path
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$resultPath = Join-Path $outputPath 'cases'
New-Item -ItemType Directory -Force -Path $resultPath | Out-Null

$packageVersions = Get-Content -LiteralPath (Join-Path $controlRootPath 'etc\package-versions.txt')
if ($packageVersions -notcontains 'coreutils 8.32-5') {
    throw 'The frozen control does not contain coreutils 8.32-5'
}
$busyBoxPath = Join-Path $candidateRootPath 'clangarm64\bin\busybox.exe'
$shimPath = Join-Path $candidateRootPath 'clangarm64\bin\busybox-shim.exe'
if ((Get-PeMachine $busyBoxPath) -cne '0xAA64' -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $busyBoxPath).Hash.ToLowerInvariant() -cne
        $provenance.candidate.busyBoxSha256 -or
    (Get-PeMachine $shimPath) -cne '0xAA64' -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $shimPath).Hash.ToLowerInvariant() -cne
        $provenance.candidate.shimSha256) {
    throw 'The candidate BusyBox binary or shim does not match frozen PR #4'
}

$replacementRows = @(
    Import-Csv -Delimiter "`t" -LiteralPath (
        Join-Path $candidateRootPath 'etc\arm64-busybox-replacements.tsv'
    )
)
foreach ($row in $dispositions) {
    $control = Join-Path $controlRootPath $row.path.Replace('/', '\')
    $candidate = Join-Path $candidateRootPath $row.path.Replace('/', '\')
    if ((Get-PeMachine $control) -cne $row.controlMachine -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $control).Hash.ToLowerInvariant() -cne
            $row.controlSha256) {
        throw "$($row.path) does not match its frozen x64 control mapping"
    }
    if ((Get-PeMachine $candidate) -cne $row.candidateMachine -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant() -cne
            $row.candidateSha256) {
        throw "$($row.path) does not dispatch through the frozen ARM64 shim"
    }
    $replacement = @($replacementRows | Where-Object path -CEQ $row.path)
    if ($replacement.Count -ne 1 -or $replacement[0].selection -cne 'experimental') {
        throw "$($row.path) is not recorded as an experimental proof candidate"
    }
}

function Initialize-Fixture {
    param([Parameter(Mandatory = $true)][string]$Root)

    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'tree\empty') | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $Root 'file.bin'),
        [byte[]](0, 1, 2, 10, 13, 31, 32, 65, 127, 128, 254, 255)
    )
    [IO.File]::WriteAllText((Join-Path $Root 'lines.txt'), "alpha`nbeta`ngamma`n")
    [IO.File]::WriteAllText((Join-Path $Root 'tree\text.txt'), "text`n")
    [IO.File]::WriteAllText((Join-Path $Root "tree\caf$([char]0x00e9).txt"), "utf8`n")
    [IO.File]::WriteAllBytes(
        (Join-Path $Root 'random.bin'),
        [byte[]](0..255)
    )
    $sparse = [IO.File]::OpenWrite((Join-Path $Root 'tree\sparse.bin'))
    try {
        $sparse.SetLength(1MB)
    }
    finally {
        $sparse.Dispose()
    }
    [IO.File]::CreateSymbolicLink(
        (Join-Path $Root 'link.txt'),
        'tree\text.txt'
    ) | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $Root 'signal.sh'),
        @'
"$EXACT24_TOOL" 5 &
pid=$!
"$EXACT24_DELAY" 0.1
kill -TERM "$pid"
wait "$pid"
printf '%s\n' "$?"
'@
    )
    [IO.File]::WriteAllText(
        (Join-Path $Root 'timeout-child.sh'),
        @'
trap 'printf "trapped\n"; exit 0' TERM
while :
do
	"$EXACT24_DELAY" 1
done
'@
    )
}

function Get-TreeFingerprint {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rows = foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -Force -File) {
        $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        "$relative`t$($file.Length)`t$hash"
    }
    ($rows | Sort-Object) -join "`n"
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$InputBytes,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $File
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add([string]$argument)
    }
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['LC_ALL'] = 'C.UTF-8'
    $start.Environment['LANG'] = 'C.UTF-8'
    $start.Environment['TZ'] = 'UTC'
    foreach ($key in $Environment.Keys) {
        $start.Environment[$key] = [string]$Environment[$key]
    }

    $process = [Diagnostics.Process]::Start($start)
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
    if ($null -ne $InputBytes -and $InputBytes.Length) {
        $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
    }
    $process.StandardInput.Close()
    $timedOut = -not $process.WaitForExit($TimeoutMilliseconds)
    if ($timedOut) {
        $process.Kill($true)
        $process.WaitForExit()
    }
    [Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))
    [pscustomobject]@{
        ExitCode = if ($timedOut) { $null } else { $process.ExitCode }
        TimedOut = $timedOut
        Stdout = $stdout.ToArray()
        Stderr = $stderr.ToArray()
    }
}

$emptyBytes = [byte[]]::new(0)
$cases = [Collections.Generic.List[object]]::new()
foreach ($row in $dispositions) {
    $cases.Add([pscustomobject]@{
        Tool = [IO.Path]::GetFileNameWithoutExtension($row.path)
        Id = 'gnu-version-contract'
        Arguments = @('--version')
        Input = $emptyBytes
        Environment = @{}
        Timeout = 5000
        MustDiffer = $true
        Launcher = $null
    })
}

$detail = @(
    @{ Tool = 'chmod'; Id = 'mode-640'; Arguments = @('640', 'file.bin') },
    @{ Tool = 'date'; Id = 'epoch-utc'; Arguments = @('-u', '-d', '@0', '+%Y-%m-%dT%H:%M:%SZ') },
    @{ Tool = 'dd'; Id = 'binary-stdio'; Arguments = @('bs=3', 'status=none'); Input = [byte[]](0, 1, 10, 13, 128, 255) },
    @{ Tool = 'df'; Id = 'posix-filesystem'; Arguments = @('-P', '.') },
    @{ Tool = 'du'; Id = 'links-and-allocation'; Arguments = @('--apparent-size', '--block-size=1', 'tree') },
    @{ Tool = 'factor'; Id = 'beyond-uint64'; Arguments = @('18446744073709551617') },
    @{ Tool = 'groups'; Id = 'current-identity'; Arguments = @() },
    @{ Tool = 'id'; Id = 'uid-gid-groups'; Arguments = @() },
    @{ Tool = 'install'; Id = 'mode-and-directories'; Arguments = @('-D', '-m', '640', 'file.bin', 'out/installed.bin') },
    @{ Tool = 'link'; Id = 'hard-link'; Arguments = @('file.bin', 'hardlink.bin') },
    @{ Tool = 'logname'; Id = 'login-identity'; Arguments = @() },
    @{ Tool = 'ls'; Id = 'piped-utf8'; Arguments = @('-1', 'tree') },
    @{ Tool = 'printenv'; Id = 'nul-unicode-environment'; Arguments = @('-0', 'EXACT24_TEXT'); Environment = @{ EXACT24_TEXT = "caf$([char]0x00e9)" } },
    @{ Tool = 'pwd'; Id = 'posix-rendering'; Arguments = @('-L') },
    @{ Tool = 'readlink'; Id = 'symlink-rendering'; Arguments = @('link.txt') },
    @{ Tool = 'realpath'; Id = 'symlink-resolution'; Arguments = @('link.txt') },
    @{ Tool = 'shred'; Id = 'zero-and-remove'; Arguments = @('--iterations=0', '--zero', '--remove=unlink', 'file.bin') },
    @{ Tool = 'shuf'; Id = 'deterministic-random-source'; Arguments = @('--random-source=random.bin', 'lines.txt') },
    @{ Tool = 'stat'; Id = 'mode-size-time-format'; Arguments = @('-c', '%f:%a:%s:%Y', 'file.bin') },
    @{ Tool = 'stty'; Id = 'redirected-terminal'; Arguments = @('-a') },
    @{ Tool = 'sync'; Id = 'file-data-durability'; Arguments = @('--data', 'file.bin') },
    @{ Tool = 'whoami'; Id = 'current-identity'; Arguments = @() }
)
foreach ($spec in $detail) {
    $cases.Add([pscustomobject]@{
        Tool = $spec.Tool
        Id = $spec.Id
        Arguments = @($spec.Arguments)
        Input = if ($spec.ContainsKey('Input')) {
            [byte[]]$spec.Input
        }
        else {
            $emptyBytes
        }
        Environment = if ($spec.ContainsKey('Environment')) {
            [hashtable]$spec.Environment
        }
        else {
            @{}
        }
        Timeout = 5000
        MustDiffer = $false
        Launcher = $null
    })
}
$controlBash = Join-Path $controlRootPath 'usr\bin\bash.exe'
$controlDelay = Join-Path $controlRootPath 'usr\bin\sleep.exe'
$cases.Add([pscustomobject]@{
    Tool = 'sleep'
    Id = 'msys-sigterm'
    Arguments = @('signal.sh')
    Input = $emptyBytes
    Environment = @{
        EXACT24_DELAY = $controlDelay
    }
    Timeout = 2000
    MustDiffer = $false
    Launcher = $controlBash
})
$cases.Add([pscustomobject]@{
    Tool = 'timeout'
    Id = 'signal-forwarding'
    Arguments = @('--signal=TERM', '0.2', $controlBash, 'timeout-child.sh')
    Input = $emptyBytes
    Environment = @{
        EXACT24_DELAY = $controlDelay
    }
    Timeout = 3000
    MustDiffer = $false
    Launcher = $null
})

$workspace = Join-Path ([IO.Path]::GetTempPath()) "busybox-exact24-$PID"
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
$results = [Collections.Generic.List[object]]::new()
try {
    foreach ($case in $cases) {
        $caseName = "$($case.Tool)-$($case.Id)"
        $controlWork = Join-Path $workspace "$caseName-control"
        $candidateWork = Join-Path $workspace "$caseName-candidate"
        New-Item -ItemType Directory -Force -Path $controlWork, $candidateWork | Out-Null
        Initialize-Fixture $controlWork
        Initialize-Fixture $candidateWork

        $controlTool = if ($case.Launcher) {
            $case.Launcher
        }
        else {
            Join-Path $controlRootPath "usr\bin\$($case.Tool).exe"
        }
        $candidateTool = if ($case.Launcher) {
            $case.Launcher
        }
        else {
            Join-Path $candidateRootPath "usr\bin\$($case.Tool).exe"
        }
        $controlEnvironment = @{} + $case.Environment
        $candidateEnvironment = @{} + $case.Environment
        if ($case.Tool -eq 'sleep' -and $case.Id -eq 'msys-sigterm') {
            $controlEnvironment.EXACT24_TOOL =
                Join-Path $controlRootPath 'usr\bin\sleep.exe'
            $candidateEnvironment.EXACT24_TOOL =
                Join-Path $candidateRootPath 'usr\bin\sleep.exe'
        }

        $controlResult = Invoke-Captured $controlTool $case.Arguments $controlWork `
            $case.Input $controlEnvironment $case.Timeout
        $candidateResult = Invoke-Captured $candidateTool $case.Arguments $candidateWork `
            $case.Input $candidateEnvironment $case.Timeout
        $controlTree = Get-TreeFingerprint $controlWork
        $candidateTree = Get-TreeFingerprint $candidateWork
        $stdoutEqual = [Linq.Enumerable]::SequenceEqual(
            [byte[]]$controlResult.Stdout,
            [byte[]]$candidateResult.Stdout
        )
        $stderrEqual = [Linq.Enumerable]::SequenceEqual(
            [byte[]]$controlResult.Stderr,
            [byte[]]$candidateResult.Stderr
        )
        $equivalent = $controlResult.ExitCode -eq $candidateResult.ExitCode -and
            $controlResult.TimedOut -eq $candidateResult.TimedOut -and
            $stdoutEqual -and $stderrEqual -and $controlTree -ceq $candidateTree
        if ($case.MustDiffer -and $equivalent) {
            throw "$caseName unexpectedly matched the GNU control"
        }

        [IO.File]::WriteAllBytes(
            (Join-Path $resultPath "$caseName-control.stdout"),
            $controlResult.Stdout
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $resultPath "$caseName-control.stderr"),
            $controlResult.Stderr
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $resultPath "$caseName-candidate.stdout"),
            $candidateResult.Stdout
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $resultPath "$caseName-candidate.stderr"),
            $candidateResult.Stderr
        )
        $results.Add([pscustomobject]@{
            Tool = $case.Tool
            Case = $case.Id
            MustDiffer = $case.MustDiffer
            Equivalent = $equivalent
            ControlExit = $controlResult.ExitCode
            CandidateExit = $candidateResult.ExitCode
            ControlTimedOut = $controlResult.TimedOut
            CandidateTimedOut = $candidateResult.TimedOut
            StdoutEqual = $stdoutEqual
            StderrEqual = $stderrEqual
            FilesystemEqual = $controlTree -ceq $candidateTree
            ControlStdoutSha256 = Get-ByteSha256 $controlResult.Stdout
            CandidateStdoutSha256 = Get-ByteSha256 $candidateResult.Stdout
            ControlStderrSha256 = Get-ByteSha256 $controlResult.Stderr
            CandidateStderrSha256 = Get-ByteSha256 $candidateResult.Stderr
        })
    }
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}

foreach ($row in $dispositions) {
    $tool = [IO.Path]::GetFileNameWithoutExtension($row.path)
    $toolResults = @($results | Where-Object Tool -CEQ $tool)
    if ($toolResults.Count -lt 2 -or
        @($toolResults | Where-Object MustDiffer).Count -lt 1 -or
        @($toolResults | Where-Object { $_.MustDiffer -and -not $_.Equivalent }).Count -lt 1) {
        throw "$tool does not have both semantic probes and a demonstrated blocker"
    }
}

$report = [ordered]@{
    SchemaVersion = 1
    NativeArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    SourceHead = $provenance.source.head
    ControlHead = $provenance.control.head
    ControlArtifactSha256 = $provenance.control.artifact.sha256
    CandidateBusyBoxSha256 = $provenance.candidate.busyBoxSha256
    CandidateShimSha256 = $provenance.candidate.shimSha256
    SafePaths = @($safe | ForEach-Object path)
    BlockedPaths = @($blocked | ForEach-Object path)
    ResidualCoreutilsPaths = $residual
    Cases = $results
}
$report | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $outputPath 'busybox-exact24-proof.json') -Encoding utf8

$markdown = [Collections.Generic.List[string]]::new()
$markdown.Add('# ARM64 BusyBox exact24 proof')
$markdown.Add('')
$markdown.Add("* Native architecture: $($report.NativeArchitecture)")
$markdown.Add('* Safe/promoted paths: 0')
$markdown.Add('* Blocked paths: 24')
$markdown.Add('* Residual coreutils paths: 54')
$markdown.Add('')
$markdown.Add('| Tool | Probe | Control exit | Candidate exit | stdout | stderr | filesystem | Equivalent |')
$markdown.Add('| --- | --- | ---: | ---: | --- | --- | --- | --- |')
foreach ($result in $results) {
    $markdown.Add(
        "| $($result.Tool) | $($result.Case) | $($result.ControlExit) | " +
        "$($result.CandidateExit) | $($result.StdoutEqual) | " +
        "$($result.StderrEqual) | $($result.FilesystemEqual) | " +
        "$($result.Equivalent) |"
    )
}
$markdown | Set-Content -LiteralPath (
    Join-Path $outputPath 'busybox-exact24-proof.md'
) -Encoding utf8
Get-Content -LiteralPath (Join-Path $outputPath 'busybox-exact24-proof.md')
