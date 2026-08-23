param(
    [string]$Root
)

$rootPath = $null
$oldPath = $env:PATH
$ErrorActionPreference = 'Stop'
$hostArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($hostArch -ne [System.Runtime.InteropServices.Architecture]::Arm64) {
    throw 'Native ARM64 runtime checks require windows-11-arm'
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

    [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

function Get-RootToolPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    foreach ($dir in @('clangarm64\bin', 'usr\bin')) {
        foreach ($ext in @('.exe', '')) {
            $candidate = Join-Path $rootPath "$dir\$Name$ext"
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    throw "The ARM64 payload does not contain $Name"
}
if ($Root) {
    $rootPath = (Resolve-Path -LiteralPath $Root).Path
    $env:PATH = "$rootPath\clangarm64\bin;$rootPath\usr\bin;$env:PATH"
}

if ($rootPath -notlike '*\portable-git' -and $rootPath -notlike '*\mingit-root') {
    $cases = @(
        @{ Name = "bunzip2"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "bzcat"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "bzip2"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "bzip2recover"; Arguments = @(); ExitCode = 1 },
        @{ Name = "nettle-hash"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "nettle-lfib-stream"; Arguments = @("--help"); ExitCode = 1 },
        @{ Name = "nettle-pbkdf2"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "pkcs1-conv"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "sexp-conv"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "p11-kit"; Arguments = @("--help"); ExitCode = 0 },
        @{ Name = "trust"; Arguments = @("--help"); ExitCode = 0 }
    )

    foreach ($case in $cases) {
        $native = Get-RootToolPath -Name $case.Name

        & $native @($case.Arguments) *> $null
        if ($LASTEXITCODE -ne $case.ExitCode) {
            throw "$native returned $LASTEXITCODE instead of $($case.ExitCode)"
        }
    }
}

$awkPath = (Get-Command awk.exe).Source
$gawkPath = (Get-Command gawk.exe).Source
if ($rootPath -like '*\mingit-root') {
    if ($awkPath -notlike '*\clangarm64\bin\awk.exe' -and $awkPath -notlike '*\usr\bin\awk.exe') {
        throw "awk resolves to $awkPath instead of an accepted MinGit path"
    }
}
else {
    if ($awkPath -notlike '*\clangarm64\bin\awk.exe' -and $awkPath -notlike '*\usr\bin\awk.exe') {
        throw "awk resolves to $awkPath instead of a clangarm64\bin or usr\bin awk.exe"
    }
}
if ($gawkPath -notlike '*\clangarm64\bin\gawk.exe' -and $gawkPath -notlike '*\usr\bin\gawk.exe') {
    throw "gawk resolves to $gawkPath instead of a clangarm64\bin or usr\bin gawk.exe"
}
$gawkBin = Split-Path -LiteralPath $gawkPath
$gawkVersioned = Join-Path $gawkBin 'gawk-5.4.1.exe'
if (-not (Test-Path -LiteralPath $gawkVersioned)) {
    throw "The ARM64 file list does not contain $gawkVersioned"
}
$runtimeGawkPath = $gawkVersioned
$gawkMpfr = Join-Path $gawkBin 'libmpfr-6.dll'
if (-not (Test-Path -LiteralPath $gawkMpfr)) {
    throw "The ARM64 payload does not contain clangarm64\bin\libmpfr-6.dll"
}
$gawkGmp = Join-Path $gawkBin 'libgmp-10.dll'
if (-not (Test-Path -LiteralPath $gawkGmp)) {
    throw "The ARM64 payload does not contain clangarm64\bin\libgmp-10.dll"
}
$gawkReadline = Join-Path $gawkBin 'libreadline8.dll'
if (-not (Test-Path -LiteralPath $gawkReadline)) {
    throw "The ARM64 payload does not contain clangarm64\bin\libreadline8.dll"
}
$gawkTermcap = Join-Path $gawkBin 'libtermcap-0.dll'
if (-not (Test-Path -LiteralPath $gawkTermcap)) {
    throw "The ARM64 payload does not contain clangarm64\bin\libtermcap-0.dll"
}
$gawkAwk = Join-Path $gawkBin 'awk.exe'
foreach ($path in @($gawkAwk, $gawkPath, $gawkVersioned, $gawkGmp, $gawkMpfr, $gawkReadline, $gawkTermcap)) {
    if ((Get-PeMachine -Path $path) -ne 0xAA64) {
        throw "$path is not ARM64"
    }
}
$gawkLib = Join-Path (Split-Path -LiteralPath $gawkBin) 'lib\gawk'
if (Test-Path -LiteralPath (Join-Path $gawkLib 'fork.dll')) {
    throw 'fork.dll should not be packaged for native ARM64 gawk'
}

$runtime = Join-Path ([IO.Path]::GetTempPath()) "arm64-gawk-$PID"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
try {
    $oldAwkPath = $env:AWKPATH
    $oldAwkLibPath = $env:AWKLIBPATH
    $oldLcAll = $env:LC_ALL
    try {
        $fieldScript = Join-Path $runtime 'field.awk'
        Set-Content -Encoding ascii -LiteralPath $fieldScript -Value '{ print $1 " " $2 }'
        $fieldInput = Join-Path $runtime 'field-input.txt'
        Set-Content -Encoding ascii -LiteralPath $fieldInput -Value "alpha beta"
        $fieldOutputFile = Join-Path $runtime 'field.out'
        $fieldError = Join-Path $runtime 'field.err'
        Remove-Item -LiteralPath $fieldOutputFile, $fieldError -ErrorAction SilentlyContinue
        $fieldProcess = Start-Process -FilePath $runtimeGawkPath -ArgumentList @('-f', $fieldScript, $fieldInput) -NoNewWindow -PassThru -Wait -RedirectStandardOutput $fieldOutputFile -RedirectStandardError $fieldError
        $fieldExitCode = $fieldProcess.ExitCode
        $fieldOutput = Get-Content -Raw -LiteralPath $fieldOutputFile
        if ($fieldExitCode -ne 0 -or $fieldOutput -notmatch '^alpha beta\r?\n?$') {
            Write-Host "gawk field output: <$fieldOutput>"
            if ((Test-Path -LiteralPath $fieldError) -and ((Get-Item -LiteralPath $fieldError).Length -gt 0)) {
                Get-Content -LiteralPath $fieldError
            }
            throw 'gawk field processing failed'
        }
        Write-Host 'native-tools: field ok'

        $scriptDir = Join-Path $runtime 'scripts'
        New-Item -ItemType Directory -Force -Path $scriptDir | Out-Null
        Set-Content -Encoding ascii -LiteralPath (Join-Path $scriptDir 'from-awkpath.awk') -Value 'BEGIN { print "awkpath-ok" }'
        $env:AWKPATH = "$([IO.Path]::GetFullPath($scriptDir));$oldAwkPath"
        $awkPathOutput = & $runtimeGawkPath -f from-awkpath.awk /dev/null
        $awkPathOutput = (@($awkPathOutput) -join "`n").TrimEnd("`r", "`n")
        if ($LASTEXITCODE -ne 0 -or $awkPathOutput -ne 'awkpath-ok') {
            throw 'AWKPATH did not honor a native Windows path list'
        }
        Write-Host 'native-tools: awkpath ok'

        $env:AWKLIBPATH = "$([IO.Path]::GetFullPath($gawkLib));$oldAwkLibPath"
        $inplaceInput = Join-Path $runtime 'inplace-input.txt'
        Set-Content -Encoding ascii -LiteralPath $inplaceInput -Value "in place"
        $inplaceScript = Join-Path $runtime 'inplace.awk'
        @'
@load "inplace"
@namespace "inplace"

BEGIN {
    enable = 1
}

BEGINFILE {
    sfx = (suffix ? suffix : awk::INPLACE_SUFFIX)
    if (filename != "") end(filename, sfx)
    if (enable) begin(filename = FILENAME, sfx)
    else filename = ""
}

END {
    if (filename != "") end(filename, (suffix ? suffix : awk::INPLACE_SUFFIX))
}

{ print toupper($0) }
'@ | Set-Content -Encoding ascii -LiteralPath $inplaceScript
        & $runtimeGawkPath -f $inplaceScript $inplaceInput
        if ($LASTEXITCODE -ne 0) {
            throw 'AWKLIBPATH or inplace extension loading failed'
        }
        if ((Get-Content -LiteralPath $inplaceInput -Raw) -ne "IN PLACE`r`n" -and
            (Get-Content -LiteralPath $inplaceInput -Raw) -ne "IN PLACE`n") {
            throw 'inplace editing did not update the file contents'
        }
        Write-Host 'native-tools: inplace ok'

        $systemInput = Join-Path $runtime 'system-input.txt'
        $systemOutput = Join-Path $runtime 'system-output.txt'
        Set-Content -Encoding ascii -LiteralPath $systemInput -Value 'quoted'
        $systemInputArg = ([IO.Path]::GetFullPath($systemInput)).Replace('\', '\\')
        $systemOutputArg = ([IO.Path]::GetFullPath($systemOutput)).Replace('\', '\\')
        & $runtimeGawkPath -v "source=$systemInputArg" -v "target=$systemOutputArg" 'BEGIN { cmd = "cmd.exe /c type \"" source "\" > \"" target "\""; if (system(cmd) != 0) exit 17 }'
        if ($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath $systemOutput -Raw) -notmatch '^quoted\r?\n?$') {
            throw 'gawk system() quoting failed'
        }
        Write-Host 'native-tools: system ok'

        $utf8Input = Join-Path $runtime 'utf8-input.txt'
        $utf8Output = Join-Path $runtime 'utf8.out'
        $utf8Error = Join-Path $runtime 'utf8.err'
        $utf8Expect = Join-Path $runtime 'utf8.expect'
        $utf8Script = Join-Path $runtime 'utf8.awk'
        Set-Content -Encoding ascii -LiteralPath $utf8Script -Value '{ print $0 }'
        [IO.File]::WriteAllBytes($utf8Input, [byte[]](0x63,0x61,0x66,0xC3,0xA9,0x0A))
        [IO.File]::WriteAllBytes($utf8Expect, [byte[]](0x63,0x61,0x66,0xC3,0xA9))
        $env:LC_ALL = 'en_US.UTF-8'
        Remove-Item -LiteralPath $utf8Output, $utf8Error -ErrorAction SilentlyContinue
        $utf8Process = Start-Process -FilePath $runtimeGawkPath -ArgumentList @('-f', $utf8Script, $utf8Input) -NoNewWindow -PassThru -Wait -RedirectStandardOutput $utf8Output -RedirectStandardError $utf8Error
        $utf8ExpectedBytes = [IO.File]::ReadAllBytes($utf8Expect)
        $utf8ActualBytes = [IO.File]::ReadAllBytes($utf8Output) | Where-Object { $_ -ne 0x0D -and $_ -ne 0x0A }
        $utf8ActualBytes = [byte[]]$utf8ActualBytes
        if ($utf8Process.ExitCode -ne 0 -or $utf8ExpectedBytes.Length -ne $utf8ActualBytes.Length -or
            -not [System.Linq.Enumerable]::SequenceEqual($utf8ExpectedBytes, $utf8ActualBytes)) {
            if ((Test-Path -LiteralPath $utf8Error) -and ((Get-Item -LiteralPath $utf8Error).Length -gt 0)) {
                Get-Content -LiteralPath $utf8Error
            }
            throw 'gawk UTF-8 handling failed'
        }
        Write-Host 'native-tools: utf8 ok'

        & $runtimeGawkPath 'BEGIN { exit 17 }'
        if ($LASTEXITCODE -ne 17) {
            throw 'gawk exit codes are not preserved'
        }
        Write-Host 'native-tools: exit codes ok'

        $forkError = Join-Path $runtime 'fork.err'
        & $runtimeGawkPath -l fork 'BEGIN { print "fork" }' 2> $forkError
        if ($LASTEXITCODE -eq 0) {
            throw 'gawk unexpectedly loaded fork.dll'
        }
        if (-not (Select-String -Quiet -LiteralPath $forkError -Pattern 'fork')) {
            throw 'gawk did not report the missing fork extension'
        }
        Write-Host 'native-tools: fork check ok'
        $LASTEXITCODE = 0
    }
    finally {
        $env:AWKPATH = $oldAwkPath
        $env:AWKLIBPATH = $oldAwkLibPath
        $env:LC_ALL = $oldLcAll
    }
}
finally {
    Remove-Item -LiteralPath $runtime -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
