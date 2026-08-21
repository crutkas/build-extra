param(
    [string]$Root
)

$rootPath = $null
$oldPath = $env:PATH
$ErrorActionPreference = 'Stop'
if ($Root) {
    $rootPath = (Resolve-Path -LiteralPath $Root).Path
    $env:PATH = "$rootPath\clangarm64\bin;$rootPath\usr\bin;$env:PATH"
}

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
    $native = Join-Path $Root "clangarm64\bin\$($case.Name).exe"
    if (-not (Test-Path -LiteralPath $native)) {
        throw "The ARM64 payload does not contain $native"
    }

    & $native @($case.Arguments) *> $null
    if ($LASTEXITCODE -ne $case.ExitCode) {
        throw "$native returned $LASTEXITCODE instead of $($case.ExitCode)"
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
    if ($awkPath -notlike '*\clangarm64\bin\awk.exe') {
        throw "awk resolves to $awkPath instead of clangarm64\bin\awk.exe"
    }
}
if ($gawkPath -notlike '*\clangarm64\bin\gawk.exe') {
    throw "gawk resolves to $gawkPath instead of clangarm64\bin\gawk.exe"
}
$gawkBin = Split-Path -LiteralPath $gawkPath
$gawkVersioned = Join-Path $gawkBin 'gawk-5.4.1.exe'
if (-not (Test-Path -LiteralPath $gawkVersioned)) {
    throw "The ARM64 file list does not contain $gawkVersioned"
}
$gawkMpfr = Join-Path $gawkBin 'libmpfr-6.dll'
if (-not (Test-Path -LiteralPath $gawkMpfr)) {
    throw "The ARM64 payload does not contain clangarm64\bin\libmpfr-6.dll"
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
        $fieldError = Join-Path $runtime 'field.err'
        $fieldOutput = "alpha beta" | & $gawkPath '{ print $1 " " $2 }' 2> $fieldError
        if ($LASTEXITCODE -ne 0 -or $fieldOutput -ne 'alpha beta') {
            Write-Host "gawk field output: <$fieldOutput>"
            if ((Test-Path -LiteralPath $fieldError) -and ((Get-Item -LiteralPath $fieldError).Length -gt 0)) {
                Get-Content -LiteralPath $fieldError
            }
            throw 'gawk field processing failed'
        }

        $scriptDir = Join-Path $runtime 'scripts'
        New-Item -ItemType Directory -Force -Path $scriptDir | Out-Null
        Set-Content -Encoding ascii -LiteralPath (Join-Path $scriptDir 'from-awkpath.awk') -Value 'BEGIN { print "awkpath-ok" }'
        $env:AWKPATH = "$([IO.Path]::GetFullPath($scriptDir));$oldAwkPath"
        $awkPathOutput = & $gawkPath -f from-awkpath.awk /dev/null
        if ($LASTEXITCODE -ne 0 -or $awkPathOutput -ne 'awkpath-ok') {
            throw 'AWKPATH did not honor a native Windows path list'
        }

        $extDir = Join-Path $runtime 'ext'
        New-Item -ItemType Directory -Force -Path $extDir | Out-Null
        Copy-Item -Path (Join-Path $gawkLib '*.dll') -Destination $extDir -Force
        $env:AWKLIBPATH = "$([IO.Path]::GetFullPath($extDir));$oldAwkLibPath"
        $inplaceInput = Join-Path $runtime 'inplace-input.txt'
        Set-Content -Encoding ascii -LiteralPath $inplaceInput -Value "in place"
        & $gawkPath -i inplace '{ print toupper($0) }' $inplaceInput
        if ($LASTEXITCODE -ne 0) {
            throw 'AWKLIBPATH or inplace extension loading failed'
        }
        if ((Get-Content -LiteralPath $inplaceInput -Raw) -ne "IN PLACE`r`n" -and
            (Get-Content -LiteralPath $inplaceInput -Raw) -ne "IN PLACE`n") {
            throw 'inplace editing did not update the file contents'
        }

        $systemInput = Join-Path $runtime 'system-input.txt'
        $systemOutput = Join-Path $runtime 'system-output.txt'
        Set-Content -Encoding ascii -LiteralPath $systemInput -Value 'quoted'
        & $gawkPath -v "source=$([IO.Path]::GetFullPath($systemInput))" -v "target=$([IO.Path]::GetFullPath($systemOutput))" 'BEGIN { cmd = "cmd.exe /c type \"" source "\" > \"" target "\""; if (system(cmd) != 0) exit 17 }'
        if ($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath $systemOutput -Raw) -notmatch '^quoted\r?\n?$') {
            throw 'gawk system() quoting failed'
        }

        $utf8Input = Join-Path $runtime 'utf8-input.txt'
        [IO.File]::WriteAllBytes($utf8Input, [byte[]](0x63,0x61,0x66,0xC3,0xA9,0x0A))
        $env:LC_ALL = 'C.UTF-8'
        $utf8Output = & $gawkPath '{ print length($0) }' $utf8Input
        if ($LASTEXITCODE -ne 0 -or $utf8Output -ne '4') {
            throw 'gawk UTF-8 handling failed'
        }

        & $gawkPath 'BEGIN { exit 17 }'
        if ($LASTEXITCODE -ne 17) {
            throw 'gawk exit codes are not preserved'
        }

        $forkError = Join-Path $runtime 'fork.err'
        & $gawkPath -l fork 'BEGIN { print "fork" }' 2> $forkError
        if ($LASTEXITCODE -eq 0) {
            throw 'gawk unexpectedly loaded fork.dll'
        }
        if (-not (Select-String -Quiet -LiteralPath $forkError -Pattern 'fork')) {
            throw 'gawk did not report the missing fork extension'
        }
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
