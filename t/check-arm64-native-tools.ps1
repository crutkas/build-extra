param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

$cases = @(
    @{ Name = "bunzip2"; RelativePath = "clangarm64\bin\bunzip2.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "bzcat"; RelativePath = "clangarm64\bin\bzcat.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "bzip2"; RelativePath = "clangarm64\bin\bzip2.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "bzip2recover"; RelativePath = "clangarm64\bin\bzip2recover.exe"; Arguments = @(); ExitCode = 1 },
    @{ Name = "nettle-hash"; RelativePath = "clangarm64\bin\nettle-hash.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "nettle-lfib-stream"; RelativePath = "clangarm64\bin\nettle-lfib-stream.exe"; Arguments = @("--help"); ExitCode = 1 },
    @{ Name = "nettle-pbkdf2"; RelativePath = "clangarm64\bin\nettle-pbkdf2.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "pkcs1-conv"; RelativePath = "clangarm64\bin\pkcs1-conv.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "sexp-conv"; RelativePath = "clangarm64\bin\sexp-conv.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "p11-kit"; RelativePath = "clangarm64\bin\p11-kit.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "trust"; RelativePath = "clangarm64\bin\trust.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "d2u"; RelativePath = "usr\bin\d2u.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "dos2unix"; RelativePath = "usr\bin\dos2unix.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "mac2unix"; RelativePath = "usr\bin\mac2unix.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "u2d"; RelativePath = "usr\bin\u2d.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "unix2dos"; RelativePath = "usr\bin\unix2dos.exe"; Arguments = @("--help"); ExitCode = 0 },
    @{ Name = "unix2mac"; RelativePath = "usr\bin\unix2mac.exe"; Arguments = @("--help"); ExitCode = 0 }
)

$ErrorActionPreference = 'Stop'

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Path is not a PE file"
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0x00 -or $bytes[$peOffset + 3] -ne 0x00) {
        throw "$Path has an invalid PE header"
    }

    [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

$hashes = @{}

foreach ($case in $cases) {
    $native = Join-Path $Root $case.RelativePath
    if (-not (Test-Path -LiteralPath $native)) {
        throw "The ARM64 payload does not contain $native"
    }

    $machine = Get-PeMachine -Path $native
    if ($machine -ne 0xAA64) {
        throw "$native has PE machine 0x$($machine.ToString('X4')), expected 0xAA64"
    }

    $hashes[$case.Name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $native).Hash.ToLowerInvariant()
    & $native @($case.Arguments) *> $null
    if ($LASTEXITCODE -ne $case.ExitCode) {
        throw "$native returned $LASTEXITCODE instead of $($case.ExitCode)"
    }
}

if ($hashes['d2u'] -ne $hashes['dos2unix']) {
    throw "d2u.exe is not byte-identical to dos2unix.exe"
}

if ($hashes['u2d'] -ne $hashes['unix2dos']) {
    throw "u2d.exe is not byte-identical to unix2dos.exe"
}

$workDir = Join-Path ([IO.Path]::GetTempPath()) "arm64-native-tools-$PID"
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
try {
    $textPath = Join-Path $workDir 'space file.txt'
    [IO.File]::WriteAllText($textPath, "line1`r`nline2`r`n")

    & (Join-Path $Root 'usr\bin\dos2unix.exe') $textPath *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "dos2unix.exe failed to normalize CRLF"
    }
    if ([IO.File]::ReadAllText($textPath) -ne "line1`nline2`n") {
        throw "dos2unix.exe did not convert CRLF to LF"
    }

    foreach ($option in '--allow-chown', '--no-allow-chown', '--follow-symlink') {
        & (Join-Path $Root 'usr\bin\dos2unix.exe') $option *> $null
        if ($LASTEXITCODE -eq 0) {
            throw "dos2unix.exe unexpectedly accepts $option"
        }
    }

    & (Join-Path $Root 'usr\bin\unix2dos.exe') $textPath *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "unix2dos.exe failed to restore CRLF"
    }
    if ([IO.File]::ReadAllText($textPath) -ne "line1`r`nline2`r`n") {
        throw "unix2dos.exe did not convert LF to CRLF"
    }
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
