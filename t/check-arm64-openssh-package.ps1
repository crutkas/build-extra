param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Scanner
)

$ErrorActionPreference = "Stop"
$expectedPackageHash = "48e679a7e5a10ee5ba43c79a8cabc535ce7daddf693c7800caa39c2cd762a6a2"
$repoRoot = Split-Path -Parent $PSScriptRoot
$expectedFiles = Get-Content -LiteralPath (Join-Path $repoRoot "arm64-openssh-client-files.txt")
$expectedMsysFiles = Get-Content -LiteralPath (Join-Path $repoRoot "arm64-openssh-msys-files.txt")
$baselineRows = @(Get-Content -LiteralPath (Join-Path $repoRoot "arm64-openssh-msys-payload.tsv") |
    Where-Object { $_ -and -not $_.StartsWith("#") } |
    ForEach-Object {
        $columns = $_ -split "`t"
        [pscustomobject]@{
            Path = $columns[0]
            Size = [long]$columns[1]
            Sha256 = $columns[2]
        }
    })
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-openssh-package-$PID"

try {
    $actualPackageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package).Hash.ToLowerInvariant()
    if ($actualPackageHash -ne $expectedPackageHash) {
        throw "Unexpected package SHA-256: $actualPackageHash"
    }

    $archiveFiles = @(& tar -tf $Package) | ForEach-Object { $_ -replace "^\./", "" }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list $Package"
    }
    $payloadFiles = @($archiveFiles |
        Where-Object { $_ -and -not $_.EndsWith("/") -and $_ -notmatch "^\.(BUILDINFO|MTREE|PKGINFO)$" } |
        Sort-Object -Unique)
    if (Compare-Object $expectedFiles $payloadFiles) {
        throw "Package paths do not match arm64-openssh-client-files.txt"
    }

    New-Item -ItemType Directory -Path $trash | Out-Null
    & tar -xf $Package -C $trash
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract $Package"
    }

    $pkgInfo = Get-Content -LiteralPath (Join-Path $trash ".PKGINFO")
    foreach ($line in @(
        "pkgname = mingw-w64-clang-aarch64-win32-openssh-client",
        "pkgver = 10.0.0.0-1",
        "conflict = openssh"
    )) {
        if ($pkgInfo -notcontains $line) {
            throw "Missing package metadata: $line"
        }
    }
    if ($pkgInfo -match "^(provides|replaces) = openssh$") {
        throw "The native package must not provide or replace MSYS openssh"
    }

    $checksumFile = Join-Path $trash "usr\share\doc\win32-openssh-client\package-files.sha256"
    foreach ($line in Get-Content -LiteralPath $checksumFile) {
        if ($line -notmatch "^([0-9a-f]{64}) \*\./(.+)$") {
            throw "Malformed package checksum line: $line"
        }
        $path = Join-Path $trash ($Matches[2] -replace "/", "\")
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $Matches[1]) {
            throw "Checksum mismatch for $($Matches[2])"
        }
    }

    $peFiles = @($expectedFiles | Where-Object { $_ -match "\.(exe|dll)$" })
    if ($peFiles.Count -ne 14) {
        throw "Expected 14 native PE files, found $($peFiles.Count)"
    }
    $peList = Join-Path $trash "pe-files.txt"
    $peFiles | Set-Content -Encoding ascii -LiteralPath $peList
    $architectures = @(& $Scanner -ArchitectureOnly -Root $trash -FileList $peList)
    if ($architectures.Count -ne 14) {
        throw "The scanner found $($architectures.Count) PE files instead of 14"
    }
    foreach ($row in $architectures) {
        $columns = $row -split "`t"
        if ($columns.Count -ne 3 -or $columns[1] -ne "arm64" -or $columns[2] -ne "0xAA64") {
            throw "Unexpected PE architecture row: $row"
        }
    }

    $systemDlls = @(
        "ADVAPI32.dll", "bcrypt.dll", "CRYPT32.dll", "HID.DLL", "KERNEL32.dll",
        "ntdll.dll", "Secur32.dll", "SETUPAPI.dll", "SHLWAPI.dll", "USER32.dll",
        "USERENV.dll", "WS2_32.dll"
    )
    foreach ($relative in $peFiles) {
        $path = Join-Path $trash ($relative -replace "/", "\")
        $imports = @(& $Scanner $path | Select-String "DLL Name:" |
            ForEach-Object { ($_ -split "DLL Name:", 2)[1].Trim() })
        foreach ($import in $imports) {
            if ($import -ieq "libcrypto.dll") {
                $localCrypto = Join-Path (Split-Path -Parent $path) "libcrypto.dll"
                if (-not (Test-Path -LiteralPath $localCrypto)) {
                    throw "$relative cannot find its colocated libcrypto.dll"
                }
            } elseif ($systemDlls -inotcontains $import) {
                throw "$relative has an unresolved non-system import: $import"
            }
        }
    }

    if ($expectedFiles -match "(^|/)(sshd|ssh-shellhost)(\.exe)?$|sshd_config|moduli|service") {
        throw "The package contains a server component"
    }
    if ($expectedFiles -match "ssh-pageant") {
        throw "ssh-pageant must remain outside this package"
    }

    $nativeText = [Text.Encoding]::ASCII.GetString(
        [IO.File]::ReadAllBytes((Join-Path $trash "usr\bin\ssh.exe")))
    if (-not $nativeText.Contains("__PROGRAMDATA__\ssh/ssh_config")) {
        throw "The expected Win32 global configuration search path changed"
    }

    $replacementCount = @($expectedMsysFiles | Where-Object { $expectedFiles -contains $_ }).Count
    $removed = @($expectedMsysFiles | Where-Object { $expectedFiles -notcontains $_ })
    if ($replacementCount -ne 10 -or $removed.Count -ne 1 -or
        $removed[0] -ne "usr/lib/ssh/ssh-keysign.exe") {
        throw "Unexpected baseline path disposition"
    }

    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq
        [Runtime.InteropServices.Architecture]::Arm64) {
        $ssh = Join-Path $trash "usr\bin\ssh.exe"
        $sshKeygen = Join-Path $trash "usr\bin\ssh-keygen.exe"
        $version = & $ssh -V 2>&1
        if ($LASTEXITCODE -ne 0 -or $version -notmatch "OpenSSH_for_Windows_10\.0") {
            throw "Unexpected ssh -V result: $version"
        }

        $key = Join-Path $trash "test-ed25519"
        & $sshKeygen -q -t ed25519 -N "" -f $key
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath "$key.pub")) {
            throw "ssh-keygen could not generate an Ed25519 key"
        }

        $testHome = Join-Path $trash "home"
        New-Item -ItemType Directory -Path (Join-Path $testHome ".ssh") | Out-Null
        @"
Host package-alias
    HostName 127.0.0.1
    Port 1
    User integration
"@ | Set-Content -Encoding ascii -LiteralPath (Join-Path $testHome ".ssh\config")
        $oldHome = $env:HOME
        $oldUserProfile = $env:USERPROFILE
        $env:HOME = $testHome
        $env:USERPROFILE = $testHome
        try {
            $effective = @(& $ssh -G package-alias 2>$null)
            if ($LASTEXITCODE -ne 0 -or
                $effective -notcontains "hostname 127.0.0.1" -or
                $effective -notcontains "user integration" -or
                $effective -notcontains "port 1") {
                throw "The native client did not load the user configuration"
            }

            $config = Join-Path $trash "etc\ssh\ssh_config"
            $knownHosts = Join-Path $testHome ".ssh\known_hosts"
            $effective = @(& $ssh -G -F $config -o "UserKnownHostsFile=$knownHosts" `
                -o "ProxyCommand=cmd.exe /c exit 7" -tt package-alias 2>$null)
            if ($LASTEXITCODE -ne 0 -or
                -not ($effective -match "^proxycommand cmd\.exe /c exit 7$") -or
                -not ($effective -match "^userknownhostsfile ")) {
                throw "Config, known_hosts, ProxyCommand, or PTY option parsing failed"
            }
        } finally {
            $env:HOME = $oldHome
            $env:USERPROFILE = $oldUserProfile
        }

        $oldTrace = $env:GIT_TRACE
        $oldGitSsh = $env:GIT_SSH
        $oldGitSshCommand = $env:GIT_SSH_COMMAND
        try {
            $env:GIT_TRACE = "1"
            $env:GIT_SSH = $ssh
            $env:GIT_SSH_COMMAND = $null
            $trace = @(& git ls-remote "ssh://git@127.0.0.1:1/repo" 2>&1)
            if ($LASTEXITCODE -eq 0 -or -not ($trace -match [regex]::Escape($ssh))) {
                throw "GIT_SSH did not select the packaged native client"
            }

            $env:GIT_SSH = $null
            $sshForShell = $ssh -replace "\\", "/"
            $configForShell = $config -replace "\\", "/"
            $env:GIT_SSH_COMMAND = "'$sshForShell' -F '$configForShell'"
            $trace = @(& git ls-remote "ssh://git@127.0.0.1:1/repo" 2>&1)
            if ($LASTEXITCODE -eq 0 -or -not ($trace -match [regex]::Escape($sshForShell))) {
                throw "GIT_SSH_COMMAND did not select the packaged native client"
            }
        } finally {
            $env:GIT_TRACE = $oldTrace
            $env:GIT_SSH = $oldGitSsh
            $env:GIT_SSH_COMMAND = $oldGitSshCommand
        }
    }

    $installedSize = ($expectedFiles | ForEach-Object {
        (Get-Item -LiteralPath (Join-Path $trash ($_ -replace "/", "\"))).Length
    } | Measure-Object -Sum).Sum
    $selectedFiles = @($expectedFiles | Where-Object { $_ -notlike "usr/share/doc/*" })
    $selectedSize = ($selectedFiles | ForEach-Object {
        (Get-Item -LiteralPath (Join-Path $trash ($_ -replace "/", "\"))).Length
    } | Measure-Object -Sum).Sum
    $baselineSize = ($baselineRows | Measure-Object -Property Size -Sum).Sum
    $common = @($baselineRows.Path | Where-Object { $selectedFiles -contains $_ })
    $removed = @($baselineRows.Path | Where-Object { $selectedFiles -notcontains $_ })
    $added = @($selectedFiles | Where-Object { $baselineRows.Path -notcontains $_ })
    if ($baselineRows.Count -ne 16 -or $selectedFiles.Count -ne 17 -or
        $common.Count -ne 11 -or $removed.Count -ne 5 -or $added.Count -ne 6) {
        throw "Unexpected full artifact path delta"
    }

    $minGitExcluded = @(
        "usr/bin/scp.exe", "usr/bin/sftp.exe", "usr/bin/ssh-copy-id",
        "usr/bin/ssh-keygen.exe", "usr/bin/ssh-keyscan.exe",
        "usr/lib/ssh/sftp-server.exe"
    )
    $minGitBaseline = @($baselineRows | Where-Object { $minGitExcluded -notcontains $_.Path })
    $minGitNative = @($selectedFiles | Where-Object { $minGitExcluded -notcontains $_ })
    $minGitBaselineSize = ($minGitBaseline | Measure-Object -Property Size -Sum).Sum
    $minGitNativeSize = ($minGitNative | ForEach-Object {
        (Get-Item -LiteralPath (Join-Path $trash ($_ -replace "/", "\"))).Length
    } | Measure-Object -Sum).Sum

    Write-Host "Package archive bytes: $((Get-Item -LiteralPath $Package).Length)"
    Write-Host "Package payload bytes: $installedSize"
    Write-Host "Full artifact OpenSSH bytes: $baselineSize -> $selectedSize ($($selectedSize - $baselineSize))"
    Write-Host "MinGit OpenSSH bytes: $minGitBaselineSize -> $minGitNativeSize ($($minGitNativeSize - $minGitBaselineSize))"
    Write-Host "Full artifact paths: 11 replaced, 5 removed, 6 added"
    Write-Host "PE architecture delta: x64 -11, arm64 +14"
    Write-Host "Projected v2.55.0.4 counts: anycpu 90, arm64 223, x64 421, x86 1"
    Write-Host "ARM64 OpenSSH package checks passed"
} finally {
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
