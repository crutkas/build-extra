param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Scanner,

    [string]$SdkRoot,

    [string]$RuntimeRoot,

    [switch]$MinGit
)

$ErrorActionPreference = "Stop"
$packageName = "mingw-w64-clang-aarch64-win32-openssh-client"
$packageVersion = "10.0.0.0-2"
$expectedPackageHash = "26f302a73a58395de8d7741077365d2e0f296343358a5f62bc5385ec8c04d2f8"
$expectedConfigSourceHash = "f783f00ce880ead34b01d6db20f35f0e9141e199ffc32ca14cd330a3165853a4"
$expectedConfigHash = "8afa8d96895abae6a4770bde0916b985b28bef5979b016da5621d65f92e1c3de"
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-openssh-package-$PID"

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-RelativePath([string]$Base, [string]$Path) {
    return [IO.Path]::GetRelativePath($Base, $Path).Replace("\", "/")
}

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Assert-SetEqual([string[]]$Expected, [string[]]$Actual, [string]$Message) {
    $difference = Compare-Object @($Expected | Sort-Object -Unique) @($Actual | Sort-Object -Unique)
    if ($difference) {
        throw "$Message`: $($difference | Out-String)"
    }
}

function Test-PeFiles([string]$Root, [string[]]$RelativePaths) {
    $peList = Join-Path $trash "pe-files-$([guid]::NewGuid()).txt"
    $RelativePaths | Set-Content -Encoding ascii -LiteralPath $peList
    $rows = @(& $Scanner -ArchitectureOnly -Root $Root -FileList $peList)
    if ($LASTEXITCODE -ne 0 -or $rows.Count -ne $RelativePaths.Count) {
        throw "The scanner found $($rows.Count) PE files instead of $($RelativePaths.Count)"
    }
    return $rows
}

function Assert-NativeSshTrace([string[]]$Output, [string]$Ssh, [string]$Probe) {
    $normalizedSsh = $Ssh.Replace("\", "/")
    if (-not ($Output -match [regex]::Escape($Ssh)) -and
        -not ($Output -match [regex]::Escape($normalizedSsh))) {
        throw "$Probe did not invoke $Ssh`: $($Output -join ' | ')"
    }
}

function Invoke-FailingGitSshProbe(
    [string]$Git,
    [string]$Ssh,
    [string]$Probe,
    [string[]]$Arguments
) {
    $output = @(& $Git @Arguments 2>&1)
    if ($LASTEXITCODE -eq 0) {
        throw "$Probe unexpectedly succeeded"
    }
    Assert-NativeSshTrace $output $Ssh $Probe
}

function Test-OpenSshBehavior([string]$Root) {
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::Arm64) {
        return
    }

    $ssh = Join-Path $Root "usr\bin\ssh.exe"
    $scp = Join-Path $Root "usr\bin\scp.exe"
    $sftp = Join-Path $Root "usr\bin\sftp.exe"
    $sshAdd = Join-Path $Root "usr\bin\ssh-add.exe"
    $sshAgent = Join-Path $Root "usr\bin\ssh-agent.exe"
    $sshKeygen = Join-Path $Root "usr\bin\ssh-keygen.exe"
    $globalConfig = Join-Path $Root "etc\ssh\ssh_config"
    $git = Join-Path $Root "cmd\git.exe"
    if (-not (Test-Path -LiteralPath $git)) {
        $git = (Get-Command git.exe).Source
    }

    $version = @(& $ssh -V 2>&1)
    if ($LASTEXITCODE -ne 0 -or $version -notmatch "OpenSSH_for_Windows_10\.0") {
        throw "Unexpected ssh -V result: $version"
    }
    $packagedPolicy = @(& $ssh -G -T package-default 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        -not ($packagedPolicy -match "^pubkeyacceptedalgorithms .*ssh-rsa") -or
        ($packagedPolicy -match "ssh-dss")) {
        throw "The packaged global policy is not usable: $($packagedPolicy -join ' | ')"
    }

    $behaviorRoot = Join-Path $trash "behavior"
    New-Item -ItemType Directory -Force -Path $behaviorRoot | Out-Null
    $key = Join-Path $behaviorRoot "test-ed25519"
    & $sshKeygen -q -t ed25519 -N "" -f $key
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath "$key.pub")) {
        throw "ssh-keygen could not generate an Ed25519 key"
    }

    $profileHome = [Environment]::GetFolderPath("UserProfile")
    $userSshDirectory = Join-Path $profileHome ".ssh"
    $userConfig = Join-Path $userSshDirectory "config"
    $userConfigExisted = Test-Path -LiteralPath $userConfig
    if ($userConfigExisted) {
        $savedUserConfig = [IO.File]::ReadAllBytes($userConfig)
    }
    $savedGlobalConfig = [IO.File]::ReadAllBytes($globalConfig)
    New-Item -ItemType Directory -Force -Path $userSshDirectory | Out-Null

    $includeConfig = Join-Path $behaviorRoot "included.conf"
    $mainConfig = Join-Path $behaviorRoot "include-main.conf"
    $overrideConfig = Join-Path $behaviorRoot "override.conf"
    $malformedConfig = Join-Path $behaviorRoot "malformed.conf"
    $knownHosts = Join-Path $behaviorRoot "known_hosts"
    $remote = "ssh://git@127.0.0.1:1/repo"
    try {
        @"
Host *
    User global-policy
Host executable-relative
    Port 2222
"@ | Set-Content -Encoding ascii -LiteralPath $globalConfig
        @"
Host precedence
    User user-policy
"@ | Set-Content -Encoding ascii -LiteralPath $userConfig

        $effective = @(& $ssh -G -T executable-relative 2>&1)
        if ($LASTEXITCODE -ne 0 -or $effective -notcontains "port 2222") {
            throw "ssh.exe did not load ../../etc/ssh/ssh_config"
        }
        $effective = @(& $ssh -G -T precedence 2>&1)
        if ($LASTEXITCODE -ne 0 -or $effective -notcontains "user user-policy") {
            throw "The user configuration did not take precedence over the global configuration"
        }

        @"
Host precedence
    User command-file-policy
    Port 2200
"@ | Set-Content -Encoding ascii -LiteralPath $overrideConfig
        $effective = @(& $ssh -G -T -F $overrideConfig precedence 2>&1)
        if ($LASTEXITCODE -ne 0 -or
            $effective -notcontains "user command-file-policy" -or
            $effective -notcontains "port 2200") {
            throw "-F did not take precedence over user and global configuration"
        }

        @"
Host included-policy
    User include-policy
"@ | Set-Content -Encoding ascii -LiteralPath $includeConfig
        "Include `"$($includeConfig.Replace('\', '/'))`"" |
            Set-Content -Encoding ascii -LiteralPath $mainConfig
        $effective = @(& $ssh -G -T -F $mainConfig included-policy 2>&1)
        if ($LASTEXITCODE -ne 0 -or $effective -notcontains "user include-policy") {
            throw "Include did not load the referenced configuration"
        }

        "UnsupportedDirective value" |
            Set-Content -Encoding ascii -LiteralPath $malformedConfig
        $malformed = @(& $ssh -G -T -F $malformedConfig malformed 2>&1)
        if ($LASTEXITCODE -ne 255 -or -not ($malformed -match "Bad configuration option")) {
            throw "Malformed configuration was not rejected: $($malformed -join ' | ')"
        }

        $effective = @(& $ssh -G -F $overrideConfig `
            -o "UserKnownHostsFile=$knownHosts" `
            -o "ProxyCommand=cmd.exe /c exit 7" -tt precedence 2>&1)
        if ($LASTEXITCODE -ne 0 -or
            -not ($effective -match "^proxycommand cmd\.exe /c exit 7$") -or
            -not ($effective -match "^userknownhostsfile ") -or
            $effective -notcontains "requesttty force") {
            throw "known_hosts, ProxyCommand, or PTY option parsing failed: $($effective -join ' | ')"
        }

        $scpUsage = @(& $scp 2>&1)
        if ($LASTEXITCODE -eq 0 -or -not ($scpUsage -match "usage: scp")) {
            throw "scp did not report its usage normally"
        }
        $sftpUsage = @(& $sftp -h 2>&1)
        if ($LASTEXITCODE -eq 0 -or -not ($sftpUsage -match "usage: sftp")) {
            throw "sftp did not report its usage normally"
        }
        $agentUsage = @(& $sshAgent -? 2>&1)
        if (-not ($agentUsage -match "usage: ssh-agent|error :1058")) {
            throw "ssh-agent did not report its usage normally: $($agentUsage -join ' | ')"
        }
        $addResult = @(& $sshAdd -l 2>&1)
        if ($LASTEXITCODE -eq 0 -or
            -not ($addResult -match "agent|pipe|communication|connect")) {
            throw "ssh-add did not probe the native agent endpoint normally"
        }

        $oldTrace = $env:GIT_TRACE
        $oldGitSsh = $env:GIT_SSH
        $oldGitSshCommand = $env:GIT_SSH_COMMAND
        try {
            $env:GIT_TRACE = "1"
            $env:GIT_SSH = $ssh
            $env:GIT_SSH_COMMAND = $null
            Invoke-FailingGitSshProbe $git $ssh "GIT_SSH clone" @(
                "clone", $remote, (Join-Path $behaviorRoot "clone")
            )

            $env:GIT_SSH = $null
            $sshForShell = $ssh.Replace("\", "/")
            $configForShell = $overrideConfig.Replace("\", "/")
            $env:GIT_SSH_COMMAND = "'$sshForShell' -F '$configForShell'"

            $repository = Join-Path $behaviorRoot "repository"
            & $git init $repository *> $null
            & $git -C $repository config user.name "ARM64 OpenSSH test"
            & $git -C $repository config user.email "arm64-openssh@example.invalid"
            "test" | Set-Content -Encoding ascii -LiteralPath (Join-Path $repository "file")
            & $git -C $repository add file
            & $git -C $repository commit -m "test" *> $null
            & $git -C $repository remote add origin $remote

            Invoke-FailingGitSshProbe $git $ssh "GIT_SSH_COMMAND fetch" @(
                "-C", $repository, "fetch", "origin"
            )
            Invoke-FailingGitSshProbe $git $ssh "GIT_SSH_COMMAND push" @(
                "-C", $repository, "push", "origin", "HEAD:main"
            )
            Invoke-FailingGitSshProbe $git $ssh "submodule clone" @(
                "-C", $repository, "submodule", "add", $remote, "dependency"
            )
        } finally {
            $env:GIT_TRACE = $oldTrace
            $env:GIT_SSH = $oldGitSsh
            $env:GIT_SSH_COMMAND = $oldGitSshCommand
        }

    } finally {
        [IO.File]::WriteAllBytes($globalConfig, $savedGlobalConfig)
        if ($userConfigExisted) {
            [IO.File]::WriteAllBytes($userConfig, $savedUserConfig)
        } else {
            Remove-Item -Force -LiteralPath $userConfig -ErrorAction SilentlyContinue
        }
    }
    $azure = @(& $ssh -G -T ssh.dev.azure.com 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "The native client rejected the Azure SSH policy: $($azure -join ' | ')"
    }
}

try {
    $actualPackageHash = Get-Sha256 $Package
    Assert-Equal $expectedPackageHash $actualPackageHash "Unexpected package SHA-256"

    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    $archiveFiles = @(& $tar -tf $Package) | ForEach-Object { $_ -replace "^\./", "" }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list $Package"
    }
    $payloadFiles = @($archiveFiles |
        Where-Object { $_ -and -not $_.EndsWith("/") -and $_ -notmatch "^\.(BUILDINFO|MTREE|PKGINFO)$" } |
        Sort-Object -Unique)
    Assert-Equal 27 $payloadFiles.Count "Unexpected package payload file count"

    New-Item -ItemType Directory -Path $trash | Out-Null
    & $tar -xf $Package -C $trash
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract $Package"
    }

    $pkgInfo = Get-Content -LiteralPath (Join-Path $trash ".PKGINFO")
    foreach ($line in @(
        "pkgname = $packageName",
        "pkgver = $packageVersion",
        "conflict = openssh",
        "backup = etc/ssh/ssh_config"
    )) {
        if ($pkgInfo -notcontains $line) {
            throw "Missing package metadata: $line"
        }
    }
    if ($pkgInfo -match "^(provides|replaces) = openssh$") {
        throw "The native package must not provide or replace MSYS openssh"
    }

    $checksumRelative = "usr/share/doc/win32-openssh-client/package-files.sha256"
    $checksumFile = Join-Path $trash ($checksumRelative.Replace("/", "\"))
    $hashedFiles = @()
    foreach ($line in Get-Content -LiteralPath $checksumFile) {
        if ($line -notmatch "^([0-9a-f]{64}) \*\./(.+)$") {
            throw "Malformed package checksum line: $line"
        }
        $relative = $Matches[2]
        $hashedFiles += $relative
        $path = Join-Path $trash ($relative.Replace("/", "\"))
        Assert-Equal $Matches[1] (Get-Sha256 $path) "Checksum mismatch for $relative"
    }
    Assert-SetEqual @($payloadFiles | Where-Object { $_ -ne $checksumRelative }) `
        $hashedFiles "Package checksum coverage differs from the payload"

    $configBefore = Join-Path $trash "usr\share\doc\win32-openssh-client\ssh_config.before"
    $configAfter = Join-Path $trash "usr\share\doc\win32-openssh-client\ssh_config.after"
    $packageConfig = Join-Path $trash "etc\ssh\ssh_config"
    Assert-Equal $expectedConfigSourceHash (Get-Sha256 $configBefore) `
        "Unexpected source ssh_config SHA-256"
    Assert-Equal $expectedConfigHash (Get-Sha256 $configAfter) `
        "Unexpected transformed ssh_config SHA-256"
    Assert-Equal $expectedConfigHash (Get-Sha256 $packageConfig) `
        "Unexpected packaged ssh_config SHA-256"
    Assert-SetEqual @(
        "PubkeyAcceptedKeyTypes ssh-ed25519*,ssh-rsa*,ssh-dss*,ecdsa-sha2*"
    ) @((Compare-Object (Get-Content $configAfter) (Get-Content $configBefore) |
        Where-Object SideIndicator -eq "=>" | ForEach-Object InputObject)) `
        "Unexpected source-only ssh_config lines"
    Assert-SetEqual @(
        "PubkeyAcceptedKeyTypes ssh-ed25519*,ssh-rsa*,ecdsa-sha2*"
    ) @((Compare-Object (Get-Content $configAfter) (Get-Content $configBefore) |
        Where-Object SideIndicator -eq "<=" | ForEach-Object InputObject)) `
        "Unexpected transformed-only ssh_config lines"

    $sourcePins = Get-Content -Raw -LiteralPath (
        Join-Path $trash "usr\share\doc\win32-openssh-client\source-pins.json"
    ) | ConvertFrom-Json
    Assert-Equal "../../etc/ssh/ssh_config" $sourcePins.globalConfig.relativeToExecutable `
        "Unexpected executable-relative global configuration path"
    Assert-Equal $expectedConfigSourceHash $sourcePins.globalConfig.sourceSha256 `
        "Unexpected source config provenance"
    Assert-Equal $expectedConfigHash $sourcePins.globalConfig.outputSha256 `
        "Unexpected output config provenance"

    $peFiles = @($payloadFiles | Where-Object { $_ -match "\.(exe|dll)$" })
    Assert-Equal 14 $peFiles.Count "Unexpected package PE count"
    $architectures = @(Test-PeFiles $trash $peFiles)
    foreach ($row in $architectures) {
        $columns = $row -split "`t"
        if ($columns.Count -ne 3 -or $columns[1] -ne "arm64" -or $columns[2] -ne "0xAA64") {
            throw "Unexpected PE architecture row: $row"
        }
    }

    $requiredLayout = @(
        "etc/ssh/ssh_config",
        "usr/bin/libcrypto.dll",
        "usr/bin/ssh.exe",
        "usr/bin/ssh-pkcs11-helper.exe",
        "usr/bin/ssh-sk-helper.exe",
        "usr/lib/ssh/libcrypto.dll",
        "usr/lib/ssh/sftp-server.exe",
        "usr/lib/ssh/ssh-pkcs11-helper.exe",
        "usr/lib/ssh/ssh-sk-helper.exe"
    )
    if ($MinGit.IsPresent) {
        $runtimeLayout = @($requiredLayout | Where-Object {
            $_ -ne "usr/lib/ssh/sftp-server.exe"
        })
    } else {
        $runtimeLayout = $requiredLayout
    }
    foreach ($relative in $requiredLayout) {
        if ($payloadFiles -notcontains $relative) {
            throw "Required package path is missing: $relative"
        }
    }
    if ($payloadFiles -match "(^|/)(sshd|ssh-shellhost)(\.exe)?$|sshd_config|moduli|service") {
        throw "The package contains a server component"
    }
    if ($payloadFiles -match "ssh-pageant|ssh-keysign") {
        throw "ssh-pageant or ssh-keysign leaked into the native package"
    }

    $nativeText = [Text.Encoding]::ASCII.GetString(
        [IO.File]::ReadAllBytes((Join-Path $trash "usr\bin\ssh.exe")))
    if (-not $nativeText.Contains("../../etc/ssh/ssh_config")) {
        throw "ssh.exe does not use the executable-relative global configuration"
    }

    $systemDlls = @(
        "ADVAPI32.dll", "bcrypt.dll", "CRYPT32.dll", "HID.DLL", "KERNEL32.dll",
        "ntdll.dll", "Secur32.dll", "SETUPAPI.dll", "SHLWAPI.dll", "USER32.dll",
        "USERENV.dll", "WS2_32.dll"
    )
    foreach ($relative in $peFiles) {
        $path = Join-Path $trash ($relative.Replace("/", "\"))
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

    if ($SdkRoot) {
        $SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
        $pacman = Join-Path $SdkRoot "usr\bin\pacman.exe"
        $installed = @(& $pacman --root $SdkRoot -Q $packageName 2>$null)
        if ($LASTEXITCODE -ne 0 -or $installed -ne "$packageName $packageVersion") {
            throw "The SDK does not own the expected native package: $installed"
        }
        $msysOpenSsh = @(Get-ChildItem -LiteralPath (
            Join-Path $SdkRoot "var\lib\pacman\local"
        ) -Directory -Filter "openssh-[0-9]*")
        if ($msysOpenSsh.Count -ne 0) {
            throw "The SDK still owns MSYS openssh"
        }
        $qkk = @(& $pacman --root $SdkRoot -Qkk $packageName 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "pacman -Qkk failed: $($qkk -join ' | ')"
        }
        $installedDesc = Join-Path $SdkRoot (
            "var\lib\pacman\local\$packageName-$packageVersion\desc"
        )
        $descLines = Get-Content -LiteralPath $installedDesc
        $providesIndex = [Array]::IndexOf($descLines, "%PROVIDES%")
        if ($providesIndex -lt 0 -or
            $providesIndex + 1 -ge $descLines.Count -or
            $descLines[$providesIndex + 1] -ne "openssh") {
            throw "The installed native package does not satisfy the OpenSSH dependency"
        }
        $ownedFiles = @(& $pacman --root $SdkRoot -Ql $packageName |
            ForEach-Object {
                if ($_ -match "^[^ ]+ /(.+[^/])$") {
                    $Matches[1]
                }
            })
        Assert-SetEqual $payloadFiles $ownedFiles "Pacman ownership differs from the package payload"
        $packageVersions = Join-Path $SdkRoot "etc\package-versions.txt"
        if ((Test-Path -LiteralPath $packageVersions) -and
            -not (Select-String -Quiet -SimpleMatch "$packageName $packageVersion" $packageVersions)) {
            throw "package-versions.txt does not record the native OpenSSH package"
        }
        foreach ($relative in $payloadFiles) {
            $installedPath = Join-Path $SdkRoot ($relative.Replace("/", "\"))
            if (-not (Test-Path -LiteralPath $installedPath)) {
                throw "Pacman-owned SDK path is missing: $relative"
            }
        }
        foreach ($relative in @(
            "etc\ssh\moduli",
            "etc\ssh\sshd_config",
            "usr\bin\ssh-copy-id",
            "usr\lib\ssh\ssh-keysign.exe",
            "usr\share\licenses\openssh\LICENCE"
        )) {
            if (Test-Path -LiteralPath (Join-Path $SdkRoot $relative)) {
                throw "Legacy OpenSSH path remains in the SDK: $relative"
            }
        }
        $pageantFiles = @(& $pacman --root $SdkRoot -Ql ssh-pageant 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not ($pageantFiles -match "/usr/bin/ssh-pageant\.exe$")) {
            throw "ssh-pageant is no longer owned separately"
        }
    }

    if ($RuntimeRoot) {
        $RuntimeRoot = (Resolve-Path -LiteralPath $RuntimeRoot).Path
        foreach ($relative in $runtimeLayout) {
            if (-not (Test-Path -LiteralPath (
                Join-Path $RuntimeRoot ($relative.Replace("/", "\"))))) {
                throw "Runtime path is missing: $relative"
            }
        }
        if (Test-Path -LiteralPath (Join-Path $RuntimeRoot "usr\lib\ssh\ssh-keysign.exe")) {
            throw "ssh-keysign is present in the runtime artifact"
        }
        if (-not $MinGit.IsPresent -and
            -not (Test-Path -LiteralPath (Join-Path $RuntimeRoot "usr\bin\ssh-pageant.exe"))) {
            throw "ssh-pageant is not present as a separate runtime component"
        }
        $runtimeConfigPath = Join-Path $RuntimeRoot "etc\ssh\ssh_config"
        $azurePolicy = @(
            "# Added by git-extra",
            "Host ssh.dev.azure.com",
            "`tHostkeyAlgorithms +ssh-rsa",
            "`tPubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256,ssh-rsa",
            "Host *.visualstudio.com",
            "`tHostkeyAlgorithms +ssh-rsa",
            "`tPubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256,ssh-rsa",
            "Host *",
            ""
        )
        $runtimeConfig = @(Get-Content -LiteralPath $runtimeConfigPath)
        $packagedConfig = @(Get-Content -LiteralPath $packageConfig)
        $expectedRuntimeConfig = @($azurePolicy) + @($packagedConfig)
        if (Compare-Object $expectedRuntimeConfig $runtimeConfig -SyncWindow 0) {
            throw "Runtime ssh_config differs from the package plus Azure policy"
        }
        $runtimePackageVersions = Join-Path $RuntimeRoot "etc\package-versions.txt"
        if (-not (Test-Path -LiteralPath $runtimePackageVersions) -or
            -not (Select-String -Quiet -SimpleMatch "$packageName $packageVersion" `
                $runtimePackageVersions) -or
            (Select-String -Quiet -Pattern "^openssh " $runtimePackageVersions)) {
            throw "Runtime package versions do not select only the native OpenSSH package"
        }

        $runtimePeFiles = @(Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -File |
            Where-Object { $_.Extension -in ".exe", ".dll" } |
            ForEach-Object { Get-RelativePath $RuntimeRoot $_.FullName })
        $runtimeArchitectures = @(Test-PeFiles $RuntimeRoot $runtimePeFiles)
        $counts = @{}
        foreach ($row in $runtimeArchitectures) {
            $architecture = ($row -split "`t")[1]
            $counts[$architecture] = 1 + [int]($counts[$architecture])
        }
        Write-Host "Runtime PE counts: $(
            @($counts.Keys | Sort-Object | ForEach-Object { "$_=$($counts[$_])" }) -join ', '
        )"
        $runtimeFiles = @(Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -File)
        $runtimeBytes = ($runtimeFiles | Measure-Object -Property Length -Sum).Sum
        Write-Host "Runtime files: $($runtimeFiles.Count); installed bytes: $runtimeBytes"
        if ($MinGit.IsPresent) {
            $minGitSsh = Join-Path $RuntimeRoot "cmd\ssh.cmd"
            if (-not (Test-Path -LiteralPath $minGitSsh)) {
                throw "MinGit does not contain the ARM64 OpenSSH launcher"
            }
            $minGitPolicy = @(& $env:ComSpec /d /s /c `
                "`"$minGitSsh`" -G -T package-default" 2>&1)
            if ($LASTEXITCODE -ne 0 -or
                -not ($minGitPolicy -match "^pubkeyacceptedalgorithms .*ssh-rsa") -or
                ($minGitPolicy -match "ssh-dss")) {
                throw "MinGit did not load the packaged global policy: $($minGitPolicy -join ' | ')"
            }
        } else {
            Test-OpenSshBehavior $RuntimeRoot
        }
    } else {
        Test-OpenSshBehavior $trash
    }

    $payloadBytes = ($payloadFiles | ForEach-Object {
        (Get-Item -LiteralPath (Join-Path $trash ($_.Replace("/", "\")))).Length
    } | Measure-Object -Sum).Sum
    Write-Host "Package provenance: crutkas/MINGW-packages c97decf4acf026790b0989e0f08be8142b9f7ec2"
    Write-Host "Package archive bytes: $((Get-Item -LiteralPath $Package).Length)"
    Write-Host "Package payload bytes: $payloadBytes"
    Write-Host "Package files: $($payloadFiles.Count); PE files: $($peFiles.Count) arm64"
    Write-Host "ARM64 OpenSSH package checks passed"
} finally {
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
