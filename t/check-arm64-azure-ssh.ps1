param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-azure-ssh-$PID"

function Assert-Match([string]$Text, [string]$Pattern, [string]$Message) {
    if ($Text -notmatch $Pattern) {
        throw "$Message`: $Text"
    }
}

function Get-EffectiveOption([string[]]$Lines, [string]$Name) {
    $prefix = "$Name "
    $line = @($Lines | Where-Object {
        $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($line.Count -ne 1) {
        throw "The effective SSH configuration has $($line.Count) '$Name' entries"
    }
    return $line[0].Substring($prefix.Length)
}

try {
    $Root = (Resolve-Path -LiteralPath $Root).Path
    $ssh = Join-Path $Root "usr\bin\ssh.exe"
    $sshKeygen = Join-Path $Root "usr\bin\ssh-keygen.exe"
    $git = Join-Path $Root "cmd\git.exe"
    $globalConfig = Join-Path $Root "etc\ssh\ssh_config"
    foreach ($path in @($ssh, $sshKeygen, $git, $globalConfig)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Azure SSH check is missing $path"
        }
    }
    $isArm64 = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq `
        [Runtime.InteropServices.Architecture]::Arm64

    New-Item -ItemType Directory -Path $trash | Out-Null
    $profileHome = [Environment]::GetFolderPath("UserProfile")
    $userConfig = Join-Path $profileHome ".ssh\config"
    $userConfigExisted = Test-Path -LiteralPath $userConfig
    if ($userConfigExisted) {
        $savedUserConfig = [IO.File]::ReadAllBytes($userConfig)
        Remove-Item -Force -LiteralPath $userConfig
    }
    try {
        $effective = @(& $ssh -G -T ssh.dev.azure.com 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "The native client rejected the Azure policy: $($effective -join ' | ')"
        }

        if ($isArm64) {
            $relativeRoot = Join-Path $trash "relative-root"
            $relativeBin = Join-Path $relativeRoot "usr\bin"
            $relativeEtc = Join-Path $relativeRoot "etc\ssh"
            New-Item -ItemType Directory -Force -Path $relativeBin, $relativeEtc |
                Out-Null
            Copy-Item -LiteralPath $ssh -Destination $relativeBin
            $sourceBin = Join-Path $Root "usr\bin"
            Copy-Item -LiteralPath (
                Join-Path $sourceBin "libcrypto.dll"
            ) -Destination $relativeBin
            $relativeConfig = Join-Path $relativeEtc "ssh_config"
            @"
Host ssh.dev.azure.com
    User azure-policy-probe
    PubkeyAcceptedKeyTypes ssh-ed25519*,ssh-rsa*,ecdsa-sha2*
"@ | Set-Content -Encoding ascii -LiteralPath $relativeConfig
            & icacls.exe $relativeConfig /inheritance:r *> $null
            & icacls.exe $relativeConfig /remove:g `
                "*S-1-5-11" "*S-1-5-32-545" "*S-1-1-0" *> $null
            & icacls.exe $relativeConfig /grant:r `
                "$($env:USERNAME):F" "*S-1-5-18:F" "*S-1-5-32-544:F" *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Could not secure the executable-relative policy probe"
            }
            $relativeSsh = Join-Path $relativeBin "ssh.exe"
            $relativeEffective = @(& $relativeSsh -G -T ssh.dev.azure.com 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "The executable-relative policy probe failed: $($relativeEffective -join ' | ')"
            }
        }
    } finally {
        if ($userConfigExisted) {
            [IO.File]::WriteAllBytes($userConfig, $savedUserConfig)
        }
    }
    $effectiveText = $effective -join "`n"
    Assert-Match $effectiveText "(?m)^hostname ssh\.dev\.azure\.com$" `
        "The native client resolved an unexpected Azure hostname"
    if ($isArm64) {
        Assert-Match ($relativeEffective -join "`n") `
            "(?m)^user azure-policy-probe$" `
            "The native client did not consume its executable-relative global config"
    }
    $hostKeyAlgorithms = "," + (
        Get-EffectiveOption $effective "hostkeyalgorithms"
    ) + ","
    $pubkeyAlgorithms = "," + (
        Get-EffectiveOption $effective "pubkeyacceptedalgorithms"
    ) + ","
    if ($hostKeyAlgorithms -notmatch ",rsa-sha2-512,") {
        throw "The effective Azure host-key policy lacks RSA/SHA-2"
    }
    if ($pubkeyAlgorithms -notmatch ",ssh-rsa,") {
        throw "The effective Azure user-key policy lacks ssh-rsa"
    }
    if ($pubkeyAlgorithms -match ",ssh-dss,") {
        throw "The effective Azure user-key policy still enables ssh-dss"
    }

    $addresses = @([Net.Dns]::GetHostAddresses("ssh.dev.azure.com"))
    if ($addresses.Count -eq 0) {
        throw "DNS returned no addresses for ssh.dev.azure.com"
    }
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $tcp.ConnectAsync("ssh.dev.azure.com", 22)
        if (-not $connect.Wait([TimeSpan]::FromSeconds(15))) {
            throw "TCP connection to ssh.dev.azure.com:22 timed out"
        }
        $null = $connect.GetAwaiter().GetResult()
        if (-not $tcp.Connected) {
            throw "TCP connection to ssh.dev.azure.com:22 did not complete"
        }
    } finally {
        $tcp.Dispose()
    }

    $probeKey = Join-Path $trash "unauthorized-rsa"
    $knownHosts = Join-Path $trash "known_hosts"
    & $sshKeygen -q -t rsa -b 3072 -N "" -f $probeKey
    if ($LASTEXITCODE -ne 0) {
        throw "Could not generate the unauthenticated Azure probe key"
    }

    $oldTransportSshCommand = $env:GIT_SSH_COMMAND
    try {
        $sshForShell = $ssh.Replace("\", "/")
        $probeKeyForShell = $probeKey.Replace("\", "/")
        $knownHostsForShell = $knownHosts.Replace("\", "/")
        $env:GIT_SSH_COMMAND = "'$sshForShell' -vvv " +
            "-i '$probeKeyForShell' -o IdentitiesOnly=yes " +
            "-o BatchMode=yes -o PreferredAuthentications=publickey " +
            "-o StrictHostKeyChecking=accept-new " +
            "-o UserKnownHostsFile='$knownHostsForShell' -o ConnectTimeout=15"
        $transport = @(& $git ls-remote `
            git@ssh.dev.azure.com:v3/git-for-windows/git/git main `
            2>&1 | ForEach-Object { "$_" })
        $transportExitCode = $LASTEXITCODE
        $transportText = $transport -join "`n"
        if ($transportExitCode -ne 128) {
            throw "Azure transport returned $transportExitCode instead of 128: $transportText"
        }
        foreach ($failure in @(
            "Could not resolve hostname",
            "Connection timed out",
            "Connection refused",
            "Host key verification failed",
            "no matching host key type found",
            "Bad owner or permissions"
        )) {
            if ($transportText.Contains($failure)) {
                throw "Azure transport failed before authentication: $failure"
            }
        }
        Assert-Match $transportText "Connection established\." `
            "Azure TCP transport did not establish an SSH connection"
        Assert-Match $transportText "Remote protocol version 2\.0" `
            "Azure SSH protocol negotiation did not complete"
        Assert-Match $transportText "Server host key: ssh-rsa SHA256:" `
            "Azure did not negotiate its RSA host key"
        Assert-Match $transportText "Authentications that can continue: .*publickey" `
            "Azure did not reach public-key authentication"
        Assert-Match $transportText "Offering public key: .*RSA SHA256:" `
            "The native client did not offer the deterministic RSA probe key"
        Assert-Match $transportText `
            "Authenticated to ssh\.dev\.azure\.com .* using `"publickey`"\." `
            "Azure did not complete SSH public-key authentication"
        Assert-Match $transportText `
            "Sending command: git-upload-pack 'v3/git-for-windows/git/git'" `
            "The native client did not request Azure's Git upload-pack"
        $rejectionPattern = "(?m)^remote: Public key authentication failed\.\s*$"
        if ([regex]::Matches($transportText, $rejectionPattern).Count -ne 1) {
            throw "Azure did not terminate in the exact expected unregistered-key state: $transportText"
        }
        Assert-Match $transportText `
            "(?m)^fatal: Could not read from remote repository\.\s*$" `
            "Git did not report Azure's expected authorization rejection"
    } finally {
        $env:GIT_SSH_COMMAND = $oldTransportSshCommand
    }
    if (-not (Test-Path -LiteralPath $knownHosts) -or
        (Get-Item -LiteralPath $knownHosts).Length -eq 0) {
        throw "Azure host-key negotiation did not record a host key"
    }
    Write-Host "::notice::Azure SSH DNS, TCP, RSA policy, host-key, and authentication-boundary checks passed."

    $privateKey = $env:ARM64_AZURE_SSH_PRIVATE_KEY
    $env:ARM64_AZURE_SSH_PRIVATE_KEY = $null
    if ([string]::IsNullOrWhiteSpace($privateKey)) {
        Write-Host "::notice::Authenticated Azure SSH clone/fetch skipped: ARM64_AZURE_SSH_PRIVATE_KEY is not configured."
    } else {
        $privateKeyPath = Join-Path $trash "azure-private-key"
        $encoding = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText(
            $privateKeyPath,
            $privateKey.TrimEnd("`r", "`n") + "`n",
            $encoding
        )
        $privateKey = $null
        & icacls.exe $privateKeyPath /inheritance:r /grant:r `
            "$($env:USERNAME):R" "*S-1-5-18:F" "*S-1-5-32-544:F" *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not secure the temporary Azure private key"
        }

        $clone = Join-Path $trash "azure-clone"
        $oldSshCommand = $env:GIT_SSH_COMMAND
        try {
            $sshForShell = $ssh.Replace("\", "/")
            $keyForShell = $privateKeyPath.Replace("\", "/")
            $knownHostsForShell = $knownHosts.Replace("\", "/")
            $env:GIT_SSH_COMMAND = "'$sshForShell' -i '$keyForShell' " +
                "-o IdentitiesOnly=yes -o BatchMode=yes " +
                "-o StrictHostKeyChecking=yes " +
                "-o UserKnownHostsFile='$knownHostsForShell'"
            & $git clone --depth=1 --branch=main --no-tags `
                git@ssh.dev.azure.com:v3/git-for-windows/git/git $clone
            if ($LASTEXITCODE -ne 0) {
                throw "Authenticated Azure SSH clone failed"
            }
            & $git -C $clone fetch --no-tags origin main
            if ($LASTEXITCODE -ne 0) {
                throw "Authenticated Azure SSH fetch failed"
            }
        } finally {
            $env:GIT_SSH_COMMAND = $oldSshCommand
        }
        Write-Host "::notice::Authenticated Azure SSH clone/fetch passed."
    }
} finally {
    $env:ARM64_AZURE_SSH_PRIVATE_KEY = $null
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
