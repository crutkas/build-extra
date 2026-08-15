param(
    [Parameter(Mandatory = $true)]
    [string]$ClientRoot,

    [Parameter(Mandatory = $true)]
    [string]$ServerRoot
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-azure-ssh-fixture-$PID"
$server = $null

function Invoke-Git([string[]]$Arguments) {
    & $git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Git failed: git $($Arguments -join ' ')"
    }
}

function Convert-ToPosix([string]$Path) {
    $value = @(& $cygpath -au $Path 2>&1)
    if ($LASTEXITCODE -ne 0 -or $value.Count -ne 1) {
        throw "Could not convert path for the fixture: $Path"
    }
    return $value[0]
}

try {
    $ClientRoot = (Resolve-Path -LiteralPath $ClientRoot).Path
    $ServerRoot = (Resolve-Path -LiteralPath $ServerRoot).Path
    $ssh = Join-Path $ClientRoot "usr\bin\ssh.exe"
    $sshKeygen = Join-Path $ClientRoot "usr\bin\ssh-keygen.exe"
    $git = Join-Path $ClientRoot "cmd\git.exe"
    $sshd = Join-Path $ServerRoot "usr\bin\sshd.exe"
    $cygpath = Join-Path $ServerRoot "usr\bin\cygpath.exe"
    foreach ($path in @($ssh, $sshKeygen, $git, $sshd, $cygpath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Azure-like SSH fixture is missing $path"
        }
    }

    New-Item -ItemType Directory -Path $trash | Out-Null
    New-Item -ItemType Directory -Force -Path (
        Join-Path $ServerRoot "var\empty"
    ) | Out-Null
    New-Item -ItemType Directory -Force -Path (
        Join-Path $ServerRoot "etc"
    ) | Out-Null

    $hostKey = Join-Path $trash "host-rsa"
    $userKey = Join-Path $trash "user-rsa"
    $authorizedKeys = Join-Path $trash "authorized_keys"
    $knownHosts = Join-Path $trash "known_hosts"
    $serverLog = Join-Path $trash "sshd.log"
    foreach ($key in @($hostKey, $userKey)) {
        & $sshKeygen -q -t rsa -b 3072 -N "" -f $key
        if ($LASTEXITCODE -ne 0) {
            throw "Could not generate fixture RSA key: $key"
        }
    }
    Copy-Item -LiteralPath "$userKey.pub" -Destination $authorizedKeys

    $remote = Join-Path $trash "remote.git"
    $seed = Join-Path $trash "seed"
    $clone = Join-Path $trash "clone"
    Invoke-Git @("init", "--bare", $remote)
    Invoke-Git @("init", $seed)
    Invoke-Git @("-C", $seed, "config", "user.name", "Azure fixture")
    Invoke-Git @("-C", $seed, "config", "user.email", "azure-fixture@example.invalid")
    "one" | Set-Content -Encoding ascii -LiteralPath (Join-Path $seed "fixture.txt")
    Invoke-Git @("-C", $seed, "add", "fixture.txt")
    Invoke-Git @("-C", $seed, "commit", "-m", "fixture one")
    Invoke-Git @("-C", $seed, "branch", "-M", "main")
    Invoke-Git @("-C", $seed, "push", $remote, "main")

    $listener = [Net.Sockets.TcpListener]::new(
        [Net.IPAddress]::Loopback,
        0
    )
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()

    $remotePosix = Convert-ToPosix $remote
    $hostKeyPosix = Convert-ToPosix $hostKey
    $authorizedKeysPosix = Convert-ToPosix $authorizedKeys
    $pidPosix = Convert-ToPosix (Join-Path $trash "sshd.pid")
    $commandPath = Join-Path $ServerRoot "fixture-command.sh"
    $gitPosix = Convert-ToPosix $git
    @"
#!/bin/sh
exec "$gitPosix" upload-pack "$remotePosix"
"@ | Set-Content -Encoding ascii -LiteralPath $commandPath

    $config = Join-Path $trash "sshd_config"
    @"
Port $port
AddressFamily inet
ListenAddress 127.0.0.1
HostKey $hostKeyPosix
PidFile $pidPosix
AuthorizedKeysFile $authorizedKeysPosix
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
StrictModes no
UseDNS no
PrintMotd no
PermitTTY no
AllowTcpForwarding no
AllowAgentForwarding no
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms rsa-sha2-512,rsa-sha2-256
AllowUsers $env:USERNAME
ForceCommand /usr/bin/bash.exe /fixture-command.sh
LogLevel DEBUG3
"@ | Set-Content -Encoding ascii -LiteralPath $config

    & $sshd -t -f $config 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The Azure-like SSH server configuration is invalid"
    }
    $oldServerPath = $env:PATH
    try {
        $env:PATH = "$(Join-Path $ServerRoot 'usr\bin');$oldServerPath"
        $server = Start-Process -PassThru -WindowStyle Hidden `
            -FilePath $sshd `
            -ArgumentList @("-D", "-e", "-f", $config) `
            -RedirectStandardError $serverLog
    } finally {
        $env:PATH = $oldServerPath
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if ($server.HasExited) {
            throw "The Azure-like SSH server exited early: $(
                Get-Content -Raw -LiteralPath $serverLog
            )"
        }
        $tcp = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $tcp.ConnectAsync("127.0.0.1", $port)
            if ($connect.Wait([TimeSpan]::FromMilliseconds(200)) -and
                $tcp.Connected) {
                $ready = $true
                break
            }
        } finally {
            $tcp.Dispose()
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) {
        throw "The Azure-like SSH server did not begin listening"
    }

    $effective = @(& $ssh -G -T `
        -o HostName=127.0.0.1 `
        -o "Port=$port" `
        ssh.dev.azure.com 2>&1)
    $hostKeyPolicy = @($effective | Where-Object {
        $_ -match "^hostkeyalgorithms "
    }) -replace "^hostkeyalgorithms ", ""
    $pubkeyPolicy = @($effective | Where-Object {
        $_ -match "^pubkeyacceptedalgorithms "
    }) -replace "^pubkeyacceptedalgorithms ", ""
    if ($LASTEXITCODE -ne 0 -or
        $hostKeyPolicy.Count -ne 1 -or
        $pubkeyPolicy.Count -ne 1 -or
        (",$hostKeyPolicy," -notmatch ",rsa-sha2-512,") -or
        (",$pubkeyPolicy," -notmatch ",ssh-rsa,")) {
        throw "The native client did not apply Azure's RSA policy to the fixture"
    }

    $oldSshCommand = $env:GIT_SSH_COMMAND
    try {
        $sshForShell = $ssh.Replace("\", "/")
        $keyForShell = $userKey.Replace("\", "/")
        $knownHostsForShell = $knownHosts.Replace("\", "/")
        $env:GIT_SSH_COMMAND = "'$sshForShell' " +
            "-i '$keyForShell' -o IdentitiesOnly=yes -o BatchMode=yes " +
            "-o HostName=127.0.0.1 -o Port=$port " +
            "-o StrictHostKeyChecking=no " +
            "-o UserKnownHostsFile='$knownHostsForShell'"
        $fixtureRemote = "$($env:USERNAME)@ssh.dev.azure.com:azure-fixture"
        try {
            Invoke-Git @("clone", $fixtureRemote, $clone)
        } catch {
            $serverDetails = Get-Content -Raw -LiteralPath $serverLog
            throw "$_`nAzure-like sshd log:`n$serverDetails"
        }

        "two" | Set-Content -Encoding ascii -LiteralPath (Join-Path $seed "fixture.txt")
        Invoke-Git @("-C", $seed, "commit", "-am", "fixture two")
        Invoke-Git @("-C", $seed, "push", $remote, "main")
        $expected = @(& $git -C $seed rev-parse HEAD)
        Invoke-Git @("-C", $clone, "fetch", "origin", "main")
        $actual = @(& $git -C $clone rev-parse FETCH_HEAD)
        if ($expected.Count -ne 1 -or $actual.Count -ne 1 -or
            $expected[0] -ne $actual[0]) {
            throw "Azure-like SSH fetch did not execute Git upload-pack"
        }
    } finally {
        $env:GIT_SSH_COMMAND = $oldSshCommand
    }

    $log = Get-Content -Raw -LiteralPath $serverLog
    if ($log -notmatch "Accepted publickey|Accepted key") {
        throw "Azure-like SSH server did not authenticate the RSA fixture key: $log"
    }
    Write-Host "Azure-like native ARM64 Git-over-SSH clone/fetch passed"
} finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id
        $server.WaitForExit()
    }
    Remove-Item -Force -LiteralPath (
        Join-Path $ServerRoot "fixture-command.sh"
    ) -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
