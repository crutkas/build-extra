param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,

    [Parameter(Mandatory = $true)]
    [string]$Package,

    [Parameter(Mandatory = $true)]
    [string]$Scanner,

    [string]$AppRoot = "$env:ProgramFiles\Git"
)

$ErrorActionPreference = "Stop"
$installArguments = "/SILENT /VERYSILENT /NORESTART /SUPPRESSMSGBOXES /ALLOWDOWNGRADE=1"

& "$PSScriptRoot\check-arm64-openssh-package.ps1" `
    -Package $Package `
    -Scanner $Scanner `
    -RuntimeRoot $AppRoot

foreach ($relative in @(
    "etc\ssh\moduli",
    "etc\ssh\ssh_config",
    "etc\ssh\sshd_config",
    "usr\bin\ssh-copy-id",
    "usr\lib\ssh\ssh-keysign.exe",
    "usr\share\licenses\openssh\LICENCE"
)) {
    $path = Join-Path $AppRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    "legacy" | Set-Content -Encoding ascii -LiteralPath $path
}

$repair = Start-Process -PassThru -Wait -FilePath $Installer `
    -ArgumentList "$installArguments /LOG=installer-repair.log"
if ($repair.ExitCode -ne 0) {
    throw "Repair/update installation failed with exit code $($repair.ExitCode)"
}
foreach ($relative in @(
    "etc\ssh\moduli",
    "etc\ssh\sshd_config",
    "usr\bin\ssh-copy-id",
    "usr\lib\ssh\ssh-keysign.exe",
    "usr\share\licenses\openssh\LICENCE"
)) {
    if (Test-Path -LiteralPath (Join-Path $AppRoot $relative)) {
        throw "Legacy path survived repair/update: $relative"
    }
}
& "$PSScriptRoot\check-arm64-openssh-package.ps1" `
    -Package $Package `
    -Scanner $Scanner `
    -RuntimeRoot $AppRoot

$uninstaller = Join-Path $AppRoot "unins000.exe"
$uninstall = Start-Process -PassThru -Wait -FilePath $uninstaller `
    -ArgumentList "/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES"
if ($uninstall.ExitCode -ne 0 -or
    (Test-Path -LiteralPath (Join-Path $AppRoot "cmd\git.exe"))) {
    throw "Uninstall failed with exit code $($uninstall.ExitCode)"
}

$external = Start-Process -PassThru -Wait -FilePath $Installer `
    -ArgumentList "$installArguments /o:SSHOption=ExternalOpenSSH /LOG=installer-external.log"
if ($external.ExitCode -ne 0) {
    throw "External-SSH installation failed with exit code $($external.ExitCode)"
}
foreach ($relative in @(
    "etc\ssh\ssh_config",
    "usr\bin\ssh.exe",
    "usr\bin\libcrypto.dll",
    "usr\lib\ssh\ssh-pkcs11-helper.exe"
)) {
    if (Test-Path -LiteralPath (Join-Path $AppRoot $relative)) {
        throw "External-SSH installation retained package-owned path: $relative"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $AppRoot "usr\bin\ssh-pageant.exe"))) {
    throw "External-SSH installation removed separately owned ssh-pageant"
}

$uninstaller = Join-Path $AppRoot "unins000.exe"
$uninstall = Start-Process -PassThru -Wait -FilePath $uninstaller `
    -ArgumentList "/VERYSILENT /SILENT /NORESTART /SUPPRESSMSGBOXES"
if ($uninstall.ExitCode -ne 0) {
    throw "External-SSH uninstall failed with exit code $($uninstall.ExitCode)"
}

Write-Host "ARM64 installer repair/update, uninstall, and external-SSH checks passed"
