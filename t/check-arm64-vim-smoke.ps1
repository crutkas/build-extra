param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

$ErrorActionPreference = "Stop"
$provenance = Join-Path $Root "etc\arm64-vim-provenance.json"
if (-not (Test-Path -LiteralPath $provenance)) {
    Write-Host "::notice::Native ARM64 Vim smoke skipped: the immutable input is not admitted."
    exit 0
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::Arm64) {
    throw "The native ARM64 Vim smoke requires an ARM64 runner"
}

$vim = Join-Path $Root "usr\bin\vim.exe"
$xxd = Join-Path $Root "usr\bin\xxd.exe"
$git = Join-Path $Root "cmd\git.exe"
$trash = Join-Path ([IO.Path]::GetTempPath()) "arm64-vim-smoke-$PID"
New-Item -ItemType Directory -Force -Path $trash | Out-Null
try {
    $savedPath = $env:PATH
    $env:PATH = "$(Join-Path $Root 'usr\bin');$(Join-Path $env:SystemRoot 'System32')"
    $env:HOME = Join-Path $trash "home"
    New-Item -ItemType Directory -Force -Path $env:HOME | Out-Null
    "set number" | Set-Content -Encoding ascii -LiteralPath (Join-Path $env:HOME "_vimrc")
    $version = @(& $vim --clean --not-a-term -es -c "set runtimepath?" -c "qa!" 2>&1)
    if ($LASTEXITCODE -ne 0 -or $version -notmatch "vim92") {
        throw "Vim could not start with its packaged runtime: $($version -join ' | ')"
    }

    $lf = Join-Path $trash "lf.txt"
    $crlf = Join-Path $trash "crlf.txt"
    [IO.File]::WriteAllText($lf, "alpha`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($crlf, "bravo`r`n", [Text.UTF8Encoding]::new($false))
    & $vim --clean --not-a-term -es $lf -c "syntax on" -c "normal! Gocharlie" -c "wq"
    if ($LASTEXITCODE -ne 0 -or (Get-Content -Raw -LiteralPath $lf) -notmatch "charlie") {
        throw "Vim failed the UTF-8 LF edit/write smoke"
    }
    & $vim --clean --not-a-term -es $crlf -c "set fileformat=dos" -c "normal! Godelta" -c "wq"
    if ($LASTEXITCODE -ne 0 -or -not ([IO.File]::ReadAllText($crlf).Contains("`r`n"))) {
        throw "Vim failed the UTF-8 CRLF edit/write smoke"
    }

    $hex = @(& $xxd -p $lf 2>&1)
    if ($LASTEXITCODE -ne 0 -or -not $hex) {
        throw "xxd failed"
    }

    $repo = Join-Path $trash "repo"
    New-Item -ItemType Directory -Force -Path $repo | Out-Null
    & $git -C $repo init --quiet
    & $git -C $repo config user.name "ARM64 Vim smoke"
    & $git -C $repo config user.email "arm64-vim@example.invalid"
    & $git -C $repo config core.editor "`"$vim`" --clean --not-a-term -es -c `"normal! iNative ARM64 Vim`" -c wq"
    "content" | Set-Content -Encoding ascii -LiteralPath (Join-Path $repo "file.txt")
    & $git -C $repo add file.txt
    & $git -C $repo commit --quiet
    if ($LASTEXITCODE -ne 0 -or
        (& $git -C $repo log -1 --format=%s) -ne "Native ARM64 Vim") {
        throw "Git core.editor did not create the commit message"
    }
    Write-Host "Native ARM64 Vim functional smoke passed"
} finally {
    $env:PATH = $savedPath
    Remove-Item Env:\HOME -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $trash) {
        Remove-Item -Recurse -Force -LiteralPath $trash
    }
}
