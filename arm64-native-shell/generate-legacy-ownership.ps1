[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,

    [string]$Output = (Join-Path $PSScriptRoot "legacy-package-ownership.tsv")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sources = @(
    @{
        Package = "msys2-runtime"
        Version = "3.6.10-1"
        Mtree = "msys2-runtime-3.6.10-1.mtree"
        Sha256 = "fd946e6aa3ae5d0c105bcc2a17cc3663cd6ce0f575b2634e7283a0fb0f194913"
    },
    @{
        Package = "ncurses"
        Version = "6.6-2"
        Mtree = "ncurses-6.6-2.mtree"
        Sha256 = "12d48d899c6a9f525af292ef6e24172d35139f021d4de0035ae0a0f4c07cb537"
    },
    @{
        Package = "libreadline"
        Version = "8.3.003-1"
        Mtree = "libreadline-8.3.003-1.mtree"
        Sha256 = "57fe7750d879491f6f7bf8074f2c7c44ddde68f81b1209edc8cde100c94349f2"
    },
    @{
        Package = "bash"
        Version = "5.3.015-2"
        Mtree = "bash-5.3.015-2.mtree"
        Sha256 = "a7271fe9718c7922122761a65d3c374d830b407482820aa5d39d8fbd3bfaae5b"
    }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Expand-MtreePath([string]$Path) {
    return [regex]::Replace($Path, "\\([0-7]{3})", {
        param($Match)
        [char][Convert]::ToInt32($Match.Groups[1].Value, 8)
    })
}

$rows = [Collections.Generic.List[object]]::new()
foreach ($source in $sources) {
    $path = Join-Path $EvidenceRoot $source.Mtree
    if ((Get-Sha256 $path) -ne $source.Sha256) {
        throw "Unexpected evidence SHA-256: $($source.Mtree)"
    }

    $file = [IO.File]::OpenRead($path)
    try {
        $gzip = [IO.Compression.GZipStream]::new(
            $file, [IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [IO.StreamReader]::new($gzip)
            try {
                $defaultType = "file"
                $defaultMode = "644"
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($line.StartsWith("/set ")) {
                        foreach ($token in $line.Substring(5).Split(" ")) {
                            if ($token -match "^type=(.+)$") {
                                $defaultType = $Matches[1]
                            } elseif ($token -match "^mode=(.+)$") {
                                $defaultMode = $Matches[1]
                            }
                        }
                        continue
                    }
                    if (-not $line.StartsWith("./")) {
                        continue
                    }

                    $tokens = @($line.Split(" "))
                    $relative = Expand-MtreePath $tokens[0].Substring(2)
                    if ($relative -in @(".BUILDINFO", ".MTREE", ".PKGINFO")) {
                        continue
                    }
                    $metadata = @{
                        type = $defaultType
                        mode = $defaultMode
                        size = ""
                        sha256digest = ""
                        link = ""
                    }
                    foreach ($token in $tokens | Select-Object -Skip 1) {
                        if ($token -match "^([^=]+)=(.*)$") {
                            $metadata[$Matches[1]] = $Matches[2]
                        }
                    }
                    if ($metadata.type -eq "dir") {
                        continue
                    }

                    $kind = if ($relative -match "\.(exe|dll)$") {
                        "pe"
                    } elseif ($metadata.type -in @("link", "hardlink")) {
                        $metadata.type
                    } elseif ([Convert]::ToInt32($metadata.mode, 8) -band 73) {
                        "script"
                    } else {
                        "data"
                    }
                    $disposition = if ($source.Package -ne "msys2-runtime") {
                        "pending-final-package"
                    } elseif ($relative -eq "usr/bin/msys-2.0.dll") {
                        "replace"
                    } elseif ($kind -eq "pe") {
                        "remove"
                    } else {
                        "retain-data"
                    }
                    $rows.Add([ordered]@{
                        package = $source.Package
                        version = $source.Version
                        path = $relative
                        kind = $kind
                        mode = $metadata.mode
                        bytes = $metadata.size
                        sha256 = $metadata.sha256digest
                        linkTarget = $metadata.link
                        finalDisposition = $disposition
                        collisionPolicy = "exclusive-owner"
                    })
                }
            } finally {
                $reader.Dispose()
            }
        } finally {
            $gzip.Dispose()
        }
    } finally {
        $file.Dispose()
    }
}

$header = "package`tversion`tpath`tkind`tmode`tbytes`tsha256`tlinkTarget`tfinalDisposition`tcollisionPolicy"
$lines = @($header) + @(
    $rows |
        ForEach-Object {
            @(
                $_.package, $_.version, $_.path, $_.kind, $_.mode, $_.bytes,
                $_.sha256, $_.linkTarget, $_.finalDisposition, $_.collisionPolicy
            ) -join "`t"
        }
)
[IO.File]::WriteAllText(
    $Output,
    (($lines -join "`n") + "`n"),
    [Text.UTF8Encoding]::new($false)
)
