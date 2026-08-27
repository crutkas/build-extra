[CmdletBinding()]
param(
    [ValidateSet("Probe", "Stage", "Finalize")]
    [string]$Phase = "Finalize",

    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$Lock,

    [Parameter(Mandatory = $true)]
    [string]$Scanner,

    [switch]$RequireAdmission,

    [switch]$TestMode,

    [string]$PackageDirectory,

    [switch]$MeasurementMode
)

$ErrorActionPreference = "Stop"
$expectedReplacements = @(
    "usr/bin/ex.exe",
    "usr/bin/rview.exe",
    "usr/bin/rvim.exe",
    "usr/bin/view.exe",
    "usr/bin/vim.exe",
    "usr/bin/vimdiff.exe",
    "usr/bin/xxd.exe"
)
$metadataMembers = @(".BUILDINFO", ".MTREE", ".PKGINFO")
$cache = Join-Path $Root "var\cache\arm64-vim"
$windowsTar = Join-Path ([Environment]::GetFolderPath("System")) "tar.exe"
if (-not (Test-Path -LiteralPath $windowsTar -PathType Leaf)) {
    throw "Windows tar.exe is required"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-RelativePath([string]$Base, [string]$Path) {
    $baseUri = [Uri]((Resolve-Path -LiteralPath $Base).Path.TrimEnd("\") + "\")
    $pathUri = [Uri](Resolve-Path -LiteralPath $Path).Path
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString())
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
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

function Get-PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -lt 64 -or $stream.ReadByte() -ne 0x4d -or
            $stream.ReadByte() -ne 0x5a) {
            return $null
        }
        $reader = [IO.BinaryReader]::new($stream)
        $stream.Position = 0x3c
        $offset = $reader.ReadInt32()
        if ($offset -lt 0 -or $offset + 6 -gt $stream.Length) {
            return $null
        }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            return $null
        }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Read-PkgInfo([string]$Path) {
    $result = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match "^([^#][^= ]*) = (.*)$") {
            if (-not $result.ContainsKey($Matches[1])) {
                $result[$Matches[1]] = [Collections.Generic.List[string]]::new()
            }
            $result[$Matches[1]].Add($Matches[2])
        }
    }
    return $result
}

function Assert-PkgInfo($Package, [string]$Path) {
    $info = Read-PkgInfo $Path
    $single = @{
        pkgname = $Package.name
        pkgbase = "mingw-w64-vim"
        pkgver = $Package.version
        pkgdesc = $Package.description
        url = "https://www.vim.org"
        arch = "any"
        license = "spdx:Vim"
        xdata = "pkgtype=split"
    }
    foreach ($entry in $single.GetEnumerator()) {
        if (-not $info.ContainsKey($entry.Key) -or $info[$entry.Key].Count -ne 1) {
            throw "Missing or duplicate .PKGINFO field '$($entry.Key)'"
        }
        Assert-Equal $entry.Value $info[$entry.Key][0] "Unexpected .PKGINFO field '$($entry.Key)'"
    }
    $depends = if ($info.ContainsKey("depend")) { @($info.depend) } else { @() }
    Assert-SetEqual @($Package.depends) $depends "Unexpected dependency set for $($Package.name)"
    $makeDepends = if ($info.ContainsKey("makedepend")) { @($info.makedepend) } else { @() }
    Assert-SetEqual @($Package.makeDepends) $makeDepends `
        "Unexpected make dependency set for $($Package.name)"
}

function Assert-BuildInfo($Package, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Package $($Package.name) is missing .BUILDINFO"
    }
    $info = Read-PkgInfo $Path
    foreach ($entry in @{
        pkgbase = "mingw-w64-vim"
        pkgver = $Package.version
        pkgarch = "any"
    }.GetEnumerator()) {
        if (-not $info.ContainsKey($entry.Key) -or $info[$entry.Key].Count -ne 1) {
            throw "Missing or duplicate .BUILDINFO field '$($entry.Key)'"
        }
        Assert-Equal $entry.Value $info[$entry.Key][0] "Unexpected .BUILDINFO field '$($entry.Key)'"
    }
}

function Get-ArchiveMembers([string]$Archive) {
    $output = @(& $windowsTar -tf $Archive 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list $Archive`: $($output -join ' | ')"
    }
    $members = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in $output) {
        $member = ([string]$raw).Replace("\", "/")
        while ($member.StartsWith("./")) {
            $member = $member.Substring(2)
        }
        $trimmed = $member.TrimEnd("/")
        if (-not $trimmed) {
            continue
        }
        if ($member.StartsWith("/") -or $member -match "^[A-Za-z]:" -or
            @($trimmed.Split("/")) -contains ".." -or
            @($trimmed.Split("/")) -contains "." -or
            @($trimmed.Split("/")) -contains "" -or
            @($trimmed.Split("/") | Where-Object {
                $_ -match "[. ]$" -or
                $_ -match '[:*?"<>|\x00-\x1f]' -or
                ($_ -split "\.")[0] -match "^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$"
            }).Count) {
            throw "Unsafe archive member '$member'"
        }
        if (-not $seen.Add($trimmed)) {
            throw "Duplicate or case-colliding archive member '$trimmed'"
        }
        if ($member.EndsWith("/")) {
            continue
        }
        $members.Add($trimmed)
    }
    $verbose = @(& $windowsTar -tvf $Archive 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect $Archive`: $($verbose -join ' | ')"
    }
    if (@($verbose | Where-Object { $_ -match "^l" }).Count) {
        throw "Archive contains a symbolic link"
    }
    if (@($verbose | Where-Object { $_ -match "^[bcps]" }).Count) {
        throw "Archive contains a special member"
    }
    foreach ($hardlink in @($verbose | Where-Object { $_ -match "^h" })) {
        if ($hardlink -notmatch "\s(\S+)\s+link to\s+(\S+)\s*$" -or
            $Matches[1] -match "(^/|(^|/)\.\.?(/|$)|\\)" -or
            $Matches[2] -match "(^/|(^|/)\.\.?(/|$)|\\)") {
            throw "Archive contains an unsafe hard link"
        }
    }
    return @($members)
}

function Assert-AllowedMember($Package, [string]$Member) {
    if ($metadataMembers -contains $Member) {
        return
    }
    if ($Package.name -eq "mingw-w64-clang-aarch64-vim") {
        if ($Member -eq "clangarm64/share/licenses/vim/LICENSE" -or
            $Member -match "^clangarm64/bin/(ex|rview|rvim|view|vim|vimdiff|xxd)\.exe$") {
            return
        }
    } elseif ($Package.name -eq "mingw-w64-clang-aarch64-vim-runtime") {
        if ($Member -eq "clangarm64/share/licenses/vim-runtime/LICENSE" -or
            $Member -match "^clangarm64/share/vim/vim92/.+" -or
            $Member -match "^clangarm64/share/man/man1/(vim|xxd)\.1\.gz$") {
            return
        }
    }
    throw "Package $($Package.name) contains undeclared member '$Member'"
}

function Get-Destination([string]$Member) {
    if (-not $Member.StartsWith("clangarm64/")) {
        throw "Cannot relocate package member '$Member'"
    }
    return "usr/" + $Member.Substring("clangarm64/".Length)
}

function Assert-Lock($Data) {
    Assert-Equal 1 $Data.schemaVersion "Unsupported ARM64 Vim lock schema"
    Assert-Equal "native-arm64-vim-9.2.0858-1" $Data.inputId "Unexpected ARM64 Vim input ID"
    Assert-Equal "crutkas/MINGW-packages" $Data.source.repository "Unexpected source repository"
    Assert-Equal 7 $Data.source.pullRequest "Unexpected source pull request"
    Assert-Equal "d012f9f8a8d05a3a51a40fe33668295a3e31c221" $Data.source.commit "Unexpected source commit"
    Assert-Equal 33048420275 $Data.source.workflowRun "Unexpected source workflow run"
    Assert-Equal "success" $Data.source.workflowConclusion "The source workflow did not succeed"
    Assert-Equal "windows-11-arm" $Data.source.runner "Unexpected source runner"
    Assert-Equal "mingw" $Data.expected.personality "Unexpected package personality"
    Assert-Equal "0xAA64" $Data.expected.machine "Unexpected package machine"
    Assert-Equal "any" $Data.expected.packageArchitecture "Unexpected package filename architecture"
    Assert-SetEqual $expectedReplacements @($Data.expected.replacements) "Unexpected replacement contract"
    Assert-SetEqual @("usr/bin/vimtutor") @($Data.expected.retained) "Unexpected retained-path contract"
    $baseClosure = $Data.expected.baseDependencyClosure
    Assert-SetEqual @(
        "mingw-w64-clang-aarch64-gettext-runtime",
        "mingw-w64-clang-aarch64-libc++",
        "mingw-w64-clang-aarch64-libiconv"
    ) @($baseClosure.packages.name) "Unexpected base dependency package set"
    Assert-Equal 3 @($baseClosure.packages).Count "Unexpected base dependency package count"
    $basePackageContracts = @{
        "mingw-w64-clang-aarch64-gettext-runtime" = @(
            "1.0-1",
            "mingw-w64-clang-aarch64-gettext-runtime-1.0-1-any.pkg.tar.zst",
            395859,
            "b5364a7c78cc4b73273a4a28e07e3c6d9cc8ec0ce269527409d944ab1c8f5a70"
        )
        "mingw-w64-clang-aarch64-libc++" = @(
            "22.1.8-1",
            "mingw-w64-clang-aarch64-libc++-22.1.8-1-any.pkg.tar.zst",
            1894929,
            "6755aa5a658d0a906e1e8477858b3518fd87d380ac5c854a226f5a3a2c78d794"
        )
        "mingw-w64-clang-aarch64-libiconv" = @(
            "1.19-1",
            "mingw-w64-clang-aarch64-libiconv-1.19-1-any.pkg.tar.zst",
            734170,
            "955499bc5cb73d86ea2850ece9bbdbbfd66b213e272e032f28147ecd42897e21"
        )
    }
    foreach ($package in $baseClosure.packages) {
        $contract = $basePackageContracts[$package.name]
        if (-not $contract) {
            throw "Unexpected base dependency package '$($package.name)'"
        }
        Assert-Equal $contract[0] $package.version "Unexpected base dependency package version"
        Assert-Equal $contract[1] $package.archive "Unexpected base dependency archive"
        Assert-Equal ([long]$contract[2]) ([long]$package.bytes) `
            "Unexpected base dependency archive size"
        Assert-Equal $contract[3] $package.sha256 "Unexpected base dependency archive SHA-256"
    }
    Assert-Equal 10 @($baseClosure.pes).Count "Unexpected base dependency PE set"
    Assert-SetEqual @(
        "clangarm64/bin/envsubst.exe",
        "clangarm64/bin/gettext.exe",
        "clangarm64/bin/libasprintf-0.dll",
        "clangarm64/bin/libc++.dll",
        "clangarm64/bin/libcharset-1.dll",
        "clangarm64/bin/libiconv-2.dll",
        "clangarm64/bin/libintl-8.dll",
        "clangarm64/bin/ngettext.exe",
        "clangarm64/bin/printf_gettext.exe",
        "clangarm64/bin/printf_ngettext.exe"
    ) @($baseClosure.pes.sourceMember) "Unexpected base dependency PE paths"
    Assert-SetEqual @("libiconv-2.dll", "libintl-8.dll") `
        @($baseClosure.loaderCopies) "Unexpected loader copy set"
    Assert-Equal 19 $Data.expected.candidateAndDependencyPeCount "Unexpected PE closure count"
    Assert-Equal 291 $Data.expected.importCount "Unexpected import count"
    Assert-Equal 0 $Data.expected.unresolvedImports "The admitted evidence has unresolved imports"
    Assert-Equal -7 $Data.expected.architectureDelta.x64 "Unexpected x64 delta"
    Assert-Equal 9 $Data.expected.architectureDelta.arm64 "Unexpected ARM64 delta"
    Assert-Equal 0 $Data.expected.architectureDelta.unexpectedX64 "Unexpected x64 payload is permitted"
    Assert-SetEqual @(
        "mingw-w64-clang-aarch64-vim",
        "mingw-w64-clang-aarch64-vim-runtime"
    ) @($Data.packages.name) "Unexpected package set"
    $binaryPackage = @($Data.packages |
        Where-Object name -eq "mingw-w64-clang-aarch64-vim")
    $runtimePackage = @($Data.packages |
        Where-Object name -eq "mingw-w64-clang-aarch64-vim-runtime")
    Assert-Equal 1 $binaryPackage.Count "Unexpected binary package count"
    Assert-Equal 1 $runtimePackage.Count "Unexpected runtime package count"
    Assert-SetEqual $expectedReplacements @($binaryPackage[0].provides) `
        "Unexpected binary package provides"
    Assert-Equal 0 @($runtimePackage[0].provides).Count `
        "The runtime package unexpectedly provides payload paths"
    if (-not $TestMode) {
        Assert-Equal "d7878b284b5a5ae43831f0a090327472035338768a8fd86deaad57581e842ed3" `
            $Data.source.sourceArchive.sha256 "Unexpected source archive SHA-256"
        Assert-Equal "2a2bd8397f3d14a4caec95d76398014f883006091f2540efa54b04bfd97dc55b" `
            $Data.source.layoutPatchSha256 "Unexpected layout patch SHA-256"
        Assert-Equal "3c16fd3d7850ca365444142fc1207964b11632b762c35f2490ebbbe9fb521040" `
            $Data.source.vimrcSha256 "Unexpected vimrc SHA-256"
        Assert-Equal "e01af1240c3f54fb878f22facf2fd2eb68aa168d685236beb191c16a9b12717d" `
            $Data.source.auditHarnessSha256 "Unexpected audit harness SHA-256"
        Assert-Equal "3c1f82e8d24b2998aaf537d9a32913e72e27ca83de4198360361305a012b8e48" `
            $Data.source.smokeHarnessSha256 "Unexpected smoke harness SHA-256"
        $lockedPackages = @{
            "mingw-w64-clang-aarch64-vim-9.2.0858-1-any.pkg.tar.zst" = @(
                11942906,
                "03b9a8bfb815d1973f788c5519a2879ee38219e9405226f1b2f5c009846be832"
            )
            "mingw-w64-clang-aarch64-vim-runtime-9.2.0858-1-any.pkg.tar.zst" = @(
                9925290,
                "f548639937a4accdb44ae2d29665ad25d7c2183c812211a8f48e7033f170ec15"
            )
        }
        $packageAssets = @($Data.release.assets | Where-Object role -eq "package")
        Assert-SetEqual @($lockedPackages.Keys) @($packageAssets.name) "Unexpected package asset set"
        foreach ($asset in $packageAssets) {
            Assert-Equal ([long]$lockedPackages[$asset.name][0]) ([long]$asset.bytes) `
                "Unexpected locked size for $($asset.name)"
            Assert-Equal $lockedPackages[$asset.name][1] $asset.sha256 `
                "Unexpected locked SHA-256 for $($asset.name)"
        }
        $evidence = @($Data.release.assets | Where-Object role -eq "evidence")
        Assert-Equal 1 $evidence.Count "Unexpected evidence asset count"
        Assert-Equal 25400287 ([long]$evidence[0].bytes) "Unexpected evidence asset size"
        Assert-Equal "a826a11469892306c1a5624dc0e07970054a9f6f694b1530c27b19cf9c13acaf" `
            $evidence[0].sha256 "Unexpected evidence asset SHA-256"
    }
}

function Assert-Admitted($Data, [switch]$AllowUnmeasured) {
    $missing = [Collections.Generic.List[string]]::new()
    if ($Data.status -ne "admitted" -and
        -not ($AllowUnmeasured -and $Data.status -eq "measuring")) {
        $missing.Add("status")
    }
    if ($Data.release.audit.status -ne "passed") { $missing.Add("audit.status") }
    if (-not $Data.release.audit.evidence) { $missing.Add("audit.evidence") }
    if (-not $Data.release.repository) { $missing.Add("release.repository") }
    foreach ($field in @(
        "releaseId", "tag", "tagObjectSha", "tagMessage", "peeledCommit",
        "url", "publishedAt"
    )) {
        if (-not $Data.release.$field) { $missing.Add("release.$field") }
    }
    if ($null -eq $Data.release.body.bytes) { $missing.Add("release.body.bytes") }
    if (-not $Data.release.body.sha256) { $missing.Add("release.body.sha256") }
    foreach ($asset in $Data.release.assets) {
        if (-not $asset.name) { $missing.Add("$($asset.role).name") }
        if (-not $asset.assetId) { $missing.Add("$($asset.name).assetId") }
        if (-not $asset.url) { $missing.Add("$($asset.name).url") }
    }
    if ($missing.Count) {
        throw "ARM64 Vim public immutable release locator is unresolved: $($missing -join ', ')"
    }
    Assert-Equal $Data.source.repository $Data.release.repository `
        "The release repository is not the source fork"
    if (-not $AllowUnmeasured -and
        ($null -eq $Data.expected.distributionBytesDelta.installer -or
        $null -eq $Data.expected.distributionBytesDelta.portable)) {
        throw "ARM64 Vim admission is missing measured distribution byte deltas"
    }
    Assert-Equal 0 ([int64]$Data.expected.distributionBytesDelta.mingit) `
        "ARM64 Vim admission permits a MinGit byte delta"
    Assert-Equal 0 ([int64]$Data.expected.distributionBytesDelta.busyboxMingit) `
        "ARM64 Vim admission permits a BusyBox MinGit byte delta"
}

function Get-PublicAssets($Data) {
    if ($TestMode) {
        return @{}
    }
    $headers = @{ "User-Agent" = "Git-for-Windows-build-extra" }
    $prApi = "https://api.github.com/repos/$($Data.source.repository)/pulls/$($Data.source.pullRequest)"
    $pr = Invoke-RestMethod -Headers $headers -Uri $prApi
    Assert-Equal "open" $pr.state "The source pull request is not open"
    Assert-Equal $false $pr.merged "The source pull request is merged"
    Assert-Equal $Data.source.commit $pr.head.sha "The source pull request head changed"
    $runApi = "https://api.github.com/repos/$($Data.source.repository)/actions/runs/$($Data.source.workflowRun)"
    $run = Invoke-RestMethod -Headers $headers -Uri $runApi
    Assert-Equal "pull_request" $run.event "The source workflow was not a pull_request run"
    Assert-Equal 1 $run.run_attempt "The source workflow run was retried"
    Assert-Equal "completed" $run.status "The source workflow run is not complete"
    Assert-Equal "success" $run.conclusion "The source workflow run did not succeed"
    Assert-Equal $Data.source.commit $run.head_sha "The source workflow did not run at the locked commit"
    $runPullRequests = @($run.pull_requests)
    Assert-Equal 1 $runPullRequests.Count "The source workflow has an unexpected PR association"
    Assert-Equal ([long]$Data.source.pullRequest) ([long]$runPullRequests[0].number) `
        "The source workflow belongs to a different pull request"
    Assert-Equal $Data.source.commit $runPullRequests[0].head.sha `
        "The source workflow PR association has a different head"
    Assert-Equal "https://api.github.com/repos/$($Data.source.repository)" `
        $runPullRequests[0].head.repo.url "The source workflow PR belongs to a different fork"
    $jobs = Invoke-RestMethod -Headers $headers -Uri "$runApi/jobs?per_page=100"
    $nativeJobs = @($jobs.jobs | Where-Object {
        $_.conclusion -eq "success" -and
        @($_.labels) -contains $Data.source.runner -and
        $_.name -match "(CLANGARM64|aarch64|ARM64)"
    })
    if (-not $nativeJobs.Count) {
        throw "The source workflow has no successful $($Data.source.runner) job"
    }
    $refApi = "https://api.github.com/repos/$($Data.release.repository)/git/ref/tags/$($Data.release.tag)"
    $ref = Invoke-RestMethod -Headers $headers -Uri $refApi
    Assert-Equal "tag" $ref.object.type "The release tag is not annotated"
    Assert-Equal $Data.release.tagObjectSha $ref.object.sha "Unexpected annotated tag object"
    $tagApi = "https://api.github.com/repos/$($Data.release.repository)/git/tags/$($ref.object.sha)"
    $tag = Invoke-RestMethod -Headers $headers -Uri $tagApi
    Assert-Equal $Data.release.tagMessage $tag.message "Unexpected annotated tag message"
    Assert-Equal "commit" $tag.object.type "The annotated tag does not target a commit"
    Assert-Equal $Data.source.commit $tag.object.sha "The annotated tag targets the wrong commit"
    Assert-Equal $Data.release.peeledCommit $tag.object.sha "The peeled release commit changed"
    $api = "https://api.github.com/repos/$($Data.release.repository)/releases/$($Data.release.releaseId)"
    $release = Invoke-RestMethod -Headers $headers -Uri $api
    Assert-Equal $false $release.draft "The ARM64 Vim release is still a draft"
    Assert-Equal $true $release.prerelease "The ARM64 Vim release is not a prerelease"
    if (-not $release.published_at) {
        throw "The ARM64 Vim release is not published"
    }
    Assert-Equal ([long]$Data.release.releaseId) ([long]$release.id) "Unexpected release ID"
    Assert-Equal $Data.release.tag $release.tag_name "Unexpected release tag"
    Assert-Equal $Data.release.url $release.html_url "Unexpected public release URL"
    Assert-Equal $Data.release.publishedAt $release.published_at "Unexpected release publication time"
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes([string]$release.body)
    Assert-Equal ([long]$Data.release.body.bytes) ([long]$bodyBytes.Length) "Unexpected release body size"
    $bodyHash = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash($bodyBytes)
    ).Replace("-", "").ToLowerInvariant()
    Assert-Equal $Data.release.body.sha256 $bodyHash "Unexpected release body SHA-256"
    Assert-Equal 3 @($Data.release.assets).Count "Unexpected locked release asset count"
    Assert-Equal 3 @($release.assets).Count "Unexpected public release asset count"
    Assert-SetEqual @($Data.release.assets.assetId | ForEach-Object { [string]$_ }) `
        @($release.assets.id | ForEach-Object { [string]$_ }) "Unexpected public release asset IDs"
    $result = @{}
    foreach ($locked in $Data.release.assets) {
        $asset = @($release.assets | Where-Object { [long]$_.id -eq [long]$locked.assetId })
        if ($asset.Count -ne 1) {
            throw "Could not resolve immutable asset ID $($locked.assetId)"
        }
        Assert-Equal $locked.name $asset[0].name "Unexpected asset name"
        Assert-Equal ([long]$locked.bytes) ([long]$asset[0].size) "Unexpected public asset size"
        Assert-Equal $locked.url $asset[0].browser_download_url "Unexpected asset URL"
        if ($asset[0].digest) {
            Assert-Equal "sha256:$($locked.sha256)" $asset[0].digest "Unexpected public asset digest"
        }
        $result[$locked.name] = $asset[0]
    }
    return $result
}

function Resolve-Package([object]$Asset, [string]$Destination, $PublicAssets) {
    if ($TestMode) {
        if (-not $PackageDirectory) {
            throw "-PackageDirectory is required with -TestMode"
        }
        Copy-Item -LiteralPath (Join-Path $PackageDirectory $Asset.name) -Destination $Destination
    } else {
        $assetApi = "https://api.github.com/repos/$($script:data.release.repository)/releases/assets/$($Asset.assetId)"
        Invoke-WebRequest -UseBasicParsing -Headers @{
            "User-Agent" = "Git-for-Windows-build-extra"
            "Accept" = "application/octet-stream"
        } -Uri $assetApi -OutFile $Destination
    }
    Assert-Equal ([long]$Asset.bytes) (Get-Item -LiteralPath $Destination).Length "Unexpected asset size"
    Assert-Equal $Asset.sha256 (Get-Sha256 $Destination) "Unexpected asset SHA-256"
}

function Get-PackageMetadata([string]$Member) {
    if ($TestMode) {
        return [pscustomobject]@{
            Name = "synthetic-base"
            Version = "synthetic"
        }
    }
    $owners = [Collections.Generic.List[string]]::new()
    $database = Join-Path $Root "var\lib\pacman\local"
    foreach ($directory in Get-ChildItem -LiteralPath $database -Directory) {
        $files = Join-Path $directory.FullName "files"
        if (-not (Test-Path -LiteralPath $files -PathType Leaf) -or
            -not (@(Get-Content -LiteralPath $files) -contains $Member)) {
            continue
        }
        $desc = Join-Path $directory.FullName "desc"
        $lines = @(Get-Content -LiteralPath $desc)
        $index = [Array]::IndexOf($lines, "%NAME%")
        if ($index -lt 0 -or $index + 1 -ge $lines.Count) {
            throw "Could not read the package owner for $Member"
        }
        $versionIndex = [Array]::IndexOf($lines, "%VERSION%")
        if ($versionIndex -lt 0 -or $versionIndex + 1 -ge $lines.Count) {
            throw "Could not read the package version for $Member"
        }
        $owners.Add("$($lines[$index + 1])`t$($lines[$versionIndex + 1])")
    }
    Assert-Equal 1 $owners.Count "Unexpected package ownership for $Member"
    $fields = $owners[0] -split "`t", 2
    return [pscustomobject]@{
        Name = $fields[0]
        Version = $fields[1]
    }
}

function Get-PackageOwner([string]$Member) {
    return (Get-PackageMetadata $Member).Name
}

function Get-DependencyClosure($Stage) {
    $candidate = @($Stage.files | Where-Object type -eq "pe")
    $dependencyDirectory = Join-Path $Root "clangarm64\bin"
    $available = @{}
    foreach ($file in Get-ChildItem -LiteralPath $dependencyDirectory -Filter "*.dll" -File) {
        $key = $file.Name.ToLowerInvariant()
        if ($available.ContainsKey($key)) {
            throw "Case-colliding native dependency '$($file.Name)'"
        }
        $available[$key] = $file.FullName
    }
    if ($TestMode) {
        $dependencies = @("libiconv-2.dll", "libintl-8.dll")
        return @($dependencies | ForEach-Object {
            $path = $available[$_.ToLowerInvariant()]
            if (-not $path) {
                throw "Missing native Vim dependency clangarm64/bin/$_"
            }
            if ((Get-PeMachine $path) -ne 0xAA64) {
                throw "clangarm64/bin/$_ is not ARM64"
            }
            [pscustomobject][ordered]@{
                package = Get-PackageOwner "clangarm64/bin/$_"
                sourceInput = "base"
                sourceMember = "clangarm64/bin/$_"
                destinationPath = "usr/bin/$_"
                type = "pe"
                copy = $true
                bytes = (Get-Item -LiteralPath $path).Length
                sha256 = Get-Sha256 $path
            }
        })
    }

    $dependencyRecords = [Collections.Generic.List[object]]::new()
    $scanEntries = [Collections.Generic.List[object]]::new()
    $selectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($locked in $data.expected.baseDependencyClosure.pes) {
        $path = Join-Path $Root $locked.sourceMember
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Missing admitted base dependency $($locked.sourceMember)"
        }
        Assert-Equal ([long]$locked.bytes) (Get-Item -LiteralPath $path).Length `
            "Unexpected base dependency size"
        Assert-Equal $locked.sha256 (Get-Sha256 $path) "Unexpected base dependency SHA-256"
        $owner = Get-PackageMetadata $locked.sourceMember
        Assert-Equal $locked.package $owner.Name `
            "Unexpected base dependency package owner"
        $package = @($data.expected.baseDependencyClosure.packages |
            Where-Object name -eq $owner.Name)
        Assert-Equal 1 $package.Count "Could not resolve locked base dependency package"
        Assert-Equal $package[0].version $owner.Version `
            "Unexpected base dependency package version"
        Assert-Equal 0xAA64 (Get-PeMachine $path) "Base dependency is not ARM64"
        [void]$selectedNames.Add([IO.Path]::GetFileName($path))
        $record = [pscustomobject][ordered]@{
            package = $locked.package
            sourceInput = "base"
            sourceMember = $locked.sourceMember
            destinationPath = $locked.sourceMember
            type = "pe"
            copy = $false
            bytes = [long]$locked.bytes
            sha256 = $locked.sha256
        }
        $dependencyRecords.Add($record)
        $scanEntries.Add([pscustomobject]@{
            Identity = "base:$($locked.sourceMember)"
            Path = $path
        })
    }
    foreach ($name in $data.expected.baseDependencyClosure.loaderCopies) {
        $locked = @($data.expected.baseDependencyClosure.pes | Where-Object {
            [IO.Path]::GetFileName($_.sourceMember) -eq $name
        })
        Assert-Equal 1 $locked.Count "Could not resolve admitted loader dependency"
        $record = [pscustomobject][ordered]@{
            package = $locked[0].package
            sourceInput = "base"
            sourceMember = $locked[0].sourceMember
            destinationPath = "usr/bin/$name"
            type = "pe"
            copy = $true
            bytes = [long]$locked[0].bytes
            sha256 = $locked[0].sha256
        }
        $dependencyRecords.Add($record)
        $scanEntries.Add([pscustomobject]@{
            Identity = "loader:$name"
            Path = Join-Path $Root $locked[0].sourceMember
        })
    }

    $systemDlls = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot "System32") -File |
        Where-Object { $_.Extension -in @(".dll", ".drv") } |
        ForEach-Object { [void]$systemDlls.Add($_.Name) }
    $queue = [Collections.Generic.Queue[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $candidate) {
        $queue.Enqueue([pscustomobject]@{
            Identity = "candidate:$($record.destinationPath)"
            Path = Join-Path (Join-Path $cache $record.package) $record.sourceMember
        })
    }
    foreach ($entry in $scanEntries) {
        $queue.Enqueue($entry)
    }
    $importCount = 0
    while ($queue.Count) {
        $entry = $queue.Dequeue()
        if (-not $seen.Add($entry.Identity)) {
            continue
        }
        if ((Get-PeMachine $entry.Path) -ne 0xAA64) {
            throw "$($entry.Path) is not ARM64"
        }
        $output = @(& $Scanner $entry.Path 2>&1)
        $imports = @($output | ForEach-Object {
            if ([string]$_ -match "^\s*DLL Name:\s*(\S+)\s*$") {
                $Matches[1]
            }
        })
        $importCount += $imports.Count
        foreach ($import in $imports) {
            if ($import -match "^(api|ext)-ms-" -or $systemDlls.Contains($import)) {
                continue
            }
            $dependency = $available[$import.ToLowerInvariant()]
            if (-not $dependency) {
                throw "Unresolved native Vim import '$import' from $($entry.Path)"
            }
            if (-not $selectedNames.Contains([IO.Path]::GetFileName($dependency))) {
                throw "Native Vim import '$import' is outside the admitted dependency closure"
            }
        }
    }
    Assert-Equal ([int]$data.expected.candidateAndDependencyPeCount) $seen.Count `
        "Unexpected native Vim PE closure count"
    Assert-Equal ([int]$data.expected.importCount) $importCount `
        "Unexpected native Vim import count"
    Assert-Equal 0 ([int]$data.expected.unresolvedImports) `
        "The native Vim closure permits unresolved imports"
    return @($dependencyRecords)
}

function Invoke-Stage($Data) {
    $script:data = $Data
    $publicAssets = Get-PublicAssets $Data
    if (Test-Path -LiteralPath $cache) {
        Remove-Item -Recurse -Force -LiteralPath $cache
    }
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    $destinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $records = [Collections.Generic.List[object]]::new()
    try {
        $evidence = @($Data.release.assets | Where-Object role -eq "evidence")
        if ($evidence.Count -ne 1) {
            throw "The lock must contain exactly one evidence asset"
        }
        $evidencePath = Join-Path $cache $evidence[0].name
        Resolve-Package $evidence[0] $evidencePath $publicAssets
        Remove-Item -LiteralPath $evidencePath
        foreach ($package in $Data.packages) {
            $asset = @($Data.release.assets | Where-Object {
                $_.role -eq "package" -and $_.name -eq $package.asset
            })
            if ($asset.Count -ne 1) {
                throw "Package $($package.name) does not resolve exactly one locked asset"
            }
            $archive = Join-Path $cache $asset[0].name
            Resolve-Package $asset[0] $archive $publicAssets
            $members = Get-ArchiveMembers $archive
            foreach ($member in $members) {
                Assert-AllowedMember $package $member
            }
            $packageRoot = Join-Path $cache $package.name
            New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null
            $tarOutput = @(& $windowsTar -xf $archive -C $packageRoot 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Could not extract $($asset[0].name)`: $($tarOutput -join ' | ')"
            }
            $links = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
            if ($links.Count) {
                throw "Package $($package.name) contains a symbolic link or reparse point"
            }
            Assert-PkgInfo $package (Join-Path $packageRoot ".PKGINFO")
            Assert-BuildInfo $package (Join-Path $packageRoot ".BUILDINFO")
            $files = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File -Force)
            Assert-SetEqual @($members) @($files | ForEach-Object {
                Get-RelativePath $packageRoot $_.FullName
            }) "Extracted inventory does not match $($package.name)"
            foreach ($file in $files) {
                $member = Get-RelativePath $packageRoot $file.FullName
                if ($metadataMembers -contains $member) {
                    continue
                }
                Assert-AllowedMember $package $member
                $destination = Get-Destination $member
                if (-not $destinations.Add($destination)) {
                    throw "Duplicate or case-colliding destination '$destination'"
                }
                $machine = Get-PeMachine $file.FullName
                if ($member -match "\.exe$") {
                    if ($null -eq $machine -or $machine -ne 0xAA64) {
                        throw "$member is not an ARM64 PE"
                    }
                } elseif ($null -ne $machine) {
                    throw "Runtime package unexpectedly contains PE '$member'"
                }
                $records.Add([ordered]@{
                    package = $package.name
                    sourceMember = $member
                    destinationPath = $destination
                    type = if ($null -eq $machine) { "file" } else { "pe" }
                    bytes = $file.Length
                    sha256 = Get-Sha256 $file.FullName
                })
            }
        }
        $actualReplacements = @($records |
            Where-Object { $_.type -eq "pe" } |
            ForEach-Object { $_.destinationPath })
        Assert-SetEqual $expectedReplacements $actualReplacements "The Vim PE replacement set is incomplete"
        $stage = [ordered]@{
            schemaVersion = 1
            lockSha256 = Get-Sha256 $Lock
            files = @($records)
        }
        $stage | ConvertTo-Json -Depth 8 |
            Set-Content -Encoding ascii -LiteralPath (Join-Path $cache "stage.json")
        @(
            @($records | ForEach-Object { $_.destinationPath })
            @($Data.expected.baseDependencyClosure.pes |
                ForEach-Object { $_.sourceMember })
        ) | Sort-Object -Unique |
            Set-Content -Encoding ascii -LiteralPath (Join-Path $cache "payload-paths.txt")
        if (-not $TestMode) {
            Get-PublicAssets $Data | Out-Null
        }
    } catch {
        if (Test-Path -LiteralPath $cache) {
            Remove-Item -Recurse -Force -LiteralPath $cache
        }
        throw
    }
}

function Invoke-Finalize($Data) {
    $stagePath = Join-Path $cache "stage.json"
    if (-not (Test-Path -LiteralPath $stagePath)) {
        throw "ARM64 Vim packages were not staged"
    }
    $stage = Get-Content -Raw -LiteralPath $stagePath | ConvertFrom-Json
    Assert-Equal (Get-Sha256 $Lock) $stage.lockSha256 "The ARM64 Vim lock changed after staging"
    $dependencyRecords = @(Get-DependencyClosure $stage)
    $allRecords = @($stage.files) + $dependencyRecords
    $vimTutor = Join-Path $Root "usr\bin\vimtutor"
    if (-not (Test-Path -LiteralPath $vimTutor -PathType Leaf)) {
        throw "The MSYS-owned usr/bin/vimtutor is missing"
    }
    $vimTutorHash = Get-Sha256 $vimTutor
    $busyBoxReplacements = Join-Path $Root "etc\arm64-busybox-replacements.tsv"
    if (Test-Path -LiteralPath $busyBoxReplacements) {
        $busyBoxPaths = @(Get-Content -LiteralPath $busyBoxReplacements |
            ForEach-Object { ($_ -split "`t")[0].Replace("\", "/").TrimStart("/") })
        $overlap = Compare-Object $expectedReplacements $busyBoxPaths -IncludeEqual -ExcludeDifferent
        if ($overlap) {
            throw "The Vim replacements overlap the BusyBox layer"
        }
    }
    foreach ($path in $expectedReplacements) {
        $destination = Join-Path $Root $path
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw "Missing legacy Vim replacement $path"
        }
        $stageRecord = @($stage.files | Where-Object { $_.destinationPath -eq $path })
        $installedHash = Get-Sha256 $destination
        if ($stageRecord.Count -ne 1) {
            throw "Missing staged ownership for $path"
        }
        if ($installedHash -ne $stageRecord[0].sha256 -and
            (Get-PeMachine $destination) -ne 0x8664) {
            throw "Legacy Vim replacement $path is not x64"
        }
    }
    foreach ($record in @($dependencyRecords | Where-Object copy)) {
        $destination = Join-Path $Root $record.destinationPath
        if (Test-Path -LiteralPath $destination) {
            throw "Native Vim dependency destination collides with $($record.destinationPath)"
        }
    }
    $provenance = [Collections.Generic.List[object]]::new()
    $dependencyProvenance = [Collections.Generic.List[object]]::new()
    foreach ($record in @($allRecords | Sort-Object destinationPath)) {
        $source = if ($record.sourceInput -eq "base") {
            Join-Path $Root $record.sourceMember
        } else {
            Join-Path (Join-Path $cache $record.package) $record.sourceMember
        }
        $destination = Join-Path $Root $record.destinationPath
        $preservedBase = $record.sourceInput -eq "base" -and
            $record.destinationPath -eq $record.sourceMember
        $replaces = if (-not $preservedBase -and (Test-Path -LiteralPath $destination)) {
            "base"
        } else {
            $null
        }
        if (-not $preservedBase) {
            $parent = Split-Path -Parent $destination
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
            $temporary = "$destination.arm64-vim-$PID"
            Copy-Item -LiteralPath $source -Destination $temporary
            Move-Item -Force -LiteralPath $temporary -Destination $destination
        }
        Assert-Equal $record.sha256 (Get-Sha256 $destination) "Installed file hash mismatch"
        $provenanceRecord = [ordered]@{
            sourceInput = if ($record.sourceInput) { $record.sourceInput } else { $Data.inputId }
            sourcePackage = $record.package
            sourceMember = $record.sourceMember
            destinationPath = $record.destinationPath
            type = "file"
            bytes = $record.bytes
            sha256 = $record.sha256
            replacesSourceInput = $replaces
        }
        if ($record.type -eq "pe") {
            $provenanceRecord.peMachine = "0xAA64"
        }
        if ($record.sourceInput -eq "base") {
            $dependencyProvenance.Add($provenanceRecord)
        } else {
            $provenance.Add($provenanceRecord)
        }
    }
    Assert-Equal $vimTutorHash (Get-Sha256 $vimTutor) "usr/bin/vimtutor changed during integration"
    $manifest = [ordered]@{
        schemaVersion = 1
        mode = "final"
        inputId = $Data.inputId
        lockSha256 = Get-Sha256 $Lock
        source = $Data.source
        release = $Data.release
        expected = $Data.expected
        packageProvides = @($Data.packages[0].provides)
        files = @($provenance)
        dependencyClosure = @($dependencyProvenance)
        retained = @(
            [ordered]@{
                destinationPath = "usr/bin/vimtutor"
                sourceInput = "base"
                sha256 = $vimTutorHash
            }
        )
    }
    $etc = Join-Path $Root "etc"
    New-Item -ItemType Directory -Force -Path $etc | Out-Null
    $manifest | ConvertTo-Json -Depth 12 |
        Set-Content -Encoding ascii -LiteralPath (Join-Path $etc "arm64-vim-provenance.json")
    @($provenance + $dependencyProvenance |
        ForEach-Object { $_.destinationPath } | Sort-Object) |
        Set-Content -Encoding ascii -LiteralPath (Join-Path $etc "arm64-vim-payload.txt")
    Remove-Item -Recurse -Force -LiteralPath $cache
}

$data = Get-Content -Raw -LiteralPath $Lock | ConvertFrom-Json
Assert-Lock $data
if ($data.status -notin @("unresolved", "measuring", "admitted")) {
    throw "Unknown ARM64 Vim admission status '$($data.status)'"
}
if ($data.status -ne "admitted") {
    if ($data.status -eq "measuring" -and $MeasurementMode) {
        Assert-Admitted $data -AllowUnmeasured
    } elseif ($RequireAdmission) {
        if ($data.status -eq "measuring") {
            throw "ARM64 Vim input is public but requires explicit measurement mode"
        }
        Assert-Admitted $data
    } else {
        Write-Host "::notice::Native ARM64 Vim integration skipped: admission or exact distribution measurements are unresolved."
        exit 0
    }
} else {
    Assert-Admitted $data
}
if ($Phase -eq "Probe") {
    Write-Output "admitted"
    exit 0
}
if ($Phase -eq "Stage") {
    Invoke-Stage $data
} else {
    Invoke-Finalize $data
}
