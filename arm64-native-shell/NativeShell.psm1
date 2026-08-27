Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NativeShellSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-NativeShellProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "$Context is missing '$Name'"
    }
    return $property.Value
}

function Assert-NativeShellPathSegment {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Segment,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if (-not $Segment -or $Segment -in @(".", "..") -or
        $Segment -match "[\x00-\x1f<>:`"|\?\*]" -or
        $Segment.EndsWith(".") -or $Segment.EndsWith(" ") -or
        $Segment -match "^(?i:con|prn|aux|nul|clock`$|conin`$|conout`$|com[1-9]|lpt[1-9])(?:\..*)?`$") {
        throw "Unsafe $Context segment: '$Segment'"
    }
}

function Assert-NativeShellRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Context = "path"
    )

    if (-not $Path -or
        $Path.StartsWith("/") -or
        $Path.StartsWith("\") -or
        $Path -match "^[A-Za-z]:" -or
        $Path -match "^(\\\\|//)[.?]/" -or
        $Path.Contains("\")) {
        throw "Unsafe $Context`: '$Path'"
    }

    $segments = @($Path.Split("/"))
    if ($segments.Count -eq 0) {
        throw "Unsafe $Context`: '$Path'"
    }
    foreach ($segment in $segments) {
        Assert-NativeShellPathSegment $segment $Context
    }
    return $segments -join "/"
}

function Assert-NativeShellLinkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Member,
        [Parameter(Mandatory = $true)][string]$Target
    )

    $memberPath = Assert-NativeShellRelativePath $Member "link member"
    if (-not $Target -or
        $Target.StartsWith("/") -or
        $Target.StartsWith("\") -or
        $Target -match "^[A-Za-z]:" -or
        $Target.Contains("\")) {
        throw "Unsafe link target '$Target' for '$Member'"
    }

    $memberSegments = @($memberPath.Split("/"))
    $stack = [Collections.Generic.List[string]]::new()
    if ($memberSegments.Count -gt 1) {
        foreach ($segment in $memberSegments[0..($memberSegments.Count - 2)]) {
            $stack.Add($segment)
        }
    }
    foreach ($segment in $Target.Split("/")) {
        switch ($segment) {
            "" { throw "Unsafe link target '$Target' for '$Member'" }
            "." { continue }
            ".." {
                if ($stack.Count -eq 0) {
                    throw "Link target escapes the extraction root: '$Member' -> '$Target'"
                }
                $stack.RemoveAt($stack.Count - 1)
            }
            default {
                Assert-NativeShellPathSegment $segment "link target"
                $stack.Add($segment)
            }
        }
    }
}

function Assert-NativeShellSetEqual {
    param(
        [AllowEmptyCollection()][object[]]$Expected,
        [AllowEmptyCollection()][object[]]$Actual,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $expectedSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $actualSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($value in $Expected) {
        [void]$expectedSet.Add([string]$value)
    }
    foreach ($value in $Actual) {
        [void]$actualSet.Add([string]$value)
    }
    if (-not $expectedSet.SetEquals($actualSet)) {
        throw "$Context differs"
    }
}

function Read-NativeShellLock {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    return Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -Depth 100
}

function Test-NativeShellLock {
    param(
        [Parameter(Mandatory = $true)][object]$Lock,
        [ValidateSet("Preview", "Final")][string]$Mode = "Preview"
    )

    if ((Get-NativeShellProperty $Lock "schemaVersion" "lock") -ne 1) {
        throw "Unsupported native shell lock schema"
    }
    foreach ($name in @(
        "sourceDateEpoch", "state", "legacyBaseline",
        "authoritativeGate", "pseudoRelocGate",
        "nativeCompilerProof", "inputs", "nativeShellClosure",
        "finalRequiredInputs", "allowedPayloadDestinationPrefixes",
        "forbiddenPayloadSourcePrefixes",
        "collisionPolicy", "smokeContract"
    )) {
        $null = Get-NativeShellProperty $Lock $name "lock"
    }
    $gateStatus = [string](Get-NativeShellProperty $Lock.authoritativeGate (
        "status") "authoritative gate")
    if ($gateStatus -eq "unresolved") {
        foreach ($field in @("identity", "reportContract", "runtimeEvidenceContract")) {
            if ($null -ne (Get-NativeShellProperty $Lock.authoritativeGate $field (
                "authoritative gate"))) {
                throw "Unresolved authoritative gate must keep $field null"
            }
        }
        $gateUnresolvedFields = @(
            Get-NativeShellProperty $Lock.authoritativeGate "unresolvedFields" (
                "authoritative gate")
        )
        if ($gateUnresolvedFields.Count -eq 0) {
            throw "Unresolved authoritative gate has no exact unresolved fields"
        }
    } elseif ($gateStatus -eq "resolved") {
        foreach ($field in @("identity", "reportContract", "runtimeEvidenceContract")) {
            if ($null -eq (Get-NativeShellProperty $Lock.authoritativeGate $field (
                "authoritative gate"))) {
                throw "Resolved authoritative gate is missing $field"
            }
        }
        $gateIdentity = $Lock.authoritativeGate.identity
        foreach ($field in @("repository", "commit", "path", "bytes", "sha256")) {
            $value = Get-NativeShellProperty $gateIdentity $field (
                "authoritative gate identity")
            if (-not $value) {
                throw "Authoritative gate identity has an empty $field"
            }
        }
        $null = Assert-NativeShellRelativePath ([string]$gateIdentity.path) (
            "authoritative gate path")
        if ([string]$gateIdentity.commit -notmatch "^[0-9a-f]{40}$" -or
            [int64]$gateIdentity.bytes -le 0 -or
            [string]$gateIdentity.sha256 -notmatch "^[0-9a-f]{64}$") {
            throw "Authoritative gate identity is invalid"
        }
    } else {
        throw "Invalid authoritative gate status '$gateStatus'"
    }

    $inputs = @($Lock.inputs)
    if (@($Lock.nativeShellClosure).Count -eq 0 -or
        @($Lock.finalRequiredInputs).Count -eq 0) {
        throw "Native shell closure and final required input lists must not be empty"
    }
    $ids = @{}
    $assetIds = @{}
    $assetNames = @{}
    $assetUrls = @{}
    $assetHashes = @{}
    $destinations = @{}
    $guardedLegacyPaths = @{}
    $linkMappings = [Collections.Generic.List[object]]::new()
    $unresolved = [Collections.Generic.List[object]]::new()

    foreach ($lockInput in $inputs) {
        $id = [string](Get-NativeShellProperty $lockInput "id" "input")
        if (-not $id -or $ids.ContainsKey($id)) {
            throw "Duplicate or empty input id '$id'"
        }
        $ids[$id] = $lockInput

        $requiredPayloadShape = $null
        $admissionProperty = $lockInput.PSObject.Properties["admission"]
        if ($admissionProperty -and $null -ne $admissionProperty.Value) {
            $shapeProperty = $admissionProperty.Value.PSObject.Properties[
                "requiredPayloadShape"]
            if ($shapeProperty) {
                $requiredPayloadShape = $shapeProperty.Value
                foreach ($field in @(
                    "peCount", "symlinkCount", "forbiddenDestinations"
                )) {
                    $null = Get-NativeShellProperty $requiredPayloadShape $field (
                        "required payload shape for '$id'")
                }
                if ([int]$requiredPayloadShape.peCount -lt 0 -or
                    [int]$requiredPayloadShape.symlinkCount -lt 0) {
                    throw "Input '$id' has invalid required payload counts"
                }
                foreach ($path in @($requiredPayloadShape.forbiddenDestinations)) {
                    $null = Assert-NativeShellRelativePath ([string]$path) (
                        "forbidden payload destination for '$id'")
                }
            }
            $omittedProperty = $admissionProperty.Value.PSObject.Properties[
                "omittedLegacyMembers"]
            if ($omittedProperty) {
                foreach ($member in @($omittedProperty.Value)) {
                    foreach ($field in @(
                        "path", "kind", "bytes", "sha256", "finalDisposition",
                        "requiredImportName", "proofScope"
                    )) {
                        $null = Get-NativeShellProperty $member $field (
                            "omitted legacy member for '$id'")
                    }
                    $path = Assert-NativeShellRelativePath ([string]$member.path) (
                        "omitted legacy member path for '$id'")
                    $key = $path.ToLowerInvariant()
                    if ($guardedLegacyPaths.ContainsKey($key)) {
                        throw "Duplicate guarded legacy removal '$path'"
                    }
                    $guardedLegacyPaths[$key] = $true
                    if ([string]$member.kind -ne "pe" -or
                        [int64]$member.bytes -le 0 -or
                        [string]$member.sha256 -notmatch "^[0-9a-f]{64}$" -or
                        [string]$member.finalDisposition -ne
                            "remove-after-zero-reverse-imports" -or
                        [string]$member.proofScope -ne "post-overlay-all-files" -or
                        [string]$member.requiredImportName -cne
                            [IO.Path]::GetFileName($path)) {
                        throw "Input '$id' has an invalid guarded legacy removal '$path'"
                    }
                }
            }
        }

        $status = [string](Get-NativeShellProperty $lockInput "status" "input '$id'")
        $shipPolicy = [string](Get-NativeShellProperty $lockInput "shipPolicy" "input '$id'")
        if ($status -eq "unresolved") {
            foreach ($field in @("identity", "asset", "package", "overlay")) {
                if ($null -ne (Get-NativeShellProperty $lockInput $field "input '$id'")) {
                    throw "Unresolved input '$id' must keep $field null"
                }
            }
            if ($null -eq (Get-NativeShellProperty $lockInput "admission" "input '$id'")) {
                throw "Unresolved input '$id' has no admission contract"
            }
            $fields = @(
                Get-NativeShellProperty $lockInput "unresolvedFields" "input '$id'" |
                    ForEach-Object { [string]$_ }
            )
            if ($fields.Count -eq 0 -or $fields | Where-Object { -not $_ }) {
                throw "Unresolved input '$id' has no exact unresolved fields"
            }
            $unresolved.Add([ordered]@{
                id = $id
                fields = @($fields)
            })
            continue
        }
        if ($status -ne "resolved") {
            throw "Input '$id' has invalid status '$status'"
        }

        $identity = Get-NativeShellProperty $lockInput "identity" "input '$id'"
        $asset = Get-NativeShellProperty $lockInput "asset" "input '$id'"
        foreach ($field in @("repository", "releaseId", "tag", "commit")) {
            $value = Get-NativeShellProperty $identity $field "identity for '$id'"
            if (-not $value) {
                throw "Input '$id' has an empty identity.$field"
            }
        }
        if ([string]$identity.commit -notmatch "^[0-9a-f]{40}$") {
            throw "Input '$id' has an invalid producer commit"
        }

        foreach ($field in @("id", "name", "url", "expectedBytes", "sha256", "format")) {
            $value = Get-NativeShellProperty $asset $field "asset for '$id'"
            if (-not $value) {
                throw "Input '$id' has an empty asset.$field"
            }
        }
        if ([int64]$asset.expectedBytes -le 0 -or
            [string]$asset.sha256 -notmatch "^[0-9a-f]{64}$") {
            throw "Input '$id' has an invalid asset size or SHA-256"
        }
        $assetUri = [Uri]$asset.url
        $decodedPath = [Uri]::UnescapeDataString($assetUri.AbsolutePath)
        if (-not $decodedPath.EndsWith("/$($asset.name)", [StringComparison]::Ordinal)) {
            throw "Input '$id' asset URL does not end in its exact asset name"
        }
        $expectedPath = "/$($identity.repository)/releases/download/" +
            "$($identity.tag)/$($asset.name)"
        if ($assetUri.Scheme -ne "https" -or $assetUri.Host -ne "github.com" -or
            $decodedPath -ne $expectedPath) {
            throw "Input '$id' asset URL does not match its repository, tag, and name"
        }
        foreach ($pair in @(
            @($assetIds, [string]$asset.id, "asset id"),
            @($assetNames, [string]$asset.name, "asset name"),
            @($assetUrls, [string]$asset.url, "asset URL")
        )) {
            if ($pair[0].ContainsKey($pair[1])) {
                throw "Duplicate $($pair[2]) '$($pair[1])'"
            }
            $pair[0][$pair[1]] = $id
        }
        if ($assetHashes.ContainsKey([string]$asset.sha256) -and
            $assetHashes[[string]$asset.sha256] -ne $id) {
            throw "Duplicate asset SHA-256 '$($asset.sha256)'"
        }
        $assetHashes[[string]$asset.sha256] = $id

        $package = Get-NativeShellProperty $lockInput "package" "input '$id'"
        if ($null -ne $package) {
            foreach ($field in @("name", "version", "architecture", "provides", "depends")) {
                $null = Get-NativeShellProperty $package $field "package for '$id'"
            }
            if (-not $package.name -or -not $package.version -or
                $package.architecture -notin @("x86_64", "aarch64")) {
                throw "Input '$id' has incomplete package metadata"
            }
        }

        $overlay = Get-NativeShellProperty $lockInput "overlay" "input '$id'"
        $enabled = [bool](Get-NativeShellProperty $overlay "enabled" "overlay for '$id'")
        $mappings = @(
            Get-NativeShellProperty $overlay "mappings" "overlay for '$id'"
        )
        if ($shipPolicy -eq "forbidden" -and ($enabled -or $mappings.Count -ne 0)) {
            throw "Validation-only input '$id' cannot map files into the payload"
        }
        if ($shipPolicy -notin @("forbidden", "mapped-native-target-only")) {
            throw "Input '$id' has invalid ship policy '$shipPolicy'"
        }
        if ($enabled -ne ($mappings.Count -ne 0)) {
            throw "Input '$id' overlay enabled state does not match its mappings"
        }
        foreach ($mapping in $mappings) {
            $source = Assert-NativeShellRelativePath (
                [string](Get-NativeShellProperty $mapping "source" "mapping for '$id'")) "mapping source"
            $destination = Assert-NativeShellRelativePath (
                [string](Get-NativeShellProperty $mapping "destination" "mapping for '$id'")) "mapping destination"
            if (-not @(
                $Lock.allowedPayloadDestinationPrefixes |
                    Where-Object {
                        $destination.StartsWith(
                            [string]$_, [StringComparison]::OrdinalIgnoreCase)
                    }
            )) {
                throw "Input '$id' maps outside the native shell payload roots: '$destination'"
            }
            $null = Get-NativeShellProperty $mapping "allowOverwrite" "mapping for '$id'"
            $content = [string](Get-NativeShellProperty $mapping "content" "mapping for '$id'")
            if ($mapping.PSObject.Properties["variants"]) {
                throw "Variant-scoped native shell mappings are not supported"
            }
            if ($content -notin @("pe-aa64", "data", "script", "symlink", "hardlink")) {
                throw "Input '$id' mapping '$destination' has invalid content '$content'"
            }
            foreach ($prefix in @($Lock.forbiddenPayloadSourcePrefixes)) {
                if ($source.StartsWith([string]$prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Input '$id' maps forbidden cross-host source '$source'"
                }
            }
            $key = $destination.ToLowerInvariant()
            if ($destinations.ContainsKey($key)) {
                throw "Duplicate payload ownership for '$destination'"
            }
            $destinations[$key] = $id
            if ($content -eq "pe-aa64") {
                foreach ($field in @("bytes", "sha256")) {
                    $null = Get-NativeShellProperty $mapping $field "PE mapping '$destination'"
                }
                if ([int64]$mapping.bytes -le 0 -or
                    [string]$mapping.sha256 -notmatch "^[0-9a-f]{64}$") {
                    throw "Input '$id' mapping '$destination' has invalid PE identity"
                }
            }
            if ($content -in @("symlink", "hardlink")) {
                $sourceLinkTarget = [string](Get-NativeShellProperty $mapping (
                    "sourceLinkTarget") "link mapping '$destination'")
                $linkTarget = [string](Get-NativeShellProperty $mapping (
                    "linkTarget") "link mapping '$destination'")
                if ($content -eq "symlink") {
                    Assert-NativeShellLinkTarget $source $sourceLinkTarget
                    Assert-NativeShellLinkTarget $destination $linkTarget
                } else {
                    $null = Assert-NativeShellRelativePath $sourceLinkTarget (
                        "hardlink source target")
                    $null = Assert-NativeShellRelativePath $linkTarget (
                        "hardlink payload target")
                }
                $linkMappings.Add([ordered]@{
                    input = $id
                    content = $content
                    destination = $destination
                    target = $linkTarget
                })
            }
            if ([bool]$mapping.allowOverwrite) {
                foreach ($field in @(
                    "expectedDestinationBytes", "expectedDestinationSha256"
                )) {
                    $null = Get-NativeShellProperty $mapping $field (
                        "replacement mapping '$destination'")
                }
                if ([int64]$mapping.expectedDestinationBytes -le 0 -or
                    [string]$mapping.expectedDestinationSha256 -notmatch "^[0-9a-f]{64}$") {
                    throw "Input '$id' mapping '$destination' has invalid replacement identity"
                }
            }
            if ($requiredPayloadShape) {
                $peCount = @($mappings | Where-Object content -eq "pe-aa64").Count
                $symlinkCount = @($mappings | Where-Object content -eq "symlink").Count
                if ($peCount -ne [int]$requiredPayloadShape.peCount -or
                    $symlinkCount -ne [int]$requiredPayloadShape.symlinkCount) {
                    throw "Input '$id' resolved payload shape does not match admission"
                }
                foreach ($path in @($requiredPayloadShape.forbiddenDestinations)) {
                    if ($mappings.destination -ccontains [string]$path) {
                        throw "Input '$id' maps forbidden omitted member '$path'"
                    }
                }
            }
        }
    }

    foreach ($id in @($Lock.nativeShellClosure) + @($Lock.finalRequiredInputs)) {
        if (-not $ids.ContainsKey([string]$id)) {
            throw "Lock references unknown input '$id'"
        }
    }
    foreach ($link in $linkMappings | Where-Object content -eq "hardlink") {
        $targetKey = ([string]$link.target).ToLowerInvariant()
        if (-not $destinations.ContainsKey($targetKey) -or
            $destinations[$targetKey] -ne $link.input) {
            throw "Hardlink '$($link.destination)' crosses an input ownership boundary"
        }
    }
    if ($Mode -eq "Final") {
        $blocked = @(
            $Lock.finalRequiredInputs |
                Where-Object { $ids[[string]$_].status -ne "resolved" }
        )
        if ($blocked.Count -ne 0) {
            $details = @(
                $blocked | ForEach-Object {
                    $blockedInput = $ids[[string]$_]
                    "$_`: $(@($blockedInput.unresolvedFields) -join ', ')"
                }
            )
            throw "Native shell closure unresolved: $($details -join '; ')"
        }
        if ($gateStatus -ne "resolved") {
            throw "Authoritative ARM64 payload gate unresolved: $($gateUnresolvedFields -join ', ')"
        }
    }
    return @($unresolved)
}

function Get-NativeShellTar {
    param([string]$Tar)

    if ($Tar) {
        $tarPath = (Get-Command $Tar -CommandType Application -ErrorAction Stop).Source
        if ([IO.Path]::GetFullPath($tarPath).StartsWith(
            "C:\msys64\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "The shared C:\msys64 tar is a forbidden input"
        }
        return $tarPath
    }
    foreach ($name in @("tar.exe", "tar")) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
        if ($command) {
            if ([IO.Path]::GetFullPath($command.Source).StartsWith(
                "C:\msys64\", [StringComparison]::OrdinalIgnoreCase)) {
                throw "The shared C:\msys64 tar is a forbidden input"
            }
            return $command.Source
        }
    }
    throw "Could not find tar"
}

function Get-NativeShellArchiveInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [string]$Tar
    )

    $tarPath = Get-NativeShellTar $Tar
    $members = @(& $tarPath -tf $Archive)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list archive '$Archive'"
    }
    $seen = @{}
    $normalized = [Collections.Generic.List[string]]::new()
    $memberTypes = @{}
    $linkTargets = @{}
    foreach ($raw in $members) {
        $member = ([string]$raw).Trim()
        if (-not $member) {
            continue
        }
        while ($member.StartsWith("./", [StringComparison]::Ordinal)) {
            $member = $member.Substring(2)
        }
        $isDirectory = $member.EndsWith("/")
        if ($isDirectory) {
            $member = $member.TrimEnd("/")
        }
        if (-not $member) {
            continue
        }
        $member = Assert-NativeShellRelativePath $member "archive member"
        $key = $member.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            throw "Duplicate or case-colliding archive member '$member'"
        }
        $seen[$key] = $true
        $normalized.Add($(if ($isDirectory) { "$member/" } else { $member }))
        $memberTypes[$key] = $(if ($isDirectory) { "directory" } else { "file" })
    }

    $verbose = @(& $tarPath -tvf $Archive)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect archive links in '$Archive'"
    }
    foreach ($line in $verbose) {
        $text = [string]$line
        if (-not $text.StartsWith("l") -and -not $text.StartsWith("h")) {
            continue
        }
        $marker = if ($text.Contains(" -> ")) { " -> " } else { " link to " }
        $markerIndex = $text.IndexOf($marker, [StringComparison]::Ordinal)
        if ($markerIndex -lt 0) {
            throw "Could not parse archive link metadata: '$text'"
        }
        $left = $text.Substring(0, $markerIndex)
        $member = @(
            $normalized |
                Where-Object { -not $_.EndsWith("/") } |
                Sort-Object Length -Descending |
                Where-Object {
                    $left.EndsWith(" $_", [StringComparison]::Ordinal) -or
                    $left.EndsWith(" ./$_", [StringComparison]::Ordinal)
                } |
                Select-Object -First 1
        )
        if ($member.Count -ne 1) {
            throw "Could not identify archive link member: '$text'"
        }
        $target = $text.Substring($markerIndex + $marker.Length)
        if ($text.StartsWith("h") -and
            $target.StartsWith("./", [StringComparison]::Ordinal)) {
            $target = $target.Substring(2)
        }
        if (-not $target) {
            throw "Archive link has an empty target: '$($member[0])'"
        }
        if ($text.StartsWith("h")) {
            $null = Assert-NativeShellRelativePath $target "hardlink target"
            $linkTarget = $target
        } else {
            Assert-NativeShellLinkTarget $member[0] $target
            $fakeRoot = [IO.Path]::GetFullPath((Join-Path $PWD ".native-shell-link-root"))
            $fakeMember = Join-Path $fakeRoot $member[0].Replace("/", "\")
            $fakeTarget = [IO.Path]::GetFullPath(
                (Join-Path (Split-Path -Parent $fakeMember) $target.Replace("/", "\")))
            $linkTarget = [IO.Path]::GetRelativePath(
                $fakeRoot, $fakeTarget).Replace("\", "/")
        }
        $key = $member[0].ToLowerInvariant()
        $memberTypes[$key] = $(if ($text.StartsWith("h")) { "hardlink" } else { "symlink" })
        $linkTargets[$key] = $linkTarget
    }

    return [ordered]@{
        tar = $tarPath
        members = @($normalized)
        memberTypes = $memberTypes
        linkTargets = $linkTargets
        payloadMembers = @(
            $normalized |
                Where-Object {
                    -not $_.EndsWith("/") -and
                    $_ -notin @(".BUILDINFO", ".MTREE", ".PKGINFO")
                }
        )
    }
}

function Get-NativeShellPackageMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [string]$Tar
    )

    $tarPath = Get-NativeShellTar $Tar
    $lines = @(& $tarPath -xOf $Archive .PKGINFO)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) {
        throw "Could not read .PKGINFO from '$Archive'"
    }
    $metadata = @{}
    foreach ($line in $lines) {
        if ([string]$line -match "^([^#][^= ]*) = (.*)$") {
            $key = $Matches[1]
            if (-not $metadata.ContainsKey($key)) {
                $metadata[$key] = [Collections.Generic.List[string]]::new()
            }
            $metadata[$key].Add($Matches[2])
        }
    }
    return $metadata
}

function Test-NativeShellHardLinkPair {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Target
    )

    $pathItem = Get-Item -Force -LiteralPath $Path -ErrorAction SilentlyContinue
    $targetItem = Get-Item -Force -LiteralPath $Target -ErrorAction SilentlyContinue
    if ($null -eq $pathItem -or $null -eq $targetItem -or
        $pathItem.LinkType -ne "HardLink" -or $targetItem.LinkType -ne "HardLink") {
        return $false
    }

    $pathId = @(& fsutil.exe file queryfileid $Path 2>$null)
    if ($LASTEXITCODE -ne 0 -or $pathId.Count -ne 1) {
        throw "Could not query hardlink identity for '$Path'"
    }
    $targetId = @(& fsutil.exe file queryfileid $Target 2>$null)
    if ($LASTEXITCODE -ne 0 -or $targetId.Count -ne 1) {
        throw "Could not query hardlink identity for '$Target'"
    }
    return [string]$pathId[0] -eq [string]$targetId[0]
}

function Assert-NativeShellPackageMetadata {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Actual,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$InputId
    )

    foreach ($pair in @(
        @("pkgname", [string]$Expected.name),
        @("pkgver", [string]$Expected.version),
        @("arch", [string]$Expected.architecture)
    )) {
        if (-not $Actual.ContainsKey($pair[0]) -or
            @($Actual[$pair[0]]).Count -ne 1 -or
            $Actual[$pair[0]][0] -ne $pair[1]) {
            throw "Package metadata mismatch for '$InputId': $($pair[0])"
        }
    }
    if ($Expected.PSObject.Properties["base"] -and $Expected.base) {
        if (-not $Actual.ContainsKey("pkgbase") -or $Actual["pkgbase"][0] -ne $Expected.base) {
            throw "Package metadata mismatch for '$InputId': pkgbase"
        }
    }
    Assert-NativeShellSetEqual @($Expected.provides) @(
        if ($Actual.ContainsKey("provides")) { $Actual["provides"] } else { @() }
    ) "Package provides for '$InputId'"
    Assert-NativeShellSetEqual @($Expected.depends) @(
        if ($Actual.ContainsKey("depend")) { $Actual["depend"] } else { @() }
    ) "Package dependencies for '$InputId'"
}

function Expand-NativeShellArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][object]$Inventory,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        throw "Extraction directory must not exist: '$Destination'"
    }
    $null = New-Item -ItemType Directory -Path $Destination
    & $Inventory.tar -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract '$Archive'"
    }

    foreach ($member in @($Inventory.members | Where-Object { -not $_.EndsWith("/") })) {
        $path = Join-Path $Destination ($member.Replace("/", "\"))
        if ($null -eq (Get-Item -Force -LiteralPath $path -ErrorAction SilentlyContinue)) {
            throw "Archive extraction is missing '$member'"
        }
    }

    $actual = @(
        Get-ChildItem -Force -Recurse -LiteralPath $Destination |
            Where-Object { -not $_.PSIsContainer -or $_.LinkType } |
            ForEach-Object {
                [IO.Path]::GetRelativePath($Destination, $_.FullName).Replace("\", "/")
            }
    )
    $expected = @($Inventory.members | Where-Object { -not $_.EndsWith("/") })
    Assert-NativeShellSetEqual $expected $actual "Extracted archive members"

    foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $Destination) {
        if (-not $item.LinkType) {
            continue
        }
        $relative = [IO.Path]::GetRelativePath($Destination, $item.FullName).Replace("\", "/")
        if ($item.LinkType -eq "HardLink") {
            continue
        }
        if ($item.LinkType -ne "SymbolicLink") {
            throw "Unsupported extracted link type '$($item.LinkType)': '$relative'"
        }
        $linkTarget = ([string]$item.LinkTarget).Replace("\", "/")
        Assert-NativeShellLinkTarget $relative $linkTarget
        $resolved = $item.ResolveLinkTarget($true)
        if ($null -eq $resolved -or
            -not $resolved.FullName.StartsWith(
                ([IO.Path]::GetFullPath($Destination).TrimEnd("\") + "\"),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Extracted link escapes the extraction root: '$relative'"
        }
    }
}

function Test-NativeShellResolvedInput {
    param(
        [Parameter(Mandatory = $true)][object]$PackageInput,
        [Parameter(Mandatory = $true)][string]$Archive,
        [string]$ExtractTo,
        [string]$Tar
    )

    $item = Get-Item -LiteralPath $Archive
    if ($item.Length -ne [int64]$PackageInput.asset.expectedBytes) {
        throw "Asset size mismatch for '$($PackageInput.id)'"
    }
    $hash = Get-NativeShellSha256 $Archive
    if ($hash -ne [string]$PackageInput.asset.sha256) {
        throw "Asset SHA-256 mismatch for '$($PackageInput.id)'"
    }

    if ($PackageInput.asset.format -notin @("pkg.tar.zst", "pkg.tar", "zip")) {
        throw "Unsupported asset format '$($PackageInput.asset.format)' for '$($PackageInput.id)'"
    }

    $inventory = Get-NativeShellArchiveInventory $Archive $Tar
    if ($null -ne $PackageInput.package -and
        $PackageInput.package.PSObject.Properties["payloadMembers"] -and
        $null -ne $PackageInput.package.payloadMembers -and
        $inventory.payloadMembers.Count -ne [int]$PackageInput.package.payloadMembers) {
        throw "Package payload member count mismatch for '$($PackageInput.id)'"
    }
    if ($null -ne $PackageInput.package) {
        $metadata = Get-NativeShellPackageMetadata $Archive $Tar
        Assert-NativeShellPackageMetadata $metadata $PackageInput.package $PackageInput.id
    }

    if ($ExtractTo) {
        Expand-NativeShellArchive $Archive $inventory $ExtractTo
        foreach ($mapping in @($PackageInput.overlay.mappings)) {
            if ($inventory.payloadMembers -notcontains [string]$mapping.source) {
                throw "Mapped source is not package-owned: '$($mapping.source)'"
            }
            $source = Join-Path $ExtractTo ([string]$mapping.source).Replace("/", "\")
            $sourceItem = Get-Item -Force -LiteralPath $source -ErrorAction SilentlyContinue
            if ($null -eq $sourceItem) {
                throw "Mapped source is missing after extraction: '$($mapping.source)'"
            }
            if ($mapping.content -eq "pe-aa64") {
                if ($sourceItem.Length -ne [int64]$mapping.bytes -or
                    (Get-NativeShellSha256 $source) -ne [string]$mapping.sha256) {
                    throw "Mapped PE identity mismatch: '$($mapping.source)'"
                }
            }
            if ($mapping.content -in @("symlink", "hardlink")) {
                if ($mapping.content -eq "symlink") {
                    if ($sourceItem.LinkType -ne "SymbolicLink" -or
                        ([string]$sourceItem.LinkTarget).Replace("\", "/") -ne
                            [string]$mapping.sourceLinkTarget) {
                        throw "Mapped link identity mismatch: '$($mapping.source)'"
                    }
                } else {
                    $target = Join-Path $ExtractTo (
                        [string]$mapping.sourceLinkTarget).Replace("/", "\")
                    if (-not (Test-NativeShellHardLinkPair $source $target)) {
                        throw "Mapped link identity mismatch: '$($mapping.source)'"
                    }
                }
            }
        }
        foreach ($seal in @(
            if ($PackageInput.PSObject.Properties["sealedMembers"]) {
                $PackageInput.sealedMembers
            } else {
                @()
            }
        )) {
            $sealedMember = Assert-NativeShellRelativePath (
                [string](Get-NativeShellProperty $seal "path" (
                    "sealed member for '$($PackageInput.id)'"))) "sealed member"
            if ($inventory.payloadMembers -notcontains $sealedMember) {
                throw "Sealed member is not archive-owned: '$sealedMember'"
            }
            $sealedPath = Join-Path $ExtractTo $sealedMember.Replace("/", "\")
            $sealedItem = Get-Item -Force -LiteralPath $sealedPath -ErrorAction SilentlyContinue
            if ($null -eq $sealedItem -or $sealedItem.PSIsContainer -or
                $sealedItem.LinkType -eq "SymbolicLink" -or
                $sealedItem.Length -ne [int64](Get-NativeShellProperty $seal "bytes" (
                    "sealed member '$sealedMember'")) -or
                (Get-NativeShellSha256 $sealedPath) -ne
                    [string](Get-NativeShellProperty $seal "sha256" (
                        "sealed member '$sealedMember'"))) {
                throw "Sealed member identity mismatch: '$sealedMember'"
            }
        }
    } elseif ($PackageInput.PSObject.Properties["sealedMembers"] -and
            @($PackageInput.sealedMembers).Count -ne 0) {
        throw "Sealed members require private extraction for '$($PackageInput.id)'"
    }

    return [ordered]@{
        id = $PackageInput.id
        archive = $Archive
        bytes = $item.Length
        sha256 = $hash
        extractRoot = $ExtractTo
        payloadMembers = @($inventory.payloadMembers)
        archiveMembers = @(
            if ($ExtractTo) {
                Get-NativeShellExtractedArchiveMembers $inventory $ExtractTo
            } else {
                @()
            }
        )
    }
}

function Test-NativeShellOverlayPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Lock,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd("\")
    $plan = [Collections.Generic.List[object]]::new()
    foreach ($lockInput in @($Lock.inputs | Where-Object { $_.status -eq "resolved" })) {
        foreach ($mapping in @($lockInput.overlay.mappings)) {
            $destination = Join-Path $rootPath ([string]$mapping.destination).Replace("/", "\")
            $full = [IO.Path]::GetFullPath($destination)
            if (-not $full.StartsWith("$rootPath\", [StringComparison]::OrdinalIgnoreCase)) {
                throw "Payload destination escapes the root: '$($mapping.destination)'"
            }
            $exists = $null -ne (
                Get-Item -Force -LiteralPath $full -ErrorAction SilentlyContinue)
            if ([bool]$mapping.allowOverwrite -and -not $exists) {
                throw "Expected replacement is missing: '$($mapping.destination)'"
            }
            if (-not [bool]$mapping.allowOverwrite -and $exists) {
                throw "Unexpected payload collision: '$($mapping.destination)'"
            }
            if ([bool]$mapping.allowOverwrite) {
                foreach ($field in @(
                    "expectedDestinationBytes", "expectedDestinationSha256"
                )) {
                    $null = Get-NativeShellProperty $mapping $field (
                        "replacement mapping '$($mapping.destination)'")
                }
                $item = Get-Item -Force -LiteralPath $full
                if ($item.Length -ne [int64]$mapping.expectedDestinationBytes -or
                    (Get-NativeShellSha256 $full) -ne
                        [string]$mapping.expectedDestinationSha256) {
                    throw "Unexpected replacement identity: '$($mapping.destination)'"
                }
            }
            $plan.Add([ordered]@{
                input = $lockInput.id
                source = $mapping.source
                destination = $mapping.destination
                allowOverwrite = [bool]$mapping.allowOverwrite
                content = $mapping.content
                sourceLinkTarget = $(
                    if ($mapping.PSObject.Properties["sourceLinkTarget"]) {
                        $mapping.sourceLinkTarget
                    } else {
                        $null
                    })
                linkTarget = $(
                    if ($mapping.PSObject.Properties["linkTarget"]) {
                        $mapping.linkTarget
                    } else {
                        $null
                    })
            })
        }
    }
    return @($plan)
}

function Sort-NativeShellOrdinal {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,
        [Parameter(Mandatory = $true)][scriptblock]$Property
    )

    $valuesList = [Collections.ArrayList]::new()
    foreach ($candidate in $InputObject) {
        if ($candidate -is [Collections.IEnumerator]) {
            while ($candidate.MoveNext()) {
                [void]$valuesList.Add($candidate.Current)
            }
        } else {
            [void]$valuesList.Add($candidate)
        }
    }
    [object[]]$values = $valuesList.ToArray()
    for ($index = 1; $index -lt $values.Count; $index++) {
        $value = $values[$index]
        $key = [string](& $Property $value)
        $cursor = $index
        while ($cursor -gt 0 -and
            [StringComparer]::Ordinal.Compare(
                [string](& $Property $values[$cursor - 1]), $key) -gt 0) {
            $values[$cursor] = $values[$cursor - 1]
            $cursor--
        }
        $values[$cursor] = $value
    }
    return $values
}

function Get-NativeShellExtractedArchiveMembers {
    param(
        [Parameter(Mandatory = $true)][object]$Inventory,
        [Parameter(Mandatory = $true)][string]$ExtractRoot
    )

    $members = [Collections.Generic.List[object]]::new()
    foreach ($memberName in @($Inventory.members)) {
        $sourceMember = ([string]$memberName).TrimEnd("/")
        $path = Join-Path $ExtractRoot $sourceMember.Replace("/", "\")
        $item = Get-Item -Force -LiteralPath $path -ErrorAction Stop
        $key = $sourceMember.ToLowerInvariant()
        $type = [string]$Inventory.memberTypes[$key]
        $linkTarget = $(if ($Inventory.linkTargets.ContainsKey($key)) {
            [string]$Inventory.linkTargets[$key]
        } else {
            $null
        })
        $contentItem = $item
        if ($type -eq "symlink") {
            $targetPath = Join-Path $ExtractRoot $linkTarget.Replace("/", "\")
            $contentItem = Get-Item -Force -LiteralPath $targetPath -ErrorAction Stop
        } elseif ($type -eq "hardlink") {
            $targetPath = Join-Path $ExtractRoot $linkTarget.Replace("/", "\")
            $contentItem = Get-Item -Force -LiteralPath $targetPath -ErrorAction Stop
        }
        $members.Add([ordered]@{
            sourceMember = $sourceMember
            type = $type
            bytes = $(if ($type -eq "directory") { 0 } else { [long]$contentItem.Length })
            sha256 = $(if ($type -eq "directory") {
                $null
            } else {
                Get-NativeShellSha256 $contentItem.FullName
            })
            linkTarget = $linkTarget
        })
    }
    return @(Sort-NativeShellOrdinal -InputObject $members -Property {
        param($item) $item["sourceMember"]
    })
}

function Get-NativeShellTreeManifest {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd("\")
    $rows = @(
        Get-ChildItem -Force -Recurse -LiteralPath $rootPath |
            ForEach-Object {
                [pscustomobject]@{
                    item = $_
                    path = [IO.Path]::GetRelativePath(
                        $rootPath, $_.FullName).Replace("\", "/")
                }
            } |
            Where-Object {
                $_.path -ine "preview-evidence" -and
                -not $_.path.StartsWith(
                    "preview-evidence/", [StringComparison]::OrdinalIgnoreCase)
            }
    )
    $rows = @(Sort-NativeShellOrdinal -InputObject $rows -Property {
        param($row) $row.path
    })
    $entries = @(
        foreach ($row in $rows) {
            $item = $row.item
            $relative = Assert-NativeShellRelativePath $row.path "base tree member"
            $type = "file"
            $linkTarget = $null
            $contentPath = $item.FullName
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                if ($item.PSIsContainer -or $item.LinkType -ne "SymbolicLink") {
                    throw "Unsupported base tree reparse point: '$relative'"
                }
                $targetPath = [IO.Path]::GetFullPath(
                    (Join-Path $item.DirectoryName ([string]$item.Target)))
                if (-not $targetPath.StartsWith(
                    "$rootPath\", [StringComparison]::OrdinalIgnoreCase) -or
                    -not [IO.File]::Exists($targetPath)) {
                    throw "Base tree symlink is broken or escapes Root: '$relative'"
                }
                $linkTarget = [IO.Path]::GetRelativePath(
                    $rootPath, $targetPath).Replace("\", "/")
                $null = Assert-NativeShellRelativePath $linkTarget (
                    "base tree symlink target")
                $contentPath = $targetPath
                $type = "symlink"
            } elseif ($item.PSIsContainer) {
                $type = "directory"
            } elseif ($item.LinkType -eq "HardLink") {
                $output = @(& "$env:SystemRoot\System32\fsutil.exe" hardlink list (
                    $item.FullName) 2>&1)
                if ($LASTEXITCODE -ne 0) {
                    throw "Could not enumerate base tree hardlink '$relative'"
                }
                $volume = [IO.Path]::GetPathRoot($item.FullName).TrimEnd("\")
                [string[]]$names = @(
                    foreach ($line in $output) {
                        $text = ([string]$line).Trim()
                        if (-not $text) {
                            continue
                        }
                        $full = [IO.Path]::GetFullPath($(if (
                            [IO.Path]::IsPathFullyQualified($text)) {
                            $text
                        } else {
                            $volume + $text
                        }))
                        if (-not $full.StartsWith(
                            "$rootPath\", [StringComparison]::OrdinalIgnoreCase)) {
                            throw "Base tree hardlink escapes Root: '$relative'"
                        }
                        [IO.Path]::GetRelativePath(
                            $rootPath, $full).Replace("\", "/")
                    }
                )
                [Array]::Sort($names, [StringComparer]::Ordinal)
                $canonical = $names[0]
                if ($relative -cne $canonical) {
                    $type = "hardlink"
                    $linkTarget = $canonical
                }
            }
            [ordered]@{
                path = $relative
                type = $type
                bytes = $(if ($type -eq "directory") {
                    [long]0
                } else {
                    [long](Get-Item -Force -LiteralPath $contentPath).Length
                })
                sha256 = $(if ($type -eq "directory") {
                    $null
                } else {
                    Get-NativeShellSha256 $contentPath
                })
                linkTarget = $linkTarget
            }
        }
    )
    if ($entries.Count -eq 0) {
        throw "Base tree manifest cannot be empty"
    }
    return [ordered]@{
        schemaVersion = 1
        entries = $entries
    }
}

function New-NativeShellAdapterLock {
    param(
        [Parameter(Mandatory = $true)][object]$RichLock,
        [Parameter(Mandatory = $true)][string]$SourceLockSha256,
        [Parameter(Mandatory = $true)][hashtable]$ArchiveMembers,
        [Parameter(Mandatory = $true)][string]$BaseManifestSha256,
        [Parameter(Mandatory = $true)][object[]]$BaseEntries,
        [string[]]$RemovedBasePaths = @()
    )

    if ($SourceLockSha256 -notmatch "^[0-9a-f]{64}$" -or
        $BaseManifestSha256 -notmatch "^[0-9a-f]{64}$") {
        throw "Source or base manifest SHA-256 is invalid"
    }
    $removed = @{}
    foreach ($path in $RemovedBasePaths) {
        $removed[[string]$path] = $true
    }
    $basePaths = @{}
    foreach ($entry in $BaseEntries) {
        if (-not $removed.ContainsKey([string]$entry.path)) {
            $basePaths[[string]$entry.path] = $true
        }
    }
    $parentPath = {
        param([string]$Path)
        $index = $Path.LastIndexOf("/")
        if ($index -lt 0) { return $null }
        return $Path.Substring(0, $index)
    }
    $closureIds = @{}
    foreach ($id in @($RichLock.nativeShellClosure)) {
        $closureIds[[string]$id] = $true
    }
    $closure = @()
    $adapterInputs = @()
    foreach ($richInput in @($RichLock.inputs)) {
        $id = [string]$richInput.id
        if ($richInput.status -eq "unresolved") {
            $adapterInputs += ,([pscustomobject][ordered]@{
                id = $id
                role = "validation-tool"
                status = "unresolved"
                resolution = $null
                release = $null
                asset = $null
                package = $null
                overlay = $null
            })
            continue
        }

        $mappings = @($richInput.overlay.mappings)
        $isPayload = $mappings.Count -ne 0
        if (-not $ArchiveMembers.ContainsKey($id)) {
            throw "Archive inventory is required for resolved input '$id'"
        }
        $archive = @($ArchiveMembers[$id])
        $archiveDirectories = @{}
        foreach ($member in $archive | Where-Object type -eq "directory") {
            $archiveDirectories[[string]$member.sourceMember] = $true
        }
        $adapterMappings = [Collections.Generic.List[object]]::new()
        $mappingDestinations = @{}
        foreach ($mapping in $mappings) {
            $source = [string]$mapping.source
            $destination = [string]$mapping.destination
            $adapterMappings.Add([ordered]@{
                sourceMember = $source
                destinationPath = $destination
            })
            $mappingDestinations[$destination] = $source
            $sourceParent = & $parentPath $source
            $destinationParent = & $parentPath $destination
            while ($destinationParent) {
                if ($basePaths.ContainsKey($destinationParent)) {
                    break
                }
                if (-not $sourceParent -or
                    -not $archiveDirectories.ContainsKey($sourceParent)) {
                    throw "Mapped file '$source' needs new directory " +
                        "'$destinationParent' without a validated archive directory owner"
                }
                if ($mappingDestinations.ContainsKey($destinationParent)) {
                    if ($mappingDestinations[$destinationParent] -cne $sourceParent) {
                        throw "Mapped directory ownership collides at '$destinationParent'"
                    }
                } else {
                    $adapterMappings.Add([ordered]@{
                        sourceMember = $sourceParent
                        destinationPath = $destinationParent
                    })
                    $mappingDestinations[$destinationParent] = $sourceParent
                }
                $sourceParent = & $parentPath $sourceParent
                $destinationParent = & $parentPath $destinationParent
            }
        }
        $adapterMappings = @(Sort-NativeShellOrdinal `
            -InputObject @($adapterMappings | ForEach-Object { $_ }) -Property {
                param($mapping) $mapping["sourceMember"]
            })
        $include = @($adapterMappings |
            ForEach-Object { [string]$_.sourceMember })
        $package = $null
        if ($null -ne $richInput.package) {
            $provides = if ($isPayload) {
                @($adapterMappings |
                    ForEach-Object { [string]$_.destinationPath })
            } elseif ($id -eq "fixed-binutils") {
                @(
                    "opt/bin/aarch64-pc-cygwin-ld.exe",
                    "opt/bin/aarch64-pc-cygwin-nm.exe",
                    "opt/bin/aarch64-pc-cygwin-objdump.exe"
                )
            } else {
                @($archive | Where-Object type -eq "file" |
                    ForEach-Object { [string]$_.sourceMember })
            }
            $provides = @(Sort-NativeShellOrdinal `
                -InputObject $provides -Property { param($path) $path })
            if ($provides.Count -eq 0) {
                throw "Resolved package input '$id' has no truthful file provides"
            }
            $package = [ordered]@{
                name = [string]$richInput.package.name
                version = [string]$richInput.package.version
                personality = $(if ($isPayload) { "msys" } else { "tool" })
                provides = $provides
            }
        }
        $assetUri = [Uri][string]$richInput.asset.url
        if ($assetUri.Host -eq "raw.githubusercontent.com") {
            $prefix = "/$($richInput.identity.repository)/" +
                "$($richInput.identity.commit)/"
            $decodedPath = [Uri]::UnescapeDataString($assetUri.AbsolutePath)
            if (-not $decodedPath.StartsWith($prefix, [StringComparison]::Ordinal)) {
                throw "Raw commit input '$id' URL does not match its identity"
            }
            $resolutionMethod = "github-raw-commit"
            $release = [ordered]@{
                repository = [string]$richInput.identity.repository
                targetCommit = [string]$richInput.identity.commit
                sourcePath = $decodedPath.Substring($prefix.Length)
            }
        } else {
            $resolutionMethod = "github-release"
            $release = [ordered]@{
                repository = [string]$richInput.identity.repository
                tag = [string]$richInput.identity.tag
                targetCommit = [string]$richInput.identity.commit
            }
        }
        if ($closureIds.ContainsKey($id)) {
            foreach ($mapping in $mappings) {
                if ([string]$mapping.content -eq "pe-aa64") {
                    $closure += [string]$mapping.destination
                }
            }
        }
        $adapterInputs += ,([pscustomobject][ordered]@{
            id = $id
            role = $(if ($isPayload) { "payload" } else { "validation-tool" })
            status = "resolved"
            resolution = [ordered]@{ method = $resolutionMethod }
            release = $release
            asset = [ordered]@{
                url = [string]$richInput.asset.url
                name = [string]$richInput.asset.name
                bytes = [long]$richInput.asset.expectedBytes
                sha256 = [string]$richInput.asset.sha256
            }
            package = $package
            overlay = [ordered]@{
                enabled = $isPayload
                destination = $(if ($isPayload) { "." } else { $null })
                include = $include
                exclude = @()
                mappings = $adapterMappings
            }
        })
    }
    $retainedBase = @($BaseEntries | Where-Object {
        -not $removed.ContainsKey([string]$_.path)
    })
    if ($retainedBase.Count -eq 0) {
        throw "Base tree adapter cannot remove every staged member"
    }
    $adapterInputs += ,([pscustomobject][ordered]@{
        id = "stack-base"
        role = "base-bundle"
        status = "resolved"
        resolution = [ordered]@{
            method = "derived-tree"
            build = [ordered]@{
                repository = "crutkas/build-extra"
                commit = "be0217cb572704f27ea04c9abde8bb992b8ef0c0"
            }
            sdkSource = $null
            manifest = [ordered]@{
                path = "preview-evidence/base-tree-manifest.v1.json"
                sha256 = $BaseManifestSha256
            }
        }
        release = $null
        asset = $null
        package = $null
        overlay = [ordered]@{
            enabled = $true
            destination = "."
            include = @($retainedBase | ForEach-Object { [string]$_.path })
            exclude = @()
            mappings = @($retainedBase | ForEach-Object {
                [ordered]@{
                    sourceMember = [string]$_.path
                    destinationPath = [string]$_.path
                }
            })
        }
    })
    $closure = @(Sort-NativeShellOrdinal `
        -InputObject $closure -Property { param($path) $path } |
        Select-Object -Unique)
    if ($closure.Count -eq 0) {
        throw "Rich lock does not resolve any native shell closure paths"
    }
    for ($index = 1; $index -lt $adapterInputs.Count; $index++) {
        $value = $adapterInputs[$index]
        $cursor = $index
        while ($cursor -gt 0 -and
            [StringComparer]::Ordinal.Compare(
                [string]$adapterInputs[$cursor - 1].id,
                [string]$value.id) -gt 0) {
            $adapterInputs[$cursor] = $adapterInputs[$cursor - 1]
            $cursor--
        }
        $adapterInputs[$cursor] = $value
    }
    return [ordered]@{
        schemaVersion = 1
        sourceLock = [ordered]@{
            path = "preview-evidence/source-lock.json"
            sha256 = $SourceLockSha256
        }
        sourceDateEpoch = [long]$RichLock.sourceDateEpoch
        nativeShellClosure = $closure
        inputs = @($adapterInputs)
    }
}

function Get-NativeShellPeClassification {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DisplayPath
    )

    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        return [ordered]@{
            architecture = "non-pe"
            machine = $null
            personality = "none"
            imports = @()
            clrFlags = $null
        }
    }
    $read16 = {
        param([int]$Offset)
        if ($Offset -lt 0 -or $Offset + 2 -gt $bytes.Length) {
            throw "Malformed PE '$DisplayPath'"
        }
        [BitConverter]::ToUInt16($bytes, $Offset)
    }
    $read32 = {
        param([int]$Offset)
        if ($Offset -lt 0 -or $Offset + 4 -gt $bytes.Length) {
            throw "Malformed PE '$DisplayPath'"
        }
        [BitConverter]::ToUInt32($bytes, $Offset)
    }
    $read64 = {
        param([int]$Offset)
        if ($Offset -lt 0 -or $Offset + 8 -gt $bytes.Length) {
            throw "Malformed PE '$DisplayPath'"
        }
        [BitConverter]::ToUInt64($bytes, $Offset)
    }
    if ($bytes.Length -lt 64) {
        throw "Malformed PE '$DisplayPath'"
    }
    [uint32]$peOffset = & $read32 60
    if ([uint64]$peOffset + 24 -gt $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "Malformed PE '$DisplayPath'"
    }
    [uint16]$machine = & $read16 ($peOffset + 4)
    [uint16]$sectionCount = & $read16 ($peOffset + 6)
    [uint16]$optionalSize = & $read16 ($peOffset + 20)
    $optionalOffset = [int]$peOffset + 24
    $sectionOffset = $optionalOffset + [int]$optionalSize
    if ($sectionCount -eq 0 -or
        [uint64]$sectionOffset + ([uint64]$sectionCount * 40) -gt $bytes.Length) {
        throw "Malformed PE '$DisplayPath'"
    }
    [uint16]$magic = & $read16 $optionalOffset
    if ($magic -eq 0x10b) {
        $directoryCountOffset = $optionalOffset + 92
        $directoryOffset = $optionalOffset + 96
        [uint64]$imageBase = [uint64](& $read32 ($optionalOffset + 28))
    } elseif ($magic -eq 0x20b) {
        $directoryCountOffset = $optionalOffset + 108
        $directoryOffset = $optionalOffset + 112
        [uint64]$imageBase = & $read64 ($optionalOffset + 24)
    } else {
        throw "Malformed PE '$DisplayPath'"
    }
    [uint32]$directoryCount = & $read32 $directoryCountOffset
    $sections = @(
        for ($index = 0; $index -lt $sectionCount; $index++) {
            $offset = $sectionOffset + ($index * 40)
            [ordered]@{
                virtualSize = [uint32](& $read32 ($offset + 8))
                virtualAddress = [uint32](& $read32 ($offset + 12))
                rawSize = [uint32](& $read32 ($offset + 16))
                rawPointer = [uint32](& $read32 ($offset + 20))
            }
        }
    )
    $rvaOffset = {
        param([uint32]$Rva)
        foreach ($section in $sections) {
            [uint64]$span = [Math]::Max(
                [uint64]$section.virtualSize, [uint64]$section.rawSize)
            if ([uint64]$Rva -ge [uint64]$section.virtualAddress -and
                [uint64]$Rva -lt [uint64]$section.virtualAddress + $span) {
                $offset = [uint64]$section.rawPointer +
                    ([uint64]$Rva - [uint64]$section.virtualAddress)
                if ($offset -ge [uint64]$bytes.Length) {
                    throw "Malformed PE '$DisplayPath'"
                }
                return [int]$offset
            }
        }
        throw "Malformed PE '$DisplayPath'"
    }
    $readAscii = {
        param([int]$Offset)
        $end = $Offset
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) {
            $end++
        }
        if ($end -eq $bytes.Length) {
            throw "Malformed PE '$DisplayPath'"
        }
        [Text.Encoding]::ASCII.GetString(
            $bytes, $Offset, $end - $Offset).ToLowerInvariant()
    }
    $imports = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    if ($directoryCount -gt 1) {
        [uint32]$importRva = & $read32 ($directoryOffset + 8)
        [uint32]$importSize = & $read32 ($directoryOffset + 12)
        if ($importRva -ne 0 -and $importSize -ne 0) {
            $importOffset = & $rvaOffset $importRva
            for ($offset = $importOffset;
                $offset + 20 -le $importOffset + $importSize;
                $offset += 20) {
                $allZero = $true
                for ($byteIndex = 0; $byteIndex -lt 20; $byteIndex++) {
                    if ($bytes[$offset + $byteIndex] -ne 0) {
                        $allZero = $false
                        break
                    }
                }
                if ($allZero) {
                    break
                }
                [uint32]$nameRva = & $read32 ($offset + 12)
                $nameOffset = & $rvaOffset $nameRva
                [void]$imports.Add((& $readAscii $nameOffset))
            }
        }
    }
    if ($directoryCount -gt 11) {
        [uint32]$boundRva = & $read32 ($directoryOffset + 88)
        [uint32]$boundSize = & $read32 ($directoryOffset + 92)
        if ($boundRva -ne 0 -and $boundSize -ne 0) {
            $boundOffset = & $rvaOffset $boundRva
            for ($offset = $boundOffset;
                $offset + 8 -le $boundOffset + $boundSize;
                $offset += 8) {
                [uint32]$timestamp = & $read32 $offset
                [uint16]$nameOffset = & $read16 ($offset + 4)
                [uint16]$forwarders = & $read16 ($offset + 6)
                if ($timestamp -eq 0 -and $nameOffset -eq 0 -and $forwarders -eq 0) {
                    break
                }
                [void]$imports.Add((& $readAscii ($boundOffset + $nameOffset)))
                $offset += 8 * $forwarders
            }
        }
    }
    if ($directoryCount -gt 13) {
        [uint32]$delayRva = & $read32 ($directoryOffset + 104)
        [uint32]$delaySize = & $read32 ($directoryOffset + 108)
        if ($delayRva -ne 0 -and $delaySize -ne 0) {
            $delayOffset = & $rvaOffset $delayRva
            for ($offset = $delayOffset;
                $offset + 32 -le $delayOffset + $delaySize;
                $offset += 32) {
                [uint32]$attributes = & $read32 $offset
                [uint32]$nameAddress = & $read32 ($offset + 4)
                $allZero = $true
                for ($byteIndex = 0; $byteIndex -lt 32; $byteIndex++) {
                    if ($bytes[$offset + $byteIndex] -ne 0) {
                        $allZero = $false
                        break
                    }
                }
                if ($allZero) {
                    break
                }
                if ($nameAddress -eq 0) {
                    throw "Malformed PE '$DisplayPath'"
                }
                [uint64]$nameRva = if (($attributes -band 1) -ne 0) {
                    $nameAddress
                } else {
                    if ([uint64]$nameAddress -lt $imageBase) {
                        throw "Malformed PE '$DisplayPath'"
                    }
                    [uint64]$nameAddress - $imageBase
                }
                if ($nameRva -gt [uint32]::MaxValue) {
                    throw "Malformed PE '$DisplayPath'"
                }
                [void]$imports.Add((& $readAscii (
                    & $rvaOffset ([uint32]$nameRva))))
            }
        }
    }
    $clrFlags = $null
    $hasClr = $false
    if ($directoryCount -gt 14) {
        [uint32]$clrRva = & $read32 ($directoryOffset + 112)
        [uint32]$clrSize = & $read32 ($directoryOffset + 116)
        if ($clrRva -ne 0 -and $clrSize -ne 0) {
            $clrOffset = & $rvaOffset $clrRva
            $clrFlags = [uint32](& $read32 ($clrOffset + 16))
            $hasClr = $true
        }
    }
    $architecture = switch ($machine) {
        0xaa64 { "arm64"; break }
        0x8664 { "x64"; break }
        0xa641 { "arm64ec"; break }
        0x014c {
            if ($hasClr -and ($clrFlags -band 0x1) -ne 0 -and
                ($clrFlags -band 0x2) -eq 0) {
                "anycpu"
            } else {
                "x86"
            }
            break
        }
        default { "unknown" }
    }
    $orderedImports = @(Sort-NativeShellOrdinal `
        -InputObject @($imports) -Property { param($name) $name })
    return [ordered]@{
        architecture = $architecture
        machine = "0x{0:X4}" -f $machine
        personality = $(if ($hasClr) {
            "managed"
        } elseif ($orderedImports -ccontains "msys-2.0.dll") {
            "msys"
        } elseif ($orderedImports -ccontains "cygwin1.dll") {
            "cygwin"
        } else {
            "mingw"
        })
        imports = $orderedImports
        clrFlags = $clrFlags
    }
}

function Assert-NativeShellNoReverseImports {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$ImportName
    )

    $targetKey = $TargetPath.Replace("\", "/").ToLowerInvariant()
    $consumers = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -Force -File -Recurse -LiteralPath $PayloadRoot)) {
        $relative = [IO.Path]::GetRelativePath(
            $PayloadRoot, $file.FullName).Replace("\", "/")
        if ($relative.ToLowerInvariant() -eq $targetKey) {
            continue
        }
        $classification = Get-NativeShellPeClassification $file.FullName $relative
        if (@($classification.imports) -ccontains $ImportName.ToLowerInvariant()) {
            $consumers.Add($relative)
        }
    }
    if ($consumers.Count -ne 0) {
        $ordered = @(Sort-NativeShellOrdinal -InputObject @($consumers) -Property {
            param($path) $path
        })
        throw "Cannot remove '$TargetPath'; '$ImportName' is still imported by: " +
            ($ordered -join ", ")
    }
}

function Write-NativeShellCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 100
    $json = $json.Replace("`r`n", "`n") + "`n"
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function @(
    "Assert-NativeShellLinkTarget",
    "Assert-NativeShellPackageMetadata",
    "Assert-NativeShellRelativePath",
    "Assert-NativeShellSetEqual",
    "Expand-NativeShellArchive",
    "Assert-NativeShellNoReverseImports",
    "Get-NativeShellArchiveInventory",
    "Get-NativeShellExtractedArchiveMembers",
    "Get-NativeShellPeClassification",
    "Get-NativeShellTreeManifest",
    "Get-NativeShellPackageMetadata",
    "Get-NativeShellSha256",
    "New-NativeShellAdapterLock",
    "Read-NativeShellLock",
    "Sort-NativeShellOrdinal",
    "Test-NativeShellLock",
    "Test-NativeShellOverlayPlan",
    "Test-NativeShellResolvedInput",
    "Write-NativeShellCanonicalJson"
)
