[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Preview", "Final")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [Alias("PortableRoot")]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [Alias("LockPath")]
    [string]$Lock,

    [Parameter(Mandatory = $true)]
    [Alias("ProvenancePath")]
    [string]$Provenance,

    [Parameter(Mandatory = $true)]
    [Alias("PayloadManifestPath")]
    [string]$PayloadManifest,

    [Parameter(Mandatory = $true)]
    [Alias("RuntimeEvidencePath")]
    [string]$RuntimeEvidence,

    [string]$ToolRoot,

    [string]$Baseline,

    [Alias("OutputPath")]
    [string]$Report = "arm64-bundle-validation.json"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Baseline)) {
    $Baseline = Join-Path $PSScriptRoot "arm64-x64-payload-baseline.txt"
}

$issues = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[object]

function Add-Issue {
    param(
        [ValidateSet("scanner", "contract", "payload", "runtime")]
        [string]$Category,
        [string]$Code,
        [string]$Message
    )

    $issues.Add([pscustomobject]@{
        category = $Category
        code = $Code
        message = $Message
    })
}

function Add-Warning {
    param([string]$Code, [string]$Message)

    $warnings.Add([pscustomobject]@{
        code = $Code
        message = $Message
    })
}

function Get-Property {
    param([object]$Object, [string]$Name)

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Has-Property {
    param([object]$Object, [string]$Name)

    return $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

function Get-Sha256 {
    param([string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Sha256 {
    param([object]$Value)

    return $Value -is [string] -and $Value -match "^[0-9a-f]{64}$"
}

function Test-Commit {
    param([object]$Value)

    return $Value -is [string] -and $Value -match "^[0-9a-f]{40}$"
}

function Test-RelativePath {
    param([object]$Value, [switch]$AllowEmpty, [switch]$AllowWildcards)

    if ($Value -isnot [string]) {
        return $false
    }
    if ($Value.Length -eq 0) {
        return $AllowEmpty.IsPresent
    }
    if ($Value -match "[\\:`0]" -or $Value.StartsWith("/") -or
        $Value.EndsWith("/") -or $Value.Contains("//")) {
        return $false
    }
    foreach ($segment in $Value.Split("/")) {
        if ($segment -eq "." -or $segment -eq ".." -or $segment.Length -eq 0) {
            return $false
        }
        if (-not $AllowWildcards -and $segment -match "[*?]") {
            return $false
        }
    }
    return $true
}

function Test-Placeholder {
    param([object]$Object)

    if ($null -eq $Object) {
        return $false
    }
    $json = $Object | ConvertTo-Json -Depth 20 -Compress
    return $json -match "(?i)\b(todo|tbd|placeholder|replace-me|unknown)\b"
}

function Test-SharedMsysPath {
    param([object]$Value)

    return $Value -is [string] -and
        $Value -match '(?i)(^|["/])c:[\\/]msys64([\\/]|$)'
}

function Read-Json {
    param([string]$Path, [string]$Label)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Issue contract "${Label}_MISSING" "$Label does not exist: $Path"
        return $null
    }
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        Add-Issue contract "${Label}_JSON" "$Label is not valid JSON: $($_.Exception.Message)"
        return $null
    }
}

function Assert-Equal {
    param(
        [object]$Actual,
        [object]$Expected,
        [string]$Category,
        [string]$Code,
        [string]$Label
    )

    if ([string]$Actual -cne [string]$Expected) {
        Add-Issue $Category $Code "$Label is '$Actual', expected '$Expected'"
    }
}

function New-PathSet {
    return New-Object "System.Collections.Generic.Dictionary[string,object]" `
        ([System.StringComparer]::OrdinalIgnoreCase)
}

function Add-Unique {
    param(
        [System.Collections.Generic.Dictionary[string,object]]$Set,
        [string]$Value,
        [string]$Code,
        [string]$Label
    )

    if ($Set.ContainsKey($Value)) {
        Add-Issue contract $Code "Duplicate $Label '$Value'"
        return $false
    }
    $Set.Add($Value, $true)
    return $true
}

$modeLower = $Mode.ToLowerInvariant()
$rootPath = $null
try {
    $rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd("\")
} catch {
    Add-Issue contract ROOT_MISSING "Payload root does not exist: $Root"
}

$lockObject = Read-Json $Lock "LOCK"
$provenanceObject = Read-Json $Provenance "PROVENANCE"
$payloadObject = Read-Json $PayloadManifest "PAYLOAD"
$evidenceObject = Read-Json $RuntimeEvidence "EVIDENCE"

$lockSha256 = if (Test-Path -LiteralPath $Lock -PathType Leaf) {
    Get-Sha256 $Lock
} else { $null }
$provenanceSha256 = if (Test-Path -LiteralPath $Provenance -PathType Leaf) {
    Get-Sha256 $Provenance
} else { $null }
$payloadSha256 = if (Test-Path -LiteralPath $PayloadManifest -PathType Leaf) {
    Get-Sha256 $PayloadManifest
} else { $null }
$evidenceSha256 = if (Test-Path -LiteralPath $RuntimeEvidence -PathType Leaf) {
    Get-Sha256 $RuntimeEvidence
} else { $null }

$inputById = New-PathSet
$resolvedInputById = New-PathSet
$unresolvedInputIds = New-Object System.Collections.Generic.List[string]
$assetUrls = New-PathSet
$assetNames = New-PathSet
$assetHashes = New-PathSet
$providedPaths = New-PathSet

if ($null -ne $lockObject) {
    Assert-Equal (Get-Property $lockObject "schemaVersion") 1 contract LOCK_SCHEMA `
        "Lock schemaVersion"
    $inputs = @(Get-Property $lockObject "inputs")
    if ($inputs.Count -eq 0) {
        Add-Issue contract LOCK_INPUTS "Lock inputs must not be empty"
    }

    foreach ($input in $inputs) {
        $id = Get-Property $input "id"
        if ($id -isnot [string] -or $id -notmatch "^[a-z0-9][a-z0-9._-]*$") {
            Add-Issue contract LOCK_ID "Invalid lock input id '$id'"
            continue
        }
        if (-not (Add-Unique $inputById $id LOCK_DUPLICATE_ID "lock input id")) {
            continue
        }
        $inputById[$id] = $input

        $role = Get-Property $input "role"
        if ($role -notin @("base-bundle", "package", "runtime", "tool")) {
            Add-Issue contract LOCK_ROLE "Input '$id' has invalid role '$role'"
        }

        $status = Get-Property $input "status"
        if ($status -eq "unresolved") {
            $unresolvedInputIds.Add($id)
            foreach ($field in @("resolution", "release", "asset", "package", "overlay")) {
                if (-not (Has-Property $input $field) -or $null -ne (Get-Property $input $field)) {
                    Add-Issue contract LOCK_UNRESOLVED_FIELD `
                        "Unresolved input '$id' must set '$field' to null"
                }
            }
            if ($modeLower -eq "final") {
                Add-Issue contract LOCK_UNRESOLVED_FINAL `
                    "Final mode rejects unresolved input '$id'"
            } else {
                Add-Warning LOCK_UNRESOLVED "Preview input '$id' is unresolved"
            }
            continue
        }
        if ($status -ne "resolved") {
            Add-Issue contract LOCK_STATUS "Input '$id' has invalid status '$status'"
            continue
        }
        $resolvedInputById.Add($id, $input)

        if (Test-Placeholder $input) {
            Add-Issue contract LOCK_PLACEHOLDER "Resolved input '$id' contains a placeholder"
        }

        $resolution = Get-Property $input "resolution"
        if ($resolution -isnot [string] -or [string]::IsNullOrWhiteSpace($resolution)) {
            Add-Issue contract LOCK_RESOLUTION "Resolved input '$id' lacks a resolution"
        }

        $release = Get-Property $input "release"
        $repository = Get-Property $release "repository"
        $tag = Get-Property $release "tag"
        $targetCommit = Get-Property $release "targetCommit"
        if ($repository -isnot [string] -or $repository -notmatch "^crutkas/[^/]+$") {
            Add-Issue contract LOCK_REPOSITORY `
                "Resolved input '$id' must use a crutkas fork repository"
        }
        if ($tag -isnot [string] -or [string]::IsNullOrWhiteSpace($tag)) {
            Add-Issue contract LOCK_RELEASE_TAG "Resolved input '$id' lacks a release tag"
        }
        if (-not (Test-Commit $targetCommit)) {
            Add-Issue contract LOCK_RELEASE_COMMIT `
                "Resolved input '$id' has an invalid release targetCommit"
        }

        $asset = Get-Property $input "asset"
        $assetUrl = Get-Property $asset "url"
        $assetName = Get-Property $asset "name"
        $assetBytes = Get-Property $asset "bytes"
        $assetHash = Get-Property $asset "sha256"
        if ($assetUrl -isnot [string] -or
            $assetUrl -notmatch "^https://github\.com/crutkas/") {
            Add-Issue contract LOCK_ASSET_URL `
                "Resolved input '$id' must use a crutkas fork asset URL"
        } else {
            [void](Add-Unique $assetUrls $assetUrl LOCK_DUPLICATE_URL "asset URL")
        }
        if ($assetName -isnot [string] -or [string]::IsNullOrWhiteSpace($assetName)) {
            Add-Issue contract LOCK_ASSET_NAME "Resolved input '$id' lacks an asset name"
        } else {
            [void](Add-Unique $assetNames $assetName LOCK_DUPLICATE_ASSET_NAME "asset name")
        }
        if ($assetBytes -isnot [long] -and $assetBytes -isnot [int]) {
            Add-Issue contract LOCK_ASSET_BYTES "Resolved input '$id' has invalid asset bytes"
        } elseif ([long]$assetBytes -le 0) {
            Add-Issue contract LOCK_ASSET_BYTES "Resolved input '$id' has non-positive asset bytes"
        }
        if (-not (Test-Sha256 $assetHash)) {
            Add-Issue contract LOCK_ASSET_HASH "Resolved input '$id' has an invalid asset SHA-256"
        } else {
            [void](Add-Unique $assetHashes $assetHash LOCK_DUPLICATE_ASSET_HASH "asset SHA-256")
        }

        $package = Get-Property $input "package"
        $packageName = Get-Property $package "name"
        $packageVersion = Get-Property $package "version"
        $personality = Get-Property $package "personality"
        if ($packageName -isnot [string] -or [string]::IsNullOrWhiteSpace($packageName) -or
            $packageVersion -isnot [string] -or [string]::IsNullOrWhiteSpace($packageVersion)) {
            Add-Issue contract LOCK_PACKAGE `
                "Resolved input '$id' requires immutable package name and version"
        }
        if ($personality -notin @("mixed", "mingw", "msys", "managed", "windows")) {
            Add-Issue contract LOCK_PERSONALITY `
                "Resolved input '$id' has invalid package personality '$personality'"
        }
        foreach ($path in @(Get-Property $package "provides")) {
            if (-not (Test-RelativePath $path)) {
                Add-Issue contract LOCK_PROVIDES_PATH `
                    "Input '$id' provides invalid path '$path'"
            } else {
                [void](Add-Unique $providedPaths $path LOCK_DUPLICATE_PROVIDES `
                    "provided destination path")
            }
        }

        $overlay = Get-Property $input "overlay"
        if ($null -eq $overlay) {
            Add-Issue contract LOCK_OVERLAY "Resolved input '$id' requires overlay metadata"
            continue
        }
        $overlayEnabled = Get-Property $overlay "enabled"
        $expectedOverlayEnabled = $role -ne "tool"
        if ($overlayEnabled -ne $expectedOverlayEnabled) {
            Add-Issue contract LOCK_OVERLAY `
                "Input '$id' role '$role' requires overlay.enabled=$expectedOverlayEnabled"
        }
        $destination = Get-Property $overlay "destination"
        if (-not (Test-RelativePath $destination -AllowEmpty)) {
            Add-Issue contract LOCK_OVERLAY_DESTINATION `
                "Input '$id' has invalid overlay destination '$destination'"
        }
        $include = @(Get-Property $overlay "include")
        if ($include.Count -eq 0) {
            Add-Issue contract LOCK_OVERLAY_INCLUDE "Input '$id' overlay include is empty"
        }
        foreach ($pattern in @($include + @(Get-Property $overlay "exclude"))) {
            if (-not (Test-RelativePath $pattern -AllowWildcards)) {
                Add-Issue contract LOCK_OVERLAY_PATTERN `
                    "Input '$id' has invalid overlay pattern '$pattern'"
            }
        }
    }
}

$overlayFinal = New-PathSet
$provenanceInputById = New-PathSet
$overlaySeenIds = New-PathSet

if ($null -ne $provenanceObject) {
    Assert-Equal (Get-Property $provenanceObject "schemaVersion") 1 contract `
        PROVENANCE_SCHEMA "Provenance schemaVersion"
    Assert-Equal (Get-Property $provenanceObject "lockSha256") $lockSha256 contract `
        PROVENANCE_LOCK_DIGEST "Provenance lockSha256"
    if (-not (Test-Commit (Get-Property $provenanceObject "assemblerCommit"))) {
        Add-Issue contract PROVENANCE_COMMIT "Provenance assemblerCommit is invalid"
    }
    $hostObject = Get-Property $provenanceObject "host"
    Assert-Equal (Get-Property $hostObject "os") "windows" contract `
        PROVENANCE_HOST_OS "Provenance host OS"
    Assert-Equal (Get-Property $hostObject "architecture") "arm64" contract `
        PROVENANCE_HOST_ARCH "Provenance host architecture"
    try {
        $created = [DateTimeOffset]::Parse([string](Get-Property $provenanceObject "createdAt"))
        if ($created.Offset -ne [TimeSpan]::Zero) {
            Add-Issue contract PROVENANCE_TIME "Provenance createdAt must be UTC"
        }
    } catch {
        Add-Issue contract PROVENANCE_TIME "Provenance createdAt is not RFC 3339"
    }

    foreach ($verification in @(Get-Property $provenanceObject "inputs")) {
        $id = Get-Property $verification "id"
        if ($id -isnot [string] -or -not $resolvedInputById.ContainsKey($id)) {
            Add-Issue contract PROVENANCE_INPUT "Unknown provenance input '$id'"
            continue
        }
        if (-not (Add-Unique $provenanceInputById $id PROVENANCE_DUPLICATE_INPUT `
            "provenance input")) {
            continue
        }
        $provenanceInputById[$id] = $verification
        Assert-Equal (Get-Property $verification "status") "verified" contract `
            PROVENANCE_INPUT_STATUS "Provenance input '$id' status"

        $locked = $resolvedInputById[$id]
        foreach ($field in @("repository", "tag", "targetCommit")) {
            Assert-Equal (Get-Property (Get-Property $verification "release") $field) `
                (Get-Property (Get-Property $locked "release") $field) contract `
                PROVENANCE_RELEASE "Provenance input '$id' release.$field"
        }
        foreach ($field in @("url", "name", "bytes", "sha256")) {
            Assert-Equal (Get-Property (Get-Property $verification "asset") $field) `
                (Get-Property (Get-Property $locked "asset") $field) contract `
                PROVENANCE_ASSET "Provenance input '$id' asset.$field"
        }
        foreach ($field in @("name", "version", "personality")) {
            Assert-Equal (Get-Property (Get-Property $verification "package") $field) `
                (Get-Property (Get-Property $locked "package") $field) contract `
                PROVENANCE_PACKAGE "Provenance input '$id' package.$field"
        }
    }
    foreach ($id in $resolvedInputById.Keys) {
        if (-not $provenanceInputById.ContainsKey($id)) {
            Add-Issue contract PROVENANCE_INPUT_MISSING `
                "Resolved lock input '$id' lacks provenance verification"
        }
    }

    $overlayOrder = @(Get-Property $provenanceObject "overlayOrder")
    for ($index = 0; $index -lt $overlayOrder.Count; $index++) {
        $overlayRecord = $overlayOrder[$index]
        Assert-Equal (Get-Property $overlayRecord "index") $index contract `
            PROVENANCE_OVERLAY_INDEX "Overlay order index"
        $id = Get-Property $overlayRecord "inputId"
        if ($id -isnot [string] -or -not $resolvedInputById.ContainsKey($id)) {
            Add-Issue contract PROVENANCE_OVERLAY_INPUT "Unknown overlay input '$id'"
            continue
        }
        if ((Get-Property (Get-Property $resolvedInputById[$id] "overlay") "enabled") -ne $true) {
            Add-Issue contract PROVENANCE_TOOL_OVERLAY `
                "Tool input '$id' must not be materialized into the payload"
            continue
        }
        if (-not (Add-Unique $overlaySeenIds $id PROVENANCE_DUPLICATE_OVERLAY `
            "overlay input")) {
            continue
        }

        $locked = $resolvedInputById[$id]
        $lockedOverlay = Get-Property $locked "overlay"
        $includePatterns = @(Get-Property $lockedOverlay "include")
        $excludePatterns = @(Get-Property $lockedOverlay "exclude")
        $includeMatches = @{}
        foreach ($pattern in $includePatterns) {
            $includeMatches[$pattern] = 0
        }
        $memberPaths = New-PathSet

        foreach ($member in @(Get-Property $overlayRecord "members")) {
            $sourceMember = Get-Property $member "sourceMember"
            $destinationPath = Get-Property $member "destinationPath"
            $type = Get-Property $member "type"
            if (-not (Test-RelativePath $sourceMember)) {
                Add-Issue contract PROVENANCE_SOURCE_PATH `
                    "Overlay '$id' has invalid source member '$sourceMember'"
                continue
            }
            if (-not (Test-RelativePath $destinationPath)) {
                Add-Issue contract PROVENANCE_DESTINATION_PATH `
                    "Overlay '$id' has invalid destination path '$destinationPath'"
                continue
            }
            if (-not (Add-Unique $memberPaths $sourceMember PROVENANCE_DUPLICATE_MEMBER `
                "source member for '$id'")) {
                continue
            }
            if ($type -notin @("file", "directory", "symlink")) {
                Add-Issue contract PROVENANCE_MEMBER_TYPE `
                    "Overlay '$id' member '$sourceMember' has invalid type '$type'"
            }
            if ($type -eq "file") {
                if (-not (Test-Sha256 (Get-Property $member "sha256")) -or
                    [long](Get-Property $member "bytes") -lt 0) {
                    Add-Issue contract PROVENANCE_MEMBER_FILE `
                        "Overlay '$id' file '$sourceMember' lacks immutable size/hash"
                }
            }

            $included = $false
            foreach ($pattern in $includePatterns) {
                $matcher = New-Object System.Management.Automation.WildcardPattern(
                    $pattern, [System.Management.Automation.WildcardOptions]::IgnoreCase)
                if ($matcher.IsMatch($sourceMember)) {
                    $includeMatches[$pattern]++
                    $included = $true
                }
            }
            foreach ($pattern in $excludePatterns) {
                $matcher = New-Object System.Management.Automation.WildcardPattern(
                    $pattern, [System.Management.Automation.WildcardOptions]::IgnoreCase)
                if ($matcher.IsMatch($sourceMember)) {
                    $included = $false
                }
            }
            if (-not $included) {
                Add-Issue contract PROVENANCE_MEMBER_SELECTION `
                    "Overlay '$id' member '$sourceMember' is not selected by the lock"
            }

            $replaces = Get-Property $member "replacesSourceInput"
            if ($overlayFinal.ContainsKey($destinationPath)) {
                $previous = Get-Property $overlayFinal[$destinationPath] "inputId"
                if ($replaces -cne $previous) {
                    Add-Issue contract PROVENANCE_COLLISION `
                        "Overlay '$id' collision at '$destinationPath' must declare replacement of '$previous'"
                    continue
                }
                $previousPath = Get-Property $overlayFinal[$destinationPath] "destinationPath"
                if ($previousPath -cne $destinationPath) {
                    Add-Issue contract PROVENANCE_CASE_COLLISION `
                        "Overlay '$id' changes path case at '$destinationPath'"
                    continue
                }
            } elseif ($null -ne $replaces -and [string]$replaces -ne "") {
                Add-Issue contract PROVENANCE_SPURIOUS_REPLACEMENT `
                    "Overlay '$id' declares replacement at new path '$destinationPath'"
            }
            $overlayFinal[$destinationPath] = [pscustomobject]@{
                inputId = $id
                sourceMember = $sourceMember
                destinationPath = $destinationPath
                type = $type
                linkTarget = Get-Property $member "linkTarget"
            }
        }

        foreach ($pattern in $includePatterns) {
            if ($includeMatches[$pattern] -eq 0) {
                Add-Issue contract PROVENANCE_INCLUDE_EMPTY `
                    "Overlay '$id' include pattern '$pattern' matched no members"
            }
        }
    }
    foreach ($id in $resolvedInputById.Keys) {
        $overlayEnabled = Get-Property `
            (Get-Property $resolvedInputById[$id] "overlay") "enabled"
        if ($overlayEnabled -eq $true -and -not $overlaySeenIds.ContainsKey($id)) {
            Add-Issue contract PROVENANCE_OVERLAY_MISSING `
                "Resolved lock input '$id' is absent from overlayOrder"
        }
    }

    foreach ($id in $resolvedInputById.Keys) {
        if ((Get-Property (Get-Property $resolvedInputById[$id] "overlay") "enabled") -ne $true) {
            continue
        }
        $package = Get-Property $resolvedInputById[$id] "package"
        foreach ($path in @(Get-Property $package "provides")) {
            if (-not $overlayFinal.ContainsKey($path) -or
                (Get-Property $overlayFinal[$path] "inputId") -cne $id) {
                Add-Issue contract PROVENANCE_REPLACEMENT_MISSING `
                    "Input '$id' does not provide expected final path '$path'"
            }
        }
    }

    $scanner = Get-Property $provenanceObject "scanner"
    $scannerScript = Get-Property $scanner "script"
    Assert-Equal (Get-Property $scannerScript "path") "validate-arm64-bundle.ps1" `
        contract PROVENANCE_SCANNER_PATH "Provenance scanner path"
    Assert-Equal (Get-Property $scannerScript "sha256") `
        (Get-Sha256 $PSCommandPath) contract PROVENANCE_SCANNER_HASH `
        "Provenance scanner SHA-256"
    foreach ($candidate in @(Get-Property $scanner "candidates")) {
        if (-not (Test-Sha256 (Get-Property $candidate "sha256")) -or
            (Test-SharedMsysPath (Get-Property $candidate "path"))) {
            Add-Issue contract PROVENANCE_SCANNER_CANDIDATE `
                "Scanner candidate identity is incomplete or uses shared C:\msys64"
        }
    }

    foreach ($observation in @(Get-Property $provenanceObject "externalObservations")) {
        if ((Get-Property $observation "authoritative") -ne $false) {
            Add-Issue contract PROVENANCE_EXTERNAL_AUTHORITY `
                "External observations must be explicitly non-authoritative"
        }
        try {
            [void][DateTimeOffset]::Parse([string](Get-Property $observation "cutoff"))
        } catch {
            Add-Issue contract PROVENANCE_EXTERNAL_CUTOFF `
                "External observation cutoff is not RFC 3339"
        }
        $before = Get-Property $observation "before"
        $after = Get-Property $observation "after"
        foreach ($field in @("bytes", "sha256")) {
            Assert-Equal (Get-Property (Get-Property $before "log") $field) `
                (Get-Property (Get-Property $after "log") $field) contract `
                PROVENANCE_EXTERNAL_MUTATION "External log before/after $field"
        }
        foreach ($field in @("files", "manifestSha256")) {
            Assert-Equal (Get-Property (Get-Property $before "database") $field) `
                (Get-Property (Get-Property $after "database") $field) contract `
                PROVENANCE_EXTERNAL_MUTATION "External database before/after $field"
        }
        if (-not (Test-Sha256 (Get-Property (Get-Property $before "log") "sha256")) -or
            -not (Test-Sha256 (Get-Property (Get-Property $before "database") "manifestSha256"))) {
            Add-Issue contract PROVENANCE_EXTERNAL_HASH `
                "External observation must record full SHA-256 values"
        }
        foreach ($command in @(Get-Property $observation "commands")) {
            if ($command -match "(?i)\bpacman(?:\.exe)?\b.*(?:^|\s)-S[a-z]*w[a-z]*(?:\s|$)") {
                Add-Issue contract PROVENANCE_EXTERNAL_MUTATION_RISK `
                    "External observation used mutation-risk command '$command'"
            }
        }
    }
}

$payloadEntryByPath = New-PathSet
$payloadEntries = @()
if ($null -ne $payloadObject) {
    Assert-Equal (Get-Property $payloadObject "schemaVersion") 1 contract `
        PAYLOAD_SCHEMA "Payload schemaVersion"
    Assert-Equal (Get-Property $payloadObject "lockSha256") $lockSha256 contract `
        PAYLOAD_LOCK_DIGEST "Payload lockSha256"
    Assert-Equal (Get-Property $payloadObject "provenanceSha256") $provenanceSha256 contract `
        PAYLOAD_PROVENANCE_DIGEST "Payload provenanceSha256"

    $payloadEntries = @(Get-Property $payloadObject "entries")
    $previousPath = $null
    foreach ($entry in $payloadEntries) {
        $path = Get-Property $entry "path"
        if (-not (Test-RelativePath $path)) {
            Add-Issue contract PAYLOAD_PATH "Invalid payload path '$path'"
            continue
        }
        if ($null -ne $previousPath -and
            [StringComparer]::Ordinal.Compare($previousPath, $path) -ge 0) {
            Add-Issue contract PAYLOAD_ORDER `
                "Payload entries must use unique ordinal path order at '$path'"
        }
        $previousPath = $path
        if (-not (Add-Unique $payloadEntryByPath $path PAYLOAD_DUPLICATE_PATH `
            "payload path")) {
            continue
        }
        $payloadEntryByPath[$path] = $entry

        $type = Get-Property $entry "type"
        if ($type -notin @("file", "directory", "symlink")) {
            Add-Issue contract PAYLOAD_TYPE "Payload '$path' has invalid type '$type'"
        }
        $sourceInput = Get-Property $entry "sourceInput"
        if ($sourceInput -isnot [string] -or -not $resolvedInputById.ContainsKey($sourceInput)) {
            Add-Issue contract PAYLOAD_SOURCE_INPUT `
                "Payload '$path' has unknown sourceInput '$sourceInput'"
        } else {
            $expectedPackage = Get-Property `
                (Get-Property $resolvedInputById[$sourceInput] "package") "name"
            Assert-Equal (Get-Property $entry "sourcePackage") $expectedPackage contract `
                PAYLOAD_SOURCE_PACKAGE "Payload '$path' sourcePackage"
        }
        $sourceMember = Get-Property $entry "sourceMember"
        if (-not (Test-RelativePath $sourceMember)) {
            Add-Issue contract PAYLOAD_SOURCE_MEMBER `
                "Payload '$path' has invalid sourceMember '$sourceMember'"
        }
        if (-not $overlayFinal.ContainsKey($path)) {
            Add-Issue contract PAYLOAD_OVERLAY_PATH `
                "Payload '$path' is absent from provenance overlay output"
        } else {
            $final = $overlayFinal[$path]
            Assert-Equal $sourceInput (Get-Property $final "inputId") contract `
                PAYLOAD_OVERLAY_INPUT "Payload '$path' sourceInput"
            Assert-Equal $sourceMember (Get-Property $final "sourceMember") contract `
                PAYLOAD_OVERLAY_MEMBER "Payload '$path' sourceMember"
            Assert-Equal $type (Get-Property $final "type") contract `
                PAYLOAD_OVERLAY_TYPE "Payload '$path' type"
            if ($type -eq "symlink") {
                Assert-Equal (Get-Property $entry "linkTarget") `
                    (Get-Property $final "linkTarget") contract `
                    PAYLOAD_OVERLAY_LINK "Payload '$path' linkTarget"
            }
        }
    }
    foreach ($path in $overlayFinal.Keys) {
        if (-not $payloadEntryByPath.ContainsKey($path)) {
            Add-Issue contract PAYLOAD_MEMBER_MISSING `
                "Provenance output '$path' is absent from the payload manifest"
        }
    }
}

$diskEntryByPath = New-PathSet
if ($null -ne $rootPath) {
    try {
        foreach ($item in Get-ChildItem -LiteralPath $rootPath -Force -Recurse) {
            $relative = $item.FullName.Substring($rootPath.Length).TrimStart("\").Replace("\", "/")
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $type = "symlink"
            } elseif ($item.PSIsContainer) {
                $type = "directory"
            } else {
                $type = "file"
            }
            if ($diskEntryByPath.ContainsKey($relative)) {
                Add-Issue contract PAYLOAD_DISK_DUPLICATE `
                    "Materialized payload has case-colliding path '$relative'"
            } else {
                $diskEntryByPath.Add($relative, [pscustomobject]@{
                    item = $item
                    type = $type
                    linkTarget = if ($type -eq "symlink") {
                        Get-Property $item "Target"
                    } else { $null }
                })
            }
        }
    } catch {
        Add-Issue scanner PAYLOAD_ENUMERATION `
            "Could not enumerate materialized payload: $($_.Exception.Message)"
    }

    foreach ($path in $payloadEntryByPath.Keys) {
        if (-not $diskEntryByPath.ContainsKey($path)) {
            Add-Issue contract PAYLOAD_DISK_MISSING `
                "Manifest path '$path' is absent from the materialized payload"
            continue
        }
        $entry = $payloadEntryByPath[$path]
        $disk = $diskEntryByPath[$path]
        Assert-Equal (Get-Property $entry "type") (Get-Property $disk "type") `
            contract PAYLOAD_DISK_TYPE "Payload '$path' materialized type"
        if ((Get-Property $entry "type") -eq "file") {
            $item = Get-Property $disk "item"
            Assert-Equal (Get-Property $entry "bytes") $item.Length contract `
                PAYLOAD_FILE_BYTES "Payload '$path' bytes"
            if (-not (Test-Sha256 (Get-Property $entry "sha256"))) {
                Add-Issue contract PAYLOAD_FILE_HASH "Payload '$path' lacks a full SHA-256"
            } else {
                Assert-Equal (Get-Property $entry "sha256") `
                    (Get-Sha256 $item.FullName) contract PAYLOAD_FILE_HASH `
                    "Payload '$path' SHA-256"
            }
        } elseif ((Get-Property $entry "type") -eq "symlink") {
            $linkTarget = Get-Property $entry "linkTarget"
            if (-not (Test-RelativePath $linkTarget)) {
                Add-Issue contract PAYLOAD_LINK_TARGET `
                    "Payload '$path' has unsafe linkTarget '$linkTarget'"
            }
            Assert-Equal $linkTarget (Get-Property $disk "linkTarget") contract `
                PAYLOAD_DISK_LINK "Payload '$path' materialized linkTarget"
        }
    }
    foreach ($path in $diskEntryByPath.Keys) {
        if (-not $payloadEntryByPath.ContainsKey($path)) {
            Add-Issue contract PAYLOAD_UNMANIFESTED `
                "Materialized payload path '$path' is not in the payload manifest"
        }
    }
}

$peScanByPath = New-PathSet
$payloadCounts = @{
    anycpu = 0
    arm64 = 0
    arm64ec = 0
    x64 = 0
    x86 = 0
}
$x64Paths = New-Object System.Collections.Generic.List[string]
$pseudoRelocResults = New-Object System.Collections.Generic.List[object]

if ($null -ne $rootPath -and $payloadEntryByPath.Count -gt 0) {
    $candidateList = Join-Path ([IO.Path]::GetTempPath()) `
        "arm64-validator-candidates-$PID.txt"
    $peList = Join-Path ([IO.Path]::GetTempPath()) "arm64-validator-pe-$PID.txt"
    try {
        $filePaths = @($payloadEntries | Where-Object {
            (Get-Property $_ "type") -eq "file"
        } | ForEach-Object {
            Get-Property $_ "path"
        })
        [IO.File]::WriteAllLines($candidateList, $filePaths, [Text.Encoding]::UTF8)

        try {
            $scanLines = @(& (Join-Path $PSScriptRoot "pe-imports.ps1") `
                -ArchitectureOnly -FailOnMalformedPe `
                -Root $rootPath -FileList $candidateList `
                -ErrorAction Stop)
        } catch {
            Add-Issue scanner PE_ARCHITECTURE_SCAN `
                "PE architecture scan failed: $($_.Exception.Message)"
            $scanLines = @()
        }

        foreach ($line in $scanLines) {
            $fields = ([string]$line).TrimEnd("`r").Split("`t")
            if ($fields.Count -ne 3 -or -not (Test-RelativePath $fields[0]) -or
                $fields[1] -notin @("anycpu", "arm64", "arm64ec", "x64", "x86") -or
                $fields[2] -notmatch "^0x[0-9A-F]{4}$") {
                Add-Issue scanner PE_ARCHITECTURE_OUTPUT `
                    "Invalid PE scanner output '$line'"
                continue
            }
            if ($peScanByPath.ContainsKey($fields[0])) {
                Add-Issue scanner PE_ARCHITECTURE_DUPLICATE `
                    "PE scanner returned duplicate path '$($fields[0])'"
                continue
            }
            $peScanByPath.Add($fields[0], [pscustomobject]@{
                kind = $fields[1]
                machine = $fields[2]
                imports = New-Object System.Collections.Generic.List[string]
                personality = $null
            })
        }

        [IO.File]::WriteAllLines($peList, @($peScanByPath.Keys), [Text.Encoding]::UTF8)
        if ($peScanByPath.Count -gt 0) {
            try {
                $importLines = @(& (Join-Path $PSScriptRoot "pe-imports.ps1") `
                    -Root $rootPath -FileList $peList -ErrorAction Stop)
                $current = $null
                foreach ($line in $importLines) {
                    $text = ([string]$line).TrimEnd("`r")
                    if ($text.EndsWith(":")) {
                        $current = $text.Substring(0, $text.Length - 1)
                        if (-not $peScanByPath.ContainsKey($current)) {
                            Add-Issue scanner PE_IMPORT_PATH `
                                "Import scanner returned unknown path '$current'"
                            $current = $null
                        }
                    } elseif ($text -match "^\s*DLL Name:\s*(.+)$") {
                        if ($null -eq $current) {
                            Add-Issue scanner PE_IMPORT_OUTPUT `
                                "Import scanner returned a DLL without a file header"
                        } else {
                            $peScanByPath[$current].imports.Add($Matches[1].ToLowerInvariant())
                        }
                    } elseif (-not [string]::IsNullOrWhiteSpace($text)) {
                        Add-Issue scanner PE_IMPORT_OUTPUT `
                            "Invalid import scanner output '$text'"
                    }
                }
            } catch {
                Add-Issue scanner PE_IMPORT_SCAN `
                    "PE import scan failed: $($_.Exception.Message)"
            }
        }

        foreach ($path in $peScanByPath.Keys) {
            $scan = $peScanByPath[$path]
            if ($scan.kind -eq "anycpu") {
                $scan.personality = "managed"
            } else {
                $hasMsys = $scan.imports.Contains("msys-2.0.dll")
                $hasCygwin = $scan.imports.Contains("cygwin1.dll")
                if ($hasMsys -and $hasCygwin) {
                    Add-Issue payload PE_MIXED_RUNTIME `
                        "PE '$path' imports both MSYS and Cygwin runtimes"
                    $scan.personality = "mixed"
                } elseif ($hasMsys) {
                    $scan.personality = "msys"
                } elseif ($hasCygwin) {
                    $scan.personality = "cygwin"
                } else {
                    $scan.personality = "mingw"
                }
            }

            $payloadCounts[$scan.kind]++
            if ($scan.kind -eq "x64") {
                $x64Paths.Add($path)
            }

            $entry = $payloadEntryByPath[$path]
            $declared = Get-Property $entry "architecture"
            if ($null -eq $declared) {
                Add-Issue contract PAYLOAD_ARCHITECTURE_MISSING `
                    "PE '$path' lacks architecture metadata"
            } else {
                foreach ($field in @("kind", "machine", "personality")) {
                    Assert-Equal (Get-Property $declared $field) `
                        (Get-Property $scan $field) payload PAYLOAD_ARCHITECTURE `
                        "Payload '$path' architecture.$field"
                }
            }

            $sourceInput = Get-Property $entry "sourceInput"
            if ($resolvedInputById.ContainsKey([string]$sourceInput)) {
                $expectedPersonality = Get-Property `
                    (Get-Property $resolvedInputById[$sourceInput] "package") "personality"
                if ($expectedPersonality -ne "mixed" -and
                    $scan.personality -cne $expectedPersonality) {
                    Add-Issue payload PAYLOAD_PERSONALITY `
                        "Payload '$path' is '$($scan.personality)', expected '$expectedPersonality' from '$sourceInput'"
                }
            }
        }

        foreach ($entry in $payloadEntries) {
            if ((Get-Property $entry "type") -ne "file") {
                continue
            }
            $path = Get-Property $entry "path"
            if (-not $peScanByPath.ContainsKey($path) -and
                $null -ne (Get-Property $entry "architecture")) {
                Add-Issue contract PAYLOAD_NON_PE_ARCHITECTURE `
                    "Non-PE payload '$path' must set architecture to null"
            }
        }
    } finally {
        Remove-Item -LiteralPath $candidateList, $peList -Force -ErrorAction SilentlyContinue
    }
}

$expectedPseudoRelocPaths = @($payloadEntries | Where-Object {
    $entry = $_
    $path = Get-Property $entry "path"
    $sourceInput = Get-Property $entry "sourceInput"
    $sourcePersonality = if ($resolvedInputById.ContainsKey([string]$sourceInput)) {
        Get-Property (Get-Property $resolvedInputById[$sourceInput] "package") "personality"
    } else { $null }
    (Get-Property $entry "type") -eq "file" -and
        $peScanByPath.ContainsKey([string]$path) -and
        $peScanByPath[$path].kind -eq "arm64" -and
        $sourcePersonality -eq "msys"
} | ForEach-Object {
    Get-Property $_ "path"
} | Sort-Object)

$pseudoReloc = if ($null -ne $provenanceObject) {
    Get-Property (Get-Property $provenanceObject "scanner") "pseudoReloc"
} else { $null }

if ($expectedPseudoRelocPaths.Count -gt 0 -or $null -ne $pseudoReloc) {
    $pseudoStatus = Get-Property $pseudoReloc "status"
    if ($pseudoStatus -eq "unresolved") {
        foreach ($field in @("script", "toolPackageInput", "objdump", "nm", "linker")) {
            if (-not (Has-Property $pseudoReloc $field) -or
                $null -ne (Get-Property $pseudoReloc $field)) {
                Add-Issue contract PSEUDO_RELOC_UNRESOLVED_FIELD `
                    "Unresolved pseudo-reloc field '$field' must be null"
            }
        }
        if (@(Get-Property $pseudoReloc "targets").Count -ne 0) {
            Add-Issue contract PSEUDO_RELOC_UNRESOLVED_TARGETS `
                "Unresolved pseudo-reloc validation cannot claim targets"
        }
        if ($modeLower -eq "final" -and $expectedPseudoRelocPaths.Count -gt 0) {
            Add-Issue payload PSEUDO_RELOC_UNRESOLVED `
                "Final mode requires pseudo-reloc validation for native MSYS PEs"
        } else {
            Add-Warning PSEUDO_RELOC_UNRESOLVED `
                "Pseudo-reloc validation is unresolved in preview mode"
        }
    } elseif ($pseudoStatus -eq "resolved") {
        $toolRootPath = $null
        if ([string]::IsNullOrWhiteSpace($ToolRoot)) {
            Add-Issue scanner PSEUDO_RELOC_TOOL_ROOT `
                "Resolved pseudo-reloc validation requires -ToolRoot"
        } elseif (Test-SharedMsysPath $ToolRoot) {
            Add-Issue scanner PSEUDO_RELOC_SHARED_TOOL_ROOT `
                "Pseudo-reloc tools cannot come from shared C:\msys64"
        } else {
            try {
                $toolRootPath = (Resolve-Path -LiteralPath $ToolRoot).Path.TrimEnd("\")
            } catch {
                Add-Issue scanner PSEUDO_RELOC_TOOL_ROOT `
                    "Pseudo-reloc tool root does not exist: $ToolRoot"
            }
        }

        $scriptIdentity = Get-Property $pseudoReloc "script"
        Assert-Equal (Get-Property $scriptIdentity "repository") `
            "crutkas/MSYS2-packages" contract PSEUDO_RELOC_SCRIPT_SOURCE `
            "Pseudo-reloc scanner repository"
        Assert-Equal (Get-Property $scriptIdentity "commit") `
            "3356eec1411983cc252b04afac32bca5f3b8d824" contract `
            PSEUDO_RELOC_SCRIPT_SOURCE "Pseudo-reloc scanner commit"
        Assert-Equal (Get-Property $scriptIdentity "sourceMember") `
            ".ci/check-aarch64-pseudo-relocs.ps1" contract `
            PSEUDO_RELOC_SCRIPT_SOURCE "Pseudo-reloc scanner sourceMember"
        Assert-Equal (Get-Property $scriptIdentity "bytes") 10569 contract `
            PSEUDO_RELOC_SCRIPT_BYTES "Pseudo-reloc scanner bytes"
        Assert-Equal (Get-Property $scriptIdentity "sha256") `
            "888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9" `
            contract PSEUDO_RELOC_SCRIPT_HASH "Pseudo-reloc scanner SHA-256"

        $toolInputId = Get-Property $pseudoReloc "toolPackageInput"
        $toolInput = if ($toolInputId -is [string] -and
            $resolvedInputById.ContainsKey($toolInputId)) {
            $resolvedInputById[$toolInputId]
        } else { $null }
        if ($null -eq $toolInput -or (Get-Property $toolInput "role") -ne "tool") {
            Add-Issue contract PSEUDO_RELOC_TOOL_INPUT `
                "Pseudo-reloc toolPackageInput '$toolInputId' is not a resolved tool input"
        } else {
            Assert-Equal (Get-Property (Get-Property $toolInput "package") "name") `
                "mingw-w64-cross-cygwinarm64-binutils" contract `
                PSEUDO_RELOC_TOOL_PACKAGE "Pseudo-reloc tool package name"
            Assert-Equal (Get-Property (Get-Property $toolInput "package") "version") `
                "2.44.50-2" contract PSEUDO_RELOC_TOOL_PACKAGE `
                "Pseudo-reloc tool package version"
            Assert-Equal (Get-Property (Get-Property $toolInput "asset") "sha256") `
                "3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b" `
                contract PSEUDO_RELOC_TOOL_PACKAGE "Pseudo-reloc tool package SHA-256"
        }

        $toolObjects = @(
            [pscustomobject]@{
                name = "objdump"
                identity = Get-Property $pseudoReloc "objdump"
                expectedName = "aarch64-pc-cygwin-objdump.exe"
                expectedHash = $null
            },
            [pscustomobject]@{
                name = "nm"
                identity = Get-Property $pseudoReloc "nm"
                expectedName = "aarch64-pc-cygwin-nm.exe"
                expectedHash = $null
            },
            [pscustomobject]@{
                name = "linker"
                identity = Get-Property $pseudoReloc "linker"
                expectedName = "aarch64-pc-cygwin-ld.exe"
                expectedHash = "075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f"
            }
        )
        $resolvedToolPaths = @{}
        foreach ($tool in $toolObjects) {
            $path = Get-Property $tool.identity "path"
            $hash = Get-Property $tool.identity "sha256"
            Assert-Equal (Get-Property $tool.identity "sourceInput") $toolInputId `
                contract PSEUDO_RELOC_TOOL_OWNER "Pseudo-reloc $($tool.name) sourceInput"
            if (-not (Test-RelativePath $path) -or
                [IO.Path]::GetFileName($path) -cne $tool.expectedName) {
                Add-Issue contract PSEUDO_RELOC_TOOL_PATH `
                    "Pseudo-reloc $($tool.name) path '$path' is invalid"
                continue
            }
            if (-not (Test-Sha256 $hash)) {
                Add-Issue contract PSEUDO_RELOC_TOOL_HASH `
                    "Pseudo-reloc $($tool.name) lacks a full SHA-256"
                continue
            }
            if ($null -ne $tool.expectedHash) {
                Assert-Equal $hash $tool.expectedHash contract PSEUDO_RELOC_TOOL_HASH `
                    "Pseudo-reloc $($tool.name) SHA-256"
            }
            if ($null -ne $toolRootPath) {
                $fullPath = Join-Path $toolRootPath $path.Replace("/", "\")
                if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                    Add-Issue scanner PSEUDO_RELOC_TOOL_MISSING `
                        "Pseudo-reloc $($tool.name) is missing: $path"
                } else {
                    Assert-Equal (Get-Sha256 $fullPath) $hash scanner `
                        PSEUDO_RELOC_TOOL_HASH "Pseudo-reloc $($tool.name) file SHA-256"
                    $resolvedToolPaths[$tool.name] = $fullPath
                }
            }
            foreach ($entry in $payloadEntries) {
                if ((Get-Property $entry "type") -eq "file" -and
                    (Get-Property $entry "sha256") -ceq $hash) {
                    Add-Issue contract PSEUDO_RELOC_TOOL_IN_PAYLOAD `
                        "Pseudo-reloc $($tool.name) must not be copied into payload '$((Get-Property $entry 'path'))'"
                }
            }
        }

        $scriptPath = Get-Property $scriptIdentity "path"
        $resolvedScriptPath = $null
        if (-not (Test-RelativePath $scriptPath)) {
            Add-Issue contract PSEUDO_RELOC_SCRIPT_PATH `
                "Pseudo-reloc scanner tool path '$scriptPath' is invalid"
        } elseif ($null -ne $toolRootPath) {
            $resolvedScriptPath = Join-Path $toolRootPath $scriptPath.Replace("/", "\")
            if (-not (Test-Path -LiteralPath $resolvedScriptPath -PathType Leaf)) {
                Add-Issue scanner PSEUDO_RELOC_SCRIPT_MISSING `
                    "Pseudo-reloc scanner is missing: $scriptPath"
                $resolvedScriptPath = $null
            } else {
                Assert-Equal (Get-Sha256 $resolvedScriptPath) `
                    (Get-Property $scriptIdentity "sha256") scanner `
                    PSEUDO_RELOC_SCRIPT_HASH "Pseudo-reloc scanner file SHA-256"
                Assert-Equal (Get-Item -LiteralPath $resolvedScriptPath).Length `
                    (Get-Property $scriptIdentity "bytes") scanner `
                    PSEUDO_RELOC_SCRIPT_BYTES "Pseudo-reloc scanner file bytes"
            }
        }

        $declaredTargets = @(Get-Property $pseudoReloc "targets")
        $targetSet = New-PathSet
        $previousTarget = $null
        foreach ($path in $declaredTargets) {
            if (-not (Test-RelativePath $path)) {
                Add-Issue contract PSEUDO_RELOC_TARGET `
                    "Invalid pseudo-reloc target '$path'"
                continue
            }
            if ($null -ne $previousTarget -and
                [StringComparer]::Ordinal.Compare($previousTarget, $path) -ge 0) {
                Add-Issue contract PSEUDO_RELOC_TARGET_ORDER `
                    "Pseudo-reloc targets must be uniquely sorted at '$path'"
            }
            $previousTarget = $path
            $targetSet[$path] = $true
        }
        foreach ($path in $expectedPseudoRelocPaths) {
            if (-not $targetSet.ContainsKey($path)) {
                Add-Issue contract PSEUDO_RELOC_TARGET_MISSING `
                    "Native MSYS PE '$path' is absent from pseudo-reloc targets"
            }
        }
        foreach ($path in $targetSet.Keys) {
            if ($expectedPseudoRelocPaths -cnotcontains $path) {
                Add-Issue contract PSEUDO_RELOC_TARGET_EXTRA `
                    "Pseudo-reloc target '$path' is not a native MSYS PE"
            }
        }

        if ($null -ne $resolvedScriptPath -and
            $resolvedToolPaths.ContainsKey("objdump") -and
            $resolvedToolPaths.ContainsKey("nm")) {
            $pwsh = Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue
            if ($null -eq $pwsh) {
                $pwsh = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue
            }
            if ($null -eq $pwsh) {
                Add-Issue scanner PSEUDO_RELOC_PWSH `
                    "Pseudo-reloc validation requires pwsh"
            } else {
                foreach ($path in $declaredTargets) {
                    if (-not $peScanByPath.ContainsKey([string]$path)) {
                        continue
                    }
                    $outputPath = Join-Path ([IO.Path]::GetTempPath()) `
                        "pseudo-reloc-$PID-$($pseudoRelocResults.Count).json"
                    $targetPath = Join-Path $rootPath $path.Replace("/", "\")
                    try {
                        & $pwsh.Source -NoProfile -File $resolvedScriptPath `
                            -PePath $targetPath -OutputPath $outputPath `
                            -Objdump $resolvedToolPaths["objdump"] `
                            -Nm $resolvedToolPaths["nm"]
                        $exitCode = $LASTEXITCODE
                        if ($exitCode -ne 0 -or
                            -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
                            Add-Issue payload PSEUDO_RELOC_POLICY `
                                "Pseudo-reloc scanner rejected '$path' with exit code $exitCode"
                            continue
                        }
                        try {
                            $result = Get-Content -LiteralPath $outputPath -Raw |
                                ConvertFrom-Json
                        } catch {
                            Add-Issue scanner PSEUDO_RELOC_OUTPUT `
                                "Pseudo-reloc scanner emitted invalid JSON for '$path'"
                            continue
                        }
                        if ((Get-Property $result "result") -ne "pass") {
                            Add-Issue payload PSEUDO_RELOC_POLICY `
                                "Pseudo-reloc result for '$path' is not pass"
                            continue
                        }
                        $flags = @(Get-Property $result "flags")
                        if (@($flags | Where-Object { [int]$_ -ne 64 }).Count -gt 0) {
                            Add-Issue payload PSEUDO_RELOC_FLAGS `
                                "Pseudo-reloc target '$path' contains non-scalar64 flags"
                        }
                        if ((Get-Property $result "table_format") -eq "v1" -and
                            [int](Get-Property $result "record_count") -gt 0) {
                            Add-Issue payload PSEUDO_RELOC_V1 `
                                "Pseudo-reloc target '$path' contains a nonempty v1 table"
                        }
                        $pseudoRelocResults.Add([pscustomobject]@{
                            path = $path
                            resultSha256 = Get-Sha256 $outputPath
                            tableFormat = Get-Property $result "table_format"
                            recordCount = Get-Property $result "record_count"
                            flags = $flags
                        })
                    } catch {
                        Add-Issue scanner PSEUDO_RELOC_EXECUTION `
                            "Pseudo-reloc scanner failed for '$path': $($_.Exception.Message)"
                    } finally {
                        Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    } elseif ($expectedPseudoRelocPaths.Count -gt 0) {
        Add-Issue contract PSEUDO_RELOC_MISSING `
            "Provenance lacks pseudo-reloc validation for native MSYS PEs"
    }
}

$baselinePaths = New-PathSet
if (-not (Test-Path -LiteralPath $Baseline -PathType Leaf)) {
    Add-Issue contract BASELINE_MISSING "x64 baseline does not exist: $Baseline"
} else {
    $previous = $null
    foreach ($path in @(Get-Content -LiteralPath $Baseline | ForEach-Object {
        $_.TrimEnd("`r")
    })) {
        if (-not (Test-RelativePath $path)) {
            Add-Issue contract BASELINE_PATH "Invalid x64 baseline path '$path'"
            continue
        }
        if ($null -ne $previous -and [StringComparer]::Ordinal.Compare($previous, $path) -ge 0) {
            Add-Issue contract BASELINE_ORDER `
                "x64 baseline is not uniquely sorted at '$path'"
        }
        $previous = $path
        $baselinePaths[$path] = $true
    }
}

foreach ($path in $x64Paths) {
    if (-not $baselinePaths.ContainsKey($path)) {
        Add-Issue payload PAYLOAD_NEW_X64 "Unexpected x64 payload '$path'"
    }
}
if ($modeLower -eq "final" -and $x64Paths.Count -gt 0) {
    Add-Issue payload PAYLOAD_X64_FINAL `
        "Final mode requires zero x64 payloads; found $($x64Paths.Count)"
} elseif ($modeLower -eq "preview" -and $x64Paths.Count -gt 0) {
    Add-Warning PAYLOAD_X64_PREVIEW `
        "Preview contains $($x64Paths.Count) baseline x64 payloads"
}

$requiredScenarios = [ordered]@{
    "git-bash" = @([pscustomobject]@{ role = "shell"; personality = "msys" })
    "git" = @([pscustomobject]@{ role = "git"; personality = "mingw" })
    "ssh" = @([pscustomobject]@{ role = "ssh"; personality = "mingw" })
    "gpg" = @([pscustomobject]@{ role = "gpg"; personality = "mingw" })
    "hook" = @(
        [pscustomobject]@{ role = "git"; personality = "mingw" },
        [pscustomobject]@{ role = "hook"; personality = "msys" }
    )
    "submodule" = @(
        [pscustomobject]@{ role = "git"; personality = "mingw" },
        [pscustomobject]@{ role = "submodule"; personality = "mingw" }
    )
    "rebase" = @(
        [pscustomobject]@{ role = "git"; personality = "mingw" },
        [pscustomobject]@{ role = "rebase"; personality = "msys" }
    )
    "git-svn" = @(
        [pscustomobject]@{ role = "git"; personality = "mingw" },
        [pscustomobject]@{ role = "git-svn"; personality = "msys" }
    )
}
$unresolvedScenarioIds = New-Object System.Collections.Generic.List[string]

if ($null -ne $evidenceObject) {
    Assert-Equal (Get-Property $evidenceObject "schemaVersion") 1 runtime `
        EVIDENCE_SCHEMA "Evidence schemaVersion"
    Assert-Equal (Get-Property $evidenceObject "mode") $modeLower runtime `
        EVIDENCE_MODE "Evidence mode"
    Assert-Equal (Get-Property $evidenceObject "lockSha256") $lockSha256 runtime `
        EVIDENCE_LOCK_DIGEST "Evidence lockSha256"
    Assert-Equal (Get-Property $evidenceObject "provenanceSha256") `
        $provenanceSha256 runtime EVIDENCE_PROVENANCE_DIGEST `
        "Evidence provenanceSha256"
    Assert-Equal (Get-Property $evidenceObject "payloadSha256") $payloadSha256 runtime `
        EVIDENCE_PAYLOAD_DIGEST "Evidence payloadSha256"
    $hostObject = Get-Property $evidenceObject "host"
    Assert-Equal (Get-Property $hostObject "os") "windows" runtime `
        EVIDENCE_HOST_OS "Evidence host OS"
    Assert-Equal (Get-Property $hostObject "architecture") "arm64" runtime `
        EVIDENCE_HOST_ARCH "Evidence host architecture"
    Assert-Equal (Get-Property $hostObject "nativeArchitecture") "arm64" runtime `
        EVIDENCE_NATIVE_ARCH "Evidence native architecture"
    try {
        $evidenceCreated = [DateTimeOffset]::Parse(
            [string](Get-Property $evidenceObject "createdAt"))
        if ($evidenceCreated.Offset -ne [TimeSpan]::Zero) {
            Add-Issue runtime EVIDENCE_TIME "Evidence createdAt must be UTC"
        }
    } catch {
        Add-Issue runtime EVIDENCE_TIME "Evidence createdAt is not RFC 3339"
    }
    $collector = Get-Property $evidenceObject "collector"
    if ((Get-Property $collector "repository") -notmatch "^crutkas/[^/]+$" -or
        -not (Test-Commit (Get-Property $collector "commit")) -or
        -not (Test-RelativePath (Get-Property $collector "path")) -or
        -not (Test-Sha256 (Get-Property $collector "sha256"))) {
        Add-Issue runtime EVIDENCE_COLLECTOR `
            "Evidence collector lacks immutable fork-only identity"
    }
    Assert-Equal (Get-Property $collector "method") `
        "etw-kernel-process-image-load" runtime EVIDENCE_COLLECTOR_METHOD `
        "Evidence collector method"

    $scenarioById = New-PathSet
    foreach ($scenario in @(Get-Property $evidenceObject "scenarios")) {
        $id = Get-Property $scenario "id"
        if ($id -isnot [string] -or -not $requiredScenarios.Contains($id)) {
            Add-Issue runtime EVIDENCE_SCENARIO "Unknown evidence scenario '$id'"
            continue
        }
        if (-not (Add-Unique $scenarioById $id EVIDENCE_DUPLICATE_SCENARIO `
            "evidence scenario")) {
            continue
        }
        $scenarioById[$id] = $scenario

        $status = Get-Property $scenario "status"
        if ($status -eq "unresolved") {
            $unresolvedScenarioIds.Add($id)
            if (@(Get-Property $scenario "processes").Count -ne 0 -or
                [string]::IsNullOrWhiteSpace([string](Get-Property $scenario "reason"))) {
                Add-Issue runtime EVIDENCE_UNRESOLVED_CONTENT `
                    "Unresolved scenario '$id' requires a reason and no process claims"
            }
            if ($modeLower -eq "final") {
                Add-Issue runtime EVIDENCE_UNRESOLVED_FINAL `
                    "Final mode rejects unresolved scenario '$id'"
            } else {
                Add-Warning EVIDENCE_UNRESOLVED "Preview scenario '$id' is unresolved"
            }
            continue
        }
        if ($status -ne "passed") {
            Add-Issue runtime EVIDENCE_STATUS "Scenario '$id' has invalid status '$status'"
            continue
        }
        Assert-Equal (Get-Property $scenario "exitCode") 0 runtime `
            EVIDENCE_EXIT "Scenario '$id' exitCode"
        Assert-Equal (Get-Property $scenario "traceComplete") $true runtime `
            EVIDENCE_TRACE "Scenario '$id' traceComplete"
        $command = @(Get-Property $scenario "command")
        if ($command.Count -eq 0 -or @($command | Where-Object {
            $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)
        }).Count -gt 0) {
            Add-Issue runtime EVIDENCE_COMMAND `
                "Scenario '$id' lacks an exact command vector"
        }
        $processes = @(Get-Property $scenario "processes")
        if ($processes.Count -eq 0) {
            Add-Issue runtime EVIDENCE_PROCESSES "Scenario '$id' has no process evidence"
            continue
        }

        $processInstances = New-PathSet
        foreach ($process in $processes) {
            $role = Get-Property $process "role"
            $payloadPath = Get-Property $process "payloadPath"
            $processId = Get-Property $process "processId"
            $startedAt = Get-Property $process "startedAt"
            if ($processId -isnot [int] -and $processId -isnot [long]) {
                Add-Issue runtime EVIDENCE_PROCESS_ID `
                    "Scenario '$id' process role '$role' has invalid processId"
            } else {
                [void](Add-Unique $processInstances "$processId@$startedAt" `
                    EVIDENCE_DUPLICATE_PROCESS "process instance in '$id'")
            }
            try {
                [void][DateTimeOffset]::Parse([string]$startedAt)
                [void][DateTimeOffset]::Parse(
                    [string](Get-Property $process "endedAt"))
            } catch {
                Add-Issue runtime EVIDENCE_PROCESS_TIME `
                    "Scenario '$id' process role '$role' has invalid timestamps"
            }
            if (-not (Test-RelativePath $payloadPath) -or
                -not $payloadEntryByPath.ContainsKey([string]$payloadPath)) {
                Add-Issue runtime EVIDENCE_PROCESS_PAYLOAD `
                    "Scenario '$id' process role '$role' has invalid payloadPath '$payloadPath'"
                continue
            }
            if (Test-SharedMsysPath (Get-Property $process "path")) {
                Add-Issue runtime EVIDENCE_SHARED_MSYS `
                    "Scenario '$id' process uses forbidden shared C:\msys64"
            }
            $payloadEntry = $payloadEntryByPath[$payloadPath]
            Assert-Equal (Get-Property $process "sha256") `
                (Get-Property $payloadEntry "sha256") runtime EVIDENCE_PROCESS_HASH `
                "Scenario '$id' process '$payloadPath' SHA-256"
            $processArch = Get-Property $process "architecture"
            $payloadArch = Get-Property $payloadEntry "architecture"
            foreach ($field in @("kind", "machine", "personality")) {
                Assert-Equal (Get-Property $processArch $field) `
                    (Get-Property $payloadArch $field) runtime EVIDENCE_PROCESS_ARCH `
                    "Scenario '$id' process '$payloadPath' architecture.$field"
            }
            if ((Get-Property $processArch "kind") -ne "arm64") {
                Add-Issue runtime EVIDENCE_FOREIGN_PROCESS `
                    "Scenario '$id' observed non-ARM64 process '$payloadPath'"
            }
            if ((Get-Property $processArch "personality") -eq "cygwin") {
                Add-Issue runtime EVIDENCE_CYGWIN_PROCESS `
                    "Scenario '$id' observed Cygwin process '$payloadPath'"
            }
            Assert-Equal (Get-Property $process "modulesComplete") $true runtime `
                EVIDENCE_MODULE_TRACE "Scenario '$id' process '$payloadPath' modulesComplete"
            $modules = @(Get-Property $process "modules")
            if ($modules.Count -eq 0) {
                Add-Issue runtime EVIDENCE_MODULES `
                    "Scenario '$id' process '$payloadPath' has no module evidence"
            }
            foreach ($module in $modules) {
                if (Test-SharedMsysPath (Get-Property $module "path")) {
                    Add-Issue runtime EVIDENCE_SHARED_MSYS `
                        "Scenario '$id' module uses forbidden shared C:\msys64"
                }
                $moduleArch = Get-Property $module "architecture"
                if ((Get-Property $moduleArch "kind") -notin @("arm64", "anycpu")) {
                    Add-Issue runtime EVIDENCE_FOREIGN_MODULE `
                        "Scenario '$id' observed foreign module '$((Get-Property $module 'path'))'"
                }
                if ((Get-Property $moduleArch "personality") -eq "cygwin") {
                    Add-Issue runtime EVIDENCE_CYGWIN_MODULE `
                        "Scenario '$id' observed Cygwin module '$((Get-Property $module 'path'))'"
                }
                $modulePayloadPath = Get-Property $module "payloadPath"
                if ($null -ne $modulePayloadPath -and [string]$modulePayloadPath -ne "") {
                    if (-not (Test-RelativePath $modulePayloadPath) -or
                        -not $payloadEntryByPath.ContainsKey([string]$modulePayloadPath)) {
                        Add-Issue runtime EVIDENCE_MODULE_PAYLOAD `
                            "Scenario '$id' module has invalid payloadPath '$modulePayloadPath'"
                        continue
                    }
                    $moduleEntry = $payloadEntryByPath[$modulePayloadPath]
                    Assert-Equal (Get-Property $module "sha256") `
                        (Get-Property $moduleEntry "sha256") runtime EVIDENCE_MODULE_HASH `
                        "Scenario '$id' module '$modulePayloadPath' SHA-256"
                    foreach ($field in @("kind", "machine", "personality")) {
                        Assert-Equal (Get-Property $moduleArch $field) `
                            (Get-Property (Get-Property $moduleEntry "architecture") $field) `
                            runtime EVIDENCE_MODULE_ARCH `
                            "Scenario '$id' module '$modulePayloadPath' architecture.$field"
                    }
                } else {
                    Assert-Equal (Get-Property $module "origin") "windows" runtime `
                        EVIDENCE_MODULE_ORIGIN `
                        "Scenario '$id' external module origin"
                    if ((Get-Property $module "path") -notmatch "(?i)^[A-Z]:\\Windows\\") {
                        Add-Issue runtime EVIDENCE_EXTERNAL_MODULE_PATH `
                            "Scenario '$id' external module is not under C:\Windows"
                    }
                    if (-not (Test-Sha256 (Get-Property $module "sha256"))) {
                        Add-Issue runtime EVIDENCE_EXTERNAL_MODULE_HASH `
                            "Scenario '$id' external module lacks a full SHA-256"
                    }
                }
            }
        }

        foreach ($requirement in $requiredScenarios[$id]) {
            $requiredRole = $requirement.role
            $requiredPersonality = $requirement.personality
            $matches = @($processes | Where-Object {
                (Get-Property $_ "role") -ceq $requiredRole -and
                (Get-Property (Get-Property $_ "architecture") "personality") -ceq `
                    $requiredPersonality
            })
            if ($matches.Count -eq 0) {
                Add-Issue runtime EVIDENCE_REQUIRED_ROLE `
                    "Scenario '$id' lacks ARM64 $requiredRole/$requiredPersonality evidence"
            }
        }
    }
    foreach ($id in $requiredScenarios.Keys) {
        if (-not $scenarioById.ContainsKey($id)) {
            Add-Issue runtime EVIDENCE_SCENARIO_MISSING `
                "Required runtime scenario '$id' is missing"
        }
    }
}

$readyForFinal = $issues.Count -eq 0 -and $x64Paths.Count -eq 0 -and
    $unresolvedInputIds.Count -eq 0 -and $unresolvedScenarioIds.Count -eq 0

$reportObject = [ordered]@{
    schemaVersion = 1
    mode = $modeLower
    status = if ($issues.Count -eq 0) { "passed" } else { "failed" }
    readyForFinal = $readyForFinal
    inputs = [ordered]@{
        lockSha256 = $lockSha256
        provenanceSha256 = $provenanceSha256
        payloadSha256 = $payloadSha256
        runtimeEvidenceSha256 = $evidenceSha256
    }
    payload = [ordered]@{
        entries = $payloadEntryByPath.Count
        peFiles = $peScanByPath.Count
        architectures = $payloadCounts
        x64Paths = @($x64Paths | Sort-Object)
        pseudoReloc = @($pseudoRelocResults | ForEach-Object { $_ })
    }
    unresolved = [ordered]@{
        inputs = @($unresolvedInputIds | Sort-Object)
        scenarios = @($unresolvedScenarioIds | Sort-Object)
    }
    warnings = @($warnings | ForEach-Object { $_ })
    issues = @($issues | ForEach-Object { $_ })
}

try {
    $reportDirectory = Split-Path -Parent $Report
    if ($reportDirectory -and -not (Test-Path -LiteralPath $reportDirectory)) {
        [void](New-Item -ItemType Directory -Path $reportDirectory)
    }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Report,
        ($reportObject | ConvertTo-Json -Depth 20) + "`n", $utf8)
} catch {
    Write-Error "Could not write validation report '$Report': $($_.Exception.Message)"
    exit 1
}

Write-Host "ARM64 bundle validation ($modeLower): $($reportObject.status)"
Write-Host "Payload architectures: ARM64=$($payloadCounts.arm64), x64=$($payloadCounts.x64), x86=$($payloadCounts.x86), AnyCPU=$($payloadCounts.anycpu)"
Write-Host "Unresolved inputs=$($unresolvedInputIds.Count), scenarios=$($unresolvedScenarioIds.Count)"
Write-Host "Report: $Report"

foreach ($issue in $issues) {
    Write-Error "[$($issue.category)/$($issue.code)] $($issue.message)" `
        -ErrorAction Continue
}

if ($issues.Count -eq 0) {
    exit 0
}
if (@($issues | Where-Object category -eq "scanner").Count -gt 0) {
    exit 1
}
if (@($issues | Where-Object category -eq "contract").Count -gt 0) {
    exit 2
}
if (@($issues | Where-Object category -eq "payload").Count -gt 0) {
    exit 3
}
exit 4
