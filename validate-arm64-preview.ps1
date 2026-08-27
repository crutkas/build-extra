# validate-arm64-preview.ps1 - Authoritative ARM64 preview payload validator.
#
# This script is the single fail-closed post-materialization admission point.
# It never downloads, extracts or assembles anything: every
# artifact it inspects must already exist on disk and must already be described
# by the input documents.
#
#   pwsh -NoProfile -File validate-arm64-preview.ps1 \
#       -Mode preview|final \
#       -PortableRoot <root> \
#       -LockPath <lock.json> \
#       -ProvenancePath <provenance.json> \
#       -PayloadManifestPath <payload.json> \
#       -OutputPath <evidence.json>
#
#       -RuntimeEvidencePath <runtime-evidence.json>
#
# Exit codes (exact):
#
#   0   Ready/compliant: every contract, content and policy check passed.
#   2   Preview only: the inputs are structurally valid but the payload is not
#       ready because at least one package slot is still unresolved.  Evidence
#       is written and never claims readiness.
#   3   Policy or content validation failure.  Evidence is written and lists
#       every violation.
#   64  Usage error (missing, unknown or mutually exclusive arguments).
#   65  Malformed or missing input, input-contract violation, or a digest
#       binding failure between lock, provenance, payload manifest and runtime
#       evidence.  No evidence is written because the inputs cannot be trusted.
#   70  Unexpected internal failure.
#
# JSON contracts (all documents use "schemaVersion": 1 and an exact "kind"):
#
#   git-for-windows/arm64-preview-lock
#     { schemaVersion, kind, nativeShellClosure: [ <path> ],
#       packages: [ { name, slot, resolved, version?, archive? } ] }
#
#   git-for-windows/arm64-preview-provenance
#     { schemaVersion, kind, previewId, lock: { path, sha256 },
#       payload: { path, sha256 }, assembler, validator, inputs }
#
#   git-for-windows/arm64-preview-payload-manifest
#     { schemaVersion, kind,
#       scope: { root: ".", excludedPrefixes: [ "preview-evidence/" ] },
#       lock: { bytes, sha256 },
#       files: [ { path, type, bytes, sha256, linkTarget, owner } ],
#       archives?: [ { path, format, bytes, sha256, owner,
#                      members: [ { path, type, bytes, sha256, linkTarget,
#                                   owner } ] } ] }
#
#   git-for-windows/arm64-preview-runtime-evidence
#     { schemaVersion, kind,
#       binding: { lockSha256, provenanceSha256, payloadManifestSha256,
#                  rootInventorySha256 },
#       collection: { method, complete, droppedEvents, startedAt, completedAt,
#                     hostArchitecture },
#       smokes: [ { name, command, exitCode, succeeded, processPid } ],
#       processes: [ { pid, path, architecture, modules: [ <path> ] } ],
#       modules: [ { path, architecture, bytes, sha256 } ] }
#
#   git-for-windows/arm64-preview-validation-evidence (this script's output)
#
# Portable-root inventory SHA256 (canonical algorithm, version 1):
#
#   1. Enumerate every non-directory entry below the portable root
#      recursively.  Plain directories are skipped; reparse-point links are
#      recorded even when they point at a directory.
#   2. Express every path relative to the root using forward slashes.
#   3. Sort ascending using an ordinal (case sensitive) comparison of the
#      relative path.
#   4. Emit one record per entry:
#        <path> TAB <type> TAB <bytes> TAB <sha256> TAB <linkTarget> LF
#      where <type> is "file" or "symlink", <bytes> is the decimal file size
#      (0 for links), <sha256> is the lowercase file digest ("-" for links)
#      and <linkTarget> is the link target with backslashes replaced by
#      forward slashes ("-" for files).
#   5. Encode the concatenated records as UTF-8 without a byte-order mark and
#      report the lowercase SHA-256 of those bytes.
#
# Architecture policy:
#
#   A PE file is acceptable when its machine type is ARM64, or when it is an
#   AnyCPU CLR assembly, or when it is a mixed-mode CLR image whose machine
#   type is ARM64.  Everything else (x64, x86, ARM64EC and anything the parser
#   cannot classify) is rejected.  ARM64EC images embed x64 code, so they are
#   reported as "unknown" and rejected rather than silently accepted.
#
#   - preview: files outside lock.nativeShellClosure are inventoried and
#     reported, and broader x64 content does not fail the run.  Any x64, x86 or
#     unknown file referenced by lock.nativeShellClosure fails the run.
#   - final: any unacceptable PE file anywhere in the payload fails the run,
#     and unresolved package slots fail the run.
#   Both modes require event-complete runtime evidence.  The native shell
#   closure and every observed process and module must be ARM64.

[CmdletBinding()]
param(
    [string]$Mode,
    [string]$PortableRoot,
    [string]$LockPath,
    [string]$ProvenancePath,
    [string]$PayloadManifestPath,
    [string]$RuntimeEvidencePath,
    [string]$OutputPath,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$script:ExitReady = 0
$script:ExitNotReady = 2
$script:ExitPolicy = 3
$script:ExitUsage = 64
$script:ExitInput = 65
$script:ExitInternal = 70

$script:KindLock = 'git-for-windows/arm64-preview-lock'
$script:KindProvenance = 'git-for-windows/arm64-preview-provenance'
$script:KindPayload = 'git-for-windows/arm64-preview-payload-manifest'
$script:KindRuntime = 'git-for-windows/arm64-preview-runtime-evidence'
$script:KindEvidence = 'git-for-windows/arm64-preview-validation-evidence'
$script:SchemaVersion = 1
$script:InventoryAlgorithm = 'gfw-arm64-preview-root-inventory-v1'
$script:RuntimeCollectionMethod = 'etw-image-load'
$script:EvidencePrefix = 'preview-evidence/'
$script:ValidatorRepository = 'crutkas/build-extra'

class ValidatorUsageException : System.Exception {
    ValidatorUsageException([string]$message) : base($message) { }
}

class ValidatorInputException : System.Exception {
    ValidatorInputException([string]$message) : base($message) { }
}

function Stop-WithUsageError([string]$Message) {
    throw [ValidatorUsageException]::new($Message)
}

function Stop-WithInputError([string]$Message) {
    throw [ValidatorInputException]::new($Message)
}

function Show-Usage {
    @(
        'usage: validate-arm64-preview.ps1 -Mode preview|final -PortableRoot <root>',
        '           -LockPath <lock.json> -ProvenancePath <provenance.json>',
        '           -PayloadManifestPath <payload.json>',
        '           -RuntimeEvidencePath <runtime-evidence.json> -OutputPath <evidence.json>',
        '',
        'exit codes: 0 ready/compliant, 2 preview structurally valid but not ready,',
        '            3 policy or content violation (evidence written), 64 usage,',
        '            65 malformed input or digest binding failure, 70 internal error.'
    ) -join [System.Environment]::NewLine
}

function ConvertTo-ForwardSlash([string]$Value) {
    if ($null -eq $Value) { return $null }
    return ($Value -replace '\\', '/')
}

function Sort-OrdinalPath {
    param([object[]]$Items, [string]$Property)

    $array = @($Items)
    if ($array.Count -le 1) { return $array }
    $copy = [object[]]::new($array.Count)
    [System.Array]::Copy($array, $copy, $array.Count)
    $comparer = [System.Comparison[object]] {
        param($a, $b)
        $left = if ($Property) { [string]$a.$Property } else { [string]$a }
        $right = if ($Property) { [string]$b.$Property } else { [string]$b }
        return [string]::CompareOrdinal($left, $right)
    }
    [System.Array]::Sort($copy, $comparer)
    return $copy
}

function Test-PlaceholderString([string]$Value) {
    if ($null -eq $Value) { return $true }
    $trimmed = $Value.Trim()
    if ($trimmed.Length -eq 0) { return $true }
    $upper = $trimmed.ToUpperInvariant()
    $known = @('TBD', 'TODO', 'PLACEHOLDER', 'CHANGEME', 'XXX', 'N/A', 'NONE', 'FIXME', 'UNKNOWN', 'REPLACE_ME')
    if ($known -contains $upper) { return $true }
    if ($upper.Contains('PLACEHOLDER')) { return $true }
    if ($trimmed -match '^<.*>$') { return $true }
    return $false
}

function Test-Sha256String([string]$Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { return $false }
    if ($Value -eq ('0' * 64)) { return $false }
    return $true
}

function Test-RelativePathValue([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.Contains('\')) { return $false }
    if ($Value.StartsWith('/')) { return $false }
    if ($Value.EndsWith('/')) { return $false }
    if ($Value -match '^[A-Za-z]:') { return $false }
    foreach ($ch in $Value.ToCharArray()) {
        if ([char]::IsControl($ch)) { return $false }
    }
    foreach ($segment in $Value.Split('/')) {
        if ($segment.Length -eq 0) { return $false }
        if ($segment -eq '.' -or $segment -eq '..') { return $false }
        if ($segment -ne $segment.Trim()) { return $false }
    }
    return $true
}

function Assert-RelativePath {
    param([string]$Value, [string]$Context)

    if (-not ($Value -is [string])) {
        Stop-WithInputError "$Context must be a string path"
    }
    if (Test-PlaceholderString $Value) {
        Stop-WithInputError "$Context is empty or a placeholder"
    }
    if (-not (Test-RelativePathValue $Value)) {
        Stop-WithInputError "$Context is not a safe relative forward-slash path: '$Value'"
    }
    return $Value
}

function Assert-PayloadPath {
    param([string]$Value, [string]$Context)

    $path = Assert-RelativePath -Value $Value -Context $Context
    if ($path.StartsWith($script:EvidencePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-WithInputError "$Context must be outside the excluded preview-evidence prefix"
    }
    return $path
}

function Assert-Sha256 {
    param([string]$Value, [string]$Context)

    if (-not ($Value -is [string])) {
        Stop-WithInputError "$Context must be a lowercase hexadecimal SHA-256 string"
    }
    if (Test-PlaceholderString $Value) {
        Stop-WithInputError "$Context is empty or a placeholder"
    }
    if (-not (Test-Sha256String $Value)) {
        Stop-WithInputError "$Context is not a valid lowercase SHA-256 digest: '$Value'"
    }
    return $Value
}

function Assert-NonNegativeInteger {
    param($Value, [string]$Context)

    if ($Value -is [bool]) { Stop-WithInputError "$Context must be a non-negative integer" }
    if (-not (($Value -is [int]) -or ($Value -is [long]) -or ($Value -is [double]) -or ($Value -is [decimal]))) {
        Stop-WithInputError "$Context must be a non-negative integer"
    }
    $asDouble = [double]$Value
    if ([math]::Floor($asDouble) -ne $asDouble) {
        Stop-WithInputError "$Context must be a non-negative integer"
    }
    if ($asDouble -lt 0) {
        Stop-WithInputError "$Context must be a non-negative integer"
    }
    return [long]$asDouble
}

function Assert-Boolean {
    param($Value, [string]$Context)

    if (-not ($Value -is [bool])) {
        Stop-WithInputError "$Context must be a boolean"
    }
    return [bool]$Value
}

function Get-MemberValue {
    param([psobject]$Object, [string]$Name)

    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -ceq $Name) {
            if ($property.Value -is [System.Array]) { return ,$property.Value }
            return $property.Value
        }
    }
    return $null
}

function Test-HasMember {
    param([psobject]$Object, [string]$Name)

    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -ceq $Name) { return $true }
    }
    return $false
}

function Assert-ObjectMembers {
    param(
        $Object,
        [string[]]$Required,
        [string[]]$Optional = @(),
        [string]$Context
    )

    if ($null -eq $Object -or -not ($Object -is [psobject]) -or ($Object -is [System.Array])) {
        Stop-WithInputError "$Context must be a JSON object"
    }
    $allowed = @($Required) + @($Optional)
    foreach ($name in $Required) {
        if (-not (Test-HasMember -Object $Object -Name $name)) {
            Stop-WithInputError "$Context is missing required member '$name'"
        }
    }
    foreach ($property in $Object.PSObject.Properties) {
        if ($allowed -cnotcontains $property.Name) {
            Stop-WithInputError "$Context contains unexpected member '$($property.Name)'"
        }
    }
    return $Object
}

function Assert-JsonArray {
    param($Value, [string]$Context, [switch]$AllowEmpty)

    if ($null -eq $Value -or -not ($Value -is [System.Array])) {
        Stop-WithInputError "$Context must be a JSON array"
    }
    if (-not $AllowEmpty -and $Value.Count -eq 0) {
        Stop-WithInputError "$Context must not be empty"
    }
    return @($Value)
}

function Get-FileSha256 {
    param([string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-JsonDocument {
    param([string]$Path, [string]$Context)

    if (-not [System.IO.File]::Exists($Path)) {
        Stop-WithInputError "$Context file does not exist: $Path"
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) {
        Stop-WithInputError "$Context file is empty: $Path"
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    try {
        $document = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Stop-WithInputError "$Context is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $document -or -not ($document -is [psobject]) -or ($document -is [System.Array])) {
        Stop-WithInputError "$Context must contain a single JSON object"
    }
    return [pscustomobject]@{
        Path     = $Path
        Bytes    = [long]$bytes.Length
        Sha256   = Get-BytesSha256 -Bytes $bytes
        Document = $document
    }
}

function Assert-DocumentHeader {
    param($Document, [string]$Kind, [string]$Context)

    $schemaVersion = Get-MemberValue -Object $Document -Name 'schemaVersion'
    if ($null -eq $schemaVersion -or ([long]$schemaVersion) -ne $script:SchemaVersion) {
        Stop-WithInputError "$Context must declare schemaVersion $($script:SchemaVersion)"
    }
    $actualKind = Get-MemberValue -Object $Document -Name 'kind'
    if (-not ($actualKind -is [string]) -or ($actualKind -cne $Kind)) {
        Stop-WithInputError "$Context must declare kind '$Kind'"
    }
}

function Read-UInt16 {
    param([byte[]]$Buffer, [int]$Offset)
    return [System.BitConverter]::ToUInt16($Buffer, $Offset)
}

function Read-UInt32 {
    param([byte[]]$Buffer, [int]$Offset)
    return [System.BitConverter]::ToUInt32($Buffer, $Offset)
}

function Read-ExactBytes {
    param([System.IO.FileStream]$Stream, [long]$Offset, [int]$Count)

    if ($Offset -lt 0 -or ($Offset + $Count) -gt $Stream.Length) { return $null }
    $buffer = [byte[]]::new($Count)
    $Stream.Position = $Offset
    $read = 0
    while ($read -lt $Count) {
        $chunk = $Stream.Read($buffer, $read, $Count - $read)
        if ($chunk -le 0) { return $null }
        $read += $chunk
    }
    return $buffer
}

# Classify a file as PE and, when it is, determine its machine architecture and
# its CLR flavour.  Returns $null when the file is not a PE image.
function Get-PeInfo {
    param([string]$Path)

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    } catch {
        Stop-WithInputError "could not open payload file for PE inspection: $Path"
    }
    try {
        $magic = Read-ExactBytes -Stream $stream -Offset 0 -Count 2
        if ($null -eq $magic -or $magic[0] -ne 0x4D -or $magic[1] -ne 0x5A) {
            return $null
        }
        $unknown = [pscustomobject]@{ IsPe = $true; Architecture = 'unknown'; ClrKind = 'unknown' }
        $dos = Read-ExactBytes -Stream $stream -Offset 0 -Count 64
        if ($null -eq $dos) { return $unknown }
        $peOffset = [long](Read-UInt32 -Buffer $dos -Offset 0x3C)
        $signature = Read-ExactBytes -Stream $stream -Offset $peOffset -Count 4
        if ($null -eq $signature) { return $unknown }
        if ($signature[0] -ne 0x50 -or $signature[1] -ne 0x45 -or $signature[2] -ne 0 -or $signature[3] -ne 0) {
            return $unknown
        }

        $coff = Read-ExactBytes -Stream $stream -Offset ($peOffset + 4) -Count 20
        if ($null -eq $coff) { return $unknown }
        $machine = Read-UInt16 -Buffer $coff -Offset 0
        $sectionCount = [int](Read-UInt16 -Buffer $coff -Offset 2)
        $optionalSize = [int](Read-UInt16 -Buffer $coff -Offset 16)

        $architecture = switch ($machine) {
            0xAA64 { 'arm64' }
            0x8664 { 'x64' }
            0x014C { 'x86' }
            default { 'unknown' }
        }

        $result = [pscustomobject]@{ IsPe = $true; Architecture = $architecture; ClrKind = 'unknown' }
        if ($optionalSize -lt 96) { return $result }

        $optionalOffset = $peOffset + 4 + 20
        $optional = Read-ExactBytes -Stream $stream -Offset $optionalOffset -Count $optionalSize
        if ($null -eq $optional) { return $result }
        $magic = Read-UInt16 -Buffer $optional -Offset 0
        if ($magic -eq 0x10B) {
            $rvaCountOffset = 92
            $dataDirOffset = 96
        } elseif ($magic -eq 0x20B) {
            $rvaCountOffset = 108
            $dataDirOffset = 112
        } else {
            return $result
        }
        if ($optionalSize -lt ($dataDirOffset + 128)) {
            $result.ClrKind = 'native'
            return $result
        }
        $rvaCount = [int](Read-UInt32 -Buffer $optional -Offset $rvaCountOffset)
        if ($rvaCount -lt 15) {
            $result.ClrKind = 'native'
            return $result
        }
        $clrRva = Read-UInt32 -Buffer $optional -Offset ($dataDirOffset + (14 * 8))
        $clrSize = Read-UInt32 -Buffer $optional -Offset ($dataDirOffset + (14 * 8) + 4)
        if ($clrRva -eq 0 -or $clrSize -eq 0) {
            $result.ClrKind = 'native'
            return $result
        }

        $sectionTableOffset = $optionalOffset + $optionalSize
        $clrOffset = -1
        for ($index = 0; $index -lt $sectionCount; $index++) {
            $section = Read-ExactBytes -Stream $stream -Offset ($sectionTableOffset + ($index * 40)) -Count 40
            if ($null -eq $section) { break }
            $virtualSize = Read-UInt32 -Buffer $section -Offset 8
            $virtualAddress = Read-UInt32 -Buffer $section -Offset 12
            $rawSize = Read-UInt32 -Buffer $section -Offset 16
            $rawPointer = Read-UInt32 -Buffer $section -Offset 20
            $span = if ($virtualSize -gt 0) { $virtualSize } else { $rawSize }
            if ($clrRva -ge $virtualAddress -and $clrRva -lt ($virtualAddress + $span)) {
                $clrOffset = [long]$rawPointer + ([long]$clrRva - [long]$virtualAddress)
                break
            }
        }
        if ($clrOffset -lt 0) { return $result }

        $clrHeader = Read-ExactBytes -Stream $stream -Offset $clrOffset -Count 72
        if ($null -eq $clrHeader) { return $result }
        $headerSize = Read-UInt32 -Buffer $clrHeader -Offset 0
        if ($headerSize -lt 72) { return $result }
        $flags = Read-UInt32 -Buffer $clrHeader -Offset 16
        $ilOnly = ($flags -band 0x1) -ne 0
        $requires32Bit = ($flags -band 0x2) -ne 0
        $prefers32Bit = ($flags -band 0x20000) -ne 0
        if ($ilOnly) {
            if (-not $requires32Bit) {
                $result.ClrKind = 'anycpu'
            } elseif ($prefers32Bit) {
                $result.ClrKind = 'anycpu-prefer32'
            } else {
                $result.ClrKind = 'clr-x86'
            }
        } else {
            $result.ClrKind = switch ($architecture) {
                'arm64' { 'clr-arm64' }
                'x64' { 'clr-x64' }
                'x86' { 'clr-x86' }
                default { 'unknown' }
            }
        }
        return $result
    } catch {
        return [pscustomobject]@{ IsPe = $true; Architecture = 'unknown'; ClrKind = 'unknown' }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-PeAcceptable {
    param($PeInfo)

    if ($null -eq $PeInfo) { return $true }
    if ($PeInfo.ClrKind -eq 'anycpu') { return $true }
    if ($PeInfo.ClrKind -eq 'clr-arm64') { return $true }
    if ($PeInfo.Architecture -eq 'arm64' -and $PeInfo.ClrKind -eq 'native') { return $true }
    return $false
}

function Get-DiskInventory {
    param([string]$Root)

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $prefix = $rootFull
    if (-not $prefix.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $prefix += [System.IO.Path]::DirectorySeparatorChar
    }
    $entries = @()
    foreach ($item in (Get-ChildItem -LiteralPath $rootFull -Recurse -Force -ErrorAction Stop)) {
        $isLink = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        $isDirectory = ($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0
        if ($isDirectory -and -not $isLink) { continue }
        $full = [System.IO.Path]::GetFullPath($item.FullName)
        $relative = ConvertTo-ForwardSlash $full.Substring($prefix.Length)
        if ($relative.StartsWith($script:EvidencePrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($isLink) {
            $entries += [pscustomobject]@{
                Path       = $relative
                FullPath   = $full
                Type       = 'symlink'
                Bytes      = [long]0
                Sha256     = $null
                LinkTarget = ConvertTo-ForwardSlash ([string]$item.LinkTarget)
                Owner      = Get-OwnerName -Path $full
            }
        } else {
            $entries += [pscustomobject]@{
                Path       = $relative
                FullPath   = $full
                Type       = 'file'
                Bytes      = [long]$item.Length
                Sha256     = Get-FileSha256 -Path $full
                LinkTarget = $null
                Owner      = Get-OwnerName -Path $full
            }
        }
    }
    return Sort-OrdinalPath -Items $entries -Property 'Path'
}

function Get-InventorySha256 {
    param([object[]]$Inventory)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($entry in $Inventory) {
        $sha = if ($entry.Type -eq 'file') { $entry.Sha256 } else { '-' }
        $target = if ($entry.Type -eq 'file') { '-' } else { $entry.LinkTarget }
        if ([string]::IsNullOrEmpty($target)) { $target = '-' }
        [void]$builder.Append($entry.Path)
        [void]$builder.Append("`t")
        [void]$builder.Append($entry.Type)
        [void]$builder.Append("`t")
        [void]$builder.Append([string]$entry.Bytes)
        [void]$builder.Append("`t")
        [void]$builder.Append($sha)
        [void]$builder.Append("`t")
        [void]$builder.Append($target)
        [void]$builder.Append("`n")
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    return Get-BytesSha256 -Bytes $bytes
}

function Get-OwnerName {
    param([string]$Path)

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $acl -or $null -eq $acl.Owner) { return $null }
        return [string]$acl.Owner
    } catch {
        return $null
    }
}

function Test-OwnerMatch {
    param([string]$Declared, [string]$Actual)

    if ([string]::IsNullOrEmpty($Actual)) { return $false }
    if ($Declared -eq $Actual) { return $true }
    $declaredLeaf = $Declared.Split('\')[-1]
    $actualLeaf = $Actual.Split('\')[-1]
    return [string]::Equals($declaredLeaf, $actualLeaf, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-LockDocument {
    param([string]$Path)

    $raw = Read-JsonDocument -Path $Path -Context 'lock'
    $document = $raw.Document
    Assert-DocumentHeader -Document $document -Kind $script:KindLock -Context 'lock'
    Assert-ObjectMembers -Object $document -Required @('schemaVersion', 'kind', 'previewId', 'nativeShellClosure', 'packages') -Context 'lock' | Out-Null
    $previewId = Get-MemberValue $document 'previewId'
    if (-not ($previewId -is [string]) -or $previewId -cnotmatch '^[a-z0-9][a-z0-9._-]{0,127}$') {
        Stop-WithInputError 'lock.previewId must be a concrete lowercase identifier'
    }

    $closureRaw = @(Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'nativeShellClosure') -Context 'lock.nativeShellClosure')
    $closure = @()
    $seen = @{}
    foreach ($entry in $closureRaw) {
        $value = Assert-PayloadPath -Value $entry -Context 'lock.nativeShellClosure entry'
        $key = $value.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            Stop-WithInputError "lock.nativeShellClosure contains a duplicate path: '$value'"
        }
        $seen[$key] = $true
        $closure += $value
    }

    $packagesRaw = @(Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'packages') -Context 'lock.packages')
    $packages = @()
    $packageSeen = @{}
    foreach ($entry in $packagesRaw) {
        Assert-ObjectMembers -Object $entry -Required @('name', 'slot', 'resolved') -Optional @('version', 'archive') -Context 'lock.packages entry' | Out-Null
        $name = Get-MemberValue -Object $entry -Name 'name'
        if (-not ($name -is [string]) -or (Test-PlaceholderString $name)) {
            Stop-WithInputError 'lock.packages entry has an empty or placeholder name'
        }
        $slot = Get-MemberValue -Object $entry -Name 'slot'
        if (-not ($slot -is [string]) -or (Test-PlaceholderString $slot)) {
            Stop-WithInputError "lock.packages entry '$name' has an empty or placeholder slot"
        }
        $resolved = Assert-Boolean -Value (Get-MemberValue -Object $entry -Name 'resolved') -Context "lock.packages entry '$name'.resolved"
        $key = "$($name.ToLowerInvariant())/$($slot.ToLowerInvariant())"
        if ($packageSeen.ContainsKey($key)) {
            Stop-WithInputError "lock.packages contains a duplicate name/slot pair: '$name'/'$slot'"
        }
        $packageSeen[$key] = $true
        $version = $null
        if (Test-HasMember -Object $entry -Name 'version') {
            $version = Get-MemberValue -Object $entry -Name 'version'
            if ($null -ne $version -and -not ($version -is [string])) {
                Stop-WithInputError "lock.packages entry '$name'.version must be a string"
            }
        }
        $archive = $null
        if (Test-HasMember -Object $entry -Name 'archive') {
            $archive = Get-MemberValue -Object $entry -Name 'archive'
            if ($null -ne $archive) {
                $archive = Assert-RelativePath -Value $archive -Context "lock.packages entry '$name'.archive"
            }
        }
        if ($resolved) {
            if ($null -eq $version -or (Test-PlaceholderString $version)) {
                Stop-WithInputError "lock.packages entry '$name' is resolved but has no concrete version"
            }
        }
        $packages += [pscustomobject]@{
            Name     = $name
            Slot     = $slot
            Resolved = $resolved
            Version  = $version
            Archive  = $archive
        }
    }

    return [pscustomobject]@{
        Path     = $raw.Path
        Bytes    = $raw.Bytes
        Sha256   = $raw.Sha256
        PreviewId = $previewId
        Closure  = $closure
        Packages = $packages
    }
}

function Read-ProvenanceDocument {
    param([string]$Path, $Lock, [string]$PayloadManifestPath)

    $raw = Read-JsonDocument -Path $Path -Context 'provenance'
    $document = $raw.Document
    Assert-DocumentHeader -Document $document -Kind $script:KindProvenance -Context 'provenance'
    Assert-ObjectMembers -Object $document -Required @('schemaVersion', 'kind', 'previewId', 'lock', 'payload', 'assembler', 'validator', 'inputs') -Context 'provenance' | Out-Null
    if ((Get-MemberValue $document 'previewId') -cne $Lock.PreviewId) {
        Stop-WithInputError 'provenance.previewId does not match lock.previewId'
    }

    $lockRef = Get-MemberValue -Object $document -Name 'lock'
    Assert-ObjectMembers -Object $lockRef -Required @('path', 'sha256') -Context 'provenance.lock' | Out-Null
    $lockRefPath = Get-MemberValue -Object $lockRef -Name 'path'
    if ($lockRefPath -cne 'bundle-lock.v1.json') {
        Stop-WithInputError "provenance.lock.path must be 'bundle-lock.v1.json'"
    }
    $lockSha = Assert-Sha256 -Value (Get-MemberValue -Object $lockRef -Name 'sha256') -Context 'provenance.lock.sha256'
    if ($lockSha -cne $Lock.Sha256) {
        Stop-WithInputError "provenance.lock.sha256 does not bind the lock: expected $($Lock.Sha256), found $lockSha"
    }

    $payloadRef = Get-MemberValue -Object $document -Name 'payload'
    Assert-ObjectMembers -Object $payloadRef -Required @('path', 'sha256') -Context 'provenance.payload' | Out-Null
    if ((Get-MemberValue -Object $payloadRef -Name 'path') -cne 'payload-manifest.v1.json') {
        Stop-WithInputError "provenance.payload.path must be 'payload-manifest.v1.json'"
    }
    if (-not [System.IO.File]::Exists($PayloadManifestPath)) {
        Stop-WithInputError "payload manifest does not exist: $PayloadManifestPath"
    }
    $payloadSha = Assert-Sha256 -Value (Get-MemberValue -Object $payloadRef -Name 'sha256') -Context 'provenance.payload.sha256'
    $actualPayloadSha = Get-FileSha256 -Path $PayloadManifestPath
    if ($payloadSha -cne $actualPayloadSha) {
        Stop-WithInputError "provenance.payload.sha256 does not bind the payload manifest: expected $actualPayloadSha, found $payloadSha"
    }
    $assembler = Get-MemberValue $document 'assembler'
    Assert-ObjectMembers $assembler @('repository', 'commit') @() 'provenance.assembler' | Out-Null
    if (Test-PlaceholderString (Get-MemberValue $assembler 'repository')) { Stop-WithInputError 'provenance.assembler.repository must be concrete' }
    if ((Get-MemberValue $assembler 'commit') -cnotmatch '^[0-9a-f]{40}$') { Stop-WithInputError 'provenance.assembler.commit must be a full lowercase commit' }

    $validator = Get-MemberValue $document 'validator'
    Assert-ObjectMembers $validator @('repository', 'commit', 'files') @() 'provenance.validator' | Out-Null
    if ((Get-MemberValue $validator 'repository') -cne $script:ValidatorRepository) { Stop-WithInputError "provenance.validator.repository must be '$($script:ValidatorRepository)'" }
    if ((Get-MemberValue $validator 'commit') -cnotmatch '^[0-9a-f]{40}$') { Stop-WithInputError 'provenance.validator.commit must be a full lowercase commit' }
    $validatorFiles = @(Assert-JsonArray (Get-MemberValue $validator 'files') 'provenance.validator.files')
    $expectedFiles = @{
        'validate-arm64-preview.ps1' = $PSCommandPath
        'pe-imports.ps1' = Join-Path (Split-Path -Parent $PSCommandPath) 'pe-imports.ps1'
    }
    $seenFiles = @{}
    foreach ($file in $validatorFiles) {
        Assert-ObjectMembers $file @('path', 'bytes', 'sha256') @() 'provenance.validator.files entry' | Out-Null
        $filePath = Assert-RelativePath (Get-MemberValue $file 'path') 'provenance.validator.files entry.path'
        if (-not $expectedFiles.ContainsKey($filePath) -or $seenFiles.ContainsKey($filePath)) { Stop-WithInputError "unexpected or duplicate validator file '$filePath'" }
        $actual = $expectedFiles[$filePath]
        $bytes = Assert-NonNegativeInteger (Get-MemberValue $file 'bytes') "validator file '$filePath'.bytes"
        $sha = Assert-Sha256 (Get-MemberValue $file 'sha256') "validator file '$filePath'.sha256"
        if (-not [IO.File]::Exists($actual) -or [IO.FileInfo]::new($actual).Length -ne $bytes -or (Get-FileSha256 $actual) -cne $sha) {
            Stop-WithInputError "validator file '$filePath' does not match the invoked immutable file"
        }
        $seenFiles[$filePath] = $true
    }
    if ($seenFiles.Count -ne $expectedFiles.Count) {
        Stop-WithInputError 'validator.files must bind validate-arm64-preview.ps1 and pe-imports.ps1 exactly'
    }
    $inputs = @(Assert-JsonArray (Get-MemberValue $document 'inputs') 'provenance.inputs' -AllowEmpty)
    foreach ($input in $inputs) {
        Assert-ObjectMembers $input @('id', 'path', 'bytes', 'sha256') @() 'provenance.inputs entry' | Out-Null
        if (Test-PlaceholderString (Get-MemberValue $input 'id')) { Stop-WithInputError 'provenance input id must be concrete' }
        [void](Assert-RelativePath (Get-MemberValue $input 'path') 'provenance input path')
        [void](Assert-NonNegativeInteger (Get-MemberValue $input 'bytes') 'provenance input bytes')
        [void](Assert-Sha256 (Get-MemberValue $input 'sha256') 'provenance input sha256')
    }

    return [pscustomobject]@{
        Path   = $raw.Path
        Bytes  = $raw.Bytes
        Sha256 = $raw.Sha256
        Validator = $validator
        Assembler = $assembler
    }
}

function Read-ManifestEntry {
    param($Entry, [string]$Context, [switch]$AllowOwnerOverride)

    Assert-ObjectMembers -Object $Entry -Required @('path', 'type', 'bytes', 'sha256', 'linkTarget', 'owner') -Context $Context | Out-Null
    $path = Assert-PayloadPath -Value (Get-MemberValue -Object $Entry -Name 'path') -Context "$Context.path"
    $type = Get-MemberValue -Object $Entry -Name 'type'
    if (-not ($type -is [string]) -or ($type -cne 'file' -and $type -cne 'symlink')) {
        Stop-WithInputError "$Context.type must be either 'file' or 'symlink'"
    }
    $bytes = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $Entry -Name 'bytes') -Context "$Context.bytes"
    $sha = Get-MemberValue -Object $Entry -Name 'sha256'
    $linkTarget = Get-MemberValue -Object $Entry -Name 'linkTarget'
    if ($type -eq 'file') {
        $sha = Assert-Sha256 -Value $sha -Context "$Context.sha256"
        if ($null -ne $linkTarget) {
            Stop-WithInputError "$Context.linkTarget must be null for a file entry"
        }
    } else {
        if ($null -ne $sha) {
            Stop-WithInputError "$Context.sha256 must be null for a symlink entry"
        }
        if ($bytes -ne 0) {
            Stop-WithInputError "$Context.bytes must be 0 for a symlink entry"
        }
        if (-not ($linkTarget -is [string]) -or (Test-PlaceholderString $linkTarget)) {
            Stop-WithInputError "$Context.linkTarget is empty or a placeholder"
        }
        $normalizedTarget = ConvertTo-ForwardSlash $linkTarget
        if ($normalizedTarget -cne $linkTarget) {
            Stop-WithInputError "$Context.linkTarget must use forward slashes"
        }
        foreach ($segment in $linkTarget.Split('/')) {
            if ($segment -eq '..') {
                Stop-WithInputError "$Context.linkTarget must not traverse outside the payload"
            }
        }
    }
    $owner = Get-MemberValue -Object $Entry -Name 'owner'
    if (-not ($owner -is [string]) -or (Test-PlaceholderString $owner)) {
        Stop-WithInputError "$Context.owner is empty or a placeholder"
    }

    return [pscustomobject]@{
        Path       = $path
        Type       = $type
        Bytes      = $bytes
        Sha256     = $sha
        LinkTarget = $linkTarget
        Owner      = $owner
    }
}

function Read-PayloadManifestDocument {
    param([string]$Path, $Lock)

    $raw = Read-JsonDocument -Path $Path -Context 'payload manifest'
    $document = $raw.Document
    Assert-DocumentHeader -Document $document -Kind $script:KindPayload -Context 'payload manifest'
    Assert-ObjectMembers -Object $document -Required @('schemaVersion', 'kind', 'previewId', 'scope', 'lock', 'files') -Optional @('archives') -Context 'payload manifest' | Out-Null
    if ((Get-MemberValue $document 'previewId') -cne $Lock.PreviewId) { Stop-WithInputError 'payload manifest previewId does not match lock.previewId' }
    $scope = Get-MemberValue $document 'scope'
    Assert-ObjectMembers $scope @('root', 'excludedPrefixes') @() 'payload manifest scope' | Out-Null
    $excluded = @(Assert-JsonArray (Get-MemberValue $scope 'excludedPrefixes') 'payload manifest scope.excludedPrefixes')
    if ((Get-MemberValue $scope 'root') -cne '.' -or $excluded.Count -ne 1 -or $excluded[0] -cne $script:EvidencePrefix) {
        Stop-WithInputError 'payload manifest scope must be exactly {root:".",excludedPrefixes:["preview-evidence/"]}'
    }

    $lockRef = Get-MemberValue -Object $document -Name 'lock'
    Assert-ObjectMembers -Object $lockRef -Required @('bytes', 'sha256') -Context 'payload manifest lock binding' | Out-Null
    $lockSha = Assert-Sha256 -Value (Get-MemberValue -Object $lockRef -Name 'sha256') -Context 'payload manifest lock.sha256'
    $lockBytes = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $lockRef -Name 'bytes') -Context 'payload manifest lock.bytes'
    if ($lockSha -cne $Lock.Sha256 -or $lockBytes -ne $Lock.Bytes) {
        Stop-WithInputError "payload manifest lock binding does not match the lock file (expected $($Lock.Sha256)/$($Lock.Bytes), found $lockSha/$lockBytes)"
    }

    $filesRaw = @(Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'files') -Context 'payload manifest files')
    $files = @()
    $seen = @{}
    foreach ($entry in $filesRaw) {
        $parsed = Read-ManifestEntry -Entry $entry -Context 'payload manifest files entry'
        $key = $parsed.Path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            Stop-WithInputError "payload manifest files contains a duplicate path (case-insensitive): '$($parsed.Path)'"
        }
        $seen[$key] = $true
        $files += $parsed
    }

    $archives = @()
    if (Test-HasMember -Object $document -Name 'archives') {
        $archivesRaw = @(Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'archives') -Context 'payload manifest archives' -AllowEmpty)
        $archiveSeen = @{}
        foreach ($entry in $archivesRaw) {
            Assert-ObjectMembers -Object $entry -Required @('path', 'format', 'bytes', 'sha256', 'owner', 'members') -Context 'payload manifest archives entry' | Out-Null
            $archivePath = Assert-PayloadPath -Value (Get-MemberValue -Object $entry -Name 'path') -Context 'payload manifest archives entry.path'
            $key = $archivePath.ToLowerInvariant()
            if ($archiveSeen.ContainsKey($key)) {
                Stop-WithInputError "payload manifest archives contains a duplicate path (case-insensitive): '$archivePath'"
            }
            $archiveSeen[$key] = $true
            $format = Get-MemberValue -Object $entry -Name 'format'
            if (-not ($format -is [string]) -or (Test-PlaceholderString $format) -or -not $script:ArchiveFormats.ContainsKey($format)) {
                Stop-WithInputError "payload manifest archives entry '$archivePath'.format is not a supported authoritative format"
            }
            $archiveBytes = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $entry -Name 'bytes') -Context "payload manifest archives entry '$archivePath'.bytes"
            $archiveSha = Assert-Sha256 -Value (Get-MemberValue -Object $entry -Name 'sha256') -Context "payload manifest archives entry '$archivePath'.sha256"
            $archiveOwner = Get-MemberValue -Object $entry -Name 'owner'
            if (-not ($archiveOwner -is [string]) -or (Test-PlaceholderString $archiveOwner)) {
                Stop-WithInputError "payload manifest archives entry '$archivePath'.owner is empty or a placeholder"
            }
            $membersRaw = @(Assert-JsonArray -Value (Get-MemberValue -Object $entry -Name 'members') -Context "payload manifest archives entry '$archivePath'.members")
            $members = @()
            $memberSeen = @{}
            foreach ($member in $membersRaw) {
                $parsedMember = Read-ManifestEntry -Entry $member -Context "payload manifest archives entry '$archivePath' member"
                $memberKey = $parsedMember.Path.ToLowerInvariant()
                if ($memberSeen.ContainsKey($memberKey)) {
                    Stop-WithInputError "payload manifest archives entry '$archivePath' contains a duplicate member path: '$($parsedMember.Path)'"
                }
                $memberSeen[$memberKey] = $true
                $members += $parsedMember
            }
            $archives += [pscustomobject]@{
                Path    = $archivePath
                Format  = $format
                Bytes   = $archiveBytes
                Sha256  = $archiveSha
                Owner   = $archiveOwner
                Members = Sort-OrdinalPath -Items $members -Property 'Path'
            }
        }
    }

    return [pscustomobject]@{
        Path     = $raw.Path
        Bytes    = $raw.Bytes
        Sha256   = $raw.Sha256
        Files    = Sort-OrdinalPath -Items $files -Property 'Path'
        Archives = Sort-OrdinalPath -Items $archives -Property 'Path'
    }
}

$script:ArchiveFormats = @{
    'zip'     = @{ Magic = @(0x50, 0x4B, 0x03, 0x04); Offset = 0; Native = $true; TarFlag = $null }
    'tar'     = @{ Magic = @(0x75, 0x73, 0x74, 0x61, 0x72); Offset = 257; Native = $false; TarFlag = '' }
    'tar.gz'  = @{ Magic = @(0x1F, 0x8B); Offset = 0; Native = $false; TarFlag = '' }
    'tar.bz2' = @{ Magic = @(0x42, 0x5A, 0x68); Offset = 0; Native = $false; TarFlag = '' }
    'tar.xz'  = @{ Magic = @(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00); Offset = 0; Native = $false; TarFlag = '' }
    'tar.zst' = @{ Magic = @(0x28, 0xB5, 0x2F, 0xFD); Offset = 0; Native = $false; TarFlag = '' }
}

function Test-ArchiveMagic {
    param([string]$Path, [string]$Format)

    $spec = $script:ArchiveFormats[$Format]
    if ($null -eq $spec) { return $false }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $expected = @($spec.Magic)
        $buffer = Read-ExactBytes -Stream $stream -Offset ([long]$spec.Offset) -Count $expected.Count
        if ($null -eq $buffer) { return $false }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if ($buffer[$index] -ne $expected[$index]) { return $false }
        }
        return $true
    } finally {
        $stream.Dispose()
    }
}

function Get-TarExecutable {
    $command = Get-Command -Name 'tar' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { return $command.Source }
    $fallback = [System.IO.Path]::Combine($env:SystemRoot, 'system32', 'tar.exe')
    if ([System.IO.File]::Exists($fallback)) { return $fallback }
    return $null
}

function Read-ZipArchiveMembers {
    param([string]$Path)

    Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $members = @()
        foreach ($entry in $archive.Entries) {
            $name = ConvertTo-ForwardSlash $entry.FullName
            if ($name.EndsWith('/')) { continue }
            $unixMode = ($entry.ExternalAttributes -shr 16) -band 0xF000
            $stream = $entry.Open()
            try {
                $memory = [System.IO.MemoryStream]::new()
                try {
                    $stream.CopyTo($memory)
                    $bytes = $memory.ToArray()
                } finally {
                    $memory.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
            if ($unixMode -eq 0xA000) {
                $members += [pscustomobject]@{
                    Path       = $name
                    Type       = 'symlink'
                    Bytes      = [long]0
                    Sha256     = $null
                    LinkTarget = ConvertTo-ForwardSlash ([System.Text.Encoding]::UTF8.GetString($bytes))
                }
            } else {
                $members += [pscustomobject]@{
                    Path       = $name
                    Type       = 'file'
                    Bytes      = [long]$bytes.Length
                    Sha256     = Get-BytesSha256 -Bytes $bytes
                    LinkTarget = $null
                }
            }
        }
        return Sort-OrdinalPath -Items $members -Property 'Path'
    } finally {
        $archive.Dispose()
    }
}

function Invoke-TarCapture {
    param([string]$TarExecutable, [string[]]$Arguments)

    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $TarExecutable
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($info)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

function Get-TarMemberDigest {
    param([string]$TarExecutable, [string]$ArchivePath, [string]$Member)

    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $TarExecutable
    foreach ($argument in @('-xOf', $ArchivePath, '--', $Member)) { [void]$info.ArgumentList.Add($argument) }
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($info)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = [byte[]]::new(65536)
        $total = [long]0
        $stream = $process.StandardOutput.BaseStream
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
            $total += $read
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $digest = ([System.BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    [void]$process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { return $null }
    return [pscustomobject]@{ Bytes = $total; Sha256 = $digest }
}

function Read-TarArchiveMembers {
    param([string]$Path, [string]$TarExecutable)

    $listing = Invoke-TarCapture -TarExecutable $TarExecutable -Arguments @('-tf', $Path)
    if ($listing.ExitCode -ne 0) { return $null }
    $verbose = Invoke-TarCapture -TarExecutable $TarExecutable -Arguments @('-tvf', $Path)
    if ($verbose.ExitCode -ne 0) { return $null }

    $names = @($listing.StdOut -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    $details = @($verbose.StdOut -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    if ($names.Count -ne $details.Count) { return $null }

    $members = @()
    for ($index = 0; $index -lt $names.Count; $index++) {
        $name = ConvertTo-ForwardSlash $names[$index]
        $detail = $details[$index]
        $kind = $detail.Substring(0, 1)
        if ($name.EndsWith('/') -or $kind -eq 'd') { continue }
        if ($kind -eq 'l') {
            $target = $null
            $marker = $detail.IndexOf(' -> ')
            if ($marker -ge 0) { $target = ConvertTo-ForwardSlash $detail.Substring($marker + 4) }
            if ([string]::IsNullOrEmpty($target)) { return $null }
            $members += [pscustomobject]@{
                Path       = $name
                Type       = 'symlink'
                Bytes      = [long]0
                Sha256     = $null
                LinkTarget = $target
            }
            continue
        }
        if ($kind -ne '-') { return $null }
        $digest = Get-TarMemberDigest -TarExecutable $TarExecutable -ArchivePath $Path -Member $names[$index]
        if ($null -eq $digest) { return $null }
        $members += [pscustomobject]@{
            Path       = $name
            Type       = 'file'
            Bytes      = $digest.Bytes
            Sha256     = $digest.Sha256
            LinkTarget = $null
        }
    }
    return Sort-OrdinalPath -Items $members -Property 'Path'
}

function New-Violation {
    param([string]$Code, [string]$Path, [string]$Detail)

    return [ordered]@{
        code   = $Code
        path   = $Path
        detail = $Detail
    }
}

function Compare-ManifestWithDisk {
    param($Manifest, [object[]]$Inventory, [System.Collections.ArrayList]$Violations)

    $diskByPath = @{}
    foreach ($entry in $Inventory) { $diskByPath[$entry.Path] = $entry }
    $manifestByPath = @{}
    foreach ($entry in $Manifest.Files) { $manifestByPath[$entry.Path] = $entry }

    foreach ($declared in $Manifest.Files) {
        $actual = $diskByPath[$declared.Path]
        if ($null -eq $actual) {
            [void]$Violations.Add((New-Violation -Code 'payload-file-missing-on-disk' -Path $declared.Path -Detail 'declared by the payload manifest but not present below the portable root'))
            continue
        }
        if ($actual.Path -cne $declared.Path) {
            [void]$Violations.Add((New-Violation -Code 'payload-path-case-mismatch' -Path $declared.Path -Detail "on disk the entry is named '$($actual.Path)'"))
        }
        if ($actual.Type -ne $declared.Type) {
            [void]$Violations.Add((New-Violation -Code 'payload-type-mismatch' -Path $declared.Path -Detail "declared '$($declared.Type)', found '$($actual.Type)'"))
            continue
        }
        if (-not (Test-OwnerMatch -Declared $declared.Owner -Actual $actual.Owner)) {
            [void]$Violations.Add((New-Violation -Code 'payload-owner-mismatch' -Path $declared.Path -Detail "declared '$($declared.Owner)', found '$($actual.Owner)'"))
        }
        if ($declared.Type -eq 'file') {
            if ($actual.Bytes -ne $declared.Bytes) {
                [void]$Violations.Add((New-Violation -Code 'payload-bytes-mismatch' -Path $declared.Path -Detail "declared $($declared.Bytes) bytes, found $($actual.Bytes) bytes"))
            }
            if ($actual.Sha256 -cne $declared.Sha256) {
                [void]$Violations.Add((New-Violation -Code 'payload-sha256-mismatch' -Path $declared.Path -Detail "declared $($declared.Sha256), found $($actual.Sha256)"))
            }
        } else {
            $actualTarget = if ($null -eq $actual.LinkTarget) { '' } else { $actual.LinkTarget }
            if (-not [string]::Equals($actualTarget, $declared.LinkTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                [void]$Violations.Add((New-Violation -Code 'payload-link-target-mismatch' -Path $declared.Path -Detail "declared '$($declared.LinkTarget)', found '$actualTarget'"))
            }
        }
    }

    foreach ($entry in $Inventory) {
        if (-not $manifestByPath.ContainsKey($entry.Path)) {
            [void]$Violations.Add((New-Violation -Code 'payload-extra-disk-entry' -Path $entry.Path -Detail 'present below the portable root but not declared by the payload manifest'))
        }
    }
}

function Get-PeInventory {
    param([object[]]$Inventory, [string[]]$Closure, [string]$Root)

    $closureSet = @{}
    foreach ($path in $Closure) { $closureSet[$path] = $true }
    $fileEntries = @($Inventory | Where-Object Type -eq 'file')
    if ($fileEntries.Count -eq 0) { return @() }

    $helper = Join-Path (Split-Path -Parent $PSCommandPath) 'pe-imports.ps1'
    if (-not [System.IO.File]::Exists($helper)) {
        throw "required architecture inventory helper is missing: $helper"
    }
    $listPath = Join-Path ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutputPath))) ".$PID-pe-inventory.txt"
    try {
        [System.IO.File]::WriteAllLines(
            $listPath,
            [string[]]@($fileEntries | ForEach-Object Path),
            [System.Text.UTF8Encoding]::new($false)
        )
        $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $processInfo.FileName = Join-Path $PSHOME 'pwsh.exe'
        foreach ($argument in @(
            '-NoProfile', '-File', $helper, '-ArchitectureOnly', '-FailOnMalformedPe',
            '-Root', $Root, '-FileList', $listPath
        )) {
            [void]$processInfo.ArgumentList.Add($argument)
        }
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $process = [System.Diagnostics.Process]::Start($processInfo)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "pe-imports.ps1 architecture inventory failed (exit $($process.ExitCode)): $($stderr.Trim())"
        }
    } finally {
        Remove-Item -LiteralPath $listPath -Force -ErrorAction SilentlyContinue
    }

    $inventoryByPath = @{}
    foreach ($line in @($stdout -split "`r?`n" | Where-Object { $_ })) {
        $parts = $line -split "`t"
        if ($parts.Count -ne 3) { throw "pe-imports.ps1 returned malformed architecture inventory: $line" }
        if ($inventoryByPath.ContainsKey($parts[0])) { throw "pe-imports.ps1 returned duplicate path '$($parts[0])'" }
        $inventoryByPath[$parts[0]] = $parts[1]
    }

    $peFiles = @()
    foreach ($entry in $fileEntries) {
        if (-not $inventoryByPath.ContainsKey($entry.Path)) { continue }
        $info = Get-PeInfo -Path $entry.FullPath
        if ($null -eq $info) { throw "pe-imports.ps1 classified '$($entry.Path)' as PE but detailed CLR parsing failed" }
        $helperArchitecture = $inventoryByPath[$entry.Path]
        $expectedArchitecture = if ($helperArchitecture -eq 'arm64ec' -or $helperArchitecture.StartsWith('unknown-')) {
            'unknown'
        } elseif ($helperArchitecture -eq 'anycpu') {
            'x86'
        } else {
            $helperArchitecture
        }
        if ($info.Architecture -cne $expectedArchitecture -or ($helperArchitecture -eq 'anycpu' -and $info.ClrKind -cne 'anycpu')) {
            throw "architecture helper disagreement for '$($entry.Path)': helper=$helperArchitecture validator=$($info.Architecture)"
        }
        $reportedArchitecture = if ($helperArchitecture -eq 'anycpu') { 'anycpu' } else { $expectedArchitecture }
        $peFiles += [pscustomobject]@{
            Path         = $entry.Path
            Architecture = $reportedArchitecture
            ClrKind      = $info.ClrKind
            Acceptable   = [bool](Test-PeAcceptable -PeInfo $info)
            InClosure    = [bool]$closureSet.ContainsKey($entry.Path)
        }
    }
    return Sort-OrdinalPath -Items $peFiles -Property 'Path'
}

function Test-ArchiveSet {
    param($Manifest, [object[]]$Inventory, [string]$RootFull, [System.Collections.ArrayList]$Violations)

    $checks = @()
    if ($Manifest.Archives.Count -eq 0) { return $checks }

    $diskByPath = @{}
    foreach ($entry in $Inventory) { $diskByPath[$entry.Path] = $entry }
    $manifestByPath = @{}
    foreach ($entry in $Manifest.Files) { $manifestByPath[$entry.Path] = $entry }
    $tarExecutable = Get-TarExecutable

    foreach ($archive in $Manifest.Archives) {
        $check = [ordered]@{
            path            = $archive.Path
            format          = $archive.Format
            declaredMembers = $archive.Members.Count
            verifiedMembers = 0
            verified        = $false
        }
        $declaration = $manifestByPath[$archive.Path]
        if ($null -eq $declaration) {
            [void]$Violations.Add((New-Violation -Code 'archive-not-in-payload' -Path $archive.Path -Detail 'declared as an archive but not declared in payload manifest files'))
            $checks += $check
            continue
        }
        $actual = $diskByPath[$archive.Path]
        if ($null -eq $actual -or $actual.Type -ne 'file') {
            [void]$Violations.Add((New-Violation -Code 'archive-missing' -Path $archive.Path -Detail 'declared archive is not present as a file below the portable root'))
            $checks += $check
            continue
        }
        if ($actual.Bytes -ne $archive.Bytes) {
            [void]$Violations.Add((New-Violation -Code 'archive-bytes-mismatch' -Path $archive.Path -Detail "declared $($archive.Bytes) bytes, found $($actual.Bytes) bytes"))
        }
        if ($actual.Sha256 -cne $archive.Sha256) {
            [void]$Violations.Add((New-Violation -Code 'archive-sha256-mismatch' -Path $archive.Path -Detail "declared $($archive.Sha256), found $($actual.Sha256)"))
            $checks += $check
            continue
        }
        if ($declaration.Sha256 -cne $archive.Sha256 -or $declaration.Bytes -ne $archive.Bytes) {
            [void]$Violations.Add((New-Violation -Code 'archive-declaration-mismatch' -Path $archive.Path -Detail 'the archive declaration disagrees with the payload manifest file entry'))
        }

        $spec = $script:ArchiveFormats[$archive.Format]
        if ($null -eq $spec) {
            [void]$Violations.Add((New-Violation -Code 'archive-format-unsupported' -Path $archive.Path -Detail "archive format '$($archive.Format)' cannot be validated authoritatively"))
            $checks += $check
            continue
        }
        if (-not (Test-ArchiveMagic -Path $actual.FullPath -Format $archive.Format)) {
            [void]$Violations.Add((New-Violation -Code 'archive-format-mismatch' -Path $archive.Path -Detail "the file does not start with the expected '$($archive.Format)' signature"))
            $checks += $check
            continue
        }

        $members = $null
        if ($spec.Native) {
            try {
                $members = Read-ZipArchiveMembers -Path $actual.FullPath
            } catch {
                $members = $null
            }
        } elseif ($null -eq $tarExecutable) {
            [void]$Violations.Add((New-Violation -Code 'archive-format-unsupported' -Path $archive.Path -Detail "no tar executable is available to read '$($archive.Format)' archives"))
            $checks += $check
            continue
        } else {
            $members = Read-TarArchiveMembers -Path $actual.FullPath -TarExecutable $tarExecutable
        }
        if ($null -eq $members) {
            [void]$Violations.Add((New-Violation -Code 'archive-unreadable' -Path $archive.Path -Detail 'the archive could not be enumerated authoritatively'))
            $checks += $check
            continue
        }

        $actualByPath = @{}
        foreach ($member in $members) { $actualByPath[$member.Path] = $member }
        $declaredByPath = @{}
        foreach ($member in $archive.Members) { $declaredByPath[$member.Path] = $member }

        foreach ($declaredMember in $archive.Members) {
            $actualMember = $actualByPath[$declaredMember.Path]
            if ($null -eq $actualMember) {
                [void]$Violations.Add((New-Violation -Code 'archive-member-missing' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail 'declared archive member is not present in the archive'))
                continue
            }
            if ($actualMember.Type -ne $declaredMember.Type) {
                [void]$Violations.Add((New-Violation -Code 'archive-member-type-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail "declared '$($declaredMember.Type)', found '$($actualMember.Type)'"))
                continue
            }
            if ($declaredMember.Type -eq 'file') {
                if ($actualMember.Bytes -ne $declaredMember.Bytes) {
                    [void]$Violations.Add((New-Violation -Code 'archive-member-bytes-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail "declared $($declaredMember.Bytes) bytes, found $($actualMember.Bytes) bytes"))
                }
                if ($actualMember.Sha256 -cne $declaredMember.Sha256) {
                    [void]$Violations.Add((New-Violation -Code 'archive-member-sha256-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail "declared $($declaredMember.Sha256), found $($actualMember.Sha256)"))
                }
            } else {
                if (-not [string]::Equals($actualMember.LinkTarget, $declaredMember.LinkTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                    [void]$Violations.Add((New-Violation -Code 'archive-member-link-target-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail "declared '$($declaredMember.LinkTarget)', found '$($actualMember.LinkTarget)'"))
                }
            }
            if ($declaredMember.Owner -cne $archive.Owner) {
                [void]$Violations.Add((New-Violation -Code 'archive-member-owner-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail "declared owner '$($declaredMember.Owner)' does not match the archive owner '$($archive.Owner)'"))
            }
            $materialized = $manifestByPath[$declaredMember.Path]
            if ($null -ne $materialized) {
                if ($materialized.Type -ne $declaredMember.Type -or
                    $materialized.Bytes -ne $declaredMember.Bytes -or
                    $materialized.Sha256 -cne $declaredMember.Sha256 -or
                    $materialized.LinkTarget -cne $declaredMember.LinkTarget -or
                    $materialized.Owner -cne $declaredMember.Owner) {
                    [void]$Violations.Add((New-Violation -Code 'archive-member-materialization-mismatch' -Path "$($archive.Path)!$($declaredMember.Path)" -Detail 'the materialized payload entry disagrees with the archive member declaration'))
                }
            }
            $check.verifiedMembers = [int]$check.verifiedMembers + 1
        }

        foreach ($actualMember in $members) {
            if (-not $declaredByPath.ContainsKey($actualMember.Path)) {
                [void]$Violations.Add((New-Violation -Code 'archive-member-extra' -Path "$($archive.Path)!$($actualMember.Path)" -Detail 'present in the archive but not declared by the payload manifest'))
            }
        }
        $check.verified = $true
        $checks += $check
    }
    return $checks
}

function Read-RuntimeEvidenceDocument {
    param([string]$Path, [string]$Mode, $Lock, $Provenance, $Manifest, [string]$RootInventorySha256)

    $raw = Read-JsonDocument -Path $Path -Context 'runtime evidence'
    $document = $raw.Document
    Assert-DocumentHeader -Document $document -Kind $script:KindRuntime -Context 'runtime evidence'
    Assert-ObjectMembers -Object $document -Required @('schemaVersion', 'kind', 'previewId', 'mode', 'binding', 'collection', 'smokes', 'processes', 'modules') -Context 'runtime evidence' | Out-Null
    if ((Get-MemberValue $document 'previewId') -cne $Lock.PreviewId) { Stop-WithInputError 'runtime evidence previewId does not match lock.previewId' }
    if ((Get-MemberValue $document 'mode') -cne $Mode) { Stop-WithInputError "runtime evidence mode must match validator mode '$Mode'" }

    $binding = Get-MemberValue -Object $document -Name 'binding'
    Assert-ObjectMembers -Object $binding -Required @('lockSha256', 'provenanceSha256', 'payloadManifestSha256', 'rootInventorySha256') -Context 'runtime evidence binding' | Out-Null
    $bindings = @(
        @{ Name = 'lockSha256'; Expected = $Lock.Sha256 },
        @{ Name = 'provenanceSha256'; Expected = $Provenance.Sha256 },
        @{ Name = 'payloadManifestSha256'; Expected = $Manifest.Sha256 },
        @{ Name = 'rootInventorySha256'; Expected = $RootInventorySha256 }
    )
    foreach ($item in $bindings) {
        $value = Assert-Sha256 -Value (Get-MemberValue -Object $binding -Name $item.Name) -Context "runtime evidence binding.$($item.Name)"
        if ($value -cne $item.Expected) {
            Stop-WithInputError "runtime evidence binding.$($item.Name) does not bind the current inputs: expected $($item.Expected), found $value"
        }
    }

    $collection = Get-MemberValue -Object $document -Name 'collection'
    Assert-ObjectMembers -Object $collection -Required @('method', 'complete', 'droppedEvents', 'startedAt', 'completedAt', 'hostArchitecture') -Optional @('samplingIntervalMs', 'sampled', 'failOpen') -Context 'runtime evidence collection' | Out-Null
    $method = Get-MemberValue -Object $collection -Name 'method'
    if (-not ($method -is [string]) -or (Test-PlaceholderString $method)) {
        Stop-WithInputError 'runtime evidence collection.method is empty or a placeholder'
    }
    $complete = Assert-Boolean -Value (Get-MemberValue -Object $collection -Name 'complete') -Context 'runtime evidence collection.complete'
    $dropped = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $collection -Name 'droppedEvents') -Context 'runtime evidence collection.droppedEvents'
    $hostArchitecture = Get-MemberValue -Object $collection -Name 'hostArchitecture'
    if (-not ($hostArchitecture -is [string]) -or (Test-PlaceholderString $hostArchitecture)) {
        Stop-WithInputError 'runtime evidence collection.hostArchitecture is empty or a placeholder'
    }
    $startedAt = $null
    $completedAt = $null
    foreach ($name in @('startedAt', 'completedAt')) {
        $value = Get-MemberValue -Object $collection -Name $name
        if ($null -eq $value -or (Test-PlaceholderString ([string]$value))) {
            Stop-WithInputError "runtime evidence collection.$name is empty or a placeholder"
        }
        $parsed = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse($value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            Stop-WithInputError "runtime evidence collection.$name is not a parseable timestamp: '$value'"
        }
        if ($name -eq 'startedAt') { $startedAt = $parsed } else { $completedAt = $parsed }
    }

    $smokes = @()
    $smokeNames = @{}
    foreach ($entry in (Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'smokes') -Context 'runtime evidence smokes')) {
        Assert-ObjectMembers -Object $entry -Required @('name', 'command', 'exitCode', 'succeeded', 'processPid') -Context 'runtime evidence smokes entry' | Out-Null
        $name = Get-MemberValue -Object $entry -Name 'name'
        if (-not ($name -is [string]) -or (Test-PlaceholderString $name)) {
            Stop-WithInputError 'runtime evidence smokes entry has an empty or placeholder name'
        }
        if (@('shell', 'git') -cnotcontains $name -or $smokeNames.ContainsKey($name)) {
            Stop-WithInputError "runtime evidence smoke name '$name' is unknown or duplicated"
        }
        $smokeNames[$name] = $true
        $command = Get-MemberValue -Object $entry -Name 'command'
        if (-not ($command -is [string]) -or (Test-PlaceholderString $command)) {
            Stop-WithInputError "runtime evidence smokes entry '$name' has an empty or placeholder command"
        }
        $exitCode = Get-MemberValue -Object $entry -Name 'exitCode'
        if ($exitCode -is [bool] -or -not (($exitCode -is [int]) -or ($exitCode -is [long]) -or ($exitCode -is [double]))) {
            Stop-WithInputError "runtime evidence smokes entry '$name'.exitCode must be an integer"
        }
        $smokes += [pscustomobject]@{
            Name       = $name
            Command    = $command
            ExitCode   = [long]$exitCode
            Succeeded  = Assert-Boolean -Value (Get-MemberValue -Object $entry -Name 'succeeded') -Context "runtime evidence smokes entry '$name'.succeeded"
            ProcessPid = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $entry -Name 'processPid') -Context "runtime evidence smokes entry '$name'.processPid"
        }
    }
    if ($smokes.Count -ne 2 -or $smokeNames.Count -ne 2) {
        Stop-WithInputError "runtime evidence smokes must contain exactly one 'shell' and one 'git' entry"
    }

    $processes = @()
    $pidSeen = @{}
    foreach ($entry in (Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'processes') -Context 'runtime evidence processes')) {
        Assert-ObjectMembers -Object $entry -Required @('pid', 'path', 'architecture', 'modulesComplete', 'modules') -Context 'runtime evidence processes entry' | Out-Null
        $processPid = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $entry -Name 'pid') -Context 'runtime evidence processes entry.pid'
        if ($pidSeen.ContainsKey([string]$processPid)) {
            Stop-WithInputError "runtime evidence processes contains a duplicate pid: $processPid"
        }
        $pidSeen[[string]$processPid] = $true
        $path = Assert-PayloadPath -Value (Get-MemberValue -Object $entry -Name 'path') -Context 'runtime evidence processes entry.path'
        $architecture = Get-MemberValue -Object $entry -Name 'architecture'
        if (@('arm64', 'x64', 'x86', 'unknown') -cnotcontains $architecture) {
            Stop-WithInputError "runtime evidence processes entry '$path'.architecture is not recognized"
        }
        $modules = @()
        $moduleSeen = @{}
        foreach ($module in (Assert-JsonArray -Value (Get-MemberValue -Object $entry -Name 'modules') -Context "runtime evidence processes entry '$path'.modules")) {
            $modulePath = Assert-PayloadPath -Value $module -Context "runtime evidence processes entry '$path'.modules entry"
            if ($moduleSeen.ContainsKey($modulePath.ToLowerInvariant())) {
                Stop-WithInputError "runtime evidence processes entry '$path' references module '$modulePath' more than once"
            }
            $moduleSeen[$modulePath.ToLowerInvariant()] = $true
            $modules += $modulePath
        }
        $processes += [pscustomobject]@{
            Pid          = $processPid
            Path         = $path
            Architecture = $architecture
            ModulesComplete = Assert-Boolean (Get-MemberValue $entry 'modulesComplete') "runtime evidence process '$path'.modulesComplete"
            Modules      = $modules
        }
    }
    if ($processes.Count -lt 2) {
        Stop-WithInputError 'runtime evidence processes must cover at least the shell and Git smoke processes'
    }

    $modules = @()
    $moduleSeen = @{}
    foreach ($entry in (Assert-JsonArray -Value (Get-MemberValue -Object $document -Name 'modules') -Context 'runtime evidence modules')) {
        Assert-ObjectMembers -Object $entry -Required @('path', 'payloadPath', 'origin', 'architecture', 'bytes', 'sha256') -Context 'runtime evidence modules entry' | Out-Null
        $path = Get-MemberValue $entry 'path'
        if (-not ($path -is [string]) -or (Test-PlaceholderString $path)) { Stop-WithInputError 'runtime module path must be concrete' }
        if ($moduleSeen.ContainsKey($path.ToLowerInvariant())) {
            Stop-WithInputError "runtime evidence modules contains a duplicate path (case-insensitive): '$path'"
        }
        $moduleSeen[$path.ToLowerInvariant()] = $true
        $architecture = Get-MemberValue -Object $entry -Name 'architecture'
        if (@('arm64', 'x64', 'x86', 'unknown') -cnotcontains $architecture) {
            Stop-WithInputError "runtime evidence modules entry '$path'.architecture is not recognized"
        }
        $origin = Get-MemberValue $entry 'origin'
        $payloadPath = Get-MemberValue $entry 'payloadPath'
        if ($origin -ceq 'payload') {
            $payloadPath = Assert-PayloadPath $payloadPath "runtime module '$path'.payloadPath"
            if ($path -cne $payloadPath) { Stop-WithInputError "payload runtime module '$path' must use its payloadPath as path" }
        } elseif ($origin -ceq 'windows') {
            if ($null -ne $payloadPath -or $path -notmatch '^[A-Za-z]:\\Windows\\') { Stop-WithInputError "Windows runtime module '$path' is malformed" }
        } else { Stop-WithInputError "runtime module '$path'.origin must be payload or windows" }
        $modules += [pscustomobject]@{
            Path         = $path
            PayloadPath  = $payloadPath
            Origin       = $origin
            Architecture = $architecture
            Bytes        = Assert-NonNegativeInteger -Value (Get-MemberValue -Object $entry -Name 'bytes') -Context "runtime evidence modules entry '$path'.bytes"
            Sha256       = Assert-Sha256 -Value (Get-MemberValue -Object $entry -Name 'sha256') -Context "runtime evidence modules entry '$path'.sha256"
        }
    }

    return [pscustomobject]@{
        Path             = $raw.Path
        Bytes            = $raw.Bytes
        Sha256           = $raw.Sha256
        Method           = $method
        Complete         = $complete
        DroppedEvents    = $dropped
        StartedAt        = $startedAt
        CompletedAt      = $completedAt
        HostArchitecture = $hostArchitecture
        Collection       = $collection
        Smokes           = $smokes
        Processes        = $processes
        Modules          = Sort-OrdinalPath -Items $modules -Property 'Path'
    }
}

function Test-RuntimeEvidence {
    param(
        $Runtime,
        $Lock,
        $Manifest,
        [object[]]$Inventory,
        [object[]]$PeInventory,
        [System.Collections.ArrayList]$Violations
    )

    if ($Runtime.Method -cne $script:RuntimeCollectionMethod) {
        [void]$Violations.Add((New-Violation -Code 'runtime-collection-method' -Path $Runtime.Path -Detail "collection.method must be '$($script:RuntimeCollectionMethod)', found '$($Runtime.Method)'"))
    }
    if (-not $Runtime.Complete) {
        [void]$Violations.Add((New-Violation -Code 'runtime-collection-incomplete' -Path $Runtime.Path -Detail 'collection.complete must be true; partial collections cannot authorize a release'))
    }
    if ($Runtime.DroppedEvents -ne 0) {
        [void]$Violations.Add((New-Violation -Code 'runtime-collection-dropped-events' -Path $Runtime.Path -Detail "collection.droppedEvents must be 0, found $($Runtime.DroppedEvents)"))
    }
    foreach ($name in @('samplingIntervalMs', 'sampled', 'failOpen')) {
        if (-not (Test-HasMember -Object $Runtime.Collection -Name $name)) { continue }
        $value = Get-MemberValue -Object $Runtime.Collection -Name $name
        if ($null -eq $value) { continue }
        if (($value -is [bool]) -and -not $value) { continue }
        [void]$Violations.Add((New-Violation -Code 'runtime-sampling-not-allowed' -Path $Runtime.Path -Detail "collection.$name indicates sampled or fail-open collection, which is not acceptable"))
    }
    if ($Runtime.CompletedAt -lt $Runtime.StartedAt) {
        [void]$Violations.Add((New-Violation -Code 'runtime-collection-time-bounds' -Path $Runtime.Path -Detail 'collection.completedAt precedes collection.startedAt'))
    }
    if ($Runtime.CompletedAt -gt [datetimeoffset]::UtcNow.AddMinutes(5)) {
        [void]$Violations.Add((New-Violation -Code 'runtime-collection-time-bounds' -Path $Runtime.Path -Detail 'collection.completedAt lies in the future'))
    }
    if ($Runtime.HostArchitecture -cne 'arm64') {
        [void]$Violations.Add((New-Violation -Code 'runtime-host-architecture' -Path $Runtime.Path -Detail "collection.hostArchitecture must be 'arm64', found '$($Runtime.HostArchitecture)'"))
    }

    $processByPid = @{}
    foreach ($process in $Runtime.Processes) { $processByPid[[string]$process.Pid] = $process }
    foreach ($required in @('shell', 'git')) {
        $smoke = $Runtime.Smokes | Where-Object { $_.Name -ceq $required } | Select-Object -First 1
        if ($null -eq $smoke) {
            [void]$Violations.Add((New-Violation -Code 'runtime-smoke-missing' -Path $Runtime.Path -Detail "the required '$required' smoke test is missing"))
            continue
        }
        if (-not $smoke.Succeeded -or $smoke.ExitCode -ne 0) {
            [void]$Violations.Add((New-Violation -Code 'runtime-smoke-failed' -Path $Runtime.Path -Detail "the '$required' smoke test did not succeed (exitCode $($smoke.ExitCode))"))
        }
        if (-not $processByPid.ContainsKey([string]$smoke.ProcessPid)) {
            [void]$Violations.Add((New-Violation -Code 'runtime-smoke-process-unresolved' -Path $Runtime.Path -Detail "the '$required' smoke test references pid $($smoke.ProcessPid), which is not among the collected processes"))
        }
    }

    $moduleByPath = @{}
    foreach ($module in $Runtime.Modules) { $moduleByPath[$module.Path] = $module }
    $referenced = @{}
    foreach ($process in $Runtime.Processes) {
        if (-not $process.ModulesComplete) {
            [void]$Violations.Add((New-Violation -Code 'runtime-process-modules-incomplete' -Path $process.Path -Detail "process $($process.Pid) module evidence is incomplete"))
        }
        foreach ($modulePath in $process.Modules) {
            if (-not $moduleByPath.ContainsKey($modulePath)) {
                [void]$Violations.Add((New-Violation -Code 'runtime-process-module-unresolved' -Path $modulePath -Detail "process $($process.Pid) ($($process.Path)) references a module that is not described by runtime evidence modules"))
                continue
            }
            $referenced[$modulePath] = $true
        }
    }
    foreach ($module in $Runtime.Modules) {
        if (-not $referenced.ContainsKey($module.Path)) {
            [void]$Violations.Add((New-Violation -Code 'runtime-module-unreferenced' -Path $module.Path -Detail 'the module is described but not referenced by any collected process'))
        }
    }

    $manifestByPath = @{}
    foreach ($entry in $Manifest.Files) { $manifestByPath[$entry.Path] = $entry }
    $diskByPath = @{}
    foreach ($entry in $Inventory) { $diskByPath[$entry.Path] = $entry }
    $peByPath = @{}
    foreach ($entry in $PeInventory) { $peByPath[$entry.Path] = $entry }

    $observed = @()
    foreach ($process in $Runtime.Processes) {
        $observed += [pscustomobject]@{ Path = $process.Path; Architecture = $process.Architecture; Bytes = $null; Sha256 = $null; Label = "process $($process.Pid)" }
    }
    foreach ($module in $Runtime.Modules) {
        $observed += [pscustomobject]@{ Path = $module.Path; Origin = $module.Origin; Architecture = $module.Architecture; Bytes = $module.Bytes; Sha256 = $module.Sha256; Label = 'module' }
    }

    $verified = 0
    foreach ($item in $observed) {
        if ($item.Architecture -cne 'arm64') {
            [void]$Violations.Add((New-Violation -Code 'runtime-architecture-violation' -Path $item.Path -Detail "the observed native $($item.Label) declares '$($item.Architecture)', not ARM64"))
        }
        if ($item.Label -eq 'module' -and $item.Origin -eq 'windows') {
            if (-not [System.IO.File]::Exists($item.Path)) {
                [void]$Violations.Add((New-Violation -Code 'runtime-file-missing' -Path $item.Path -Detail 'the observed Windows module is missing'))
                continue
            }
            $windowsFile = [System.IO.FileInfo]::new($item.Path)
            $windowsSha = Get-FileSha256 -Path $item.Path
            if ($windowsFile.Length -ne $item.Bytes) {
                [void]$Violations.Add((New-Violation -Code 'runtime-bytes-mismatch' -Path $item.Path -Detail "runtime evidence declares $($item.Bytes) bytes, found $($windowsFile.Length) bytes"))
            }
            if ($windowsSha -cne $item.Sha256) {
                [void]$Violations.Add((New-Violation -Code 'runtime-sha256-mismatch' -Path $item.Path -Detail "runtime evidence declares $($item.Sha256), found $windowsSha"))
            }
            $windowsInfo = Get-PeInfo -Path $item.Path
            if ($null -eq $windowsInfo -or $windowsInfo.Architecture -cne 'arm64' -or -not (Test-PeAcceptable -PeInfo $windowsInfo)) {
                $observedArchitecture = if ($null -eq $windowsInfo) { 'not-pe' } else { "$($windowsInfo.Architecture)/$($windowsInfo.ClrKind)" }
                [void]$Violations.Add((New-Violation -Code 'runtime-architecture-violation' -Path $item.Path -Detail "the observed Windows module recomputes as $observedArchitecture, not ARM64"))
            }
            $verified++
            continue
        }
        if (-not $manifestByPath.ContainsKey($item.Path)) {
            [void]$Violations.Add((New-Violation -Code 'runtime-path-not-in-manifest' -Path $item.Path -Detail "the observed $($item.Label) is not declared by the payload manifest"))
            continue
        }
        $actual = $diskByPath[$item.Path]
        if ($null -eq $actual -or $actual.Type -ne 'file') {
            [void]$Violations.Add((New-Violation -Code 'runtime-file-missing' -Path $item.Path -Detail "the observed $($item.Label) is not present as a file below the portable root"))
            continue
        }
        if ($null -ne $item.Bytes -and $actual.Bytes -ne $item.Bytes) {
            [void]$Violations.Add((New-Violation -Code 'runtime-bytes-mismatch' -Path $item.Path -Detail "runtime evidence declares $($item.Bytes) bytes, found $($actual.Bytes) bytes"))
        }
        if ($null -ne $item.Sha256 -and $actual.Sha256 -cne $item.Sha256) {
            [void]$Violations.Add((New-Violation -Code 'runtime-sha256-mismatch' -Path $item.Path -Detail "runtime evidence declares $($item.Sha256), found $($actual.Sha256)"))
        }
        $info = $peByPath[$item.Path]
        if ($null -eq $info) {
            [void]$Violations.Add((New-Violation -Code 'runtime-not-pe' -Path $item.Path -Detail "the observed $($item.Label) is not a PE image"))
            continue
        }
        if ($info.Architecture -cne $item.Architecture) {
            [void]$Violations.Add((New-Violation -Code 'runtime-architecture-mismatch' -Path $item.Path -Detail "runtime evidence declares '$($item.Architecture)', recomputed '$($info.Architecture)'"))
        }
        if (-not $info.Acceptable) {
            [void]$Violations.Add((New-Violation -Code 'runtime-architecture-violation' -Path $item.Path -Detail "the observed $($item.Label) is $($info.Architecture)/$($info.ClrKind), which is not acceptable on ARM64"))
        }
        $verified++
    }

    $processPaths = @{}
    foreach ($process in $Runtime.Processes) { $processPaths[$process.Path] = $true }
    $coverage = @{}
    foreach ($process in $Runtime.Processes) { $coverage[$process.Path] = $true }
    foreach ($module in $Runtime.Modules) { $coverage[$module.Path] = $true }
    $closureProcess = $false
    foreach ($path in $Lock.Closure) {
        if ($processPaths.ContainsKey($path)) { $closureProcess = $true }
        if (-not $coverage.ContainsKey($path)) {
            [void]$Violations.Add((New-Violation -Code 'runtime-closure-coverage' -Path $path -Detail 'the native shell closure entry was never observed as a process or module'))
        }
    }
    if (-not $closureProcess) {
        [void]$Violations.Add((New-Violation -Code 'runtime-closure-process-missing' -Path $Runtime.Path -Detail 'no collected process is part of the native shell closure'))
    }

    return [ordered]@{
        method             = $Runtime.Method
        complete           = [bool]$Runtime.Complete
        droppedEvents      = [long]$Runtime.DroppedEvents
        hostArchitecture   = $Runtime.HostArchitecture
        startedAt          = $Runtime.StartedAt.ToUniversalTime().ToString('o')
        completedAt        = $Runtime.CompletedAt.ToUniversalTime().ToString('o')
        smokeCount         = [int]$Runtime.Smokes.Count
        processCount       = [int]$Runtime.Processes.Count
        moduleCount        = [int]$Runtime.Modules.Count
        reverifiedBinaries = [int]$verified
    }
}

function Write-Evidence {
    param([string]$Path, $Evidence)

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrEmpty($directory) -and -not [System.IO.Directory]::Exists($directory)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    $json = $Evidence | ConvertTo-Json -Depth 20
    $temporary = "$Path.$PID.tmp"
    try {
        [System.IO.File]::WriteAllText($temporary, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-PathBeneath {
    param([string]$Candidate, [string]$Root)

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    if (-not $rootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $rootFull += [System.IO.Path]::DirectorySeparatorChar
    }

    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    return $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-ProhibitedPreparationTool {
    param([string]$Path)
    return $Path -match '(?i)(^|/)(7z|7za|bsdtar|objdump|llvm-objdump|nm|readelf)(\.exe)?$' -or
        $Path -match '(?i)(^|/)(extract|prepare|assembler)[^/]*\.exe$'
}

function Invoke-Validation {
    param([string]$Mode)

    $rootFull = [System.IO.Path]::GetFullPath($PortableRoot)
    if (-not [System.IO.Directory]::Exists($rootFull)) {
        Stop-WithInputError "the portable root does not exist or is not a directory: $rootFull"
    }

    $lock = Read-LockDocument -Path ([System.IO.Path]::GetFullPath($LockPath))
    $provenance = Read-ProvenanceDocument -Path ([System.IO.Path]::GetFullPath($ProvenancePath)) -Lock $lock -PayloadManifestPath ([System.IO.Path]::GetFullPath($PayloadManifestPath))
    $manifest = Read-PayloadManifestDocument -Path ([System.IO.Path]::GetFullPath($PayloadManifestPath)) -Lock $lock

    $inventory = Get-DiskInventory -Root $rootFull
    $inventorySha = Get-InventorySha256 -Inventory $inventory

    $runtime = Read-RuntimeEvidenceDocument -Path ([System.IO.Path]::GetFullPath($RuntimeEvidencePath)) -Mode $Mode -Lock $lock -Provenance $provenance -Manifest $manifest -RootInventorySha256 $inventorySha

    $violations = [System.Collections.ArrayList]::new()
    Compare-ManifestWithDisk -Manifest $manifest -Inventory $inventory -Violations $violations
    $peInventory = Get-PeInventory -Inventory $inventory -Closure $lock.Closure -Root $rootFull
    $archiveChecks = Test-ArchiveSet -Manifest $manifest -Inventory $inventory -RootFull $rootFull -Violations $violations

    $peByPath = @{}
    foreach ($entry in $peInventory) { $peByPath[$entry.Path] = $entry }
    $manifestByPath = @{}
    foreach ($entry in $manifest.Files) { $manifestByPath[$entry.Path] = $entry }

    foreach ($path in $lock.Closure) {
        if (-not $manifestByPath.ContainsKey($path)) {
            [void]$violations.Add((New-Violation -Code 'closure-entry-missing' -Path $path -Detail 'the native shell closure entry is not declared by the payload manifest'))
            continue
        }
        $pe = $peByPath[$path]
        if ($null -eq $pe) {
            [void]$violations.Add((New-Violation -Code 'closure-entry-not-pe' -Path $path -Detail 'the native shell closure entry is missing on disk or is not a PE image'))
            continue
        }
        if ($pe.Architecture -cne 'arm64' -or -not $pe.Acceptable) {
            [void]$violations.Add((New-Violation -Code 'closure-architecture-violation' -Path $path -Detail "the native shell closure entry is $($pe.Architecture)/$($pe.ClrKind), which is not acceptable on ARM64"))
        }
    }

    $broaderNonArm64 = @()
    foreach ($entry in $peInventory) {
        if ($entry.Acceptable -or $entry.InClosure) { continue }
        $broaderNonArm64 += $entry.Path
        if ($Mode -eq 'final') {
            [void]$violations.Add((New-Violation -Code 'payload-architecture-violation' -Path $entry.Path -Detail "the payload binary is $($entry.Architecture)/$($entry.ClrKind), which is not acceptable on ARM64"))
        }
    }

    $unresolved = @()
    foreach ($package in $lock.Packages) {
        if ($package.Resolved) { continue }
        $unresolved += [ordered]@{ name = $package.Name; slot = $package.Slot }
        if ($Mode -eq 'final') {
            [void]$violations.Add((New-Violation -Code 'package-unresolved' -Path $package.Slot -Detail "package '$($package.Name)' has no resolved build for slot '$($package.Slot)'"))
        }
    }

    $runtimeSummary = Test-RuntimeEvidence -Runtime $runtime -Lock $lock -Manifest $manifest -Inventory $inventory -PeInventory $peInventory -Violations $violations
    foreach ($entry in $inventory) {
        if (Test-ProhibitedPreparationTool $entry.Path) {
            [void]$violations.Add((New-Violation 'preparation-tool-in-payload' $entry.Path 'extractor, binutils, or preparation executable is prohibited from the preview'))
        }
    }
    $evidenceDirectory = Join-Path $rootFull 'preview-evidence'
    if ([IO.Directory]::Exists($evidenceDirectory)) {
        foreach ($tool in Get-ChildItem -LiteralPath $evidenceDirectory -Recurse -File -Force) {
            $relativeTool = ConvertTo-ForwardSlash $tool.FullName.Substring($rootFull.Length + 1)
            if ($tool.Extension -ieq '.exe' -or (Test-ProhibitedPreparationTool $relativeTool)) {
                [void]$violations.Add((New-Violation 'preparation-tool-in-preview' $relativeTool 'executable tooling is prohibited below the excluded evidence prefix'))
            }
        }
    }

    $counts = [ordered]@{ arm64 = 0; anycpu = 0; x64 = 0; x86 = 0; unknown = 0 }
    $clrCounts = [ordered]@{ native = 0; anycpu = 0; 'anycpu-prefer32' = 0; 'clr-x86' = 0; 'clr-x64' = 0; 'clr-arm64' = 0; unknown = 0 }
    foreach ($entry in $peInventory) {
        $counts[$entry.Architecture] = [int]$counts[$entry.Architecture] + 1
        $clrCounts[$entry.ClrKind] = [int]$clrCounts[$entry.ClrKind] + 1
    }

    $failed = $violations.Count -gt 0
    $notReady = (-not $failed) -and ($Mode -eq 'preview') -and ($unresolved.Count -gt 0)
    if ($failed) {
        $result = 'failed'
        $exitCode = $script:ExitPolicy
    } elseif ($notReady) {
        $result = 'not-ready'
        $exitCode = $script:ExitNotReady
    } else {
        $result = 'ready'
        $exitCode = $script:ExitReady
    }
    $ready = ($result -eq 'ready')

    $inputs = [ordered]@{
        lock            = [ordered]@{ path = 'bundle-lock.v1.json'; bytes = $lock.Bytes; sha256 = $lock.Sha256 }
        provenance      = [ordered]@{ path = 'deterministic-provenance.v1.json'; bytes = $provenance.Bytes; sha256 = $provenance.Sha256 }
        payloadManifest = [ordered]@{ path = 'payload-manifest.v1.json'; bytes = $manifest.Bytes; sha256 = $manifest.Sha256 }
    }
    $inputs['runtimeEvidence'] = [ordered]@{ path = 'runtime-evidence.v1.json'; bytes = $runtime.Bytes; sha256 = $runtime.Sha256 }

    $peFiles = @()
    foreach ($entry in $peInventory) {
        $peFiles += [ordered]@{
            path         = $entry.Path
            architecture = $entry.Architecture
            clrKind      = $entry.ClrKind
            acceptable   = $entry.Acceptable
            inClosure    = $entry.InClosure
        }
    }

    $fileCount = 0
    $linkCount = 0
    foreach ($entry in $inventory) {
        if ($entry.Type -eq 'file') { $fileCount++ } else { $linkCount++ }
    }

    $evidence = [ordered]@{
        schemaVersion = $script:SchemaVersion
        kind          = $script:KindEvidence
        mode          = $Mode
        previewId     = $lock.PreviewId
        validator     = [ordered]@{
            repository        = $script:ValidatorRepository
            commit            = (Get-MemberValue $provenance.Validator 'commit')
            files             = @($provenance.Validator.PSObject.Properties['files'].Value)
            inventoryAlgorithm = $script:InventoryAlgorithm
        }
        bindings      = $inputs
        portableRoot  = [ordered]@{
            path              = $rootFull
            inventorySha256   = $inventorySha
            inventoryAlgorithm = $script:InventoryAlgorithm
            entryCount        = [int]$inventory.Count
            fileCount         = [int]$fileCount
            linkCount         = [int]$linkCount
            entries           = @($inventory | ForEach-Object {
                [ordered]@{ path = $_.Path; type = $_.Type; bytes = $_.Bytes; sha256 = $_.Sha256; linkTarget = $_.LinkTarget; owner = $_.Owner }
            })
        }
        peInventory   = [ordered]@{
            files     = $peFiles
            count     = [int]$peInventory.Count
            counts    = $counts
            clrCounts = $clrCounts
        }
        closure       = [ordered]@{
            entries = @($lock.Closure)
            count   = [int]$lock.Closure.Count
        }
        archiveChecks = [ordered]@{
            declared = [int]$manifest.Archives.Count
            archives = @($archiveChecks)
            inventory = @($manifest.Archives | ForEach-Object {
                [ordered]@{
                    path = $_.Path
                    format = $_.Format
                    bytes = $_.Bytes
                    sha256 = $_.Sha256
                    owner = $_.Owner
                    members = @($_.Members | ForEach-Object {
                        [ordered]@{
                            path = $_.Path
                            type = $_.Type
                            bytes = $_.Bytes
                            sha256 = $_.Sha256
                            linkTarget = $_.LinkTarget
                            owner = $_.Owner
                        }
                    })
                }
            })
        }
        broaderNonCompliantBinaries = @(Sort-OrdinalPath -Items $broaderNonArm64)
        unresolvedPackages = @($unresolved)
        violations    = @($violations.ToArray())
        result        = $(if ($result -eq 'ready') { 'pass' } elseif ($result -eq 'failed') { 'fail' } else { $result })
        ready         = $ready
        exitCode      = $exitCode
    }
    $evidence['runtime'] = $runtimeSummary

    Write-Evidence -Path ([System.IO.Path]::GetFullPath($OutputPath)) -Evidence $evidence
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw 'validation evidence output is missing'
    }
    $written = Read-JsonDocument $OutputPath 'written validation evidence'
    if ((Get-MemberValue $written.Document 'result') -cne $evidence.result -or
        -not (Test-HasMember $written.Document 'bindings') -or
        -not (Test-HasMember $written.Document 'portableRoot') -or
        -not (Test-HasMember $written.Document 'validator') -or
        -not (Test-HasMember $written.Document 'runtime') -or
        (Get-MemberValue (Get-MemberValue $written.Document 'bindings') 'lock').sha256 -cne $lock.Sha256 -or
        (Get-MemberValue (Get-MemberValue $written.Document 'bindings') 'provenance').sha256 -cne $provenance.Sha256 -or
        (Get-MemberValue (Get-MemberValue $written.Document 'bindings') 'payloadManifest').sha256 -cne $manifest.Sha256) {
        throw 'validation evidence output is nonpassing or an incomplete no-op'
    }
    return $exitCode
}

function Invoke-Main {
    if ($Help) {
        Write-Output (Show-Usage)
        return $script:ExitReady
    }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error 'validate-arm64-preview.ps1 requires PowerShell 7 or newer'
        return $script:ExitUsage
    }

    $normalizedMode = if ($null -eq $Mode) { '' } else { $Mode.Trim() }
    if ($normalizedMode.Length -eq 0) {
        Stop-WithUsageError 'a -Mode of preview or final is required'
    }
    if (@('preview', 'final') -cnotcontains $normalizedMode) {
        Stop-WithUsageError "unknown -Mode '$normalizedMode'; expected preview or final"
    }
    foreach ($name in @('PortableRoot', 'LockPath', 'ProvenancePath', 'PayloadManifestPath', 'RuntimeEvidencePath', 'OutputPath')) {
        $value = (Get-Variable -Name $name -ValueOnly)
        if ([string]::IsNullOrWhiteSpace($value)) {
            Stop-WithUsageError "-$name is required"
        }
    }
    $requiredNames = [ordered]@{
        LockPath = @($LockPath, 'bundle-lock.v1.json')
        ProvenancePath = @($ProvenancePath, 'deterministic-provenance.v1.json')
        PayloadManifestPath = @($PayloadManifestPath, 'payload-manifest.v1.json')
        RuntimeEvidencePath = @($RuntimeEvidencePath, 'runtime-evidence.v1.json')
        OutputPath = @($OutputPath, 'validation-evidence.v1.json')
    }
    $evidenceRoot = Join-Path ([IO.Path]::GetFullPath($PortableRoot)) 'preview-evidence'
    foreach ($name in $requiredNames.Keys) {
        if ([IO.Path]::GetFileName($requiredNames[$name][0]) -cne $requiredNames[$name][1]) { Stop-WithUsageError "-$name must name '$($requiredNames[$name][1])'" }
        $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($requiredNames[$name][0]))
        if (-not [string]::Equals($parent, $evidenceRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Stop-WithUsageError "-$name must be directly below <PortableRoot>\preview-evidence"
        }
    }
    $contractPaths = @($LockPath, $ProvenancePath, $PayloadManifestPath, $RuntimeEvidencePath, $OutputPath)
    foreach ($path in $contractPaths) {
        if (-not (Test-PathBeneath $path $evidenceRoot)) { Stop-WithUsageError 'all contract/evidence paths must be below <PortableRoot>\preview-evidence' }
    }

    Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    return (Invoke-Validation -Mode $normalizedMode)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }
try {
    $exit = Invoke-Main
} catch [ValidatorUsageException] {
    [Console]::Error.WriteLine("usage error: $($_.Exception.Message)")
    Write-Output (Show-Usage)
    exit $script:ExitUsage
} catch [ValidatorInputException] {
    Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    [Console]::Error.WriteLine("input contract error: $($_.Exception.Message)")
    exit $script:ExitInput
} catch {
    Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    [Console]::Error.WriteLine("internal error: $($_.Exception.Message)")
    exit $script:ExitInternal
}
exit $exit
