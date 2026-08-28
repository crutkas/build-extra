$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:CanonicalManifest = 'mode<TAB>type<TAB>object-id<TAB>size-or-dash<TAB>percent-encoded-UTF-8-path<LF> in recursive Git tree order; tree size is dash'
$script:PackageCanonicalization = 'the complete-tree canonical records whose paths equal or descend from a listed scope'
$script:Repository = 'git-for-windows/git-sdk-arm64'
$script:RemoteUrl = 'https://github.com/git-for-windows/git-sdk-arm64.git'
$script:Commit = 'f1e6b08892fc285dcb401433db359c3c61c0defd'
$script:Tree = '6b92d3a604c63481bff454dcd3da40d0b6293082'
$script:Parent = 'bd683ba009eeed6d87334bda905e687a260c175a'
$script:ManifestSha256 = '6d3407edcebcd4bec2b985e8a1dd5d16720cafd08d326a5b99fa4c76d97d7882'
$script:PackageDatabaseSha256 = 'ac954098803554fddcfa79bf66aeddd7ede4659ae645072493743a14f5bf8d89'
$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)
# GetLongPathNameW and the other Win32 path entry points this module relies on
# resolve a DOS path only while it stays shorter than MAX_PATH. Measured on
# Windows, they succeed at 259 characters and fail with ERROR_PATH_NOT_FOUND
# at 260. Extended-length '\\?\' syntax lifts that limit, but this module
# deliberately refuses to accept or construct such paths, so every path it
# validates or creates has to stay at or below the usable length. The .NET
# directory APIs carry no such limit, so without this bound the bootstrap can
# create a root it can no longer canonicalize, identity-check or delete.
$script:MaxUsablePathLength = 259
$script:RootSentinelName = '.gfw-sdk-bootstrap-owner'
# The bootstrap creates its bare mirror at <root>\repository.git and fetches
# into it long before the worktree gate can read the locked manifest, so the
# root has to be budgeted for Git's own control paths as well. The deepest of
# those is a pack file: the object-id is 40 hexadecimal characters and
# '.promisor' is the longest suffix Git appends to a pack name.
$script:GitDirectoryName = 'repository.git'
$script:SdkDirectoryName = 'sdk'
$script:GitTemplateDirectoryName = 'empty-git-template'
$script:GitControlReserve =
	1 + $script:GitDirectoryName.Length +
	1 + 'objects'.Length +
	1 + 'pack'.Length +
	1 + 'pack-'.Length + 40 + '.promisor'.Length
$script:TrustedGitExecPath = $null
$script:TrustedGitRuntimePath = $null
$script:PrivateTempPath = $null

if (-not ('GfwSdkBootstrapNativeMethods' -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class GfwSdkBootstrapNativeMethods
{
    public const int TokenElevation = 20;
    public const uint TokenQuery = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenElevationInfo
    {
        public int TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetLongPathName(
        string shortPath,
        StringBuilder longPath,
        uint bufferLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        out TokenElevationInfo tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle file,
        out ByHandleFileInformation information);
}
'@
}

function Get-Sha256Hex {
	param([Parameter(Mandatory = $true)][byte[]]$Bytes)

	$hash = [Security.Cryptography.SHA256]::HashData($Bytes)
	return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Assert-HexString {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][int]$Length,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-ExactStringValue $Value $Name
	if ($Value -cnotmatch "^[0-9a-f]{$Length}$") {
		throw "$Name must be exactly $Length lowercase hexadecimal characters"
	}
}

function Assert-ExactProperties {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string[]]$Expected,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if (
		$null -eq $Value -or
		$Value.GetType() -ne [Management.Automation.PSCustomObject]
	) {
		throw "$Name must be an object"
	}
	$actual = [Collections.Generic.List[string]]::new()
	foreach ($property in $Value.PSObject.Properties) {
		$actual.Add($property.Name)
	}
	if ($actual.Count -ne $Expected.Count) {
		throw "$Name has an unexpected property count"
	}
	$expectedSet = [Collections.Generic.HashSet[string]]::new(
		$Expected, [StringComparer]::Ordinal)
	foreach ($property in $actual) {
		if (-not $expectedSet.Remove($property)) {
			throw "$Name has unexpected property '$property'"
		}
	}
	if ($expectedSet.Count -ne 0) {
		throw "$Name is missing required properties"
	}
}

function Assert-ExactStringValue {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name,
		[switch]$AllowEmpty
	)

	if ($null -eq $Value -or $Value.GetType() -ne [string]) {
		throw "$Name must be a JSON string"
	}
	if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($Value)) {
		throw "$Name must be a nonempty JSON string"
	}
}

function Assert-ExactInt64Value {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($null -eq $Value -or $Value.GetType() -ne [long]) {
		throw "$Name must be a JSON integer"
	}
}

function Assert-ExactBooleanValue {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($null -eq $Value -or $Value.GetType() -ne [bool]) {
		throw "$Name must be a JSON boolean"
	}
}

function Assert-ExactArrayValue {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($null -eq $Value -or $Value.GetType() -ne [object[]]) {
		throw "$Name must be a JSON array"
	}
}

function Assert-JsonKind {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][Text.Json.JsonValueKind]$Kind,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($Element.ValueKind -ne $Kind) {
		throw "$Name must be a JSON $($Kind.ToString().ToLowerInvariant())"
	}
}

function Get-JsonProperty {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string]$Property,
		[Parameter(Mandatory = $true)][string]$Name
	)

	[Text.Json.JsonElement]$value = [Text.Json.JsonElement]::new()
	if (-not $Element.TryGetProperty($Property, [ref]$value)) {
		throw "$Name is missing required property '$Property'"
	}
	return $value
}

function Assert-ExactJsonProperties {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string[]]$Expected,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-JsonKind $Element ([Text.Json.JsonValueKind]::Object) $Name
	$actual = [Collections.Generic.List[string]]::new()
	foreach ($property in $Element.EnumerateObject()) {
		$actual.Add($property.Name)
	}
	if ($actual.Count -ne $Expected.Count) {
		throw "$Name has an unexpected property count"
	}
	$expectedSet = [Collections.Generic.HashSet[string]]::new(
		$Expected, [StringComparer]::Ordinal)
	foreach ($property in $actual) {
		if (-not $expectedSet.Remove($property)) {
			throw "$Name has unexpected property '$property'"
		}
	}
	if ($expectedSet.Count -ne 0) {
		throw "$Name is missing required properties"
	}
}

function Get-JsonString {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-JsonKind $Element ([Text.Json.JsonValueKind]::String) $Name
	return $Element.GetString()
}

function Get-JsonInt64 {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-JsonKind $Element ([Text.Json.JsonValueKind]::Number) $Name
	$value = 0L
	if (-not $Element.TryGetInt64([ref]$value)) {
		throw "$Name must be a JSON integer"
	}
	return $value
}

function Get-JsonBoolean {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if (
		$Element.ValueKind -ne [Text.Json.JsonValueKind]::True -and
		$Element.ValueKind -ne [Text.Json.JsonValueKind]::False
	) {
		throw "$Name must be a JSON boolean"
	}
	return $Element.GetBoolean()
}

function Assert-JsonNull {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-JsonKind $Element ([Text.Json.JsonValueKind]::Null) $Name
}

function Assert-NoDuplicateJsonProperties {
	param(
		[Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
		[string]$Path = '$'
	)

	switch ($Element.ValueKind) {
		'Object' {
			$names = [Collections.Generic.HashSet[string]]::new(
				[StringComparer]::Ordinal)
			foreach ($property in $Element.EnumerateObject()) {
				if (-not $names.Add($property.Name)) {
					throw "Duplicate JSON property '$($property.Name)' at $Path"
				}
				Assert-NoDuplicateJsonProperties `
					-Element $property.Value `
					-Path "$Path.$($property.Name)"
			}
		}
		'Array' {
			$index = 0
			foreach ($item in $Element.EnumerateArray()) {
				Assert-NoDuplicateJsonProperties `
					-Element $item `
					-Path "$Path[$index]"
				$index++
			}
		}
	}
}

function ConvertFrom-AdmissionEvidenceJson {
	param([Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element)

	Assert-ExactJsonProperties $Element @(
		'authority_repository',
		'authority_ref',
		'protected_base_commit',
		'reviewed_source_commit',
		'reviewed_source_tree',
		'base_protected',
		'required_checks_passed',
		'required_checks',
		'native_runner'
	) 'lock.admission.evidence'
	$checksElement = Get-JsonProperty $Element 'required_checks' `
		'lock.admission.evidence'
	Assert-JsonKind $checksElement ([Text.Json.JsonValueKind]::Array) `
		'lock.admission.evidence.required_checks'
	$checks = [Collections.Generic.List[object]]::new()
	foreach ($check in $checksElement.EnumerateArray()) {
		$checks.Add((Get-JsonString $check `
			'lock.admission.evidence.required_checks[]'))
	}

	$runnerElement = Get-JsonProperty $Element 'native_runner' `
		'lock.admission.evidence'
	Assert-ExactJsonProperties $runnerElement @(
		'provider',
		'image',
		'os',
		'os_architecture',
		'process_architecture',
		'evidence_uri'
	) 'lock.admission.evidence.native_runner'

	return [pscustomobject][ordered]@{
		authority_repository = Get-JsonString (
			Get-JsonProperty $Element 'authority_repository' `
				'lock.admission.evidence') `
			'lock.admission.evidence.authority_repository'
		authority_ref = Get-JsonString (
			Get-JsonProperty $Element 'authority_ref' `
				'lock.admission.evidence') `
			'lock.admission.evidence.authority_ref'
		protected_base_commit = Get-JsonString (
			Get-JsonProperty $Element 'protected_base_commit' `
				'lock.admission.evidence') `
			'lock.admission.evidence.protected_base_commit'
		reviewed_source_commit = Get-JsonString (
			Get-JsonProperty $Element 'reviewed_source_commit' `
				'lock.admission.evidence') `
			'lock.admission.evidence.reviewed_source_commit'
		reviewed_source_tree = Get-JsonString (
			Get-JsonProperty $Element 'reviewed_source_tree' `
				'lock.admission.evidence') `
			'lock.admission.evidence.reviewed_source_tree'
		base_protected = Get-JsonBoolean (
			Get-JsonProperty $Element 'base_protected' `
				'lock.admission.evidence') `
			'lock.admission.evidence.base_protected'
		required_checks_passed = Get-JsonBoolean (
			Get-JsonProperty $Element 'required_checks_passed' `
				'lock.admission.evidence') `
			'lock.admission.evidence.required_checks_passed'
		required_checks = [object[]]$checks.ToArray()
		native_runner = [pscustomobject][ordered]@{
			provider = Get-JsonString (
				Get-JsonProperty $runnerElement 'provider' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.provider'
			image = Get-JsonString (
				Get-JsonProperty $runnerElement 'image' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.image'
			os = Get-JsonString (
				Get-JsonProperty $runnerElement 'os' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.os'
			os_architecture = Get-JsonString (
				Get-JsonProperty $runnerElement 'os_architecture' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.os_architecture'
			process_architecture = Get-JsonString (
				Get-JsonProperty $runnerElement 'process_architecture' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.process_architecture'
			evidence_uri = Get-JsonString (
				Get-JsonProperty $runnerElement 'evidence_uri' `
					'lock.admission.evidence.native_runner') `
				'lock.admission.evidence.native_runner.evidence_uri'
		}
	}
}

function ConvertFrom-SdkLockJson {
	param([Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element)

	Assert-ExactJsonProperties $Element @(
		'format',
		'repository',
		'remote_url',
		'commit',
		'tree',
		'parent',
		'commit_metadata',
		'manifest',
		'package_database',
		'admission'
	) 'lock'
	$metadataElement = Get-JsonProperty $Element 'commit_metadata' 'lock'
	Assert-ExactJsonProperties $metadataElement @(
		'author',
		'committer',
		'authored_at',
		'committed_at',
		'signature_status',
		'subject'
	) 'lock.commit_metadata'
	$manifestElement = Get-JsonProperty $Element 'manifest' 'lock'
	Assert-ExactJsonProperties $manifestElement @(
		'canonicalization',
		'sha256',
		'entry_count',
		'blob_count',
		'tree_count',
		'total_blob_bytes'
	) 'lock.manifest'
	$packageElement = Get-JsonProperty $Element 'package_database' 'lock'
	Assert-ExactJsonProperties $packageElement @(
		'scope',
		'canonicalization',
		'sha256',
		'entry_count',
		'blob_count',
		'tree_count',
		'total_blob_bytes'
	) 'lock.package_database'
	$scopeElement = Get-JsonProperty $packageElement 'scope' `
		'lock.package_database'
	Assert-JsonKind $scopeElement ([Text.Json.JsonValueKind]::Array) `
		'lock.package_database.scope'
	$scope = [Collections.Generic.List[object]]::new()
	foreach ($path in $scopeElement.EnumerateArray()) {
		$scope.Add((Get-JsonString $path 'lock.package_database.scope[]'))
	}

	$admissionElement = Get-JsonProperty $Element 'admission' 'lock'
	Assert-ExactJsonProperties $admissionElement @(
		'status',
		'approved_by',
		'approved_at',
		'evidence'
	) 'lock.admission'
	$status = Get-JsonString (
		Get-JsonProperty $admissionElement 'status' 'lock.admission') `
		'lock.admission.status'
	$approvedByElement = Get-JsonProperty $admissionElement 'approved_by' `
		'lock.admission'
	$approvedAtElement = Get-JsonProperty $admissionElement 'approved_at' `
		'lock.admission'
	$evidenceElement = Get-JsonProperty $admissionElement 'evidence' `
		'lock.admission'
	$approvedBy = $null
	$approvedAt = $null
	$evidence = $null
	if ($status -ceq 'pending-independent-review') {
		Assert-JsonNull $approvedByElement 'lock.admission.approved_by'
		Assert-JsonNull $approvedAtElement 'lock.admission.approved_at'
		Assert-JsonNull $evidenceElement 'lock.admission.evidence'
	} elseif ($status -ceq 'approved') {
		$approvedBy = Get-JsonString $approvedByElement `
			'lock.admission.approved_by'
		$approvedAt = Get-JsonString $approvedAtElement `
			'lock.admission.approved_at'
		$evidence = ConvertFrom-AdmissionEvidenceJson $evidenceElement
	} else {
		throw 'Unknown snapshot admission status'
	}

	return [pscustomobject][ordered]@{
		format = Get-JsonString (
			Get-JsonProperty $Element 'format' 'lock') 'lock.format'
		repository = Get-JsonString (
			Get-JsonProperty $Element 'repository' 'lock') 'lock.repository'
		remote_url = Get-JsonString (
			Get-JsonProperty $Element 'remote_url' 'lock') 'lock.remote_url'
		commit = Get-JsonString (
			Get-JsonProperty $Element 'commit' 'lock') 'lock.commit'
		tree = Get-JsonString (
			Get-JsonProperty $Element 'tree' 'lock') 'lock.tree'
		parent = Get-JsonString (
			Get-JsonProperty $Element 'parent' 'lock') 'lock.parent'
		commit_metadata = [pscustomobject][ordered]@{
			author = Get-JsonString (
				Get-JsonProperty $metadataElement 'author' `
					'lock.commit_metadata') 'lock.commit_metadata.author'
			committer = Get-JsonString (
				Get-JsonProperty $metadataElement 'committer' `
					'lock.commit_metadata') 'lock.commit_metadata.committer'
			authored_at = Get-JsonString (
				Get-JsonProperty $metadataElement 'authored_at' `
					'lock.commit_metadata') 'lock.commit_metadata.authored_at'
			committed_at = Get-JsonString (
				Get-JsonProperty $metadataElement 'committed_at' `
					'lock.commit_metadata') 'lock.commit_metadata.committed_at'
			signature_status = Get-JsonString (
				Get-JsonProperty $metadataElement 'signature_status' `
					'lock.commit_metadata') 'lock.commit_metadata.signature_status'
			subject = Get-JsonString (
				Get-JsonProperty $metadataElement 'subject' `
					'lock.commit_metadata') 'lock.commit_metadata.subject'
		}
		manifest = [pscustomobject][ordered]@{
			canonicalization = Get-JsonString (
				Get-JsonProperty $manifestElement 'canonicalization' `
					'lock.manifest') 'lock.manifest.canonicalization'
			sha256 = Get-JsonString (
				Get-JsonProperty $manifestElement 'sha256' `
					'lock.manifest') 'lock.manifest.sha256'
			entry_count = Get-JsonInt64 (
				Get-JsonProperty $manifestElement 'entry_count' `
					'lock.manifest') 'lock.manifest.entry_count'
			blob_count = Get-JsonInt64 (
				Get-JsonProperty $manifestElement 'blob_count' `
					'lock.manifest') 'lock.manifest.blob_count'
			tree_count = Get-JsonInt64 (
				Get-JsonProperty $manifestElement 'tree_count' `
					'lock.manifest') 'lock.manifest.tree_count'
			total_blob_bytes = Get-JsonString (
				Get-JsonProperty $manifestElement 'total_blob_bytes' `
					'lock.manifest') 'lock.manifest.total_blob_bytes'
		}
		package_database = [pscustomobject][ordered]@{
			scope = [object[]]$scope.ToArray()
			canonicalization = Get-JsonString (
				Get-JsonProperty $packageElement 'canonicalization' `
					'lock.package_database') `
				'lock.package_database.canonicalization'
			sha256 = Get-JsonString (
				Get-JsonProperty $packageElement 'sha256' `
					'lock.package_database') 'lock.package_database.sha256'
			entry_count = Get-JsonInt64 (
				Get-JsonProperty $packageElement 'entry_count' `
					'lock.package_database') 'lock.package_database.entry_count'
			blob_count = Get-JsonInt64 (
				Get-JsonProperty $packageElement 'blob_count' `
					'lock.package_database') 'lock.package_database.blob_count'
			tree_count = Get-JsonInt64 (
				Get-JsonProperty $packageElement 'tree_count' `
					'lock.package_database') 'lock.package_database.tree_count'
			total_blob_bytes = Get-JsonString (
				Get-JsonProperty $packageElement 'total_blob_bytes' `
					'lock.package_database') `
				'lock.package_database.total_blob_bytes'
		}
		admission = [pscustomobject][ordered]@{
			status = $status
			approved_by = $approvedBy
			approved_at = $approvedAt
			evidence = $evidence
		}
	}
}

function Read-SdkLock {
	[CmdletBinding()]
	param([Parameter(Mandatory = $true)][object]$Path)

	Assert-ExactStringValue $Path 'SDK lock path'
	$item = Get-Item -LiteralPath $Path -Force
	if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
		throw 'The SDK lock must be a regular, non-reparse file'
	}
	if ($item.Length -gt 65536) {
		throw 'The SDK lock is unexpectedly large'
	}

	$bytes = [IO.File]::ReadAllBytes($item.FullName)
	$stream = [IO.MemoryStream]::new($bytes, $false)
	try {
		$document = [Text.Json.JsonDocument]::Parse($stream)
		try {
			Assert-NoDuplicateJsonProperties -Element $document.RootElement
			return ConvertFrom-SdkLockJson $document.RootElement
		} finally {
			$document.Dispose()
		}
	} finally {
		$stream.Dispose()
	}
}

function Assert-PositiveInteger {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-ExactInt64Value $Value $Name
	if ($Value -le 0) {
		throw "$Name must be a positive integer"
	}
	return $Value
}

function Assert-PositiveDecimalString {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-ExactStringValue $Value $Name
	$number = 0UL
	if (
		-not [uint64]::TryParse(
			$Value,
			[Globalization.NumberStyles]::None,
			[Globalization.CultureInfo]::InvariantCulture,
			[ref]$number
		) -or
		$number -eq 0 -or
		$number.ToString([Globalization.CultureInfo]::InvariantCulture) -cne
			$Value
	) {
		throw "$Name must be a positive canonical decimal string"
	}
	return $number
}

function ConvertTo-LockTimestamp {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-ExactStringValue $Value $Name
	$timestamp = [DateTimeOffset]::MinValue
	if (-not [DateTimeOffset]::TryParseExact(
		$Value,
		'yyyy-MM-ddTHH:mm:ssZ',
		[Globalization.CultureInfo]::InvariantCulture,
		[Globalization.DateTimeStyles]::AssumeUniversal -bor
			[Globalization.DateTimeStyles]::AdjustToUniversal,
		[ref]$timestamp
	) -or $timestamp.ToString(
		'yyyy-MM-ddTHH:mm:ssZ',
		[Globalization.CultureInfo]::InvariantCulture) -cne $Value) {
		throw "$Name must be an exact UTC timestamp"
	}
	return $Value
}

function Assert-SdkLockSchema {
	param([Parameter(Mandatory = $true)][object]$Lock)

	Assert-ExactProperties $Lock @(
		'format',
		'repository',
		'remote_url',
		'commit',
		'tree',
		'parent',
		'commit_metadata',
		'manifest',
		'package_database',
		'admission'
	) 'lock'
	Assert-ExactProperties $Lock.commit_metadata @(
		'author',
		'committer',
		'authored_at',
		'committed_at',
		'signature_status',
		'subject'
	) 'lock.commit_metadata'
	Assert-ExactProperties $Lock.manifest @(
		'canonicalization',
		'sha256',
		'entry_count',
		'blob_count',
		'tree_count',
		'total_blob_bytes'
	) 'lock.manifest'
	Assert-ExactProperties $Lock.package_database @(
		'scope',
		'canonicalization',
		'sha256',
		'entry_count',
		'blob_count',
		'tree_count',
		'total_blob_bytes'
	) 'lock.package_database'
	Assert-ExactProperties $Lock.admission @(
		'status',
		'approved_by',
		'approved_at',
		'evidence'
	) 'lock.admission'

	foreach ($entry in @(
		[pscustomobject]@{ Value = $Lock.format; Name = 'lock.format' },
		[pscustomobject]@{
			Value = $Lock.repository
			Name = 'lock.repository'
		},
		[pscustomobject]@{
			Value = $Lock.remote_url
			Name = 'lock.remote_url'
		},
		[pscustomobject]@{ Value = $Lock.commit; Name = 'lock.commit' },
		[pscustomobject]@{ Value = $Lock.tree; Name = 'lock.tree' },
		[pscustomobject]@{ Value = $Lock.parent; Name = 'lock.parent' },
		[pscustomobject]@{
			Value = $Lock.commit_metadata.author
			Name = 'lock.commit_metadata.author'
		},
		[pscustomobject]@{
			Value = $Lock.commit_metadata.committer
			Name = 'lock.commit_metadata.committer'
		},
		[pscustomobject]@{
			Value = $Lock.commit_metadata.authored_at
			Name = 'lock.commit_metadata.authored_at'
		},
		[pscustomobject]@{
			Value = $Lock.commit_metadata.committed_at
			Name = 'lock.commit_metadata.committed_at'
		},
		[pscustomobject]@{
			Value = $Lock.commit_metadata.signature_status
			Name = 'lock.commit_metadata.signature_status'
		},
		[pscustomobject]@{
			Value = $Lock.commit_metadata.subject
			Name = 'lock.commit_metadata.subject'
		},
		[pscustomobject]@{
			Value = $Lock.manifest.canonicalization
			Name = 'lock.manifest.canonicalization'
		},
		[pscustomobject]@{
			Value = $Lock.manifest.sha256
			Name = 'lock.manifest.sha256'
		},
		[pscustomobject]@{
			Value = $Lock.manifest.total_blob_bytes
			Name = 'lock.manifest.total_blob_bytes'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.canonicalization
			Name = 'lock.package_database.canonicalization'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.sha256
			Name = 'lock.package_database.sha256'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.total_blob_bytes
			Name = 'lock.package_database.total_blob_bytes'
		},
		[pscustomobject]@{
			Value = $Lock.admission.status
			Name = 'lock.admission.status'
		}
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	foreach ($entry in @(
		[pscustomobject]@{
			Value = $Lock.manifest.entry_count
			Name = 'lock.manifest.entry_count'
		},
		[pscustomobject]@{
			Value = $Lock.manifest.blob_count
			Name = 'lock.manifest.blob_count'
		},
		[pscustomobject]@{
			Value = $Lock.manifest.tree_count
			Name = 'lock.manifest.tree_count'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.entry_count
			Name = 'lock.package_database.entry_count'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.blob_count
			Name = 'lock.package_database.blob_count'
		},
		[pscustomobject]@{
			Value = $Lock.package_database.tree_count
			Name = 'lock.package_database.tree_count'
		}
	)) {
		Assert-ExactInt64Value $entry.Value $entry.Name
	}
	Assert-ExactArrayValue $Lock.package_database.scope `
		'lock.package_database.scope'
	foreach ($scopePath in $Lock.package_database.scope) {
		Assert-ExactStringValue $scopePath 'lock.package_database.scope[]'
	}

	if ($Lock.format -cne 'git-for-windows-sdk-git-tree-lock-v1') {
		throw 'Unexpected SDK lock format'
	}
	Assert-HexString $Lock.commit 40 'lock.commit'
	Assert-HexString $Lock.tree 40 'lock.tree'
	Assert-HexString $Lock.parent 40 'lock.parent'
	Assert-HexString $Lock.manifest.sha256 64 'lock.manifest.sha256'
	Assert-HexString $Lock.package_database.sha256 64 `
		'lock.package_database.sha256'

	$manifestEntries = Assert-PositiveInteger `
		$Lock.manifest.entry_count 'lock.manifest.entry_count'
	$manifestBlobs = Assert-PositiveInteger `
		$Lock.manifest.blob_count 'lock.manifest.blob_count'
	$manifestTrees = Assert-PositiveInteger `
		$Lock.manifest.tree_count 'lock.manifest.tree_count'
	[void](Assert-PositiveDecimalString `
		$Lock.manifest.total_blob_bytes 'lock.manifest.total_blob_bytes')
	if ($manifestEntries -ne $manifestBlobs + $manifestTrees) {
		throw 'The complete manifest entry counts are inconsistent'
	}

	$packageEntries = Assert-PositiveInteger `
		$Lock.package_database.entry_count `
		'lock.package_database.entry_count'
	$packageBlobs = Assert-PositiveInteger `
		$Lock.package_database.blob_count `
		'lock.package_database.blob_count'
	$packageTrees = Assert-PositiveInteger `
		$Lock.package_database.tree_count `
		'lock.package_database.tree_count'
	[void](Assert-PositiveDecimalString `
		$Lock.package_database.total_blob_bytes `
		'lock.package_database.total_blob_bytes')
	if ($packageEntries -ne $packageBlobs + $packageTrees) {
		throw 'The package database manifest entry counts are inconsistent'
	}

	$scope = $Lock.package_database.scope
	if (
		$scope.Count -ne 2 -or
		$scope[0] -cne 'var/lib/pacman/local' -or
		$scope[1] -cne 'var/lib/pacman/sync'
	) {
		throw 'Unexpected package database scope'
	}

	if ($Lock.admission.status -ceq 'pending-independent-review') {
		if (
			$null -ne $Lock.admission.approved_by -or
			$null -ne $Lock.admission.approved_at -or
			$null -ne $Lock.admission.evidence
		) {
			throw 'A pending snapshot cannot contain approval evidence'
		}
	} elseif ($Lock.admission.status -ceq 'approved') {
		Assert-ExactStringValue $Lock.admission.approved_by `
			'lock.admission.approved_by'
		[void](ConvertTo-LockTimestamp `
			$Lock.admission.approved_at 'lock.admission.approved_at')
		Assert-ExactProperties $Lock.admission.evidence @(
			'authority_repository',
			'authority_ref',
			'protected_base_commit',
			'reviewed_source_commit',
			'reviewed_source_tree',
			'base_protected',
			'required_checks_passed',
			'required_checks',
			'native_runner'
		) 'lock.admission.evidence'
		$evidence = $Lock.admission.evidence
		foreach ($entry in @(
			[pscustomobject]@{
				Value = $evidence.authority_repository
				Name = 'lock.admission.evidence.authority_repository'
			},
			[pscustomobject]@{
				Value = $evidence.authority_ref
				Name = 'lock.admission.evidence.authority_ref'
			},
			[pscustomobject]@{
				Value = $evidence.protected_base_commit
				Name = 'lock.admission.evidence.protected_base_commit'
			},
			[pscustomobject]@{
				Value = $evidence.reviewed_source_commit
				Name = 'lock.admission.evidence.reviewed_source_commit'
			},
			[pscustomobject]@{
				Value = $evidence.reviewed_source_tree
				Name = 'lock.admission.evidence.reviewed_source_tree'
			}
		)) {
			Assert-ExactStringValue $entry.Value $entry.Name
		}
		Assert-HexString $evidence.protected_base_commit 40 `
			'lock.admission.evidence.protected_base_commit'
		Assert-HexString $evidence.reviewed_source_commit 40 `
			'lock.admission.evidence.reviewed_source_commit'
		Assert-HexString $evidence.reviewed_source_tree 40 `
			'lock.admission.evidence.reviewed_source_tree'
		if (
			$evidence.authority_repository -cne 'crutkas/build-extra' -or
			$evidence.authority_ref -cne 'refs/heads/main'
		) {
			throw 'Admission evidence is not anchored to the protected base'
		}
		Assert-ExactBooleanValue $evidence.base_protected `
			'lock.admission.evidence.base_protected'
		Assert-ExactBooleanValue $evidence.required_checks_passed `
			'lock.admission.evidence.required_checks_passed'
		if (-not $evidence.base_protected -or -not $evidence.required_checks_passed) {
			throw 'Admission evidence does not prove protected-base governance'
		}
		Assert-ExactArrayValue $evidence.required_checks `
			'lock.admission.evidence.required_checks'
		if (
			$evidence.required_checks.Count -ne 1 -or
			$evidence.required_checks[0] -cne 'source-lock-validation'
		) {
			throw 'Admission evidence must name the protected required check'
		}
		$checks = [Collections.Generic.HashSet[string]]::new(
			[StringComparer]::Ordinal)
		foreach ($check in $evidence.required_checks) {
			Assert-ExactStringValue $check `
				'lock.admission.evidence.required_checks[]'
			if (
				$check.Length -gt 128 -or
				$check -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._ /-]*$' -or
				-not $checks.Add($check)
			) {
				throw 'Admission evidence contains an invalid required check'
			}
		}
		Assert-ExactProperties $evidence.native_runner @(
			'provider',
			'image',
			'os',
			'os_architecture',
			'process_architecture',
			'evidence_uri'
		) 'lock.admission.evidence.native_runner'
		foreach ($property in @(
			'provider',
			'image',
			'os',
			'os_architecture',
			'process_architecture',
			'evidence_uri'
		)) {
			Assert-ExactStringValue $evidence.native_runner.$property `
				"lock.admission.evidence.native_runner.$property"
		}
		if (
			$evidence.native_runner.provider -cne 'github-hosted' -or
			$evidence.native_runner.image -cne 'windows-11-arm' -or
			$evidence.native_runner.os -cne 'Windows' -or
			$evidence.native_runner.os_architecture -cne 'Arm64' -or
			$evidence.native_runner.process_architecture -cne 'Arm64'
		) {
			throw 'Admission evidence does not identify a native ARM64 runner'
		}
		$evidenceUri = $null
		if (
			-not [Uri]::TryCreate(
				$evidence.native_runner.evidence_uri,
				[UriKind]::Absolute,
				[ref]$evidenceUri
			) -or
			$evidenceUri.Scheme -cne 'https' -or
			$evidenceUri.AbsoluteUri -cne
				$evidence.native_runner.evidence_uri -or
			$evidence.native_runner.evidence_uri -cnotmatch
				'^https://github\.com/crutkas/build-extra/actions/runs/[1-9][0-9]*$' -or
			-not [string]::IsNullOrEmpty($evidenceUri.UserInfo) -or
			-not [string]::IsNullOrEmpty($evidenceUri.Fragment)
		) {
			throw 'Admission native-runner evidence URI must be immutable HTTPS'
		}
		if ($Lock.admission.approved_by -cne 'protected-base-governance') {
			throw 'Admission approver is not the protected-base authority'
		}
	} else {
		throw 'Unknown snapshot admission status'
	}
}

function Assert-ProductionSdkLock {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$Lock,
		[switch]$RequireApproval
	)

	Assert-SdkLockSchema $Lock

	$expectedStrings = [ordered]@{
		format = 'git-for-windows-sdk-git-tree-lock-v1'
		repository = $script:Repository
		remote_url = $script:RemoteUrl
		commit = $script:Commit
		tree = $script:Tree
		parent = $script:Parent
	}
	foreach ($property in $expectedStrings.Keys) {
		if ($Lock.$property -cne $expectedStrings[$property]) {
			throw "Unexpected production lock $property"
		}
	}
	if (
		$Lock.commit_metadata.author -cne
			'Git for Windows Build Agent <ci@git-for-windows.build> 1787836270 +0000' -or
		$Lock.commit_metadata.committer -cne
			'Git for Windows Build Agent <ci@git-for-windows.build> 1787836270 +0000' -or
		(ConvertTo-LockTimestamp `
			$Lock.commit_metadata.authored_at 'commit_metadata.authored_at') -cne
			'2026-08-27T13:11:10Z' -or
		(ConvertTo-LockTimestamp `
			$Lock.commit_metadata.committed_at 'commit_metadata.committed_at') -cne
			'2026-08-27T13:11:10Z' -or
		$Lock.commit_metadata.signature_status -cne 'unsigned' -or
		$Lock.commit_metadata.subject -cne 'Update 1 package'
	) {
		throw 'Unexpected production commit metadata'
	}
	if (
		$Lock.manifest.canonicalization -cne $script:CanonicalManifest -or
		$Lock.manifest.sha256 -cne $script:ManifestSha256 -or
		$Lock.manifest.entry_count -ne 88249L -or
		$Lock.manifest.blob_count -ne 83648L -or
		$Lock.manifest.tree_count -ne 4601L -or
		$Lock.manifest.total_blob_bytes -cne '3615514045'
	) {
		throw 'Unexpected production complete-tree manifest metadata'
	}
	if (
		$Lock.package_database.canonicalization -cne
			$script:PackageCanonicalization -or
		$Lock.package_database.sha256 -cne $script:PackageDatabaseSha256 -or
		$Lock.package_database.entry_count -ne 1309L -or
		$Lock.package_database.blob_count -ne 995L -or
		$Lock.package_database.tree_count -ne 314L -or
		$Lock.package_database.total_blob_bytes -cne '43600841'
	) {
		throw 'Unexpected production package database manifest metadata'
	}
	if ($RequireApproval -and $Lock.admission.status -cne 'approved') {
		throw 'The pinned SDK snapshot is not independently admitted'
	}
}

function Assert-RunnerPlatformFacts {
	param(
		[Parameter(Mandatory = $true)][object]$WindowsPlatform,
		[Parameter(Mandatory = $true)][object]$OSArchitecture,
		[Parameter(Mandatory = $true)][object]$ProcessArchitecture,
		[Parameter(Mandatory = $true)][object]$IsElevated
	)

	Assert-ExactBooleanValue $WindowsPlatform 'runner Windows fact'
	Assert-ExactStringValue $OSArchitecture 'runner OS architecture fact'
	Assert-ExactStringValue $ProcessArchitecture `
		'runner process architecture fact'
	Assert-ExactBooleanValue $IsElevated 'runner elevation fact'
	if (
		-not $WindowsPlatform -or
		$OSArchitecture -cne 'Arm64' -or
		$ProcessArchitecture -cne 'Arm64'
	) {
		throw 'The pinned SDK requires a native Windows ARM64 process'
	}
	if ($IsElevated) {
		throw 'The pinned SDK refuses an elevated runner token'
	}
}

function Test-TokenElevation {
	$token = [IntPtr]::Zero
	if (-not [GfwSdkBootstrapNativeMethods]::OpenProcessToken(
		[GfwSdkBootstrapNativeMethods]::GetCurrentProcess(),
		[GfwSdkBootstrapNativeMethods]::TokenQuery,
		[ref]$token
	)) {
		$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
		throw "Cannot inspect runner token elevation (Win32 error $errorCode)"
	}
	try {
		$elevation =
			[GfwSdkBootstrapNativeMethods+TokenElevationInfo]::new()
		$returnLength = 0
		$size = [Runtime.InteropServices.Marshal]::SizeOf($elevation)
		if (-not [GfwSdkBootstrapNativeMethods]::GetTokenInformation(
			$token,
			[GfwSdkBootstrapNativeMethods]::TokenElevation,
			[ref]$elevation,
			$size,
			[ref]$returnLength
		)) {
			$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
			throw "Cannot inspect runner token elevation (Win32 error $errorCode)"
		}
		return $elevation.TokenIsElevated -ne 0
	} finally {
		if (
			$token -ne [IntPtr]::Zero -and
			-not [GfwSdkBootstrapNativeMethods]::CloseHandle($token)
		) {
			$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
			throw "Cannot close runner token handle (Win32 error $errorCode)"
		}
	}
}

function Assert-NativeRunnerPolicy {
	param(
		[Parameter(Mandatory = $true)][object]$RunnerOs,
		[Parameter(Mandatory = $true)][object]$RunnerArch,
		[Parameter(Mandatory = $true)][object]$RunnerEnvironment
	)

	Assert-ExactStringValue $RunnerOs 'runner.os'
	Assert-ExactStringValue $RunnerArch 'runner.arch'
	Assert-ExactStringValue $RunnerEnvironment 'runner.environment'
	if (
		$RunnerOs -cne 'Windows' -or
		$RunnerArch -cne 'ARM64' -or
		$RunnerEnvironment -cne 'github-hosted'
	) {
		throw 'The pinned SDK requires an ephemeral GitHub-hosted ARM64 runner'
	}

	$windowsPlatform =
		[Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
		[Runtime.InteropServices.OSPlatform]::Windows)
	if (-not $windowsPlatform) {
		Assert-RunnerPlatformFacts $false `
			([Runtime.InteropServices.RuntimeInformation]::OSArchitecture).ToString() `
			([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture).ToString() `
			$false
	}
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [Security.Principal.WindowsPrincipal]::new($identity)
	$isElevated = $principal.IsInRole(
		[Security.Principal.WindowsBuiltInRole]::Administrator) -or
		(Test-TokenElevation)
	Assert-RunnerPlatformFacts `
		$windowsPlatform `
		([Runtime.InteropServices.RuntimeInformation]::OSArchitecture).ToString() `
		([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture).ToString() `
		$isElevated
}

function Assert-UsablePathLength {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][int]$ReservedChildLength,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($ReservedChildLength -lt 0) {
		throw "$Name cannot reserve a negative child length"
	}
	# Subtract rather than add so the comparison cannot overflow for a
	# hostile length, and so the reservation is expressed as headroom.
	$headroom = $script:MaxUsablePathLength - $Path.Length
	if ($headroom -lt $ReservedChildLength) {
		throw "$Name exceeds the usable Windows path length"
	}
}

function Assert-LocalPathSyntax {
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-ExactStringValue $Path $Name
	if (
		[string]::IsNullOrWhiteSpace($Path) -or
		-not [IO.Path]::IsPathFullyQualified($Path) -or
		$Path -notmatch '^[A-Za-z]:\\' -or
		$Path -match '^(\\\\[?.]\\|\\\?\?\\)' -or
		$Path.Contains('/') -or
		$Path.Substring(2).Contains(':') -or
		$Path -match '[*?]'
	) {
		throw "$Name must be a drive-qualified canonical local path"
	}

	$fullPath = [IO.Path]::GetFullPath($Path)
	$inputPath = $Path.TrimEnd('\')
	$canonicalPath = $fullPath.TrimEnd('\')
	if (
		-not [string]::Equals(
			$inputPath,
			$canonicalPath,
			[StringComparison]::OrdinalIgnoreCase
		)
	) {
		throw "$Name contains relative or noncanonical path components"
	}
	if ($canonicalPath.Length -le 3) {
		throw "$Name cannot be a drive root"
	}
	Assert-UsablePathLength $canonicalPath 0 $Name

	foreach ($segment in $canonicalPath.Substring(3).Split('\')) {
		if (
			$segment -match '^[^~\\]{1,6}~[0-9](?:\.[^.\\]{0,3})?$'
		) {
			throw "$Name contains a possible DOS short-name alias"
		}
	}

	$sharedRoot = 'C:\msys64'
	if (
		[string]::Equals(
			$canonicalPath,
			$sharedRoot,
			[StringComparison]::OrdinalIgnoreCase
		) -or
		$canonicalPath.StartsWith(
			"$sharedRoot\",
			[StringComparison]::OrdinalIgnoreCase
		)
	) {
		throw "$Name cannot use the shared C:\msys64 tree"
	}

	return $canonicalPath
}

function Get-LongPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	$buffer = [Text.StringBuilder]::new(32768)
	$length = [GfwSdkBootstrapNativeMethods]::GetLongPathName(
		$Path, $buffer, [uint32]$buffer.Capacity)
	if ($length -eq 0 -or $length -ge $buffer.Capacity) {
		$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
		throw "Cannot canonicalize path '$Path' (Win32 error $errorCode)"
	}
	return $buffer.ToString().TrimEnd('\')
}

function Assert-NoReparseAncestors {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$item = Get-Item -LiteralPath $Path -Force
	while ($null -ne $item) {
		if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw "$Name traverses a reparse point at '$($item.FullName)'"
		}
		if ($item -is [IO.FileInfo]) {
			$item = $item.Directory
		} else {
			$item = $item.Parent
		}
	}
}

function Assert-SafeExistingDirectory {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[string]$Name = 'path'
	)

	if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
		[Runtime.InteropServices.OSPlatform]::Windows
	)) {
		throw 'The ARM64 SDK bootstrap only supports Windows'
	}

	$canonicalPath = Assert-LocalPathSyntax $Path $Name
	$item = Get-Item -LiteralPath $canonicalPath -Force
	if (-not $item.PSIsContainer) {
		throw "$Name must identify an existing directory"
	}
	Assert-NoReparseAncestors $canonicalPath $Name

	$longPath = Get-LongPath $canonicalPath
	if (-not [string]::Equals(
		$canonicalPath,
		$longPath,
		[StringComparison]::OrdinalIgnoreCase
	)) {
		throw "$Name uses a path alias"
	}
	return $canonicalPath
}

function Assert-ContainedPath {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$Parent,
		[Parameter(Mandatory = $true)][object]$Child
	)

	Assert-ExactStringValue $Parent 'parent path'
	Assert-ExactStringValue $Child 'child path'
	$relative = [IO.Path]::GetRelativePath($Parent, $Child)
	if (
		$relative -eq '.' -or
		[IO.Path]::IsPathRooted($relative) -or
		$relative -eq '..' -or
		$relative.StartsWith('..\', [StringComparison]::Ordinal)
	) {
		throw "'$Child' is not a strict child of '$Parent'"
	}
}

function Assert-PrivateRootAcl {
	param([Parameter(Mandatory = $true)][object]$Path)

	Assert-ExactStringValue $Path 'SDK root'
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$actualAcl = Get-Acl -LiteralPath $Path
	$actualOwner = $actualAcl.GetOwner(
		[Security.Principal.SecurityIdentifier])
	if ($actualOwner.Value -cne $identity.User.Value) {
		throw 'The SDK root is not owned by the runner identity'
	}
	$accessRules = @($actualAcl.Access)
	if ($accessRules.Count -ne 1) {
		throw 'The SDK root ACL is not private to the runner identity'
	}
	foreach ($accessRule in $accessRules) {
		$ruleSid = $accessRule.IdentityReference.Translate(
			[Security.Principal.SecurityIdentifier])
		if (
			$accessRule.IsInherited -or
			$ruleSid.Value -cne $identity.User.Value -or
			$accessRule.AccessControlType -ne
				[Security.AccessControl.AccessControlType]::Allow -or
			-not $accessRule.FileSystemRights.HasFlag(
				[Security.AccessControl.FileSystemRights]::FullControl)
		) {
			throw 'The SDK root ACL is not private to the runner identity'
		}
	}
}

function New-PrivateSdkRoot {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$RunnerTemp,
		[Parameter(Mandatory = $true)][object]$RunId,
		[Parameter(Mandatory = $true)][object]$RunAttempt,
		[Parameter(Mandatory = $true)][object]$Job,
		[Parameter(Mandatory = $true)][object]$MatrixDiscriminator,
		[AllowNull()][object]$Nonce
	)

	foreach ($entry in @(
		[pscustomobject]@{ Value = $RunId; Name = 'run ID' },
		[pscustomobject]@{ Value = $RunAttempt; Name = 'run attempt' },
		[pscustomobject]@{ Value = $Job; Name = 'job' },
		[pscustomobject]@{
			Value = $MatrixDiscriminator
			Name = 'matrix discriminator'
		}
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	$runnerRoot = Assert-SafeExistingDirectory $RunnerTemp 'runner.temp'
	if ($RunId -notmatch '^[0-9]+$' -or $RunAttempt -notmatch '^[0-9]+$') {
		throw 'Run ID and run attempt must be decimal integers'
	}
	if (
		[string]::IsNullOrWhiteSpace($Job) -or
		$Job.Length -gt 1024 -or
		[string]::IsNullOrWhiteSpace($MatrixDiscriminator) -or
		$MatrixDiscriminator.Length -gt 16384
	) {
		throw 'Job and matrix discriminators must be nonempty and bounded'
	}

	$binding = "$RunId`0$RunAttempt`0$Job`0$MatrixDiscriminator"
	$bindingHash = Get-Sha256Hex $script:Utf8.GetBytes($binding)
	if ($null -eq $Nonce) {
		$Nonce = [Guid]::NewGuid().ToString('N')
	}
	Assert-HexString $Nonce 32 'root nonce'

	$leaf = "gfw-sdk-arm64-$RunId-$RunAttempt-$($bindingHash.Substring(0, 20))-$Nonce"
	$candidate = [IO.Path]::GetFullPath((Join-Path $runnerRoot $leaf))
	Assert-ContainedPath $runnerRoot $candidate
	# Reject the parent before creating anything beneath it. The ownership
	# sentinel is written directly inside the new root and every cleanup path
	# canonicalizes the root again, so a runner.temp that cannot hold both
	# would otherwise yield a root that can be created but never removed.
	Assert-UsablePathLength `
		$candidate ($script:RootSentinelName.Length + 1) 'runner.temp'
	if (Test-Path -LiteralPath $candidate) {
		throw 'The unique SDK root already exists'
	}

	$sentinelValue = "gfw-sdk-arm64-root-v1`n$bindingHash`n$Nonce`n"
	$sentinelPath = Join-Path $candidate $script:RootSentinelName
	$item = [IO.Directory]::CreateDirectory($candidate)
	try {
		if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw 'The newly created SDK root is a reparse point'
		}

		$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
		$security = [Security.AccessControl.DirectorySecurity]::new()
		$security.SetAccessRuleProtection($true, $false)
		$security.SetOwner($identity.User)
		$inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
			-bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
		$rule = [Security.AccessControl.FileSystemAccessRule]::new(
			$identity.User,
			[Security.AccessControl.FileSystemRights]::FullControl,
			$inheritance,
			[Security.AccessControl.PropagationFlags]::None,
			[Security.AccessControl.AccessControlType]::Allow)
		[void]$security.AddAccessRule($rule)
		Set-Acl -LiteralPath $candidate -AclObject $security
		[IO.File]::WriteAllText(
			$sentinelPath,
			$sentinelValue,
			[Text.UTF8Encoding]::new($false))

		Assert-NoReparseAncestors $candidate 'SDK root'
		$longPath = Get-LongPath $candidate
		if (-not [string]::Equals(
			$candidate,
			$longPath,
			[StringComparison]::OrdinalIgnoreCase
		)) {
			throw 'The SDK root resolved through a path alias'
		}
		Assert-PrivateRootAcl $candidate
		$script:PrivateTempPath = $candidate
		return [pscustomobject][ordered]@{
			Path = $candidate
			RunnerRoot = $runnerRoot
			SentinelValue = $sentinelValue
		}
	} catch {
		$initializationError = $_.Exception.Message
		try {
			if (Test-Path -LiteralPath $sentinelPath) {
				Remove-OwnedSdkRoot ([pscustomobject][ordered]@{
					Path = $candidate
					RunnerRoot = $runnerRoot
					SentinelValue = $sentinelValue
				})
			} else {
				$createdItem = Get-Item -LiteralPath $candidate -Force
				if (
					-not $createdItem.PSIsContainer -or
					($createdItem.Attributes -band
						[IO.FileAttributes]::ReparsePoint)
				) {
					throw 'Created root changed type during initialization'
				}
				Assert-PrivateRootAcl $candidate
				if (@(Get-ChildItem -LiteralPath $candidate -Force).Count -ne 0) {
					throw 'Created root is not empty during initialization cleanup'
				}
				Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
			}
		} catch {
			throw "$initializationError; SDK root cleanup also failed: $($_.Exception.Message)"
		}
		throw $initializationError
	}
}

function Remove-OwnedSdkRoot {
	param([Parameter(Mandatory = $true)][object]$OwnedRoot)

	Assert-ExactProperties $OwnedRoot @(
		'Path',
		'RunnerRoot',
		'SentinelValue'
	) 'owned SDK root'
	Assert-ExactStringValue $OwnedRoot.Path 'owned SDK root path'
	Assert-ExactStringValue $OwnedRoot.RunnerRoot 'owned SDK runner root'
	Assert-ExactStringValue $OwnedRoot.SentinelValue 'owned SDK root sentinel'
	$runnerRoot = Assert-SafeExistingDirectory `
		$OwnedRoot.RunnerRoot 'runner.temp'
	$root = Assert-SafeExistingDirectory $OwnedRoot.Path 'SDK root'
	Assert-ContainedPath $runnerRoot $root
	Assert-PrivateRootAcl $root
	foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force) {
		if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw "SDK root cleanup encountered a reparse point at '$($item.FullName)'"
		}
	}
	$sentinelPath = Join-Path $root $script:RootSentinelName
	$sentinel = Get-Item -LiteralPath $sentinelPath -Force
	if (
		$sentinel.PSIsContainer -or
		($sentinel.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
		[IO.File]::ReadAllText($sentinel.FullName, $script:Utf8) -cne
			$OwnedRoot.SentinelValue
	) {
		throw 'SDK root cleanup sentinel does not match'
	}
	Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
	if (Test-Path -LiteralPath $root) {
		throw 'SDK root cleanup did not remove the owned root'
	}
}

function Assert-CanonicalGitPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	if (
		[string]::IsNullOrEmpty($Path) -or
		$Path -cne $Path.Normalize([Text.NormalizationForm]::FormC) -or
		$Path.StartsWith('/', [StringComparison]::Ordinal) -or
		$Path.EndsWith('/', [StringComparison]::Ordinal) -or
		$Path.Contains('//') -or
		$Path.Contains('\') -or
		$Path -cmatch '[^\x20-\x7e]'
	) {
		throw "Noncanonical Git path '$Path'"
	}

	$segments = $Path.Split('/')
	foreach ($segment in $segments) {
		if (
			$segment -in '.', '..' -or
			$segment.Length -gt 255 -or
			$segment -match '[<>:"|?*]' -or
			$segment.EndsWith('.', [StringComparison]::Ordinal) -or
			$segment.EndsWith(' ', [StringComparison]::Ordinal) -or
			$segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$' -or
			$segment -ieq '.git'
		) {
			throw "Windows-unsafe Git path '$Path'"
		}
		foreach ($character in $segment.ToCharArray()) {
			if ([char]::IsControl($character)) {
				throw "Control character in Git path '$Path'"
			}
		}
	}
	if ($segments[-1] -ieq '.gitmodules') {
		throw "Git submodule metadata is forbidden at '$Path'"
	}
}

function ConvertTo-CanonicalGitPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	$bytes = $script:Utf8.GetBytes($Path)
	$builder = [Text.StringBuilder]::new($bytes.Length)
	foreach ($byte in $bytes) {
		if (
			($byte -ge 0x41 -and $byte -le 0x5a) -or
			($byte -ge 0x61 -and $byte -le 0x7a) -or
			($byte -ge 0x30 -and $byte -le 0x39) -or
			$byte -in 0x2d, 0x2e, 0x2f, 0x5f, 0x7e
		) {
			[void]$builder.Append([char]$byte)
		} else {
			[void]$builder.AppendFormat('%{0:X2}', $byte)
		}
	}
	return $builder.ToString()
}

function Get-TreeManifestFromBytes {
	[CmdletBinding()]
	param([Parameter(Mandatory = $true)][byte[]]$Bytes)

	if ($Bytes.LongLength -gt 67108864) {
		throw 'The Git tree record stream is unexpectedly large'
	}
	$text = $script:Utf8.GetString($Bytes)
	$records = $text.Split(
		@([char]0),
		[StringSplitOptions]::None)
	if ($records.Count -lt 2 -or $records[-1] -cne '') {
		throw 'The Git tree record stream is truncated'
	}

	$manifestHash = [Security.Cryptography.IncrementalHash]::CreateHash(
		[Security.Cryptography.HashAlgorithmName]::SHA256)
	$packageHash = [Security.Cryptography.IncrementalHash]::CreateHash(
		[Security.Cryptography.HashAlgorithmName]::SHA256)
	$exactPaths = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	$foldedPaths = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::OrdinalIgnoreCase)
	$entryCount = 0L
	$blobCount = 0L
	$treeCount = 0L
	$totalBlobBytes = [uint64]0
	$packageEntryCount = 0L
	$packageBlobCount = 0L
	$packageTreeCount = 0L
	$packageBlobBytes = [uint64]0
	$entries = [Collections.Generic.List[object]]::new()

	try {
		for ($index = 0; $index -lt $records.Count - 1; $index++) {
			if ($entryCount -ge 100000L) {
				throw 'The Git tree contains too many entries'
			}
			$fields = $records[$index].Split(
				@([char]9),
				5,
				[StringSplitOptions]::None)
			if ($fields.Count -ne 5) {
				throw 'Malformed Git tree record'
			}
			$mode, $type, $oid, $size, $path = $fields
			Assert-HexString $oid 40 "object ID for '$path'"
			Assert-CanonicalGitPath $path
			if ($path.Length -gt 32760) {
				throw "Git path is too long at '$path'"
			}

			if (-not $exactPaths.Add($path)) {
				throw "Duplicate Git path '$path'"
			}
			if (-not $foldedPaths.Add($path)) {
				throw "Case-colliding Git path '$path'"
			}

			switch ("$mode $type") {
				'040000 tree' {
					if ($size -cne '-') {
						throw "Unexpected tree object size for '$path'"
					}
					$canonicalSize = '-'
					$treeCount++
				}
				'100644 blob' {
					$canonicalSize = $size
					$blobCount++
				}
				'100755 blob' {
					$canonicalSize = $size
					$blobCount++
				}
				'120000 blob' {
					throw "Symbolic link indirection is forbidden at '$path'"
				}
				'160000 commit' {
					throw "Git submodule indirection is forbidden at '$path'"
				}
				default {
					throw "Unexpected Git mode/type '$mode $type' at '$path'"
				}
			}

			if ($type -eq 'blob') {
				$blobSize = [uint64]0
				if (-not [uint64]::TryParse(
					$size,
					[Globalization.NumberStyles]::None,
					[Globalization.CultureInfo]::InvariantCulture,
					[ref]$blobSize
				)) {
					throw "Missing authoritative blob size for '$path'"
				}
				if (
					$blobSize -gt 5368709120L -or
					$totalBlobBytes -gt 5368709120L - $blobSize
				) {
					throw 'The Git tree exceeds the materialization byte limit'
				}
				$totalBlobBytes += $blobSize
			}

			$canonicalPath = ConvertTo-CanonicalGitPath $path
			$line = "$mode`t$type`t$oid`t$canonicalSize`t$canonicalPath`n"
			$lineBytes = $script:Utf8.GetBytes($line)
			$manifestHash.AppendData($lineBytes)
			$entries.Add([pscustomobject][ordered]@{
				Mode = $mode
				Type = $type
				Oid = $oid
				Size = if ($type -ceq 'blob') {
					[uint64]$blobSize
				} else {
					$null
				}
				Path = $path
			})
			$entryCount++

			$isPackageDatabase = (
				$path -ceq 'var/lib/pacman/local' -or
				$path.StartsWith(
					'var/lib/pacman/local/',
					[StringComparison]::Ordinal
				) -or
				$path -ceq 'var/lib/pacman/sync' -or
				$path.StartsWith(
					'var/lib/pacman/sync/',
					[StringComparison]::Ordinal
				)
			)
			if ($isPackageDatabase) {
				$packageHash.AppendData($lineBytes)
				$packageEntryCount++
				if ($type -eq 'blob') {
					$packageBlobCount++
					$packageBlobBytes += $blobSize
				} else {
					$packageTreeCount++
				}
			}
		}

		return [pscustomobject]@{
			Sha256 = [Convert]::ToHexString(
				$manifestHash.GetHashAndReset()).ToLowerInvariant()
			EntryCount = $entryCount
			BlobCount = $blobCount
			TreeCount = $treeCount
			TotalBlobBytes = [string]$totalBlobBytes
			PackageDatabaseSha256 = [Convert]::ToHexString(
				$packageHash.GetHashAndReset()).ToLowerInvariant()
			PackageDatabaseEntryCount = $packageEntryCount
			PackageDatabaseBlobCount = $packageBlobCount
			PackageDatabaseTreeCount = $packageTreeCount
			PackageDatabaseTotalBlobBytes = [string]$packageBlobBytes
			Entries = [object[]]$entries.ToArray()
		}
	} finally {
		$manifestHash.Dispose()
		$packageHash.Dispose()
	}
}

function New-SafeGitProcess {
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string[]]$Arguments,
		[int[]]$AllowedExitCodes = @(0)
	)

	$info = [Diagnostics.ProcessStartInfo]::new()
	$info.FileName = $GitPath
	$info.UseShellExecute = $false
	$info.RedirectStandardOutput = $true
	$info.RedirectStandardError = $true
	$info.StandardOutputEncoding = $script:Utf8
	$info.StandardErrorEncoding = $script:Utf8
	$info.CreateNoWindow = $true
	$systemDirectory = [Environment]::GetFolderPath(
		[Environment+SpecialFolder]::System)
	$windowsDirectory = [Environment]::GetFolderPath(
		[Environment+SpecialFolder]::Windows)
	$info.WorkingDirectory = $systemDirectory

	foreach ($argument in @(
		'--no-pager',
		'--no-replace-objects',
		'-c', 'core.hooksPath=NUL',
		'-c', 'credential.helper=',
		'-c', 'core.askPass=',
		'-c', 'credential.interactive=never',
		'-c', 'protocol.file.allow=never',
		'-c', 'protocol.ext.allow=never',
		'-c', 'submodule.recurse=false',
		'-c', 'maintenance.auto=false',
		'-c', 'gc.auto=0'
	) + $Arguments) {
		[void]$info.ArgumentList.Add($argument)
	}

	$info.Environment.Clear()
	$info.Environment['SystemRoot'] = $windowsDirectory
	$info.Environment['windir'] = $windowsDirectory
	$info.Environment['ComSpec'] = Join-Path $systemDirectory 'cmd.exe'
	$info.Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
	$info.Environment['PATH'] = if ($null -ne $script:TrustedGitRuntimePath) {
		$script:TrustedGitRuntimePath
	} else {
		"$systemDirectory;$windowsDirectory"
	}
	$privateTemp = if ($null -ne $script:PrivateTempPath) {
		$script:PrivateTempPath
	} else {
		[IO.Path]::GetTempPath()
	}
	$info.Environment['TEMP'] = $privateTemp
	$info.Environment['TMP'] = $privateTemp
	$info.Environment['TMPDIR'] = $privateTemp
	$info.Environment['LANG'] = 'C'
	$info.Environment['LC_ALL'] = 'C'
	$info.Environment['GIT_CONFIG_NOSYSTEM'] = '1'
	$info.Environment['GIT_CONFIG_GLOBAL'] = 'NUL'
	$info.Environment['GIT_TERMINAL_PROMPT'] = '0'
	$info.Environment['GCM_INTERACTIVE'] = 'Never'
	$info.Environment['GIT_ATTR_NOSYSTEM'] = '1'
	$info.Environment['GIT_LFS_SKIP_SMUDGE'] = '1'
	$info.Environment['GIT_OPTIONAL_LOCKS'] = '0'
	if ($null -ne $script:TrustedGitExecPath) {
		$info.Environment['GIT_EXEC_PATH'] = $script:TrustedGitExecPath
	}

	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $info
	$output = [IO.MemoryStream]::new()
	try {
		if (-not $process.Start()) {
			throw 'Could not start Git'
		}
		$stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($output)
		$stderrTask = $process.StandardError.ReadToEndAsync()
		$process.WaitForExit()
		[void]$stdoutTask.GetAwaiter().GetResult()
		$stderr = $stderrTask.GetAwaiter().GetResult()
		if ($process.ExitCode -notin $AllowedExitCodes) {
			$displayArguments = $Arguments -join ' '
			throw "Git failed ($($process.ExitCode)): git $displayArguments`n$($stderr.Trim())"
		}
		return [pscustomobject]@{
			ExitCode = $process.ExitCode
			Stdout = $output.ToArray()
			Stderr = $stderr
		}
	} finally {
		$output.Dispose()
		$process.Dispose()
	}
}

function Get-GitText {
	param([Parameter(Mandatory = $true)][object]$Result)

	return $script:Utf8.GetString([byte[]]$Result.Stdout)
}

function Assert-ProtectedInstallationPath {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$InstallationRoot,
		[Parameter(Mandatory = $true)][string]$Name
	)

	Assert-NoReparseAncestors $Path $Name
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$untrustedSids = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	foreach ($sid in @(
		$identity.User.Value,
		'S-1-1-0',
		'S-1-5-4',
		'S-1-5-11',
		'S-1-5-32-545',
		'S-1-5-32-546'
	)) {
		[void]$untrustedSids.Add($sid)
	}
	$principal = [Security.Principal.WindowsPrincipal]::new($identity)
	foreach ($group in $identity.Groups) {
		if ($principal.IsInRole($group)) {
			[void]$untrustedSids.Add($group.Value)
		}
	}
	[long]$writeRights = (
		[long][Security.AccessControl.FileSystemRights]::WriteData -bor
		[long][Security.AccessControl.FileSystemRights]::AppendData -bor
		[long][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
		[long][Security.AccessControl.FileSystemRights]::WriteAttributes -bor
		[long][Security.AccessControl.FileSystemRights]::Delete -bor
		[long][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
		[long][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
		[long][Security.AccessControl.FileSystemRights]::TakeOwnership -bor
		0x10000000 -bor
		0x40000000
	)

	$item = Get-Item -LiteralPath $Path -Force
	while ($null -ne $item) {
		$acl = Get-Acl -LiteralPath $item.FullName
		$owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
		if ($untrustedSids.Contains($owner.Value)) {
			throw "$Name is owned by the runner token at '$($item.FullName)'"
		}
		foreach ($rule in $acl.Access) {
			if ($rule.AccessControlType -ne
				[Security.AccessControl.AccessControlType]::Allow) {
				continue
			}
			$sid = $null
			try {
				$sid = $rule.IdentityReference.Translate(
					[Security.Principal.SecurityIdentifier])
			} catch [System.Security.Principal.IdentityNotMappedException] {
				if (([long]$rule.FileSystemRights -band $writeRights) -ne 0) {
					throw "$Name has an unresolved writable ACL at '$($item.FullName)'"
				}
				continue
			}
			if (
				$untrustedSids.Contains($sid.Value) -and
				(([long]$rule.FileSystemRights -band $writeRights) -ne 0)
			) {
				throw "$Name is writable by an untrusted identity at '$($item.FullName)'"
			}
		}
		if ([string]::Equals(
			$item.FullName.TrimEnd('\'),
			$InstallationRoot.TrimEnd('\'),
			[StringComparison]::OrdinalIgnoreCase
		)) {
			return
		}
		if ($item -is [IO.FileInfo]) {
			$item = $item.Directory
		} else {
			$item = $item.Parent
		}
	}
	throw "$Name escaped the protected Git installation root"
}

function Assert-GitAuthenticodeSignature {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$signature = Get-AuthenticodeSignature -LiteralPath $Path
	if (
		$signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
		$null -eq $signature.SignerCertificate -or
		$signature.SignerCertificate.Subject -cne
			'CN=Johannes Schindelin, O=Johannes Schindelin, L=Bruehl, C=DE'
	) {
		throw "$Name does not have the expected valid Git for Windows signature"
	}
}

function Get-SystemGitPath {
	param([Parameter(Mandatory = $true)][string]$RunnerTemp)

	$programFiles = [Environment]::GetFolderPath(
		[Environment+SpecialFolder]::ProgramFiles)
	$installRoot = Join-Path $programFiles 'Git'
	$gitPath = Join-Path $installRoot 'cmd\git.exe'
	$gitPath = Assert-LocalPathSyntax $gitPath 'system Git'
	if (-not (Test-Path -LiteralPath $gitPath -PathType Leaf)) {
		throw 'The protected system Git executable does not exist'
	}
	$installRoot = Assert-SafeExistingDirectory $installRoot `
		'Git installation root'
	Assert-ContainedPath $installRoot $gitPath
	Assert-ProtectedInstallationPath $gitPath $installRoot 'system Git'
	$longPath = Get-LongPath $gitPath
	if (-not [string]::Equals(
		$gitPath,
		$longPath,
		[StringComparison]::OrdinalIgnoreCase
	)) {
		throw 'The system Git executable uses a path alias'
	}
	Assert-GitAuthenticodeSignature $gitPath 'system Git'
	$relative = [IO.Path]::GetRelativePath($RunnerTemp, $gitPath)
	if (
		$relative -eq '.' -or
		(-not [IO.Path]::IsPathRooted($relative) -and
			$relative -ne '..' -and
			-not $relative.StartsWith('..\', [StringComparison]::Ordinal))
	) {
		throw 'System Git cannot come from runner.temp'
	}

	$execPathResult = New-SafeGitProcess $gitPath @('--exec-path')
	$execPathText = (Get-GitText $execPathResult).Trim().Replace('/', '\')
	$execPath = Assert-SafeExistingDirectory $execPathText 'Git exec path'
	Assert-ContainedPath $installRoot $execPath
	Assert-ProtectedInstallationPath $execPath $installRoot 'Git exec path'

	$httpsHelper = Join-Path $execPath 'git-remote-https.exe'
	if (-not (Test-Path -LiteralPath $httpsHelper -PathType Leaf)) {
		throw 'The protected Git HTTPS helper does not exist'
	}
	Assert-ContainedPath $installRoot $httpsHelper
	Assert-ProtectedInstallationPath $httpsHelper $installRoot 'Git HTTPS helper'
	Assert-GitAuthenticodeSignature $httpsHelper 'Git HTTPS helper'

	$runtimeDirectories = [Collections.Generic.List[string]]::new()
	foreach ($candidate in @(
		(Join-Path $installRoot 'cmd'),
		(Join-Path $installRoot 'mingw64\bin'),
		(Join-Path $installRoot 'clangarm64\bin')
	)) {
		if (Test-Path -LiteralPath $candidate -PathType Container) {
			$runtimeDirectory = Assert-SafeExistingDirectory `
				$candidate 'Git runtime directory'
			Assert-ContainedPath $installRoot $runtimeDirectory
			Assert-ProtectedInstallationPath `
				$runtimeDirectory $installRoot 'Git runtime directory'
			$runtimeDirectories.Add($runtimeDirectory)
		}
	}
	if ($runtimeDirectories.Count -lt 2) {
		throw 'The protected Git runtime directories are incomplete'
	}
	$systemDirectory = [Environment]::GetFolderPath(
		[Environment+SpecialFolder]::System)
	$windowsDirectory = [Environment]::GetFolderPath(
		[Environment+SpecialFolder]::Windows)
	$script:TrustedGitRuntimePath = (
		@($runtimeDirectories) + $systemDirectory + $windowsDirectory
	) -join ';'
	$script:TrustedGitExecPath = $execPath
	return $gitPath
}

function Assert-LockedRefs {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][string]$Commit
	)

	$result = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'for-each-ref',
		'--format=%(objectname)%09%(refname)'
	)
	$lines = @((Get-GitText $result) -split "`r?`n" |
		Where-Object { $_ -cne '' })
	if (
		$lines.Count -ne 1 -or
		$lines[0] -cne "$Commit`trefs/gfw-sdk/locked"
	) {
		throw 'The SDK repository contains an unexpected or mutable ref'
	}
}

function Assert-GitObjectIdentity {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][object]$Lock
	)

	Assert-LockedRefs $GitPath $GitDir $Lock.commit

	$commit = (Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'rev-parse',
		'--verify',
		'refs/gfw-sdk/locked^{commit}'
	))).Trim()
	if ($commit -cne $Lock.commit) {
		throw 'Fetched commit does not match the lock'
	}
	$tree = (Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'rev-parse',
		'--verify',
		'refs/gfw-sdk/locked^{tree}'
	))).Trim()
	if ($tree -cne $Lock.tree) {
		throw 'Fetched tree does not match the lock'
	}

	$commitText = Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'cat-file',
		'commit',
		$Lock.commit
	))
	$parts = $commitText -split "`n`n", 2
	if ($parts.Count -ne 2) {
		throw 'Malformed commit object'
	}
	$headers = @($parts[0] -split "`n")
	if (
		$headers.Count -ne 4 -or
		$headers[0] -cne "tree $($Lock.tree)" -or
		$headers[1] -cne "parent $($Lock.parent)" -or
		$headers[2] -cne "author $($Lock.commit_metadata.author)" -or
		$headers[3] -cne "committer $($Lock.commit_metadata.committer)" -or
		$parts[1].Split("`n")[0] -cne $Lock.commit_metadata.subject
	) {
		throw 'Commit object metadata does not match the lock'
	}

	[void](New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'fsck',
		'--strict',
		'--full',
		'--no-reflogs'
	))
	$missing = Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'rev-list',
		'--objects',
		'--missing=print',
		'refs/gfw-sdk/locked'
	))
	if ($missing -match '(?m)^\?') {
		throw 'The fetched snapshot is missing Git objects'
	}

	if (
		(Test-Path -LiteralPath (Join-Path $GitDir 'objects\info\alternates')) -or
		@(Get-ChildItem -LiteralPath (Join-Path $GitDir 'objects\pack') `
			-Filter '*.promisor' -Force).Count -ne 0
	) {
		throw 'Alternate or partial Git object storage is forbidden'
	}
	$partialClone = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'config',
		'--local',
		'--get-regexp',
		'^(extensions\.partialClone|remote\..*\.promisor)$'
	) @(0, 1)
	if ($partialClone.ExitCode -eq 0) {
		throw 'Partial clone configuration is forbidden'
	}
}

function Get-GitTreeManifest {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][string]$Commit
	)

	$result = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'ls-tree',
		'-r',
		'-t',
		'-z',
		'--full-tree',
		'--format=%(objectmode)%x09%(objecttype)%x09%(objectname)%x09%(objectsize)%x09%(path)',
		$Commit
	)
	return Get-TreeManifestFromBytes $result.Stdout
}

function Assert-ManifestMatchesLock {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$Manifest,
		[Parameter(Mandatory = $true)][object]$Lock
	)

	if (
		$Manifest.Sha256 -cne $Lock.manifest.sha256 -or
		$Manifest.EntryCount -ne $Lock.manifest.entry_count -or
		$Manifest.BlobCount -ne $Lock.manifest.blob_count -or
		$Manifest.TreeCount -ne $Lock.manifest.tree_count -or
		$Manifest.TotalBlobBytes -cne $Lock.manifest.total_blob_bytes
	) {
		throw 'The complete Git tree manifest does not match the lock'
	}
	if (
		$Manifest.PackageDatabaseSha256 -cne
			$Lock.package_database.sha256 -or
		$Manifest.PackageDatabaseEntryCount -ne
			$Lock.package_database.entry_count -or
		$Manifest.PackageDatabaseBlobCount -ne
			$Lock.package_database.blob_count -or
		$Manifest.PackageDatabaseTreeCount -ne
			$Lock.package_database.tree_count -or
		$Manifest.PackageDatabaseTotalBlobBytes -cne
			$Lock.package_database.total_blob_bytes
	) {
		throw 'The package database metadata does not match the lock'
	}
}

function Assert-NoLfsPointers {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][string]$Commit
	)

	$result = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'grep',
		'-I',
		'-l',
		'-z',
		'-e',
		'^version https://git-lfs.github.com/spec/v1',
		$Commit,
		'--'
	) @(0, 1)
	if ($result.ExitCode -eq 0 -or $result.Stdout.Count -ne 0) {
		throw 'Git LFS pointer indirection is forbidden'
	}
}

function Assert-RepositoryOrigin {
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][string]$RemoteUrl
	)

	$remotes = @((Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'remote'
	))) -split "`r?`n" | Where-Object { $_ -cne '' })
	$urls = @((Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'remote',
		'get-url',
		'--all',
		'origin'
	))) -split "`r?`n" | Where-Object { $_ -cne '' })
	$config = @((Get-GitText (New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		'config',
		'--local',
		'--get-regexp',
		'^remote\.'
	))) -split "`r?`n" | Where-Object { $_ -cne '' })
	if (
		$remotes.Count -ne 1 -or $remotes[0] -cne 'origin' -or
		$urls.Count -ne 1 -or $urls[0] -cne $RemoteUrl -or
		$config.Count -ne 1 -or
		$config[0] -cne "remote.origin.url $RemoteUrl"
	) {
		throw 'Unexpected SDK repository host, URL, or fetch configuration'
	}
}

function Assert-SafeCommandFile {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$RunnerTemp,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$canonicalPath = Assert-LocalPathSyntax $Path $Name
	Assert-ContainedPath $RunnerTemp $canonicalPath
	$item = Get-Item -LiteralPath $canonicalPath -Force
	if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
		throw "$Name must be a regular, non-reparse file"
	}
	Assert-NoReparseAncestors $canonicalPath $Name
	$longPath = Get-LongPath $canonicalPath
	if (-not [string]::Equals(
		$canonicalPath,
		$longPath,
		[StringComparison]::OrdinalIgnoreCase
	)) {
		throw "$Name uses a path alias"
	}
	return $canonicalPath
}

function Add-GitHubCommandValue {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Value
	)

	if ($Value.Contains("`r") -or $Value.Contains("`n")) {
		throw 'GitHub command values cannot contain line breaks'
	}
	[IO.File]::AppendAllText($Path, "$Value`n", [Text.UTF8Encoding]::new($false))
}

function Get-GitBlobHash {
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[Parameter(Mandatory = $true)][object]$ExpectedSize,
		[AllowEmptyCollection()]
		[Parameter(Mandatory = $true)]
		[Collections.Generic.HashSet[string]]$FileIdentities
	)

	Assert-ExactStringValue $Path 'materialized file path'
	if (
		$null -eq $ExpectedSize -or
		$ExpectedSize.GetType() -ne [uint64]
	) {
		throw 'Expected materialized file size must be an unsigned integer'
	}
	$stream = [IO.FileStream]::new(
		$Path,
		[IO.FileMode]::Open,
		[IO.FileAccess]::Read,
		[IO.FileShare]::Read,
		1048576,
		[IO.FileOptions]::SequentialScan)
	$hash = [Security.Cryptography.IncrementalHash]::CreateHash(
		[Security.Cryptography.HashAlgorithmName]::SHA1)
	$buffer = [Buffers.ArrayPool[byte]]::Shared.Rent(1048576)
	try {
		if ([uint64]$stream.Length -ne $ExpectedSize) {
			throw "Materialized file size differs at '$Path'"
		}
		$information =
			[GfwSdkBootstrapNativeMethods+ByHandleFileInformation]::new()
		if (-not [GfwSdkBootstrapNativeMethods]::GetFileInformationByHandle(
			$stream.SafeFileHandle,
			[ref]$information
		)) {
			$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
			throw "Cannot inspect materialized file '$Path' (Win32 error $errorCode)"
		}
		if ($information.NumberOfLinks -ne 1) {
			throw "Materialized file is a hardlink alias at '$Path'"
		}
		$fileIdentity = '{0:x8}:{1:x8}:{2:x8}' -f
			$information.VolumeSerialNumber,
			$information.FileIndexHigh,
			$information.FileIndexLow
		if (-not $FileIdentities.Add($fileIdentity)) {
			throw "Materialized files alias the same file at '$Path'"
		}

		$header = [Text.Encoding]::ASCII.GetBytes(
			"blob $ExpectedSize`0")
		$hash.AppendData($header)
		while (($read = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
			$hash.AppendData($buffer, 0, $read)
		}
		if ([uint64]$stream.Position -ne $ExpectedSize) {
			throw "Materialized file changed while hashing at '$Path'"
		}
		return [Convert]::ToHexString(
			$hash.GetHashAndReset()).ToLowerInvariant()
	} finally {
		[Buffers.ArrayPool[byte]]::Shared.Return($buffer, $true)
		$hash.Dispose()
		$stream.Dispose()
	}
}

function Assert-MaterializedSdkIndex {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$SdkRoot,
		[Parameter(Mandatory = $true)]
		[Collections.Generic.Dictionary[string, object]]$ExpectedBlobs
	)

	foreach ($entry in @(
		[pscustomobject]@{ Value = $GitPath; Name = 'Git path' },
		[pscustomobject]@{ Value = $GitDir; Name = 'Git directory' },
		[pscustomobject]@{ Value = $SdkRoot; Name = 'SDK root' }
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	$result = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		"--work-tree=$SdkRoot",
		'ls-files',
		'--stage',
		'-z'
	)
	$text = $script:Utf8.GetString($result.Stdout)
	$records = $text.Split(@([char]0), [StringSplitOptions]::None)
	if ($records.Count -lt 2 -or $records[-1] -cne '') {
		throw 'The materialized SDK index record stream is truncated'
	}
	$seen = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	for ($index = 0; $index -lt $records.Count - 1; $index++) {
		$match = [regex]::Match(
			$records[$index],
			'^(100644|100755) ([0-9a-f]{40}) 0\t(.+)$',
			[Text.RegularExpressions.RegexOptions]::CultureInvariant)
		if (-not $match.Success) {
			throw 'The materialized SDK index contains a malformed entry'
		}
		$mode = $match.Groups[1].Value
		$oid = $match.Groups[2].Value
		$path = $match.Groups[3].Value
		Assert-CanonicalGitPath $path
		if (-not $seen.Add($path)) {
			throw "The materialized SDK index duplicates '$path'"
		}
		$expected = $null
		if (-not $ExpectedBlobs.TryGetValue($path, [ref]$expected)) {
			throw "The materialized SDK index contains extra path '$path'"
		}
		if ($mode -cne $expected.Mode -or $oid -cne $expected.Oid) {
			throw "The materialized SDK index differs at '$path'"
		}
	}
	if ($seen.Count -ne $ExpectedBlobs.Count) {
		throw 'The materialized SDK index is missing locked paths'
	}

	$flagResult = New-SafeGitProcess $GitPath @(
		"--git-dir=$GitDir",
		"--work-tree=$SdkRoot",
		'ls-files',
		'-v',
		'-z'
	)
	$flagText = $script:Utf8.GetString($flagResult.Stdout)
	$flagRecords = $flagText.Split(
		@([char]0),
		[StringSplitOptions]::None)
	if (
		$flagRecords.Count -ne $ExpectedBlobs.Count + 1 -or
		$flagRecords[-1] -cne ''
	) {
		throw 'The materialized SDK index flags are incomplete'
	}
	foreach ($record in $flagRecords[0..($flagRecords.Count - 2)]) {
		if (
			-not $record.StartsWith('H ', [StringComparison]::Ordinal) -or
			-not $ExpectedBlobs.ContainsKey($record.Substring(2))
		) {
			throw 'The materialized SDK index contains unexpected flags'
		}
	}
}

function Assert-MaterializedSdkTree {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$SdkRoot,
		[Parameter(Mandatory = $true)][object]$Manifest
	)

	foreach ($entry in @(
		[pscustomobject]@{ Value = $GitPath; Name = 'Git path' },
		[pscustomobject]@{ Value = $GitDir; Name = 'Git directory' },
		[pscustomobject]@{ Value = $SdkRoot; Name = 'SDK root' }
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	if (
		$null -eq $Manifest -or
		$Manifest.GetType() -ne [Management.Automation.PSCustomObject] -or
		$null -eq $Manifest.Entries -or
		$Manifest.Entries.GetType() -ne [object[]]
	) {
		throw 'The verified manifest does not contain exact tree entries'
	}
	if (
		$Manifest.Entries.Count -gt 100000 -or
		$Manifest.EntryCount -ne [long]$Manifest.Entries.Count -or
		[uint64]$Manifest.TotalBlobBytes -gt 5368709120L
	) {
		throw 'The verified manifest exceeds materialization bounds'
	}

	$expectedBlobs =
		[Collections.Generic.Dictionary[string, object]]::new(
			[StringComparer]::Ordinal)
	$expectedTrees =
		[Collections.Generic.HashSet[string]]::new(
			[StringComparer]::Ordinal)
	foreach ($entry in $Manifest.Entries) {
		Assert-ExactProperties $entry @(
			'Mode',
			'Type',
			'Oid',
			'Size',
			'Path'
		) 'manifest entry'
		foreach ($property in 'Mode', 'Type', 'Oid', 'Path') {
			Assert-ExactStringValue $entry.$property "manifest entry $property"
		}
		Assert-CanonicalGitPath $entry.Path
		if ($entry.Type -ceq 'blob') {
			if (
				$entry.Size.GetType() -ne [uint64] -or
				-not $expectedBlobs.TryAdd($entry.Path, $entry)
			) {
				throw "Invalid locked blob entry '$($entry.Path)'"
			}
		} elseif ($entry.Type -ceq 'tree') {
			if ($null -ne $entry.Size -or -not $expectedTrees.Add($entry.Path)) {
				throw "Invalid locked tree entry '$($entry.Path)'"
			}
		} else {
			throw "Unexpected locked entry type '$($entry.Type)'"
		}
	}
	Assert-MaterializedSdkIndex `
		$GitPath $GitDir $SdkRoot $expectedBlobs

	$seenBlobs = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	$seenTrees = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	$fileIdentities = [Collections.Generic.HashSet[string]]::new(
		[StringComparer]::Ordinal)
	foreach ($item in Get-ChildItem -LiteralPath $SdkRoot -Recurse -Force) {
		if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw "The materialized SDK contains a reparse point at '$($item.FullName)'"
		}
		$relativePath = [IO.Path]::GetRelativePath(
			$SdkRoot, $item.FullName).Replace('\', '/')
		Assert-CanonicalGitPath $relativePath
		if ($item.PSIsContainer) {
			if (-not $expectedTrees.Contains($relativePath)) {
				throw "The materialized SDK contains extra directory '$relativePath'"
			}
			[void]$seenTrees.Add($relativePath)
			continue
		}

		$expected = $null
		if (-not $expectedBlobs.TryGetValue($relativePath, [ref]$expected)) {
			throw "The materialized SDK contains extra file '$relativePath'"
		}
		$streams = @(Get-Item -LiteralPath $item.FullName -Stream * `
			-ErrorAction Stop)
		if (
			$streams.Count -ne 1 -or
			$streams[0].Stream -notin ':$DATA', '$DATA'
		) {
			throw "The materialized SDK contains an alternate data stream at '$relativePath'"
		}
		$oid = Get-GitBlobHash `
			$item.FullName $expected.Size $fileIdentities
		if ($oid -cne $expected.Oid) {
			throw "The materialized SDK bytes differ at '$relativePath'"
		}
		[void]$seenBlobs.Add($relativePath)
	}
	if (
		$seenBlobs.Count -ne $expectedBlobs.Count -or
		$seenTrees.Count -ne $expectedTrees.Count
	) {
		throw 'The materialized SDK is missing locked filesystem entries'
	}
}

function New-VerifiedSdkWorktree {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Commit,
		[Parameter(Mandatory = $true)][object]$SdkRoot,
		[Parameter(Mandatory = $true)][object]$Manifest
	)

	foreach ($entry in @(
		[pscustomobject]@{ Value = $GitPath; Name = 'Git path' },
		[pscustomobject]@{ Value = $GitDir; Name = 'Git directory' },
		[pscustomobject]@{ Value = $Commit; Name = 'SDK commit' },
		[pscustomobject]@{ Value = $SdkRoot; Name = 'SDK root' }
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	Assert-HexString $Commit 40 'SDK commit'
	if (Test-Path -LiteralPath $SdkRoot) {
		throw 'The SDK worktree destination already exists'
	}
	$indexPath = Join-Path $GitDir 'index'
	if (Test-Path -LiteralPath $indexPath) {
		throw 'The SDK Git directory contains an unexpected checkout index'
	}
	# The locked manifest states every relative path this checkout will
	# materialize, so the longest of them is the real downstream requirement
	# on the root. Enforce it before the destination exists rather than
	# discovering it as a partial checkout that then has to be cleaned up.
	$longestEntryPath = 0
	foreach ($entry in $Manifest.Entries) {
		if ($entry.Path.Length -gt $longestEntryPath) {
			$longestEntryPath = $entry.Path.Length
		}
	}
	Assert-UsablePathLength `
		$SdkRoot ($longestEntryPath + 1) 'SDK root'
	[void][IO.Directory]::CreateDirectory($SdkRoot)
	[void](New-SafeGitProcess $GitPath @(
		'-c', 'core.autocrlf=false',
		'-c', 'core.longpaths=true',
		'-c', 'core.protectNTFS=true',
		'-c', 'core.symlinks=false',
		'-c', 'filter.lfs.required=false',
		"--git-dir=$GitDir",
		"--work-tree=$SdkRoot",
		'checkout',
		'--force',
		$Commit,
		'--',
		':/'
	))

	Assert-MaterializedSdkTree $GitPath $GitDir $SdkRoot $Manifest
	return $SdkRoot
}

function Invoke-LockedSdkBootstrapCore {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$LockPath,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerTemp,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunId,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunAttempt,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Job,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$MatrixDiscriminator,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerOs,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerArch,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerEnvironment,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubPath,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubEnv,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubOutput
	)

	$lock = Read-SdkLock $LockPath
	Assert-ProductionSdkLock $lock -RequireApproval

	foreach ($entry in @(
		[pscustomobject]@{ Value = $RunnerTemp; Name = 'runner.temp' },
		[pscustomobject]@{ Value = $RunId; Name = 'run ID' },
		[pscustomobject]@{ Value = $RunAttempt; Name = 'run attempt' },
		[pscustomobject]@{ Value = $Job; Name = 'job' },
		[pscustomobject]@{
			Value = $MatrixDiscriminator
			Name = 'matrix discriminator'
		},
		[pscustomobject]@{ Value = $RunnerOs; Name = 'runner.os' },
		[pscustomobject]@{ Value = $RunnerArch; Name = 'runner.arch' },
		[pscustomobject]@{
			Value = $RunnerEnvironment
			Name = 'runner.environment'
		},
		[pscustomobject]@{ Value = $GitHubPath; Name = 'GITHUB_PATH' },
		[pscustomobject]@{ Value = $GitHubEnv; Name = 'GITHUB_ENV' },
		[pscustomobject]@{ Value = $GitHubOutput; Name = 'GITHUB_OUTPUT' }
	)) {
		Assert-ExactStringValue $entry.Value $entry.Name
	}
	Assert-NativeRunnerPolicy $RunnerOs $RunnerArch $RunnerEnvironment

	$runnerRoot = Assert-SafeExistingDirectory $RunnerTemp 'runner.temp'
	$ownedRoot = New-PrivateSdkRoot `
		-RunnerTemp $runnerRoot `
		-RunId $RunId `
		-RunAttempt $RunAttempt `
		-Job $Job `
		-MatrixDiscriminator $MatrixDiscriminator
	$succeeded = $false
	$bootstrapError = $null
	try {
		$root = $ownedRoot.Path
		# Budget the root for Git's own control paths before creating the
		# template directory or initializing the bare mirror, so an
		# unusable root is refused while its only content is the sentinel
		# and the owned-root cleanup below can still remove exactly it.
		Assert-UsablePathLength `
			$root $script:GitControlReserve 'private SDK root'
		$gitPath = Get-SystemGitPath $runnerRoot
		$gitDir = Join-Path $root $script:GitDirectoryName
		$sdkRoot = Join-Path $root $script:SdkDirectoryName
		$templateDir = Join-Path $root $script:GitTemplateDirectoryName
		[void][IO.Directory]::CreateDirectory($templateDir)

		[void](New-SafeGitProcess $gitPath @(
			'init',
			'--bare',
			'--object-format=sha1',
			"--template=$templateDir",
			$gitDir
		))
		[void](New-SafeGitProcess $gitPath @(
			"--git-dir=$gitDir",
			'remote',
			'add',
			'origin',
			$lock.remote_url
		))
		[void](New-SafeGitProcess $gitPath @(
			"--git-dir=$gitDir",
			'config',
			'--local',
			'--unset-all',
			'remote.origin.fetch'
		) @(0, 5))
		Assert-RepositoryOrigin $gitPath $gitDir $lock.remote_url

		[void](New-SafeGitProcess $gitPath @(
			'-c', 'protocol.version=2',
			'-c', 'fetch.fsckObjects=true',
			'-c', 'transfer.fsckObjects=true',
			'-c', 'http.followRedirects=false',
			'-c', 'protocol.https.allow=always',
			"--git-dir=$gitDir",
			'fetch',
			'--force',
			'--no-tags',
			'--no-recurse-submodules',
			'--depth=1',
			'--no-write-fetch-head',
			'origin',
			"+$($lock.commit):refs/gfw-sdk/locked"
		))

		Assert-RepositoryOrigin $gitPath $gitDir $lock.remote_url
		Assert-GitObjectIdentity $gitPath $gitDir $lock
		$manifest = Get-GitTreeManifest $gitPath $gitDir $lock.commit
		Assert-ManifestMatchesLock $manifest $lock
		Assert-NoLfsPointers $gitPath $gitDir $lock.commit

		[void](New-VerifiedSdkWorktree `
			-GitPath $gitPath `
			-GitDir $gitDir `
			-Commit $lock.commit `
			-SdkRoot $sdkRoot `
			-Manifest $manifest)

		$pathEntries = @(
			(Join-Path $sdkRoot 'usr\bin\core_perl'),
			(Join-Path $sdkRoot 'usr\bin'),
			(Join-Path $sdkRoot 'clangarm64\bin')
		)
		foreach ($pathEntry in $pathEntries) {
			[void](Assert-SafeExistingDirectory $pathEntry 'SDK PATH entry')
			Assert-ContainedPath $sdkRoot $pathEntry
		}

		$githubPathFile = Assert-SafeCommandFile `
			$GitHubPath $runnerRoot 'GITHUB_PATH'
		$githubEnvFile = Assert-SafeCommandFile `
			$GitHubEnv $runnerRoot 'GITHUB_ENV'
		$githubOutputFile = Assert-SafeCommandFile `
			$GitHubOutput $runnerRoot 'GITHUB_OUTPUT'
		foreach ($pathEntry in $pathEntries) {
			Add-GitHubCommandValue $githubPathFile $pathEntry
		}
		Add-GitHubCommandValue $githubEnvFile 'MSYSTEM=CLANGARM64'
		Add-GitHubCommandValue $githubEnvFile "GFW_SDK_ROOT=$sdkRoot"
		Add-GitHubCommandValue $githubOutputFile "sdk-root=$sdkRoot"
		$succeeded = $true
	} catch {
		$bootstrapError = $_.Exception.Message
		throw
	} finally {
		if (-not $succeeded) {
			try {
				Remove-OwnedSdkRoot $ownedRoot
			} catch {
				throw "$bootstrapError; SDK root cleanup also failed: $($_.Exception.Message)"
			}
			$script:PrivateTempPath = $null
		}
	}
}

function Invoke-LockedSdkBootstrap {
	[CmdletBinding()]
	param(
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerTemp,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunId,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunAttempt,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$Job,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$MatrixDiscriminator,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerOs,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerArch,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$RunnerEnvironment,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubPath,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubEnv,
		[AllowNull()][AllowEmptyCollection()]
		[Parameter(Mandatory = $true)][object]$GitHubOutput
	)

	Invoke-LockedSdkBootstrapCore `
		-LockPath (Join-Path $PSScriptRoot 'sdk-lock.json') `
		-RunnerTemp $RunnerTemp `
		-RunId $RunId `
		-RunAttempt $RunAttempt `
		-Job $Job `
		-MatrixDiscriminator $MatrixDiscriminator `
		-RunnerOs $RunnerOs `
		-RunnerArch $RunnerArch `
		-RunnerEnvironment $RunnerEnvironment `
		-GitHubPath $GitHubPath `
		-GitHubEnv $GitHubEnv `
		-GitHubOutput $GitHubOutput
}

Export-ModuleMember -Function 'Invoke-LockedSdkBootstrap'
