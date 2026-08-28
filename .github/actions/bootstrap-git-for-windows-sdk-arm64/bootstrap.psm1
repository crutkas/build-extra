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
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetLongPathName(
        string shortPath,
        StringBuilder longPath,
        uint bufferLength);
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
		[Parameter(Mandatory = $true)][string]$Value,
		[Parameter(Mandatory = $true)][int]$Length,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($Value -cnotmatch "^[0-9a-f]{$Length}$") {
		throw "$Name must be exactly $Length lowercase hexadecimal characters"
	}
}

function Assert-ExactProperties {
	param(
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string[]]$Expected,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$actual = @($Value.PSObject.Properties.Name)
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

function Read-SdkLock {
	[CmdletBinding()]
	param([Parameter(Mandatory = $true)][string]$Path)

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
		} finally {
			$document.Dispose()
		}
	} finally {
		$stream.Dispose()
	}

	$text = $script:Utf8.GetString($bytes)
	return $text | ConvertFrom-Json -Depth 20
}

function Assert-PositiveInteger {
	param(
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$number = 0L
	if (-not [long]::TryParse(
		[string]$Value,
		[Globalization.NumberStyles]::None,
		[Globalization.CultureInfo]::InvariantCulture,
		[ref]$number
	) -or $number -le 0) {
		throw "$Name must be a positive integer"
	}
	return $number
}

function ConvertTo-LockTimestamp {
	param(
		[Parameter(Mandatory = $true)][object]$Value,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if ($Value -is [DateTime]) {
		return $Value.ToUniversalTime().ToString(
			'yyyy-MM-ddTHH:mm:ssZ',
			[Globalization.CultureInfo]::InvariantCulture)
	}
	if ($Value -is [DateTimeOffset]) {
		return $Value.UtcDateTime.ToString(
			'yyyy-MM-ddTHH:mm:ssZ',
			[Globalization.CultureInfo]::InvariantCulture)
	}

	$timestamp = [DateTimeOffset]::MinValue
	if (-not [DateTimeOffset]::TryParseExact(
		[string]$Value,
		'yyyy-MM-ddTHH:mm:ssZ',
		[Globalization.CultureInfo]::InvariantCulture,
		[Globalization.DateTimeStyles]::AssumeUniversal,
		[ref]$timestamp
	)) {
		throw "$Name must be an exact UTC timestamp"
	}
	return $timestamp.UtcDateTime.ToString(
		'yyyy-MM-ddTHH:mm:ssZ',
		[Globalization.CultureInfo]::InvariantCulture)
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
	[void](Assert-PositiveInteger `
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
	[void](Assert-PositiveInteger `
		$Lock.package_database.total_blob_bytes `
		'lock.package_database.total_blob_bytes')
	if ($packageEntries -ne $packageBlobs + $packageTrees) {
		throw 'The package database manifest entry counts are inconsistent'
	}

	$scope = @($Lock.package_database.scope)
	if (
		$scope.Count -ne 2 -or
		$scope[0] -cne 'var/lib/pacman/local' -or
		$scope[1] -cne 'var/lib/pacman/sync'
	) {
		throw 'Unexpected package database scope'
	}

	switch ($Lock.admission.status) {
		'pending-independent-review' {
			if (
				$null -ne $Lock.admission.approved_by -or
				$null -ne $Lock.admission.approved_at -or
				$null -ne $Lock.admission.evidence
			) {
				throw 'A pending snapshot cannot contain approval evidence'
			}
		}
		'approved' {
			foreach ($name in 'approved_by', 'approved_at', 'evidence') {
				if ([string]::IsNullOrWhiteSpace([string]$Lock.admission.$name)) {
					throw "An approved snapshot requires admission.$name"
				}
			}
			[void](ConvertTo-LockTimestamp `
				$Lock.admission.approved_at 'admission.approved_at')
		}
		default {
			throw 'Unknown snapshot admission status'
		}
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
		[long]$Lock.manifest.entry_count -ne 88249 -or
		[long]$Lock.manifest.blob_count -ne 83648 -or
		[long]$Lock.manifest.tree_count -ne 4601 -or
		[string]$Lock.manifest.total_blob_bytes -cne '3615514045'
	) {
		throw 'Unexpected production complete-tree manifest metadata'
	}
	if (
		$Lock.package_database.canonicalization -cne
			$script:PackageCanonicalization -or
		$Lock.package_database.sha256 -cne $script:PackageDatabaseSha256 -or
		[long]$Lock.package_database.entry_count -ne 1309 -or
		[long]$Lock.package_database.blob_count -ne 995 -or
		[long]$Lock.package_database.tree_count -ne 314 -or
		[string]$Lock.package_database.total_blob_bytes -cne '43600841'
	) {
		throw 'Unexpected production package database manifest metadata'
	}
	if ($RequireApproval -and $Lock.admission.status -cne 'approved') {
		throw 'The pinned SDK snapshot is not independently admitted'
	}
}

function Assert-LocalPathSyntax {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Name
	)

	if (
		[string]::IsNullOrWhiteSpace($Path) -or
		-not [IO.Path]::IsPathFullyQualified($Path) -or
		$Path -notmatch '^[A-Za-z]:\\' -or
		$Path -match '^(\\\\[?.]\\|\\\?\?\\)' -or
		$Path.Contains('/') -or
		$Path.Substring(2).Contains(':')
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
		[Parameter(Mandatory = $true)][string]$Path,
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
		[Parameter(Mandatory = $true)][string]$Parent,
		[Parameter(Mandatory = $true)][string]$Child
	)

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

function New-PrivateSdkRoot {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$RunnerTemp,
		[Parameter(Mandatory = $true)][string]$RunId,
		[Parameter(Mandatory = $true)][string]$RunAttempt,
		[Parameter(Mandatory = $true)][string]$Job,
		[Parameter(Mandatory = $true)][string]$MatrixDiscriminator,
		[string]$Nonce
	)

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
	if ([string]::IsNullOrEmpty($Nonce)) {
		$Nonce = [Guid]::NewGuid().ToString('N')
	}
	Assert-HexString $Nonce 32 'root nonce'

	$leaf = "gfw-sdk-arm64-$RunId-$RunAttempt-$($bindingHash.Substring(0, 20))-$Nonce"
	$candidate = [IO.Path]::GetFullPath((Join-Path $runnerRoot $leaf))
	Assert-ContainedPath $runnerRoot $candidate
	if (Test-Path -LiteralPath $candidate) {
		throw 'The unique SDK root already exists'
	}

	$item = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
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

	Assert-NoReparseAncestors $candidate 'SDK root'
	$longPath = Get-LongPath $candidate
	if (-not [string]::Equals(
		$candidate,
		$longPath,
		[StringComparison]::OrdinalIgnoreCase
	)) {
		throw 'The SDK root resolved through a path alias'
	}

	$actualAcl = Get-Acl -LiteralPath $candidate
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
	$script:PrivateTempPath = $candidate
	return $candidate
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

	try {
		for ($index = 0; $index -lt $records.Count - 1; $index++) {
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
				$totalBlobBytes += $blobSize
			}

			$canonicalPath = ConvertTo-CanonicalGitPath $path
			$line = "$mode`t$type`t$oid`t$canonicalSize`t$canonicalPath`n"
			$lineBytes = $script:Utf8.GetBytes($line)
			$manifestHash.AppendData($lineBytes)
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
		$Manifest.EntryCount -ne [long]$Lock.manifest.entry_count -or
		$Manifest.BlobCount -ne [long]$Lock.manifest.blob_count -or
		$Manifest.TreeCount -ne [long]$Lock.manifest.tree_count -or
		$Manifest.TotalBlobBytes -cne [string]$Lock.manifest.total_blob_bytes
	) {
		throw 'The complete Git tree manifest does not match the lock'
	}
	if (
		$Manifest.PackageDatabaseSha256 -cne
			$Lock.package_database.sha256 -or
		$Manifest.PackageDatabaseEntryCount -ne
			[long]$Lock.package_database.entry_count -or
		$Manifest.PackageDatabaseBlobCount -ne
			[long]$Lock.package_database.blob_count -or
		$Manifest.PackageDatabaseTreeCount -ne
			[long]$Lock.package_database.tree_count -or
		$Manifest.PackageDatabaseTotalBlobBytes -cne
			[string]$Lock.package_database.total_blob_bytes
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

function New-VerifiedSdkWorktree {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string]$GitDir,
		[Parameter(Mandatory = $true)][string]$Commit,
		[Parameter(Mandatory = $true)][string]$SdkRoot,
		[Parameter(Mandatory = $true)][object]$Manifest
	)

	if (Test-Path -LiteralPath $SdkRoot) {
		throw 'The SDK worktree destination already exists'
	}
	[void](New-Item -ItemType Directory -Path $SdkRoot)
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

	$files = 0L
	$directories = 0L
	foreach ($item in Get-ChildItem -LiteralPath $SdkRoot -Recurse -Force) {
		if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw "The materialized SDK contains a reparse point at '$($item.FullName)'"
		}
		if ($item.PSIsContainer) {
			$directories++
		} else {
			$files++
		}
	}
	if (
		$files -ne $Manifest.BlobCount -or
		$directories -ne $Manifest.TreeCount
	) {
		throw 'The materialized SDK entry counts do not match the verified tree'
	}
	return $SdkRoot
}

function Invoke-LockedSdkBootstrap {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][string]$LockPath,
		[Parameter(Mandatory = $true)][string]$RunnerTemp,
		[Parameter(Mandatory = $true)][string]$RunId,
		[Parameter(Mandatory = $true)][string]$RunAttempt,
		[Parameter(Mandatory = $true)][string]$Job,
		[Parameter(Mandatory = $true)][string]$MatrixDiscriminator,
		[Parameter(Mandatory = $true)][string]$RunnerOs,
		[Parameter(Mandatory = $true)][string]$RunnerArch,
		[Parameter(Mandatory = $true)][string]$GitHubPath,
		[Parameter(Mandatory = $true)][string]$GitHubEnv,
		[Parameter(Mandatory = $true)][string]$GitHubOutput
	)

	$lock = Read-SdkLock $LockPath
	Assert-ProductionSdkLock $lock -RequireApproval

	if (
		$RunnerOs -cne 'Windows' -or
		$RunnerArch -cne 'ARM64' -or
		[Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
			[Runtime.InteropServices.Architecture]::Arm64
	) {
		throw 'The pinned SDK requires a native Windows ARM64 runner'
	}

	$runnerRoot = Assert-SafeExistingDirectory $RunnerTemp 'runner.temp'
	$root = New-PrivateSdkRoot `
		-RunnerTemp $runnerRoot `
		-RunId $RunId `
		-RunAttempt $RunAttempt `
		-Job $Job `
		-MatrixDiscriminator $MatrixDiscriminator
	$gitPath = Get-SystemGitPath $runnerRoot
	$gitDir = Join-Path $root 'repository.git'
	$sdkRoot = Join-Path $root 'sdk'
	$templateDir = Join-Path $root 'empty-git-template'
	[void](New-Item -ItemType Directory -Path $templateDir)

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
}

Export-ModuleMember -Function @(
	'Assert-ContainedPath',
	'Assert-GitObjectIdentity',
	'Assert-LockedRefs',
	'Assert-ManifestMatchesLock',
	'Assert-NoLfsPointers',
	'Assert-ProductionSdkLock',
	'Assert-SafeExistingDirectory',
	'Get-GitTreeManifest',
	'Get-SystemGitPath',
	'Get-TreeManifestFromBytes',
	'Invoke-LockedSdkBootstrap',
	'New-PrivateSdkRoot',
	'New-VerifiedSdkWorktree',
	'Read-SdkLock'
)
