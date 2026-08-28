$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actionRoot = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $actionRoot 'bootstrap.psm1'
$lockPath = Join-Path $actionRoot 'sdk-lock.json'
$entrypointPath = Join-Path $actionRoot 'bootstrap.ps1'
$actionPath = Join-Path $actionRoot 'action.yml'

if (-not ('GfwSdkBootstrapTestNativeMethods' -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class GfwSdkBootstrapTestNativeMethods
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
}
'@
}

$bootstrapModule = Import-Module $modulePath -Force -PassThru

function Read-SdkLock {
	param([Parameter(Mandatory = $true)][object]$Path)
	return & $script:bootstrapModule {
		param($Path)
		Read-SdkLock $Path
	} $Path
}

function Assert-ProductionSdkLock {
	param(
		[Parameter(Mandatory = $true)][object]$Lock,
		[switch]$RequireApproval
	)
	& $script:bootstrapModule {
		param($Lock, $RequireApproval)
		if ($RequireApproval) {
			Assert-ProductionSdkLock $Lock -RequireApproval
		} else {
			Assert-ProductionSdkLock $Lock
		}
	} $Lock ([bool]$RequireApproval)
}

function Get-GitTreeManifest {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Commit
	)
	return & $script:bootstrapModule {
		param($GitPath, $GitDir, $Commit)
		Get-GitTreeManifest $GitPath $GitDir $Commit
	} $GitPath $GitDir $Commit
}

function Assert-GitObjectIdentity {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Lock
	)
	& $script:bootstrapModule {
		param($GitPath, $GitDir, $Lock)
		Assert-GitObjectIdentity $GitPath $GitDir $Lock
	} $GitPath $GitDir $Lock
}

function Assert-ManifestMatchesLock {
	param(
		[Parameter(Mandatory = $true)][object]$Manifest,
		[Parameter(Mandatory = $true)][object]$Lock
	)
	& $script:bootstrapModule {
		param($Manifest, $Lock)
		Assert-ManifestMatchesLock $Manifest $Lock
	} $Manifest $Lock
}

function Assert-NoLfsPointers {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Commit
	)
	& $script:bootstrapModule {
		param($GitPath, $GitDir, $Commit)
		Assert-NoLfsPointers $GitPath $GitDir $Commit
	} $GitPath $GitDir $Commit
}

function New-VerifiedSdkWorktree {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Commit,
		[Parameter(Mandatory = $true)][object]$SdkRoot,
		[Parameter(Mandatory = $true)][object]$Manifest
	)
	return & $script:bootstrapModule {
		param($GitPath, $GitDir, $Commit, $SdkRoot, $Manifest)
		New-VerifiedSdkWorktree `
			$GitPath $GitDir $Commit $SdkRoot $Manifest
	} $GitPath $GitDir $Commit $SdkRoot $Manifest
}

function Assert-MaterializedSdkTree {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$SdkRoot,
		[Parameter(Mandatory = $true)][object]$Manifest
	)
	& $script:bootstrapModule {
		param($GitPath, $GitDir, $SdkRoot, $Manifest)
		Assert-MaterializedSdkTree $GitPath $GitDir $SdkRoot $Manifest
	} $GitPath $GitDir $SdkRoot $Manifest
}

function Get-GitBlobHash {
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[Parameter(Mandatory = $true)][object]$ExpectedSize,
		[Parameter(Mandatory = $true)][object]$FileIdentities
	)
	return & $script:bootstrapModule {
		param($Path, $ExpectedSize, $FileIdentities)
		Get-GitBlobHash $Path $ExpectedSize $FileIdentities
	} $Path $ExpectedSize $FileIdentities
}

function Get-TreeManifestFromBytes {
	param([Parameter(Mandatory = $true)][byte[]]$Bytes)
	$holder = [pscustomobject]@{ Bytes = $Bytes }
	return & $script:bootstrapModule {
		param($Holder)
		Get-TreeManifestFromBytes -Bytes $Holder.Bytes
	} $holder
}

function Assert-LockedRefs {
	param(
		[Parameter(Mandatory = $true)][object]$GitPath,
		[Parameter(Mandatory = $true)][object]$GitDir,
		[Parameter(Mandatory = $true)][object]$Commit
	)
	& $script:bootstrapModule {
		param($GitPath, $GitDir, $Commit)
		Assert-LockedRefs $GitPath $GitDir $Commit
	} $GitPath $GitDir $Commit
}

function Assert-SafeExistingDirectory {
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[string]$Name = 'path'
	)
	return & $script:bootstrapModule {
		param($Path, $Name)
		Assert-SafeExistingDirectory $Path $Name
	} $Path $Name
}

function Assert-ContainedPath {
	param(
		[Parameter(Mandatory = $true)][object]$Parent,
		[Parameter(Mandatory = $true)][object]$Child
	)
	& $script:bootstrapModule {
		param($Parent, $Child)
		Assert-ContainedPath $Parent $Child
	} $Parent $Child
}

function Assert-LocalPathSyntax {
	param(
		[Parameter(Mandatory = $true)][object]$Path,
		[Parameter(Mandatory = $true)][object]$Name
	)
	return & $script:bootstrapModule {
		param($Path, $Name)
		Assert-LocalPathSyntax $Path $Name
	} $Path $Name
}

function Get-LongPath {
	param([Parameter(Mandatory = $true)][object]$Path)
	return & $script:bootstrapModule {
		param($Path)
		Get-LongPath $Path
	} $Path
}

function New-PrivateSdkRoot {
	param(
		[Parameter(Mandatory = $true)][object]$RunnerTemp,
		[Parameter(Mandatory = $true)][object]$RunId,
		[Parameter(Mandatory = $true)][object]$RunAttempt,
		[Parameter(Mandatory = $true)][object]$Job,
		[Parameter(Mandatory = $true)][object]$MatrixDiscriminator,
		[AllowNull()][object]$Nonce
	)
	return & $script:bootstrapModule {
		param(
			$RunnerTemp,
			$RunId,
			$RunAttempt,
			$Job,
			$MatrixDiscriminator,
			$Nonce
		)
		New-PrivateSdkRoot `
			$RunnerTemp $RunId $RunAttempt $Job $MatrixDiscriminator $Nonce
	} $RunnerTemp $RunId $RunAttempt $Job $MatrixDiscriminator $Nonce
}

function Remove-OwnedSdkRoot {
	param([Parameter(Mandatory = $true)][object]$OwnedRoot)
	& $script:bootstrapModule {
		param($OwnedRoot)
		Remove-OwnedSdkRoot $OwnedRoot
	} $OwnedRoot
}

function Get-SystemGitPath {
	param([Parameter(Mandatory = $true)][object]$RunnerTemp)
	return & $script:bootstrapModule {
		param($RunnerTemp)
		Get-SystemGitPath $RunnerTemp
	} $RunnerTemp
}

function Assert-RunnerPlatformFacts {
	param(
		[Parameter(Mandatory = $true)][object]$WindowsPlatform,
		[Parameter(Mandatory = $true)][object]$OSArchitecture,
		[Parameter(Mandatory = $true)][object]$ProcessArchitecture,
		[Parameter(Mandatory = $true)][object]$IsElevated
	)
	& $script:bootstrapModule {
		param(
			$WindowsPlatform,
			$OSArchitecture,
			$ProcessArchitecture,
			$IsElevated
		)
		Assert-RunnerPlatformFacts `
			$WindowsPlatform $OSArchitecture $ProcessArchitecture $IsElevated
	} $WindowsPlatform $OSArchitecture $ProcessArchitecture $IsElevated
}

$script:passed = 0
$script:failed = 0

function Assert-Equal {
	param(
		[Parameter(Mandatory = $true)][object]$Actual,
		[Parameter(Mandatory = $true)][object]$Expected
	)

	if ([string]$Actual -cne [string]$Expected) {
		throw "Expected '$Expected', got '$Actual'"
	}
}

function Assert-Throws {
	param(
		[Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
		[Parameter(Mandatory = $true)][string]$Pattern,
		[string]$ForbiddenPattern
	)

	$caught = $null
	try {
		& $ScriptBlock
	} catch {
		$caught = $_
	}
	if ($null -eq $caught) {
		throw "Expected failure matching '$Pattern'"
	}
	$message = $caught.Exception.Message
	if (
		-not [string]::IsNullOrEmpty($ForbiddenPattern) -and
		$message -cmatch $ForbiddenPattern
	) {
		throw "Expected no '$ForbiddenPattern', got '$message'"
	}
	if ($message -cnotmatch $Pattern) {
		throw "Expected '$Pattern', got '$message'"
	}
}

function Invoke-Test {
	param(
		[Parameter(Mandatory = $true)][string]$Name,
		[Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
	)

	try {
		& $ScriptBlock
		Write-Host "ok - $Name"
		$script:passed++
	} catch {
		Write-Host "not ok - $Name"
		Write-Host $_
		$script:failed++
	}
}

function Copy-Lock {
	param([Parameter(Mandatory = $true)][object]$Lock)

	return Copy-TestValue $Lock
}

function Copy-TestValue {
	param([AllowNull()][object]$Value)

	if ($null -eq $Value) {
		return $null
	}
	if ($Value.GetType() -eq [object[]]) {
		$copy = [object[]]::new($Value.Count)
		for ($index = 0; $index -lt $Value.Count; $index++) {
			$copy[$index] = Copy-TestValue $Value[$index]
		}
		return , $copy
	}
	if ($Value.GetType() -eq [Management.Automation.PSCustomObject]) {
		$copy = [ordered]@{}
		foreach ($property in $Value.PSObject.Properties) {
			$copy[$property.Name] = Copy-TestValue $property.Value
		}
		return [pscustomobject]$copy
	}
	return $Value
}

function Set-LockValue {
	param(
		[Parameter(Mandatory = $true)][object]$Lock,
		[Parameter(Mandatory = $true)][string]$Path,
		[AllowNull()]
		[AllowEmptyCollection()]
		[object]$Value
	)

	$segments = $Path.Split('.')
	$parent = $Lock
	for ($index = 0; $index -lt $segments.Count - 1; $index++) {
		$segment = $segments[$index]
		if ($parent.GetType() -eq [object[]]) {
			$parent = $parent[[int]$segment]
		} else {
			$parent = $parent.$segment
		}
	}
	$leaf = $segments[-1]
	if ($parent.GetType() -eq [object[]]) {
		$parent[[int]$leaf] = $Value
	} else {
		$parent.$leaf = $Value
	}
}

function Get-LockValue {
	param(
		[Parameter(Mandatory = $true)][object]$Lock,
		[Parameter(Mandatory = $true)][string]$Path
	)

	$value = $Lock
	foreach ($segment in $Path.Split('.')) {
		if ($value.GetType() -eq [object[]]) {
			$value = $value[[int]$segment]
		} else {
			$value = $value.$segment
		}
	}
	return $value
}

function Write-LockFixture {
	param(
		[Parameter(Mandatory = $true)][object]$Lock,
		[Parameter(Mandatory = $true)][string]$Name
	)

	$path = Join-Path $script:testRoot "$Name.json"
	[IO.File]::WriteAllText(
		$path,
		($Lock | ConvertTo-Json -Depth 20),
		[Text.UTF8Encoding]::new($false))
	return $path
}

function New-ApprovedLock {
	param([Parameter(Mandatory = $true)][object]$Lock)

	$approved = Copy-Lock $Lock
	$approved.admission.status = 'approved'
	$approved.admission.approved_by = 'protected-base-governance'
	$approved.admission.approved_at = '2026-08-28T00:00:00Z'
	$approved.admission.evidence = [pscustomobject][ordered]@{
		authority_repository = 'crutkas/build-extra'
		authority_ref = 'refs/heads/main'
		protected_base_commit =
			'79f3c5fa9111e438b923222dd27392843a995995'
		reviewed_source_commit =
			'1111111111111111111111111111111111111111'
		reviewed_source_tree =
			'2222222222222222222222222222222222222222'
		base_protected = $true
		required_checks_passed = $true
		required_checks = [object[]]@('source-lock-validation')
		native_runner = [pscustomobject][ordered]@{
			provider = 'github-hosted'
			image = 'windows-11-arm'
			os = 'Windows'
			os_architecture = 'Arm64'
			process_architecture = 'Arm64'
			evidence_uri =
				'https://github.com/crutkas/build-extra/actions/runs/1'
		}
	}
	return $approved
}

function Assert-GateStopsBeforeSideEffects {
	param(
		[Parameter(Mandatory = $true)][string]$CandidateLockPath,
		[Parameter(Mandatory = $true)][string]$ExpectedPattern
	)

	$message = & $script:bootstrapModule {
		param($CandidateLockPath)
		$names = @(
			'Assert-NativeRunnerPolicy',
			'Assert-SafeExistingDirectory',
			'New-PrivateSdkRoot',
			'Get-SystemGitPath',
			'New-SafeGitProcess',
			'Assert-RepositoryOrigin',
			'New-VerifiedSdkWorktree',
			'Add-GitHubCommandValue'
		)
		$originals = @{}
		try {
			foreach ($name in $names) {
				$originals[$name] = (Get-Item `
					-LiteralPath "Function:$name").ScriptBlock
				Set-Item -LiteralPath "Function:$name" -Value {
					throw 'SIDE_EFFECT_SENTINEL'
				}
			}
			try {
				Invoke-LockedSdkBootstrapCore `
					-LockPath $CandidateLockPath `
					-RunnerTemp 'C:\sentinel' `
					-RunId '1' `
					-RunAttempt '1' `
					-Job 'sentinel' `
					-MatrixDiscriminator 'sentinel' `
					-RunnerOs 'Windows' `
					-RunnerArch 'ARM64' `
					-RunnerEnvironment 'github-hosted' `
					-GitHubPath 'C:\sentinel\path' `
					-GitHubEnv 'C:\sentinel\env' `
					-GitHubOutput 'C:\sentinel\output'
				throw 'Expected the admission gate to fail'
			} catch {
				return $_.Exception.Message
			}
		} finally {
			foreach ($name in $names) {
				if ($originals.ContainsKey($name)) {
					Set-Item -LiteralPath "Function:$name" `
						-Value $originals[$name]
				}
			}
		}
	} $CandidateLockPath
	if ($message -ceq 'SIDE_EFFECT_SENTINEL') {
		throw 'Admission failure reached a side-effect sentinel'
	}
	if ($message -cnotmatch $ExpectedPattern) {
		throw "Expected '$ExpectedPattern', got '$message'"
	}
}

function Invoke-TestGit {
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
	)

	& $GitPath `
		--no-pager `
		-c core.hooksPath=NUL `
		-c credential.helper= `
		@Arguments
	if ($LASTEXITCODE -ne 0) {
		throw "Test Git failed: git $($Arguments -join ' ')"
	}
}

function New-TreeRecordBytes {
	param([Parameter(Mandatory = $true)][string[]]$Records)

	$text = ($Records -join [char]0) + [char]0
	return [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
}

function New-TestJunction {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Target
	)

	if ($Path -match '[*?]' -or $Target -match '[*?]') {
		throw 'Test junction paths cannot contain wildcard metacharacters'
	}
	[void](New-Item -ItemType Junction -Path $Path -Target $Target)
}

function New-TestHardLink {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$ExistingPath
	)

	if ([GfwSdkBootstrapTestNativeMethods]::CreateHardLinkW(
		$Path,
		$ExistingPath,
		[IntPtr]::Zero
	)) {
		return
	}
	$errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
	if ($errorCode -eq 1 -or $errorCode -eq 50) {
		throw [ComponentModel.Win32Exception]::new(
			$errorCode,
			"The test filesystem cannot create hardlinks at '$Path' " +
				"(Win32 error $errorCode); hardlink coverage requires NTFS")
	}
	throw [ComponentModel.Win32Exception]::new(
		$errorCode,
		"Cannot create the test hardlink '$Path' from '$ExistingPath' " +
			"(Win32 error $errorCode)")
}

function Get-TestFileFacts {
	param([Parameter(Mandatory = $true)][string]$Path)

	$stream = [IO.FileStream]::new(
		$Path,
		[IO.FileMode]::Open,
		[IO.FileAccess]::Read,
		[IO.FileShare]::ReadWrite)
	try {
		$information =
			[GfwSdkBootstrapNativeMethods+ByHandleFileInformation]::new()
		if (-not [GfwSdkBootstrapNativeMethods]::GetFileInformationByHandle(
			$stream.SafeFileHandle,
			[ref]$information
		)) {
			$errorCode =
				[Runtime.InteropServices.Marshal]::GetLastWin32Error()
			throw [ComponentModel.Win32Exception]::new(
				$errorCode,
				"Cannot inspect the test file '$Path' " +
					"(Win32 error $errorCode)")
		}
		return [pscustomobject]@{
			Links = [int]$information.NumberOfLinks
			Identity = '{0:x8}:{1:x8}:{2:x8}' -f
				$information.VolumeSerialNumber,
				$information.FileIndexHigh,
				$information.FileIndexLow
		}
	} finally {
		$stream.Dispose()
	}
}

function Resolve-TestRootBase {
	param(
		[AllowNull()]
		[AllowEmptyString()]
		[AllowEmptyCollection()]
		[object]$RunnerTemp,
		[AllowNull()]
		[AllowEmptyString()]
		[AllowEmptyCollection()]
		[object]$ProcessTemp
	)

	$candidate = $null
	$source = $null
	foreach ($entry in @(
		[pscustomobject]@{ Value = $RunnerTemp; Name = 'RUNNER_TEMP' },
		[pscustomobject]@{ Value = $ProcessTemp; Name = 'TEMP' }
	)) {
		if ($null -eq $entry.Value) {
			continue
		}
		if ($entry.Value -isnot [string]) {
			throw "$($entry.Name) must be a string path"
		}
		if ([string]::IsNullOrWhiteSpace($entry.Value)) {
			continue
		}
		$candidate = [string]$entry.Value
		$source = $entry.Name
		break
	}
	if ($null -eq $candidate) {
		throw 'No test root base is available from RUNNER_TEMP or TEMP'
	}

	$name = "test root base ($source)"
	$trimmed = $candidate.TrimEnd('\')
	if (
		-not [IO.Path]::IsPathFullyQualified($candidate) -or
		$trimmed -notmatch '^[A-Za-z]:\\' -or
		$trimmed.Contains('/') -or
		$trimmed.Substring(2).Contains(':') -or
		$trimmed -match '[*?]'
	) {
		throw "$name must be a drive-qualified canonical local path"
	}
	if (-not [IO.Directory]::Exists($trimmed)) {
		throw "$name must identify an existing directory"
	}

	$longPath = Get-LongPath $trimmed
	if (-not [IO.Directory]::Exists($longPath)) {
		throw "$name must identify an existing directory"
	}
	$canonical = Assert-LocalPathSyntax $longPath $name

	foreach ($shared in @(
		[Environment]::GetFolderPath(
			[Environment+SpecialFolder]::ProgramFiles),
		[Environment]::GetFolderPath(
			[Environment+SpecialFolder]::ProgramFilesX86),
		[Environment]::GetFolderPath(
			[Environment+SpecialFolder]::Windows),
		'C:\msys64'
	)) {
		if ([string]::IsNullOrEmpty($shared)) {
			continue
		}
		$sharedRoot = $shared.TrimEnd('\')
		if (
			[string]::Equals(
				$canonical,
				$sharedRoot,
				[StringComparison]::OrdinalIgnoreCase) -or
			$canonical.StartsWith(
				"$sharedRoot\",
				[StringComparison]::OrdinalIgnoreCase)
		) {
			throw "$name resolves to a shared installation root"
		}
	}
	return $canonical
}

function Get-TestVolumeFileSystem {
	param([Parameter(Mandatory = $true)][string]$Path)

	$root = [IO.Path]::GetPathRoot($Path)
	if ([string]::IsNullOrEmpty($root)) {
		throw "Cannot determine the volume root of '$Path'"
	}
	return [IO.DriveInfo]::new($root).DriveFormat
}

# GitHub-hosted runners point TEMP at a DOS 8.3 path such as
# C:\Users\RUNNER~1\AppData\Local\Temp. Production path validation rejects
# any 8.3-shaped segment that reaches it, so prefer RUNNER_TEMP and
# canonicalize the base explicitly rather than relying on the runtime to
# expand the alias first.
$script:AliasRejectionPattern =
	'short-name alias|relative or noncanonical path components'
$testRootBase = Resolve-TestRootBase `
	$env:RUNNER_TEMP ([IO.Path]::GetTempPath())
$testRoot = Join-Path $testRootBase (
	"gfw-sdk-bootstrap-tests-$([Guid]::NewGuid().ToString('N'))")
[void][IO.Directory]::CreateDirectory($testRoot)
try {
	$verifiedTestRoot = Assert-SafeExistingDirectory $testRoot 'test root'
	if ($verifiedTestRoot -cne $testRoot) {
		throw "The test root '$testRoot' is not its own canonical path"
	}
} catch {
	Remove-Item -LiteralPath $testRoot -Recurse -Force
	throw
}

$savedNoSystem = $env:GIT_CONFIG_NOSYSTEM
$savedGlobal = $env:GIT_CONFIG_GLOBAL
$env:GIT_CONFIG_NOSYSTEM = '1'
$env:GIT_CONFIG_GLOBAL = 'NUL'

try {
	$gitPath = (Get-Command git.exe -CommandType Application |
		Select-Object -First 1).Source
	if ([string]::IsNullOrEmpty($gitPath)) {
		throw 'git.exe is required for the offline fixtures'
	}

	$lock = Read-SdkLock $lockPath

	$sourceRepo = Join-Path $testRoot 'source'
	Invoke-TestGit $gitPath init --quiet $sourceRepo
	Invoke-TestGit $gitPath -C $sourceRepo config user.name 'SDK Test'
	Invoke-TestGit $gitPath -C $sourceRepo config user.email 'sdk-test@example.com'
	[IO.File]::WriteAllText(
		(Join-Path $sourceRepo 'base.txt'),
		"base`n",
		[Text.UTF8Encoding]::new($false))
	Invoke-TestGit $gitPath -C $sourceRepo add base.txt
	Invoke-TestGit $gitPath -C $sourceRepo commit --quiet -m base
	$fixtureParent = (& $gitPath -C $sourceRepo rev-parse HEAD).Trim()

	[void][IO.Directory]::CreateDirectory((Join-Path $sourceRepo 'bin'))
	[void][IO.Directory]::CreateDirectory(
		(Join-Path $sourceRepo 'var\lib\pacman\local'))
	[void][IO.Directory]::CreateDirectory(
		(Join-Path $sourceRepo 'var\lib\pacman\sync'))
	[IO.File]::WriteAllText(
		(Join-Path $sourceRepo 'bin\tool.exe'),
		"fixture`n",
		[Text.UTF8Encoding]::new($false))
	[IO.File]::WriteAllText(
		(Join-Path $sourceRepo 'var\lib\pacman\local\ALPM_DB_VERSION'),
		"9`n",
		[Text.UTF8Encoding]::new($false))
	[IO.File]::WriteAllText(
		(Join-Path $sourceRepo 'var\lib\pacman\sync\core.db'),
		"database`n",
		[Text.UTF8Encoding]::new($false))
	Invoke-TestGit $gitPath -C $sourceRepo add `
		bin/tool.exe `
		var/lib/pacman/local/ALPM_DB_VERSION `
		var/lib/pacman/sync/core.db
	Invoke-TestGit $gitPath -C $sourceRepo commit --quiet -m fixture
	$fixtureCommit = (& $gitPath -C $sourceRepo rev-parse HEAD).Trim()
	$fixtureTree = (& $gitPath -C $sourceRepo rev-parse 'HEAD^{tree}').Trim()

	$bareRepo = Join-Path $testRoot 'fixture.git'
	Invoke-TestGit $gitPath clone --quiet --bare $sourceRepo $bareRepo
	$headRef = (& $gitPath --git-dir=$bareRepo symbolic-ref HEAD).Trim()
	Invoke-TestGit -GitPath $gitPath -Arguments @(
		"--git-dir=$bareRepo", 'update-ref', '-d', $headRef)
	Invoke-TestGit $gitPath --git-dir=$bareRepo update-ref `
		refs/gfw-sdk/locked $fixtureCommit

	$fixtureManifest = Get-GitTreeManifest `
		-GitPath $gitPath `
		-GitDir $bareRepo `
		-Commit $fixtureCommit
	$commitText = & $gitPath --git-dir=$bareRepo cat-file commit $fixtureCommit
	$author = ($commitText | Where-Object { $_ -like 'author *' }).
		Substring(7)
	$committer = ($commitText | Where-Object { $_ -like 'committer *' }).
		Substring(10)
	$fixtureLock = [pscustomobject]@{
		commit = $fixtureCommit
		tree = $fixtureTree
		parent = $fixtureParent
		commit_metadata = [pscustomobject]@{
			author = $author
			committer = $committer
			subject = 'fixture'
		}
		manifest = [pscustomobject]@{
			sha256 = $fixtureManifest.Sha256
			entry_count = $fixtureManifest.EntryCount
			blob_count = $fixtureManifest.BlobCount
			tree_count = $fixtureManifest.TreeCount
			total_blob_bytes = $fixtureManifest.TotalBlobBytes
		}
		package_database = [pscustomobject]@{
			sha256 = $fixtureManifest.PackageDatabaseSha256
			entry_count = $fixtureManifest.PackageDatabaseEntryCount
			blob_count = $fixtureManifest.PackageDatabaseBlobCount
			tree_count = $fixtureManifest.PackageDatabaseTreeCount
			total_blob_bytes = $fixtureManifest.PackageDatabaseTotalBlobBytes
		}
	}

	function New-MaterializedFixture {
		param([Parameter(Mandatory = $true)][string]$Name)

		$indexPath = Join-Path $bareRepo 'index'
		if (Test-Path -LiteralPath $indexPath) {
			Remove-Item -LiteralPath $indexPath -Force
		}
		$worktree = Join-Path $testRoot $Name
		return New-VerifiedSdkWorktree `
			-GitPath $gitPath `
			-GitDir $bareRepo `
			-Commit $fixtureCommit `
			-SdkRoot $worktree `
			-Manifest $fixtureManifest
	}

	Invoke-Test 'production metadata lock is complete but pending' {
		Assert-ProductionSdkLock $lock
		Assert-Throws {
			Assert-ProductionSdkLock $lock -RequireApproval
		} 'not independently admitted'
	}

	Invoke-Test 'module exports only the gated bootstrap entry point' {
		$exports = @($bootstrapModule.ExportedCommands.Keys)
		Assert-Equal $exports.Count 1
		Assert-Equal $exports[0] 'Invoke-LockedSdkBootstrap'
	}

	Invoke-Test 'module file cannot be executed as a bootstrap script' {
		$output = & pwsh -NoProfile -NonInteractive -File $modulePath 2>&1
		$exitCode = $LASTEXITCODE
		if ($exitCode -eq 0) {
			throw "Direct module execution unexpectedly succeeded: $output"
		}
	}

	$stringFields = @(
		'format',
		'repository',
		'remote_url',
		'commit',
		'tree',
		'parent',
		'commit_metadata.author',
		'commit_metadata.committer',
		'commit_metadata.authored_at',
		'commit_metadata.committed_at',
		'commit_metadata.signature_status',
		'commit_metadata.subject',
		'manifest.canonicalization',
		'manifest.sha256',
		'manifest.total_blob_bytes',
		'package_database.scope.0',
		'package_database.scope.1',
		'package_database.canonicalization',
		'package_database.sha256',
		'package_database.total_blob_bytes',
		'admission.status'
	)
	$stringMutations = @(
		[pscustomobject]@{
			Name = 'empty-array'
			Value = [object[]]@()
		},
		[pscustomobject]@{
			Name = 'singleton-array'
			Value = [object[]]@('approved')
		},
		[pscustomobject]@{
			Name = 'object'
			Value = [pscustomobject]@{ value = 'approved' }
		},
		[pscustomobject]@{ Name = 'null'; Value = $null },
		[pscustomobject]@{ Name = 'number'; Value = 7L },
		[pscustomobject]@{ Name = 'boolean'; Value = $true }
	)
	foreach ($field in $stringFields) {
		foreach ($mutation in $stringMutations) {
			$testName = "JSON rejects $field as $($mutation.Name)"
			Invoke-Test $testName {
				$mutated = Copy-Lock $lock
				Set-LockValue $mutated $field $mutation.Value
				$fixtureName = 'type-' +
					($field -replace '[^A-Za-z0-9]', '-') + '-' +
					$mutation.Name
				$fixturePath = Write-LockFixture $mutated $fixtureName
				Assert-Throws {
					$parsed = Read-SdkLock $fixturePath
					Assert-ProductionSdkLock $parsed
				} 'JSON string|admission status'
			}
		}
	}

	foreach ($field in $stringFields) {
		$original = [string](Get-LockValue $lock $field)
		$semanticMutations = @(
			[pscustomobject]@{
				Name = 'leading-whitespace'
				Value = " $original"
			},
			[pscustomobject]@{
				Name = 'trailing-whitespace'
				Value = "$original "
			}
		)
		$caseVariant = $original.ToUpperInvariant()
		if ($caseVariant -ceq $original) {
			$caseVariant = $original.ToLowerInvariant()
		}
		if ($caseVariant -cne $original) {
			$semanticMutations += [pscustomobject]@{
				Name = 'case-variant'
				Value = $caseVariant
			}
		}
		foreach ($mutation in $semanticMutations) {
			Invoke-Test "lock rejects $field $($mutation.Name)" {
				$mutated = Copy-Lock $lock
				Set-LockValue $mutated $field $mutation.Value
				Assert-Throws {
					Assert-ProductionSdkLock $mutated
				} 'Unexpected|lowercase hexadecimal|timestamp|scope|admission|canonical'
			}
		}
	}

	foreach ($field in $stringFields) {
		foreach ($mutation in $stringMutations) {
			Invoke-Test "PowerShell rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $lock
				Set-LockValue $mutated $field $mutation.Value
				Assert-Throws {
					Assert-ProductionSdkLock $mutated
				} 'JSON string'
			}
		}
	}

	$numberFields = @(
		'manifest.entry_count',
		'manifest.blob_count',
		'manifest.tree_count',
		'package_database.entry_count',
		'package_database.blob_count',
		'package_database.tree_count'
	)
	$numberMutations = @(
		[pscustomobject]@{ Name = 'string'; Value = '1' },
		[pscustomobject]@{ Name = 'null'; Value = $null },
		[pscustomobject]@{ Name = 'boolean'; Value = $true },
		[pscustomobject]@{ Name = 'array'; Value = [object[]]@(1L) },
		[pscustomobject]@{
			Name = 'object'
			Value = [pscustomobject]@{ value = 1L }
		},
		[pscustomobject]@{ Name = 'fraction'; Value = [double]1.5 }
	)
	foreach ($field in $numberFields) {
		foreach ($mutation in $numberMutations) {
			Invoke-Test "JSON rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $lock
				Set-LockValue $mutated $field $mutation.Value
				$fixtureName = 'number-' +
					($field -replace '[^A-Za-z0-9]', '-') + '-' +
					$mutation.Name
				$fixturePath = Write-LockFixture $mutated $fixtureName
				Assert-Throws {
					$parsed = Read-SdkLock $fixturePath
					Assert-ProductionSdkLock $parsed
				} 'JSON number|JSON integer'
			}
		}
	}

	foreach ($field in $numberFields) {
		foreach ($mutation in $numberMutations) {
			Invoke-Test "PowerShell rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $lock
				Set-LockValue $mutated $field $mutation.Value
				Assert-Throws {
					Assert-ProductionSdkLock $mutated
				} 'JSON integer'
			}
		}
	}

	foreach ($mutation in @(
		[pscustomobject]@{ Name = 'string'; Value = 'scope' },
		[pscustomobject]@{ Name = 'number'; Value = 1L },
		[pscustomobject]@{ Name = 'null'; Value = $null },
		[pscustomobject]@{ Name = 'boolean'; Value = $true },
		[pscustomobject]@{
			Name = 'object'
			Value = [pscustomobject]@{ value = 'scope' }
		},
		[pscustomobject]@{ Name = 'empty'; Value = [object[]]@() },
		[pscustomobject]@{
			Name = 'singleton'
			Value = [object[]]@('var/lib/pacman/local')
		}
	)) {
		Invoke-Test "lock rejects scope as $($mutation.Name)" {
			$mutated = Copy-Lock $lock
			$mutated.package_database.scope = $mutation.Value
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'JSON array|scope'
		}
	}

	$approvedLock = New-ApprovedLock $lock
	$approvedStringFields = @(
		'admission.approved_by',
		'admission.approved_at',
		'admission.evidence.authority_repository',
		'admission.evidence.authority_ref',
		'admission.evidence.protected_base_commit',
		'admission.evidence.reviewed_source_commit',
		'admission.evidence.reviewed_source_tree',
		'admission.evidence.native_runner.provider',
		'admission.evidence.native_runner.image',
		'admission.evidence.native_runner.os',
		'admission.evidence.native_runner.os_architecture',
		'admission.evidence.native_runner.process_architecture',
		'admission.evidence.native_runner.evidence_uri'
	)
	foreach ($field in $approvedStringFields) {
		foreach ($mutation in $stringMutations) {
			Invoke-Test "JSON rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $approvedLock
				Set-LockValue $mutated $field $mutation.Value
				$fixtureName = 'evidence-' +
					($field -replace '[^A-Za-z0-9]', '-') + '-' +
					$mutation.Name
				$fixturePath = Write-LockFixture $mutated $fixtureName
				Assert-Throws {
					$parsed = Read-SdkLock $fixturePath
					Assert-ProductionSdkLock $parsed
				} 'JSON string'
			}
		}
	}

	foreach ($field in $approvedStringFields) {
		$original = [string](Get-LockValue $approvedLock $field)
		foreach ($mutation in @(
			[pscustomobject]@{
				Name = 'leading-whitespace'
				Value = " $original"
			},
			[pscustomobject]@{
				Name = 'trailing-whitespace'
				Value = "$original "
			},
			[pscustomobject]@{
				Name = 'case-variant'
				Value = $original.ToUpperInvariant()
			}
		)) {
			if ($mutation.Value -ceq $original) {
				continue
			}
			Invoke-Test "evidence rejects $field $($mutation.Name)" {
				$mutated = Copy-Lock $approvedLock
				Set-LockValue $mutated $field $mutation.Value
				Assert-Throws {
					Assert-ProductionSdkLock $mutated
				} 'timestamp|lowercase hexadecimal|protected|runner|URI|approver'
			}
		}
	}

	foreach ($field in @(
		'admission.evidence.base_protected',
		'admission.evidence.required_checks_passed'
	)) {
		foreach ($mutation in @(
			[pscustomobject]@{ Name = 'string'; Value = 'true' },
			[pscustomobject]@{ Name = 'number'; Value = 1L },
			[pscustomobject]@{ Name = 'null'; Value = $null },
			[pscustomobject]@{
				Name = 'array'
				Value = [object[]]@($true)
			},
			[pscustomobject]@{
				Name = 'object'
				Value = [pscustomobject]@{ value = $true }
			}
		)) {
			Invoke-Test "JSON rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $approvedLock
				Set-LockValue $mutated $field $mutation.Value
				$fixtureName = 'boolean-' +
					($field -replace '[^A-Za-z0-9]', '-') + '-' +
					$mutation.Name
				$fixturePath = Write-LockFixture $mutated $fixtureName
				Assert-Throws {
					$parsed = Read-SdkLock $fixturePath
					Assert-ProductionSdkLock $parsed
				} 'JSON boolean'
			}
		}
	}

	foreach ($mutation in @(
		[pscustomobject]@{ Name = 'string'; Value = 'check' },
		[pscustomobject]@{ Name = 'number'; Value = 1L },
		[pscustomobject]@{ Name = 'null'; Value = $null },
		[pscustomobject]@{ Name = 'boolean'; Value = $true },
		[pscustomobject]@{
			Name = 'object'
			Value = [pscustomobject]@{ value = 'check' }
		},
		[pscustomobject]@{ Name = 'empty'; Value = [object[]]@() }
	)) {
		Invoke-Test "JSON rejects required_checks as $($mutation.Name)" {
			$mutated = Copy-Lock $approvedLock
			Set-LockValue $mutated `
				'admission.evidence.required_checks' $mutation.Value
			$fixturePath = Write-LockFixture $mutated `
				"checks-$($mutation.Name)"
			Assert-Throws {
				$parsed = Read-SdkLock $fixturePath
				Assert-ProductionSdkLock $parsed
			} 'JSON array|must name (the protected )?required check'
		}
	}

	foreach ($field in @(
		'admission.evidence',
		'admission.evidence.native_runner'
	)) {
		foreach ($mutation in @(
			[pscustomobject]@{ Name = 'string'; Value = 'object' },
			[pscustomobject]@{ Name = 'number'; Value = 1L },
			[pscustomobject]@{ Name = 'null'; Value = $null },
			[pscustomobject]@{ Name = 'boolean'; Value = $true },
			[pscustomobject]@{
				Name = 'array'
				Value = [object[]]@()
			}
		)) {
			Invoke-Test "JSON rejects $field as $($mutation.Name)" {
				$mutated = Copy-Lock $approvedLock
				Set-LockValue $mutated $field $mutation.Value
				$fixtureName = 'object-' +
					($field -replace '[^A-Za-z0-9]', '-') + '-' +
					$mutation.Name
				$fixturePath = Write-LockFixture $mutated $fixtureName
				Assert-Throws {
					$parsed = Read-SdkLock $fixturePath
					Assert-ProductionSdkLock $parsed
				} 'JSON object'
			}
		}
	}

	$objectPaths = @(
		'commit_metadata',
		'manifest',
		'package_database',
		'admission'
	)
	foreach ($path in $objectPaths) {
		Invoke-Test "lock rejects missing property in $path" {
			$mutated = Copy-Lock $lock
			$object = Get-LockValue $mutated $path
			$firstProperty = @($object.PSObject.Properties.Name)[0]
			$object.PSObject.Properties.Remove($firstProperty)
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'property count'
		}
		Invoke-Test "lock rejects extra property in $path" {
			$mutated = Copy-Lock $lock
			$object = Get-LockValue $mutated $path
			$object | Add-Member -NotePropertyName extra `
				-NotePropertyValue 'forbidden'
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'property count'
		}
		Invoke-Test "lock rejects empty object at $path" {
			$mutated = Copy-Lock $lock
			Set-LockValue $mutated $path ([pscustomobject]@{})
			$escaped = [regex]::Escape("lock.$path")
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} "^$escaped has an unexpected property count$"
		}
	}

	foreach ($path in @(
		'admission.evidence',
		'admission.evidence.native_runner'
	)) {
		Invoke-Test "lock rejects missing property in $path" {
			$mutated = Copy-Lock $approvedLock
			$object = Get-LockValue $mutated $path
			$firstProperty = @($object.PSObject.Properties.Name)[0]
			$object.PSObject.Properties.Remove($firstProperty)
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'property count'
		}
		Invoke-Test "lock rejects extra property in $path" {
			$mutated = Copy-Lock $approvedLock
			$object = Get-LockValue $mutated $path
			$object | Add-Member -NotePropertyName extra `
				-NotePropertyValue 'forbidden'
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'property count'
		}
		Invoke-Test "lock rejects empty object at $path" {
			$mutated = Copy-Lock $approvedLock
			Set-LockValue $mutated $path ([pscustomobject]@{})
			$escaped = [regex]::Escape("lock.$path")
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} "^$escaped has an unexpected property count$"
		}
	}

	Invoke-Test 'JSON rejects duplicate nested properties' {
		$json = [IO.File]::ReadAllText(
			$lockPath,
			[Text.UTF8Encoding]::new($false, $true))
		$json = $json.Replace(
			'    "status": "pending-independent-review",',
			"    `"status`": `"pending-independent-review`",`n" +
				'    "status": "pending-independent-review",')
		$duplicatePath = Join-Path $testRoot 'duplicate-property.json'
		[IO.File]::WriteAllText(
			$duplicatePath,
			$json,
			[Text.UTF8Encoding]::new($false))
		Assert-Throws {
			Read-SdkLock $duplicatePath
		} 'Duplicate JSON property'
	}

	Invoke-Test 'entry point fails before root or network while pending' {
		Assert-Throws {
			& $entrypointPath `
				-RunnerTemp relative `
				-RunId invalid `
				-RunAttempt invalid `
				-Job invalid `
				-MatrixDiscriminator invalid `
				-RunnerOs invalid `
				-RunnerArch invalid `
				-RunnerEnvironment invalid `
				-GitHubPath invalid `
				-GitHubEnv invalid `
				-GitHubOutput invalid
		} 'not independently admitted'
	}

	Invoke-Test 'pending admission precedes malicious parameter types' {
		Assert-Throws {
			Invoke-LockedSdkBootstrap `
				-RunnerTemp ([object[]]@()) `
				-RunId ([pscustomobject]@{ value = '1' }) `
				-RunAttempt $null `
				-Job $true `
				-MatrixDiscriminator 7L `
				-RunnerOs ([object[]]@('Windows')) `
				-RunnerArch ([object[]]@()) `
				-RunnerEnvironment $false `
				-GitHubPath ([pscustomobject]@{}) `
				-GitHubEnv $null `
				-GitHubOutput ([object[]]@('C:\sentinel'))
		} 'not independently admitted'
	}

	Invoke-Test 'pending lock stops every side-effect sentinel' {
		Assert-GateStopsBeforeSideEffects $lockPath `
			'not independently admitted'
	}

	Invoke-Test 'malformed lock stops every side-effect sentinel' {
		$malformed = Copy-Lock $lock
		$malformed.admission.status = [object[]]@('approved')
		$malformedPath = Write-LockFixture $malformed 'malformed-ordering'
		Assert-GateStopsBeforeSideEffects $malformedPath 'JSON string'
	}

	Invoke-Test 'callers cannot supply a lock path or approval switch' {
		Assert-Throws {
			Invoke-LockedSdkBootstrap `
				-LockPath $lockPath `
				-RequireApproval:$false `
				-RunnerTemp 'C:\sentinel' `
				-RunId '1' `
				-RunAttempt '1' `
				-Job 'sentinel' `
				-MatrixDiscriminator 'sentinel' `
				-RunnerOs 'Windows' `
				-RunnerArch 'ARM64' `
				-RunnerEnvironment 'github-hosted' `
				-GitHubPath 'C:\sentinel\path' `
				-GitHubEnv 'C:\sentinel\env' `
				-GitHubOutput 'C:\sentinel\output'
		} 'parameter.*LockPath|parameter.*RequireApproval'
	}

	Invoke-Test 'native ARM64 platform facts pass policy validation' {
		Assert-RunnerPlatformFacts $true 'Arm64' 'Arm64' $false
	}

	Invoke-Test 'x64 process on ARM64 fails before side effects' {
		Assert-Throws {
			Assert-RunnerPlatformFacts $true 'Arm64' 'X64' $false
		} 'native Windows ARM64 process'
	}

	Invoke-Test 'non-Windows platform fails before side effects' {
		Assert-Throws {
			Assert-RunnerPlatformFacts $false 'Arm64' 'Arm64' $false
		} 'native Windows ARM64 process'
	}

	Invoke-Test 'x64 operating system fails before side effects' {
		Assert-Throws {
			Assert-RunnerPlatformFacts $true 'X64' 'Arm64' $false
		} 'native Windows ARM64 process'
	}

	Invoke-Test 'elevated identity fails before side effects' {
		Assert-Throws {
			Assert-RunnerPlatformFacts $true 'Arm64' 'Arm64' $true
		} 'elevated runner token'
	}

	Invoke-Test 'wrong repository is rejected' {
		$mutated = Copy-Lock $lock
		$mutated.repository = 'attacker/git-sdk-arm64'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'repository'
	}

	Invoke-Test 'wrong host is rejected' {
		$mutated = Copy-Lock $lock
		$mutated.remote_url =
			'https://example.invalid/git-for-windows/git-sdk-arm64.git'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'remote_url'
	}

	Invoke-Test 'mutable branch and tag fields are rejected' {
		foreach ($name in 'ref', 'tag') {
			$mutated = Copy-Lock $lock
			$mutated | Add-Member -NotePropertyName $name `
				-NotePropertyValue 'main'
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'unexpected property'
		}
		$mutated = Copy-Lock $lock
		$mutated.commit = 'main'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'lowercase hexadecimal'
	}

	Invoke-Test 'wrong production commit and tree are rejected' {
		$mutated = Copy-Lock $lock
		$mutated.commit = '0000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'commit'
		$mutated = Copy-Lock $lock
		$mutated.tree = '0000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'tree'
	}

	Invoke-Test 'wrong and truncated production manifests are rejected' {
		$mutated = Copy-Lock $lock
		$mutated.manifest.sha256 =
			'0000000000000000000000000000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'manifest'
		$mutated = Copy-Lock $lock
		$mutated.manifest.entry_count--
		Assert-Throws {
			Assert-ProductionSdkLock $mutated
		} 'counts|manifest'
	}

	Invoke-Test 'package update and network mutations are rejected' {
		foreach ($name in 'package_update', 'network_source') {
			$mutated = Copy-Lock $lock
			$mutated | Add-Member -NotePropertyName $name `
				-NotePropertyValue 'enabled'
			Assert-Throws {
				Assert-ProductionSdkLock $mutated
			} 'unexpected property'
		}
	}

	Invoke-Test 'offline fixture identity and manifest verify' {
		Assert-GitObjectIdentity `
			-GitPath $gitPath `
			-GitDir $bareRepo `
			-Lock $fixtureLock
		Assert-ManifestMatchesLock $fixtureManifest $fixtureLock
		Assert-NoLfsPointers $gitPath $bareRepo $fixtureCommit
	}

	Invoke-Test 'ambient Git controls cannot poison verification' {
		$savedParameters = $env:GIT_CONFIG_PARAMETERS
		$savedExecPath = $env:GIT_EXEC_PATH
		$savedTemplate = $env:GIT_TEMPLATE_DIR
		try {
			$env:GIT_CONFIG_PARAMETERS =
				"'remote.origin.vcs=__gfw_missing_helper__'"
			$env:GIT_EXEC_PATH = Join-Path $testRoot 'missing-exec-path'
			$env:GIT_TEMPLATE_DIR = Join-Path $testRoot 'missing-template'
			Assert-GitObjectIdentity `
				-GitPath $gitPath `
				-GitDir $bareRepo `
				-Lock $fixtureLock
			$poisonedManifest = Get-GitTreeManifest `
				-GitPath $gitPath `
				-GitDir $bareRepo `
				-Commit $fixtureCommit
			Assert-ManifestMatchesLock $poisonedManifest $fixtureLock
		} finally {
			$env:GIT_CONFIG_PARAMETERS = $savedParameters
			$env:GIT_EXEC_PATH = $savedExecPath
			$env:GIT_TEMPLATE_DIR = $savedTemplate
		}
	}

	Invoke-Test 'verified fixture materializes without executing payloads' {
		$fixtureWorktree = Join-Path $testRoot 'materialized-sdk'
		$result = New-MaterializedFixture 'materialized-sdk'
		Assert-Equal $result $fixtureWorktree
		Assert-Equal @(
			Get-ChildItem -LiteralPath $fixtureWorktree -File -Recurse -Force
		).Count $fixtureManifest.BlobCount
		Assert-Equal @(
			Get-ChildItem -LiteralPath $fixtureWorktree -Directory -Recurse -Force
		).Count $fixtureManifest.TreeCount
	}

	Invoke-Test 'same-count replacement is rejected' {
		$worktree = New-MaterializedFixture 'same-count-replacement'
		Remove-Item -LiteralPath (Join-Path $worktree 'bin\tool.exe') -Force
		[IO.File]::WriteAllText(
			(Join-Path $worktree 'bin\other.exe'),
			"fixture`n",
			[Text.UTF8Encoding]::new($false))
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'extra file|missing locked'
	}

	Invoke-Test 'same-size byte change is rejected' {
		$worktree = New-MaterializedFixture 'byte-change'
		[IO.File]::WriteAllText(
			(Join-Path $worktree 'bin\tool.exe'),
			"FIXTURE`n",
			[Text.UTF8Encoding]::new($false))
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'bytes differ'
	}

	Invoke-Test 'extra materialized file is rejected' {
		$worktree = New-MaterializedFixture 'extra-file'
		[IO.File]::WriteAllText(
			(Join-Path $worktree 'extra.txt'),
			"extra`n",
			[Text.UTF8Encoding]::new($false))
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'extra file'
	}

	Invoke-Test 'missing materialized file is rejected' {
		$worktree = New-MaterializedFixture 'missing-file'
		Remove-Item -LiteralPath (Join-Path $worktree 'bin\tool.exe') -Force
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'missing locked'
	}

	Invoke-Test 'index mode drift is rejected' {
		$worktree = New-MaterializedFixture 'index-mode'
		Invoke-TestGit $gitPath `
			--git-dir=$bareRepo `
			--work-tree=$worktree `
			update-index `
			--chmod=+x `
			bin/tool.exe
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'index differs'
	}

	Invoke-Test 'case-only filesystem alias is rejected' {
		$worktree = New-MaterializedFixture 'case-alias'
		$binPath = Join-Path $worktree 'bin'
		$temporaryPath = Join-Path $worktree 'bin-temporary'
		Rename-Item -LiteralPath $binPath -NewName 'bin-temporary'
		Rename-Item -LiteralPath $temporaryPath -NewName 'BIN'
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'extra directory|extra file|missing locked'
	}

	Invoke-Test 'unexpected Git control directory is rejected' {
		$worktree = New-MaterializedFixture 'git-control'
		[void][IO.Directory]::CreateDirectory((Join-Path $worktree '.git'))
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'Windows-unsafe Git path'
	}

	Invoke-Test 'alternate data stream is rejected' {
		$worktree = New-MaterializedFixture 'alternate-stream'
		$file = Join-Path $worktree 'bin\tool.exe'
		$fileSystem = Get-TestVolumeFileSystem $testRoot
		if ($fileSystem -cne 'NTFS') {
			throw "The test volume is '$fileSystem'; alternate data " +
				'stream coverage requires the expected NTFS environment'
		}
		try {
			[IO.File]::WriteAllText(
				"$file`:probe",
				"probe`n",
				[Text.UTF8Encoding]::new($false))
		} catch [System.NotSupportedException] {
			throw "The NTFS test volume refused an alternate data " +
				"stream at '$file': $($_.Exception.Message)"
		}
		if ($null -eq (Get-Item -LiteralPath $file -Stream probe)) {
			throw "The alternate data stream fixture at '$file' is absent"
		}
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'alternate data stream'
	}

	Invoke-Test 'hardlink alias is rejected' {
		$worktree = New-MaterializedFixture 'hardlink-alias'
		$file = Join-Path $worktree 'bin\tool.exe'
		$linkSource = Join-Path $testRoot 'hardlink-alias-source.bin'
		[IO.File]::WriteAllText(
			$linkSource,
			"fixture`n",
			[Text.UTF8Encoding]::new($false))
		Remove-Item -LiteralPath $file -Force
		New-TestHardLink $file $linkSource
		$linked = Get-TestFileFacts $file
		$source = Get-TestFileFacts $linkSource
		Assert-Equal $linked.Links 2
		Assert-Equal $source.Links 2
		Assert-Equal $linked.Identity $source.Identity
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'Materialized file is a hardlink alias'
	}

	Invoke-Test 'repeated file identity is rejected without a hardlink' {
		$identityPath = Join-Path $testRoot 'identity-collision.bin'
		[IO.File]::WriteAllText(
			$identityPath,
			"fixture`n",
			[Text.UTF8Encoding]::new($false))
		$facts = Get-TestFileFacts $identityPath
		Assert-Equal $facts.Links 1
		$expected = @(
			$fixtureManifest.Entries |
				Where-Object { $_.Path -ceq 'bin/tool.exe' }
		)[0]
		$identities = [Collections.Generic.HashSet[string]]::new(
			[StringComparer]::Ordinal)
		$oid = Get-GitBlobHash $identityPath $expected.Size $identities
		Assert-Equal $oid $expected.Oid
		Assert-Equal $identities.Count 1
		Assert-Throws {
			Get-GitBlobHash $identityPath $expected.Size $identities
		} 'Materialized files alias the same file'
		Assert-Equal $identities.Count 1
	}

	Invoke-Test 'reparse point in materialized tree is rejected' {
		$worktree = New-MaterializedFixture 'materialized-reparse'
		$target = Join-Path $testRoot 'materialized-reparse-target'
		[void][IO.Directory]::CreateDirectory($target)
		New-TestJunction (Join-Path $worktree 'junction') $target
		Assert-Throws {
			Assert-MaterializedSdkTree `
				$gitPath $bareRepo $worktree $fixtureManifest
		} 'reparse point'
	}

	Invoke-Test 'gitattributes CRLF transformation is rejected' {
		$eolRepo = Join-Path $testRoot 'eol-source'
		Invoke-TestGit $gitPath init --quiet $eolRepo
		Invoke-TestGit $gitPath -C $eolRepo config user.name 'SDK Test'
		Invoke-TestGit $gitPath -C $eolRepo config user.email `
			'sdk-test@example.com'
		[IO.File]::WriteAllText(
			(Join-Path $eolRepo '.gitattributes'),
			"*.txt text eol=crlf`n",
			[Text.UTF8Encoding]::new($false))
		[IO.File]::WriteAllText(
			(Join-Path $eolRepo 'payload.txt'),
			"one`ntwo`n",
			[Text.UTF8Encoding]::new($false))
		Invoke-TestGit $gitPath -C $eolRepo add .gitattributes payload.txt
		Invoke-TestGit $gitPath -C $eolRepo commit --quiet -m eol
		$eolCommit = (& $gitPath -C $eolRepo rev-parse HEAD).Trim()
		$eolBare = Join-Path $testRoot 'eol.git'
		Invoke-TestGit $gitPath clone --quiet --bare $eolRepo $eolBare
		$eolManifest = Get-GitTreeManifest `
			$gitPath $eolBare $eolCommit
		Assert-Throws {
			New-VerifiedSdkWorktree `
				$gitPath `
				$eolBare `
				$eolCommit `
				(Join-Path $testRoot 'eol-worktree') `
				$eolManifest
		} 'size differs|bytes differ'
	}

	Invoke-Test 'offline fixture rejects wrong commit and tree' {
		$mutated = Copy-Lock $fixtureLock
		$mutated.commit = '0000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-GitObjectIdentity $gitPath $bareRepo $mutated
		} 'ref|commit'
		$mutated = Copy-Lock $fixtureLock
		$mutated.tree = '0000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-GitObjectIdentity $gitPath $bareRepo $mutated
		} 'tree'
	}

	Invoke-Test 'offline fixture rejects manifest mismatch and truncation' {
		$mutated = Copy-Lock $fixtureLock
		$mutated.manifest.sha256 =
			'0000000000000000000000000000000000000000000000000000000000000000'
		Assert-Throws {
			Assert-ManifestMatchesLock $fixtureManifest $mutated
		} 'complete Git tree manifest'
		$mutated = Copy-Lock $fixtureLock
		$mutated.manifest.entry_count--
		Assert-Throws {
			Assert-ManifestMatchesLock $fixtureManifest $mutated
		} 'complete Git tree manifest'

		$record = "100644`tblob`t$fixtureCommit`t1`tfile"
		$truncated = [Text.UTF8Encoding]::new($false).GetBytes($record)
		Assert-Throws {
			Get-TreeManifestFromBytes $truncated
		} 'truncated'
	}

	Invoke-Test 'duplicate and case-colliding paths are rejected' {
		$oid = '1111111111111111111111111111111111111111'
		$duplicate = New-TreeRecordBytes @(
			"100644`tblob`t$oid`t1`tdup.txt",
			"100644`tblob`t$oid`t1`tdup.txt"
		)
		Assert-Throws {
			Get-TreeManifestFromBytes $duplicate
		} 'Duplicate Git path'

		$collision = New-TreeRecordBytes @(
			"100644`tblob`t$oid`t1`tFile.txt",
			"100644`tblob`t$oid`t1`tfile.txt"
		)
		Assert-Throws {
			Get-TreeManifestFromBytes $collision
		} 'Case-colliding Git path'
	}

	Invoke-Test 'submodule symlink and noncanonical paths are rejected' {
		$oid = '2222222222222222222222222222222222222222'
		$submodule = New-TreeRecordBytes @(
			"160000`tcommit`t$oid`t-`tsubmodule"
		)
		Assert-Throws {
			Get-TreeManifestFromBytes $submodule
		} 'submodule indirection'

		$symlink = New-TreeRecordBytes @(
			"120000`tblob`t$oid`t6`tlink"
		)
		Assert-Throws {
			Get-TreeManifestFromBytes $symlink
		} 'Symbolic link indirection'

		$noncanonical = New-TreeRecordBytes @(
			"100644`tblob`t$oid`t1`ta/../escape"
		)
		Assert-Throws {
			Get-TreeManifestFromBytes $noncanonical
		} 'Windows-unsafe Git path'
	}

	Invoke-Test 'Git LFS pointers are rejected' {
		[IO.File]::WriteAllText(
			(Join-Path $sourceRepo 'pointer.dat'),
			"version https://git-lfs.github.com/spec/v1`n" +
				"oid sha256:" + ('0' * 64) + "`nsize 1`n",
			[Text.UTF8Encoding]::new($false))
		Invoke-TestGit $gitPath -C $sourceRepo add pointer.dat
		Invoke-TestGit $gitPath -C $sourceRepo commit --quiet -m pointer
		$lfsCommit = (& $gitPath -C $sourceRepo rev-parse HEAD).Trim()
		Assert-Throws {
			Assert-NoLfsPointers $gitPath (
				Join-Path $sourceRepo '.git') $lfsCommit
		} 'LFS pointer'
	}

	Invoke-Test 'moving branches and tags are rejected' {
		Assert-LockedRefs $gitPath $bareRepo $fixtureCommit
		Invoke-TestGit $gitPath --git-dir=$bareRepo update-ref `
			refs/heads/main $fixtureCommit
		Assert-Throws {
			Assert-LockedRefs $gitPath $bareRepo $fixtureCommit
		} 'mutable ref'
		Invoke-TestGit -GitPath $gitPath -Arguments @(
			"--git-dir=$bareRepo", 'update-ref', '-d', 'refs/heads/main')
		Invoke-TestGit $gitPath --git-dir=$bareRepo update-ref `
			refs/tags/latest $fixtureCommit
		Assert-Throws {
			Assert-LockedRefs $gitPath $bareRepo $fixtureCommit
		} 'mutable ref'
		Invoke-TestGit -GitPath $gitPath -Arguments @(
			"--git-dir=$bareRepo", 'update-ref', '-d', 'refs/tags/latest')
	}

	Invoke-Test 'relative device short-name and shared roots are rejected' {
		Assert-Throws {
			Assert-SafeExistingDirectory relative
		} 'drive-qualified'
		Assert-Throws {
			Assert-SafeExistingDirectory "\\?\$testRoot"
		} 'drive-qualified'
		Assert-Throws {
			Assert-SafeExistingDirectory 'C:\'
		} 'drive root'

		$shortAlias = Join-Path $testRoot 'RUNNER~1'
		[void][IO.Directory]::CreateDirectory($shortAlias)
		Assert-Throws {
			Assert-SafeExistingDirectory $shortAlias
		} 'short-name alias'
		Assert-Throws {
			Assert-SafeExistingDirectory 'C:\msys64'
		} 'shared'
	}

	Invoke-Test 'reparse and containment escapes are rejected' {
		$junctionTarget = Join-Path $testRoot 'junction-target'
		$junction = Join-Path $testRoot 'junction'
		[void][IO.Directory]::CreateDirectory($junctionTarget)
		New-TestJunction $junction $junctionTarget
		Assert-Throws {
			Assert-SafeExistingDirectory $junction
		} 'reparse point' -ForbiddenPattern $script:AliasRejectionPattern
		Assert-Throws {
			Assert-ContainedPath $testRoot (
				Join-Path $testRoot '..\escape')
		} 'not a strict child'
	}

	Invoke-Test 'private roots reject preexisting destinations' {
		$nonce = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
		$ownedRoot = New-PrivateSdkRoot `
			-RunnerTemp $testRoot `
			-RunId '123' `
			-RunAttempt '2' `
			-Job test `
			-MatrixDiscriminator arm64 `
			-Nonce $nonce
		$root = $ownedRoot.Path
		if (-not (Test-Path -LiteralPath $root -PathType Container)) {
			throw 'Private root was not created'
		}
		Assert-Throws {
			New-PrivateSdkRoot `
				-RunnerTemp $testRoot `
				-RunId '123' `
				-RunAttempt '2' `
				-Job test `
				-MatrixDiscriminator arm64 `
				-Nonce $nonce
		} 'already exists' -ForbiddenPattern $script:AliasRejectionPattern
		Remove-OwnedSdkRoot $ownedRoot
		if (Test-Path -LiteralPath $root) {
			throw 'Owned private root was not removed'
		}
	}

	Invoke-Test 'post-root failure removes only its sentinel-bound root' {
		$approvedPath = Write-LockFixture $approvedLock 'approved-cleanup'
		$message = & $bootstrapModule {
			param($ApprovedPath, $TestRoot)
			$nativePolicy = (Get-Item -LiteralPath `
				'Function:Assert-NativeRunnerPolicy').ScriptBlock
			$systemGit = (Get-Item -LiteralPath `
				'Function:Get-SystemGitPath').ScriptBlock
			try {
				Set-Item -LiteralPath 'Function:Assert-NativeRunnerPolicy' `
					-Value {}
				Set-Item -LiteralPath 'Function:Get-SystemGitPath' -Value {
					throw 'after-root-sentinel'
				}
				try {
					Invoke-LockedSdkBootstrapCore `
						-LockPath $ApprovedPath `
						-RunnerTemp $TestRoot `
						-RunId '777' `
						-RunAttempt '1' `
						-Job 'cleanup-test' `
						-MatrixDiscriminator 'arm64' `
						-RunnerOs 'Windows' `
						-RunnerArch 'ARM64' `
						-RunnerEnvironment 'github-hosted' `
						-GitHubPath (Join-Path $TestRoot 'path') `
						-GitHubEnv (Join-Path $TestRoot 'env') `
						-GitHubOutput (Join-Path $TestRoot 'output')
					throw 'Expected post-root failure'
				} catch {
					return $_.Exception.Message
				}
			} finally {
				Set-Item -LiteralPath 'Function:Assert-NativeRunnerPolicy' `
					-Value $nativePolicy
				Set-Item -LiteralPath 'Function:Get-SystemGitPath' `
					-Value $systemGit
			}
		} $approvedPath $testRoot
		if ($message -cmatch $script:AliasRejectionPattern) {
			throw "Post-root failure rejected the test root: $message"
		}
		if ($message -cnotmatch 'after-root-sentinel') {
			throw "Unexpected post-root failure: $message"
		}
		$residue = @(Get-ChildItem -LiteralPath $testRoot -Directory |
			Where-Object {
				$_.Name.StartsWith(
					'gfw-sdk-arm64-777-',
					[StringComparison]::Ordinal)
			})
		Assert-Equal $residue.Count 0
	}

	Invoke-Test 'system Git rejects writable installs and ignores PATH' {
		$poisonBin = Join-Path $testRoot 'poison-bin'
		[void][IO.Directory]::CreateDirectory($poisonBin)
		[IO.File]::WriteAllBytes(
			(Join-Path $poisonBin 'git.exe'),
			[byte[]](0x4d, 0x5a))
		$savedPath = $env:PATH
		try {
			$env:PATH = "$poisonBin;$savedPath"
			$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
			$principal = [Security.Principal.WindowsPrincipal]::new($identity)
			if ($principal.IsInRole(
				[Security.Principal.WindowsBuiltInRole]::Administrator
			)) {
				Assert-Throws {
					Get-SystemGitPath $testRoot
				} 'owned by the runner token|writable by an untrusted identity'
			} else {
				$trustedGit = Get-SystemGitPath $testRoot
				$expectedGit = Join-Path (
					[Environment]::GetFolderPath(
						[Environment+SpecialFolder]::ProgramFiles)
				) 'Git\cmd\git.exe'
				Assert-Equal $trustedGit $expectedGit
			}
		} finally {
			$env:PATH = $savedPath
		}
	}

	$aliasCandidate = 'C:\PROGRA~1'
	$aliasExpansion = $null
	if ([IO.Directory]::Exists($aliasCandidate)) {
		$probeExpansion = Get-LongPath $aliasCandidate
		if ($probeExpansion -cne $aliasCandidate) {
			$aliasExpansion = $probeExpansion
		}
	}

	Invoke-Test 'test root base prefers RUNNER_TEMP over TEMP' {
		$preferred = Join-Path $testRoot 'runner-temp-preferred'
		$ignored = Join-Path $testRoot 'process-temp-ignored'
		[void][IO.Directory]::CreateDirectory($preferred)
		[void][IO.Directory]::CreateDirectory($ignored)
		Assert-Equal (Resolve-TestRootBase $preferred $ignored) $preferred
		Assert-Equal (Resolve-TestRootBase "$preferred\" $ignored) $preferred
	}

	Invoke-Test 'test root base falls back to TEMP without RUNNER_TEMP' {
		$fallback = Join-Path $testRoot 'process-temp-fallback'
		[void][IO.Directory]::CreateDirectory($fallback)
		foreach ($absent in @($null, '', '   ')) {
			Assert-Equal (Resolve-TestRootBase $absent $fallback) $fallback
		}
	}

	Invoke-Test 'test root base accepts a hosted RUNNER_TEMP shape' {
		$hosted = Join-Path $testRoot 'a\_temp'
		[void][IO.Directory]::CreateDirectory($hosted)
		Assert-Equal (Resolve-TestRootBase $hosted $null) $hosted
		Assert-Equal (Assert-LocalPathSyntax $hosted 'hosted base') $hosted
	}

	Invoke-Test 'test root base rejects a hosted short-name TEMP shape' {
		$aliasShaped = Join-Path $testRoot `
			'hosted\Users\RUNNER~1\AppData\Local\Temp'
		[void][IO.Directory]::CreateDirectory($aliasShaped)
		foreach ($selection in @(
			[pscustomobject]@{ Runner = $aliasShaped; Process = $null },
			[pscustomobject]@{ Runner = $null; Process = $aliasShaped }
		)) {
			Assert-Throws {
				Resolve-TestRootBase $selection.Runner $selection.Process
			} 'short-name alias'
		}
	}

	if ($null -ne $aliasExpansion) {
		Invoke-Test 'test root base canonicalizes an available 8.3 alias' {
			Assert-Equal $aliasExpansion ([Environment]::GetFolderPath(
				[Environment+SpecialFolder]::ProgramFiles))
			Assert-Throws {
				Assert-LocalPathSyntax $aliasCandidate 'alias probe'
			} $script:AliasRejectionPattern
			Assert-Throws {
				Resolve-TestRootBase $aliasCandidate $null
			} 'shared installation root'
		}
	} else {
		Invoke-Test 'DOS 8.3 alias canonicalization is unavailable here' {
			if ([IO.Directory]::Exists($aliasCandidate)) {
				throw "'$aliasCandidate' exists but did not expand"
			}
			Assert-Throws {
				Get-LongPath $aliasCandidate
			} 'Cannot canonicalize path'
		}
	}

	Invoke-Test 'test root base preserves a safe non-alias path' {
		$control = Join-Path $testRoot 'non-alias-control-directory'
		[void][IO.Directory]::CreateDirectory($control)
		Assert-Equal (Get-LongPath $control) $control
		Assert-Equal (Resolve-TestRootBase $control $null) $control
		$windowsRoot = [Environment]::GetFolderPath(
			[Environment+SpecialFolder]::Windows)
		$windowsLong = Get-LongPath $windowsRoot
		if (-not [string]::Equals(
			$windowsRoot.TrimEnd('\'),
			$windowsLong,
			[StringComparison]::OrdinalIgnoreCase
		)) {
			throw "Canonicalization rewrote '$windowsRoot' to '$windowsLong'"
		}
	}

	Invoke-Test 'test root base rejects malformed and missing inputs' {
		foreach ($bad in @(
			'relative',
			'C:\',
			"\\?\$testRoot",
			(Join-Path $testRoot 'nonexistent-base'),
			(Join-Path $testRoot '..\escape'),
			(Join-Path $testRoot 'wild*card')
		)) {
			Assert-Throws {
				Resolve-TestRootBase $bad $null
			} 'drive-qualified|existing directory'
		}
		Assert-Throws {
			Resolve-TestRootBase ([object[]]@()) $testRoot
		} '^RUNNER_TEMP must be a string path$'
		Assert-Throws {
			Resolve-TestRootBase $null ([pscustomobject]@{ value = 'x' })
		} '^TEMP must be a string path$'
		Assert-Throws {
			Resolve-TestRootBase $null $null
		} '^No test root base is available from RUNNER_TEMP or TEMP$'
	}

	Invoke-Test 'test root base rejects shared installation roots' {
		$checked = 0
		foreach ($shared in @(
			[Environment]::GetFolderPath(
				[Environment+SpecialFolder]::ProgramFiles),
			[Environment]::GetFolderPath(
				[Environment+SpecialFolder]::ProgramFilesX86),
			[Environment]::GetFolderPath(
				[Environment+SpecialFolder]::Windows)
		)) {
			if (
				[string]::IsNullOrEmpty($shared) -or
				-not [IO.Directory]::Exists($shared)
			) {
				continue
			}
			$checked++
			Assert-Throws {
				Resolve-TestRootBase $shared $null
			} 'shared installation root'
		}
		if ($checked -eq 0) {
			throw 'No shared installation root was available to reject'
		}
	}

	Invoke-Test 'composed test root is canonical and alias free' {
		Assert-Equal (
			Assert-SafeExistingDirectory $testRoot 'test root') $testRoot
		Assert-Equal (Get-LongPath $testRoot) $testRoot
		Assert-Equal (Assert-LocalPathSyntax $testRoot 'test root') $testRoot
		foreach ($segment in $testRoot.Substring(3).Split('\')) {
			if ($segment -cmatch '^[^~\\]{1,6}~[0-9](?:\.[^.\\]{0,3})?$') {
				throw "The test root segment '$segment' is a DOS alias"
			}
		}
	}

	Invoke-Test 'expected-message matching is case sensitive' {
		Assert-Throws {
			Assert-ProductionSdkLock $lock -RequireApproval
		} 'not independently admitted'
		Assert-Throws {
			Assert-Throws {
				Assert-ProductionSdkLock $lock -RequireApproval
			} 'NOT INDEPENDENTLY ADMITTED'
		} "^Expected 'NOT INDEPENDENTLY ADMITTED', got '"
	}

	Invoke-Test 'expected-message matching honours forbidden patterns' {
		Assert-Throws {
			Assert-Throws {
				Assert-ProductionSdkLock $lock -RequireApproval
			} 'not independently admitted' -ForbiddenPattern 'independently'
		} "^Expected no 'independently', got '"
		Assert-Throws {
			Assert-ProductionSdkLock $lock -RequireApproval
		} 'not independently admitted' -ForbiddenPattern 'INDEPENDENTLY'
	}

	Invoke-Test 'runtime source forbids cache package and extra network operations' {
		$runtimeSource = [IO.File]::ReadAllText($entrypointPath) +
			[IO.File]::ReadAllText($modulePath) +
			[IO.File]::ReadAllText($actionPath)
		if ($runtimeSource -match
			'(?i)setup-git-for-windows-sdk|actions/cache|Invoke-WebRequest|\bcurl(?:\.exe)?\b|\bwget(?:\.exe)?\b') {
			throw 'Forbidden external download or cache operation found'
		}
		if ($runtimeSource -match
			"(?im)^\s*['`"]?(?:pacman(?:\.exe)?|git\s+(?:pull|clone))\b") {
			throw 'Forbidden package or mutable Git operation found'
		}
		$fetches = [regex]::Matches($runtimeSource, "'fetch'").Count
		Assert-Equal $fetches 1
	}
} finally {
	$env:GIT_CONFIG_NOSYSTEM = $savedNoSystem
	$env:GIT_CONFIG_GLOBAL = $savedGlobal
	if (Test-Path -LiteralPath $testRoot) {
		Remove-Item -LiteralPath $testRoot -Recurse -Force
	}
}

Write-Host "$script:passed passed, $script:failed failed"
if ($script:failed -ne 0) {
	throw "$script:failed adversarial SDK bootstrap tests failed"
}
