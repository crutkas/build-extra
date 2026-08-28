$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actionRoot = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $actionRoot 'bootstrap.psm1'
$lockPath = Join-Path $actionRoot 'sdk-lock.json'
$entrypointPath = Join-Path $actionRoot 'bootstrap.ps1'
$actionPath = Join-Path $actionRoot 'action.yml'

Import-Module $modulePath -Force

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
		[Parameter(Mandatory = $true)][string]$Pattern
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
	if ($caught.Exception.Message -notmatch $Pattern) {
		throw "Expected '$Pattern', got '$($caught.Exception.Message)'"
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

	return $Lock |
		ConvertTo-Json -Depth 20 |
		ConvertFrom-Json -Depth 20
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

$testRoot = Join-Path ([IO.Path]::GetTempPath()) (
	"gfw-sdk-bootstrap-tests-$([Guid]::NewGuid().ToString('N'))")
[void](New-Item -ItemType Directory -Path $testRoot)

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

	[void](New-Item -ItemType Directory -Path (
		Join-Path $sourceRepo 'bin'))
	[void](New-Item -ItemType Directory -Path (
		Join-Path $sourceRepo 'var\lib\pacman\local'))
	[void](New-Item -ItemType Directory -Path (
		Join-Path $sourceRepo 'var\lib\pacman\sync'))
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

	Invoke-Test 'production metadata lock is complete but pending' {
		Assert-ProductionSdkLock $lock
		Assert-Throws {
			Assert-ProductionSdkLock $lock -RequireApproval
		} 'not independently admitted'
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
				-GitHubPath invalid `
				-GitHubEnv invalid `
				-GitHubOutput invalid
		} 'not independently admitted'
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
		$result = New-VerifiedSdkWorktree `
			-GitPath $gitPath `
			-GitDir $bareRepo `
			-Commit $fixtureCommit `
			-SdkRoot $fixtureWorktree `
			-Manifest $fixtureManifest
		Assert-Equal $result $fixtureWorktree
		Assert-Equal @(
			Get-ChildItem -LiteralPath $fixtureWorktree -File -Recurse -Force
		).Count $fixtureManifest.BlobCount
		Assert-Equal @(
			Get-ChildItem -LiteralPath $fixtureWorktree -Directory -Recurse -Force
		).Count $fixtureManifest.TreeCount
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
		[void](New-Item -ItemType Directory -Path $shortAlias)
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
		[void](New-Item -ItemType Directory -Path $junctionTarget)
		[void](New-Item -ItemType Junction -Path $junction `
			-Target $junctionTarget)
		Assert-Throws {
			Assert-SafeExistingDirectory $junction
		} 'reparse point'
		Assert-Throws {
			Assert-ContainedPath $testRoot (
				Join-Path $testRoot '..\escape')
		} 'not a strict child'
	}

	Invoke-Test 'private roots reject preexisting destinations' {
		$nonce = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
		$root = New-PrivateSdkRoot `
			-RunnerTemp $testRoot `
			-RunId 123 `
			-RunAttempt 2 `
			-Job test `
			-MatrixDiscriminator arm64 `
			-Nonce $nonce
		if (-not (Test-Path -LiteralPath $root -PathType Container)) {
			throw 'Private root was not created'
		}
		Assert-Throws {
			New-PrivateSdkRoot `
				-RunnerTemp $testRoot `
				-RunId 123 `
				-RunAttempt 2 `
				-Job test `
				-MatrixDiscriminator arm64 `
				-Nonce $nonce
		} 'already exists'
	}

	Invoke-Test 'system Git rejects writable installs and ignores PATH' {
		$poisonBin = Join-Path $testRoot 'poison-bin'
		[void](New-Item -ItemType Directory -Path $poisonBin)
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
