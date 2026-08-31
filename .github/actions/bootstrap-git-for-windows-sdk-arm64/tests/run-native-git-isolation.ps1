$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actionRoot = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $actionRoot 'bootstrap.psm1'
$bootstrapModule = Import-Module $modulePath -Force -PassThru
$scratch = Join-Path ([IO.Path]::GetTempPath()) (
	"gfw-sdk-native-git-$([Guid]::NewGuid().ToString('N'))")

function Invoke-RawGit {
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
	)

	$output = & $GitPath @Arguments 2>&1
	if ($LASTEXITCODE -ne 0) {
		throw "Git failed: git $($Arguments -join ' ')`n$output"
	}
	return $output
}

function Invoke-SafeGit {
	param(
		[Parameter(Mandatory = $true)][string]$GitPath,
		[Parameter(Mandatory = $true)][string[]]$Arguments,
		[int[]]$AllowedExitCodes = @(0)
	)

	return & $script:bootstrapModule {
		param($GitPath, $Arguments, $AllowedExitCodes)
		New-SafeGitProcess $GitPath $Arguments $AllowedExitCodes
	} $GitPath $Arguments $AllowedExitCodes
}

try {
	[void][IO.Directory]::CreateDirectory($scratch)
	& $bootstrapModule {
		param($Scratch)
		$script:PrivateTempPath = $Scratch
		$script:TrustedGitExecPath = $null
		$script:TrustedGitRuntimePath = $null
	} $scratch

	$hostileHooks = Join-Path $scratch 'hostile-hooks'
	[void][IO.Directory]::CreateDirectory($hostileHooks)
	$hookCanary = Join-Path $scratch 'hook-ran'
	$hookCanaryShellPath = $hookCanary.Replace('\', '/').Replace("'", "'\''")
	[IO.File]::WriteAllText(
		(Join-Path $hostileHooks 'pre-commit'),
		"#!/bin/sh`nprintf leak >'$hookCanaryShellPath'`n",
		[Text.UTF8Encoding]::new($false))
	$hostileHooksConfigPath = $hostileHooks.Replace('\', '/')
	$globalConfig = Join-Path $scratch 'hostile-global.config'
	$systemConfig = Join-Path $scratch 'hostile-system.config'
	[IO.File]::WriteAllText(
		$globalConfig,
		"[test]`n`tglobalLeak = yes`n[core]`n`thooksPath = $hostileHooksConfigPath`n",
		[Text.UTF8Encoding]::new($false))
	[IO.File]::WriteAllText(
		$systemConfig,
		"[test]`n`tsystemLeak = yes`n",
		[Text.UTF8Encoding]::new($false))

	$savedGitConfigEnvironment = @{}
	foreach ($entry in @(Get-ChildItem Env: | Where-Object {
		$_.Name.StartsWith('GIT_CONFIG_', [StringComparison]::Ordinal)
	})) {
		$savedGitConfigEnvironment[$entry.Name] = $entry.Value
		Remove-Item -LiteralPath "Env:$($entry.Name)"
	}
	$env:GIT_CONFIG_GLOBAL = $globalConfig
	$env:GIT_CONFIG_SYSTEM = $systemConfig
	try {
		$candidates = @(
			Get-Command git.exe -All -CommandType Application |
				Select-Object -ExpandProperty Source -Unique
		)
		$versions = [ordered]@{}
		foreach ($candidate in $candidates) {
			$version = (& $candidate --version).Trim()
			if (-not $versions.Contains($version)) {
				$versions[$version] = $candidate
			}
		}
		if ($versions.Count -eq 0) {
			throw 'No native Git executable is available'
		}

		foreach ($version in $versions.Keys) {
			$gitPath = $versions[$version]
			if (
				(Invoke-RawGit $gitPath config --global --get test.globalLeak) `
					-cne 'yes' -or
				(Invoke-RawGit $gitPath config --system --get test.systemLeak) `
					-cne 'yes'
			) {
				throw "The hostile config fixture is inactive for $gitPath"
			}

			$globalResult = Invoke-SafeGit `
				$gitPath @('config', '--global', '--get', 'test.globalLeak') @(1)
			$systemResult = Invoke-SafeGit `
				$gitPath @('config', '--system', '--get', 'test.systemLeak') @(1)
			if (
				$globalResult.ExitCode -ne 1 -or
				$globalResult.Stdout.Count -ne 0 -or
				$systemResult.ExitCode -ne 1 -or
				$systemResult.Stdout.Count -ne 0
			) {
				throw "User or system Git config leaked into $gitPath"
			}

			$repo = Join-Path $scratch (
				'repository-' + [Guid]::NewGuid().ToString('N'))
			[void](Invoke-SafeGit $gitPath @('init', '--quiet', $repo))
			[void](Invoke-SafeGit $gitPath @(
				'-C', $repo, 'config', 'user.name', 'SDK Test'))
			[void](Invoke-SafeGit $gitPath @(
				'-C', $repo, 'config', 'user.email', 'sdk-test@example.com'))
			[IO.File]::WriteAllText(
				(Join-Path $repo 'tracked.txt'),
				"tracked`n",
				[Text.UTF8Encoding]::new($false))
			[void](Invoke-SafeGit $gitPath @('-C', $repo, 'add', 'tracked.txt'))
			[void](Invoke-SafeGit $gitPath @(
				'-C', $repo, 'commit', '--quiet', '-m', 'isolated'))
			if (Test-Path -LiteralPath $hookCanary) {
				throw "A configured user hook executed under $gitPath"
			}
			if (@(
				Get-ChildItem -LiteralPath $scratch -Directory -Filter `
					'git-process-*'
			).Count -ne 0) {
				throw "Git process isolation files were not cleaned for $gitPath"
			}

			Write-Host "ok - $version at $gitPath"
		}
	} finally {
		foreach ($entry in @(Get-ChildItem Env: | Where-Object {
			$_.Name.StartsWith('GIT_CONFIG_', [StringComparison]::Ordinal)
		})) {
			Remove-Item -LiteralPath "Env:$($entry.Name)"
		}
		foreach ($name in $savedGitConfigEnvironment.Keys) {
			Set-Item -LiteralPath "Env:$name" `
				-Value $savedGitConfigEnvironment[$name]
		}
	}
} finally {
	if (Test-Path -LiteralPath $scratch) {
		Remove-Item -LiteralPath $scratch -Recurse -Force
	}
}
