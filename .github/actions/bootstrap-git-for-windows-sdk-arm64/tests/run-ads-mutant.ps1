$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actionRoot = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([IO.Path]::GetTempPath()) (
	"gfw-sdk-ads-mutant-$([Guid]::NewGuid().ToString('N'))")
$mutantRoot = Join-Path $scratch 'action'

try {
	[void][IO.Directory]::CreateDirectory($scratch)
	Copy-Item -LiteralPath $actionRoot -Destination $mutantRoot -Recurse

	$modulePath = Join-Path $mutantRoot 'bootstrap.psm1'
	$source = [IO.File]::ReadAllText($modulePath)
	$guardPattern = (@'
(?ms)^\t\tif \(\r?\n\t\t\t\$streams\.Count -ne 1 -or\r?\n\t\t\t\$streams\[0\]\.Stream -notin ':\$DATA', '\$DATA'\r?\n\t\t\) \{\r?\n\t\t\tthrow "The materialized SDK contains an alternate data stream at '\$relativePath'"\r?\n\t\t\}\r?\n
'@).Trim()
	$guardRegex = [regex]::new(
		$guardPattern,
		[Text.RegularExpressions.RegexOptions]::CultureInvariant)
	$guardMatches = $guardRegex.Matches($source)
	# MODE: argued. SCOPE: this file at this head. This count check is the
	# only protection against more than one matching production rejection:
	# Replace(..., 1) removes only the first, so a clean kill could leave a
	# second rejection site unmutated.
	if ($guardMatches.Count -ne 1) {
		throw "Expected exactly one production ADS rejection; found $($guardMatches.Count)"
	}
	$mutated = $guardRegex.Replace($source, '', 1)
	[IO.File]::WriteAllText(
		$modulePath,
		$mutated,
		[Text.UTF8Encoding]::new($false))

	$info = [Diagnostics.ProcessStartInfo]::new()
	$info.FileName = [Environment]::ProcessPath
	$info.UseShellExecute = $false
	$info.RedirectStandardOutput = $true
	$info.RedirectStandardError = $true
	foreach ($argument in @(
		'-NoLogo',
		'-NoProfile',
		'-NonInteractive',
		'-File',
		(Join-Path $mutantRoot 'tests\run.ps1'),
		'-SkipMutationChecks'
	)) {
		[void]$info.ArgumentList.Add($argument)
	}

	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $info
	try {
		if (-not $process.Start()) {
			throw 'Could not start the ADS mutation test process'
		}
		$stdoutTask = $process.StandardOutput.ReadToEndAsync()
		$stderrTask = $process.StandardError.ReadToEndAsync()
		$process.WaitForExit()
		$stdout = $stdoutTask.GetAwaiter().GetResult()
		$stderr = $stderrTask.GetAwaiter().GetResult()
		$exitCode = $process.ExitCode
	} finally {
		$process.Dispose()
	}

	$lines = @($stdout -split '\r?\n')
	$okLines = @($lines | Where-Object {
		$_.StartsWith('ok - ', [StringComparison]::Ordinal)
	})
	$failedLines = @($lines | Where-Object {
		$_.StartsWith('not ok - ', [StringComparison]::Ordinal)
	})
	$skippedLines = @($lines | Where-Object {
		$_.StartsWith('skip - ', [StringComparison]::Ordinal)
	})
	$summaryLines = @($lines | Where-Object {
		$_ -ceq '620 passed, 1 failed, 0 skipped'
	})
	$adsFailureLines = @($lines | Where-Object {
		$_ -ceq 'not ok - alternate data stream is rejected'
	})
	if (
		$exitCode -ne 1 -or
		$okLines.Count -ne 620 -or
		$failedLines.Count -ne 1 -or
		$skippedLines.Count -ne 0 -or
		$summaryLines.Count -ne 1 -or
		$adsFailureLines.Count -ne 1
	) {
		throw (
			"The ADS rejection mutant was not killed exactly as expected.`n" +
			"exit=$exitCode; ok=$($okLines.Count); " +
			"failed=$($failedLines.Count); skipped=$($skippedLines.Count); " +
			"summary=$($summaryLines.Count); " +
			"ADS failure=$($adsFailureLines.Count)`n" +
			"stdout:`n$stdout`nstderr:`n$stderr")
	}

	Write-Host (
		'mutation killed - production alternate data stream rejection ' +
		'(620 passed, 1 failed, 0 skipped)')
} finally {
	if (Test-Path -LiteralPath $scratch) {
		Remove-Item -LiteralPath $scratch -Recurse -Force
	}
}
