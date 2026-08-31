[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunnerTemp,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunId,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunAttempt,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$Job,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$MatrixDiscriminator,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunnerOs,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunnerArch,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$RunnerEnvironment,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$GitHubPath,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$GitHubEnv,

	[Parameter(Mandatory = $true)]
	[AllowNull()]
	[AllowEmptyCollection()]
	[object]$GitHubOutput
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/bootstrap.psm1" -Force

Invoke-LockedSdkBootstrap `
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
