[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$RunnerTemp,

	[Parameter(Mandatory = $true)]
	[string]$RunId,

	[Parameter(Mandatory = $true)]
	[string]$RunAttempt,

	[Parameter(Mandatory = $true)]
	[string]$Job,

	[Parameter(Mandatory = $true)]
	[string]$MatrixDiscriminator,

	[Parameter(Mandatory = $true)]
	[string]$RunnerOs,

	[Parameter(Mandatory = $true)]
	[string]$RunnerArch,

	[Parameter(Mandatory = $true)]
	[string]$GitHubPath,

	[Parameter(Mandatory = $true)]
	[string]$GitHubEnv,

	[Parameter(Mandatory = $true)]
	[string]$GitHubOutput
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/bootstrap.psm1" -Force

Invoke-LockedSdkBootstrap `
	-LockPath "$PSScriptRoot/sdk-lock.json" `
	-RunnerTemp $RunnerTemp `
	-RunId $RunId `
	-RunAttempt $RunAttempt `
	-Job $Job `
	-MatrixDiscriminator $MatrixDiscriminator `
	-RunnerOs $RunnerOs `
	-RunnerArch $RunnerArch `
	-GitHubPath $GitHubPath `
	-GitHubEnv $GitHubEnv `
	-GitHubOutput $GitHubOutput
