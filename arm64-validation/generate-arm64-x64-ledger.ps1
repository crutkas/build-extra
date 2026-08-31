[CmdletBinding()]
param(
    [string]$ModelPath,
    [string]$OutputDirectory,
    [string]$PrivateRoot,
    [string]$GitHubToken = $(if ($env:GITHUB_TOKEN) {
        $env:GITHUB_TOKEN
    } else {
        $env:GH_TOKEN
    }),
    [switch]$KeepPrivateRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([string]::IsNullOrEmpty($ModelPath)) {
    $ModelPath = Join-Path $PSScriptRoot 'ledger-model-v2.55.0.4.json'
}
if ([string]::IsNullOrEmpty($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot 'artifacts\v2.55.0.4'
}
$modulePath = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot 'Arm64Ledger.psm1'))
$moduleStream = New-Object System.IO.FileStream(
    $modulePath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read)
try {
    if ($moduleStream.Length -gt 4194304) {
        throw 'Ledger module exceeds the bootstrap size limit'
    }
    $moduleBytes = New-Object byte[] ([int]$moduleStream.Length)
    $moduleOffset = 0
    while ($moduleOffset -lt $moduleBytes.Length) {
        $moduleRead = $moduleStream.Read(
            $moduleBytes,
            $moduleOffset,
            $moduleBytes.Length - $moduleOffset)
        if ($moduleRead -le 0) {
            throw 'Unexpected EOF while bootstrapping the ledger module'
        }
        $moduleOffset += $moduleRead
    }
} finally {
    $moduleStream.Dispose()
}
$moduleEncoding = New-Object System.Text.UTF8Encoding($false, $true)
$moduleText = $moduleEncoding.GetString($moduleBytes)
if ($moduleText.Length -gt 0 -and $moduleText[0] -eq [char]0xFEFF) {
    throw 'Ledger module must not contain a BOM'
}
$module = New-Module `
    -Name Arm64Ledger `
    -ScriptBlock ([ScriptBlock]::Create($moduleText))
Import-Module $module -Force -DisableNameChecking
$stableModuleBytes = Read-StableBytes -Path $modulePath
if (-not [System.Linq.Enumerable]::SequenceEqual(
    [byte[]]$moduleBytes, [byte[]]$stableModuleBytes)) {
    throw 'Ledger module changed during bootstrap'
}

function ConvertTo-NativeArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append('\' * (($slashes * 2) + 1))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append('\' * $slashes)
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) {
        [void]$builder.Append('\' * ($slashes * 2))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-ProcessStartInfo {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [switch]$GitEnvironment
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($Arguments | ForEach-Object {
        ConvertTo-NativeArgument -Value $_
    }) -join ' ')
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($GitEnvironment) {
        foreach ($name in @(
            'GIT_DIR',
            'GIT_WORK_TREE',
            'GIT_INDEX_FILE',
            'GIT_OBJECT_DIRECTORY',
            'GIT_ALTERNATE_OBJECT_DIRECTORIES')) {
            $startInfo.EnvironmentVariables.Remove($name)
        }
        $startInfo.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
        $startInfo.EnvironmentVariables['GIT_CONFIG_GLOBAL'] = 'NUL'
        $startInfo.EnvironmentVariables['GIT_TERMINAL_PROMPT'] = '0'
        $startInfo.EnvironmentVariables['GCM_INTERACTIVE'] = 'Never'
        $startInfo.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
    }
    return $startInfo
}

function Invoke-TextProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [switch]$GitEnvironment
    )

    $startInfo = New-ProcessStartInfo `
        -FilePath $FilePath `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -GitEnvironment:$GitEnvironment
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Could not start process: $FilePath"
        }
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $outputTask.GetAwaiter().GetResult()
        $errorText = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Process failed ($($process.ExitCode)): $FilePath " +
                "$($Arguments -join ' ')`n$errorText"
        }
        if ($errorText.Trim().Length -gt 0) {
            throw "Process wrote unexpected stderr: $FilePath`n$errorText"
        }
        return $output.TrimEnd("`r", "`n")
    } finally {
        $process.Dispose()
    }
}

function Invoke-BinaryTarProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$AllowedAbsoluteSymlinks,
        [switch]$CollectFiles,
        [switch]$GitEnvironment
    )

    $startInfo = New-ProcessStartInfo `
        -FilePath $FilePath `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -GitEnvironment:$GitEnvironment
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Could not start process: $FilePath"
        }
        $errorTask = $process.StandardError.ReadToEndAsync()
        try {
            $result = Read-TarPayload `
                -Stream $process.StandardOutput.BaseStream `
                -AllowedAbsoluteSymlinks $AllowedAbsoluteSymlinks `
                -CollectFiles:$CollectFiles
        } catch {
            if (-not $process.HasExited) {
                $process.Kill()
            }
            throw
        } finally {
            $process.StandardOutput.Dispose()
        }
        $process.WaitForExit()
        $errorText = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "TAR producer failed ($($process.ExitCode)): $FilePath`n" +
                $errorText
        }
        if ($errorText.Trim().Length -gt 0) {
            throw "TAR producer wrote unexpected stderr: $FilePath`n$errorText"
        }
        return $result
    } finally {
        $process.Dispose()
    }
}

function New-GitHubClient {
    param(
        [Parameter(Mandatory = $true)][string]$Accept,
        [string]$Token
    )

    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $handler.AutomaticDecompression =
        [System.Net.DecompressionMethods]::GZip -bor
        [System.Net.DecompressionMethods]::Deflate
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(30)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        'git-for-windows-arm64-ledger/1')
    $client.DefaultRequestHeaders.Accept.ParseAdd($Accept)
    $client.DefaultRequestHeaders.Add(
        'X-GitHub-Api-Version', '2022-11-28')
    if (-not [string]::IsNullOrEmpty($Token)) {
        $client.DefaultRequestHeaders.Authorization =
            New-Object System.Net.Http.Headers.AuthenticationHeaderValue(
                'Bearer', $Token)
    }
    return $client
}

function Invoke-GitHubJson {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Token
    )

    $client = New-GitHubClient `
        -Accept 'application/vnd.github+json' `
        -Token $Token
    try {
        $response = $client.GetAsync($Url).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                throw "GitHub API request failed ($([int]$response.StatusCode)): " +
                    $Url
            }
            $bytes = $response.Content.ReadAsByteArrayAsync().
                GetAwaiter().GetResult()
            return ConvertFrom-StrictJsonBytes -Bytes $bytes
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
    }
}

function Save-GitHubAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][long]$ExpectedSize,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [string]$Token
    )

    $client = New-GitHubClient `
        -Accept 'application/octet-stream' `
        -Token $Token
    try {
        $response = $client.GetAsync(
            $Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).
            GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                throw "Asset API download failed ($([int]$response.StatusCode)): " +
                    $Url
            }
            $mediaType = [string]$response.Content.Headers.ContentType.MediaType
            if ($mediaType -match '(?i)json') {
                throw 'Asset API returned metadata instead of asset bytes'
            }
            $source = $response.Content.ReadAsStreamAsync().
                GetAwaiter().GetResult()
            $destinationStream = New-Object System.IO.FileStream(
                $Destination,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
            try {
                $source.CopyTo($destinationStream, 1048576)
                $destinationStream.Flush($true)
            } finally {
                $destinationStream.Dispose()
                $source.Dispose()
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
    }
    $identity = Get-StableFileHash -Path $Destination
    if ($identity.length -ne $ExpectedSize -or
        $identity.sha256 -ne $ExpectedSha256) {
        throw "Downloaded asset identity mismatch: $Destination"
    }
    return $identity
}

function Assert-ExactValue {
    param(
        [Parameter(Mandatory = $false)]$Actual,
        [Parameter(Mandatory = $false)]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Actual -is [string] -and $Expected -is [string]) {
        if (-not [StringComparer]::Ordinal.Equals($Actual, $Expected)) {
            throw "$Context differs: expected '$Expected', found '$Actual'"
        }
        return
    }
    if ($Actual -ne $Expected) {
        throw "$Context differs: expected '$Expected', found '$Actual'"
    }
}

function Get-ReleaseApiEvidence {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [string]$Token
    )

    $baseUrl = "https://api.github.com/repos/$($Model.release.repository)"
    $release = Invoke-GitHubJson `
        -Url "$baseUrl/releases/$($Model.release.id)" `
        -Token $Token
    Assert-ExactValue $release.id $Model.release.id 'release.id'
    Assert-ExactValue $release.tag_name $Model.release.tag 'release.tag'
    Assert-ExactValue `
        $release.target_commitish `
        $Model.release.peeledCommit `
        'release.target_commitish'
    Assert-ExactValue `
        $release.created_at `
        $Model.release.createdAt `
        'release.created_at'
    Assert-ExactValue `
        $release.published_at `
        $Model.release.publishedAt `
        'release.published_at'
    Assert-ExactValue $release.draft $false 'release.draft'
    Assert-ExactValue $release.prerelease $false 'release.prerelease'

    $assetMatches = @($release.assets | Where-Object {
        $_.id -eq $Model.release.asset.id
    })
    if ($assetMatches.Count -ne 1) {
        throw 'Release does not contain exactly one asset with the pinned ID'
    }
    $asset = $assetMatches[0]
    $assetById = Invoke-GitHubJson `
        -Url $Model.release.asset.apiUrl `
        -Token $Token
    foreach ($candidate in @($asset, $assetById)) {
        Assert-ExactValue $candidate.id $Model.release.asset.id 'asset.id'
        Assert-ExactValue $candidate.name $Model.release.asset.name 'asset.name'
        Assert-ExactValue $candidate.size $Model.release.asset.size 'asset.size'
        Assert-ExactValue `
            $candidate.digest `
            $Model.release.asset.apiDigest `
            'asset.digest'
        Assert-ExactValue `
            $candidate.created_at `
            $Model.release.asset.createdAt `
            'asset.created_at'
        Assert-ExactValue `
            $candidate.updated_at `
            $Model.release.asset.updatedAt `
            'asset.updated_at'
        Assert-ExactValue `
            $candidate.url `
            $Model.release.asset.apiUrl `
            'asset.url'
    }

    $tagRef = Invoke-GitHubJson `
        -Url "$baseUrl/git/ref/tags/$($Model.release.tag)" `
        -Token $Token
    Assert-ExactValue `
        $tagRef.ref `
        "refs/tags/$($Model.release.tag)" `
        'tag ref'
    Assert-ExactValue $tagRef.object.type 'tag' 'tag ref object type'
    Assert-ExactValue `
        $tagRef.object.sha `
        $Model.release.tagObject `
        'tag object'
    $tag = Invoke-GitHubJson `
        -Url "$baseUrl/git/tags/$($Model.release.tagObject)" `
        -Token $Token
    Assert-ExactValue $tag.tag $Model.release.tag 'annotated tag name'
    Assert-ExactValue $tag.object.type 'commit' 'annotated tag target type'
    Assert-ExactValue `
        $tag.object.sha `
        $Model.release.peeledCommit `
        'annotated tag target'
    $commit = Invoke-GitHubJson `
        -Url "$baseUrl/git/commits/$($Model.release.peeledCommit)" `
        -Token $Token
    Assert-ExactValue `
        $commit.tree.sha `
        $Model.release.peeledCommitTree `
        'release commit tree'
    return [ordered]@{
        assetApiDigest = $assetById.digest
        assetCreatedAt = $assetById.created_at
        assetUpdatedAt = $assetById.updated_at
        commitTree = $commit.tree.sha
        peeledCommit = $tag.object.sha
        releaseCreatedAt = $release.created_at
        releaseId = [long]$release.id
        releasePublishedAt = $release.published_at
        tagObject = $tagRef.object.sha
    }
}

function Get-GitExecutable {
    $command = Get-Command git.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    Assert-SafeExistingPath -Path $command.Source -Kind File | Out-Null
    return $command.Source
}

function Get-Bzip2Executable {
    $command = Get-Command bzip2.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    Assert-SafeExistingPath -Path $command.Source -Kind File | Out-Null
    return $command.Source
}

function Get-OwnershipSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$GitPath
    )

    $gitDirectory = Join-Path $RunRoot 'ownership.git'
    if (Test-Path -LiteralPath $gitDirectory) {
        throw "Ownership clone path already exists: $gitDirectory"
    }
    [void](Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @('init', '--quiet', '--bare', $gitDirectory) `
        -WorkingDirectory $RunRoot `
        -GitEnvironment)
    Assert-SafeTree -Root $gitDirectory
    $isBare = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            '--is-bare-repository') `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue $isBare 'true' 'ownership clone bare identity'
    [void](Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'remote',
            'add',
            'origin',
            "https://github.com/$($Model.ownership.repository).git") `
        -WorkingDirectory $RunRoot `
        -GitEnvironment)
    [void](Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            '-c',
            'protocol.version=2',
            'fetch',
            '--quiet',
            '--no-tags',
            '--depth=1',
            '--filter=blob:none',
            'origin',
            $Model.ownership.commit) `
        -WorkingDirectory $RunRoot `
        -GitEnvironment)
    $remoteUrl = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'remote',
            'get-url',
            'origin') `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue `
        $remoteUrl `
        "https://github.com/$($Model.ownership.repository).git" `
        'ownership remote'
    $fetchedCommit = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            'FETCH_HEAD^{commit}') `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue `
        $fetchedCommit $Model.ownership.commit 'ownership fetched commit'
    $rootTree = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            "$($Model.ownership.commit)^{tree}") `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue $rootTree $Model.ownership.rootTree 'ownership root tree'
    $databaseTree = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            "$($Model.ownership.commit):$($Model.ownership.databasePath)") `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue `
        $databaseTree `
        $Model.ownership.databaseTree `
        'ownership database tree'

    $tar = Invoke-BinaryTarProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'archive',
            '--format=tar',
            '--mtime=1970-01-01T00:00:00Z',
            $Model.ownership.databaseTree) `
        -WorkingDirectory $RunRoot `
        -AllowedAbsoluteSymlinks (New-OrdinalDictionary) `
        -CollectFiles `
        -GitEnvironment
    $database = ConvertFrom-PacmanTarResult `
        -TarResult $tar `
        -ExpectedPackageCount $Model.ownership.packageCount `
        -ExpectedRecordBlobCount $Model.ownership.recordBlobCount
    Assert-ExactValue `
        $tar.tarSha256 `
        $Model.ownership.databaseArchiveTarSha256 `
        'ownership database archive TAR hash'
    $afterCommit = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            'FETCH_HEAD^{commit}') `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue `
        $afterCommit $Model.ownership.commit 'ownership post-read commit'
    $afterTree = Invoke-TextProcess `
        -FilePath $GitPath `
        -Arguments @(
            "--git-dir=$gitDirectory",
            'rev-parse',
            "$($Model.ownership.commit):$($Model.ownership.databasePath)") `
        -WorkingDirectory $RunRoot `
        -GitEnvironment
    Assert-ExactValue `
        $afterTree `
        $Model.ownership.databaseTree `
        'ownership post-read database tree'
    Assert-SafeTree -Root $gitDirectory
    return [ordered]@{
        database = $database
        gitArchiveTarSha256 = $tar.tarSha256
        repository = $Model.ownership.repository
        commit = $fetchedCommit
        rootTree = $rootTree
        databaseTree = $databaseTree
    }
}

function Get-PathRowsBytes {
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows
    )

    $builder = New-Object System.Text.StringBuilder
    foreach ($row in $Rows) {
        foreach ($field in $row) {
            Assert-SafeField -Value ([string]$field) -Context 'mapping row'
        }
        [void]$builder.Append(($row -join "`t"))
        [void]$builder.Append("`n")
    }
    return ,(New-Object System.Text.UTF8Encoding($false, $true)).
        GetBytes($builder.ToString())
}

function Get-ProductScopes {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]$RuleCompilation
    )

    $rulePaths = New-OrdinalDictionary
    foreach ($rule in $RuleCompilation.rules) {
        $rulePaths[$rule.id] = $rule.paths
    }
    $modeled = New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    foreach ($path in $RuleCompilation.assignments.Keys) {
        if ($RuleCompilation.assignments[$path].ledgerClass -eq
            'modeled-unresolved') {
            [void]$modeled.Add($path)
        }
    }
    $results = New-Object System.Collections.ArrayList
    foreach ($product in $Model.products) {
        $paths = New-Object 'System.Collections.Generic.HashSet[string]' (
            [StringComparer]::Ordinal)
        if ($product.Contains('ruleIds')) {
            foreach ($ruleId in $product.ruleIds) {
                foreach ($path in $rulePaths[$ruleId]) {
                    if (-not $paths.Add($path)) {
                        throw "Product $($product.id) has a duplicate rule path: $path"
                    }
                }
            }
        } else {
            foreach ($path in $product.paths) {
                if (-not $paths.Add($path)) {
                    throw "Product $($product.id) repeats path: $path"
                }
            }
        }
        if ($paths.Count -ne $product.expectedCount) {
            throw "Product $($product.id) expected $($product.expectedCount) " +
                "paths, found $($paths.Count)"
        }
        foreach ($path in $paths) {
            if (-not $modeled.Contains($path)) {
                throw "Product $($product.id) contains non-modeled path: $path"
            }
        }
        $pathArray = New-Object string[] $paths.Count
        $paths.CopyTo($pathArray)
        [void]$results.Add([ordered]@{
            id = $product.id
            pathCount = [long]$paths.Count
            paths = Sort-Bytewise -Values $pathArray
            status = 'projection-only-unresolved'
        })
    }
    return ,$results.ToArray()
}

function New-CanonicalArtifactSet {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]$ApiEvidence,
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)]$OwnershipSnapshot,
        [Parameter(Mandatory = $true)][byte[]]$ModelBytes,
        [Parameter(Mandatory = $true)][byte[]]$ScannerBytes
    )

    if ($Archive.memberCount -ne $Model.archiveExpectations.memberCount -or
        $Archive.typeCounts.hardlink -ne
            $Model.archiveExpectations.hardlinkCount -or
        $Archive.peByPath.Count -ne $Model.archiveExpectations.peCount) {
        throw 'Archive member, hardlink, or PE count differs from the model'
    }
    $architectureCounts = [ordered]@{
        anycpu = [long]0
        arm64 = [long]0
        x64 = [long]0
        x86 = [long]0
    }
    foreach ($pe in $Archive.peByPath.Values) {
        if (-not $architectureCounts.Contains($pe.architecture)) {
            throw "Unconsumed PE architecture: $($pe.architecture)"
        }
        $architectureCounts[$pe.architecture]++
    }
    foreach ($architecture in $architectureCounts.Keys) {
        if ($architectureCounts[$architecture] -ne
            $Model.archiveExpectations.architectureCounts[$architecture]) {
            throw "PE architecture count differs for $architecture"
        }
    }
    $x64Paths = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Archive.peByPath.Keys) {
        if ($Archive.peByPath[$path].architecture -eq 'x64') {
            $x64Paths.Add($path)
        }
    }
    $x64PathBytes = Get-CanonicalPathSetBytes -Paths $x64Paths.ToArray()
    $x64PathSha256 = Get-Sha256Hex -Bytes $x64PathBytes
    if ($x64PathSha256 -ne
        $Model.archiveExpectations.x64PathSha256) {
        throw 'Canonical x64 path hash differs from the release baseline'
    }
    $sortedX64Paths = Sort-Bytewise -Values $x64Paths.ToArray()
    $ownership = ConvertTo-OwnershipMapping `
        -PackageFiles $OwnershipSnapshot.database.packages `
        -X64Paths $sortedX64Paths
    $ownershipRows = New-Object System.Collections.ArrayList
    foreach ($path in $sortedX64Paths) {
        [void]$ownershipRows.Add(@(
            $path,
            $ownership[$path].owner,
            $ownership[$path].version))
    }
    $mappingBytes = Get-PathRowsBytes -Rows $ownershipRows.ToArray()
    $mappingSha256 = Get-Sha256Hex -Bytes $mappingBytes
    if ($mappingSha256 -ne $Model.ownership.canonicalMappingSha256) {
        throw 'Canonical path-owner-version mapping hash differs'
    }
    $ownershipTsv = ConvertTo-CanonicalTsvBytes `
        -Header @('path', 'owner', 'version') `
        -Rows $ownershipRows.ToArray()

    $ruleCompilation = Compile-LedgerRules `
        -Model $Model `
        -Ownership $ownership
    $recommendations = Get-LedgerRecommendations `
        -Ownership $ownership `
        -Assignments $ruleCompilation.assignments
    if ($recommendations.Count -ne $Model.expected.recommendationCount) {
        throw 'Recommendation count differs from the model'
    }
    $products = Get-ProductScopes `
        -Model $Model `
        -RuleCompilation $ruleCompilation

    $ownerVersionGroups = New-Object `
        'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($record in $ownership.Values) {
        [void]$ownerVersionGroups.Add(
            "$($record.owner)`0$($record.version)")
    }
    if ($ownerVersionGroups.Count -ne $Model.expected.ownerVersionGroupCount) {
        throw 'Owner/version group count differs from the model'
    }

    $sourceRuleRows = New-Object System.Collections.ArrayList
    $pathRecords = New-Object System.Collections.ArrayList
    foreach ($path in $sortedX64Paths) {
        $assignment = $ruleCompilation.assignments[$path]
        $owner = $ownership[$path]
        [void]$sourceRuleRows.Add(@(
            $path,
            $owner.owner,
            $owner.version,
            $assignment.ruleId,
            $assignment.ledgerClass,
            $assignment.action))
        [void]$pathRecords.Add([ordered]@{
            action = $assignment.action
            ledgerClass = $assignment.ledgerClass
            owner = $owner.owner
            path = $path
            ruleId = $assignment.ruleId
            version = $owner.version
        })
    }
    $sourceRulesTsv = ConvertTo-CanonicalTsvBytes `
        -Header @(
            'path',
            'owner',
            'version',
            'ruleId',
            'ledgerClass',
            'action') `
        -Rows $sourceRuleRows.ToArray()

    $peRows = New-Object System.Collections.ArrayList
    foreach ($path in (Sort-Bytewise -Values $Archive.peByPath.Keys)) {
        $pe = $Archive.peByPath[$path]
        $owner = 'not-applicable'
        $version = 'not-applicable'
        if ($ownership.Contains($path)) {
            $owner = $ownership[$path].owner
            $version = $ownership[$path].version
        }
        [void]$peRows.Add(@(
            $path,
            $pe.architecture,
            $pe.machine,
            $pe.size.ToString(
                [Globalization.CultureInfo]::InvariantCulture),
            $pe.sha256,
            $Archive.entries[$path].kind,
            $owner,
            $version))
    }
    $peTsv = ConvertTo-CanonicalTsvBytes `
        -Header @(
            'path',
            'architecture',
            'machine',
            'size',
            'sha256',
            'archiveType',
            'owner',
            'version') `
        -Rows $peRows.ToArray()

    $linkRows = New-Object System.Collections.ArrayList
    $linksByPath = New-OrdinalDictionary
    foreach ($link in $Archive.links) {
        if ($linksByPath.Contains($link.path)) {
            throw "Duplicate link metadata path: $($link.path)"
        }
        $linksByPath[$link.path] = $link
    }
    foreach ($path in (Sort-Bytewise -Values $linksByPath.Keys)) {
        $link = $linksByPath[$path]
        $resolvedTarget = if ($link.resolvedTarget.Length -eq 0) {
            'not-applicable'
        } else {
            $link.resolvedTarget
        }
        [void]$linkRows.Add(@(
            $link.path,
            $link.type,
            $link.target,
            $link.policy,
            $resolvedTarget))
    }
    $linksTsv = ConvertTo-CanonicalTsvBytes `
        -Header @('path', 'type', 'target', 'policy', 'resolvedTarget') `
        -Rows $linkRows.ToArray()

    $archiveSummary = [ordered]@{
        architectureCounts = $architectureCounts
        hardlinkCount = [long]$Archive.typeCounts.hardlink
        installedLinkPolicy = [ordered]@{
            absoluteTargetsAreExtractionPaths = $false
            description = 'The five allowlisted POSIX absolute links are payload metadata. The scanner never resolves or materializes them.'
            links = $Model.archiveExpectations.allowedAbsoluteSymlinks
        }
        linkCount = [long]$Archive.links.Count
        memberCount = [long]$Archive.memberCount
        peCount = [long]$Archive.peByPath.Count
        tarSha256 = $Archive.tarSha256
        typeCounts = $Archive.typeCounts
        x64PathSha256 = $x64PathSha256
        zeroBlockCount = [long]$Archive.zeroBlockCount
    }
    $backlog = [ordered]@{
        accounting = [ordered]@{
            admittedPathReduction = [long]0
            evidenceBackedCandidate = [long]$ruleCompilation.classCounts[
                'evidence-backed-candidate']
            modeledUnresolved = [long]$ruleCompilation.classCounts[
                'modeled-unresolved']
            releasedX64Paths = [long]$sortedX64Paths.Count
            residual = [long]$ruleCompilation.classCounts.residual
            schedulingOnly = $true
        }
        baseline = [ordered]@{
            ownershipMappingSha256 = $mappingSha256
            releaseAssetSha256 = $Model.release.asset.downloadSha256
            x64PathSha256 = $x64PathSha256
        }
        legacyOverlap = $Model.legacyOverlap
        notice = 'This ledger is scheduling evidence only. Every listed path remains x64 in the released payload until immutable downstream native bytes are separately admitted.'
        paths = $pathRecords.ToArray()
        products = $products
        recommendations = $recommendations
        rules = $ruleCompilation.rules
        schemaVersion = [long]1
        sourceRuleAudit = [ordered]@{
            consumedPathCount = [long]$ruleCompilation.assignments.Count
            sourceOverlapCount = [long]$ruleCompilation.sourceOverlapCount
            unconsumedPathCount = [long]0
        }
    }
    $provenance = [ordered]@{
        archive = [ordered]@{
            authenticatedDownloadCopies = [long]2
            tarSha256 = $Archive.tarSha256
        }
        apiEvidence = $ApiEvidence
        ownership = [ordered]@{
            canonicalMappingSha256 = $mappingSha256
            commit = $OwnershipSnapshot.commit
            databaseArchiveTarSha256 =
                $OwnershipSnapshot.gitArchiveTarSha256
            databasePath = $Model.ownership.databasePath
            databaseTree = $OwnershipSnapshot.databaseTree
            independentPrivateBareClones = [long]2
            packageCount = [long]$OwnershipSnapshot.database.packageCount
            recordBlobCount =
                [long]$OwnershipSnapshot.database.recordBlobCount
            repository = $OwnershipSnapshot.repository
            rootTree = $OwnershipSnapshot.rootTree
        }
        release = $Model.release
        scanner = [ordered]@{
            gitBlobSha1 = Get-GitBlobSha1 -Bytes $ScannerBytes
            path = $Model.scanner.path
            referenceScanners = $Model.scanner.referenceScanners
            sha256 = Get-Sha256Hex -Bytes $ScannerBytes
        }
        sourceModel = [ordered]@{
            gitBlobSha1 = Get-GitBlobSha1 -Bytes $ModelBytes
            path = 'arm64-validation/ledger-model-v2.55.0.4.json'
            sha256 = Get-Sha256Hex -Bytes $ModelBytes
        }
    }

    $artifacts = [ordered]@{
        'archive-links.tsv' =
            $linksTsv
        'archive-summary.json' =
            (ConvertTo-CanonicalJsonBytes -Value $archiveSummary)
        'backlog.json' =
            (ConvertTo-CanonicalJsonBytes -Value $backlog)
        'pe-manifest.tsv' =
            $peTsv
        'provenance.json' =
            (ConvertTo-CanonicalJsonBytes -Value $provenance)
        'source-rules.tsv' =
            $sourceRulesTsv
        'x64-ownership.tsv' =
            $ownershipTsv
        'x64-paths.txt' =
            $x64PathBytes
    }
    return $artifacts
}

function Assert-ArtifactSetsEqual {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$First,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Second
    )

    if ($First.Count -ne $Second.Count) {
        throw 'Independent artifact sets have different file counts'
    }
    foreach ($name in $First.Keys) {
        if (-not $Second.Contains($name)) {
            throw "Independent artifact set is missing: $name"
        }
        if (-not [System.Linq.Enumerable]::SequenceEqual(
            [byte[]]$First[$name], [byte[]]$Second[$name])) {
            throw "Independent artifact bytes differ: $name"
        }
    }
}

function Add-ArtifactManifest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Artifacts,
        [Parameter(Mandatory = $true)][byte[]]$ModelBytes,
        [Parameter(Mandatory = $true)][byte[]]$ScannerBytes
    )

    $records = New-Object System.Collections.ArrayList
    foreach ($name in (Sort-Bytewise -Values $Artifacts.Keys)) {
        [void]$records.Add([ordered]@{
            path = $name
            sha256 = Get-Sha256Hex -Bytes $Artifacts[$name]
            size = [long]$Artifacts[$name].Length
        })
    }
    $manifest = [ordered]@{
        artifacts = $records.ToArray()
        canonicalSerialization = [ordered]@{
            encoding = 'UTF-8 without BOM'
            jsonObjectKeys = 'UTF-8 bytewise ascending'
            lineEndings = 'LF'
            pathOrder = 'UTF-8 bytewise ascending'
            terminalLf = $true
        }
        scanner = [ordered]@{
            gitBlobSha1 = Get-GitBlobSha1 -Bytes $ScannerBytes
            path = 'arm64-validation/Arm64Ledger.psm1'
            sha256 = Get-Sha256Hex -Bytes $ScannerBytes
        }
        schemaVersion = [long]1
        sourceModel = [ordered]@{
            gitBlobSha1 = Get-GitBlobSha1 -Bytes $ModelBytes
            path = 'arm64-validation/ledger-model-v2.55.0.4.json'
            sha256 = Get-Sha256Hex -Bytes $ModelBytes
        }
    }
    $Artifacts['manifest.json'] =
        ConvertTo-CanonicalJsonBytes -Value $manifest
}

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..'))
$modelFullPath = [System.IO.Path]::GetFullPath($ModelPath)
$outputFullPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$scannerPath = $modulePath
if (-not (Test-ContainedPath -Path $modelFullPath -Root $repositoryRoot) -or
    -not (Test-ContainedPath -Path $scannerPath -Root $repositoryRoot) -or
    -not (Test-ContainedPath -Path $outputFullPath -Root $repositoryRoot)) {
    throw 'Model, scanner, and output must be contained by this repository'
}
$modelBytes = Read-StableBytes -Path $modelFullPath
$scannerBytes = Read-StableBytes -Path $scannerPath
$model = ConvertFrom-StrictJsonBytes -Bytes $modelBytes
Assert-LedgerModel -Model $model
if (-not [System.Linq.Enumerable]::SequenceEqual(
    [byte[]]$modelBytes,
    [byte[]](ConvertTo-CanonicalJsonBytes -Value $model))) {
    throw 'Source model is not canonical LF JSON'
}

if ([string]::IsNullOrEmpty($PrivateRoot)) {
    $PrivateRoot = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        ('arm64-ledger-' + [Guid]::NewGuid().ToString('N'))
}
$privateFullPath = [System.IO.Path]::GetFullPath($PrivateRoot)
$privateIdentity = New-SafePrivateDirectory `
    -Path $privateFullPath `
    -ForbiddenRoots @($repositoryRoot, 'C:\msys64')
$gitPath = Get-GitExecutable
$bzip2Path = Get-Bzip2Executable

try {
    $apiEvidence = Get-ReleaseApiEvidence `
        -Model $model `
        -Token $GitHubToken
    $allowedLinks = New-OrdinalDictionary
    foreach ($link in $model.archiveExpectations.allowedAbsoluteSymlinks) {
        $allowedLinks[$link.path] = $link.target
    }
    $sets = New-Object System.Collections.ArrayList
    foreach ($suffix in @('a', 'b')) {
        $runRoot = Join-Path $privateFullPath "run-$suffix"
        [void][System.IO.Directory]::CreateDirectory($runRoot)
        Assert-SafeExistingPath `
            -Path $runRoot `
            -Kind Directory `
            -AllowedRoot $privateFullPath | Out-Null
        $assetPath = Join-Path $runRoot $model.release.asset.name
        [void](Save-GitHubAsset `
            -Url $model.release.asset.apiUrl `
            -Destination $assetPath `
            -ExpectedSize $model.release.asset.size `
            -ExpectedSha256 $model.release.asset.downloadSha256 `
            -Token $GitHubToken)
        $archive = Invoke-BinaryTarProcess `
            -FilePath $bzip2Path `
            -Arguments @('-dc', $assetPath) `
            -WorkingDirectory $runRoot `
            -AllowedAbsoluteSymlinks $allowedLinks
        $ownershipSnapshot = Get-OwnershipSnapshot `
            -Model $model `
            -RunRoot $runRoot `
            -GitPath $gitPath
        [void]$sets.Add((New-CanonicalArtifactSet `
            -Model $model `
            -ApiEvidence $apiEvidence `
            -Archive $archive `
            -OwnershipSnapshot $ownershipSnapshot `
            -ModelBytes $modelBytes `
            -ScannerBytes $scannerBytes))
    }
    Assert-IdentityUnchanged `
        -Before $privateIdentity `
        -Path $privateFullPath
    Assert-ArtifactSetsEqual -First $sets[0] -Second $sets[1]
    Add-ArtifactManifest `
        -Artifacts $sets[0] `
        -ModelBytes $modelBytes `
        -ScannerBytes $scannerBytes
    Write-CanonicalArtifactSet `
        -OutputDirectory $outputFullPath `
        -Artifacts $sets[0]
    foreach ($name in (Sort-Bytewise -Values $sets[0].Keys)) {
        Write-Host (
            "$name`t$($sets[0][$name].Length)`t" +
            (Get-Sha256Hex -Bytes $sets[0][$name]))
    }
} finally {
    if (-not $KeepPrivateRoot -and
        [System.IO.Directory]::Exists($privateFullPath)) {
        Remove-SafePrivateDirectory `
            -Path $privateFullPath `
            -ExpectedIdentity $privateIdentity
    }
}
