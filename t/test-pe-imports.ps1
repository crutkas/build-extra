# Tests for pe-imports.ps1.
#
# Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File t/test-pe-imports.ps1
#
# The fixtures are synthesised rather than checked in, so that a machine type
# can be varied one field at a time and so that truncated and malformed inputs
# can be produced exactly.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$peImports = Join-Path (Split-Path -Parent $here) 'pe-imports.ps1'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("pe-imports-tests-" + [System.Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work

$script:failures = 0
$script:checks = 0

function Assert-Equal {
    param($Expected, $Actual, [string]$What)
    $script:checks++
    if ("$Expected" -ne "$Actual") {
        Write-Host "not ok - $What"
        Write-Host "    expected: $Expected"
        Write-Host "    actual:   $Actual"
        $script:failures++
    } else {
        Write-Host "ok - $What"
    }
}

function Invoke-PeImports {
    param([string[]]$Arguments)

    $stdout = Join-Path $work 'stdout.txt'
    $stderr = Join-Path $work 'stderr.txt'
    $p = Start-Process -FilePath 'powershell.exe' -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $peImports) + $Arguments)
    New-Object PSObject -Property @{
        ExitCode = $p.ExitCode
        Stdout   = [string](Get-Content -Raw -LiteralPath $stdout -ErrorAction SilentlyContinue)
        Stderr   = [string](Get-Content -Raw -LiteralPath $stderr -ErrorAction SilentlyContinue)
    }
}

. (Join-Path $here 'make-pe-fixture.ps1')

# Same builder as the shell tests use, with fixtures landing in $work.
function New-Pe {
    param(
        [string]$Name,
        [int]$MachineValue,
        [bool]$Is64Bit = $true,
        [hashtable]$DataDirs = @{},
        [byte[]]$SectionData = @(),
        [int]$TruncateTo = 0,
        [int]$OptionalHeaderSize = -1,
        [int]$OverrideMagic = 0
    )

    New-TestPe -Path (Join-Path $work $Name) -MachineValue $MachineValue -Is64Bit $Is64Bit `
        -DataDirs $DataDirs -SectionData $SectionData -TruncateTo $TruncateTo `
        -OptionalHeaderSize $OptionalHeaderSize -OverrideMagic $OverrideMagic
}
function Get-Machine {
    param([string]$PePath)
    $r = Invoke-PeImports -Arguments @('-Machine', $PePath)
    if ($r.ExitCode -ne 0) { return "exit$($r.ExitCode)" }
    return ($r.Stdout -split "`n")[0].Split("`t")[0]
}

Write-Host "# exact machine parsing"

Assert-Equal 'arm64'   (Get-Machine (New-Pe -Name 'arm64.dll'  -MachineValue 0xAA64)) 'ARM64 0xAA64'
Assert-Equal 'amd64'   (Get-Machine (New-Pe -Name 'amd64.dll'  -MachineValue 0x8664)) 'AMD64 0x8664'
Assert-Equal 'arm64ec' (Get-Machine (New-Pe -Name 'ec-raw.dll' -MachineValue 0xA641)) 'ARM64EC 0xA641'
Assert-Equal 'arm64x'  (Get-Machine (New-Pe -Name 'x-raw.dll'  -MachineValue 0xA64E)) 'ARM64X 0xA64E'
Assert-Equal 'i386'    (Get-Machine (New-Pe -Name 'i386.dll'   -MachineValue 0x014C -Is64Bit $false)) 'i386 0x014C'
Assert-Equal 'armnt'   (Get-Machine (New-Pe -Name 'armnt.dll'  -MachineValue 0x01C4 -Is64Bit $false)) 'ARMNT 0x01C4'
Assert-Equal 'unknown-0x1234' (Get-Machine (New-Pe -Name 'weird.dll' -MachineValue 0x1234)) 'an unrecognised machine is never mistaken for a known one'

Write-Host "# hybrid images masquerade as their non-hybrid machine"

$hybrid64 = New-HybridLoadConfig -Is64Bit $true
Assert-Equal 'arm64x' (Get-Machine (New-Pe -Name 'arm64x.dll' -MachineValue 0xAA64 `
    -DataDirs @{ 10 = @(0x1000, 0x140) } -SectionData $hybrid64)) 'ARM64 plus CHPE metadata is ARM64X, not ARM64'
Assert-Equal 'arm64ec' (Get-Machine (New-Pe -Name 'arm64ec.dll' -MachineValue 0x8664 `
    -DataDirs @{ 10 = @(0x1000, 0x140) } -SectionData $hybrid64)) 'AMD64 plus CHPE metadata is ARM64EC, not AMD64'
Assert-Equal 'arm64' (Get-Machine (New-Pe -Name 'arm64-lc.dll' -MachineValue 0xAA64 `
    -DataDirs @{ 10 = @(0x1000, 0x140) } -SectionData (New-Object byte[] 0x140))) 'ARM64 with an all-zero load config stays ARM64'

# CHPEMetadataPointer is at a different offset in IMAGE_LOAD_CONFIG_DIRECTORY32
# (0x7C, after DynamicValueRelocTable) than in the 64-bit layout (0xC8). A PE32
# optional header is the only way to reach that branch.
$hybrid32 = New-HybridLoadConfig -Is64Bit $false
Assert-Equal 'arm64ec' (Get-Machine (New-Pe -Name 'hybrid32.dll' -MachineValue 0x8664 -Is64Bit $false `
    -DataDirs @{ 10 = @(0x1000, 0xB0) } -SectionData $hybrid32)) 'the 32-bit CHPE offset is read at 0x7C'
$notHybrid32 = New-Object byte[] 0xB0
[Array]::Copy([BitConverter]::GetBytes([uint32]0xB0), 0, $notHybrid32, 0, 4)
[Array]::Copy([BitConverter]::GetBytes([uint32]0x3000), 0, $notHybrid32, 0x78, 4)
Assert-Equal 'amd64' (Get-Machine (New-Pe -Name 'reloc32.dll' -MachineValue 0x8664 -Is64Bit $false `
    -DataDirs @{ 10 = @(0x1000, 0xB0) } -SectionData $notHybrid32)) 'DynamicValueRelocTable at 0x78 is not mistaken for CHPE metadata'

Write-Host "# managed assemblies"

Assert-Equal 'anycpu' (Get-Machine (New-Pe -Name 'anycpu.dll' -MachineValue 0x014C -Is64Bit $false `
    -DataDirs @{ 14 = @(0x1000, 72) } -SectionData (New-ClrHeader -Flags 0x1))) 'an IL-only managed assembly is anycpu'
Assert-Equal 'i386' (Get-Machine (New-Pe -Name 'il32.dll' -MachineValue 0x014C -Is64Bit $false `
    -DataDirs @{ 14 = @(0x1000, 72) } -SectionData (New-ClrHeader -Flags 0x3))) 'a managed assembly that requires 32 bits is i386'

Write-Host "# malformed, truncated and non-PE inputs"

$notPe = Join-Path $work 'plain.txt'
[System.IO.File]::WriteAllText($notPe, 'this is not a PE file at all, not even close')
Assert-Equal 'not-pe' (Get-Machine $notPe) 'a text file is not-pe'

$tiny = Join-Path $work 'tiny.bin'
[System.IO.File]::WriteAllBytes($tiny, [byte[]]@(0x4D, 0x5A, 0, 0))
Assert-Equal 'not-pe' (Get-Machine $tiny) 'an MZ stub shorter than a DOS header is not-pe'

$badSig = New-Pe -Name 'badsig.dll' -MachineValue 0xAA64
$bytes = [System.IO.File]::ReadAllBytes($badSig)
$bytes[0x80] = 0x51
[System.IO.File]::WriteAllBytes($badSig, $bytes)
Assert-Equal 'not-pe' (Get-Machine $badSig) 'a corrupt PE signature is not-pe'

$farLfanew = New-Pe -Name 'farlfanew.dll' -MachineValue 0xAA64
$bytes = [System.IO.File]::ReadAllBytes($farLfanew)
[Array]::Copy([BitConverter]::GetBytes([int]0x7FFFFF00), 0, $bytes, 0x3C, 4)
[System.IO.File]::WriteAllBytes($farLfanew, $bytes)
Assert-Equal 'truncated' (Get-Machine $farLfanew) 'a COFF header past the end of the file is truncated'

$negLfanew = New-Pe -Name 'neglfanew.dll' -MachineValue 0xAA64
$bytes = [System.IO.File]::ReadAllBytes($negLfanew)
[Array]::Copy([BitConverter]::GetBytes([int](-16)), 0, $bytes, 0x3C, 4)
[System.IO.File]::WriteAllBytes($negLfanew, $bytes)
Assert-Equal 'truncated' (Get-Machine $negLfanew) 'a negative e_lfanew is truncated rather than a crash'

Assert-Equal 'truncated' (Get-Machine (New-Pe -Name 'cutopt.dll' -MachineValue 0xAA64 -TruncateTo 0xB0)) 'an optional header past the end of the file is truncated'
Assert-Equal 'malformed' (Get-Machine (New-Pe -Name 'nooptional.dll' -MachineValue 0xAA64 -OptionalHeaderSize 0)) 'an object file with no optional header is malformed'
Assert-Equal 'malformed' (Get-Machine (New-Pe -Name 'badmagic.dll' -MachineValue 0xAA64 -OverrideMagic 0x999)) 'an unknown optional header magic is malformed'
Assert-Equal 'unreadable' (Get-Machine (Join-Path $work 'does-not-exist.dll')) 'a missing file is unreadable'

Write-Host "# -RequireMachine enforcement"

$arm64 = New-Pe -Name 'req-arm64.dll' -MachineValue 0xAA64
$amd64 = New-Pe -Name 'req-amd64.dll' -MachineValue 0x8664
$arm64x = New-Pe -Name 'req-arm64x.dll' -MachineValue 0xAA64 -DataDirs @{ 10 = @(0x1000, 0x140) } -SectionData $hybrid64
$arm64ec = New-Pe -Name 'req-arm64ec.dll' -MachineValue 0x8664 -DataDirs @{ 10 = @(0x1000, 0x140) } -SectionData $hybrid64
$ecRaw = New-Pe -Name 'req-ecraw.dll' -MachineValue 0xA641
$xRaw = New-Pe -Name 'req-xraw.dll' -MachineValue 0xA64E

Assert-Equal 0 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', $arm64)).ExitCode 'an ARM64 binary satisfies -RequireMachine arm64'

foreach ($rejected in @(
        @($amd64,   'AMD64'),
        @($arm64x,  'ARM64X'),
        @($arm64ec, 'ARM64EC'),
        @($ecRaw,   'ARM64EC 0xA641'),
        @($xRaw,    'ARM64X 0xA64E'),
        @($notPe,   'a non-PE file'),
        @($tiny,    'a truncated file'))) {
    Assert-Equal 1 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', $rejected[0])).ExitCode `
        "-RequireMachine arm64 rejects $($rejected[1])"
}

Assert-Equal 1 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', $arm64, $amd64)).ExitCode `
    'one bad binary fails the whole batch'

$allowList = Join-Path $work 'allow.txt'
[System.IO.File]::WriteAllText($allowList, "# reviewed`n$amd64`n")
Assert-Equal 0 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', '-AllowList', $allowList, $arm64, $amd64)).ExitCode `
    'an allowlisted path is exempt from -RequireMachine'
Assert-Equal 1 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', '-AllowList', $allowList, $arm64, $arm64x)).ExitCode `
    'an allowlist exempts nothing else'
Assert-Equal 2 (Invoke-PeImports -Arguments @('-RequireMachine', 'sparc', $arm64)).ExitCode `
    'an unknown machine name is a usage error rather than a silent pass'
Assert-Equal 2 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', '-AllowList', (Join-Path $work 'no-such-allowlist'), $arm64)).ExitCode `
    'a missing allowlist is a usage error rather than a silent pass'

Write-Host "# a file argument is never bound to a named parameter"

$r = Invoke-PeImports -Arguments @('-Machine', $arm64, $amd64)
Assert-Equal 0 $r.ExitCode 'positional binding is off, so file arguments stay file arguments'
Assert-Equal 2 (($r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }) | Measure-Object).Count '-Machine emits one line per input'

Write-Host "# -Machine reports rather than enforces"

$r = Invoke-PeImports -Arguments @('-Machine', $arm64, $amd64, $notPe)
Assert-Equal 0 $r.ExitCode '-Machine exits zero even for unclassifiable inputs'
Assert-Equal 3 (($r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }) | Measure-Object).Count '-Machine accounts for every input'

Write-Host "# -PathFile"

$pathFile = Join-Path $work 'paths.txt'
[System.IO.File]::WriteAllText($pathFile, "$arm64`n$amd64`n")
$r = Invoke-PeImports -Arguments @('-Machine', '-PathFile', $pathFile)
Assert-Equal 0 $r.ExitCode '-PathFile is accepted'
Assert-Equal 2 (($r.Stdout -split "`n" | Where-Object { $_.Trim() -ne '' }) | Measure-Object).Count '-PathFile inspects every listed path'
Assert-Equal 1 (Invoke-PeImports -Arguments @('-RequireMachine', 'arm64', '-PathFile', $pathFile)).ExitCode `
    '-PathFile inputs are enforced like command-line inputs'
Assert-Equal 2 (Invoke-PeImports -Arguments @('-Machine', '-PathFile', (Join-Path $work 'no-such-list'))).ExitCode `
    'a missing path file is a usage error rather than a silent pass'

# A bracket in a path is why -PathFile exists: MSYS refuses to convert such an
# argument, so it must never have to.
$bracket = New-Pe -Name '[.exe' -MachineValue 0x8664
[System.IO.File]::WriteAllText($pathFile, "$bracket`n")
$r = Invoke-PeImports -Arguments @('-Machine', '-PathFile', $pathFile)
Assert-Equal 'amd64' (($r.Stdout -split "`n")[0].Split("`t")[0]) 'a path containing a bracket is read literally'

Write-Host "# default mode still speaks objdump"

$r = Invoke-PeImports -Arguments @($arm64)
Assert-Equal 0 $r.ExitCode 'default mode succeeds on a valid PE'
Assert-Equal "${arm64}:" (($r.Stdout -split "`n")[0].TrimEnd("`r")) 'default mode emits the objdump-style header'

$r = Invoke-PeImports -Arguments @($notPe)
Assert-Equal 1 $r.ExitCode 'default mode fails on an unparseable input instead of exiting zero'

Remove-Item -Recurse -Force $work

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAILED $($script:failures) of $($script:checks) checks"
    exit 1
}
Write-Host "passed all $($script:checks) checks"
exit 0
