# pe-imports.ps1 - Parse PE import tables and COFF machine types.
#
# Without switches the output is `objdump -p` compatible, so
# check-for-missing-dlls.sh can use it as a drop-in replacement when
# /usr/bin/objdump cannot handle the PE architecture (e.g. pei-aarch64).
#
# With -Machine, one "<machine><TAB><file>" line is written per input instead,
# which is what check-payload-architecture.sh consumes. Files that cannot be
# classified report their failure reason in the machine column rather than
# being silently skipped.
#
# With -RequireMachine, the machine type of every input is enforced and the
# script exits non-zero when any input does not match. -AllowList names a file
# listing paths that are exempt from that enforcement.
#
# -PathFile names a file of paths, one per line, to inspect in addition to the
# command line. Callers should prefer it: it has no command-line length limit,
# and it avoids both the quoting of paths containing spaces and MSYS argument
# conversion, which silently refuses to convert a path containing a bracket
# such as `usr/bin/[.exe`.
#
# With -Magic, only the first two bytes of each input are read and one
# "mz|other|unreadable<TAB><file>" line is written per input. That is what lets
# a caller ask whether anything it declined to classify is in fact an image.
#
# PE format reference:
# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
#
# Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File pe-imports.ps1
#            [-Machine] [-RequireMachine <name>] [-AllowList <file>]
#            [-PathFile <file>] [FILE...]

# PositionalBinding is off so that a file argument can never be bound to
# -RequireMachine or -AllowList by position.
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Machine,
    [switch]$Magic,
    [string]$RequireMachine,
    [string]$AllowList,
    [string]$PathFile,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0

# IMAGE_FILE_MACHINE_* from winnt.h. Anything absent is reported as
# "unknown-0x<value>", so an unrecognised machine can never be mistaken for a
# recognised one.
$MachineNames = @{
    0x014c = 'i386'
    0x01c0 = 'arm'
    0x01c2 = 'thumb'
    0x01c4 = 'armnt'
    0x0200 = 'ia64'
    0x0ebc = 'ebc'
    0x5032 = 'riscv32'
    0x5064 = 'riscv64'
    0x6264 = 'loongarch64'
    0x8664 = 'amd64'
    0xa641 = 'arm64ec'
    0xa64e = 'arm64x'
    0xaa64 = 'arm64'
}

# Classes derived from more than the COFF machine word. `anycpu` is a managed
# assembly the runtime compiles for whatever it runs on, and is the only class
# the ratchet accepts as architecture-neutral. `anycpu32` is a managed assembly
# marked 32BITPREFERRED, which starts a 32-bit process wherever one can be
# started and so is emulated on ARM64; it is deliberately not neutral.
# `chpe-x86` is a hybrid x86 image, the 32-bit sibling of ARM64EC.
$DerivedClasses = @('anycpu', 'anycpu32', 'chpe-x86')

function New-PeResult {
    param([string]$File, [string]$Status, [string]$MachineName, [int]$MachineValue, [string]$Detail)

    New-Object PSObject -Property @{
        File         = $File
        Status       = $Status
        Machine      = $MachineName
        MachineValue = $MachineValue
        Detail       = $Detail
        Imports      = New-Object System.Collections.ArrayList
    }
}

function Get-U16 { param([byte[]]$Bytes, [int]$Offset) [BitConverter]::ToUInt16($Bytes, $Offset) }
function Get-U32 { param([byte[]]$Bytes, [int]$Offset) [BitConverter]::ToUInt32($Bytes, $Offset) }

# Translate an RVA to a file offset, or -1 when it falls outside every section.
# Per the PE spec an RVA belongs to a section when
# VirtualAddress <= RVA < VirtualAddress + VirtualSize.
# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
function Convert-RvaToOffset {
    param([uint32]$Rva, $Sections)

    foreach ($s in $Sections) {
        if ($Rva -ge $s.VirtualAddress -and $Rva -lt ($s.VirtualAddress + $s.VirtualSize)) {
            return [int64]$Rva - [int64]$s.VirtualAddress + [int64]$s.PointerToRawData
        }
    }
    return -1
}

# Walk an import descriptor array and collect the imported DLL names.
function Read-ImportNames {
    param([byte[]]$Bytes, $Sections, [uint32]$DescRva, [uint32]$DescRvaSize,
          [int]$DescSize, [int]$NameField, $Into)

    $p = Convert-RvaToOffset -Rva $DescRva -Sections $Sections
    if ($p -lt 0) { return }

    $remaining = [int64]$DescRvaSize
    while ($remaining -ge $DescSize -and ($p + $DescSize) -le $Bytes.Length) {
        $nameRva = Get-U32 -Bytes $Bytes -Offset ([int]$p + $NameField)
        if ($nameRva -eq 0) { break }

        $nameOffset = Convert-RvaToOffset -Rva $nameRva -Sections $Sections
        if ($nameOffset -lt 0 -or $nameOffset -ge $Bytes.Length) { break }

        $end = [int]$nameOffset
        while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) { $end++ }

        $null = $Into.Add([System.Text.Encoding]::ASCII.GetString($Bytes, [int]$nameOffset, $end - [int]$nameOffset))

        $p += $DescSize
        $remaining -= $DescSize
    }
}

# An ARM64EC image reports IMAGE_FILE_MACHINE_AMD64, an ARM64X image reports
# IMAGE_FILE_MACHINE_ARM64 and a CHPE x86 image reports IMAGE_FILE_MACHINE_I386,
# so the COFF machine alone cannot tell any of them apart from an ordinary
# binary. All three carry a non-zero CHPEMetadataPointer in the load
# configuration directory, at offset 0xC8 of IMAGE_LOAD_CONFIG_DIRECTORY64 and
# 0x7C of the 32-bit variant, where it follows DynamicValueRelocTable at 0x78.
#
# Returns 'none', 'hybrid' or 'malformed'. A load configuration that is too
# short to contain the field predates it and is reported as 'none'; one we
# cannot read at all is 'malformed', so a corrupt directory is never quietly
# reported as an ordinary ARM64 or AMD64 binary.
function Get-HybridState {
    param([byte[]]$Bytes, $Sections, [uint32]$LoadConfigRva, [bool]$Is64Bit)

    if ($LoadConfigRva -eq 0) { return 'none' }

    $offset = Convert-RvaToOffset -Rva $LoadConfigRva -Sections $Sections
    if ($offset -lt 0) { return 'malformed' }
    if (($offset + 4) -gt $Bytes.Length) { return 'malformed' }

    $declaredSize = Get-U32 -Bytes $Bytes -Offset ([int]$offset)
    if ($Is64Bit) { $field = 0xC8; $width = 8 } else { $field = 0x7C; $width = 4 }

    if ($declaredSize -lt ($field + $width)) { return 'none' }
    if (($offset + $field + $width) -gt $Bytes.Length) { return 'malformed' }

    if ($Is64Bit) {
        $value = [BitConverter]::ToUInt64($Bytes, [int]$offset + $field)
    } else {
        $value = Get-U32 -Bytes $Bytes -Offset ([int]$offset + $field)
    }
    if ($value -ne 0) { return 'hybrid' }
    return 'none'
}

# Classify the CLR header, which decides whether the COFF machine says anything
# useful about the architecture. Returns:
#
#   none            not a managed assembly
#   anycpu          IL only, neither 32-bit required nor 32-bit preferred, so
#                   the runtime compiles it for whatever it is running on
#   anycpu32        IL only but 32BITPREFERRED, which starts a 32-bit process
#                   wherever one can be started, and so is emulated on ARM64
#   managed-native  mixed mode, a native entry point or ReadyToRun, all of
#                   which contain native code; the COFF machine governs
#   malformed       the directory is unreadable or too small to trust
#
# https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutablekinds
function Get-ManagedClass {
    param([byte[]]$Bytes, $Sections, [uint32]$ClrRva, [uint32]$ClrSize)

    if ($ClrRva -eq 0) { return 'none' }

    # IMAGE_COR20_HEADER is 72 bytes; anything shorter cannot be one.
    if ($ClrSize -lt 72) { return 'malformed' }

    $offset = Convert-RvaToOffset -Rva $ClrRva -Sections $Sections
    if ($offset -lt 0) { return 'malformed' }
    if (($offset + 72) -gt $Bytes.Length) { return 'malformed' }

    $cb = Get-U32 -Bytes $Bytes -Offset ([int]$offset)
    if ($cb -lt 72) { return 'malformed' }

    $flags = Get-U32 -Bytes $Bytes -Offset ([int]$offset + 16)
    $ilOnly = ($flags -band 0x00000001) -ne 0
    $requires32Bit = ($flags -band 0x00000002) -ne 0
    $nativeEntryPoint = ($flags -band 0x00000010) -ne 0
    $prefers32Bit = ($flags -band 0x00020000) -ne 0

    if (-not $ilOnly) { return 'managed-native' }
    if ($nativeEntryPoint) { return 'managed-native' }
    if ($prefers32Bit) { return 'anycpu32' }
    if ($requires32Bit) { return 'managed-native' }
    return 'anycpu'
}

function Get-PeInfo {
    param([string]$File)

    try {
        $bytes = [System.IO.File]::ReadAllBytes($File)
    } catch {
        return New-PeResult -File $File -Status 'unreadable' -MachineName 'unreadable' -MachineValue -1 -Detail 'cannot read file'
    }

    # `MZ`: DOS stub
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        return New-PeResult -File $File -Status 'not-pe' -MachineName 'not-pe' -MachineValue -1 -Detail 'not a PE file'
    }

    $peSignatureOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peSignatureOffset -lt 0 -or ($peSignatureOffset + 24) -gt $bytes.Length) {
        return New-PeResult -File $File -Status 'truncated' -MachineName 'truncated' -MachineValue -1 -Detail 'COFF header beyond end of file'
    }

    # Look for `PE\0\0`
    if ($bytes[$peSignatureOffset] -ne 0x50 -or $bytes[$peSignatureOffset + 1] -ne 0x45 -or
        $bytes[$peSignatureOffset + 2] -ne 0 -or $bytes[$peSignatureOffset + 3] -ne 0) {
        return New-PeResult -File $File -Status 'not-pe' -MachineName 'not-pe' -MachineValue -1 -Detail 'bad PE signature'
    }
    $peOffset = $peSignatureOffset + 4

    # IMAGE_FILE_HEADER: Machine is the first field.
    # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
    $machineValue = [int](Get-U16 -Bytes $bytes -Offset $peOffset)
    $numSections = [int](Get-U16 -Bytes $bytes -Offset ($peOffset + 2))
    $optHdrSize = [int](Get-U16 -Bytes $bytes -Offset ($peOffset + 16))
    $optHdrOff = $peOffset + 20

    if ($MachineNames.ContainsKey($machineValue)) {
        $machineName = $MachineNames[$machineValue]
    } else {
        $machineName = 'unknown-0x{0:x4}' -f $machineValue
    }

    if ($optHdrSize -eq 0) {
        return New-PeResult -File $File -Status 'malformed' -MachineName 'malformed' -MachineValue $machineValue -Detail 'no optional header'
    }
    if (($optHdrOff + $optHdrSize) -gt $bytes.Length) {
        return New-PeResult -File $File -Status 'truncated' -MachineName 'truncated' -MachineValue $machineValue -Detail 'optional header beyond end of file'
    }

    # See https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
    $magic = Get-U16 -Bytes $bytes -Offset $optHdrOff
    if ($magic -eq 0x10B) {
        $dataDirBase = $optHdrOff + 96          # PE32
        $is64Bit = $false
    } elseif ($magic -eq 0x20B) {
        $dataDirBase = $optHdrOff + 112         # PE32+ (x64/ARM64)
        $is64Bit = $true
    } else {
        return New-PeResult -File $File -Status 'malformed' -MachineName 'malformed' -MachineValue $machineValue `
            -Detail ('unknown optional header magic 0x{0:X4}' -f $magic)
    }
    $optHdrEnd = $optHdrOff + $optHdrSize

    $sectionStart = $optHdrOff + $optHdrSize
    if (($sectionStart + $numSections * 40) -gt $bytes.Length) {
        return New-PeResult -File $File -Status 'truncated' -MachineName 'truncated' -MachineValue $machineValue -Detail 'section table beyond end of file'
    }

    $sections = @()
    for ($i = 0; $i -lt $numSections; $i++) {
        $o = $sectionStart + $i * 40
        $sections += New-Object PSObject -Property @{
            VirtualSize      = Get-U32 -Bytes $bytes -Offset ($o + 8)
            VirtualAddress   = Get-U32 -Bytes $bytes -Offset ($o + 12)
            PointerToRawData = Get-U32 -Bytes $bytes -Offset ($o + 20)
        }
    }

    # Data directory entries are 8 bytes each: index 1 is the import table,
    # index 10 the load configuration, index 13 the delay-load imports and
    # index 14 the CLR header. For details, see
    # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    $readDir = {
        param([int]$Index)
        $o = $dataDirBase + $Index * 8
        if (($o + 8) -gt $optHdrEnd -or ($o + 8) -gt $bytes.Length) {
            return @([uint32]0, [uint32]0)
        }
        return @((Get-U32 -Bytes $bytes -Offset $o), (Get-U32 -Bytes $bytes -Offset ($o + 4)))
    }

    $importDir = & $readDir 1
    $loadConfigDir = & $readDir 10
    $delayDir = & $readDir 13
    $clrDir = & $readDir 14

    $managed = Get-ManagedClass -Bytes $bytes -Sections $sections -ClrRva $clrDir[0] -ClrSize $clrDir[1]
    if ($managed -eq 'malformed') {
        return New-PeResult -File $File -Status 'malformed' -MachineName 'malformed' -MachineValue $machineValue `
            -Detail 'unreadable CLR header'
    }

    if ($managed -eq 'anycpu') {
        $machineName = 'anycpu'
    } elseif ($managed -eq 'anycpu32') {
        $machineName = 'anycpu32'
    } elseif ($machineValue -eq 0xaa64 -or $machineValue -eq 0x8664 -or $machineValue -eq 0x014c) {
        # The three machines for which a hybrid image exists. A directory we
        # cannot read is fatal here: reporting the COFF machine instead would
        # pass an ARM64X image off as ordinary ARM64.
        $hybrid = Get-HybridState -Bytes $bytes -Sections $sections `
            -LoadConfigRva $loadConfigDir[0] -Is64Bit $is64Bit
        if ($hybrid -eq 'malformed') {
            return New-PeResult -File $File -Status 'malformed' -MachineName 'malformed' -MachineValue $machineValue `
                -Detail 'unreadable load configuration directory'
        }
        if ($hybrid -eq 'hybrid') {
            if ($machineValue -eq 0xaa64) {
                $machineName = 'arm64x'
            } elseif ($machineValue -eq 0x8664) {
                $machineName = 'arm64ec'
            } else {
                $machineName = 'chpe-x86'
            }
        }
    }
    $result = New-PeResult -File $File -Status 'ok' -MachineName $machineName -MachineValue $machineValue -Detail ''

    if ($importDir[0] -ne 0 -and $importDir[1] -ne 0) {
        Read-ImportNames -Bytes $bytes -Sections $sections -DescRva $importDir[0] `
            -DescRvaSize $importDir[1] -DescSize 20 -NameField 12 -Into $result.Imports
    }
    if ($delayDir[0] -ne 0 -and $delayDir[1] -ne 0) {
        Read-ImportNames -Bytes $bytes -Sections $sections -DescRva $delayDir[0] `
            -DescRvaSize $delayDir[1] -DescSize 32 -NameField 4 -Into $result.Imports
    }

    return $result
}

# Ordinal, not the default case-insensitive hashtable comparer: an allowlist
# spelled ARM64EC.DLL must not exempt arm64ec.dll.
$allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
if ($AllowList -ne '') {
    if (-not (Test-Path -LiteralPath $AllowList)) {
        Write-Error "pe-imports: ${AllowList}: allowlist not found"
        exit 2
    }
    foreach ($line in @(Get-Content -LiteralPath $AllowList)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $null = $allowed.Add($trimmed)
    }
}

if ($RequireMachine -ne '' -and -not ($MachineNames.Values -contains $RequireMachine) -and
    -not ($DerivedClasses -contains $RequireMachine)) {
    Write-Error "pe-imports: unknown machine name '$RequireMachine'"
    exit 2
}

$failed = $false

# Read only the first two bytes. This is for the negative reconciliation in
# check-payload-architecture.sh, which has to ask "is anything I did not select
# actually an image?" of every remaining payload entry, and must not read whole
# files to answer it.
function Test-MzMagic {
    param([string]$File)

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($File, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $first = $stream.ReadByte()
        $second = $stream.ReadByte()
        if ($first -eq 0x4D -and $second -eq 0x5A) { return 'mz' }
        return 'other'
    } catch {
        return 'unreadable'
    } finally {
        if ($stream -ne $null) { $stream.Dispose() }
    }
}

$inputs = New-Object System.Collections.ArrayList
if ($PathFile -ne '') {
    if (-not (Test-Path -LiteralPath $PathFile)) {
        Write-Error "pe-imports: ${PathFile}: path file not found"
        exit 2
    }
    foreach ($line in @(Get-Content -LiteralPath $PathFile)) {
        if ($line -ne '') { $null = $inputs.Add($line) }
    }
}
foreach ($p in @($Path)) {
    if ($p -ne $null -and $p -ne '') { $null = $inputs.Add($p) }
}

foreach ($file in $inputs) {
    if ($Magic) {
        Write-Output ("{0}`t{1}" -f (Test-MzMagic -File $file), $file)
        continue
    }

    $info = Get-PeInfo -File $file

    if ($Machine) {
        Write-Output ("{0}`t{1}" -f $info.Machine, $file)
    }

    if ($RequireMachine -ne '') {
        if ($allowed.Contains($file)) { continue }
        if ($info.Machine -ne $RequireMachine) {
            $detail = $info.Machine
            if ($info.Detail -ne '') { $detail = "$($info.Machine): $($info.Detail)" }
            Write-Error "pe-imports: ${file}: expected $RequireMachine, got $detail"
            $failed = $true
        }
        continue
    }

    if (-not $Machine) {
        if ($info.Status -ne 'ok') {
            Write-Error "pe-imports: ${file}: $($info.Detail)"
            $failed = $true
            continue
        }
        Write-Output "${file}:"
        foreach ($name in $info.Imports) {
            Write-Output "$([char]9)DLL Name: $name"
        }
    }
}

if ($failed) { exit 1 }
exit 0
