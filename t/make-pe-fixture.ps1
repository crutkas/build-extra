# Build minimal but structurally valid PE files for the test suite.
#
# Dot-source it to get New-TestPe, or run it to write a single fixture:
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File t/make-pe-fixture.ps1 \
#       -Out C:\tmp\thing.exe -MachineValue 0xAA64 [-Bits 32|64] [-Hybrid] [-AnyCpu]
#
# Fixtures are synthesised rather than checked in so that one header field can
# be varied at a time, and so that truncated and malformed inputs can be
# produced exactly.

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Out,
    [int]$MachineValue = 0xAA64,
    [int]$Bits = 64,
    [switch]$Hybrid,
    [switch]$AnyCpu,
    [switch]$AnyCpu32,
    [switch]$Requires32,
    [switch]$MixedMode
)

Set-StrictMode -Version 2.0

function New-TestPeBytes {
    param(
        [int]$MachineValue,
        [bool]$Is64Bit = $true,
        [hashtable]$DataDirs = @{},
        [byte[]]$SectionData = @(),
        [int]$TruncateTo = 0,
        [int]$OptionalHeaderSize = -1,
        [int]$OverrideMagic = 0
    )

    $peOff = 0x80
    $optHdrOff = $peOff + 4 + 20
    if ($Is64Bit) { $realOptSize = 112 + 16 * 8 } else { $realOptSize = 96 + 16 * 8 }
    if ($OptionalHeaderSize -lt 0) { $optSize = $realOptSize } else { $optSize = $OptionalHeaderSize }
    $sectionTableOff = $optHdrOff + $optSize
    # Round the raw data up so that it cannot overlap the section table.
    $rawDataOff = [int]([Math]::Ceiling(($sectionTableOff + 40) / 512.0) * 512)

    $payload = [Math]::Max($SectionData.Length, 16)
    $b = New-Object byte[] ($rawDataOff + $payload)

    $b[0] = 0x4D; $b[1] = 0x5A                                            # MZ
    [Array]::Copy([BitConverter]::GetBytes([int]$peOff), 0, $b, 0x3C, 4)  # e_lfanew
    $b[$peOff] = 0x50; $b[$peOff + 1] = 0x45                              # PE\0\0

    [Array]::Copy([BitConverter]::GetBytes([uint16]$MachineValue), 0, $b, $peOff + 4, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $b, $peOff + 6, 2)          # NumberOfSections
    [Array]::Copy([BitConverter]::GetBytes([uint16]$optSize), 0, $b, $peOff + 20, 2)  # SizeOfOptionalHeader

    if ($OverrideMagic -ne 0) {
        $magic = $OverrideMagic
    } elseif ($Is64Bit) {
        $magic = 0x20B
    } else {
        $magic = 0x10B
    }
    if ($optSize -ge 2) {
        [Array]::Copy([BitConverter]::GetBytes([uint16]$magic), 0, $b, $optHdrOff, 2)
    }

    if ($Is64Bit) { $dataDirBase = $optHdrOff + 112 } else { $dataDirBase = $optHdrOff + 96 }
    foreach ($index in $DataDirs.Keys) {
        $entry = $DataDirs[$index]
        $o = $dataDirBase + [int]$index * 8
        if (($o + 8) -le $b.Length) {
            [Array]::Copy([BitConverter]::GetBytes([uint32]$entry[0]), 0, $b, $o, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$entry[1]), 0, $b, $o + 4, 4)
        }
    }

    # Section header: Name, VirtualSize, VirtualAddress, SizeOfRawData,
    # PointerToRawData.
    $name8 = [System.Text.Encoding]::ASCII.GetBytes('.rdata')
    [Array]::Copy($name8, 0, $b, $sectionTableOff, $name8.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $b, $sectionTableOff + 8, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $b, $sectionTableOff + 12, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$payload), 0, $b, $sectionTableOff + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$rawDataOff), 0, $b, $sectionTableOff + 20, 4)

    if ($SectionData.Length -gt 0) {
        [Array]::Copy($SectionData, 0, $b, $rawDataOff, $SectionData.Length)
    }

    if ($TruncateTo -gt 0 -and $TruncateTo -lt $b.Length) {
        $b = $b[0..($TruncateTo - 1)]
    }

    return $b
}

function New-TestPe {
    param(
        [string]$Path,
        [int]$MachineValue,
        [bool]$Is64Bit = $true,
        [hashtable]$DataDirs = @{},
        [byte[]]$SectionData = @(),
        [int]$TruncateTo = 0,
        [int]$OptionalHeaderSize = -1,
        [int]$OverrideMagic = 0
    )

    $bytes = New-TestPeBytes -MachineValue $MachineValue -Is64Bit $Is64Bit -DataDirs $DataDirs `
        -SectionData $SectionData -TruncateTo $TruncateTo `
        -OptionalHeaderSize $OptionalHeaderSize -OverrideMagic $OverrideMagic
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    return $Path
}

# A load configuration directory with a non-zero CHPEMetadataPointer, which is
# what makes an image ARM64EC or ARM64X rather than plain AMD64 or ARM64.
# The field sits at 0xC8 in the 64-bit layout and 0x7C in the 32-bit one.
function New-HybridLoadConfig {
    param([bool]$Is64Bit = $true)
    if ($Is64Bit) { $field = 0xC8; $size = 0x140 } else { $field = 0x7C; $size = 0xB0 }
    $data = New-Object byte[] $size
    [Array]::Copy([BitConverter]::GetBytes([uint32]$size), 0, $data, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x2000), 0, $data, $field, 4)
    return $data
}

# IMAGE_COR20_HEADER. COMIMAGE_FLAGS_ILONLY is 0x1, 32BITREQUIRED 0x2,
# NATIVE_ENTRYPOINT 0x10 and 32BITPREFERRED 0x20000.
function New-ClrHeader {
    param([uint32]$Flags = 0x1, [int]$Size = 72, [int]$DeclaredSize = -1)
    $data = New-Object byte[] $Size
    if ($DeclaredSize -lt 0) { $DeclaredSize = 72 }
    if ($Size -ge 4) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]$DeclaredSize), 0, $data, 0, 4)
    }
    if ($Size -ge 20) {
        [Array]::Copy([BitConverter]::GetBytes($Flags), 0, $data, 16, 4)
    }
    return $data
}

if ($Out -ne '') {
    $is64 = ($Bits -eq 64)
    $dirs = @{}
    $data = @()

    if ($Hybrid) {
        $dirs[10] = @(0x1000, 0x140)
        $data = New-HybridLoadConfig -Is64Bit $is64
    } elseif ($AnyCpu) {
        $dirs[14] = @(0x1000, 72)
        $data = New-ClrHeader -Flags 0x1
    } elseif ($AnyCpu32) {
        # 32BITPREFERRED is only ever set alongside 32BITREQUIRED.
        $dirs[14] = @(0x1000, 72)
        $data = New-ClrHeader -Flags 0x20003
    } elseif ($Requires32) {
        $dirs[14] = @(0x1000, 72)
        $data = New-ClrHeader -Flags 0x3
    } elseif ($MixedMode) {
        $dirs[14] = @(0x1000, 72)
        $data = New-ClrHeader -Flags 0x0
    }

    $null = New-TestPe -Path $Out -MachineValue $MachineValue -Is64Bit $is64 `
        -DataDirs $dirs -SectionData $data
}
