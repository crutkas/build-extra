Set-StrictMode -Version 2.0

$script:Utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$script:Ascii = New-Object System.Text.ASCIIEncoding
$script:Ordinal = [System.StringComparer]::Ordinal
$script:OrdinalIgnoreCase = [System.StringComparer]::OrdinalIgnoreCase

if (-not ('Arm64Ledger.NativePath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Arm64Ledger
{
    public sealed class Utf8BytewiseComparer : IComparer<string>
    {
        public static readonly Utf8BytewiseComparer Instance =
            new Utf8BytewiseComparer();

        public int Compare(string left, string right)
        {
            if (Object.ReferenceEquals(left, right))
                return 0;
            if (left == null)
                return -1;
            if (right == null)
                return 1;

            byte[] a = Encoding.UTF8.GetBytes(left);
            byte[] b = Encoding.UTF8.GetBytes(right);
            int count = Math.Min(a.Length, b.Length);
            for (int i = 0; i < count; i++)
            {
                int comparison = a[i].CompareTo(b[i]);
                if (comparison != 0)
                    return comparison;
            }
            return a.Length.CompareTo(b.Length);
        }
    }

    public sealed class PathIdentity
    {
        public string FinalPath;
        public uint VolumeSerialNumber;
        public ulong FileId;
        public FileAttributes Attributes;
        public long Length;
        public long LastWriteTimeUtcTicks;
    }

    public static class NativePath
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint FILE_SHARE_DELETE = 0x4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint MOVEFILE_REPLACE_EXISTING = 0x1;
        private const uint MOVEFILE_WRITE_THROUGH = 0x8;

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle, StringBuilder path, uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern bool MoveFileExW(
            string existingFileName, string newFileName, uint flags);

        public static PathIdentity Inspect(string path)
        {
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT;
            if (Directory.Exists(path))
                flags |= FILE_FLAG_BACKUP_SEMANTICS;

            using (SafeFileHandle handle = CreateFileW(
                path, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero))
            {
                if (handle.IsInvalid)
                    throw new IOException(
                        "CreateFileW failed for protected path",
                        new System.ComponentModel.Win32Exception(
                            Marshal.GetLastWin32Error()));

                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new IOException(
                        "GetFileInformationByHandle failed",
                        new System.ComponentModel.Win32Exception(
                            Marshal.GetLastWin32Error()));

                StringBuilder finalPath = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandleW(
                    handle, finalPath, (uint)finalPath.Capacity, 0);
                if (length == 0 || length >= finalPath.Capacity)
                    throw new IOException(
                        "GetFinalPathNameByHandleW failed",
                        new System.ComponentModel.Win32Exception(
                            Marshal.GetLastWin32Error()));

                string normalized = finalPath.ToString();
                if (normalized.StartsWith(@"\\?\UNC\",
                    StringComparison.Ordinal))
                    normalized = @"\\" + normalized.Substring(8);
                else if (normalized.StartsWith(@"\\?\",
                    StringComparison.Ordinal))
                    normalized = normalized.Substring(4);

                long writeTicks =
                    ((long)info.LastWriteTime.dwHighDateTime << 32) |
                    (uint)info.LastWriteTime.dwLowDateTime;
                return new PathIdentity {
                    FinalPath = normalized,
                    VolumeSerialNumber = info.VolumeSerialNumber,
                    FileId = ((ulong)info.FileIndexHigh << 32) |
                        info.FileIndexLow,
                    Attributes = (FileAttributes)info.FileAttributes,
                    Length = ((long)info.FileSizeHigh << 32) |
                        info.FileSizeLow,
                    LastWriteTimeUtcTicks = writeTicks
                };
            }
        }

        public static void AtomicReplace(string source, string destination)
        {
            if (!MoveFileExW(source, destination,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw new IOException(
                    "MoveFileExW failed",
                    new System.ComponentModel.Win32Exception(
                        Marshal.GetLastWin32Error()));
        }
    }
}
'@
}

function New-LedgerError {
    param([Parameter(Mandatory = $true)][string]$Message)
    return New-Object System.IO.InvalidDataException($Message)
}

function New-OrdinalDictionary {
    return New-Object System.Collections.Specialized.OrderedDictionary (
        [System.StringComparer]::Ordinal)
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString(
            $algorithm.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-GitBlobSha1 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $header = $script:Ascii.GetBytes("blob $($Bytes.Length)`0")
    $algorithm = [System.Security.Cryptography.SHA1]::Create()
    try {
        [void]$algorithm.TransformBlock(
            $header, 0, $header.Length, $header, 0)
        [void]$algorithm.TransformFinalBlock($Bytes, 0, $Bytes.Length)
        return ([System.BitConverter]::ToString(
            $algorithm.Hash)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Read-StableBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [long]$MaximumLength = 67108864
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    Assert-SafeExistingPath -Path $fullPath -Kind File | Out-Null
    $stream = New-Object System.IO.FileStream(
        $fullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $before = [Arm64Ledger.NativePath]::Inspect($fullPath)
        if ($stream.Length -gt $MaximumLength) {
            throw (New-LedgerError "File exceeds the permitted size: $fullPath")
        }
        if ($stream.Length -gt [int]::MaxValue) {
            throw (New-LedgerError "File cannot be represented safely: $fullPath")
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw (New-LedgerError "Unexpected EOF while reading $fullPath")
            }
            $offset += $read
        }
        $after = [Arm64Ledger.NativePath]::Inspect($fullPath)
        if ($before.VolumeSerialNumber -ne $after.VolumeSerialNumber -or
            $before.FileId -ne $after.FileId -or
            $before.Length -ne $after.Length -or
            $before.LastWriteTimeUtcTicks -ne $after.LastWriteTimeUtcTicks) {
            throw (New-LedgerError "File identity changed while reading: $fullPath")
        }
        return ,$bytes
    } finally {
        $stream.Dispose()
    }
}

function Get-StableFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    Assert-SafeExistingPath -Path $fullPath -Kind File | Out-Null
    $stream = New-Object System.IO.FileStream(
        $fullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $before = [Arm64Ledger.NativePath]::Inspect($fullPath)
        $hash = $algorithm.ComputeHash($stream)
        $after = [Arm64Ledger.NativePath]::Inspect($fullPath)
        if ($before.VolumeSerialNumber -ne $after.VolumeSerialNumber -or
            $before.FileId -ne $after.FileId -or
            $before.Length -ne $after.Length -or
            $before.LastWriteTimeUtcTicks -ne $after.LastWriteTimeUtcTicks) {
            throw (New-LedgerError "File identity changed while hashing: $fullPath")
        }
        return [ordered]@{
            length = [long]$before.Length
            sha256 = ([System.BitConverter]::ToString(
                $hash)).Replace('-', '').ToLowerInvariant()
        }
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Test-ContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).
        TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if ($script:OrdinalIgnoreCase.Equals($fullPath, $fullRoot)) {
        return $true
    }
    return $fullPath.StartsWith(
        $fullRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafeExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('File', 'Directory')][string]$Kind,
        [string]$AllowedRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($Kind -eq 'File' -and
        -not [System.IO.File]::Exists($fullPath)) {
        throw (New-LedgerError "Required file does not exist: $fullPath")
    }
    if ($Kind -eq 'Directory' -and
        -not [System.IO.Directory]::Exists($fullPath)) {
        throw (New-LedgerError "Required directory does not exist: $fullPath")
    }
    if ($AllowedRoot -and
        -not (Test-ContainedPath -Path $fullPath -Root $AllowedRoot)) {
        throw (New-LedgerError "Path is outside its permitted root: $fullPath")
    }

    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $relative = $fullPath.Substring($root.Length)
    $current = $root.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    foreach ($component in $relative.Split(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = if ($current.EndsWith(':')) {
            $current + [System.IO.Path]::DirectorySeparatorChar + $component
        } else {
            [System.IO.Path]::Combine($current, $component)
        }
        $attributes = [System.IO.File]::GetAttributes($current)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (New-LedgerError "Reparse points are forbidden: $current")
        }
    }

    $identity = [Arm64Ledger.NativePath]::Inspect($fullPath)
    if (($identity.Attributes -band
        [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw (New-LedgerError "Reparse point identity is forbidden: $fullPath")
    }
    if (-not $script:OrdinalIgnoreCase.Equals(
        $identity.FinalPath.TrimEnd('\'),
        $fullPath.TrimEnd('\'))) {
        throw (New-LedgerError "Path alias is forbidden: $fullPath")
    }
    return $identity
}

function Assert-IdentityUnchanged {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $after = [Arm64Ledger.NativePath]::Inspect(
        [System.IO.Path]::GetFullPath($Path))
    if ($Before.VolumeSerialNumber -ne $after.VolumeSerialNumber -or
        $Before.FileId -ne $after.FileId -or
        $Before.Attributes -ne $after.Attributes) {
        throw (New-LedgerError "Protected path identity changed: $Path")
    }
}

function Assert-SafeTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    Assert-SafeExistingPath -Path $fullRoot -Kind Directory | Out-Null
    foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries(
        $fullRoot,
        '*',
        [System.IO.SearchOption]::AllDirectories)) {
        if (-not (Test-ContainedPath -Path $entry -Root $fullRoot)) {
            throw (New-LedgerError(
                "Tree enumeration escaped its root: $entry"))
        }
        $attributes = [System.IO.File]::GetAttributes($entry)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (New-LedgerError "Tree contains a reparse point: $entry")
        }
    }
}

function New-SafePrivateDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$ForbiddenRoots = @()
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.Directory]::Exists($fullPath) -or
        [System.IO.File]::Exists($fullPath)) {
        throw (New-LedgerError "Private root already exists: $fullPath")
    }
    foreach ($forbiddenRoot in $ForbiddenRoots) {
        if (Test-ContainedPath -Path $fullPath -Root $forbiddenRoot) {
            throw (New-LedgerError "Private root is protected: $fullPath")
        }
    }
    $parent = [System.IO.Path]::GetDirectoryName($fullPath)
    Assert-SafeExistingPath -Path $parent -Kind Directory | Out-Null
    [void][System.IO.Directory]::CreateDirectory($fullPath)
    return Assert-SafeExistingPath -Path $fullPath -Kind Directory
}

function Remove-SafePrivateDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$ExpectedIdentity
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    Assert-IdentityUnchanged `
        -Before $ExpectedIdentity `
        -Path $fullPath
    foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries(
        $fullPath,
        '*',
        [System.IO.SearchOption]::AllDirectories)) {
        if (-not (Test-ContainedPath -Path $entry -Root $fullPath)) {
            throw (New-LedgerError(
                "Cleanup enumerated an uncontained path: $entry"))
        }
        $attributes = [System.IO.File]::GetAttributes($entry)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (New-LedgerError(
                "Cleanup refuses a reparse point: $entry"))
        }
        if (($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
            [System.IO.File]::SetAttributes(
                $entry, [System.IO.FileAttributes]::Normal)
        } else {
            [System.IO.File]::SetAttributes(
                $entry, [System.IO.FileAttributes]::Directory)
        }
    }
    [System.IO.File]::SetAttributes(
        $fullPath, [System.IO.FileAttributes]::Directory)
    [System.IO.Directory]::Delete($fullPath, $true)
    if ([System.IO.Directory]::Exists($fullPath) -or
        [System.IO.File]::Exists($fullPath)) {
        throw (New-LedgerError "Private root cleanup did not complete: $fullPath")
    }
}

function Write-CanonicalArtifactSet {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Artifacts
    )

    $fullOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (-not [System.IO.Directory]::Exists($fullOutput)) {
        $missing = New-Object System.Collections.Generic.List[string]
        $cursor = $fullOutput
        while (-not [System.IO.Directory]::Exists($cursor)) {
            $missing.Add($cursor)
            $parent = [System.IO.Path]::GetDirectoryName($cursor)
            if ([string]::IsNullOrEmpty($parent) -or
                $script:OrdinalIgnoreCase.Equals($parent, $cursor)) {
                throw (New-LedgerError(
                    "Cannot resolve output directory parent: $fullOutput"))
            }
            $cursor = $parent
        }
        Assert-SafeExistingPath -Path $cursor -Kind Directory | Out-Null
        for ($index = $missing.Count - 1; $index -ge 0; $index--) {
            [void][System.IO.Directory]::CreateDirectory($missing[$index])
            Assert-SafeExistingPath `
                -Path $missing[$index] -Kind Directory | Out-Null
        }
    }
    $rootIdentity = Assert-SafeExistingPath `
        -Path $fullOutput -Kind Directory
    $expectedNames = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($name in $Artifacts.Keys) {
        if ($name -isnot [string] -or
            $name -notmatch '^[a-z0-9][a-z0-9.-]*\.(?:json|tsv|txt)$' -or
            -not $expectedNames.Add($name)) {
            throw (New-LedgerError "Unsafe artifact name: $name")
        }
        $bytes = $Artifacts[$name]
        if ($bytes -isnot [byte[]]) {
            throw (New-LedgerError "Artifact is not a byte array: $name")
        }
        if ($bytes.Length -eq 0 -or $bytes[-1] -ne 0x0A) {
            throw (New-LedgerError "Artifact lacks final LF: $name")
        }
        foreach ($value in $bytes) {
            if ($value -eq 0x0D) {
                throw (New-LedgerError "Artifact contains CR: $name")
            }
        }
        $destination = [System.IO.Path]::Combine($fullOutput, $name)
        $temporary = [System.IO.Path]::Combine(
            $fullOutput,
            ".$name.$([Guid]::NewGuid().ToString('N')).tmp")
        $stream = New-Object System.IO.FileStream(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        try {
            Assert-IdentityUnchanged `
                -Before $rootIdentity -Path $fullOutput
            [Arm64Ledger.NativePath]::AtomicReplace(
                $temporary, $destination)
            Assert-IdentityUnchanged `
                -Before $rootIdentity -Path $fullOutput
            $written = Read-StableBytes `
                -Path $destination -MaximumLength ($bytes.Length + 1)
            if (-not [System.Linq.Enumerable]::SequenceEqual(
                [byte[]]$bytes, [byte[]]$written)) {
                throw (New-LedgerError(
                    "Artifact changed during atomic write: $name"))
            }
        } finally {
            if ([System.IO.File]::Exists($temporary)) {
                [System.IO.File]::Delete($temporary)
            }
        }
    }
    foreach ($file in [System.IO.Directory]::GetFiles($fullOutput)) {
        $name = [System.IO.Path]::GetFileName($file)
        if (-not $expectedNames.Contains($name)) {
            throw (New-LedgerError(
                "Output directory contains unconsumed file: $name"))
        }
    }
}

function Sort-Bytewise {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    $strings = New-Object string[] $Values.Count
    for ($index = 0; $index -lt $Values.Count; $index++) {
        if ($null -eq $Values[$index] -or
            $Values[$index] -isnot [string]) {
            throw (New-LedgerError 'Bytewise sorting accepts strings only')
        }
        $strings[$index] = [string]$Values[$index]
    }
    [System.Array]::Sort(
        $strings, [Arm64Ledger.Utf8BytewiseComparer]::Instance)
    return ,$strings
}

function Get-JsonCharacter {
    param(
        [Parameter(Mandatory = $true)]$State,
        [switch]$Required
    )

    if ($State.Index -ge $State.Text.Length) {
        if ($Required) {
            throw (New-LedgerError 'Unexpected end of JSON input')
        }
        return $null
    }
    return $State.Text[$State.Index]
}

function Skip-JsonWhitespace {
    param([Parameter(Mandatory = $true)]$State)

    while ($State.Index -lt $State.Text.Length) {
        $character = $State.Text[$State.Index]
        if ($character -ne ' ' -and $character -ne "`t" -and
            $character -ne "`r" -and $character -ne "`n") {
            break
        }
        $State.Index++
    }
}

function Read-JsonString {
    param([Parameter(Mandatory = $true)]$State)

    if ((Get-JsonCharacter -State $State -Required) -ne '"') {
        throw (New-LedgerError "Expected JSON string at offset $($State.Index)")
    }
    $State.Index++
    $builder = New-Object System.Text.StringBuilder
    while ($State.Index -lt $State.Text.Length) {
        $character = $State.Text[$State.Index++]
        if ($character -eq '"') {
            return $builder.ToString()
        }
        if ([int][char]$character -lt 0x20) {
            throw (New-LedgerError 'Unescaped control character in JSON string')
        }
        if ($character -ne '\') {
            [void]$builder.Append($character)
            continue
        }
        if ($State.Index -ge $State.Text.Length) {
            throw (New-LedgerError 'Incomplete JSON escape')
        }
        $escape = $State.Text[$State.Index++]
        switch ($escape) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]8) }
            'f' { [void]$builder.Append([char]12) }
            'n' { [void]$builder.Append("`n") }
            'r' { [void]$builder.Append("`r") }
            't' { [void]$builder.Append("`t") }
            'u' {
                if ($State.Index + 4 -gt $State.Text.Length) {
                    throw (New-LedgerError 'Incomplete JSON Unicode escape')
                }
                $hex = $State.Text.Substring($State.Index, 4)
                if ($hex -notmatch '^[0-9A-Fa-f]{4}$') {
                    throw (New-LedgerError 'Malformed JSON Unicode escape')
                }
                $State.Index += 4
                $value = [Convert]::ToInt32($hex, 16)
                if ($value -ge 0xD800 -and $value -le 0xDBFF) {
                    if ($State.Index + 6 -gt $State.Text.Length -or
                        $State.Text.Substring($State.Index, 2) -ne '\u') {
                        throw (New-LedgerError 'Unpaired high surrogate in JSON')
                    }
                    $lowHex = $State.Text.Substring($State.Index + 2, 4)
                    if ($lowHex -notmatch '^[0-9A-Fa-f]{4}$') {
                        throw (New-LedgerError 'Malformed low surrogate in JSON')
                    }
                    $low = [Convert]::ToInt32($lowHex, 16)
                    if ($low -lt 0xDC00 -or $low -gt 0xDFFF) {
                        throw (New-LedgerError 'Unpaired high surrogate in JSON')
                    }
                    $State.Index += 6
                    [void]$builder.Append([char]$value)
                    [void]$builder.Append([char]$low)
                } elseif ($value -ge 0xDC00 -and $value -le 0xDFFF) {
                    throw (New-LedgerError 'Unpaired low surrogate in JSON')
                } else {
                    [void]$builder.Append([char]$value)
                }
            }
            default {
                throw (New-LedgerError "Unknown JSON escape: \$escape")
            }
        }
    }
    throw (New-LedgerError 'Unterminated JSON string')
}

function Read-JsonValue {
    param([Parameter(Mandatory = $true)]$State)

    Skip-JsonWhitespace -State $State
    $character = Get-JsonCharacter -State $State -Required
    if ($character -eq '{') {
        $State.Index++
        $result = New-OrdinalDictionary
        $keys = New-Object 'System.Collections.Generic.HashSet[string]' (
            $script:Ordinal)
        Skip-JsonWhitespace -State $State
        if ((Get-JsonCharacter -State $State -Required) -eq '}') {
            $State.Index++
            return $result
        }
        while ($true) {
            Skip-JsonWhitespace -State $State
            $key = Read-JsonString -State $State
            if (-not $keys.Add($key)) {
                throw (New-LedgerError "Duplicate JSON property: $key")
            }
            Skip-JsonWhitespace -State $State
            if ((Get-JsonCharacter -State $State -Required) -ne ':') {
                throw (New-LedgerError 'Expected colon after JSON property')
            }
            $State.Index++
            $result[$key] = Read-JsonValue -State $State
            Skip-JsonWhitespace -State $State
            $separator = Get-JsonCharacter -State $State -Required
            $State.Index++
            if ($separator -eq '}') {
                return $result
            }
            if ($separator -ne ',') {
                throw (New-LedgerError 'Expected comma in JSON object')
            }
        }
    }
    if ($character -eq '[') {
        $State.Index++
        $items = New-Object System.Collections.ArrayList
        Skip-JsonWhitespace -State $State
        if ((Get-JsonCharacter -State $State -Required) -eq ']') {
            $State.Index++
            return ,$items.ToArray()
        }
        while ($true) {
            [void]$items.Add((Read-JsonValue -State $State))
            Skip-JsonWhitespace -State $State
            $separator = Get-JsonCharacter -State $State -Required
            $State.Index++
            if ($separator -eq ']') {
                return ,$items.ToArray()
            }
            if ($separator -ne ',') {
                throw (New-LedgerError 'Expected comma in JSON array')
            }
        }
    }
    if ($character -eq '"') {
        return Read-JsonString -State $State
    }

    $remaining = $State.Text.Substring($State.Index)
    if ($remaining.StartsWith('true', [StringComparison]::Ordinal)) {
        $State.Index += 4
        return $true
    }
    if ($remaining.StartsWith('false', [StringComparison]::Ordinal)) {
        $State.Index += 5
        return $false
    }
    if ($remaining.StartsWith('null', [StringComparison]::Ordinal)) {
        $State.Index += 4
        return $null
    }
    $match = [regex]::Match(
        $remaining, '^-?(?:0|[1-9][0-9]*)',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) {
        throw (New-LedgerError "Invalid JSON value at offset $($State.Index)")
    }
    $State.Index += $match.Length
    $number = [long]0
    if (-not [long]::TryParse(
        $match.Value,
        [System.Globalization.NumberStyles]::AllowLeadingSign,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$number)) {
        throw (New-LedgerError "JSON integer is outside Int64: $($match.Value)")
    }
    return $number
}

function ConvertFrom-StrictJsonBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $text = $script:Utf8.GetString($Bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        throw (New-LedgerError 'JSON must not contain a BOM')
    }
    $state = [pscustomobject]@{ Text = $text; Index = 0 }
    $value = Read-JsonValue -State $state
    Skip-JsonWhitespace -State $state
    if ($state.Index -ne $state.Text.Length) {
        throw (New-LedgerError "Trailing JSON content at offset $($state.Index)")
    }
    return $value
}

function ConvertFrom-StrictJsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return ConvertFrom-StrictJsonBytes -Bytes (Read-StableBytes -Path $Path)
}

function ConvertTo-JsonStringLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int][char]$character
        switch ($code) {
            0x08 { [void]$builder.Append('\b'); continue }
            0x09 { [void]$builder.Append('\t'); continue }
            0x0A { [void]$builder.Append('\n'); continue }
            0x0C { [void]$builder.Append('\f'); continue }
            0x0D { [void]$builder.Append('\r'); continue }
            0x22 { [void]$builder.Append('\"'); continue }
            0x5C { [void]$builder.Append('\\'); continue }
        }
        if ($code -lt 0x20 -or $code -eq 0x2028 -or $code -eq 0x2029) {
            [void]$builder.Append(
                '\u' + $code.ToString(
                    'x4', [System.Globalization.CultureInfo]::InvariantCulture))
        } else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Write-CanonicalJsonValue {
    param(
        [Parameter(Mandatory = $false)]$Value,
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory = $true)][int]$Depth
    )

    if ($null -eq $Value) {
        [void]$Builder.Append('null')
        return
    }
    if ($Value -is [string]) {
        [void]$Builder.Append((ConvertTo-JsonStringLiteral -Value $Value))
        return
    }
    if ($Value -is [bool]) {
        [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' }))
        return
    }
    if ($Value -is [byte] -or $Value -is [int16] -or
        $Value -is [int32] -or $Value -is [int64] -or
        $Value -is [uint16] -or $Value -is [uint32]) {
        [void]$Builder.Append(
            ([Convert]::ToInt64($Value)).ToString(
                [System.Globalization.CultureInfo]::InvariantCulture))
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Builder.Append('{')
        $keys = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Value.Keys) {
            if ($key -isnot [string]) {
                throw (New-LedgerError 'JSON object keys must be strings')
            }
            $keys.Add([string]$key)
        }
        $sorted = Sort-Bytewise -Values $keys.ToArray()
        if ($sorted.Count -gt 0) {
            [void]$Builder.Append("`n")
        }
        for ($index = 0; $index -lt $sorted.Count; $index++) {
            [void]$Builder.Append('  ' * ($Depth + 1))
            [void]$Builder.Append(
                (ConvertTo-JsonStringLiteral -Value $sorted[$index]))
            [void]$Builder.Append(': ')
            Write-CanonicalJsonValue `
                -Value $Value[$sorted[$index]] `
                -Builder $Builder `
                -Depth ($Depth + 1)
            if ($index + 1 -lt $sorted.Count) {
                [void]$Builder.Append(',')
            }
            [void]$Builder.Append("`n")
        }
        if ($sorted.Count -gt 0) {
            [void]$Builder.Append('  ' * $Depth)
        }
        [void]$Builder.Append('}')
        return
    }
    if ($Value -is [System.Collections.IList] -or
        $Value.GetType().IsArray) {
        [void]$Builder.Append('[')
        if ($Value.Count -gt 0) {
            [void]$Builder.Append("`n")
        }
        for ($index = 0; $index -lt $Value.Count; $index++) {
            [void]$Builder.Append('  ' * ($Depth + 1))
            Write-CanonicalJsonValue `
                -Value $Value[$index] `
                -Builder $Builder `
                -Depth ($Depth + 1)
            if ($index + 1 -lt $Value.Count) {
                [void]$Builder.Append(',')
            }
            [void]$Builder.Append("`n")
        }
        if ($Value.Count -gt 0) {
            [void]$Builder.Append('  ' * $Depth)
        }
        [void]$Builder.Append(']')
        return
    }
    throw (New-LedgerError(
        "Unsupported canonical JSON type: $($Value.GetType().FullName)"))
}

function ConvertTo-CanonicalJsonBytes {
    param([Parameter(Mandatory = $false)]$Value)

    $builder = New-Object System.Text.StringBuilder
    Write-CanonicalJsonValue -Value $Value -Builder $builder -Depth 0
    [void]$builder.Append("`n")
    return ,$script:Utf8.GetBytes($builder.ToString())
}

function Assert-ObjectShape {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Required,
        [string[]]$Optional = @(),
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Object -isnot [System.Collections.IDictionary]) {
        throw (New-LedgerError "$Context must be a JSON object")
    }
    $allowed = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($name in $Required + $Optional) {
        [void]$allowed.Add($name)
    }
    foreach ($name in $Object.Keys) {
        if (-not $allowed.Contains([string]$name)) {
            throw (New-LedgerError "$Context has unknown property: $name")
        }
    }
    foreach ($name in $Required) {
        if (-not $Object.Contains($name)) {
            throw (New-LedgerError "$Context is missing property: $name")
        }
    }
}

function Assert-SafeField {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    foreach ($character in $Value.ToCharArray()) {
        $code = [int][char]$character
        if ($code -lt 0x20 -or $code -eq 0x7F) {
            throw (New-LedgerError "$Context contains a control character")
        }
    }
}

function ConvertTo-CanonicalTsvBytes {
    param(
        [Parameter(Mandatory = $true)][string[]]$Header,
        [Parameter(Mandatory = $true)][object[]]$Rows
    )

    foreach ($field in $Header) {
        Assert-SafeField -Value $field -Context 'TSV header'
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append(($Header -join "`t"))
    [void]$builder.Append("`n")
    foreach ($row in $Rows) {
        if ($row.Count -ne $Header.Count) {
            throw (New-LedgerError 'TSV row has the wrong field count')
        }
        $fields = New-Object string[] $Header.Count
        for ($index = 0; $index -lt $Header.Count; $index++) {
            if ($null -eq $row[$index]) {
                throw (New-LedgerError 'TSV fields cannot be null')
            }
            $fields[$index] = [string]$row[$index]
            Assert-SafeField -Value $fields[$index] -Context 'TSV field'
        }
        [void]$builder.Append(($fields -join "`t"))
        [void]$builder.Append("`n")
    }
    return ,$script:Utf8.GetBytes($builder.ToString())
}

function ConvertFrom-StrictTsvBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string[]]$Header,
        [int]$KeyColumn = -1
    )

    $text = $script:Utf8.GetString($Bytes)
    if ($text.Length -eq 0 -or -not $text.EndsWith(
        "`n", [System.StringComparison]::Ordinal)) {
        throw (New-LedgerError 'TSV must end with LF')
    }
    if ($text.Contains("`r")) {
        throw (New-LedgerError 'TSV must use LF line endings')
    }
    if ($text[0] -eq [char]0xFEFF) {
        throw (New-LedgerError 'TSV must not contain a BOM')
    }
    $lines = $text.Substring(0, $text.Length - 1).Split("`n")
    if (-not $script:Ordinal.Equals($lines[0], ($Header -join "`t"))) {
        throw (New-LedgerError 'TSV header does not match its schema')
    }
    $rows = New-Object System.Collections.ArrayList
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    for ($lineIndex = 1; $lineIndex -lt $lines.Count; $lineIndex++) {
        $fields = $lines[$lineIndex].Split("`t")
        if ($fields.Count -ne $Header.Count) {
            throw (New-LedgerError(
                "TSV row $lineIndex has the wrong field count"))
        }
        foreach ($field in $fields) {
            Assert-SafeField -Value $field -Context "TSV row $lineIndex"
        }
        if ($KeyColumn -ge 0 -and -not $keys.Add($fields[$KeyColumn])) {
            throw (New-LedgerError(
                "TSV contains duplicate key: $($fields[$KeyColumn])"))
        }
        [void]$rows.Add($fields)
    }
    return ,$rows.ToArray()
}

function Normalize-ArchivePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    if ([string]::IsNullOrEmpty($Path)) {
        throw (New-LedgerError 'Archive path is empty')
    }
    if ($Path.Contains('\') -or $Path.Contains(':')) {
        throw (New-LedgerError "Archive path has a Windows alias: $Path")
    }
    while ($Path.StartsWith('./', [StringComparison]::Ordinal)) {
        $Path = $Path.Substring(2)
    }
    if ($Directory) {
        $Path = $Path.TrimEnd('/')
    } elseif ($Path.EndsWith('/', [StringComparison]::Ordinal)) {
        throw (New-LedgerError "Non-directory archive path ends in slash: $Path")
    }
    if ([string]::IsNullOrEmpty($Path) -or
        $Path.StartsWith('/', [StringComparison]::Ordinal) -or
        $Path -match '^[A-Za-z]:') {
        throw (New-LedgerError "Archive path is rooted: $Path")
    }
    if (-not $Path.IsNormalized(
        [System.Text.NormalizationForm]::FormC)) {
        throw (New-LedgerError "Archive path is not Unicode NFC: $Path")
    }
    foreach ($character in $Path.ToCharArray()) {
        $code = [int][char]$character
        if ($code -lt 0x20 -or $code -eq 0x7F) {
            throw (New-LedgerError "Archive path has a control character: $Path")
        }
    }
    foreach ($segment in $Path.Split('/')) {
        if ([string]::IsNullOrEmpty($segment) -or
            $segment -eq '.' -or $segment -eq '..') {
            throw (New-LedgerError "Archive path has an unsafe segment: $Path")
        }
        if ($segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal)) {
            throw (New-LedgerError "Archive path has a Windows-trim alias: $Path")
        }
        $device = $segment.Split('.')[0]
        if ($device -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw (New-LedgerError "Archive path uses a device name: $Path")
        }
    }
    return $Path
}

function Resolve-LexicalLinkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$LinkPath,
        [Parameter(Mandatory = $true)][string]$Target
    )

    if ([string]::IsNullOrEmpty($Target) -or
        $Target.Contains('\') -or $Target.Contains(':') -or
        $Target.StartsWith('/', [StringComparison]::Ordinal)) {
        throw (New-LedgerError "Relative link target is unsafe: $Target")
    }
    $segments = New-Object System.Collections.Generic.List[string]
    $parent = [System.IO.Path]::GetDirectoryName(
        $LinkPath.Replace('/', '\'))
    if ($parent) {
        foreach ($segment in $parent.Replace('\', '/').Split('/')) {
            $segments.Add($segment)
        }
    }
    foreach ($segment in $Target.Split('/')) {
        if ($segment -eq '' -or $segment -eq '.') {
            continue
        }
        if ($segment -eq '..') {
            if ($segments.Count -eq 0) {
                throw (New-LedgerError "Link target escapes payload: $Target")
            }
            $segments.RemoveAt($segments.Count - 1)
            continue
        }
        Assert-SafeField -Value $segment -Context 'Link target'
        if ($segment.Contains(':') -or
            $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
            $segment.EndsWith('.', [StringComparison]::Ordinal)) {
            throw (New-LedgerError "Link target has a Windows alias: $Target")
        }
        $segments.Add($segment)
    }
    if ($segments.Count -eq 0) {
        throw (New-LedgerError "Link target resolves to payload root: $Target")
    }
    return Normalize-ArchivePath -Path ($segments -join '/')
}

function Read-TarString {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $end = $Offset
    while ($end -lt $Offset + $Length -and $Header[$end] -ne 0) {
        $end++
    }
    for ($index = $end; $index -lt $Offset + $Length; $index++) {
        if ($Header[$index] -ne 0 -and $Header[$index] -ne 0x20) {
            throw (New-LedgerError "Malformed TAR $Field padding")
        }
    }
    try {
        return $script:Utf8.GetString($Header, $Offset, $end - $Offset)
    } catch {
        throw (New-LedgerError "TAR $Field is not valid UTF-8")
    }
}

function Read-TarNumber {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Field
    )

    if (($Header[$Offset] -band 0x80) -ne 0) {
        if (($Header[$Offset] -band 0x40) -ne 0) {
            throw (New-LedgerError "Negative TAR $Field is forbidden")
        }
        [uint64]$value = [uint64]($Header[$Offset] -band 0x7F)
        for ($index = 1; $index -lt $Length; $index++) {
            if ($value -gt ([uint64]::MaxValue -shr 8)) {
                throw (New-LedgerError "TAR $Field overflows UInt64")
            }
            $value = ($value -shl 8) -bor $Header[$Offset + $index]
        }
        if ($value -gt [long]::MaxValue) {
            throw (New-LedgerError "TAR $Field overflows Int64")
        }
        return [long]$value
    }

    $text = $script:Ascii.GetString($Header, $Offset, $Length).
        Trim([char]0, [char]0x20)
    if ($text.Length -eq 0) {
        return [long]0
    }
    if ($text -notmatch '^[0-7]+$') {
        throw (New-LedgerError "Malformed octal TAR $Field")
    }
    [uint64]$value = 0
    foreach ($character in $text.ToCharArray()) {
        if ($value -gt (([uint64][long]::MaxValue - 7) -shr 3)) {
            throw (New-LedgerError "TAR $Field overflows Int64")
        }
        $value = ($value -shl 3) + ([int][char]$character - 48)
    }
    return [long]$value
}

function Read-ExactStreamBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $true)]$Hash,
        [switch]$AllowEof
    )

    $bytes = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($bytes, $offset, $Count - $offset)
        if ($read -eq 0) {
            if ($AllowEof -and $offset -eq 0) {
                return $null
            }
            throw (New-LedgerError 'Unexpected EOF in TAR stream')
        }
        [void]$Hash.TransformBlock($bytes, $offset, $read, $bytes, $offset)
        $offset += $read
    }
    return ,$bytes
}

function Get-PeRecord {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($Bytes.Length -lt 2 -or
        $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
        return $null
    }
    if ($Bytes.Length -lt 64) {
        throw (New-LedgerError "Truncated MZ file: $Path")
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peOffset -lt 64 -or $peOffset -gt $Bytes.Length - 24 -or
        $Bytes[$peOffset] -ne 0x50 -or
        $Bytes[$peOffset + 1] -ne 0x45 -or
        $Bytes[$peOffset + 2] -ne 0 -or
        $Bytes[$peOffset + 3] -ne 0) {
        throw (New-LedgerError "Malformed PE signature: $Path")
    }
    $coff = $peOffset + 4
    $machine = [BitConverter]::ToUInt16($Bytes, $coff)
    $sectionCount = [BitConverter]::ToUInt16($Bytes, $coff + 2)
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $coff + 16)
    $optional = $coff + 20
    if ($sectionCount -eq 0 -or $sectionCount -gt 96 -or
        $optionalSize -lt 96 -or
        $optional + $optionalSize -gt $Bytes.Length -or
        $optional + $optionalSize + (40 * $sectionCount) -gt $Bytes.Length) {
        throw (New-LedgerError "Malformed PE headers: $Path")
    }
    $magic = [BitConverter]::ToUInt16($Bytes, $optional)
    switch ($magic) {
        0x10B {
            $dataDirectory = $optional + 96
            $directoryCountOffset = $optional + 92
        }
        0x20B {
            $dataDirectory = $optional + 112
            $directoryCountOffset = $optional + 108
        }
        default {
            throw (New-LedgerError "Unknown PE optional header: $Path")
        }
    }
    $directoryCount = [BitConverter]::ToUInt32(
        $Bytes, $directoryCountOffset)
    $clrRva = [uint32]0
    if ($directoryCount -gt 14 -and
        $dataDirectory + (15 * 8) -le $optional + $optionalSize) {
        $clrRva = [BitConverter]::ToUInt32(
            $Bytes, $dataDirectory + (14 * 8))
    }
    $clrFlags = [uint32]0
    if ($clrRva -ne 0) {
        $sectionTable = $optional + $optionalSize
        $clrOffset = -1
        for ($index = 0; $index -lt $sectionCount; $index++) {
            $section = $sectionTable + (40 * $index)
            $virtualSize = [BitConverter]::ToUInt32($Bytes, $section + 8)
            $virtualAddress = [BitConverter]::ToUInt32($Bytes, $section + 12)
            $rawSize = [BitConverter]::ToUInt32($Bytes, $section + 16)
            $rawOffset = [BitConverter]::ToUInt32($Bytes, $section + 20)
            [uint64]$extent = [Math]::Max(
                [uint64]$virtualSize, [uint64]$rawSize)
            if ([uint64]$clrRva -ge [uint64]$virtualAddress -and
                [uint64]$clrRva -lt [uint64]$virtualAddress + $extent) {
                [uint64]$candidate = [uint64]$rawOffset +
                    ([uint64]$clrRva - [uint64]$virtualAddress)
                if ($candidate + 20 -gt [uint64]$Bytes.Length) {
                    throw (New-LedgerError "CLR header is outside PE file: $Path")
                }
                $clrOffset = [int]$candidate
                break
            }
        }
        if ($clrOffset -lt 0) {
            throw (New-LedgerError "CLR RVA cannot be resolved: $Path")
        }
        $clrSize = [BitConverter]::ToUInt32($Bytes, $clrOffset)
        if ($clrSize -lt 20 -or $clrOffset + $clrSize -gt $Bytes.Length) {
            throw (New-LedgerError "Malformed CLR header: $Path")
        }
        $clrFlags = [BitConverter]::ToUInt32($Bytes, $clrOffset + 16)
    }

    switch ($machine) {
        0x8664 { $architecture = 'x64' }
        0xAA64 { $architecture = 'arm64' }
        0x014C {
            if ($clrRva -ne 0 -and
                ($clrFlags -band 0x1) -ne 0 -and
                ($clrFlags -band 0x2) -eq 0) {
                $architecture = 'anycpu'
            } else {
                $architecture = 'x86'
            }
        }
        default {
            throw (New-LedgerError(
                "Unsupported PE machine 0x$($machine.ToString('X4')): $Path"))
        }
    }
    return [ordered]@{
        architecture = $architecture
        machine = '0x' + $machine.ToString('X4')
        sha256 = Get-Sha256Hex -Bytes $Bytes
        size = [long]$Bytes.Length
    }
}

function Read-TarPayload {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$AllowedAbsoluteSymlinks,
        [int]$MaximumPeSize = 536870912,
        [switch]$CollectFiles
    )

    $tarHash = [System.Security.Cryptography.SHA256]::Create()
    $entries = New-OrdinalDictionary
    $collisionKeys = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        $script:Ordinal)
    $peByPath = New-OrdinalDictionary
    $fileBytes = New-OrdinalDictionary
    $links = New-Object System.Collections.ArrayList
    $typeCounts = [ordered]@{
        directory = [long]0
        file = [long]0
        hardlink = [long]0
        symlink = [long]0
    }
    $zeroBlocks = 0
    $memberCount = [long]0
    try {
        while ($true) {
            $header = Read-ExactStreamBytes `
                -Stream $Stream -Count 512 -Hash $tarHash -AllowEof
            if ($null -eq $header) {
                break
            }
            $allZero = $true
            foreach ($value in $header) {
                if ($value -ne 0) {
                    $allZero = $false
                    break
                }
            }
            if ($allZero) {
                $zeroBlocks++
                continue
            }
            if ($zeroBlocks -gt 0) {
                throw (New-LedgerError 'Non-zero TAR data follows an end block')
            }

            $storedChecksum = Read-TarNumber `
                -Header $header -Offset 148 -Length 8 -Field checksum
            [long]$calculatedChecksum = 0
            for ($index = 0; $index -lt 512; $index++) {
                if ($index -ge 148 -and $index -lt 156) {
                    $calculatedChecksum += 0x20
                } else {
                    $calculatedChecksum += $header[$index]
                }
            }
            if ($storedChecksum -ne $calculatedChecksum) {
                throw (New-LedgerError 'TAR header checksum mismatch')
            }
            $magic = Read-TarString `
                -Header $header -Offset 257 -Length 6 -Field magic
            if (-not $script:Ordinal.Equals($magic, 'ustar') -and
                -not $script:Ordinal.Equals($magic, 'ustar ')) {
                throw (New-LedgerError "Unsupported TAR magic: $magic")
            }
            $version = Read-TarString `
                -Header $header -Offset 263 -Length 2 -Field version
            if (-not $script:Ordinal.Equals($version, '00') -and
                -not $script:Ordinal.Equals($version, ' ')) {
                throw (New-LedgerError "Unsupported TAR version: $version")
            }
            $name = Read-TarString `
                -Header $header -Offset 0 -Length 100 -Field name
            $prefix = Read-TarString `
                -Header $header -Offset 345 -Length 155 -Field prefix
            if ($prefix) {
                $name = "$prefix/$name"
            }
            $linkName = Read-TarString `
                -Header $header -Offset 157 -Length 100 -Field linkname
            $size = Read-TarNumber `
                -Header $header -Offset 124 -Length 12 -Field size
            [void](Read-TarNumber `
                -Header $header -Offset 100 -Length 8 -Field mode)
            [void](Read-TarNumber `
                -Header $header -Offset 108 -Length 8 -Field uid)
            [void](Read-TarNumber `
                -Header $header -Offset 116 -Length 8 -Field gid)
            [void](Read-TarNumber `
                -Header $header -Offset 136 -Length 12 -Field mtime)
            $typeByte = $header[156]
            $type = if ($typeByte -eq 0) { '0' } else { [char]$typeByte }
            switch ($type) {
                '0' { $kind = 'file' }
                '1' { $kind = 'hardlink' }
                '2' { $kind = 'symlink' }
                '5' { $kind = 'directory' }
                default {
                    throw (New-LedgerError "Unsupported TAR member type: $type")
                }
            }
            if ($kind -ne 'file' -and $size -ne 0) {
                throw (New-LedgerError "$kind TAR member has non-zero size")
            }
            if ($size -gt [int]::MaxValue -and $kind -eq 'file') {
                throw (New-LedgerError "TAR member is too large: $name")
            }
            $path = Normalize-ArchivePath `
                -Path $name -Directory:($kind -eq 'directory')
            if ($entries.Contains($path)) {
                throw (New-LedgerError "Duplicate TAR destination: $path")
            }
            $collisionKey = $path.Normalize(
                [System.Text.NormalizationForm]::FormD).ToUpperInvariant()
            if ($collisionKeys.ContainsKey($collisionKey)) {
                throw (New-LedgerError(
                    "Case or Unicode TAR collision: $path and " +
                    $collisionKeys[$collisionKey]))
            }
            $collisionKeys.Add($collisionKey, $path)

            if ($kind -eq 'file') {
                $firstCount = [int][Math]::Min(2, $size)
                $first = Read-ExactStreamBytes `
                    -Stream $Stream -Count $firstCount -Hash $tarHash
                $isPe = $first.Length -eq 2 -and
                    $first[0] -eq 0x4D -and $first[1] -eq 0x5A
                if (($isPe -or $CollectFiles) -and
                    $size -gt $MaximumPeSize) {
                    throw (New-LedgerError "Collected member exceeds size limit: $path")
                }
                if ($isPe -or $CollectFiles) {
                    $payload = New-Object byte[] ([int]$size)
                    if ($first.Length -gt 0) {
                        [System.Array]::Copy(
                            $first, 0, $payload, 0, $first.Length)
                    }
                    $remaining = [int]$size - $first.Length
                    if ($remaining -gt 0) {
                        $rest = Read-ExactStreamBytes `
                            -Stream $Stream -Count $remaining -Hash $tarHash
                        [System.Array]::Copy(
                            $rest, 0, $payload, $first.Length, $rest.Length)
                    }
                    if ($CollectFiles) {
                        $fileBytes[$path] = $payload
                    }
                    if ($isPe) {
                        $pe = Get-PeRecord -Bytes $payload -Path $path
                        $peByPath[$path] = $pe
                    }
                } else {
                    $remaining = $size - $first.Length
                    while ($remaining -gt 0) {
                        $chunk = [int][Math]::Min(1048576, $remaining)
                        [void](Read-ExactStreamBytes `
                            -Stream $Stream -Count $chunk -Hash $tarHash)
                        $remaining -= $chunk
                    }
                }
            }
            $padding = (512 - ($size % 512)) % 512
            if ($padding -gt 0) {
                $paddingBytes = Read-ExactStreamBytes `
                    -Stream $Stream -Count ([int]$padding) -Hash $tarHash
                foreach ($value in $paddingBytes) {
                    if ($value -ne 0) {
                        throw (New-LedgerError(
                            "Non-zero TAR padding after member: $path"))
                    }
                }
            }

            if ($kind -eq 'hardlink') {
                $resolvedTarget = Normalize-ArchivePath -Path $linkName
                [void]$links.Add([ordered]@{
                    path = $path
                    type = 'hardlink'
                    target = $linkName
                    policy = 'payload-internal'
                    resolvedTarget = $resolvedTarget
                })
            } elseif ($kind -eq 'symlink') {
                if ($linkName.StartsWith('/', [StringComparison]::Ordinal)) {
                    if (-not $AllowedAbsoluteSymlinks.Contains($path) -or
                        -not $script:Ordinal.Equals(
                            [string]$AllowedAbsoluteSymlinks[$path], $linkName)) {
                        throw (New-LedgerError(
                            "Absolute symlink is not installed-link policy: " +
                            "$path -> $linkName"))
                    }
                    $policy = 'runtime-virtual-absolute'
                    $resolvedTarget = ''
                } else {
                    $policy = 'payload-relative'
                    $resolvedTarget = Resolve-LexicalLinkTarget `
                        -LinkPath $path -Target $linkName
                }
                [void]$links.Add([ordered]@{
                    path = $path
                    type = 'symlink'
                    target = $linkName
                    policy = $policy
                    resolvedTarget = $resolvedTarget
                })
            } elseif ($linkName) {
                throw (New-LedgerError "Non-link member has a link target: $path")
            }

            $entries[$path] = [ordered]@{
                kind = $kind
                linkTarget = $linkName
                resolvedTarget = if ($kind -eq 'hardlink') {
                    Normalize-ArchivePath -Path $linkName
                } elseif ($kind -eq 'symlink' -and
                    -not $linkName.StartsWith(
                        '/', [StringComparison]::Ordinal)) {
                    Resolve-LexicalLinkTarget `
                        -LinkPath $path -Target $linkName
                } else {
                    ''
                }
            }
            $typeCounts[$kind]++
            $memberCount++
        }
        if ($zeroBlocks -lt 2) {
            throw (New-LedgerError 'TAR stream lacks two end blocks')
        }
        [void]$tarHash.TransformFinalBlock((New-Object byte[] 0), 0, 0)

        foreach ($link in $links) {
            if ($link.type -eq 'symlink') {
                if ($link.policy -eq 'payload-relative' -and
                    -not $entries.Contains($link.resolvedTarget)) {
                    throw (New-LedgerError(
                        "Relative symlink target is absent: $($link.path)"))
                }
                continue
            }
            $visited = New-Object 'System.Collections.Generic.HashSet[string]' (
                $script:Ordinal)
            $target = $link.resolvedTarget
            while ($true) {
                if (-not $visited.Add($target)) {
                    throw (New-LedgerError(
                        "Hardlink cycle from $($link.path)"))
                }
                if (-not $entries.Contains($target)) {
                    throw (New-LedgerError(
                        "Hardlink target is absent: $($link.path) -> $target"))
                }
                $targetEntry = $entries[$target]
                if ($targetEntry.kind -eq 'hardlink') {
                    $target = $targetEntry.resolvedTarget
                    continue
                }
                if ($targetEntry.kind -ne 'file') {
                    throw (New-LedgerError(
                        "Hardlink target is not a file: $($link.path)"))
                }
                if ($peByPath.Contains($target)) {
                    $peByPath[$link.path] = $peByPath[$target]
                }
                break
            }
        }

        $absoluteCount = 0
        foreach ($link in $links) {
            if ($link.policy -eq 'runtime-virtual-absolute') {
                $absoluteCount++
            }
        }
        if ($absoluteCount -ne $AllowedAbsoluteSymlinks.Count) {
            throw (New-LedgerError(
                "Installed-link policy expected $($AllowedAbsoluteSymlinks.Count) " +
                "absolute links, found $absoluteCount"))
        }
        return [ordered]@{
            entries = $entries
            fileBytes = $fileBytes
            links = $links.ToArray()
            memberCount = $memberCount
            peByPath = $peByPath
            tarSha256 = ([System.BitConverter]::ToString(
                $tarHash.Hash)).Replace('-', '').ToLowerInvariant()
            typeCounts = $typeCounts
            zeroBlockCount = [long]$zeroBlocks
        }
    } finally {
        $tarHash.Dispose()
    }
}

function Read-PacmanSections {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string[]]$AllowedSections,
        [string[]]$AllowEmptySections = @(),
        [Parameter(Mandatory = $true)][string]$Context
    )

    $text = $script:Utf8.GetString($Bytes)
    if ($text.Contains("`r")) {
        throw (New-LedgerError "$Context uses non-LF line endings")
    }
    if (-not $text.EndsWith("`n", [StringComparison]::Ordinal)) {
        throw (New-LedgerError "$Context lacks final LF")
    }
    $allowed = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($section in $AllowedSections) {
        [void]$allowed.Add($section)
    }
    $allowEmpty = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($section in $AllowEmptySections) {
        if (-not $allowed.Contains($section)) {
            throw (New-LedgerError(
                "Empty-section exception is not in the schema: $section"))
        }
        [void]$allowEmpty.Add($section)
    }
    $result = New-OrdinalDictionary
    $lines = $text.Substring(0, $text.Length - 1).Split("`n")
    $index = 0
    while ($index -lt $lines.Count) {
        if ($lines[$index] -eq '') {
            $index++
            continue
        }
        if ($lines[$index] -notmatch '^%([A-Z0-9_]+)%$') {
            throw (New-LedgerError(
                "$Context has malformed section header at line $($index + 1)"))
        }
        $name = $Matches[1]
        if (-not $allowed.Contains($name)) {
            throw (New-LedgerError "$Context has unknown section: $name")
        }
        if ($result.Contains($name)) {
            throw (New-LedgerError "$Context has duplicate section: $name")
        }
        $index++
        $values = New-Object System.Collections.ArrayList
        while ($index -lt $lines.Count -and $lines[$index] -ne '') {
            if ($name -eq 'BACKUP') {
                if ($lines[$index] -notmatch
                    '^[^\t\r\n]+\t[0-9a-f]{32,128}$') {
                    throw (New-LedgerError(
                        "$Context section BACKUP has malformed value"))
                }
            } else {
                Assert-SafeField `
                    -Value $lines[$index] `
                    -Context "$Context section $name"
            }
            [void]$values.Add($lines[$index])
            $index++
        }
        if ($values.Count -eq 0 -and -not $allowEmpty.Contains($name)) {
            throw (New-LedgerError "$Context section $name is empty")
        }
        $result[$name] = $values.ToArray()
    }
    return $result
}

function ConvertTo-OwnershipMapping {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$PackageFiles,
        [Parameter(Mandatory = $true)][string[]]$X64Paths
    )

    $owners = New-Object `
        'System.Collections.Generic.Dictionary[string,System.Collections.ArrayList]' (
        $script:Ordinal)
    foreach ($packageName in $PackageFiles.Keys) {
        $record = $PackageFiles[$packageName]
        foreach ($path in $record.paths) {
            if (-not $owners.ContainsKey($path)) {
                $owners.Add($path, (New-Object System.Collections.ArrayList))
            }
            [void]$owners[$path].Add($record)
        }
    }
    $mapping = New-OrdinalDictionary
    foreach ($path in $X64Paths) {
        if (-not $owners.ContainsKey($path)) {
            throw (New-LedgerError "x64 path has no package owner: $path")
        }
        if ($owners[$path].Count -ne 1) {
            throw (New-LedgerError(
                "x64 path has ambiguous package ownership: $path"))
        }
        $record = $owners[$path][0]
        if ($mapping.Contains($path)) {
            throw (New-LedgerError "Duplicate x64 path in ownership join: $path")
        }
        $mapping[$path] = [ordered]@{
            owner = $record.name
            version = $record.version
        }
    }
    return $mapping
}

function ConvertFrom-PacmanTarResult {
    param(
        [Parameter(Mandatory = $true)]$TarResult,
        [Parameter(Mandatory = $true)][int]$ExpectedPackageCount,
        [Parameter(Mandatory = $true)][int]$ExpectedRecordBlobCount
    )

    if ($TarResult.typeCounts.hardlink -ne 0 -or
        $TarResult.typeCounts.symlink -ne 0 -or
        $TarResult.peByPath.Count -ne 0) {
        throw (New-LedgerError(
            'Pacman database Git archive contains unexpected link or PE data'))
    }
    if (-not $TarResult.fileBytes.Contains('ALPM_DB_VERSION')) {
        throw (New-LedgerError 'Pacman database lacks ALPM_DB_VERSION')
    }
    $databaseVersion = $script:Utf8.GetString(
        $TarResult.fileBytes['ALPM_DB_VERSION'])
    if (-not $script:Ordinal.Equals($databaseVersion, "9`n")) {
        throw (New-LedgerError 'Unsupported Pacman local database version')
    }

    $packageDirectories = New-Object System.Collections.Generic.List[string]
    foreach ($path in $TarResult.entries.Keys) {
        if ($TarResult.entries[$path].kind -eq 'directory') {
            if ($path.Contains('/')) {
                throw (New-LedgerError(
                    "Pacman database has nested directory entry: $path"))
            }
            $packageDirectories.Add($path)
        }
    }
    if ($packageDirectories.Count -ne $ExpectedPackageCount) {
        throw (New-LedgerError(
            "Pacman database expected $ExpectedPackageCount packages, found " +
            $packageDirectories.Count))
    }
    $descAllowed = @(
        'ARCH',
        'BASE',
        'BUILDDATE',
        'CONFLICTS',
        'DEPENDS',
        'DESC',
        'GROUPS',
        'INSTALLDATE',
        'LICENSE',
        'NAME',
        'OPTDEPENDS',
        'PACKAGER',
        'PROVIDES',
        'REASON',
        'REPLACES',
        'SIZE',
        'URL',
        'VALIDATION',
        'VERSION',
        'XDATA')
    $descRequired = @(
        'ARCH',
        'BASE',
        'BUILDDATE',
        'DESC',
        'INSTALLDATE',
        'LICENSE',
        'NAME',
        'PACKAGER',
        'URL',
        'VALIDATION',
        'VERSION')
    $packages = New-OrdinalDictionary
    $recordBlobCount = 0
    $knownPackageFiles = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($name in @('desc', 'files', 'install', 'mtree')) {
        [void]$knownPackageFiles.Add($name)
    }
    foreach ($directory in (Sort-Bytewise -Values $packageDirectories.ToArray())) {
        $members = New-Object 'System.Collections.Generic.HashSet[string]' (
            $script:Ordinal)
        foreach ($path in $TarResult.fileBytes.Keys) {
            if ($path.StartsWith(
                "$directory/", [StringComparison]::Ordinal)) {
                $leaf = $path.Substring($directory.Length + 1)
                if ($leaf.Contains('/') -or
                    -not $knownPackageFiles.Contains($leaf) -or
                    -not $members.Add($leaf)) {
                    throw (New-LedgerError(
                        "Pacman package has unknown or duplicate member: $path"))
                }
            }
        }
        foreach ($requiredMember in @('desc', 'files', 'mtree')) {
            if (-not $members.Contains($requiredMember)) {
                throw (New-LedgerError(
                    "Pacman package $directory lacks $requiredMember"))
            }
        }
        $descPath = "$directory/desc"
        $filesPath = "$directory/files"
        $recordBlobCount += 2
        $desc = Read-PacmanSections `
            -Bytes $TarResult.fileBytes[$descPath] `
            -AllowedSections $descAllowed `
            -AllowEmptySections @('URL') `
            -Context $descPath
        foreach ($requiredSection in $descRequired) {
            if (-not $desc.Contains($requiredSection)) {
                throw (New-LedgerError(
                    "Pacman package $directory lacks section $requiredSection"))
            }
        }
        foreach ($singleSection in @(
            'ARCH',
            'BASE',
            'BUILDDATE',
            'DESC',
            'INSTALLDATE',
            'NAME',
            'PACKAGER',
            'SIZE',
            'VERSION')) {
            if ($desc.Contains($singleSection) -and
                $desc[$singleSection].Count -ne 1) {
                throw (New-LedgerError(
                    "Pacman package $directory section $singleSection " +
                    'must contain one value'))
            }
        }
        $packageName = [string]$desc.NAME[0]
        $packageVersion = [string]$desc.VERSION[0]
        if (-not $script:Ordinal.Equals(
            $directory, "$packageName-$packageVersion")) {
            throw (New-LedgerError(
                "Pacman directory does not match NAME/VERSION: $directory"))
        }
        if ($packages.Contains($packageName)) {
            throw (New-LedgerError(
                "Pacman database has duplicate package NAME: $packageName"))
        }
        $paths = New-Object System.Collections.Generic.List[string]
        $pathSet = New-Object 'System.Collections.Generic.HashSet[string]' (
            $script:Ordinal)
        $filesBytes = $TarResult.fileBytes[$filesPath]
        if ($filesBytes.Length -eq 0) {
            if (-not $script:Ordinal.Equals(
                "$packageName@$packageVersion", 'autotools@2022.01.16-2')) {
                throw (New-LedgerError(
                    "Pacman package has an empty files record: $directory"))
            }
        } else {
            $files = Read-PacmanSections `
                -Bytes $filesBytes `
                -AllowedSections @('BACKUP', 'FILES') `
                -Context $filesPath
            if (-not $files.Contains('FILES')) {
                throw (New-LedgerError(
                    "Pacman package $directory lacks FILES section"))
            }
            foreach ($rawPath in $files.FILES) {
                $directoryPath = $rawPath.EndsWith(
                    '/', [StringComparison]::Ordinal)
                $path = Normalize-ArchivePath `
                    -Path $rawPath -Directory:$directoryPath
                if (-not $pathSet.Add($path)) {
                    throw (New-LedgerError(
                        "Pacman package $directory repeats path: $path"))
                }
                if (-not $directoryPath) {
                    $paths.Add($path)
                }
            }
        }
        $packages[$packageName] = [ordered]@{
            name = $packageName
            paths = Sort-Bytewise -Values $paths.ToArray()
            version = $packageVersion
        }
    }
    if ($recordBlobCount -ne $ExpectedRecordBlobCount) {
        throw (New-LedgerError(
            "Pacman database expected $ExpectedRecordBlobCount desc/files " +
            "records, found $recordBlobCount"))
    }
    return [ordered]@{
        databaseVersion = [long]9
        packageCount = [long]$packages.Count
        packages = $packages
        recordBlobCount = [long]$recordBlobCount
    }
}

function Assert-HexString {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value.Length -ne $Length -or $Value -notmatch '^[0-9a-f]+$') {
        throw (New-LedgerError(
            "$Context must be $Length lowercase hexadecimal characters"))
    }
}

function Assert-PositiveInteger {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowZero
    )

    if ($Value -isnot [long] -and $Value -isnot [int]) {
        throw (New-LedgerError "$Context must be an integer")
    }
    if (($AllowZero -and $Value -lt 0) -or
        (-not $AllowZero -and $Value -le 0)) {
        throw (New-LedgerError "$Context is outside its permitted range")
    }
}

function Assert-StringArray {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$Paths,
        [switch]$Owners
    )

    if ($Value -isnot [System.Array]) {
        throw (New-LedgerError "$Context must be an array")
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($item in $Value) {
        if ($item -isnot [string] -or [string]::IsNullOrEmpty($item)) {
            throw (New-LedgerError "$Context contains a non-string or empty value")
        }
        Assert-SafeField -Value $item -Context $Context
        if (-not $seen.Add($item)) {
            throw (New-LedgerError "$Context contains duplicate value: $item")
        }
        if ($Paths) {
            $normalized = Normalize-ArchivePath -Path $item
            if (-not $script:Ordinal.Equals($normalized, $item)) {
                throw (New-LedgerError "$Context path is not canonical: $item")
            }
        }
        if ($Owners -and $item -notmatch '^[^@\x00-\x20\x7f]+@[^@\x00-\x20\x7f]+$') {
            throw (New-LedgerError "$Context owner selector is malformed: $item")
        }
    }
}

function Assert-LedgerModel {
    param([Parameter(Mandatory = $true)]$Model)

    Assert-ObjectShape `
        -Object $Model `
        -Required @(
            'archiveExpectations',
            'expected',
            'legacyOverlap',
            'ownership',
            'products',
            'release',
            'rules',
            'scanner',
            'schemaVersion') `
        -Context 'model'
    if ($Model.schemaVersion -ne 1) {
        throw (New-LedgerError 'Unsupported model schemaVersion')
    }

    Assert-ObjectShape `
        -Object $Model.release `
        -Required @(
            'asset',
            'createdAt',
            'id',
            'peeledCommit',
            'peeledCommitTree',
            'publishedAt',
            'repository',
            'tag',
            'tagObject') `
        -Context 'release'
    Assert-PositiveInteger -Value $Model.release.id -Context 'release.id'
    Assert-HexString `
        -Value $Model.release.tagObject -Length 40 -Context 'release.tagObject'
    Assert-HexString `
        -Value $Model.release.peeledCommit `
        -Length 40 `
        -Context 'release.peeledCommit'
    Assert-HexString `
        -Value $Model.release.peeledCommitTree `
        -Length 40 `
        -Context 'release.peeledCommitTree'
    if ($Model.release.repository -ne 'git-for-windows/git') {
        throw (New-LedgerError 'release.repository is not authoritative')
    }
    foreach ($timestampName in @('createdAt', 'publishedAt')) {
        if ($Model.release[$timestampName] -notmatch
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') {
            throw (New-LedgerError "release.$timestampName is not canonical UTC")
        }
    }
    Assert-ObjectShape `
        -Object $Model.release.asset `
        -Required @(
            'apiDigest',
            'apiUrl',
            'createdAt',
            'downloadSha256',
            'id',
            'name',
            'size',
            'updatedAt') `
        -Context 'release.asset'
    Assert-PositiveInteger `
        -Value $Model.release.asset.id -Context 'release.asset.id'
    Assert-PositiveInteger `
        -Value $Model.release.asset.size -Context 'release.asset.size'
    Assert-HexString `
        -Value $Model.release.asset.downloadSha256 `
        -Length 64 `
        -Context 'release.asset.downloadSha256'
    if ($Model.release.asset.apiDigest -ne
        "sha256:$($Model.release.asset.downloadSha256)") {
        throw (New-LedgerError 'release asset digest fields disagree')
    }
    if ($Model.release.asset.apiUrl -ne
        "https://api.github.com/repos/$($Model.release.repository)/releases/assets/$($Model.release.asset.id)") {
        throw (New-LedgerError 'release.asset.apiUrl is not ID-addressed')
    }
    foreach ($timestampName in @('createdAt', 'updatedAt')) {
        if ($Model.release.asset[$timestampName] -notmatch
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') {
            throw (New-LedgerError(
                "release.asset.$timestampName is not canonical UTC"))
        }
    }

    Assert-ObjectShape `
        -Object $Model.ownership `
        -Required @(
            'canonicalMappingSha256',
            'commit',
            'databaseArchiveTarSha256',
            'databasePath',
            'databaseTree',
            'packageCount',
            'recordBlobCount',
            'repository',
            'rootTree') `
        -Context 'ownership'
    if ($Model.ownership.repository -ne
        'git-for-windows/git-sdk-arm64') {
        throw (New-LedgerError 'ownership.repository is not authoritative')
    }
    if ($Model.ownership.databasePath -ne 'var/lib/pacman/local') {
        throw (New-LedgerError 'ownership.databasePath is not canonical')
    }
    foreach ($hashName in @('commit', 'databaseTree', 'rootTree')) {
        Assert-HexString `
            -Value $Model.ownership[$hashName] `
            -Length 40 `
            -Context "ownership.$hashName"
    }
    Assert-HexString `
        -Value $Model.ownership.canonicalMappingSha256 `
        -Length 64 `
        -Context 'ownership.canonicalMappingSha256'
    Assert-HexString `
        -Value $Model.ownership.databaseArchiveTarSha256 `
        -Length 64 `
        -Context 'ownership.databaseArchiveTarSha256'
    Assert-PositiveInteger `
        -Value $Model.ownership.packageCount `
        -Context 'ownership.packageCount'
    Assert-PositiveInteger `
        -Value $Model.ownership.recordBlobCount `
        -Context 'ownership.recordBlobCount'

    Assert-ObjectShape `
        -Object $Model.scanner `
        -Required @('path', 'referenceScanners') `
        -Context 'scanner'
    if ($Model.scanner.path -ne 'arm64-validation/Arm64Ledger.psm1') {
        throw (New-LedgerError 'scanner.path is not the committed scanner')
    }
    if ($Model.scanner.referenceScanners -isnot [System.Array] -or
        $Model.scanner.referenceScanners.Count -ne 2) {
        throw (New-LedgerError 'scanner.referenceScanners must contain two entries')
    }
    foreach ($reference in $Model.scanner.referenceScanners) {
        Assert-ObjectShape `
            -Object $reference `
            -Required @(
                'gitBlobSha1',
                'path',
                'repository',
                'sha256',
                'sourceCommit') `
            -Context 'scanner.reference'
        Assert-HexString `
            -Value $reference.gitBlobSha1 `
            -Length 40 `
            -Context 'scanner.reference.gitBlobSha1'
        Assert-HexString `
            -Value $reference.sha256 `
            -Length 64 `
            -Context 'scanner.reference.sha256'
        Assert-HexString `
            -Value $reference.sourceCommit `
            -Length 40 `
            -Context 'scanner.reference.sourceCommit'
    }

    Assert-ObjectShape `
        -Object $Model.archiveExpectations `
        -Required @(
            'allowedAbsoluteSymlinks',
            'architectureCounts',
            'hardlinkCount',
            'memberCount',
            'peCount',
            'x64PathSha256') `
        -Context 'archiveExpectations'
    Assert-ObjectShape `
        -Object $Model.archiveExpectations.architectureCounts `
        -Required @('anycpu', 'arm64', 'x64', 'x86') `
        -Context 'archiveExpectations.architectureCounts'
    foreach ($name in @(
        'hardlinkCount', 'memberCount', 'peCount')) {
        Assert-PositiveInteger `
            -Value $Model.archiveExpectations[$name] `
            -Context "archiveExpectations.$name"
    }
    foreach ($name in @('anycpu', 'arm64', 'x64', 'x86')) {
        Assert-PositiveInteger `
            -Value $Model.archiveExpectations.architectureCounts[$name] `
            -Context "archiveExpectations.architectureCounts.$name"
    }
    Assert-HexString `
        -Value $Model.archiveExpectations.x64PathSha256 `
        -Length 64 `
        -Context 'archiveExpectations.x64PathSha256'
    if ($Model.archiveExpectations.allowedAbsoluteSymlinks -isnot
        [System.Array]) {
        throw (New-LedgerError(
            'archiveExpectations.allowedAbsoluteSymlinks must be an array'))
    }
    $linkPaths = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($link in $Model.archiveExpectations.allowedAbsoluteSymlinks) {
        Assert-ObjectShape `
            -Object $link `
            -Required @('path', 'target') `
            -Context 'installed link'
        if (-not $linkPaths.Add($link.path)) {
            throw (New-LedgerError(
                "Duplicate installed-link policy path: $($link.path)"))
        }
        if ((Normalize-ArchivePath -Path $link.path) -ne $link.path -or
            -not $link.target.StartsWith('/', [StringComparison]::Ordinal)) {
            throw (New-LedgerError 'Installed-link policy is malformed')
        }
    }

    Assert-ObjectShape `
        -Object $Model.expected `
        -Required @(
            'candidateCount',
            'candidatePathSha256',
            'evidenceBackedCandidateCount',
            'modeledCount',
            'ownerVersionGroupCount',
            'recommendationCount',
            'residualCount',
            'residualPathSha256',
            'ruleCount',
            'sourceOverlapCount',
            'totalCount') `
        -Context 'expected'
    foreach ($name in @(
        'candidateCount',
        'evidenceBackedCandidateCount',
        'modeledCount',
        'ownerVersionGroupCount',
        'recommendationCount',
        'residualCount',
        'ruleCount',
        'totalCount')) {
        Assert-PositiveInteger `
            -Value $Model.expected[$name] -Context "expected.$name"
    }
    Assert-PositiveInteger `
        -Value $Model.expected.sourceOverlapCount `
        -Context 'expected.sourceOverlapCount' `
        -AllowZero
    foreach ($name in @('candidatePathSha256', 'residualPathSha256')) {
        Assert-HexString `
            -Value $Model.expected[$name] `
            -Length 64 `
            -Context "expected.$name"
    }

    Assert-ObjectShape `
        -Object $Model.legacyOverlap `
        -Required @(
            'activeRuleCount',
            'pathCount',
            'pathSha256',
            'paths',
            'resolution') `
        -Context 'legacyOverlap'
    Assert-PositiveInteger `
        -Value $Model.legacyOverlap.activeRuleCount `
        -Context 'legacyOverlap.activeRuleCount' `
        -AllowZero
    Assert-PositiveInteger `
        -Value $Model.legacyOverlap.pathCount `
        -Context 'legacyOverlap.pathCount'
    Assert-HexString `
        -Value $Model.legacyOverlap.pathSha256 `
        -Length 64 `
        -Context 'legacyOverlap.pathSha256'
    Assert-StringArray `
        -Value $Model.legacyOverlap.paths `
        -Context 'legacyOverlap.paths' `
        -Paths
    if ($Model.legacyOverlap.paths.Count -ne
        $Model.legacyOverlap.pathCount) {
        throw (New-LedgerError 'legacyOverlap path count differs')
    }

    if ($Model.rules -isnot [System.Array] -or
        $Model.rules.Count -ne $Model.expected.ruleCount) {
        throw (New-LedgerError 'rules array has the wrong count')
    }
    $ruleIds = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($rule in $Model.rules) {
        Assert-ObjectShape `
            -Object $rule `
            -Required @(
                'action',
                'evidence',
                'expectedCount',
                'id',
                'ledgerClass') `
            -Optional @('owners', 'paths') `
            -Context 'rule'
        if ($rule.id -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
            -not $ruleIds.Add($rule.id)) {
            throw (New-LedgerError "Invalid or duplicate rule ID: $($rule.id)")
        }
        if ($rule.ledgerClass -notin @(
            'evidence-backed-candidate', 'modeled-unresolved', 'residual')) {
            throw (New-LedgerError(
                "Invalid ledger class in rule $($rule.id)"))
        }
        Assert-PositiveInteger `
            -Value $rule.expectedCount `
            -Context "rule $($rule.id) expectedCount"
        $hasSelector = $false
        if ($rule.Contains('paths')) {
            Assert-StringArray `
                -Value $rule.paths `
                -Context "rule $($rule.id) paths" `
                -Paths
            $hasSelector = $hasSelector -or $rule.paths.Count -gt 0
        }
        if ($rule.Contains('owners')) {
            Assert-StringArray `
                -Value $rule.owners `
                -Context "rule $($rule.id) owners" `
                -Owners
            $hasSelector = $hasSelector -or $rule.owners.Count -gt 0
        }
        if (-not $hasSelector) {
            throw (New-LedgerError "Rule has no selector: $($rule.id)")
        }
        if ($null -ne $rule.evidence) {
            Assert-ObjectShape `
                -Object $rule.evidence `
                -Required @(
                    'admission',
                    'head',
                    'pullRequest',
                    'repository',
                    'tree') `
                -Optional @(
                    'artifactDigest',
                    'artifactId',
                    'jobId',
                    'workflowRun') `
                -Context "rule $($rule.id) evidence"
            if ($rule.evidence.admission -ne 'unresolved') {
                throw (New-LedgerError(
                    "Rule evidence claims admission: $($rule.id)"))
            }
            Assert-HexString `
                -Value $rule.evidence.head `
                -Length 40 `
                -Context "rule $($rule.id) evidence head"
            Assert-HexString `
                -Value $rule.evidence.tree `
                -Length 40 `
                -Context "rule $($rule.id) evidence tree"
            Assert-PositiveInteger `
                -Value $rule.evidence.pullRequest `
                -Context "rule $($rule.id) evidence pullRequest"
            if ($rule.evidence.Contains('artifactDigest')) {
                if ($rule.evidence.artifactDigest -notmatch
                    '^sha256:[0-9a-f]{64}$') {
                    throw (New-LedgerError 'Evidence artifact digest is malformed')
                }
                foreach ($name in @(
                    'artifactId', 'jobId', 'workflowRun')) {
                    if (-not $rule.evidence.Contains($name)) {
                        throw (New-LedgerError(
                            "Evidence artifact is missing $name"))
                    }
                    Assert-PositiveInteger `
                        -Value $rule.evidence[$name] `
                        -Context "evidence.$name"
                }
            } elseif ($rule.evidence.Contains('artifactId') -or
                $rule.evidence.Contains('jobId') -or
                $rule.evidence.Contains('workflowRun')) {
                throw (New-LedgerError(
                    'Evidence artifact identity is incomplete'))
            }
        } elseif ($rule.ledgerClass -eq 'evidence-backed-candidate' -or
            $rule.action -eq 'busybox-semantic-proof') {
            throw (New-LedgerError(
                "Evidence-bearing rule has null evidence: $($rule.id)"))
        }
    }

    if ($Model.products -isnot [System.Array] -or
        $Model.products.Count -eq 0) {
        throw (New-LedgerError 'products must be a non-empty array')
    }
    $productIds = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    foreach ($product in $Model.products) {
        Assert-ObjectShape `
            -Object $product `
            -Required @('expectedCount', 'id') `
            -Optional @('paths', 'ruleIds') `
            -Context 'product'
        if ($product.id -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
            -not $productIds.Add($product.id)) {
            throw (New-LedgerError(
                "Invalid or duplicate product ID: $($product.id)"))
        }
        Assert-PositiveInteger `
            -Value $product.expectedCount `
            -Context "product $($product.id) expectedCount"
        $selectors = 0
        if ($product.Contains('paths')) {
            Assert-StringArray `
                -Value $product.paths `
                -Context "product $($product.id) paths" `
                -Paths
            $selectors++
        }
        if ($product.Contains('ruleIds')) {
            Assert-StringArray `
                -Value $product.ruleIds `
                -Context "product $($product.id) ruleIds"
            foreach ($ruleId in $product.ruleIds) {
                if (-not $ruleIds.Contains($ruleId)) {
                    throw (New-LedgerError(
                        "Product references unknown rule: $ruleId"))
                }
            }
            $selectors++
        }
        if ($selectors -ne 1) {
            throw (New-LedgerError(
                "Product must have exactly one selector: $($product.id)"))
        }
    }
}

function Get-CanonicalPathSetBytes {
    param([Parameter(Mandatory = $true)][object[]]$Paths)

    $sorted = Sort-Bytewise -Values $Paths
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' (
        $script:Ordinal)
    $builder = New-Object System.Text.StringBuilder
    foreach ($path in $sorted) {
        if (-not $seen.Add($path)) {
            throw (New-LedgerError "Duplicate path in canonical set: $path")
        }
        [void]$builder.Append($path)
        [void]$builder.Append("`n")
    }
    return ,$script:Utf8.GetBytes($builder.ToString())
}

function Compile-LedgerRules {
    param(
        [Parameter(Mandatory = $true)]$Model,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Ownership
    )

    Assert-LedgerModel -Model $Model
    $assignments = New-OrdinalDictionary
    $ruleResults = New-Object System.Collections.ArrayList
    foreach ($rule in $Model.rules) {
        $matches = New-Object 'System.Collections.Generic.HashSet[string]' (
            $script:Ordinal)
        if ($rule.Contains('paths')) {
            foreach ($path in $rule.paths) {
                if (-not $Ownership.Contains($path)) {
                    throw (New-LedgerError(
                        "Rule $($rule.id) references unknown path: $path"))
                }
                if (-not $matches.Add($path)) {
                    throw (New-LedgerError(
                        "Rule $($rule.id) has a duplicate path selector: $path"))
                }
            }
        }
        if ($rule.Contains('owners')) {
            foreach ($ownerSelector in $rule.owners) {
                $separator = $ownerSelector.IndexOf('@')
                $owner = $ownerSelector.Substring(0, $separator)
                $version = $ownerSelector.Substring($separator + 1)
                $ownerMatches = 0
                foreach ($path in $Ownership.Keys) {
                    $record = $Ownership[$path]
                    if ($script:Ordinal.Equals($record.owner, $owner) -and
                        $script:Ordinal.Equals($record.version, $version)) {
                        if (-not $matches.Add($path)) {
                            throw (New-LedgerError(
                                "Rule $($rule.id) selectors overlap at $path"))
                        }
                        $ownerMatches++
                    }
                }
                if ($ownerMatches -eq 0) {
                    throw (New-LedgerError(
                        "Rule $($rule.id) owner selector was unconsumed: " +
                        $ownerSelector))
                }
            }
        }
        if ($matches.Count -ne $rule.expectedCount) {
            throw (New-LedgerError(
                "Rule $($rule.id) expected $($rule.expectedCount) paths, " +
                "found $($matches.Count)"))
        }
        $matchArray = New-Object string[] $matches.Count
        $matches.CopyTo($matchArray)
        $sortedMatches = Sort-Bytewise -Values $matchArray
        foreach ($path in $sortedMatches) {
            if ($assignments.Contains($path)) {
                throw (New-LedgerError(
                    "Source rules overlap at ${path}: " +
                    "$($assignments[$path].ruleId), $($rule.id)"))
            }
            $assignments[$path] = [ordered]@{
                action = $rule.action
                ledgerClass = $rule.ledgerClass
                ruleId = $rule.id
            }
        }
        [void]$ruleResults.Add([ordered]@{
            action = $rule.action
            evidence = $rule.evidence
            id = $rule.id
            ledgerClass = $rule.ledgerClass
            pathCount = [long]$sortedMatches.Count
            paths = $sortedMatches
        })
    }
    if ($assignments.Count -ne $Ownership.Count) {
        $unassigned = New-Object System.Collections.Generic.List[string]
        foreach ($path in $Ownership.Keys) {
            if (-not $assignments.Contains($path)) {
                $unassigned.Add($path)
            }
        }
        throw (New-LedgerError(
            "Source rules do not consume all ownership paths: " +
            ((Sort-Bytewise -Values $unassigned.ToArray()) -join ', ')))
    }

    $classCounts = [ordered]@{
        'evidence-backed-candidate' = [long]0
        'modeled-unresolved' = [long]0
        residual = [long]0
    }
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $residualPaths = New-Object System.Collections.Generic.List[string]
    foreach ($path in $assignments.Keys) {
        $assignment = $assignments[$path]
        $classCounts[$assignment.ledgerClass]++
        if ($assignment.ledgerClass -eq 'residual') {
            $residualPaths.Add($path)
        } else {
            $candidatePaths.Add($path)
        }
    }
    if ($classCounts['evidence-backed-candidate'] -ne
            $Model.expected.evidenceBackedCandidateCount -or
        $classCounts['modeled-unresolved'] -ne
            $Model.expected.modeledCount -or
        $classCounts.residual -ne $Model.expected.residualCount -or
        $candidatePaths.Count -ne $Model.expected.candidateCount -or
        $assignments.Count -ne $Model.expected.totalCount) {
        throw (New-LedgerError 'Ledger class totals do not match the model')
    }
    $candidateBytes = Get-CanonicalPathSetBytes `
        -Paths $candidatePaths.ToArray()
    $residualBytes = Get-CanonicalPathSetBytes `
        -Paths $residualPaths.ToArray()
    if ((Get-Sha256Hex -Bytes $candidateBytes) -ne
            $Model.expected.candidatePathSha256 -or
        (Get-Sha256Hex -Bytes $residualBytes) -ne
            $Model.expected.residualPathSha256) {
        throw (New-LedgerError 'Ledger partition path hash mismatch')
    }

    $legacyBytes = Get-CanonicalPathSetBytes `
        -Paths $Model.legacyOverlap.paths
    if ((Get-Sha256Hex -Bytes $legacyBytes) -ne
        $Model.legacyOverlap.pathSha256) {
        throw (New-LedgerError 'Legacy overlap path hash mismatch')
    }
    foreach ($path in $Model.legacyOverlap.paths) {
        if ($assignments[$path].ruleId -ne 'candidate-gawk') {
            throw (New-LedgerError(
                "Legacy overlap was not eliminated at path: $path"))
        }
    }

    return [ordered]@{
        assignments = $assignments
        candidatePathBytes = $candidateBytes
        classCounts = $classCounts
        residualPathBytes = $residualBytes
        rules = $ruleResults.ToArray()
        sourceOverlapCount = [long]0
    }
}

function Get-LedgerRecommendations {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Ownership,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Assignments
    )

    $groups = New-OrdinalDictionary
    foreach ($path in $Ownership.Keys) {
        $assignment = $Assignments[$path]
        if ($assignment.ledgerClass -ne 'residual') {
            continue
        }
        $owner = $Ownership[$path]
        $key = "$($assignment.action)`0$($owner.owner)`0$($owner.version)"
        if (-not $groups.Contains($key)) {
            $groups[$key] = [ordered]@{
                action = $assignment.action
                owner = $owner.owner
                paths = New-Object System.Collections.Generic.List[string]
                version = $owner.version
            }
        }
        $groups[$key].paths.Add($path)
    }
    $sortable = New-Object `
        'System.Collections.Generic.Dictionary[string,object]' (
        $script:Ordinal)
    $sortKeys = New-Object System.Collections.Generic.List[string]
    foreach ($group in $groups.Values) {
        $paths = Sort-Bytewise -Values $group.paths.ToArray()
        $countKey = ([long](1000000 - $paths.Count)).ToString(
            'D7', [System.Globalization.CultureInfo]::InvariantCulture)
        $sortKey = $countKey + "`0" + $group.owner + "`0" +
            $group.version + "`0" + $group.action
        if ($sortable.ContainsKey($sortKey)) {
            throw (New-LedgerError(
                "Recommendation tie-break key is not unique: $sortKey"))
        }
        $sortable.Add($sortKey, [pscustomobject]@{
            action = $group.action
            owner = $group.owner
            pathCount = $paths.Count
            paths = $paths
            version = $group.version
        })
        $sortKeys.Add($sortKey)
    }
    $results = New-Object System.Collections.ArrayList
    $rank = 1
    foreach ($sortKey in (Sort-Bytewise -Values $sortKeys.ToArray())) {
        $group = $sortable[$sortKey]
        [void]$results.Add([ordered]@{
            action = $group.action
            owner = $group.owner
            pathCount = [long]$group.pathCount
            paths = $group.paths
            rank = [long]$rank
            version = $group.version
        })
        $rank++
    }
    return ,$results.ToArray()
}

Export-ModuleMember -Function @(
    'Assert-IdentityUnchanged',
    'Assert-LedgerModel',
    'Assert-ObjectShape',
    'Assert-SafeExistingPath',
    'Assert-SafeTree',
    'Assert-SafeField',
    'ConvertFrom-StrictJsonBytes',
    'ConvertFrom-StrictJsonFile',
    'ConvertFrom-StrictTsvBytes',
    'ConvertFrom-PacmanTarResult',
    'ConvertTo-CanonicalJsonBytes',
    'ConvertTo-CanonicalTsvBytes',
    'ConvertTo-OwnershipMapping',
    'Compile-LedgerRules',
    'Get-GitBlobSha1',
    'Get-CanonicalPathSetBytes',
    'Get-LedgerRecommendations',
    'Get-PeRecord',
    'Get-Sha256Hex',
    'Get-StableFileHash',
    'New-SafePrivateDirectory',
    'New-OrdinalDictionary',
    'Normalize-ArchivePath',
    'Read-PacmanSections',
    'Read-StableBytes',
    'Read-TarPayload',
    'Remove-SafePrivateDirectory',
    'Resolve-LexicalLinkTarget',
    'Sort-Bytewise',
    'Test-ContainedPath'
    'Write-CanonicalArtifactSet'
)
