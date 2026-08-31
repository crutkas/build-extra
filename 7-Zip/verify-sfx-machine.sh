#!/bin/sh

# Verify the PE "Machine" field of a 7-Zip self-extractor (SFX) stub matches the
# architecture that is about to be packaged.
#
# Git for Windows builds PortableGit-*.7z.exe and git-sdk-installer-*.7z.exe by
# concatenating a 7-Zip SFX stub in front of the compressed payload.  On ARM64
# the stub MUST be a native ARM64 binary (PE Machine 0xAA64); shipping the x86
# stub (0x014C) would force the self-extractor to run under emulation on the
# supported extraction path.  This gate refuses to build an ARM64 self-extractor
# from a non-native stub, so there can be no silent fallback to the x86 stub.
#
# The check is deliberately dependency-light (POSIX sh plus `od`/`awk`) so it
# runs in the same environments as the release scripts and in CI.
#
# Usage: verify-sfx-machine.sh <arch|0xMACHINE> <sfx-file>
#
# <arch> may be an MSYSTEM name (MINGW32/MINGW64/UCRT64/CLANGARM64), a Git for
# Windows architecture token (i686/x86_64/ucrt64/aarch64), an SDK architecture
# token (32/64/arm64), or an explicit expected machine value such as 0xAA64.

die () {
	echo "verify-sfx-machine: $*" >&2
	exit 1
}

test $# -eq 2 ||
die "usage: $0 <arch|0xMACHINE> <sfx-file>"

target=$1
file=$2

test -e "$file" ||
die "no such SFX stub: $file (a native stub must be provided; refusing to fall back)"
test -f "$file" ||
die "not a regular file: $file"

# IMAGE_FILE_MACHINE_* constants (decimal) used below:
#   332   = 0x014C i386 (x86)
#   34404 = 0x8664 AMD64 (x64)
#   43620 = 0xAA64 ARM64
#   42561 = 0xA641 ARM64EC
#   42574 = 0xA64E ARM64X
#   452   = 0x01C4 ARMNT (ARM Thumb-2)

machine_name () {
	case "$1" in
	332)   echo "x86 (IMAGE_FILE_MACHINE_I386, 0x014C)";;
	34404) echo "x64 (IMAGE_FILE_MACHINE_AMD64, 0x8664)";;
	43620) echo "ARM64 (IMAGE_FILE_MACHINE_ARM64, 0xAA64)";;
	42561) echo "ARM64EC (IMAGE_FILE_MACHINE_ARM64EC, 0xA641)";;
	42574) echo "ARM64X (IMAGE_FILE_MACHINE_ARM64X, 0xA64E)";;
	452)   echo "ARM Thumb-2 (IMAGE_FILE_MACHINE_ARMNT, 0x01C4)";;
	*)     printf '0x%04X (unrecognized)\n' "$1";;
	esac
}

# Map the requested target to the PE Machine value we require for it.  ARM64 is
# the only architecture that gets a native stub; every other architecture shares
# the x86 stub, which also runs natively on x64.
case "$target" in
0[xX]*)
	hex=${target#0[xX]}
	expected=$(awk -v h="$hex" 'BEGIN {
		n = 0; h = toupper(h)
		if (length(h) == 0 || length(h) > 4) exit 1
		for (i = 1; i <= length(h); i++) {
			c = index("0123456789ABCDEF", substr(h, i, 1))
			if (c == 0) exit 1
			n = n * 16 + (c - 1)
		}
		printf "%d", n
	}') ||
	die "invalid machine value: $target"
	;;
aarch64|arm64|clangarm64|ARM64|CLANGARM64)
	expected=43620 # 0xAA64
	;;
i686|x86_64|ucrt64|mingw32|mingw64|MINGW32|MINGW64|UCRT64|32|64|x86|x64|i386)
	expected=332 # 0x014C (shared x86 stub, also runs on x64)
	;;
*)
	die "unknown architecture token: $target"
	;;
esac

read_uint_le () {
	# read_uint_le <offset> <byte-count>: little-endian unsigned integer.
	od -An -tu1 -j "$1" -N "$2" "$file" |
	awk '{ v = 0; m = 1; for (i = 1; i <= NF; i++) { v += $i * m; m *= 256 } print v }'
}

size=$(wc -c <"$file")

# DOS header: "MZ" (0x5A4D little-endian == 23117).
test "$(read_uint_le 0 2)" = 23117 ||
die "$file: not a PE image (missing MZ signature)"

# e_lfanew at 0x3C points at the PE header.
elfanew=$(read_uint_le 60 4)
case "$elfanew" in
''|*[!0-9]*) die "$file: could not read PE header offset";;
esac
test "$elfanew" -ge 64 && test $((elfanew + 6)) -le "$size" ||
die "$file: PE header offset out of range ($elfanew)"

# PE signature: "PE\0\0" (0x00004550 little-endian == 17744).
test "$(read_uint_le "$elfanew" 4)" = 17744 ||
die "$file: not a PE image (missing PE signature)"

# COFF file header starts right after the signature; Machine is its first field.
machine=$(read_uint_le $((elfanew + 4)) 2)

if test "$machine" != "$expected"
then
	die "$file: PE Machine is $(machine_name "$machine") but $target requires $(machine_name "$expected"); refusing to build the self-extractor (no fallback to the x86 stub)"
fi

echo "verify-sfx-machine: $file is $(machine_name "$machine"), as required for $target" >&2
exit 0
