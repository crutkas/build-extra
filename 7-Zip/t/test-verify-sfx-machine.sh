#!/bin/sh

# Tests for 7-Zip/verify-sfx-machine.sh, the architecture gate that keeps the
# ARM64 self-extractors from silently falling back to the x86 SFX stub.
#
# These tests use tiny synthesized PE headers as fixtures; they never write a
# fake .sfx into the tree.  Run with any POSIX shell that has `od` and `awk`
# (Git for Windows Bash, the Git SDK, or a Linux CI runner):
#
#   sh 7-Zip/t/test-verify-sfx-machine.sh

set -e

self_dir=$(cd "$(dirname "$0")" && pwd)
sevenzip_dir=$(cd "$self_dir/.." && pwd)
gate="$sevenzip_dir/verify-sfx-machine.sh"

test -f "$gate" || { echo "Bail out! gate not found: $gate" >&2; exit 1; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sfx-gate.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

pass=0
fail=0

run () { sh "$gate" "$1" "$2" >/dev/null 2>&1; }

expect_pass () { # expect_pass <description> <arch> <file>
	if run "$2" "$3"
	then pass=$((pass + 1)); echo "ok - $1"
	else fail=$((fail + 1)); echo "not ok - $1 (expected the gate to accept)"
	fi
}

expect_fail () { # expect_fail <description> <arch> <file>
	if run "$2" "$3"
	then fail=$((fail + 1)); echo "not ok - $1 (expected the gate to reject)"
	else pass=$((pass + 1)); echo "ok - $1"
	fi
}

# Write a minimal PE image whose only meaningful field is the Machine value.
# $2/$3 are the little-endian Machine bytes as octal escapes for printf.
make_pe () { # make_pe <outfile> <lo-octal> <hi-octal>
	{
		printf 'MZ'
		head -c 58 /dev/zero
		printf '\100\000\000\000'   # e_lfanew = 64 (0x40)
		printf 'PE\000\000'         # PE signature
		printf "$2$3"               # Machine (little-endian)
		printf '\000\000'           # padding
	} >"$1"
}

arm64="$tmp/arm64.pe";   make_pe "$arm64"   '\144' '\252' # 0xAA64
amd64="$tmp/amd64.pe";   make_pe "$amd64"   '\144' '\206' # 0x8664
arm64ec="$tmp/ec.pe";    make_pe "$arm64ec" '\101' '\246' # 0xA641
arm64x="$tmp/x.pe";      make_pe "$arm64x"  '\116' '\246' # 0xA64E
i386="$tmp/i386.pe";     make_pe "$i386"    '\114' '\001' # 0x014C
notpe="$tmp/notpe.txt";  printf 'this is not a PE file\n' >"$notpe"

# The synthesized ARM64 header is accepted only for ARM64, by every spelling.
expect_pass "native ARM64 stub accepted for aarch64"    aarch64    "$arm64"
expect_pass "native ARM64 stub accepted for arm64"      arm64      "$arm64"
expect_pass "native ARM64 stub accepted for CLANGARM64" CLANGARM64 "$arm64"
expect_pass "native ARM64 stub accepted for 0xAA64"     0xAA64     "$arm64"

# The forbidden machine types (0x14c/0x8664/0xA641/0xA64E) are all rejected when
# ARM64 is requested -- this is the whole point of the gate.
expect_fail "x86 stub rejected for aarch64"     aarch64 "$i386"
expect_fail "x64 stub rejected for aarch64"     aarch64 "$amd64"
expect_fail "ARM64EC stub rejected for aarch64" aarch64 "$arm64ec"
expect_fail "ARM64X stub rejected for aarch64"  aarch64 "$arm64x"

# The shared x86 stub is what non-ARM64 architectures expect...
expect_pass "x86 stub accepted for x86_64" x86_64 "$i386"
expect_pass "x86 stub accepted for i686"   i686   "$i386"
expect_pass "x86 stub accepted for ucrt64" ucrt64 "$i386"
# ...and an ARM64 stub must not be used for an x86/x64 self-extractor.
expect_fail "ARM64 stub rejected for x86_64" x86_64 "$arm64"

# Non-PE inputs and unknown tokens fail loudly rather than being ignored.
expect_fail "non-PE input rejected"       aarch64 "$notpe"
expect_fail "missing file rejected"       aarch64 "$tmp/does-not-exist"
expect_fail "unknown arch token rejected" sparc   "$i386"

# The real, checked-in x86 stub must be x86 -- and must be refused for ARM64.
real="$sevenzip_dir/7zS.sfx"
if test -f "$real"
then
	expect_pass "checked-in 7zS.sfx is x86 (x86_64 build)" x86_64 "$real"
	expect_fail "checked-in 7zS.sfx refused for aarch64"   aarch64 "$real"
fi

# Once the native ARM64 stub is committed, prove it really is native ARM64.
real_arm64="$sevenzip_dir/7zS-arm64.sfx"
if test -f "$real_arm64"
then
	expect_pass "checked-in 7zS-arm64.sfx is native ARM64" aarch64 "$real_arm64"
	expect_fail "checked-in 7zS-arm64.sfx refused for x86_64" x86_64 "$real_arm64"
else
	echo "# note: 7-Zip/7zS-arm64.sfx not present yet (native ARM64 stub pending)"
fi

echo "1..$((pass + fail))"
echo "# passed $pass, failed $fail"
test "$fail" -eq 0
