#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
selection_only=
case "$1" in
--selection-only) selection_only=t;;
"") ;;
*) die "Unknown option: $1";;
esac
tmp=${TMPDIR:-/tmp}/arm64-native-tools.$$
trap 'rm -f "$tmp"' EXIT

ARCH=aarch64 INCLUDE_GIT_UPDATE=1 \
	"$thisdir/../make-file-list.sh" >"$tmp" ||
die "Could not generate the ARM64 file list"

for tool in bunzip2 bzcat bzip2 bzip2recover \
	nettle-hash nettle-lfib-stream nettle-pbkdf2 pkcs1-conv sexp-conv \
	p11-kit trust
do
	grep -qx "usr/bin/$tool.exe" "$tmp" &&
	die "The ARM64 file list still contains usr/bin/$tool.exe"
	grep -qx "clangarm64/bin/$tool.exe" "$tmp" ||
	die "The ARM64 file list does not contain clangarm64/bin/$tool.exe"
done

for tool in d2u dos2unix mac2unix u2d unix2dos unix2mac
do
	grep -qx "usr/bin/$tool.exe" "$tmp" ||
	die "The ARM64 file list does not contain usr/bin/$tool.exe"
	! grep -qx "clangarm64/bin/$tool.exe" "$tmp" ||
	die "The ARM64 file list unexpectedly contains clangarm64/bin/$tool.exe"
done

for pattern in \
	'^usr/bin/msys-bz2-[0-9].*\.dll$' \
	'^usr/lib/perl5/.*/auto/Compress/Raw/Bzip2/Bzip2\.dll$' \
	'^usr/bin/msys-hogweed-[0-9].*\.dll$' \
	'^usr/bin/msys-nettle-[0-9].*\.dll$' \
	'^usr/bin/msys-p11-kit-[0-9].*\.dll$' \
	'^usr/lib/pkcs11/p11-kit-trust\.dll$' \
	'^usr/libexec/p11-kit/p11-kit-remote\.exe$' \
	'^usr/libexec/p11-kit/p11-kit-server\.exe$'
do
	grep -Eq "$pattern" "$tmp" ||
	die "The ARM64 file list no longer contains required x64 payload matching $pattern"
done

test -z "$selection_only" || exit 0

PATH=/clangarm64/bin:/usr/bin
export PATH
check_tool () {
	expected_prefix=$1
	tool=$2
	expected=$3
	shift 3

	path=$(command -v "$tool") ||
	die "Could not resolve $tool from Git Bash"
	test "$expected_prefix/$tool" = "$path" ||
	die "$tool resolves to $path instead of $expected_prefix/$tool"

	"$tool" "$@" >"$tmp" 2>&1
	actual=$?
	test "$expected" = "$actual" ||
	die "$tool returned $actual instead of $expected"
}

for tool in bunzip2 bzcat bzip2 bzip2recover \
	nettle-hash nettle-lfib-stream nettle-pbkdf2 pkcs1-conv sexp-conv \
	p11-kit trust
do
	case "$tool" in
	bzip2recover|nettle-lfib-stream) expected=1;;
	*) expected=0;;
	esac
	case "$tool" in
	bzip2recover) args=;;
	*) args=--help;;
	esac
	check_tool /clangarm64/bin "$tool" "$expected" $args
done

PATH=/usr/bin:/clangarm64/bin
export PATH
for tool in d2u dos2unix mac2unix u2d unix2dos unix2mac
do
	check_tool /usr/bin "$tool" 0 --help
done

workdir=${TMPDIR:-/tmp}/arm64-native-tools.$$.d
mkdir "$workdir" ||
die "Could not create $workdir"
trap 'rm -f "$tmp" "$tmp.expected" && rm -rf "$workdir"' EXIT

printf 'line1\r\nline2\r\n' >"$workdir/space file.txt" &&
dos2unix.exe "$workdir/space file.txt" >/dev/null 2>&1 ||
die "dos2unix.exe failed to normalize CRLF"
printf 'line1\nline2\n' >"$tmp.expected" &&
cmp -s "$workdir/space file.txt" "$tmp.expected" ||
die "dos2unix.exe did not convert CRLF to LF"

for option in --allow-chown --no-allow-chown
do
	dos2unix.exe "$option" >/dev/null 2>&1 &&
	die "dos2unix.exe unexpectedly accepts $option"
done

dos2unix.exe --follow-symlink >/dev/null 2>&1 ||
die "dos2unix.exe unexpectedly rejects --follow-symlink"

unix2dos.exe "$workdir/space file.txt" >/dev/null 2>&1 ||
die "unix2dos.exe failed to restore CRLF"
printf 'line1\r\nline2\r\n' >"$tmp.expected" &&
cmp -s "$workdir/space file.txt" "$tmp.expected" ||
die "unix2dos.exe did not convert LF to CRLF"
