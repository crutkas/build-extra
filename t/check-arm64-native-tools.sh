#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
root_dir=
root_supplied=
case "$1" in
--selection-only) ;;
--root)
	shift
	root_dir=$1
	;;
"--root="*) root_dir=${1#*=};;
"") ;;
*) die "Unknown option: $1";;
esac
if test -n "$root_dir"
then
	root_supplied=t
	case "$root_dir" in
	/*) ;;
	*) root_dir="$(cygpath -au "$root_dir")" ||
		die "Could not resolve the ARM64 root";;
	esac
	PATH="$root_dir/clangarm64/bin:$root_dir/usr/bin:$PATH"
	awk_path="$root_dir/clangarm64/bin/awk.exe"
	gawk_path="$root_dir/clangarm64/bin/gawk.exe"
fi
if test -z "$root_supplied"
then
	tmp=${TMPDIR:-/tmp}/arm64-native-tools.$$
	trap 'rm -f "$tmp"; test -n "$runtime" && rm -rf "$runtime"' EXIT

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

	grep -qx "clangarm64/bin/gawk.exe" "$tmp" ||
	die "The ARM64 file list does not contain clangarm64/bin/gawk.exe"
	grep -qx "clangarm64/bin/gawk-5.4.1.exe" "$tmp" ||
	die "The ARM64 file list does not contain clangarm64/bin/gawk-5.4.1.exe"
	grep -qx "clangarm64/bin/libmpfr-6.dll" "$tmp" ||
	die "The ARM64 file list does not contain clangarm64/bin/libmpfr-6.dll"
	grep -qx "clangarm64/lib/gawk/fork.dll" "$tmp" &&
	die "fork.dll should not be packaged for native ARM64 gawk"

	exit 0
fi

export PATH
gawk_versioned_path=$(command -v gawk-5.4.1) ||
die "Could not resolve gawk-5.4.1 from Git Bash"
case "$gawk_versioned_path" in
*/clangarm64/bin/gawk-5.4.1|*/clangarm64/bin/gawk-5.4.1.exe) ;;
*) die "gawk-5.4.1 resolves to $gawk_versioned_path instead of a clangarm64/bin/gawk-5.4.1[.exe] path";;
esac
test ! -f "$root_dir/clangarm64/lib/gawk/fork.dll" ||
die "fork.dll should not be packaged for native ARM64 gawk"

if test -z "$root_supplied"
then
	awk_path=$(command -v awk) ||
	die "Could not resolve awk from Git Bash"
	gawk_path=$(command -v gawk) ||
	die "Could not resolve gawk from Git Bash"
fi
case "$root_dir" in
*/mingit-root)
	case "$awk_path" in
	*/clangarm64/bin/awk|*/clangarm64/bin/awk.exe|*/usr/bin/awk|*/usr/bin/awk.exe) ;;
	*) die "awk resolves to $awk_path instead of an accepted MinGit path";;
	esac
	;;
*)
	case "$awk_path" in
	*/clangarm64/bin/awk|*/clangarm64/bin/awk.exe) ;;
	*) die "awk resolves to $awk_path instead of a clangarm64/bin/awk[.exe] path";;
	esac
	;;
esac
case "$gawk_path" in
*/clangarm64/bin/gawk|*/clangarm64/bin/gawk.exe) ;;
*) die "gawk resolves to $gawk_path instead of a clangarm64/bin/gawk[.exe] path";;
esac
test -f "$root_dir/clangarm64/bin/libmpfr-6.dll" ||
die "The ARM64 payload does not contain clangarm64/bin/libmpfr-6.dll"
check_tool () {
	tool=$1
	expected=$2
	shift 2

	path="$root_dir/clangarm64/bin/$tool.exe"
	test -f "$path" || path="$root_dir/clangarm64/bin/$tool"
	test -f "$path" ||
	die "$tool does not exist in the ARM64 payload"
	"$path" "$@" >"$tmp" 2>&1
	actual=$?
	test "$expected" = "$actual" ||
	die "$tool returned $actual instead of $expected"
}

if test -z "$root_supplied"
then
	check_tool bunzip2 1 --help
	check_tool bzcat 0 --help
	check_tool bzip2 0 --help
	check_tool bzip2recover 1
	check_tool nettle-hash 0 --help
	check_tool nettle-lfib-stream 1 --help
	check_tool nettle-pbkdf2 0 --help
	check_tool pkcs1-conv 0 --help
	check_tool sexp-conv 0 --help
	check_tool p11-kit 0 --help
	check_tool trust 0 --help
fi

runtime=${TMPDIR:-/tmp}/arm64-gawk.$$
trap 'rm -f "$tmp"; rm -rf "$runtime"' EXIT
mkdir -p "$runtime/scripts" "$runtime/ext"

cat >"$runtime/scripts/field.awk" <<'EOF'
{ print $1 " " $2 }
EOF
printf 'alpha beta\n' >"$runtime/field-input.txt" &&
field_input=$(cygpath -aw "$runtime/field-input.txt") &&
field_output=$("$gawk_path" -f "$runtime/scripts/field.awk" "$field_input" 2>"$runtime/field.err" | tr -d '\r') &&
if test 'alpha beta' = "$field_output"
then
	:
else
	printf 'gawk field output: <%s>\n' "$field_output" >&2
	test ! -s "$runtime/field.err" || cat "$runtime/field.err" >&2
	die "gawk field processing failed"
fi

cat >"$runtime/scripts/from-awkpath.awk" <<'EOF'
BEGIN { print "awkpath-ok" }
EOF
awkpath_dir=$(cygpath -aw "$runtime/scripts") &&
AWKPATH="$awkpath_dir;$AWKPATH" \
	"$gawk_path" -f from-awkpath.awk /dev/null >"$runtime/awkpath.out" &&
printf 'awkpath-ok\n' >"$runtime/awkpath.expect" &&
cmp "$runtime/awkpath.expect" "$runtime/awkpath.out" ||
die "AWKPATH did not honor a native Windows path list"

cp "$root_dir/clangarm64/lib/gawk"/*.dll "$runtime/ext/" &&
printf 'in place\n' >"$runtime/inplace-input.txt" &&
inplace_input=$(cygpath -aw "$runtime/inplace-input.txt") &&
inplace_lib=$(cygpath -aw "$runtime/ext") &&
AWKLIBPATH="$inplace_lib;$AWKLIBPATH" \
	"$gawk_path" -i inplace '{ print toupper($0) }' "$inplace_input" &&
printf 'IN PLACE\n' >"$runtime/inplace.expect" &&
cmp "$runtime/inplace.expect" "$runtime/inplace-input.txt" ||
die "AWKLIBPATH or inplace extension loading failed"

printf 'quoted\n' >"$runtime/system-input.txt" &&
system_input=$(cygpath -aw "$runtime/system-input.txt") &&
system_output=$(cygpath -aw "$runtime/system-output.txt") &&
"$gawk_path" -v source="$system_input" -v target="$system_output" '
BEGIN {
  cmd = "cmd.exe /c type \"" source "\" > \"" target "\""
  if (system(cmd) != 0)
    exit 17
}' &&
printf 'quoted\n' >"$runtime/system.expect" &&
cmp "$runtime/system.expect" "$runtime/system-output.txt" ||
die "gawk system() quoting failed"

printf 'caf\303\251\n' >"$runtime/utf8-input.txt" &&
utf8_input=$(cygpath -aw "$runtime/utf8-input.txt") &&
LC_ALL=C.UTF-8 "$gawk_path" '{ print length($0) }' "$utf8_input" >"$runtime/utf8.out" &&
printf '4\n' >"$runtime/utf8.expect" &&
cmp "$runtime/utf8.expect" "$runtime/utf8.out" ||
die "gawk UTF-8 handling failed"

"$gawk_path" 'BEGIN { exit 17 }'
test 17 = "$?" ||
die "gawk exit codes are not preserved"

if "$gawk_path" -l fork 'BEGIN { print "fork" }' >/dev/null 2>"$runtime/fork.err"
then
	die "gawk unexpectedly loaded fork.dll"
fi
grep -qi 'fork' "$runtime/fork.err" ||
die "gawk did not report the missing fork extension"
