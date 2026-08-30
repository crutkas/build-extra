#!/bin/sh

# Verify that every PE shipped in the ARM64 payload is a native ARM64 binary,
# and that the list of known non-ARM64 binaries only ever shrinks.
#
# Two lists back this check:
#
#   arm64-payload-baseline.txt    native non-ARM64 binaries, i.e. residual
#                                 emulation debt. Cannot grow past its recorded
#                                 seed-entries; reductions are reported.
#   arm64-payload-exceptions.txt  reviewed, architecture-neutral binaries that
#                                 are not an emulation dependency. Refuses
#                                 native machine types, so the ratchet above
#                                 cannot be bypassed here.
#
# Anything shipped that is neither ARM64 nor listed is a failure.

die () {
	echo "$*" >&2
	exit 1
}

usage () {
	cat >&2 <<-EOF
	Usage: $0 [options]

	  --baseline=<file>    default: <script dir>/arm64-payload-baseline.txt
	  --exceptions=<file>  default: <script dir>/arm64-payload-exceptions.txt
	  --file-list=<file>   payload paths to inspect; default: run make-file-list.sh
	  --root=<dir>         prefix for payload paths; default: none, i.e. /
	  --pe-imports=<file>  default: <script dir>/pe-imports.ps1
	EOF
	exit 2
}

# Globbing is never wanted here and payload names such as `[.exe` would
# otherwise be expanded when a batch is split into arguments.
set -f

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine script directory"

baseline_file="$thisdir/arm64-payload-baseline.txt"
exceptions_file="$thisdir/arm64-payload-exceptions.txt"
pe_imports="$thisdir/pe-imports.ps1"
file_list=
root=

while test $# -gt 0
do
	case "$1" in
	--baseline=*) baseline_file="${1#*=}";;
	--exceptions=*) exceptions_file="${1#*=}";;
	--file-list=*) file_list="${1#*=}";;
	--root=*) root="${1#*=}";;
	--pe-imports=*) pe_imports="${1#*=}";;
	-h|--help) usage;;
	*) echo "Unknown option: $1" >&2; usage;;
	esac
	shift
done

type sha256sum >/dev/null 2>&1 ||
die "sha256sum is required to verify the baseline digest"

test -f "$pe_imports" ||
die "Not found: $pe_imports"

tmp=/tmp/payload-arch.$$
# `set -f` above is still in effect inside the trap, so the glob would not be
# expanded and the cleanup would quietly remove nothing.
trap "set +f; rm -f \"$tmp\".*" EXIT

# The machine names that describe an architecture-neutral payload. Only these
# may appear in the exceptions file; everything else is a concrete instruction
# set and belongs in the baseline.
NEUTRAL_MACHINES='anycpu'

header_value () { # <file> <key>
	sed -n "s/^# $2: \\(.*\\)\$/\\1/p" "$1" | head -n 1
}

list_body () { # <file>
	sed -e '/^[ 	]*#/d' -e '/^[ 	]*$/d' "$1"
}

digest_of () { # <file>
	sha256sum <"$1" | sed 's/ .*//'
}

check_list_format () { # <file> <label>
	test -f "$1" ||
	die "Not found: $1"

	version="$(header_value "$1" format-version)"
	test "$version" = 1 ||
	die "$2: unsupported format-version '$version', expected 1"

	declared="$(header_value "$1" entries)"
	case "$declared" in
	'' | *[!0-9]*) die "$2: missing or malformed 'entries' header";;
	esac

	list_body "$1" >"$tmp.body"
	actual=$(($(wc -l <"$tmp.body")))
	test "$declared" -eq "$actual" ||
	die "$2: header says $declared entries but the body has $actual"

	declared_digest="$(header_value "$1" sha256)"
	actual_digest="$(digest_of "$tmp.body")"
	test "$declared_digest" = "$actual_digest" ||
	die "$2: sha256 header is $declared_digest but the body hashes to $actual_digest"
}

check_list_format "$baseline_file" "$baseline_file"
cp "$tmp.body" "$tmp.baseline"

seed="$(header_value "$baseline_file" seed-entries)"
case "$seed" in
'' | *[!0-9]*) die "$baseline_file: missing or malformed 'seed-entries' header";;
esac
baseline_count=$(($(wc -l <"$tmp.baseline")))
test "$baseline_count" -le "$seed" ||
die "$baseline_file: $baseline_count entries exceeds seed-entries $seed; the baseline may only shrink"

check_list_format "$exceptions_file" "$exceptions_file"
cut -f 1,2 <"$tmp.body" >"$tmp.exceptions"

# Reject a native machine in the exceptions file, which would otherwise be a
# way to add emulation debt without touching the baseline.
cut -f 1 <"$tmp.exceptions" | sort -u >"$tmp.exception-machines"
while read -r machine
do
	case " $NEUTRAL_MACHINES " in
	*" $machine "*) ;;
	*) die "$exceptions_file: '$machine' is a native machine type; list it in $baseline_file instead";;
	esac
done <"$tmp.exception-machines"

if test -n "$file_list"
then
	test -f "$file_list" ||
	die "Not found: $file_list"
	cat "$file_list" >"$tmp.all"
else
	ARCH=aarch64 "$thisdir"/make-file-list.sh >"$tmp.all" ||
	die "Could not generate the file list"
fi

sed -n -e 's|^/||' -e '/\.\(dll\|exe\)$/p' "$tmp.all" | LC_ALL=C sort -u >"$tmp.candidates"
candidate_count=$(($(wc -l <"$tmp.candidates")))
test "$candidate_count" -gt 0 ||
die "The payload contains no .dll or .exe files; refusing to report success"

type cygpath >/dev/null 2>&1 ||
die "cygpath is required to hand payload paths to the PE parser"

# Hand the paths over in a file rather than as arguments. MSYS silently
# refuses to convert an argument containing a bracket, and the payload really
# does contain `usr/bin/[.exe`.
: >"$tmp.absolute"
while read -r payload_path
do
	printf '%s\n' "$root/$payload_path" >>"$tmp.absolute"
done <"$tmp.candidates"

cygpath -w -f "$tmp.absolute" >"$tmp.windows" ||
die "Could not convert the payload paths to Windows form"

windows_count=$(($(wc -l <"$tmp.windows")))
test "$windows_count" -eq "$candidate_count" ||
die "Converted $windows_count of $candidate_count payload paths; refusing to report success"

powershell.exe -NoProfile -ExecutionPolicy Bypass \
	-File "$pe_imports" -Machine -PathFile "$(cygpath -w "$tmp.windows")" >"$tmp.out" ||
die "pe-imports.ps1 failed while classifying the payload"

out_n=$(($(wc -l <"$tmp.out")))
test "$out_n" -eq "$candidate_count" ||
die "pe-imports.ps1 described $out_n of $candidate_count binaries; refusing to report success"

# Join by position: pe-imports.ps1 emits exactly one line per input, in order.
# Its echoed path is in Windows form, so it is not comparable to the payload
# path.
: >"$tmp.machines"
exec 3<"$tmp.candidates" 4<"$tmp.out"
while read -r payload_path <&3 && read -r machine_line <&4
do
	printf '%s\t%s\n' "${machine_line%%	*}" "$payload_path" >>"$tmp.machines"
done
exec 3<&- 4<&-

classified=$(($(wc -l <"$tmp.machines")))
test "$classified" -eq "$candidate_count" ||
die "Classified $classified of $candidate_count binaries; refusing to report success"

grep -v '^arm64	' <"$tmp.machines" | LC_ALL=C sort >"$tmp.observed"
observed_count=$(($(wc -l <"$tmp.observed")))

LC_ALL=C sort "$tmp.baseline" >"$tmp.baseline.sorted"
LC_ALL=C sort "$tmp.exceptions" >"$tmp.exceptions.sorted"
LC_ALL=C sort -u "$tmp.baseline.sorted" "$tmp.exceptions.sorted" >"$tmp.known"

LC_ALL=C comm -23 "$tmp.observed" "$tmp.known" >"$tmp.unlisted"
LC_ALL=C comm -13 "$tmp.observed" "$tmp.baseline.sorted" >"$tmp.gone"

status=0

if test -s "$tmp.unlisted"
then
	echo "The ARM64 payload gained binaries that are not native ARM64:" >&2
	sed 's/^/  /' <"$tmp.unlisted" >&2
	echo >&2
	echo "Make them ARM64, or -- if a listed path merely changed machine type --" >&2
	echo "update the entry. A native machine belongs in $baseline_file," >&2
	echo "which cannot grow past its seed-entries; an architecture-neutral one" >&2
	echo "belongs in $exceptions_file with a reason." >&2
	status=1
fi

echo "Inspected $candidate_count binaries: $(($candidate_count - $observed_count)) ARM64," \
	"$observed_count not ARM64." >&2
echo "Baseline holds $baseline_count of a seeded $seed entries." >&2

if test -s "$tmp.gone"
then
	removed=$(($(wc -l <"$tmp.gone")))
	echo >&2
	echo "$removed baseline entries are no longer shipped and can be dropped:" >&2
	sed 's/^/  /' <"$tmp.gone" >&2
	LC_ALL=C comm -12 "$tmp.observed" "$tmp.baseline.sorted" >"$tmp.baseline.next"
	echo >&2
	echo "After dropping them, $baseline_file should read:" >&2
	echo "  # entries: $(($(wc -l <"$tmp.baseline.next")))" >&2
	echo "  # sha256: $(digest_of "$tmp.baseline.next")" >&2
fi

exit $status
