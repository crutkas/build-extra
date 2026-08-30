#!/bin/sh

# Verify that every PE shipped in the ARM64 payload is an ordinary ARM64
# binary, and that the set of exceptions to that only ever shrinks.
#
# Two lists back this check:
#
#   arm64-payload-baseline.txt    The seed: the native non-ARM64 binaries
#                                 present when the ratchet was introduced, i.e.
#                                 the residual emulation debt. It is immutable
#                                 evidence. Its size and digest are pinned in
#                                 this script, so it cannot be edited -- not
#                                 even to swap one entry for another at the
#                                 same count -- without a visible change here.
#                                 Debt is paid down by the payload changing,
#                                 which this check then reports as a reduction.
#
#   arm64-payload-exceptions.txt  Reviewed binaries that are architecture
#                                 neutral and so are not an emulation
#                                 dependency. Only the strict AnyCPU class is
#                                 accepted, so nothing native can be admitted
#                                 here instead of failing against the seed.
#
# Anything shipped that is neither ordinary ARM64 nor listed is a failure, as
# is any binary whose classification has drifted away from what the seed
# records.

# The seed is pinned here rather than only self-describing. A digest that a
# contributor recomputes from the file they just edited proves nothing; these
# constants mean the file cannot change without this script changing too.
SEED_ENTRIES=433
SEED_SHA256=a1e536ae97206e0b88e432978aed40a13d19f61c27076fc28052dcd1de9aeb10
SEED_VERSION=v2.55.0.4
SEED_ARTIFACT=arm64-payload-architecture-v2.55.0.4.tsv

# The only class that may appear in the exceptions file. `anycpu32` is
# deliberately absent: a 32-bit-preferred assembly starts a 32-bit process
# wherever one can be started, and so is emulated on ARM64.
EXCEPTION_CLASSES='anycpu'

# Classes that may not appear in the seed. `arm64` because it is the thing
# being required; `anycpu` because it belongs in the exceptions file; and every
# parse failure because a binary nobody could decode must be fixed rather than
# grandfathered.
FORBIDDEN_BASELINE_CLASSES='arm64 anycpu not-pe truncated malformed unreadable'

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
	  --seed-sha256=<hex>  override the pinned seed digest; for tests only
	  --seed-entries=<n>   override the pinned seed size; for tests only
	  --seed-version=<v>   override the pinned seed version; for tests only
	  --seed-artifact=<a>  override the pinned seed artifact; for tests only
	EOF
	exit 2
}

# Globbing is never wanted here, and payload names such as `[.exe` would
# otherwise be expanded when a list is read.
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
	--seed-sha256=*) SEED_SHA256="${1#*=}";;
	--seed-entries=*) SEED_ENTRIES="${1#*=}";;
	--seed-version=*) SEED_VERSION="${1#*=}";;
	--seed-artifact=*) SEED_ARTIFACT="${1#*=}";;
	-h|--help) usage;;
	*) echo "Unknown option: $1" >&2; usage;;
	esac
	shift
done

type sha256sum >/dev/null 2>&1 ||
die "sha256sum is required to verify the list digests"

type cygpath >/dev/null 2>&1 ||
die "cygpath is required to hand payload paths to the PE parser"

test -f "$pe_imports" ||
die "Not found: $pe_imports"

tmp=/tmp/payload-arch.$$
# `set -f` is still in effect inside the trap, so a glob there would not be
# expanded and the cleanup would quietly remove nothing.
trap "set +f; rm -f \"$tmp\".*" EXIT

header_value () { # <file> <key>
	sed -n "s/^# $2: \\(.*\\)\$/\\1/p" "$1" | head -n 1
}

list_body () { # <file>
	sed -e '/^[ 	]*#/d' -e '/^[ 	]*$/d' "$1"
}

digest_of () { # <file>
	sha256sum <"$1" | sed 's/ .*//'
}

# Everything a list has to satisfy regardless of which list it is: a declared
# format and size that match the body, a fixed number of tab-separated fields,
# byte order, uniqueness of both whole entries and paths, and paths that are
# repo-relative and canonical.
validate_list () { # <file> <label> <fields> <body-out>
	list_file="$1"
	label="$2"
	fields="$3"
	body_out="$4"

	test -f "$list_file" ||
	die "Not found: $list_file"

	version="$(header_value "$list_file" format-version)"
	test "$version" = 1 ||
	die "$label: unsupported format-version '$version', expected 1"

	list_body "$list_file" >"$body_out"

	declared="$(header_value "$list_file" entries)"
	case "$declared" in
	'' | *[!0-9]*) die "$label: missing or malformed 'entries' header";;
	esac
	actual=$(($(wc -l <"$body_out")))
	test "$declared" -eq "$actual" ||
	die "$label: header says $declared entries but the body has $actual"

	declared_digest="$(header_value "$list_file" sha256)"
	actual_digest="$(digest_of "$body_out")"
	test "$declared_digest" = "$actual_digest" ||
	die "$label: sha256 header is $declared_digest but the body hashes to $actual_digest"

	# Exactly <fields> tab-separated fields, no more and no fewer. `awk` is
	# not assumed to be present, so count the tabs with `tr`.
	line_no=0
	while IFS= read -r entry
	do
		line_no=$(($line_no + 1))
		tabs=$(($(printf '%s' "$entry" | tr -cd '	' | wc -c)))
		test "$tabs" -eq $(($fields - 1)) ||
		die "$label line $line_no: expected $fields tab-separated fields, found $(($tabs + 1))"
	done <"$body_out"

	LC_ALL=C sort "$body_out" >"$body_out.sorted"
	cmp -s "$body_out" "$body_out.sorted" ||
	die "$label: the body is not sorted with LC_ALL=C"

	LC_ALL=C sort -u "$body_out" >"$body_out.uniq"
	cmp -s "$body_out" "$body_out.uniq" ||
	die "$label: the body contains duplicate entries"

	cut -f 2 <"$body_out" | LC_ALL=C sort >"$body_out.paths"
	LC_ALL=C sort -u "$body_out.paths" >"$body_out.paths.uniq"
	cmp -s "$body_out.paths" "$body_out.paths.uniq" ||
	die "$label: the same path is listed more than once"

	while IFS= read -r payload_path
	do
		case "$payload_path" in
		'') die "$label: an entry has an empty path";;
		/*) die "$label: '$payload_path' is absolute; paths are repo-relative";;
		*\\*) die "$label: '$payload_path' contains a backslash";;
		./* | ../* | */../* | */./*) die "$label: '$payload_path' is not canonical";;
		esac
	done <"$body_out.paths"
}

validate_list "$baseline_file" "$baseline_file" 2 "$tmp.baseline"

# The seed is evidence, not a working file. Pinning its size and digest here is
# what stops one grandfathered entry being swapped for a new one at the same
# count with a recomputed header.
baseline_count=$(($(wc -l <"$tmp.baseline")))
test "$baseline_count" -eq "$SEED_ENTRIES" ||
die "$baseline_file: the seed has $baseline_count entries but $SEED_ENTRIES are pinned in $0"

baseline_digest="$(digest_of "$tmp.baseline")"
test "$baseline_digest" = "$SEED_SHA256" ||
die "$baseline_file: the seed hashes to $baseline_digest but $SEED_SHA256 is pinned in $0; the seed is immutable evidence and must not be edited"

# The seed also has to say which payload it describes. A digest on its own
# identifies the bytes; these say what they are evidence of.
seed_version="$(header_value "$baseline_file" seed-version)"
test "$seed_version" = "$SEED_VERSION" ||
die "$baseline_file: seed-version is '$seed_version' but '$SEED_VERSION' is pinned in $0"

seed_artifact="$(header_value "$baseline_file" seed-artifact)"
test "$seed_artifact" = "$SEED_ARTIFACT" ||
die "$baseline_file: seed-artifact is '$seed_artifact' but '$SEED_ARTIFACT' is pinned in $0"

test -n "$(header_value "$baseline_file" seed-source)" ||
die "$baseline_file: the seed does not record where it came from"

cut -f 1 <"$tmp.baseline" | LC_ALL=C sort -u >"$tmp.baseline.classes"
while IFS= read -r machine
do
	case " $FORBIDDEN_BASELINE_CLASSES " in
	*" $machine "*) die "$baseline_file: '$machine' must not appear in the seed";;
	esac
	case "$machine" in
	unknown-*) die "$baseline_file: '$machine' is unrecognised and must not appear in the seed";;
	esac
done <"$tmp.baseline.classes"

validate_list "$exceptions_file" "$exceptions_file" 3 "$tmp.exceptions.full"
cut -f 1,2 <"$tmp.exceptions.full" >"$tmp.exceptions"

# Only the strict AnyCPU class is neutral. Anything else here would be a way to
# admit emulation debt without touching the seed.
cut -f 1 <"$tmp.exceptions" | LC_ALL=C sort -u >"$tmp.exceptions.classes"
while IFS= read -r machine
do
	case " $EXCEPTION_CLASSES " in
	*" $machine "*) ;;
	*) die "$exceptions_file: '$machine' is not architecture-neutral; it belongs in $baseline_file, which is immutable";;
	esac
done <"$tmp.exceptions.classes"

line_no=0
while IFS= read -r entry
do
	line_no=$(($line_no + 1))
	reason="${entry#*	}"
	reason="${reason#*	}"
	test -n "$(printf '%s' "$reason" | tr -d ' 	')" ||
	die "$exceptions_file line $line_no: the reason is empty"
done <"$tmp.exceptions.full"

LC_ALL=C comm -12 "$tmp.baseline.paths" "$tmp.exceptions.full.paths" >"$tmp.overlap"
test ! -s "$tmp.overlap" || {
	echo "A path is listed in both $baseline_file and $exceptions_file:" >&2
	sed 's/^/  /' <"$tmp.overlap" >&2
	die "Each path must appear in exactly one list"
}

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

# Hand the paths over in a file rather than as arguments. MSYS silently
# refuses to convert an argument containing a bracket, and the payload really
# does contain `usr/bin/[.exe`.
: >"$tmp.absolute"
while IFS= read -r payload_path
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
# path and must not be used to pair the two up.
: >"$tmp.machines"
exec 3<"$tmp.candidates" 4<"$tmp.out"
while IFS= read -r payload_path <&3 && IFS= read -r machine_line <&4
do
	printf '%s\t%s\n' "${machine_line%%	*}" "$payload_path" >>"$tmp.machines"
done
exec 3<&- 4<&-

classified=$(($(wc -l <"$tmp.machines")))
test "$classified" -eq "$candidate_count" ||
die "Classified $classified of $candidate_count binaries; refusing to report success"

grep -v '^arm64	' <"$tmp.machines" | LC_ALL=C sort >"$tmp.observed"
observed_count=$(($(wc -l <"$tmp.observed")))

LC_ALL=C sort "$tmp.baseline" >"$tmp.baseline.byline"
LC_ALL=C sort "$tmp.exceptions" >"$tmp.exceptions.byline"
LC_ALL=C sort -u "$tmp.baseline.byline" "$tmp.exceptions.byline" >"$tmp.known"

LC_ALL=C comm -23 "$tmp.observed" "$tmp.known" >"$tmp.unlisted"
LC_ALL=C comm -13 "$tmp.observed" "$tmp.baseline.byline" >"$tmp.gone"

# A path that is listed but now classifies differently appears in both sets at
# once. That is drift, not a reduction, and reporting it as one would let an
# ARM64 binary turn into an ARM64EC binary and look like progress.
cut -f 2 <"$tmp.unlisted" | LC_ALL=C sort -u >"$tmp.unlisted.paths"
cut -f 2 <"$tmp.gone" | LC_ALL=C sort -u >"$tmp.gone.paths"
LC_ALL=C comm -12 "$tmp.unlisted.paths" "$tmp.gone.paths" >"$tmp.drift.paths"

machine_for () { # <path> <file>
	while IFS='	' read -r machine listed_path
	do
		test "$listed_path" = "$1" || continue
		printf '%s' "$machine"
		return
	done <"$2"
}

without_drift () { # <file>
	while IFS='	' read -r machine listed_path
	do
		grep -q -x -F "$listed_path" "$tmp.drift.paths" ||
		printf '%s\t%s\n' "$machine" "$listed_path"
	done <"$1"
}

without_drift "$tmp.unlisted" >"$tmp.unlisted.net"
without_drift "$tmp.gone" >"$tmp.gone.net"

status=0

if test -s "$tmp.drift.paths"
then
	echo "The classification of a listed binary changed:" >&2
	while IFS= read -r drifted
	do
		printf '  %s: %s -> %s\n' "$drifted" \
			"$(machine_for "$drifted" "$tmp.gone")" \
			"$(machine_for "$drifted" "$tmp.unlisted")" >&2
	done <"$tmp.drift.paths"
	echo "That is a change of architecture, not a reduction in emulation debt." >&2
	echo >&2
	status=1
fi

if test -s "$tmp.unlisted.net"
then
	echo "The ARM64 payload gained binaries that are not ordinary ARM64:" >&2
	sed 's/^/  /' <"$tmp.unlisted.net" >&2
	echo >&2
	echo "Make them ARM64. The seed in $baseline_file is immutable evidence of" >&2
	echo "what was already emulated and cannot be extended; only an" >&2
	echo "architecture-neutral binary may be added to $exceptions_file, with a" >&2
	echo "reason." >&2
	status=1
fi

echo "Inspected $candidate_count binaries: $(($candidate_count - $observed_count)) ordinary ARM64," \
	"$observed_count not." >&2
echo "The seed records $SEED_ENTRIES emulated binaries." >&2

if test -s "$tmp.gone.net"
then
	removed=$(($(wc -l <"$tmp.gone.net")))
	echo "$removed of them are no longer shipped, or are now ARM64:" >&2
	sed 's/^/  /' <"$tmp.gone.net" >&2
fi

exit $status
