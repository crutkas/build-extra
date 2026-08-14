#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
before=
after=
scanner=
for arg
do
	case "$arg" in
	--before=*) before=${arg#*=};;
	--after=*) after=${arg#*=};;
	--scanner=*) scanner=${arg#*=};;
	*) die "Unknown option: $arg";;
	esac
done
test -n "$before" && test -n "$after" && test -n "$scanner" ||
die "Usage: $0 --before=<root> --after=<root> --scanner=<pe-imports.ps1>"

before="$(cd "$before" && pwd)" ||
die "Could not resolve the before root"
after="$(cd "$after" && pwd)" ||
die "Could not resolve the after root"
scanner="$(cd "${scanner%/*}" && pwd)/${scanner##*/}" ||
die "Could not resolve the scanner"
test -f "$scanner" ||
die "Missing scanner: $scanner"

scanner_hash=$(sha256sum "$scanner") &&
scanner_hash=${scanner_hash%% *} ||
die "Could not hash $scanner"
test 30adb26e7a4df9946a1c7b145e6613f3efb116745ad09a0978f89cb592932d84 = \
	"$scanner_hash" ||
die "The scanner does not match crutkas/build-extra#1 at 9e8e3eb"

tmp=${TMPDIR:-/tmp}/arm64-busybox-architecture.$$
mkdir -p "$tmp" ||
die "Could not create $tmp"
trap 'rm -rf "$tmp"' EXIT

GFW_ARM64_BUSYBOX=0 ARCH=aarch64 INCLUDE_GIT_UPDATE=1 \
	"$before/git-cmd.exe" --command=usr\\bin\\sh.exe -l \
	"$thisdir/../make-file-list.sh" >"$tmp/before.files" ||
die "Could not generate the comparison file list"
ARCH=aarch64 INCLUDE_GIT_UPDATE=1 \
	"$after/git-cmd.exe" --command=usr\\bin\\sh.exe -l \
	"$thisdir/../make-file-list.sh" >"$tmp/after.files" ||
die "Could not generate the BusyBox file list"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -aw "$scanner")" \
	-ArchitectureOnly -Root "$(cygpath -aw "$before")" \
	-FileList "$(cygpath -aw "$tmp/before.files")" |
	sort >"$tmp/before.tsv" ||
die "Could not scan the comparison payload"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -aw "$scanner")" \
	-ArchitectureOnly -Root "$(cygpath -aw "$after")" \
	-FileList "$(cygpath -aw "$tmp/after.files")" |
	sort >"$tmp/after.tsv" ||
die "Could not scan the BusyBox payload"

replaced=0
while IFS= read -r path
do
	grep -Fqx "$path	x64	0x8664" "$tmp/before.tsv" ||
	die "$path was not x64 in the comparison payload"
	grep -Fqx "$path	arm64	0xAA64" "$tmp/after.tsv" ||
	die "$path is not ARM64 in the BusyBox payload"
	replaced=$((replaced + 1))
done <"$thisdir/../arm64-busybox/default-replacements.txt"
test 59 = "$replaced" ||
die "Expected 59 default replacements, checked $replaced"

awk -F '	' '$2 != "arm64" && $2 != "anycpu" { print $1 "\t" $2 }' \
	"$tmp/before.tsv" | sort -u >"$tmp/before.foreign"
awk -F '	' '$2 != "arm64" && $2 != "anycpu" { print $1 "\t" $2 }' \
	"$tmp/after.tsv" | sort -u >"$tmp/after.foreign"
comm -13 "$tmp/before.foreign" "$tmp/after.foreign" >"$tmp/new.foreign"
test ! -s "$tmp/new.foreign" || {
	cat "$tmp/new.foreign" >&2
	die "The BusyBox payload introduced foreign-architecture paths"
}

count () {
	awk -F '	' -v architecture="$2" \
		'$2 == architecture { count++ } END { print count + 0 }' "$1"
}

payload_size () {
	root=$1
	list=$2
	total=0
	while IFS= read -r path
	do
		test -f "$root/$path" || continue
		size=$(wc -c <"$root/$path") ||
		die "Could not measure $root/$path"
		total=$((total + size))
	done <"$list"
	echo "$total"
}

before_x64=$(count "$tmp/before.tsv" x64)
before_arm64=$(count "$tmp/before.tsv" arm64)
before_x86=$(count "$tmp/before.tsv" x86)
before_anycpu=$(count "$tmp/before.tsv" anycpu)
after_x64=$(count "$tmp/after.tsv" x64)
after_arm64=$(count "$tmp/after.tsv" arm64)
after_x86=$(count "$tmp/after.tsv" x86)
after_anycpu=$(count "$tmp/after.tsv" anycpu)
before_size=$(payload_size "$before" "$tmp/before.files")
after_size=$(payload_size "$after" "$tmp/after.files")

report="$thisdir/../arm64-busybox-architecture-report.txt"
cat >"$report" <<-EOF
	scanner=crutkas/build-extra#1@9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19
	default_replacements=$replaced
	before_x64=$before_x64
	after_x64=$after_x64
	x64_delta=$((after_x64 - before_x64))
	before_arm64=$before_arm64
	after_arm64=$after_arm64
	arm64_delta=$((after_arm64 - before_arm64))
	before_x86=$before_x86
	after_x86=$after_x86
	before_anycpu=$before_anycpu
	after_anycpu=$after_anycpu
	before_payload_bytes=$before_size
	after_payload_bytes=$after_size
	payload_delta_bytes=$((after_size - before_size))
	new_foreign_architecture_paths=0
	EOF

cat "$report"
