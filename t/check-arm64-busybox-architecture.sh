#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
release_manifest=
leaf_root=
leaf_source=
busybox_root=
busybox_source=
combined_root=
combined_source=
scanner=
for arg
do
	case "$arg" in
	--release-manifest=*) release_manifest=${arg#*=};;
	--leaf-root=*) leaf_root=${arg#*=};;
	--leaf-source=*) leaf_source=${arg#*=};;
	--busybox-root=*) busybox_root=${arg#*=};;
	--busybox-source=*) busybox_source=${arg#*=};;
	--combined-root=*) combined_root=${arg#*=};;
	--combined-source=*) combined_source=${arg#*=};;
	--scanner=*) scanner=${arg#*=};;
	*) die "Unknown option: $arg";;
	esac
done
test -n "$release_manifest" &&
test -n "$leaf_root" && test -n "$leaf_source" &&
test -n "$busybox_root" && test -n "$busybox_source" &&
test -n "$combined_root" && test -n "$combined_source" &&
test -n "$scanner" ||
die "Usage: $0 --release-manifest=<tsv> --leaf-root=<root> --leaf-source=<source> --busybox-root=<root> --busybox-source=<source> --combined-root=<root> --combined-source=<source> --scanner=<pe-imports.ps1>"

resolve_file () {
	case "$1" in
	*/*) echo "$(cd "${1%/*}" && pwd)/${1##*/}";;
	*) echo "$PWD/$1";;
	esac
}

release_manifest="$(resolve_file "$release_manifest")" ||
die "Could not resolve the release manifest"
scanner="$(resolve_file "$scanner")" ||
die "Could not resolve the scanner"
for variable in leaf_root leaf_source busybox_root busybox_source \
	combined_root combined_source
do
	eval "value=\$$variable"
	value="$(cd "$value" && pwd)" ||
	die "Could not resolve $variable"
	eval "$variable=\$value"
done
test -f "$release_manifest" ||
die "Missing release manifest: $release_manifest"
test -f "$scanner" ||
die "Missing scanner: $scanner"

scanner_hash=$(sha256sum "$scanner") &&
scanner_hash=${scanner_hash%% *} ||
die "Could not hash $scanner"
test 30adb26e7a4df9946a1c7b145e6613f3efb116745ad09a0978f89cb592932d84 = \
	"$scanner_hash" ||
die "The scanner does not match crutkas/build-extra#1 at 9e8e3eb"
release_manifest_hash=$(sha256sum "$release_manifest") &&
release_manifest_hash=${release_manifest_hash%% *} ||
die "Could not hash $release_manifest"
test ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a = \
	"$release_manifest_hash" ||
die "The release manifest does not match crutkas/build-extra#1"

tmp=${TMPDIR:-/tmp}/arm64-combined-architecture.$$
mkdir -p "$tmp" ||
die "Could not create $tmp"
trap 'rm -rf "$tmp"' EXIT
awk -F '	' 'NR > 1 { print $1 "\t" $2 "\t" $3 }' \
	"$release_manifest" | sort >"$tmp/release.tsv" ||
die "Could not normalize the release manifest"

scan () {
	label=$1
	root=$2
	source=$3
	ARCH=aarch64 INCLUDE_GIT_UPDATE=1 \
		"$root/git-cmd.exe" --command=usr\\bin\\sh.exe -l \
		"$source/make-file-list.sh" >"$tmp/$label.files" ||
	die "Could not generate the $label file list"
	powershell.exe -NoProfile -ExecutionPolicy Bypass \
		-File "$(cygpath -aw "$scanner")" \
		-ArchitectureOnly -Root "$(cygpath -aw "$root")" \
		-FileList "$(cygpath -aw "$tmp/$label.files")" |
		sort >"$tmp/$label.tsv" ||
	die "Could not scan the $label payload"
}

scan current-leaf "$leaf_root" "$leaf_source"
scan current-busybox "$busybox_root" "$busybox_source"
scan current-combined "$combined_root" "$combined_source"

assert_machines () {
	label=$1
	awk -F '	' \
		'($2 == "arm64" && $3 != "0xAA64") ||
		 ($2 == "x64" && $3 != "0x8664") ||
		 (($2 == "x86" || $2 == "anycpu") && $3 != "0x014C") {
			print
			bad = 1
		}
		END { exit bad }' "$tmp/$label.tsv" ||
	die "$label contains an unexpected PE machine"
}

assert_machines release
assert_machines current-leaf
assert_machines current-busybox
assert_machines current-combined

added_or_replaced () {
	before=$1
	after=$2
	output=$3
	awk -F '	' 'NR == FNR {
			architecture[$1] = $2
			machine[$1] = $3
			next
		}
		!($1 in architecture) ||
		architecture[$1] != $2 ||
		machine[$1] != $3' \
		"$tmp/$before.tsv" "$tmp/$after.tsv" >"$output"
	test ! -s "$output" ||
	awk -F '	' '$2 != "arm64" || $3 != "0xAA64" {
			print
			bad = 1
		}
		END { exit bad }' "$output" ||
	die "$after introduced a non-ARM64 PE"
}

added_or_replaced current-leaf current-busybox "$tmp/busybox.changed"
added_or_replaced current-busybox current-combined "$tmp/combined.changed"

x64_to_arm64 () {
	before=$1
	after=$2
	output=$3
	awk -F '	' 'NR == FNR {
			architecture[$1] = $2
			next
		}
		architecture[$1] == "x64" && $2 == "arm64"' \
		"$tmp/$before.tsv" "$tmp/$after.tsv" >"$output"
}

x64_to_arm64 current-leaf current-busybox "$tmp/busybox.replaced"
x64_to_arm64 current-busybox current-combined "$tmp/openssh.replaced"
cut -f1 "$tmp/busybox.replaced" | sort >"$tmp/busybox.paths"
sort "$thisdir/../arm64-busybox/default-replacements.txt" >"$tmp/busybox.expected"
diff -u "$tmp/busybox.expected" "$tmp/busybox.paths" ||
die "The BusyBox x64-to-ARM64 path set is incomplete"
busybox_replaced=$(wc -l <"$tmp/busybox.replaced")
openssh_replaced=$(wc -l <"$tmp/openssh.replaced")
test 59 = "$busybox_replaced" ||
die "Expected 59 BusyBox x64-to-ARM64 paths, found $busybox_replaced"
test 11 = "$openssh_replaced" ||
die "Expected 11 OpenSSH x64-to-ARM64 paths, found $openssh_replaced"

manifest_row () {
	manifest=$1
	path=$2
	architecture=$3
	row="$(awk -F '	' -v path="$path" -v architecture="$architecture" \
		'$1 == path && $2 == architecture { print }' "$manifest")"
	test -n "$row" ||
	die "Missing $architecture scanner row for $path in ${manifest##*/}"
	test 1 = "$(printf '%s\n' "$row" | wc -l)" ||
	die "Found multiple $architecture scanner rows for $path in ${manifest##*/}"
	printf '%s\n' "$row"
}

remove_manifest_path () {
	manifest=$1
	path=$2
	awk -F '	' -v path="$path" '$1 != path' "$manifest" >"$manifest.new" &&
	mv "$manifest.new" "$manifest" ||
	die "Could not remove $path from ${manifest##*/}"
}

cp "$tmp/release.tsv" "$tmp/leaf.tsv" ||
die "Could not initialize the leaf manifest"
cat >"$tmp/leaf-x64.paths" <<-\EOF
	usr/bin/bunzip2.exe
	usr/bin/bzcat.exe
	usr/bin/bzip2.exe
	usr/bin/bzip2recover.exe
	usr/bin/nettle-hash.exe
	usr/bin/nettle-lfib-stream.exe
	usr/bin/nettle-pbkdf2.exe
	usr/bin/p11-kit.exe
	usr/bin/pkcs1-conv.exe
	usr/bin/sexp-conv.exe
	usr/bin/trust.exe
	EOF
cat >"$tmp/leaf-arm64.paths" <<-\EOF
	clangarm64/bin/bunzip2.exe
	clangarm64/bin/bzcat.exe
	clangarm64/bin/bzip2.exe
	clangarm64/bin/bzip2recover.exe
	clangarm64/bin/nettle-hash.exe
	clangarm64/bin/nettle-lfib-stream.exe
	clangarm64/bin/nettle-pbkdf2.exe
	clangarm64/bin/p11-kit.exe
	clangarm64/bin/pkcs1-conv.exe
	clangarm64/bin/sexp-conv.exe
	clangarm64/bin/trust.exe
	EOF
leaf_removed=0
while IFS= read -r path
do
	manifest_row "$tmp/leaf.tsv" "$path" x64 >/dev/null
	remove_manifest_path "$tmp/leaf.tsv" "$path"
	leaf_removed=$((leaf_removed + 1))
done <"$tmp/leaf-x64.paths"
test 11 = "$leaf_removed" ||
die "Expected 11 leaf-tool x64 removals, found $leaf_removed"
leaf_added=0
while IFS= read -r path
do
	row="$(manifest_row "$tmp/current-leaf.tsv" "$path" arm64)"
	if ! awk -F '	' -v path="$path" '$1 == path { found = 1 } END { exit !found }' \
		"$tmp/leaf.tsv"
	then
		printf '%s\n' "$row" >>"$tmp/leaf.tsv" ||
		die "Could not add $path to the leaf manifest"
		leaf_added=$((leaf_added + 1))
	fi
done <"$tmp/leaf-arm64.paths"
test 3 = "$leaf_added" ||
die "Expected 3 leaf-tool ARM64 additions, found $leaf_added"
sort -o "$tmp/leaf.tsv" "$tmp/leaf.tsv"

cp "$tmp/leaf.tsv" "$tmp/busybox.tsv" ||
die "Could not initialize the BusyBox manifest"
while IFS= read -r path
do
	manifest_row "$tmp/busybox.tsv" "$path" x64 >/dev/null
	row="$(manifest_row "$tmp/current-busybox.tsv" "$path" arm64)"
	remove_manifest_path "$tmp/busybox.tsv" "$path"
	printf '%s\n' "$row" >>"$tmp/busybox.tsv" ||
	die "Could not add $path to the BusyBox manifest"
done <"$thisdir/../arm64-busybox/default-replacements.txt"
sort -o "$tmp/busybox.tsv" "$tmp/busybox.tsv"

cp "$tmp/busybox.tsv" "$tmp/combined.tsv" ||
die "Could not initialize the combined manifest"
while IFS='	' read -r path architecture machine
do
	manifest_row "$tmp/combined.tsv" "$path" x64 >/dev/null
	row="$(manifest_row "$tmp/current-combined.tsv" "$path" arm64)"
	remove_manifest_path "$tmp/combined.tsv" "$path"
	printf '%s\n' "$row" >>"$tmp/combined.tsv" ||
	die "Could not add $path to the combined manifest"
done <"$tmp/openssh.replaced"
sort -o "$tmp/combined.tsv" "$tmp/combined.tsv"

added_or_replaced release leaf "$tmp/leaf.changed"
added_or_replaced leaf busybox "$tmp/busybox.normalized.changed"
added_or_replaced busybox combined "$tmp/combined.normalized.changed"
for label in leaf busybox combined
do
	awk -F '	' '$2 != "arm64" && $2 != "anycpu" {
		print $1 "\t" $2
	}' "$tmp/$label.tsv" | sort -u >"$tmp/$label.foreign"
done
awk -F '	' '$2 != "arm64" && $2 != "anycpu" {
	print $1 "\t" $2
}' "$tmp/release.tsv" | sort -u >"$tmp/release.foreign"
for label in leaf busybox combined
do
	comm -13 "$tmp/release.foreign" "$tmp/$label.foreign" \
		>"$tmp/$label.new-foreign"
	test ! -s "$tmp/$label.new-foreign" || {
		cat "$tmp/$label.new-foreign" >&2
		die "$label introduced a foreign-architecture path"
	}
done

count () {
	awk -F '	' -v architecture="$2" \
		'$2 == architecture { count++ } END { print count + 0 }' "$1"
}

for label in release leaf busybox combined
do
	eval "${label}_x64=\$(count \"\$tmp/$label.tsv\" x64)"
	eval "${label}_arm64=\$(count \"\$tmp/$label.tsv\" arm64)"
	eval "${label}_x86=\$(count \"\$tmp/$label.tsv\" x86)"
	eval "${label}_anycpu=\$(count \"\$tmp/$label.tsv\" anycpu)"
done
test 432 = "$release_x64" ||
die "Expected the authoritative release baseline to contain 432 x64 PEs"
test -11 = "$((leaf_x64 - release_x64))" ||
die "The native leaf tools did not remove exactly 11 x64 PEs"
test -59 = "$((busybox_x64 - leaf_x64))" ||
die "BusyBox did not remove exactly 59 x64 PEs"
test -11 = "$((combined_x64 - busybox_x64))" ||
die "OpenSSH did not remove exactly 11 x64 PEs"
test 3 = "$((leaf_arm64 - release_arm64))" ||
die "The native leaf tools did not add exactly 3 ARM64 PEs"
test 59 = "$((busybox_arm64 - leaf_arm64))" ||
die "BusyBox did not add exactly 59 ARM64 PEs"
test 11 = "$((combined_arm64 - busybox_arm64))" ||
die "OpenSSH did not add exactly 11 ARM64 PEs"
test "$release_x86" = "$leaf_x86" &&
test "$release_x86" = "$busybox_x86" &&
test "$release_x86" = "$combined_x86" ||
die "The combined payload changed the x86 PE count"
test "$release_anycpu" = "$leaf_anycpu" &&
test "$release_anycpu" = "$busybox_anycpu" &&
test "$release_anycpu" = "$combined_anycpu" ||
die "The combined payload changed the CLR AnyCPU PE count"

report="$thisdir/../arm64-combined-architecture-report.txt"
{
	cat <<-EOF
	scanner=crutkas/build-extra#1@9e8e3eb929ae5c7fe8a2d899be2eefdc07356c19
	release_manifest_sha256=$release_manifest_hash
	release_x64=$release_x64
	release_arm64=$release_arm64
	release_x86=$release_x86
	release_clr_anycpu=$release_anycpu
	leaf_x64=$leaf_x64
	leaf_arm64=$leaf_arm64
	leaf_x86=$leaf_x86
	leaf_clr_anycpu=$leaf_anycpu
	busybox_x64=$busybox_x64
	busybox_arm64=$busybox_arm64
	busybox_x86=$busybox_x86
	busybox_clr_anycpu=$busybox_anycpu
	combined_x64=$combined_x64
	combined_arm64=$combined_arm64
	combined_x86=$combined_x86
	combined_clr_anycpu=$combined_anycpu
	leaf_x64_delta=$((leaf_x64 - release_x64))
	busybox_x64_delta=$((busybox_x64 - leaf_x64))
	openssh_x64_delta=$((combined_x64 - busybox_x64))
	combined_x64_delta=$((combined_x64 - release_x64))
	leaf_added_or_replaced_arm64_pes=$(wc -l <"$tmp/leaf.changed")
	busybox_added_or_replaced_arm64_pes=$(wc -l <"$tmp/busybox.normalized.changed")
	openssh_added_or_replaced_arm64_pes=$(wc -l <"$tmp/combined.normalized.changed")
	busybox_x64_to_arm64_paths=$busybox_replaced
	openssh_x64_to_arm64_paths=$openssh_replaced
	new_foreign_architecture_paths=0
	openssh_x64_to_arm64_path_list:
	EOF
	cut -f1 "$tmp/openssh.replaced" | sed 's/^/  /'
} >"$report"

cat "$report"
