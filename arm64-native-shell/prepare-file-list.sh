#!/bin/sh

cleanup_stage=
cleanup_work=
cleanup_baseline=
cleanup_archive=
baseline=
baseline_archive=

cleanup () {
	test -z "$cleanup_stage" ||
	rm -rf "$cleanup_stage"
	test -z "$cleanup_work" ||
	rm -rf "$cleanup_work"
	test -z "$cleanup_baseline" ||
	rm -f "$cleanup_baseline"
	test -z "$cleanup_archive" ||
	rm -f "$cleanup_archive"
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

die () {
	echo "$*" >&2
	exit 1
}

variant=$1
stage=$2
case "$variant" in
installer|portable|mingit) ;;
*) die "Unknown native ARM64 shell artifact variant: $variant";;
esac

if test aarch64 != "$ARCH" ||
	{
		test 1 != "${GFW_ARM64_NATIVE_SHELL:-0}" &&
		test preview != "${GFW_ARM64_NATIVE_SHELL:-0}"
	}
then
	cat
	exit
fi

test -n "$GFW_ARM64_NATIVE_SHELL_WORK" ||
die "GFW_ARM64_NATIVE_SHELL_WORK is required"
test -n "$GFW_ARM64_NATIVE_SHELL_PROVENANCE" ||
die "GFW_ARM64_NATIVE_SHELL_PROVENANCE is required"
test -n "$GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST" ||
die "GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST is required"
test -n "$GFW_ARM64_NATIVE_SHELL_REPORT" ||
die "GFW_ARM64_NATIVE_SHELL_REPORT is required"

baseline="$stage.baseline-list"
baseline_archive="$stage.baseline.tar"
test ! -e "$stage" && test ! -e "$baseline" && test ! -e "$baseline_archive" ||
die "Native ARM64 shell staging paths already exist: $stage"
cleanup_baseline=$baseline
cat >"$baseline" ||
die "Could not record the baseline artifact file list"

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the native ARM64 shell directory"
repository="$(git -C "$thisdir" rev-parse --show-toplevel)" &&
git -C "$repository" diff --quiet -- \
	arm64-native-shell/install.ps1 \
	arm64-native-shell/NativeShell.psm1 &&
git -C "$repository" diff --cached --quiet HEAD -- \
	arm64-native-shell/install.ps1 \
	arm64-native-shell/NativeShell.psm1 &&
GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT="$(
	git -C "$repository" rev-parse HEAD
)" ||
die "Native ARM64 shell assembler files must match the exact HEAD commit"
export GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT
list="$(ARCH=$ARCH "$thisdir/filter-file-list.sh" "$variant" <"$baseline")" ||
die "Could not reconcile the native ARM64 shell file list"

cleanup_stage=$stage
mkdir -p "$stage" ||
die "Could not create native ARM64 shell staging root"
cleanup_archive=$baseline_archive
(cd / && tar -cf "$baseline_archive" -T "$baseline") ||
die "Could not archive the baseline artifact payload"
tar -xf "$baseline_archive" -C "$stage" ||
die "Could not stage the baseline artifact payload"
rm "$baseline" ||
die "Could not remove the baseline artifact file list"
cleanup_baseline=
rm "$baseline_archive" ||
die "Could not remove the baseline artifact archive"
cleanup_archive=

suffix="$variant-$$"
GFW_ARM64_NATIVE_SHELL_ROOT="$stage"
GFW_ARM64_NATIVE_SHELL_WORK="$GFW_ARM64_NATIVE_SHELL_WORK-$suffix"
cleanup_work=$GFW_ARM64_NATIVE_SHELL_WORK
GFW_ARM64_NATIVE_SHELL_PROVENANCE="$GFW_ARM64_NATIVE_SHELL_PROVENANCE-$suffix"
GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST="$GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST-$suffix"
GFW_ARM64_NATIVE_SHELL_REPORT="$GFW_ARM64_NATIVE_SHELL_REPORT-$suffix"
export GFW_ARM64_NATIVE_SHELL_ROOT
export GFW_ARM64_NATIVE_SHELL_WORK
export GFW_ARM64_NATIVE_SHELL_PROVENANCE
export GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST
export GFW_ARM64_NATIVE_SHELL_REPORT

ARCH=$ARCH "$thisdir/install.sh" --materialize ||
die "Could not materialize the native ARM64 shell closure"
list="$(
	printf '%s\n%s\n%s\n' \
		"$list" \
		"preview-evidence/source-lock.json" \
		"preview-evidence/base-tree-manifest.v1.json" \
		"preview-evidence/bundle-lock.v1.json" |
	LC_ALL=C sort -u
)" ||
die "Could not add native ARM64 shell evidence to the artifact file list"
rm -rf "$cleanup_work" ||
die "Could not remove the native ARM64 shell work root"
cleanup_work=
cleanup_stage=
printf '%s\n' "$list"
