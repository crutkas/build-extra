#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

case "${GFW_ARM64_BUSYBOX:-1}" in
0) exit 0;;
1) ;;
*) die "GFW_ARM64_BUSYBOX must be 0 or 1";;
esac

case "${GFW_EXPERIMENTAL_ARM64_BUSYBOX:-0}" in
0) experimental=;;
1) experimental=t;;
*) die "GFW_EXPERIMENTAL_ARM64_BUSYBOX must be 0 or 1";;
esac

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the ARM64 BusyBox directory"
package=mingw-w64-clang-aarch64-busybox-1.38.0.git.e7299058-1-any.pkg.tar.zst
package_path="$thisdir/$package"
package_sha256=93c5bc40010b58db0de29bd4eac3b87fa48d6c0e140c620208b1cd3d6722b499
busybox_sha256=afe7768285d5bd415fc2440a74bdf6e3c828cd1aca8dd2b36fcdf9b4cc8054bf
shim_sha256=49ee6f040be4cb42cb5c7ef3dd5e25c8f431bcfbe1d2587d75c55967bbfe8959
pacman_name=mingw-w64-clang-aarch64-busybox
pacman_version=1.38.0.git.e7299058-1
busybox=/clangarm64/bin/busybox.exe
shim_path="$thisdir/busybox-shim.exe"

case "${GFW_ARM64_BUSYBOX_FORCE_COPY:-0}" in
0|1) ;;
*) die "GFW_ARM64_BUSYBOX_FORCE_COPY must be 0 or 1";;
esac

test -f "$package_path" ||
die "Missing ARM64 BusyBox package: $package_path"
actual="$(sha256sum "$package_path")" &&
actual="${actual%% *}" ||
die "Could not hash $package_path"
test "$package_sha256" = "$actual" ||
die "Unexpected SHA-256 for $package: $actual"

installed="$(pacman -Q "$pacman_name" 2>/dev/null)" || installed=
actual=
test ! -f "$busybox" ||
actual="$(sha256sum "$busybox")" &&
actual="${actual%% *}"
if test "$pacman_name $pacman_version" != "$installed" ||
	test "$busybox_sha256" != "$actual"
then
	pacman -U --noconfirm --overwrite '*' "$package_path" ||
	die "Could not install the exact ARM64 BusyBox package"
fi

actual="$(sha256sum "$busybox")" &&
actual="${actual%% *}" ||
die "Could not hash $busybox"
test "$busybox_sha256" = "$actual" ||
die "Installed busybox.exe has unexpected SHA-256: $actual"
actual="$(sha256sum "$shim_path")" &&
actual="${actual%% *}" ||
die "Could not hash $shim_path"
test "$shim_sha256" = "$actual" ||
die "busybox-shim.exe has unexpected SHA-256: $actual"

root_win="$(cygpath -aw /)" &&
busybox_win="$(cygpath -aw "$busybox")" &&
shim_win="$(cygpath -aw "$shim_path")" &&
materialize_win="$(cygpath -aw "$thisdir/materialize.ps1")" &&
default_win="$(cygpath -aw "$thisdir/default-replacements.txt")" &&
experimental_win="$(cygpath -aw "$thisdir/experimental-replacements.txt")" &&
retained_win="$(cygpath -aw "$thisdir/retained-paths.tsv")" ||
die "Could not resolve ARM64 BusyBox materialization paths"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$materialize_win" \
	-Root "$root_win" \
	-BusyBox "$busybox_win" \
	-Shim "$shim_win" \
	-DefaultList "$default_win" \
	-ExperimentalList "$experimental_win" \
	-RetainedList "$retained_win" \
	-Experimental "$(test -n "$experimental" && echo 1 || echo 0)" \
	-ForceCopy "${GFW_ARM64_BUSYBOX_FORCE_COPY:-0}" ||
die "Could not materialize ARM64 BusyBox aliases"
