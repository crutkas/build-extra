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
pacman_name=mingw-w64-clang-aarch64-busybox
pacman_version=1.38.0.git.e7299058-1
busybox=/clangarm64/bin/busybox.exe

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

mkdir -p /etc ||
die "Could not create /etc"
report=/etc/arm64-busybox-replacements.tsv
retained=/etc/arm64-busybox-retained-paths.tsv
aliases=/etc/arm64-busybox-aliases.txt
printf 'path\tapplet\tselection\n' >"$report" ||
die "Could not initialize $report"
: >"$aliases" ||
die "Could not initialize $aliases"

materialize () {
	selection=$1
	list=$2

	while IFS= read -r path
	do
		test -n "$path" || continue
		mkdir -p "/${path%/*}" &&
		{
			rm -f "/$path" &&
			ln "$busybox" "/$path"
		} ||
		cp "$busybox" "/$path" ||
		die "Could not materialize BusyBox alias /$path"
		applet=${path##*/}
		applet=${applet%.exe}
		printf '%s\t%s\t%s\n' "$path" "$applet" "$selection" >>"$report" ||
		die "Could not update $report"
		printf '%s.exe\n' "$applet" >>"$aliases" ||
		die "Could not update $aliases"
	done <"$list"
}

materialize default "$thisdir/default-replacements.txt"
if test -n "$experimental"
then
	materialize experimental "$thisdir/experimental-replacements.txt"
fi

cp "$thisdir/retained-paths.tsv" "$retained" ||
die "Could not install the retained-path report"
if test -n "$experimental"
then
	tmp="$retained".tmp
	cp "$retained" "$tmp" ||
	die "Could not prepare the experimental retained-path report"
	while IFS= read -r path
	do
		grep -Fv "$path	" "$tmp" >"$retained" &&
		mv "$retained" "$tmp" ||
		die "Could not remove $path from the retained-path report"
	done <"$thisdir/experimental-replacements.txt"
	mv "$tmp" "$retained" ||
	die "Could not finalize the experimental retained-path report"
fi
