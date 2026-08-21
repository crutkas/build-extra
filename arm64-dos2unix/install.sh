#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the ARM64 dos2unix directory"

cache_dir="$thisdir/cached-files"
package=mingw-w64-clang-aarch64-dos2unix-7.5.6-1-any.pkg.tar.zst
package_url=https://github.com/crutkas/MINGW-packages/releases/download/arm64-dos2unix-7.5.6-1/$package
package_path="$cache_dir/$package"
package_sha256=a36a9310b4cb41df8e748744653b998dfe0b8d211ab150c3e421582441b6a6f8
pacman_name=mingw-w64-clang-aarch64-dos2unix
pacman_version=7.5.6-1

download_package () {
	mkdir -p "$cache_dir" &&
	curl -Lfo "$package_path" "$package_url"
}

test -f "$package_path" ||
download_package ||
die "Could not download ARM64 dos2unix package: $package_path"
actual="$(sha256sum "$package_path")" &&
actual="${actual%% *}" ||
die "Could not hash $package_path"
if test "$package_sha256" != "$actual"
then
	rm -f "$package_path" &&
	download_package ||
	die "Could not download ARM64 dos2unix package: $package_path"
	actual="$(sha256sum "$package_path")" &&
	actual="${actual%% *}" ||
	die "Could not hash $package_path"
	test "$package_sha256" = "$actual" ||
	die "Unexpected SHA-256 for $package: $actual"
fi

installed="$(pacman -Q "$pacman_name" 2>/dev/null)" || installed=
if test "$installed" != "$pacman_name $pacman_version"
then
	pacman -U --noconfirm --overwrite '*' "$package_path" ||
	die "Could not install the native ARM64 dos2unix package"
	installed="$(pacman -Q "$pacman_name" 2>/dev/null)" || installed=
fi
test "$installed" = "$pacman_name $pacman_version" ||
die "Unexpected native ARM64 dos2unix package version: $installed"

for tool in d2u dos2unix mac2unix u2d unix2dos unix2mac
do
	src="/clangarm64/bin/$tool.exe"
	dst="/usr/bin/$tool.exe"
	test -f "$src" ||
	die "Missing native ARM64 dos2unix binary: $src"
	mkdir -p /usr/bin ||
	die "Could not create /usr/bin"
	rm -f "$dst" ||
	die "Could not replace $dst"
	if ! ln "$src" "$dst" 2>/dev/null
	then
		cp "$src" "$dst" ||
		die "Could not materialize $dst from $src"
	fi
done

for tool in d2u dos2unix mac2unix u2d unix2dos unix2mac
do
	rm -f "/clangarm64/bin/$tool.exe" ||
	die "Could not remove /clangarm64/bin/$tool.exe"
done
