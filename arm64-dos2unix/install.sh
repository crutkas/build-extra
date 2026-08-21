#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

pacman_name=mingw-w64-clang-aarch64-dos2unix

installed="$(pacman -Q "$pacman_name" 2>/dev/null)" || installed=
if test "$installed" != "$pacman_name 7.5.6-1"
then
	pacman -S --noconfirm --overwrite '*' "$pacman_name" ||
	die "Could not install the native ARM64 dos2unix package"
	installed="$(pacman -Q "$pacman_name" 2>/dev/null)" || installed=
fi
test "$installed" = "$pacman_name 7.5.6-1" ||
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
