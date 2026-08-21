#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the ARM64 dos2unix directory"

package=mingw-w64-clang-aarch64-dos2unix-7.5.6-1-any.pkg.tar.zst
package_url=https://github.com/crutkas/MINGW-packages/releases/download/arm64-dos2unix-7.5.6-1/$package
package_path="$thisdir/$package"
package_sha256=a36a9310b4cb41df8e748744653b998dfe0b8d211ab150c3e421582441b6a6f8
pacman_name=mingw-w64-clang-aarch64-dos2unix
pacman_version=7.5.6-1
package_dir_win="$(cd "$thisdir" && pwd -W)" ||
die "Could not determine Windows path for ARM64 dos2unix directory"
package_path_win="$package_dir_win\\$package"
package_tmp_win="$package_dir_win\\.$package.$$"
git_exe='C:\Program Files\Git\bin\git.exe'
curl_exe='C:\Program Files\Git\mingw64\bin\curl.exe'
sha256sum_exe='C:\Program Files\Git\usr\bin\sha256sum.exe'
pwsh_exe='C:\Program Files\PowerShell\7\pwsh.exe'

cmd.exe /c "\"$curl_exe\" --version" >/dev/null 2>&1 ||
die "Could not find curl"
cmd.exe /c "\"$sha256sum_exe\" --version" >/dev/null 2>&1 ||
die "Could not find sha256sum"
"$pwsh_exe" -NoLogo -NoProfile -Command '$null = $PSVersionTable.PSVersion' >/dev/null 2>&1 ||
die "Could not find pwsh"
cmd.exe /c "\"$git_exe\" --exec-path" >/dev/null 2>&1 ||
die "Could not find git"

download_package () {
	cmd.exe /c "\"$curl_exe\" -Lfo \"$package_tmp_win\" \"$package_url\""
}

hash_file () {
	"$pwsh_exe" -NoLogo -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '$1').Hash.ToLowerInvariant()"
}

if test -f "$package_path"
then
	actual="$(hash_file "$package_path_win")" ||
	die "Could not hash $package_path"
else
	actual=
fi

if test "$package_sha256" != "$actual"
then
	download_package ||
	die "Could not download ARM64 dos2unix package: $package_path"
	actual="$(hash_file "$package_tmp_win")" ||
	die "Could not hash $package_tmp_win"
	test "$package_sha256" = "$actual" ||
	die "Unexpected SHA-256 for $package: $actual"
	"$pwsh_exe" -NoLogo -NoProfile -Command "Move-Item -LiteralPath '$package_tmp_win' -Destination '$package_path_win' -Force" ||
	die "Could not publish ARM64 dos2unix package"
fi

actual="$(hash_file "$package_path_win")" ||
die "Could not hash $package_path"
test "$package_sha256" = "$actual" ||
die "Unexpected SHA-256 for $package: $actual"

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
