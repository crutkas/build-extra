#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the script directory"

package_name=mingw-w64-clang-aarch64-win32-openssh-client
package_version=10.0.0.0-1
archive=mingw-w64-clang-aarch64-win32-openssh-client-10.0.0.0-1-any.pkg.tar.zst
archive_sha256=48e679a7e5a10ee5ba43c79a8cabc535ce7daddf693c7800caa39c2cd762a6a2
archive_url=https://github.com/crutkas/build-extra/releases/download/win32-openssh-client-10.0.0.0-1-arm64/$archive
package_revision=2fc36f0cd70af02b0d602f2bf2380b53ea4c78eb
files=$thisdir/arm64-openssh-client-files.txt
msys_files=$thisdir/arm64-openssh-msys-files.txt

root=/
package=
verify_only=
while test $# -gt 0
do
	case "$1" in
	--root=*) root=${1#*=};;
	--package=*) package=${1#*=};;
	--verify-only) verify_only=t;;
	--print-package-name) echo "$package_name"; exit 0;;
	--print-package-version) echo "$package_version"; exit 0;;
	--print-package-files) sed 's/\r$//' "$files"; exit $?;;
	--print-msys-files) sed 's/\r$//' "$msys_files"; exit $?;;
	*) die "Unknown option: $1";;
	esac
	shift
done

test -f "$files" || die "Package file manifest is missing: $files"
test -f "$msys_files" || die "MSYS OpenSSH file manifest is missing: $msys_files"

test -n "$package" ||
package=${TMPDIR:-/tmp}/$archive
case "$package" in
[A-Za-z]:[\\/]*)
	package="$(cygpath -au "$package")" ||
	die "Could not normalize the package path"
	;;
esac

verify_archive () {
	actual=$(sha256sum <"$package" | sed 's/ .*//') ||
	{
		echo "Could not hash $package" >&2
		return 1
	}
	if test "$archive_sha256" != "$actual"
	then
		echo "Unexpected SHA-256 for $package: $actual" >&2
		return 1
	fi
}

if test -f "$package"
then
	if ! verify_archive
	then
		test -n "$verify_only" &&
		exit 1
		rm -f "$package" ||
		die "Could not remove the rejected package cache: $package"
	fi
fi

if ! test -f "$package"
then
	test -z "$verify_only" ||
	die "Package does not exist: $package"
	tmp_package=$package.tmp.$$
	trap 'rm -f "$tmp_package"' EXIT
	curl -fL --retry 3 -o "$tmp_package" "$archive_url" ||
	die "Could not download $archive_url"
	mv "$tmp_package" "$package" ||
	die "Could not store $package"
	trap - EXIT
	verify_archive ||
	die "Downloaded package failed SHA-256 verification"
fi
verify_archive ||
die "Package failed SHA-256 verification before extraction"

tmp=${TMPDIR:-/tmp}/arm64-openssh.$$
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/root" ||
die "Could not create $tmp"

tar_cmd=tar
if ! type -p zstd >/dev/null 2>&1
then
	windows_tar="$(cygpath -au "${SYSTEMROOT:-$WINDIR}/System32/tar.exe")" ||
	die "Could not locate the Windows tar executable"
	test -x "$windows_tar" ||
	die "Neither zstd nor the Windows tar executable is available"
	tar_cmd=$windows_tar
fi

"$tar_cmd" -tf "$package" | tr -d '\r' >"$tmp/archive-files" ||
die "Could not list $package"
grep -Eq '(^/|(^|/)\.\.(/|$))' "$tmp/archive-files" &&
die "Package contains an unsafe path"
sed -e 's|^\./||' -e '/\/$/d' \
	-e '/^\.\(BUILDINFO\|MTREE\|PKGINFO\)$/d' \
	<"$tmp/archive-files" |
LC_ALL=C sort -u >"$tmp/package-files" &&
sed 's/\r$//' "$files" >"$tmp/expected-package-files" &&
cmp "$tmp/expected-package-files" "$tmp/package-files" ||
die "Package contents do not match $files"

"$tar_cmd" -xOf "$package" .PKGINFO >"$tmp/PKGINFO" ||
die "Could not read .PKGINFO"
grep -qx "pkgname = $package_name" "$tmp/PKGINFO" &&
grep -qx "pkgver = $package_version" "$tmp/PKGINFO" &&
grep -qx "conflict = openssh" "$tmp/PKGINFO" &&
! grep -q '^provides = openssh$' "$tmp/PKGINFO" &&
! grep -q '^replaces = openssh$' "$tmp/PKGINFO" ||
die "Unexpected package metadata"

"$tar_cmd" -xf "$package" -C "$tmp/root" ||
die "Could not extract $package"
(cd "$tmp/root" &&
	sha256sum -c usr/share/doc/win32-openssh-client/package-files.sha256) ||
die "Package payload checksums do not match"

test -z "$verify_only" || exit 0

test -d "$root" || die "Payload root does not exist: $root"
root_prefix=${root%/}
pacman=${PACMAN:-pacman}
run_pacman () {
	if test / = "$root"
	then
		"$pacman" "$@"
	else
		"$pacman" --root "$root" "$@"
	fi
}

if test "$package_name $package_version" != \
	"$(run_pacman -Q "$package_name" 2>/dev/null)"
then
	owner_files=
	for candidate in "$root_prefix"/var/lib/pacman/local/openssh-[0-9]*/files
	do
		test -f "$candidate" || continue
		owner_files=$candidate
		break
	done
	test -n "$owner_files" ||
	die "Could not find the installed MSYS openssh ownership database below $root"

	sed 's/\r$//' "$msys_files" >"$tmp/msys-files"
	while IFS= read -r path
	do
		grep -Fqx "$path" "$owner_files" ||
		die "MSYS openssh does not own $path"
	done <"$tmp/msys-files"

	# A declared dependent must block the substitution instead of being
	# bypassed with pacman -Rdd.
	run_pacman -R --noconfirm openssh ||
	die "Could not remove MSYS openssh through its declared dependencies"
	run_pacman -U --noconfirm "$package" ||
	die "Could not install $package_name"
fi

(cd "$root" &&
	sha256sum -c usr/share/doc/win32-openssh-client/package-files.sha256) ||
die "Installed native OpenSSH payload checksums do not match"
test ! -e "$root_prefix/usr/lib/ssh/ssh-keysign.exe" ||
die "Unsupported ssh-keysign.exe is still installed"

native_owner_files="$root_prefix/var/lib/pacman/local/$package_name-$package_version/files"
test -f "$native_owner_files" ||
die "Could not find the installed $package_name ownership database"
while IFS= read -r path
do
	grep -Fqx "$path" "$native_owner_files" ||
	die "$package_name does not own $path"
done <"$tmp/expected-package-files"

mkdir -p "$root_prefix/etc" &&
cat >"$root_prefix/etc/arm64-win32-openssh" <<-EOF ||
package=$package_name
version=$package_version
sha256=$archive_sha256
source-revision=$package_revision
EOF
die "Could not record the native OpenSSH package provenance"
