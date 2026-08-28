#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

root="$(cd "$(dirname "$0")/.." && pwd)" ||
die "Could not determine the repository root"
tmp=${TMPDIR:-/tmp}/check-arm64-openssh-pacman.$$
mkdir -p "$tmp" ||
die "Could not create $tmp"
trap 'rm -rf "$tmp"' EXIT

grep -Fq 'OPENSSH_PACKAGE=mingw-w64-clang-aarch64-win32-openssh-client' \
	"$root/make-file-list.sh" &&
grep -Fq 'OPENSSH_PACKAGE=openssh' "$root/make-file-list.sh" &&
grep -Fq -- '--assume-installed "openssh=$openssh_version" "$package_path"' \
	"$root/please.sh" &&
grep -Fq '26f302a73a58395de8d7741077365d2e0f296343358a5f62bc5385ec8c04d2f8' \
	"$root/please.sh" &&
grep -Fq 'c97decf4acf026790b0989e0f08be8142b9f7ec2' "$root/please.sh" &&
grep -Fq 'pacman -Ql "$openssh_package"' "$root/installer/release.sh" &&
grep -Fq 'REMOVE_ARM64_OPENSSH_LEGACY_FILES' "$root/installer/install.iss" &&
grep -Fq "test /clangarm64 = '@@MINGW_PREFIX@@'" \
	"$root/git-extra/git-extra.install.in" &&
grep -Fq 'PubkeyAcceptedAlgorithms +rsa-sha2-512,rsa-sha2-256,ssh-rsa' \
	"$root/please.sh" &&
grep -Fq 'git ls-remote git@ssh.dev.azure.com:v3/git-for-windows/git/git main' \
	"$root/installer/run-checklist.sh" ||
die "The default package, provenance, cleanup, or Azure gate is not wired"

sed -n \
	'/^arm64_openssh_pacman_config=/,/^use_arm64_native_openssh ()/p' \
	"$root/please.sh" |
sed '$d' >"$tmp/helpers.sh" &&
. "$tmp/helpers.sh" ||
die "Could not load the ARM64 OpenSSH Pacman helpers"

fake_root=$tmp/root
pacman_private=$tmp/private
package=mingw-w64-clang-aarch64-win32-openssh-client
version=10.0.0.0-2
package_path=$fake_root/tmp/$package-$version-any.pkg.tar.zst
mkdir -p "$fake_root/usr/bin" \
	"$fake_root/var/lib/pacman/local" \
	"$pacman_private/cache" \
	"$pacman_private/hooks" \
	"$pacman_private/gnupg" ||
die "Could not create the fake Pacman root"
cat >"$fake_root/usr/bin/pacman.exe" <<-\EOF &&
	#!/bin/sh
	: >"$PACMAN_CAPTURE"
	for argument
	do
		printf '%s\n' "$argument" >>"$PACMAN_CAPTURE"
	done
	test -z "$PACMAN_STDOUT" || printf '%s\n' "$PACMAN_STDOUT"
	test -z "$PACMAN_STDERR" || printf '%s\n' "$PACMAN_STDERR" >&2
	exit "${PACMAN_STATUS:-0}"
	EOF
chmod +x "$fake_root/usr/bin/pacman.exe" ||
die "Could not create the fake Pacman executable"

PACMAN_CAPTURE=$tmp/pacman.args
PACMAN_STDOUT="$package $version"
PACMAN_STDERR=
PACMAN_STATUS=0
export PACMAN_CAPTURE PACMAN_STDOUT PACMAN_STDERR PACMAN_STATUS
printf '%s\n' "$arm64_openssh_pacman_config" \
	>"$pacman_private/pacman.conf"
metadata="$(capture_arm64_openssh_pacman \
	"reading package metadata" \
	"$fake_root" "$pacman_private" -Qp "$package_path")" ||
die "The explicit Pacman configuration probe failed"
test "$package $version" = "$metadata" ||
die "The exact OpenSSH package metadata policy changed"
cat >"$tmp/pacman.expected" <<-EOF
	--root
	$fake_root
	--dbpath
	$fake_root/var/lib/pacman
	--cachedir
	$pacman_private/cache
	--logfile
	$pacman_private/pacman.log
	--config
	$pacman_private/pacman.conf
	--hookdir
	$pacman_private/hooks
	--gpgdir
	$pacman_private/gnupg
	-Qp
	$package_path
	EOF
diff -u "$tmp/pacman.expected" "$PACMAN_CAPTURE" ||
die "Pacman did not receive only explicit private paths"

rm "$pacman_private/pacman.conf" &&
: >"$PACMAN_CAPTURE" ||
die "Could not prepare the missing-config probe"
if run_arm64_openssh_pacman \
	"$fake_root" "$pacman_private" -Qp "$package_path" \
	>"$tmp/missing.out" 2>"$tmp/missing.err"
then
	die "Pacman accepted a missing private configuration"
fi
test ! -s "$PACMAN_CAPTURE" &&
grep -Fq 'Private Pacman configuration is missing or invalid:' \
	"$tmp/missing.err" ||
die "A missing private configuration did not fail closed"

printf '%s\n' '[options]' 'Architecture = x86_64' \
	>"$pacman_private/pacman.conf" &&
: >"$PACMAN_CAPTURE" ||
die "Could not prepare the invalid-config probe"
if run_arm64_openssh_pacman \
	"$fake_root" "$pacman_private" -Qp "$package_path" \
	>"$tmp/invalid.out" 2>"$tmp/invalid.err"
then
	die "Pacman accepted an invalid private configuration"
fi
test ! -s "$PACMAN_CAPTURE" &&
grep -Fq 'Private Pacman configuration is missing or invalid:' \
	"$tmp/invalid.err" ||
die "An invalid private configuration did not fail closed"

printf '%s\n' "$arm64_openssh_pacman_config" \
	>"$pacman_private/pacman.conf"
PACMAN_STDOUT=
PACMAN_STDERR='synthetic Pacman failure'
PACMAN_STATUS=42
export PACMAN_STDOUT PACMAN_STDERR PACMAN_STATUS
if capture_arm64_openssh_pacman \
	"reading package metadata" \
	"$fake_root" "$pacman_private" -Qp "$package_path" \
	>"$tmp/failure.out" 2>"$tmp/failure.err"
then
	die "A failing Pacman metadata probe succeeded"
fi
grep -Fq 'synthetic Pacman failure' "$tmp/failure.err" &&
grep -Fq 'Pacman exited with status 42 while reading package metadata' \
	"$tmp/failure.err" &&
! grep -Fq 'Unexpected package metadata' "$tmp/failure.err" ||
die "Pacman execution failure was reported as a metadata mismatch"

grep -Fq 'test "$package $version" = "$package_metadata"' \
	"$root/please.sh" &&
grep -Fq 'Assert-Equal 27 $payloadFiles.Count' \
	"$root/t/check-arm64-openssh-package.ps1" &&
grep -Fq 'Assert-Equal 14 $peFiles.Count' \
	"$root/t/check-arm64-openssh-package.ps1" &&
grep -Fq 'Assert-SetEqual $payloadFiles $ownedFiles' \
	"$root/t/check-arm64-openssh-package.ps1" ||
die "The exact OpenSSH metadata or inventory policy changed"

grep -Fq 'test aarch64 != "${{ matrix.architecture.name }}"' \
	"$root/.github/workflows/main.yml" ||
die "CI does not keep Azure SSH mandatory for ARM64"
test -f "$root/t/check-arm64-azure-ssh.ps1" &&
test -f "$root/t/check-arm64-azure-ssh-fixture.ps1" &&
grep -Fq 'GIT_FOR_WINDOWS_AZURE_SSH_CHECK' \
	"$root/installer/run-checklist.sh" &&
grep -Fq 'ARM64_AZURE_SSH_PRIVATE_KEY' \
	"$root/.github/workflows/main.yml" ||
die "The Azure transport, local fixture, or optional credential gate is not wired"

sh -n "$root/make-file-list.sh" &&
sh -n "$root/please.sh" &&
sh -n "$root/installer/release.sh" &&
sh -n "$root/git-extra/git-extra.install.in" ||
die "A modified shell script has a syntax error"

echo "ARM64 OpenSSH integration checks passed"
