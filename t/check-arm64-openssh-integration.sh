#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

root="$(cd "$(dirname "$0")/.." && pwd)" ||
die "Could not determine the repository root"

grep -Fq 'OPENSSH_PACKAGE=mingw-w64-clang-aarch64-win32-openssh-client' \
	"$root/make-file-list.sh" &&
grep -Fq 'OPENSSH_PACKAGE=openssh' "$root/make-file-list.sh" &&
grep -Fq 'run_arm64_openssh_pacman -R --noconfirm openssh' "$root/please.sh" &&
grep -Fq '26f302a73a58395de8d7741077365d2e0f296343358a5f62bc5385ec8c04d2f8' \
	"$root/please.sh" &&
grep -Fq 'c97decf4acf026790b0989e0f08be8142b9f7ec2' "$root/please.sh" &&
grep -Fq 'pacman -Ql "$openssh_package"' "$root/installer/release.sh" &&
grep -Fq 'REMOVE_ARM64_OPENSSH_LEGACY_FILES' "$root/installer/install.iss" &&
grep -Fq "test /clangarm64 != '@@MINGW_PREFIX@@'" \
	"$root/git-extra/git-extra.install.in" &&
grep -Fq 'git ls-remote git@ssh.dev.azure.com:v3/git-for-windows/git/git main' \
	"$root/installer/run-checklist.sh" ||
die "The default package, provenance, cleanup, or Azure gate is not wired"

grep -Fq 'test aarch64 != "${{ matrix.architecture.name }}"' \
	"$root/.github/workflows/main.yml" ||
die "CI does not keep Azure SSH mandatory for ARM64"

sh -n "$root/make-file-list.sh" &&
sh -n "$root/please.sh" &&
sh -n "$root/installer/release.sh" &&
sh -n "$root/git-extra/git-extra.install.in" ||
die "A modified shell script has a syntax error"

echo "ARM64 OpenSSH integration checks passed"
