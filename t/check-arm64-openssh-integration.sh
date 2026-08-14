#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
root=$thisdir/..
tmp=${TMPDIR:-/tmp}/arm64-openssh-integration.$$
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp" ||
die "Could not create $tmp"

sed 's/\r$//' "$root/arm64-openssh-client-files.txt" >"$tmp/native-input" &&
LC_ALL=C sort -u "$tmp/native-input" >"$tmp/native" &&
cmp "$tmp/native-input" "$tmp/native" ||
die "Native OpenSSH package paths must be sorted and unique"
sed 's/\r$//' "$root/arm64-openssh-msys-files.txt" >"$tmp/msys-input" &&
LC_ALL=C sort -u "$tmp/msys-input" >"$tmp/msys" &&
cmp "$tmp/msys-input" "$tmp/msys" ||
die "MSYS OpenSSH baseline paths must be sorted and unique"

"$root/install-arm64-openssh.sh" --print-package-files >"$tmp/printed" &&
cmp "$tmp/native" "$tmp/printed" ||
die "The installer and checked-in package file manifest differ"

test 22 = "$(wc -l <"$tmp/native" | tr -d ' ')" ||
die "Expected 22 native package files"
test 11 = "$(wc -l <"$tmp/msys" | tr -d ' ')" ||
die "Expected 11 baseline MSYS OpenSSH PE files"

sed -n '/^#/!s/	.*//p' "$root/arm64-openssh-msys-payload.tsv" |
LC_ALL=C sort >"$tmp/msys-payload"
test 16 = "$(wc -l <"$tmp/msys-payload" | tr -d ' ')" ||
die "Expected 16 selected MSYS OpenSSH payload files"

comm -12 "$tmp/msys" "$tmp/native" >"$tmp/replaced"
test 10 = "$(wc -l <"$tmp/replaced" | tr -d ' ')" ||
die "Expected 10 direct native replacements"
comm -23 "$tmp/msys" "$tmp/native" >"$tmp/removed"
test usr/lib/ssh/ssh-keysign.exe = "$(cat "$tmp/removed")" ||
die "ssh-keysign.exe must be the only removed baseline path"

grep -v '^usr/share/doc/' "$tmp/native" >"$tmp/native-payload"
comm -12 "$tmp/msys-payload" "$tmp/native-payload" >"$tmp/payload-replaced"
comm -23 "$tmp/msys-payload" "$tmp/native-payload" >"$tmp/payload-removed"
comm -13 "$tmp/msys-payload" "$tmp/native-payload" >"$tmp/payload-added"
test 11 = "$(wc -l <"$tmp/payload-replaced" | tr -d ' ')" &&
test 5 = "$(wc -l <"$tmp/payload-removed" | tr -d ' ')" &&
test 6 = "$(wc -l <"$tmp/payload-added" | tr -d ' ')" ||
die "Unexpected full artifact path delta"

grep -Eq '(^|/)(sshd|ssh-shellhost)(\.exe)?$|sshd_config|moduli|service' "$tmp/native" &&
die "The native client manifest contains a server component"
grep -q 'ssh-pageant' "$tmp/native" &&
die "ssh-pageant must remain outside the native package"

grep -Fq 'USE_ARM64_WIN32_OPENSSH' "$root/make-file-list.sh" &&
grep -Fq 'arm64-win32-openssh' "$root/installer/release.sh" &&
grep -Fq 'REMOVE_ARM64_OPENSSH_KEYSIGN' "$root/installer/install.iss" ||
die "The opt-in selection or installer cleanup is not wired"

sh -n "$root/install-arm64-openssh.sh" &&
sh -n "$root/make-file-list.sh" &&
sh -n "$root/please.sh" &&
sh -n "$root/installer/release.sh" ||
die "A modified shell script has a syntax error"

echo "ARM64 OpenSSH integration checks passed"
