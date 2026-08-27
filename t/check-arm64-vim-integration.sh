#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

root="$(cd "$(dirname "$0")/.." && pwd)" ||
die "Could not determine the repository root"

test 7 = "$(wc -l <"$root/arm64-vim/expected-replacements.txt")" &&
grep -Fqx usr/bin/vim.exe "$root/arm64-vim/expected-replacements.txt" &&
! grep -Fq vimtutor "$root/arm64-vim/expected-replacements.txt" ||
die "The exact Vim PE replacement inventory changed"

grep -Fq '"status": "measuring"' "$root/arm64-vim/input-lock.json" &&
grep -Fq '"releaseId": 377949409' "$root/arm64-vim/input-lock.json" &&
grep -Fq '"assetId": 532524650' "$root/arm64-vim/input-lock.json" &&
grep -Fq 'requires explicit measurement mode' \
	"$root/arm64-vim/install.ps1" ||
die "The public Vim measurement input is not fail closed"

test 2 = "$(grep -Fc 'arm64-vim/install.sh" \' "$root/please.sh")" &&
grep -Fq -- '--stage --root="$output_path"' "$root/please.sh" &&
grep -Fq -- '--finalize --root="$output_path"' "$root/please.sh" &&
grep -Fq '/var/cache/arm64-vim/payload-paths.txt' "$root/make-file-list.sh" &&
grep -Fq 'test -z "$MINIMAL_GIT"' "$root/make-file-list.sh" ||
die "The ARM64 Vim staging or full-distribution contract is not wired"

for architecture in i686 x86_64 ucrt64
do
	marker="$TMPDIR/arm64-vim-non-arm-$architecture-$$"
	rm -f "$marker" &&
	ARCH=$architecture "$root/arm64-vim/install.sh" --root="$marker" ||
	die "The Vim installer failed for $architecture"
	test ! -e "$marker" ||
	die "The Vim installer changed the $architecture payload"
done

sh -n "$root/arm64-vim/install.sh" &&
sh -n "$root/make-file-list.sh" &&
sh -n "$root/please.sh" ||
die "A modified shell script has a syntax error"

echo "ARM64 Vim integration wiring checks passed"
