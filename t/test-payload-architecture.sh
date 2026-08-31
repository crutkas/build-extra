#!/bin/sh

# Tests for check-payload-architecture.sh.
#
# Run: sh t/test-payload-architecture.sh

here="$(cd "$(dirname "$0")" && pwd)"
top="$(dirname "$here")"
checker="$top/check-payload-architecture.sh"

work="$(mktemp -d)" ||
{ echo "Could not create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$work"' EXIT

checks=0
failures=0

ok () {
	checks=$(($checks + 1))
	echo "ok - $1"
}

not_ok () {
	checks=$(($checks + 1))
	failures=$(($failures + 1))
	echo "not ok - $1"
	test -z "$2" || sed 's/^/    /' <"$2"
}

sha_of () { # <file>
	sha256sum <"$1" | sed 's/ .*//'
}

run_checker () {
	sh "$checker" "$@" >"$work/out" 2>"$work/err"
}

expect_exit () { # <expected> <description> [args...]
	expected="$1"
	what="$2"
	shift 2

	run_checker "$@"
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$what"
	else
		not_ok "$what (expected exit $expected, got $actual)" "$work/err"
	fi
}

said () { # <pattern> <description>
	if grep -q "$1" "$work/err"
	then
		ok "$2"
	else
		not_ok "$2" "$work/err"
	fi
}

make_pe () { # <path> <machine-hex> [--32] [--hybrid] [--anycpu] [--anycpu32] [--requires32] [--mixed]
	target="$1"
	machine="$2"
	shift 2

	bits=64
	extra=
	while test $# -gt 0
	do
		case "$1" in
		--32) bits=32;;
		--hybrid) extra="$extra -Hybrid";;
		--anycpu) extra="$extra -AnyCpu";;
		--anycpu32) extra="$extra -AnyCpu32";;
		--requires32) extra="$extra -Requires32";;
		--mixed) extra="$extra -MixedMode";;
		esac
		shift
	done

	mkdir -p "$(dirname "$target")" &&
	win="$(cygpath -w "$target")" &&
	powershell.exe -NoProfile -ExecutionPolicy Bypass \
		-File "$here/make-pe-fixture.ps1" -Out "$win" \
		-MachineValue "$machine" -Bits "$bits" $extra ||
	{ echo "Could not create fixture $target" >&2; exit 1; }
}

# Write a list with a header that matches its body.
write_list () { # <path> <body-file>
	target="$1"
	body="$2"

	{
		echo "# test fixture"
		echo "# format-version: 1"
		echo "# seed-source: test-source"
		echo "# seed-version: test"
		echo "# seed-artifact: test.tsv"
		echo "# entries: $(($(wc -l <"$body")))"
		echo "# sha256: $(sha_of "$body")"
		cat "$body"
	} >"$target"
}

echo "# fixtures"

root="$work/root"
make_pe "$root/usr/bin/native.exe" 0xAA64
make_pe "$root/usr/bin/legacy.exe" 0x8664
make_pe "$root/usr/libexec/old32.exe" 0x014C --32
make_pe "$root/clangarm64/bin/Managed.dll" 0x014C --32 --anycpu
make_pe "$root/clangarm64/bin/hybrid.dll" 0xAA64 --hybrid
make_pe "$root/clangarm64/bin/Preferred32.exe" 0x014C --32 --anycpu32

# Non-binary payload entries really exist in a payload, so the fixtures create
# them. A listed file that is not on disk is a hard failure -- the same answer
# the selected half already gives -- so "missing" cannot become a way out of
# either half of the reconciliation.
mkdir -p "$root/etc" "$root/usr/share/doc"
echo '[core]' >"$root/etc/gitconfig"
echo 'readme' >"$root/usr/share/doc/README"
ok "built PE fixtures"

cat >"$work/file-list" <<-\EOF
	usr/bin/native.exe
	usr/bin/legacy.exe
	usr/libexec/old32.exe
	clangarm64/bin/Managed.dll
	etc/gitconfig
	usr/share/doc/README
EOF

printf 'amd64\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/seed-body"
printf 'anycpu\tclangarm64/bin/Managed.dll\tmanaged, architecture-neutral\n' >"$work/exceptions-body"
write_list "$work/seed" "$work/seed-body"
write_list "$work/exceptions" "$work/exceptions-body"

seed_sha="$(sha_of "$work/seed-body")"
: >"$work/renames-body"
write_list "$work/renames" "$work/renames-body"
pin="--seed-sha256=$seed_sha --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames" --seed-source=test-source --renames=$work/renames"
common="--root=$root --file-list=$work/file-list --baseline=$work/seed --exceptions=$work/exceptions $pin"

echo "# the happy path"

expect_exit 0 "a payload matching the seed and exceptions passes" $common
said 'Inspected 4 binaries: 1 ordinary ARM64, 3 not' "reports how much of the payload is native"
said 'The seed records 2 emulated binaries' "reports the size of the seed"

echo "# the seed is immutable, not merely size-capped"

# Remove one grandfathered entry, add a new one, keep the count, recompute the
# header. Nothing in the file itself can tell that apart from the original.
printf 'amd64\tusr/bin/legacy.exe\namd64\tusr/bin/newcomer.exe\n' >"$work/swapped-body"
write_list "$work/swapped" "$work/swapped-body"
make_pe "$root/usr/bin/newcomer.exe" 0x8664
cp "$work/file-list" "$work/file-list-swapped"
echo 'usr/bin/newcomer.exe' >>"$work/file-list-swapped"
expect_exit 1 "swapping one seed entry for another at the same count fails" \
	--root="$root" --file-list="$work/file-list-swapped" \
	--baseline="$work/swapped" --exceptions="$work/exceptions" \
	--seed-sha256="$seed_sha" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'immutable evidence and must not be edited' "says the seed may not be edited"

printf 'amd64\tusr/bin/legacy.exe\n' >"$work/shrunk-body"
write_list "$work/shrunk" "$work/shrunk-body"
expect_exit 1 "even shrinking the seed by hand fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/shrunk" --exceptions="$work/exceptions" \
	--seed-sha256="$seed_sha" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"

echo "# new non-ARM64 payload"

expect_exit 1 "an unlisted non-ARM64 binary fails" \
	--root="$root" --file-list="$work/file-list-swapped" \
	--baseline="$work/seed" --exceptions="$work/exceptions" $pin
said 'amd64	usr/bin/newcomer.exe' "names the binary that broke the ratchet"

echo "# hybrid and 32-bit-preferred payloads are not neutral"

cp "$work/file-list" "$work/file-list-hybrid"
echo 'clangarm64/bin/hybrid.dll' >>"$work/file-list-hybrid"
expect_exit 1 "an ARM64X binary is not accepted as ARM64" \
	--root="$root" --file-list="$work/file-list-hybrid" \
	--baseline="$work/seed" --exceptions="$work/exceptions" $pin
said 'arm64x	clangarm64/bin/hybrid.dll' "reports the hybrid binary as arm64x"

cp "$work/file-list" "$work/file-list-pref32"
echo 'clangarm64/bin/Preferred32.exe' >>"$work/file-list-pref32"
expect_exit 1 "a 32-bit-preferred assembly is not accepted as ARM64" \
	--root="$root" --file-list="$work/file-list-pref32" \
	--baseline="$work/seed" --exceptions="$work/exceptions" $pin
said 'anycpu32	clangarm64/bin/Preferred32.exe' "reports it as anycpu32, not anycpu"

printf 'anycpu\tclangarm64/bin/Managed.dll\tmanaged\nanycpu32\tclangarm64/bin/Preferred32.exe\tprefers 32-bit\n' >"$work/pref-exceptions-body"
write_list "$work/pref-exceptions" "$work/pref-exceptions-body"
expect_exit 1 "a 32-bit-preferred assembly cannot be added to the exceptions file" \
	--root="$root" --file-list="$work/file-list-pref32" \
	--baseline="$work/seed" --exceptions="$work/pref-exceptions" $pin
said 'not architecture-neutral' "explains that only AnyCPU is neutral"

echo "# classification drift is not a reduction"

# The same path, still listed, but now a different architecture.
make_pe "$root/usr/bin/legacy.exe" 0x014C --32
expect_exit 1 "a listed path whose machine changed fails" $common
said 'The classification of a listed binary changed' "reports it as drift"
said 'usr/bin/legacy.exe: amd64 -> i386' "shows the old and the new class"
if grep -q 'no longer shipped, or are now ARM64' "$work/err"
then
	not_ok "drift is not also reported as a reduction" "$work/err"
else
	ok "drift is not also reported as a reduction"
fi
make_pe "$root/usr/bin/legacy.exe" 0x8664

echo "# reductions are allowed and measured"

cat >"$work/file-list-reduced" <<-\EOF
	usr/bin/native.exe
	usr/bin/legacy.exe
	clangarm64/bin/Managed.dll
EOF
expect_exit 0 "dropping an emulated binary passes" \
	--root="$root" --file-list="$work/file-list-reduced" \
	--baseline="$work/seed" --exceptions="$work/exceptions" $pin
said '1 of them are no longer shipped' "reports the reduction"
if grep -q 'sha256' "$work/err"
then
	not_ok "does not invite anyone to edit the seed" "$work/err"
else
	ok "does not invite anyone to edit the seed"
fi

# A binary that became native counts as a reduction too.
make_pe "$root/usr/libexec/old32.exe" 0xAA64
expect_exit 0 "a binary that became ARM64 passes" $common
said 'now ARM64' "reports the conversion as a reduction"
make_pe "$root/usr/libexec/old32.exe" 0x014C --32

echo "# list schema"

printf 'amd64\tusr/libexec/old32.exe\namd64\tusr/bin/legacy.exe\n' >"$work/unsorted-body"
write_list "$work/unsorted" "$work/unsorted-body"
expect_exit 1 "an unsorted body fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/unsorted" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/unsorted-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'not sorted' "says the body is not sorted"

printf 'amd64\tusr/bin/legacy.exe\namd64\tusr/bin/legacy.exe\n' >"$work/dup-body"
write_list "$work/dup" "$work/dup-body"
expect_exit 1 "a duplicate entry fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/dup" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/dup-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'duplicate entries' "says the body has duplicates"

printf 'amd64\tusr/bin/legacy.exe\ni386\tusr/bin/legacy.exe\n' >"$work/dup-path-body"
write_list "$work/dup-path" "$work/dup-path-body"
expect_exit 1 "the same path with two machines fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/dup-path" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/dup-path-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'listed more than once' "says the path is listed twice"

printf 'amd64\tusr/bin/legacy.exe\textra\ni386\tusr/libexec/old32.exe\n' >"$work/fields-body"
write_list "$work/fields" "$work/fields-body"
expect_exit 1 "a wrong tab field count fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/fields" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/fields-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'tab-separated fields' "says the field count is wrong"

printf 'amd64\t/usr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/abs-body"
write_list "$work/abs" "$work/abs-body"
expect_exit 1 "an absolute path fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/abs" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/abs-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said 'repo-relative' "says paths must be repo-relative"

printf 'amd64\tusr/bin/../bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/noncanon-body"
write_list "$work/noncanon" "$work/noncanon-body"
expect_exit 1 "a non-canonical path fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/noncanon" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/noncanon-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"

printf 'arm64\tusr/bin/native.exe\ni386\tusr/libexec/old32.exe\n' >"$work/arm64-body"
write_list "$work/arm64seed" "$work/arm64-body"
expect_exit 1 "an arm64 entry in the seed fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/arm64seed" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/arm64-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"
said "must not appear in the seed" "refuses arm64 in the seed"

printf 'malformed\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/bad-class-body"
write_list "$work/bad-class" "$work/bad-class-body"
expect_exit 1 "a parse failure cannot be grandfathered into the seed" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-class" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/bad-class-body")" --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"

printf 'anycpu\tclangarm64/bin/Managed.dll\t\n' >"$work/blank-reason-body"
write_list "$work/blank-reason" "$work/blank-reason-body"
expect_exit 1 "a blank exception reason fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/seed" --exceptions="$work/blank-reason" $pin
said 'reason is empty' "says the reason is empty"

printf 'anycpu\tusr/bin/legacy.exe\talso in the seed\n' >"$work/overlap-body"
write_list "$work/overlap" "$work/overlap-body"
expect_exit 1 "a path in both lists fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/seed" --exceptions="$work/overlap" $pin
said 'listed in both' "says the path is in both lists"

sed 's/^# sha256: .*/# sha256: 0000000000000000000000000000000000000000000000000000000000000000/' \
	<"$work/seed" >"$work/bad-digest"
expect_exit 1 "a header digest that does not match the body fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-digest" --exceptions="$work/exceptions" $pin

sed 's/^# entries: .*/# entries: 99/' <"$work/seed" >"$work/bad-count"
expect_exit 1 "a header entry count that does not match the body fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-count" --exceptions="$work/exceptions" $pin

sed 's/^# format-version: .*/# format-version: 99/' <"$work/seed" >"$work/bad-version"
expect_exit 1 "an unsupported format-version fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-version" --exceptions="$work/exceptions" $pin

echo "# the seed has to say what it is evidence of"

expect_exit 1 "a seed-version that is not the pinned one fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--seed-sha256="$seed_sha" --seed-entries=2 \
	--seed-version=v9.9.9 --seed-artifact=test.tsv
said 'seed-version' "says which identity field is wrong"

expect_exit 1 "a seed-artifact that is not the pinned one fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--seed-sha256="$seed_sha" --seed-entries=2 \
	--seed-version=test --seed-artifact=other.tsv
said 'seed-artifact' "says which identity field is wrong"

grep -v '^# seed-source' <"$work/seed" >"$work/no-source"
expect_exit 1 "a seed that does not record where it came from fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/no-source" --exceptions="$work/exceptions" $pin

echo "# nothing inspected is never success"

: >"$work/empty-list"
expect_exit 1 "an empty payload fails rather than reporting success" \
	--root="$root" --file-list="$work/empty-list" \
	--baseline="$work/seed" --exceptions="$work/exceptions" $pin

cat >"$work/silent.ps1" <<-\EOF
	exit 0
EOF
expect_exit 1 "a parser that classifies nothing fails" \
	$common --pe-imports="$work/silent.ps1"
said 'refusing to report success' "says it refused to report success"

cat >"$work/partial.ps1" <<-\EOF
	Write-Output "arm64`tfirst"
	exit 0
EOF
expect_exit 1 "a parser that describes only some binaries fails" \
	$common --pe-imports="$work/partial.ps1"

cat >"$work/broken.ps1" <<-\EOF
	exit 3
EOF
expect_exit 1 "a parser that exits non-zero fails the check" \
	$common --pe-imports="$work/broken.ps1"

echo "# payload names that look like globs"

make_pe "$root/usr/bin/[.exe" 0x8664
cp "$work/file-list" "$work/file-list-glob"
echo 'usr/bin/[.exe' >>"$work/file-list-glob"
printf 'amd64\tusr/bin/[.exe\namd64\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/glob-body"
write_list "$work/glob-seed" "$work/glob-body"
expect_exit 0 "a payload named [.exe is handled literally" \
	--root="$root" --file-list="$work/file-list-glob" \
	--baseline="$work/glob-seed" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/glob-body")" --seed-entries=3 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source --renames="$work/renames"

echo "# renames: the legitimate path for upstream version churn"

# The real cases the audit observed against git-sdk-arm64.
make_pe "$root/usr/bin/gawk-5.4.1.exe" 0x8664
printf 'usr/bin/native.exe\nusr/bin/gawk-5.4.1.exe\nusr/libexec/old32.exe\nclangarm64/bin/Managed.dll\n' >"$work/file-list-renamed"
printf 'amd64\tusr/bin/gawk-5.4.0.exe\ni386\tusr/libexec/old32.exe\n' >"$work/rseed-body"
write_list "$work/rseed" "$work/rseed-body"
rseed_sha="$(sha_of "$work/rseed-body")"
rpin="--seed-sha256=$rseed_sha --seed-entries=2 --seed-version=test --seed-artifact=test.tsv --seed-source=test-source"

printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.1.exe\tupstream version bump\n' >"$work/ren-good-body"
write_list "$work/ren-good" "$work/ren-good-body"
expect_exit 0 "a version bump recorded as a rename passes" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-good" $rpin
if grep -q 'no longer shipped' "$work/err"
then
	not_ok "a renamed binary is not also counted as a reduction" "$work/err"
else
	ok "a renamed binary is not also counted as a reduction"
fi

expect_exit 1 "the same bump without a rename still fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $rpin

echo "# renames cannot be used to bless an arbitrary binary"

# The old side must exist in the seed, with that exact class.
printf 'amd64\tusr/bin/not-in-seed.exe\tusr/bin/gawk-5.4.1.exe\tinvented\n' >"$work/ren-noseed-body"
write_list "$work/ren-noseed" "$work/ren-noseed-body"
expect_exit 1 "a rename from a path the seed never recorded fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-noseed" $rpin
said 'seed has no' "says the rename does not start from tracked debt"

# A rename may move a binary, never reclassify it.
printf 'i386\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.1.exe\tclass laundering\n' >"$work/ren-class-body"
write_list "$work/ren-class" "$work/ren-class-body"
expect_exit 1 "a rename that changes the class fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-class" $rpin

# The old name must actually be gone.
printf 'amd64\tusr/libexec/old32.exe\tusr/bin/gawk-5.4.1.exe\tstale\n' >"$work/ren-stale-body"
write_list "$work/ren-stale" "$work/ren-stale-body"
expect_exit 1 "a rename away from a binary that is still shipped fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-stale" $rpin

# The new name must actually be there, with the class the seed recorded.
printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-9.9.9.exe\tnot shipped\n' >"$work/ren-missing-body"
write_list "$work/ren-missing" "$work/ren-missing-body"
expect_exit 1 "a rename to a binary that is not in the payload fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-missing" $rpin
said 'not in the payload' "says the new name is not shipped"

# A content swap: the new name exists but is a different architecture than the
# seed recorded, so the rename must not launder it through.
make_pe "$root/usr/bin/swapped.exe" 0xAA64
printf 'usr/bin/native.exe\nusr/bin/swapped.exe\nusr/libexec/old32.exe\nclangarm64/bin/Managed.dll\n' >"$work/file-list-swap"
printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/swapped.exe\tcontent swap\n' >"$work/ren-swap-body"
write_list "$work/ren-swap" "$work/ren-swap-body"
expect_exit 1 "a rename to a path whose real class differs fails" \
	--root="$root" --file-list="$work/file-list-swap" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-swap" $rpin

# One-to-one only.
make_pe "$root/usr/bin/gawk-5.4.2.exe" 0x8664
printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.1.exe\tfirst\ni386\tusr/libexec/old32.exe\tusr/bin/gawk-5.4.1.exe\tsecond\n' >"$work/ren-many-body"
write_list "$work/ren-many" "$work/ren-many-body"
expect_exit 1 "two renames pointing at one new path fail" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-many" $rpin
said 'one-to-one' "says a rename must be one-to-one"

printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.0.exe\tself\n' >"$work/ren-self-body"
write_list "$work/ren-self" "$work/ren-self-body"
expect_exit 1 "a rename to itself fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-self" $rpin

printf 'amd64\tusr/bin/gawk-5.4.0.exe\t/usr/bin/gawk-5.4.1.exe\tabsolute\n' >"$work/ren-abs-body"
write_list "$work/ren-abs" "$work/ren-abs-body"
expect_exit 1 "a rename to an absolute path fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-abs" $rpin

printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.1.exe\t\n' >"$work/ren-noreason-body"
write_list "$work/ren-noreason" "$work/ren-noreason-body"
expect_exit 1 "a rename with no reason fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-noreason" $rpin

echo "# no path is claimed by two lists at once"

# A path asserted to be renamed tracked debt and also asserted to be an
# architecture-neutral exception is two contradictory claims about one binary,
# and both tuples would land in the known set -- so whichever way the file
# really classifies it would be accepted and drift could never be detected.
printf 'anycpu\tusr/bin/gawk-5.4.1.exe\tclaimed twice\n' >"$work/exc-claim-body"
write_list "$work/exc-claim" "$work/exc-claim-body"
expect_exit 1 "a path in both the renames and the exceptions fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exc-claim" \
	--renames="$work/ren-good" $rpin
said 'exactly one list' "says a path belongs to exactly one list"

printf 'anycpu\tusr/bin/gawk-5.4.0.exe\tclaimed twice\n' >"$work/exc-oldclaim-body"
write_list "$work/exc-oldclaim" "$work/exc-oldclaim-body"
expect_exit 1 "a renamed-from path that is also an exception fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exc-oldclaim" \
	--renames="$work/ren-good" $rpin

# A rename target the seed already tracks needs no rename, and counting it
# twice would let one binary satisfy two entries.
printf 'amd64\tusr/bin/gawk-5.4.0.exe\namd64\tusr/bin/gawk-5.4.1.exe\ni386\tusr/libexec/old32.exe\n' >"$work/seed-both-body"
write_list "$work/seed-both" "$work/seed-both-body"
expect_exit 1 "a rename to a path the seed already tracks fails" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/seed-both" --exceptions="$work/exceptions" \
	--renames="$work/ren-good" \
	--seed-sha256="$(sha_of "$work/seed-both-body")" --seed-entries=3 \
	--seed-version=test --seed-artifact=test.tsv --seed-source=test-source
said 'already seeded' "says the seed already tracks the new name"

# Chained renames: a path that is both renamed to and renamed from means the
# two rows disagree about whether it is shipped.
printf 'amd64\tusr/bin/gawk-5.4.0.exe\tusr/bin/gawk-5.4.1.exe\tfirst hop\namd64\tusr/bin/gawk-5.4.1.exe\tusr/bin/gawk-5.4.2.exe\tsecond hop\n' >"$work/ren-chain-body"
write_list "$work/ren-chain" "$work/ren-chain-body"
expect_exit 1 "chained renames fail" \
	--root="$root" --file-list="$work/file-list-renamed" \
	--baseline="$work/rseed" --exceptions="$work/exceptions" \
	--renames="$work/ren-chain" $rpin
# The seed-membership requirement catches this first: the intermediate name is
# not tracked debt, so the second hop has nothing to rename from. The explicit
# chain check below it is defence in depth for a future reordering.
said 'seed has no' "says the intermediate name is not tracked debt"

echo "# no image escapes classification"

make_pe "$root/usr/bin/UPPER.EXE" 0x8664
make_pe "$root/usr/bin/Mixed.Dll" 0x8664
printf 'usr/bin/native.exe\nusr/bin/UPPER.EXE\nusr/bin/Mixed.Dll\n' >"$work/file-list-case"
printf 'amd64\tusr/bin/Mixed.Dll\namd64\tusr/bin/UPPER.EXE\n' >"$work/case-body"
write_list "$work/case-seed" "$work/case-body"
expect_exit 0 "mixed-case extensions are selected and classified" \
	--root="$root" --file-list="$work/file-list-case" \
	--baseline="$work/case-seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" \
	--seed-sha256="$(sha_of "$work/case-body")" --seed-entries=2 \
	--seed-version=test --seed-artifact=test.tsv --seed-source=test-source
said 'Inspected 3 binaries' "all three mixed-case entries participate"

# The same corpus with the uppercase entries unlisted must fail, so the pass
# above is not agreement-by-narrowing.
expect_exit 1 "mixed-case entries are actually required to be listed" \
	--root="$root" --file-list="$work/file-list-case" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin

echo "# an image with no recognised extension is a hard failure"

# An image with no recognised extension must not slip past the predicate.
make_pe "$root/usr/bin/oddball.bin" 0x8664
printf 'usr/bin/native.exe\nusr/bin/oddball.bin\n' >"$work/file-list-odd"
expect_exit 1 "an MZ image outside the extension set is a hard failure" \
	--root="$root" --file-list="$work/file-list-odd" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin
said 'not classified' "names the image that escaped the predicate"
said 'usr/bin/oddball.bin' "names the file itself"

# An entry the scan cannot read is not evidence of anything either. An
# unreadable `.exe` is already a hard failure, so an unreadable entry with an
# unrecognised extension must be one too -- otherwise "unreadable" is a way out
# of both halves of the reconciliation.
printf 'usr/bin/native.exe\nusr/bin/absent.bin\n' >"$work/file-list-unreadable"
expect_exit 1 "an unreadable unselected entry is a hard failure" \
	--root="$root" --file-list="$work/file-list-unreadable" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin
said 'could not be read' "says the entry could not be examined"
said 'usr/bin/absent.bin' "names the entry it could not read"

# The corresponding `.exe` case, so the two halves really do agree.
printf 'usr/bin/native.exe\nusr/bin/absent.exe\n' >"$work/file-list-absent-exe"
expect_exit 1 "an unreadable selected entry is a hard failure too" \
	--root="$root" --file-list="$work/file-list-absent-exe" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin

printf 'usr/bin/native.exe\netc/gitconfig\n' >"$work/file-list-plain"
expect_exit 0 "a non-image with no recognised extension is not a failure" \
	--root="$root" --file-list="$work/file-list-plain" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin

# The two halves of the split must account for the whole payload; if one of
# them silently came back empty because the tool failed rather than because
# nothing matched, the reconciliation above would be skipped entirely.
said_out () { # <pattern> <description>
	if grep -q "$1" "$work/out" "$work/err"
	then
		ok "$2"
	else
		not_ok "$2" "$work/err"
	fi
}
run_checker --root="$root" --file-list="$work/file-list-plain" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin
said_out 'Inspected 1 binaries' "the unselected half does not swallow the selected one"

echo "# payload paths are canonical"

printf 'usr/bin/native.exe\n../escape.dll\n' >"$work/file-list-escape"
expect_exit 1 "a payload path that escapes the root fails" \
	--root="$root" --file-list="$work/file-list-escape" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" $pin

echo "# the seed source is pinned, not merely present"

expect_exit 1 "a seed-source that is not the pinned one fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/seed" --exceptions="$work/exceptions" \
	--renames="$work/renames" \
	--seed-sha256="$seed_sha" --seed-entries=2 --seed-version=test \
	--seed-artifact=test.tsv --seed-source=somewhere-else
said 'seed-source' "names the identity field that is wrong"

echo "# the entry-count pin is named in its own right"

printf 'amd64\tusr/bin/legacy.exe\namd64\tusr/bin/newcomer.exe\ni386\tusr/libexec/old32.exe\n' >"$work/grown3-body"
write_list "$work/grown3" "$work/grown3-body"
expect_exit 1 "a seed of the wrong size is refused by name" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/grown3" --exceptions="$work/exceptions" \
	--renames="$work/renames" \
	--seed-sha256="$(sha_of "$work/grown3-body")" --seed-entries=2 \
	--seed-version=test --seed-artifact=test.tsv --seed-source=test-source
said 'the seed has 3 entries but 2 are pinned' \
	"names the entry-count pin rather than falling through to the digest"

echo "# the committed seed and exceptions"

body_of () { sed -e '/^[ 	]*#/d' -e '/^[ 	]*$/d' "$1"; }

body_of "$top/arm64-payload-baseline.txt" >"$work/committed-seed-body"
body_of "$top/arm64-payload-exceptions.txt" >"$work/committed-exceptions-body"

test "$(($(wc -l <"$work/committed-seed-body")))" = 433 &&
ok "the committed seed holds exactly 433 entries" ||
not_ok "the committed seed holds exactly 433 entries"

test "$(sha_of "$work/committed-seed-body")" = a1e536ae97206e0b88e432978aed40a13d19f61c27076fc28052dcd1de9aeb10 &&
ok "the committed seed body hashes to the audited digest" ||
not_ok "the committed seed body hashes to the audited digest"

test "$(($(wc -l <"$work/committed-exceptions-body")))" = 91 &&
ok "the committed exceptions hold exactly 91 entries" ||
not_ok "the committed exceptions hold exactly 91 entries"

test "$(sha_of "$work/committed-exceptions-body")" = 4981f23f872154f4dd0095ddbd48137fab22e34932dd74ccf880cb8c8e180bd2 &&
ok "the committed exceptions body hashes to the audited digest" ||
not_ok "the committed exceptions body hashes to the audited digest"

grep -q '^# seed-version: v2.55.0.4$' "$top/arm64-payload-baseline.txt" &&
ok "the seed records which payload version it came from" ||
not_ok "the seed records which payload version it came from"

grep -q '^# seed-artifact: ' "$top/arm64-payload-baseline.txt" &&
ok "the seed records the artifact it was derived from" ||
not_ok "the seed records the artifact it was derived from"

grep -q "^SEED_SHA256=a1e536ae97206e0b88e432978aed40a13d19f61c27076fc28052dcd1de9aeb10$" "$checker" &&
ok "the checker pins the seed digest" ||
not_ok "the checker pins the seed digest"

grep -q '^SEED_ENTRIES=433$' "$checker" &&
ok "the checker pins the seed size" ||
not_ok "the checker pins the seed size"

grep -q "^SEED_SOURCE='ARM64 RTM packaging audit of git-for-windows/build-extra'$" "$checker" &&
ok "the checker pins where the seed came from" ||
not_ok "the checker pins where the seed came from"

body_of "$top/arm64-payload-renames.txt" >"$work/committed-renames-body"

test "$(sha_of "$work/committed-renames-body")" = b33678993b962af54bb96a58cba15c00ec0f1958e22c9984001e77851167a155 &&
ok "the committed renames body hashes to the recorded digest" ||
not_ok "the committed renames body hashes to the recorded digest"

# Every rename has to start from a tuple the committed seed really holds. This
# is the property that stops the renames file being used to launder a binary
# the seed never tracked, checked here against the committed lists rather than
# against a fixture.
missing=0
while IFS='	' read -r machine old_path new_path reason
do
	grep -q -x -F "$machine	$old_path" "$work/committed-seed-body" ||
	missing=$(($missing + 1))
done <"$work/committed-renames-body"
test "$missing" = 0 &&
ok "every committed rename starts from a tuple in the committed seed" ||
not_ok "every committed rename starts from a tuple in the committed seed ($missing do not)"

# The three lists must not disagree about who owns a path.
cut -f 2 <"$work/committed-exceptions-body" | LC_ALL=C sort >"$work/exc-paths"
cut -f 2 <"$work/committed-seed-body" | LC_ALL=C sort >"$work/seed-paths"
cut -f 3 <"$work/committed-renames-body" | LC_ALL=C sort >"$work/ren-new-paths"
test -z "$(LC_ALL=C comm -12 "$work/seed-paths" "$work/exc-paths")" &&
ok "no committed path is both tracked debt and an exception" ||
not_ok "no committed path is both tracked debt and an exception"
test -z "$(LC_ALL=C comm -12 "$work/ren-new-paths" "$work/exc-paths")" &&
ok "no renamed-to path is also an exception" ||
not_ok "no renamed-to path is also an exception"

# The audited seed is evidence, so the digest is pinned in three independent
# places: the file's own header, the checker, and here. Changing the recorded
# debt therefore cannot be done quietly -- it takes three edits, all of them
# visible in the diff. This raises the cost of a self-authorising change; it
# does not by itself make one impossible, which is recorded as a residual.
grep -q '^# sha256: a1e536ae97206e0b88e432978aed40a13d19f61c27076fc28052dcd1de9aeb10$' \
	"$top/arm64-payload-baseline.txt" &&
ok "the seed file's own header records the audited digest" ||
not_ok "the seed file's own header records the audited digest"

# The committed lists have to survive their own schema validation.
expect_exit 1 "the committed lists parse, and an empty payload still fails" \
	--root="$root" --file-list="$work/empty-list"
said 'no .dll or .exe files' "the committed lists got as far as inspecting the payload"

echo "# temporary files are cleaned up"

# The checker allocates a private mktemp directory, which honours TMPDIR, so
# point it at one of ours and count only what it puts there. Counting the whole
# shared temp directory would report leaks caused by unrelated processes and
# would mask a real leak that coincided with an unrelated deletion -- and this
# suite backs a branch-protection check, so it cannot be that flaky.
private_tmp="$work/private-tmp"
mkdir -p "$private_tmp"
before=$(ls -1 "$private_tmp" | wc -l)
TMPDIR="$private_tmp" run_checker $common
after=$(ls -1 "$private_tmp" | wc -l)
test "$before" = "$after" &&
ok "leaves no temporary files behind" ||
not_ok "leaves no temporary files behind (had $before, now $after)"

# That the count is scoped is only meaningful if the checker really did work
# there, so prove the directory was used at all.
TMPDIR="$private_tmp" sh "$checker" --root="$root" --file-list="$work/no-such-list" \
	$common >/dev/null 2>&1
test "$(ls -1 "$private_tmp" | wc -l)" = "$before" &&
ok "cleans up even when it fails early" ||
not_ok "cleans up even when it fails early"

grep -q 'mktemp -d' "$checker" &&
ok "the checker allocates a private temporary directory" ||
not_ok "the checker allocates a private temporary directory"

grep -q '/tmp/payload-arch' "$checker" &&
not_ok "the checker no longer uses a shared-namespace temporary name" ||
ok "the checker no longer uses a shared-namespace temporary name"

echo "# the payload split cannot fail quietly"

# grep exits 1 for "nothing matched" and 2 for "the tool failed". Discarding
# the status with `|| :` conflates them, and on exit 2 the unselected half comes
# back empty -- which reads as "nothing was excluded" and skips the entire
# negative reconciliation while the run still reports success. There is no way
# to make the real grep exit 2 from a fixture, so this binds the shape.
grep -q '>"\$tmp\.candidates" || :' "$checker" &&
not_ok "the selected half does not discard the tool's status" ||
ok "the selected half does not discard the tool's status"

grep -q '>"\$tmp\.rest" || :' "$checker" &&
not_ok "the unselected half does not discard the tool's status" ||
ok "the unselected half does not discard the tool's status"

test "$(grep -c '^\*) die "Could not' "$checker")" -ge 2 &&
ok "both halves of the split fail closed on a tool error" ||
not_ok "both halves of the split fail closed on a tool error"

# The split reconciliation is defence in depth: `grep P` and `grep -v P` really
# do partition their input, so no payload can make them disagree. It is bound
# here by fault injection instead -- a grep that quietly drops one line from the
# unselected half, which is exactly what a future non-complementary refactor
# would look like. Without the reconciliation this is a silent no-op; with it,
# it is a hard failure.
stub_dir="$work/stub-bin"
mkdir -p "$stub_dir"
real_grep="$(command -v grep)"
cat >"$stub_dir/grep" <<-EOF
	#!/bin/sh
	# Pass everything through except the negated split, from which one line
	# vanishes -- with a zero exit status, so only a content check can see it.
	for arg
	do
		case "\$arg" in
		-*v*) drop=t;;
		esac
	done
	if test -n "\${drop-}" && test "\$1" = -i
	then
		"$real_grep" "\$@" | sed '1d'
		exit 0
	fi
	exec "$real_grep" "\$@"
EOF
chmod +x "$stub_dir/grep"

PATH="$stub_dir:$PATH" sh "$checker" $common >"$work/out" 2>"$work/err"
actual=$?
test "$actual" -ne 0 &&
ok "a split that silently loses a payload entry is a hard failure" ||
not_ok "a split that silently loses a payload entry is a hard failure (exit $actual)" "$work/err"
said 'not fully accounted for' "says the payload was not fully accounted for"

# And the stub really is reached, so the check above is not passing for some
# unrelated reason: without the reconciliation the same stub is invisible.
# The extracted copy lives outside the repository, so it is told where the
# parser is rather than resolving it beside itself.
sed -e '/^LC_ALL=C sort -u "\$tmp.candidates" "\$tmp.rest" >"\$tmp.split"$/,+5d' \
	"$checker" >"$work/checker-no-split.sh"
PATH="$stub_dir:$PATH" sh "$work/checker-no-split.sh" $common \
	--pe-imports="$top/pe-imports.ps1" >/dev/null 2>"$work/err"
test $? = 0 &&
ok "without the reconciliation the same fault goes unnoticed" ||
not_ok "without the reconciliation the same fault goes unnoticed" "$work/err"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
