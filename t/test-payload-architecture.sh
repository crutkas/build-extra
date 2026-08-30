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
pin="--seed-sha256=$seed_sha --seed-entries=2"
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
	--seed-sha256="$seed_sha" --seed-entries=2
said 'immutable evidence and must not be edited' "says the seed may not be edited"

printf 'amd64\tusr/bin/legacy.exe\n' >"$work/shrunk-body"
write_list "$work/shrunk" "$work/shrunk-body"
expect_exit 1 "even shrinking the seed by hand fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/shrunk" --exceptions="$work/exceptions" \
	--seed-sha256="$seed_sha" --seed-entries=2

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
	--seed-sha256="$(sha_of "$work/unsorted-body")" --seed-entries=2
said 'not sorted' "says the body is not sorted"

printf 'amd64\tusr/bin/legacy.exe\namd64\tusr/bin/legacy.exe\n' >"$work/dup-body"
write_list "$work/dup" "$work/dup-body"
expect_exit 1 "a duplicate entry fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/dup" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/dup-body")" --seed-entries=2
said 'duplicate entries' "says the body has duplicates"

printf 'amd64\tusr/bin/legacy.exe\ni386\tusr/bin/legacy.exe\n' >"$work/dup-path-body"
write_list "$work/dup-path" "$work/dup-path-body"
expect_exit 1 "the same path with two machines fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/dup-path" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/dup-path-body")" --seed-entries=2
said 'listed more than once' "says the path is listed twice"

printf 'amd64\tusr/bin/legacy.exe\textra\ni386\tusr/libexec/old32.exe\n' >"$work/fields-body"
write_list "$work/fields" "$work/fields-body"
expect_exit 1 "a wrong tab field count fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/fields" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/fields-body")" --seed-entries=2
said 'tab-separated fields' "says the field count is wrong"

printf 'amd64\t/usr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/abs-body"
write_list "$work/abs" "$work/abs-body"
expect_exit 1 "an absolute path fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/abs" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/abs-body")" --seed-entries=2
said 'repo-relative' "says paths must be repo-relative"

printf 'amd64\tusr/bin/../bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/noncanon-body"
write_list "$work/noncanon" "$work/noncanon-body"
expect_exit 1 "a non-canonical path fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/noncanon" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/noncanon-body")" --seed-entries=2

printf 'arm64\tusr/bin/native.exe\ni386\tusr/libexec/old32.exe\n' >"$work/arm64-body"
write_list "$work/arm64seed" "$work/arm64-body"
expect_exit 1 "an arm64 entry in the seed fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/arm64seed" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/arm64-body")" --seed-entries=2
said "must not appear in the seed" "refuses arm64 in the seed"

printf 'malformed\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/bad-class-body"
write_list "$work/bad-class" "$work/bad-class-body"
expect_exit 1 "a parse failure cannot be grandfathered into the seed" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-class" --exceptions="$work/exceptions" \
	--seed-sha256="$(sha_of "$work/bad-class-body")" --seed-entries=2

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
	--seed-sha256="$(sha_of "$work/glob-body")" --seed-entries=3

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

test "$(($(wc -l <"$work/committed-exceptions-body")))" = 90 &&
ok "the committed exceptions hold exactly 90 entries" ||
not_ok "the committed exceptions hold exactly 90 entries"

test "$(sha_of "$work/committed-exceptions-body")" = 5118b2749246ee5e8f5372fe1c4ab84c28c727f578dce49dbd09175d93d6daf7 &&
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

# The committed lists have to survive their own schema validation.
expect_exit 1 "the committed lists parse, and an empty payload still fails" \
	--root="$root" --file-list="$work/empty-list"
said 'no .dll or .exe files' "the committed lists got as far as inspecting the payload"

echo "# temporary files are cleaned up"

before=$(ls /tmp/payload-arch.* 2>/dev/null | wc -l)
run_checker $common
after=$(ls /tmp/payload-arch.* 2>/dev/null | wc -l)
test "$before" = "$after" &&
ok "leaves no temporary files behind" ||
not_ok "leaves no temporary files behind (had $before, now $after)"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
