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

# Run the checker and compare its exit code with what the test expects.
expect_exit () { # <expected> <description> [args...]
	expected="$1"
	what="$2"
	shift 2

	sh "$checker" "$@" >"$work/out" 2>"$work/err"
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$what"
	else
		not_ok "$what (expected exit $expected, got $actual)" "$work/err"
	fi
}

make_pe () { # <path> <machine-hex> [--32] [--hybrid] [--anycpu]
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

# Write a baseline or exceptions file with a correct header for its body.
write_list () { # <path> <seed-entries|-> <body-file>
	target="$1"
	seed="$2"
	body="$3"

	entries=$(($(wc -l <"$body")))
	digest="$(sha256sum <"$body" | sed 's/ .*//')"

	{
		echo "# test fixture"
		echo "# format-version: 1"
		test "$seed" = - || echo "# seed-entries: $seed"
		echo "# entries: $entries"
		echo "# sha256: $digest"
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
ok "built PE fixtures"

cat >"$work/file-list" <<-\EOF
	usr/bin/native.exe
	usr/bin/legacy.exe
	usr/libexec/old32.exe
	clangarm64/bin/Managed.dll
	etc/gitconfig
	usr/share/doc/README
EOF

printf 'amd64\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/baseline-body"
printf 'anycpu\tclangarm64/bin/Managed.dll\tmanaged, architecture-neutral\n' >"$work/exceptions-body"
write_list "$work/baseline" 2 "$work/baseline-body"
write_list "$work/exceptions" - "$work/exceptions-body"

common="--root=$root --file-list=$work/file-list --baseline=$work/baseline --exceptions=$work/exceptions"

echo "# the happy path"

expect_exit 0 "a payload matching the baseline and exceptions passes" $common

grep -q 'Inspected 4 binaries: 1 ARM64, 3 not ARM64' "$work/err" &&
ok "reports how much of the payload is native" ||
not_ok "reports how much of the payload is native" "$work/err"

grep -q 'Baseline holds 2 of a seeded 2 entries' "$work/err" &&
ok "reports the baseline against its seed" ||
not_ok "reports the baseline against its seed" "$work/err"

echo "# new non-ARM64 payload"

make_pe "$root/usr/bin/newcomer.exe" 0x8664
cp "$work/file-list" "$work/file-list-plus"
echo 'usr/bin/newcomer.exe' >>"$work/file-list-plus"
expect_exit 1 "an unlisted non-ARM64 binary fails" \
	--root="$root" --file-list="$work/file-list-plus" \
	--baseline="$work/baseline" --exceptions="$work/exceptions"
grep -q 'amd64	usr/bin/newcomer.exe' "$work/err" &&
ok "names the binary that broke the ratchet" ||
not_ok "names the binary that broke the ratchet" "$work/err"

echo "# ARM64X and ARM64EC are not ARM64"

cp "$work/file-list" "$work/file-list-hybrid"
echo 'clangarm64/bin/hybrid.dll' >>"$work/file-list-hybrid"
expect_exit 1 "an ARM64X binary is not accepted as ARM64" \
	--root="$root" --file-list="$work/file-list-hybrid" \
	--baseline="$work/baseline" --exceptions="$work/exceptions"
grep -q 'arm64x	clangarm64/bin/hybrid.dll' "$work/err" &&
ok "reports the hybrid binary as arm64x" ||
not_ok "reports the hybrid binary as arm64x" "$work/err"

echo "# machine drift on a listed path"

printf 'amd64\tusr/bin/legacy.exe\namd64\tusr/libexec/old32.exe\n' >"$work/drift-body"
write_list "$work/drift" 2 "$work/drift-body"
expect_exit 1 "a listed path whose machine changed fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/drift" --exceptions="$work/exceptions"

echo "# the baseline may only shrink"

printf 'amd64\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\namd64\tusr/bin/newcomer.exe\n' >"$work/grown-body"
write_list "$work/grown" 2 "$work/grown-body"
expect_exit 1 "a baseline larger than its seed fails" \
	--root="$root" --file-list="$work/file-list-plus" \
	--baseline="$work/grown" --exceptions="$work/exceptions"
grep -q 'may only shrink' "$work/err" &&
ok "says why the baseline was rejected" ||
not_ok "says why the baseline was rejected" "$work/err"

echo "# reductions are allowed and measured"

cat >"$work/file-list-reduced" <<-\EOF
	usr/bin/native.exe
	usr/bin/legacy.exe
	clangarm64/bin/Managed.dll
EOF
expect_exit 0 "dropping an emulated binary passes" \
	--root="$root" --file-list="$work/file-list-reduced" \
	--baseline="$work/baseline" --exceptions="$work/exceptions"
grep -q '1 baseline entries are no longer shipped' "$work/err" &&
ok "reports the reduction" ||
not_ok "reports the reduction" "$work/err"
grep -q '# sha256: ' "$work/err" &&
ok "offers the header values for the reduced baseline" ||
not_ok "offers the header values for the reduced baseline" "$work/err"

echo "# the exceptions file cannot be used to bypass the ratchet"

printf 'anycpu\tclangarm64/bin/Managed.dll\tmanaged\namd64\tusr/bin/newcomer.exe\tsneaked in\n' >"$work/bad-exceptions-body"
write_list "$work/bad-exceptions" - "$work/bad-exceptions-body"
expect_exit 1 "a native machine in the exceptions file is refused" \
	--root="$root" --file-list="$work/file-list-plus" \
	--baseline="$work/baseline" --exceptions="$work/bad-exceptions"
grep -q 'native machine type' "$work/err" &&
ok "explains that native machines belong in the baseline" ||
not_ok "explains that native machines belong in the baseline" "$work/err"

echo "# list integrity"

sed 's/^# sha256: .*/# sha256: 0000000000000000000000000000000000000000000000000000000000000000/' \
	<"$work/baseline" >"$work/bad-digest"
expect_exit 1 "a baseline whose digest does not match its body fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-digest" --exceptions="$work/exceptions"

sed 's/^# entries: .*/# entries: 99/' <"$work/baseline" >"$work/bad-count"
expect_exit 1 "a baseline whose entry count does not match its body fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-count" --exceptions="$work/exceptions"

sed 's/^# format-version: .*/# format-version: 99/' <"$work/baseline" >"$work/bad-version"
expect_exit 1 "an unsupported format-version fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/bad-version" --exceptions="$work/exceptions"

grep -v '^# seed-entries' <"$work/baseline" >"$work/no-seed"
expect_exit 1 "a baseline without seed-entries fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/no-seed" --exceptions="$work/exceptions"

echo "# nothing inspected is never success"

: >"$work/empty-list"
expect_exit 1 "an empty payload fails rather than reporting success" \
	--root="$root" --file-list="$work/empty-list" \
	--baseline="$work/baseline" --exceptions="$work/exceptions"

cat >"$work/silent.ps1" <<-\EOF
	# A parser that describes nothing at all.
	exit 0
EOF
expect_exit 1 "a parser that classifies nothing fails rather than reporting success" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/baseline" --exceptions="$work/exceptions" \
	--pe-imports="$work/silent.ps1"
grep -q 'refusing to report success' "$work/err" &&
ok "says it refused to report success" ||
not_ok "says it refused to report success" "$work/err"

cat >"$work/partial.ps1" <<-\EOF
	# A parser that describes only the first binary it is given.
	Write-Output "arm64`tfirst"
	exit 0
EOF
expect_exit 1 "a parser that describes only some binaries fails" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/baseline" --exceptions="$work/exceptions" \
	--pe-imports="$work/partial.ps1"

cat >"$work/broken.ps1" <<-\EOF
	# A parser that fails outright.
	exit 3
EOF
expect_exit 1 "a parser that exits non-zero fails the check" \
	--root="$root" --file-list="$work/file-list" \
	--baseline="$work/baseline" --exceptions="$work/exceptions" \
	--pe-imports="$work/broken.ps1"

echo "# payload names that look like globs"

make_pe "$root/usr/bin/[.exe" 0x8664
cp "$work/file-list" "$work/file-list-glob"
echo 'usr/bin/[.exe' >>"$work/file-list-glob"
printf 'amd64\tusr/bin/[.exe\namd64\tusr/bin/legacy.exe\ni386\tusr/libexec/old32.exe\n' >"$work/glob-body"
write_list "$work/glob-baseline" 3 "$work/glob-body"
expect_exit 0 "a payload named [.exe is handled literally" \
	--root="$root" --file-list="$work/file-list-glob" \
	--baseline="$work/glob-baseline" --exceptions="$work/exceptions"

echo "# the committed lists are well formed"

expect_exit 1 "the committed baseline and exceptions parse, and an empty payload still fails" \
	--root="$root" --file-list="$work/empty-list"

echo "# temporary files are cleaned up"

before=$(ls /tmp/payload-arch.* 2>/dev/null | wc -l)
sh "$checker" $common >/dev/null 2>&1
after=$(ls /tmp/payload-arch.* 2>/dev/null | wc -l)
if test "$before" = "$after"
then
	ok "leaves no temporary files behind"
else
	not_ok "leaves no temporary files behind (had $before, now $after)"
fi

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
