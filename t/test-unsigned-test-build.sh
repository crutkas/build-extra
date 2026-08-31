#!/bin/sh

# Tests for installer/expect-unsigned-test-build.sh, the only caller allowed to
# accept an unsigned installer build.
#
# Run: sh t/test-unsigned-test-build.sh
#
# installer/release.sh needs a full SDK, so it is stubbed here. What is under
# test is the contract between the two: an unsigned build must finish with a
# distinct non-zero status and a sidecar, and anything else -- including plain
# success -- must be refused.

here="$(cd "$(dirname "$0")" && pwd)"
top="$(dirname "$here")"
accepter="$top/installer/expect-unsigned-test-build.sh"

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

said () { # <pattern> <description>
	if grep -q "$1" "$work/err"
	then
		ok "$2"
	else
		not_ok "$2" "$work/err"
	fi
}

# Build a stub release.sh with a chosen exit code, and a chosen set of outputs.
make_release () { # <exit-code> <make-exe:yes|no> <sidecar:none|bound|wrong-name|wrong-digest|bare>
	cat >"$work/release.sh" <<-EOF
		#!/bin/sh
		out=
		for a
		do
			case "\$a" in
			--output=*) out="\${a#*=}";;
			esac
		done
		test -n "\$out" || { echo "no --output" >&2; exit 1; }
		exe="\$out/Git-0-test-arm64.exe"
		test "$2" != yes || echo installer >"\$exe"
		digest=
		test ! -f "\$exe" || digest="\$(sha256sum <"\$exe" | sed 's/ .*//')"
		case "$3" in
		bound)
			printf '# unsigned\nartifact: Git-0-test-arm64.exe\nsha256: %s\n' "\$digest" >"\$exe.UNSIGNED"
			;;
		wrong-name)
			printf '# unsigned\nartifact: Something-Else.exe\nsha256: %s\n' "\$digest" >"\$exe.UNSIGNED"
			;;
		wrong-digest)
			printf '# unsigned\nartifact: Git-0-test-arm64.exe\nsha256: %s\n' \
				0000000000000000000000000000000000000000000000000000000000000000 >"\$exe.UNSIGNED"
			;;
		bare)
			printf '# unsigned\n' >"\$exe.UNSIGNED"
			;;
		esac
		exit $1
	EOF
}

run_accepter () {
	rm -rf "$work/out"
	mkdir -p "$work/out"
	sh "$accepter" --release-sh="$work/release.sh" --output="$work/out" 0-test \
		>"$work/stdout" 2>"$work/err"
}

expect_exit () { # <expected> <description>
	expected="$1"

	run_accepter
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$2"
	else
		not_ok "$2 (expected exit $expected, got $actual)" "$work/err"
	fi
}

echo "# the one accepted outcome"

make_release 3 yes bound
expect_exit 0 "exit 3 with an installer and a bound sidecar is accepted"
said 'refused by the promotion gate' "confirms the promotion gate refuses the result"

echo "# everything else is refused"

make_release 0 yes bound
expect_exit 1 "plain success is refused, because a release path would have continued"
said 'must exit 3' "explains that an unsigned build has to be distinguishable"

make_release 1 yes bound
expect_exit 1 "an ordinary failure is refused"

make_release 2 yes bound
expect_exit 1 "a usage failure is refused"

make_release 3 yes none
expect_exit 1 "exit 3 without a sidecar is refused"
said 'no .UNSIGNED sidecar' "says the sidecar is missing"

make_release 3 no none
expect_exit 1 "exit 3 with no installer at all is refused"
said 'No installer was produced' "says nothing was built"

echo "# the sidecar has to belong to the artifact"

make_release 3 yes wrong-name
expect_exit 1 "a sidecar naming a different artifact is refused"
said 'names' "says the sidecar names something else"

make_release 3 yes wrong-digest
expect_exit 1 "a sidecar whose digest does not match the artifact is refused"
said 'hashes to' "says the digest does not match"

make_release 3 yes bare
expect_exit 1 "a sidecar with no identity at all is refused"

echo "# the accepted status is named in exactly one place"

# If this ever grows a second caller, the opt-out has stopped being narrow.
callers=$(grep -rl 'UNSIGNED_EXIT_CODE' "$top/installer" "$top/.github" \
	--include=*.sh --include=*.yml 2>/dev/null | LC_ALL=C sort | tr '\n' ' ')
expected_callers="$top/installer/expect-unsigned-test-build.sh $top/installer/release.sh "
if test "$callers" = "$expected_callers"
then
	ok "only release.sh defines the code and only the accepter names it"
else
	not_ok "only release.sh defines the code and only the accepter names it (found: $callers)"
fi

echo "# the arguments reach release.sh intact"

# A stub that records exactly what it was invoked with, so a silently dropped
# or reordered option cannot pass unnoticed.
cat >"$work/release.sh" <<-EOF
	#!/bin/sh
	: >"$work/argv"
	out=
	for a
	do
		printf '%s\n' "\$a" >>"$work/argv"
		case "\$a" in
		--output=*) out="\${a#*=}";;
		esac
	done
	exe="\$out/Git-0-test-arm64.exe"
	echo installer >"\$exe"
	printf '# unsigned\nartifact: Git-0-test-arm64.exe\nsha256: %s\n' \
		"\$(sha256sum <"\$exe" | sed 's/ .*//')" >"\$exe.UNSIGNED"
	exit 3
EOF

rm -rf "$work/out"
mkdir -p "$work/out"
sh "$accepter" --release-sh="$work/release.sh" --output="$work/out" \
	--include-self-check --window-title-version=1.2.3 0-test \
	>"$work/stdout" 2>"$work/err"
accept_status=$?

test "$accept_status" = 0 &&
ok "the accepter succeeds when it forwards a fuller argument list" ||
not_ok "the accepter succeeds when it forwards a fuller argument list" "$work/err"

grep -q -x -F -- '--allow-unsigned' "$work/argv" &&
ok "the opt-out release.sh requires is added" ||
not_ok "the opt-out release.sh requires is added" "$work/argv"

grep -q -- '--release-sh=' "$work/argv" &&
not_ok "the accepter's own option is not forwarded" "$work/argv" ||
ok "the accepter's own option is not forwarded"

printf -- '--allow-unsigned\n--output=%s\n--include-self-check\n--window-title-version=1.2.3\n0-test\n' \
	"$work/out" >"$work/argv-expected"
if cmp -s "$work/argv" "$work/argv-expected"
then
	ok "every other argument is forwarded once, in order"
else
	not_ok "every other argument is forwarded once, in order" "$work/argv"
fi

echo "# no build path can finish unsigned without marking and exiting 3"

release="$top/installer/release.sh"

# The test-installer path used to `exec` the freshly built installer, which
# replaced the shell and skipped the marker and the exit status entirely.
if grep -q 'exec "\$TEMP/\$version.exe"' "$release"
then
	not_ok "the test-installer path no longer execs past the unsigned handling"
else
	ok "the test-installer path no longer execs past the unsigned handling"
fi

marks=$(grep -c '^[ 	]*mark_unsigned ' "$release")
test "$marks" -ge 2 &&
ok "both the test-installer and the release path mark an unsigned build" ||
not_ok "both the test-installer and the release path mark an unsigned build (found $marks)"

exits=$(grep -c 'exit \$UNSIGNED_EXIT_CODE' "$release")
test "$exits" -ge 2 &&
ok "both paths exit with the unsigned status" ||
not_ok "both paths exit with the unsigned status (found $exits)"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
