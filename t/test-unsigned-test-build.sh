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
make_release () { # <exit-code> <make-exe:yes|no> <make-sidecar:yes|no>
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
		test "$2" != yes || echo installer >"\$out/Git-0-test-arm64.exe"
		test "$3" != yes || echo unsigned >"\$out/Git-0-test-arm64.exe.UNSIGNED"
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

make_release 3 yes yes
expect_exit 0 "exit 3 with an installer and a sidecar is accepted"
said 'refused by the promotion gate' "confirms the promotion gate refuses the result"

echo "# everything else is refused"

make_release 0 yes yes
expect_exit 1 "plain success is refused, because a release path would have continued"
said 'must exit 3' "explains that an unsigned build has to be distinguishable"

make_release 1 yes yes
expect_exit 1 "an ordinary failure is refused"

make_release 2 yes yes
expect_exit 1 "a usage failure is refused"

make_release 3 yes no
expect_exit 1 "exit 3 without a sidecar is refused"
said 'no .UNSIGNED sidecar' "says the sidecar is missing"

make_release 3 no no
expect_exit 1 "exit 3 with no installer at all is refused"
said 'No installer was produced' "says nothing was built"

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

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
