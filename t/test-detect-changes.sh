#!/bin/sh

# Tests for .github/detect-changes.sh.
#
# Run: sh t/test-detect-changes.sh
#
# The detection this replaces was fail-open: `test -z "$(git diff ...)"` reads a
# failed `git` and a clean tree identically, so a broken `git` silently switched
# the payload gates off. These tests hold that shut.

here="$(cd "$(dirname "$0")" && pwd)"
top="$(dirname "$here")"
detect="$top/.github/detect-changes.sh"

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

run () { # <git-stub> [extra args...]
	stub="$1"
	shift
	: >"$work/out"
	sh "$detect" --base=deadbeef --git="$stub" --output="$work/out" "$@" \
		>"$work/stdout" 2>"$work/stderr"
}

expect_exit () { # <expected> <description> <git-stub>
	expected="$1"
	what="$2"

	run "$3"
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$what"
	else
		not_ok "$what (expected exit $expected, got $actual)" "$work/stderr"
	fi
}

emitted () { # <key> <description>
	if grep -q "^$1=true$" "$work/out"
	then
		ok "$2"
	else
		not_ok "$2" "$work/out"
	fi
}

not_emitted () { # <key> <description>
	if grep -q "^$1=" "$work/out"
	then
		not_ok "$2" "$work/out"
	else
		ok "$2"
	fi
}

# A git that reports no changes anywhere.
cat >"$work/git-clean" <<-\EOF
	#!/bin/sh
	exit 0
EOF

# A git that reports a change to whatever it is asked about.
cat >"$work/git-dirty" <<-\EOF
	#!/bin/sh
	case " $* " in
	*--numstat*) echo "3	4	please.sh";;
	*) echo "some change";;
	esac
	exit 0
EOF

# A git that fails, the way a broken checkout or a bad ref does.
cat >"$work/git-broken" <<-\EOF
	#!/bin/sh
	echo "fatal: bad revision 'deadbeef..'" >&2
	exit 128
EOF

# A git that fails only for the payload-gate query, so the failure cannot be
# masked by the earlier queries succeeding.
cat >"$work/git-broken-late" <<-\EOF
	#!/bin/sh
	case " $* " in
	*check-payload-architecture.sh*)
		echo "fatal: unable to read tree" >&2
		exit 128
		;;
	esac
	exit 0
EOF

# A git whose numstat is not a number.
cat >"$work/git-odd-numstat" <<-\EOF
	#!/bin/sh
	case " $* " in
	*--numstat*) echo "-	-	please.sh";;
	*) exit 0;;
	esac
	exit 0
EOF

chmod +x "$work"/git-*

echo "# a clean tree asks for nothing"

expect_exit 0 "a clean tree succeeds" "$work/git-clean"
not_emitted test-sdk-artifacts "does not ask for the SDK artifact tests"
not_emitted check-for-missing-dlls "does not ask for the payload gates"

echo "# a relevant change asks for the right gates"

expect_exit 0 "a dirty tree succeeds" "$work/git-dirty"
emitted test-sdk-artifacts "asks for the SDK artifact tests"
emitted check-for-missing-dlls "asks for the payload gates"

echo "# a git that fails is an error, not an empty result"

expect_exit 1 "a git that fails outright fails the detection" "$work/git-broken"
not_emitted check-for-missing-dlls "emits no flag when git failed"
if grep -q 'git failed with status 128' "$work/stderr"
then
	ok "reports the status git exited with"
else
	not_ok "reports the status git exited with" "$work/stderr"
fi

expect_exit 1 "a git that fails only on the payload query still fails" "$work/git-broken-late"
if grep -q 'payload gate inputs' "$work/stderr"
then
	ok "names the query that failed"
else
	not_ok "names the query that failed" "$work/stderr"
fi

expect_exit 1 "an unreadable change count fails rather than being assumed small" "$work/git-odd-numstat"

echo "# usage"

sh "$detect" --git=true --output="$work/out" >/dev/null 2>&1
test $? = 1 &&
ok "a missing --base is a usage error" ||
not_ok "a missing --base is a usage error"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
