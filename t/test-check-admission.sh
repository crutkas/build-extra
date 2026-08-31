#!/bin/sh

# Tests for .github/check-admission.sh.

top="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' 0

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

# <expected> <description> <determine> <unit> <packages> <artifacts> <sdk> <dlls>
expect_exit () {
	expected="$1"
	what="$2"

	DETERMINE="$3" UNIT="$4" PACKAGES="$5" ARTIFACTS="$6" SDK="$7" DLLS="$8" \
	sh "$top/.github/check-admission.sh" >"$work/out" 2>"$work/err"
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

echo "# a run where everything did its job"

expect_exit 0 "every leg succeeding is admitted" \
	success success success success success success

# The conditional legs are gated on determine-packages' output, so a pull
# request that touches nothing they care about skips them legitimately.
expect_exit 0 "conditional legs that were not needed may be skipped" \
	success success skipped skipped skipped skipped

expect_exit 0 "a mixture of run and skipped conditional legs is admitted" \
	success success success skipped success skipped

echo "# a required leg that did not succeed is never admitted"

expect_exit 1 "a failing unit-tests leg is rejected" \
	success failure skipped skipped skipped skipped
said 'unit-tests did not succeed' "names the leg that failed"

expect_exit 1 "a cancelled unit-tests leg is rejected" \
	success cancelled skipped skipped skipped skipped

# This is the finding this job exists for: a required check whose name only
# appears when the variant is skipped can be satisfied by that skip.
expect_exit 1 "a unit-tests leg that never ran is rejected rather than assumed fine" \
	success skipped skipped skipped skipped skipped
said 'unit-tests did not succeed' "says the leg did not succeed, rather than accepting the skip"

expect_exit 1 "a failing determine-packages is rejected" \
	failure success skipped skipped skipped skipped

expect_exit 1 "a skipped determine-packages is rejected" \
	skipped success skipped skipped skipped skipped

echo "# a conditional leg may skip, but may not fail"

expect_exit 1 "a failing build-packages leg is rejected" \
	success success failure skipped skipped skipped
said 'build-packages did not succeed' "names the conditional leg that failed"

expect_exit 1 "a cancelled build-artifacts leg is rejected" \
	success success skipped cancelled skipped skipped

expect_exit 1 "a failing sdk-artifacts leg is rejected" \
	success success skipped skipped failure skipped

expect_exit 1 "a failing check-for-missing-dlls leg is rejected" \
	success success skipped skipped skipped failure
said 'check-for-missing-dlls did not succeed' "names the payload gate"

echo "# absence is not success"

expect_exit 1 "no results at all is rejected" '' '' '' '' '' ''
said '<none>' "says the result was missing rather than printing nothing"

expect_exit 1 "a missing required result is rejected" \
	success '' skipped skipped skipped skipped

expect_exit 1 "a missing conditional result is rejected" \
	success success '' skipped skipped skipped

# A result GitHub does not currently produce must not fall through to success.
expect_exit 1 "an unrecognised result is rejected" \
	success success neutral skipped skipped skipped

expect_exit 1 "a result that merely contains 'success' is rejected" \
	success success unsuccessful skipped skipped skipped

echo "# every leg is reported, not just the first"

expect_exit 1 "several failures are all rejected" \
	success failure failure failure failure failure
count="$(grep -c 'did not succeed' "$work/err")"
test "$count" -eq 5 &&
ok "reports all five legs that did not succeed" ||
not_ok "reports all five legs that did not succeed (reported $count)" "$work/err"

echo "# the workflow uses this script rather than its own copy"

grep -q 'sh .github/check-admission.sh' "$top/.github/workflows/main.yml" &&
ok "the admission job runs this script" ||
not_ok "the admission job runs this script" /dev/null

# The names this script reads have to be the names the workflow supplies.
for var in DETERMINE UNIT PACKAGES ARTIFACTS SDK DLLS
do
	grep -q "^          $var: " "$top/.github/workflows/main.yml" &&
	ok "the workflow supplies $var" ||
	not_ok "the workflow supplies $var" /dev/null
done

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
