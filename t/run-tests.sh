#!/bin/sh

# Run every test in this directory.
#
#   sh t/run-tests.sh
#
# Each test is self-contained and needs no Git SDK: PE fixtures are synthesised
# and the external tools the scripts under test depend on are stubbed.

here="$(cd "$(dirname "$0")" && pwd)"

status=0

run () { # <description> <command...>
	echo "=== $1"
	shift
	if "$@"
	then
		echo
	else
		echo "=== FAILED: $1"
		echo
		status=1
	fi
}

run "pe-imports.ps1" \
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$here/test-pe-imports.ps1"
run "check-for-missing-dlls.sh" \
	sh "$here/test-check-for-missing-dlls.sh"
run "check-payload-architecture.sh" \
	sh "$here/test-payload-architecture.sh"
run "installer/check-release-prerequisites.sh" \
	sh "$here/test-release-prerequisites.sh"

if test $status = 0
then
	echo "All test suites passed."
else
	echo "Some test suites failed."
fi
exit $status
