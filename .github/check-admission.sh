#!/bin/sh

# Decide whether the pull-request checks admitted the change.
#
# GitHub gives a matrix job a suffixed check name per variant, so there is no
# stable name for branch protection to require, and a name that only exists
# when a variant is skipped can be satisfied by that skip. This script backs a
# single non-matrix job that runs with `if: always()` and turns the results of
# every leg into one verdict.
#
# The results are read from the environment rather than the command line so the
# workflow can hand them over verbatim:
#
#   DETERMINE  determine-packages
#   UNIT       unit-tests
#   PACKAGES   build-packages
#   ARTIFACTS  build-artifacts
#   SDK        sdk-artifacts
#   DLLS       check-for-missing-dlls
#
# Jobs with no `if:` must have run, so anything other than `success` -- failure,
# cancellation, an unexpected skip, or no result at all -- is a rejection. Jobs
# gated on determine-packages' output may legitimately be skipped, but may not
# fail or be cancelled. determine-packages itself is unconditional, so if it
# fails the conditional legs skip and the first loop is what rejects the run.

die () {
	echo "::error::$*" >&2
	status=1
}

status=0

for required in DETERMINE:determine-packages UNIT:unit-tests
do
	name="${required#*:}"
	eval "result=\${${required%%:*}:-}"
	test "$result" = success ||
	die "$name did not succeed (result: ${result:-<none>})"
done

for conditional in \
	PACKAGES:build-packages \
	ARTIFACTS:build-artifacts \
	SDK:sdk-artifacts \
	DLLS:check-for-missing-dlls
do
	name="${conditional#*:}"
	eval "result=\${${conditional%%:*}:-}"
	case "$result" in
	success | skipped) ;;
	*) die "$name did not succeed (result: ${result:-<none>})";;
	esac
done

test $status = 0 || exit 1

echo "All required legs succeeded or were legitimately skipped."
