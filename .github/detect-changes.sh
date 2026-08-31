#!/bin/sh

# Decide which parts of the PR build need to run, from the diff against the
# pull request's base.
#
# This lives outside the workflow so that its failure behaviour can be tested.
# The detection it replaces was fail-open: it asked `test -z "$(git diff ...)"`,
# and a `git` that failed produced empty output, which reads exactly like "no
# relevant change" and quietly switched the gate off. Here a `git` that fails is
# a hard error, and "no relevant change" is a status, not an absence.
#
# Usage: detect-changes.sh --base=<sha> [--git=<command>] [--output=<file>]

die () {
	echo "$*" >&2
	exit 1
}

base=
git_cmd=git
output=${GITHUB_OUTPUT:-/dev/stdout}

while test $# -gt 0
do
	case "$1" in
	--base=*) base="${1#*=}";;
	--git=*) git_cmd="${1#*=}";;
	--output=*) output="${1#*=}";;
	*) die "Unknown option: $1";;
	esac
	shift
done

test -n "$base" ||
die "Usage: $0 --base=<sha> [--git=<command>] [--output=<file>]"

work="$(mktemp -d)" ||
die "Could not create a temporary directory"
trap 'rm -rf "$work"' EXIT

# Run a git command, and treat any failure as a failure rather than as an empty
# result. Returns 0 when the command produced no output, 1 when it produced
# some; anything else exits the script.
git_output () { # <label> <args...>
	label="$1"
	shift

	"$git_cmd" "$@" >"$work/out" 2>"$work/err"
	status=$?

	if test "$status" -ne 0
	then
		echo "::error::git failed with status $status while checking $label" >&2
		sed 's/^/  /' <"$work/err" >&2
		exit 1
	fi

	test -s "$work/out"
}

emit () { # <key> <value>
	printf '%s=%s\n' "$1" "$2" >>"$output"
}

# The SDK artifact tests are needed when the artifact recipe itself moved.
sdk=false
if git_output "create_sdk_artifact" log -L :create_sdk_artifact:please.sh "$base.." --
then
	sdk=true
fi
if git_output "make-file-list.sh" diff "$base.." -- make-file-list.sh
then
	sdk=true
fi
if git_output "please.sh size" diff --numstat "$base.." -- please.sh
then
	changed=$(cut -f 2 <"$work/out" | head -n 1)
	case "$changed" in
	'' | *[!0-9]*) die "Could not read the change count for please.sh";;
	esac
	test "$changed" -lt 200 || sdk=true
fi
test false = "$sdk" || emit test-sdk-artifacts true

# The payload gates are needed when anything they are built out of moved.
#
# make-file-list.sh already reaches these gates through test-sdk-artifacts
# above -- that chain works and is deliberately left alone. Naming it here as
# well is redundancy, not a fix: it means a change to the file list reaches the
# payload gates directly rather than only via the SDK artifact tests.
if git_output "payload gate inputs" diff "$base.." -- \
	check-for-missing-dlls.sh \
	pe-imports.ps1 \
	check-payload-architecture.sh \
	make-file-list.sh \
	arm64-payload-baseline.txt \
	arm64-payload-exceptions.txt \
	arm64-payload-renames.txt
then
	emit check-for-missing-dlls true
fi
