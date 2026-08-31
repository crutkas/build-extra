#!/bin/sh

# Build an installer that is deliberately unsigned, and accept only the exact
# outcome that means "built, but not releasable".
#
# installer/release.sh exits 3 rather than 0 when --allow-unsigned was given, so
# that no ordinary `release.sh && promote` path can continue. A caller that
# genuinely wants an unsigned test build therefore has to name that code, which
# is what this script does -- and it is the only thing in the tree that does.
# It then insists on the sidecar and on the promotion gate rejecting the result,
# so an unsigned build cannot be mistaken for a releasable one further down the
# line.
#
# Usage: expect-unsigned-test-build.sh [--release-sh=<path>] --output=<dir> <version>

UNSIGNED_EXIT_CODE=3

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine script directory"

release_sh="$thisdir/release.sh"
output_directory=

# Rebuild the argument list: drop our own option, remember --output, and add the
# opt-out that release.sh requires. Rotating through the positional parameters
# keeps arguments intact rather than flattening them into a string.
count=$#
i=0
while test $i -lt $count
do
	arg="$1"
	shift
	i=$(($i + 1))

	case "$arg" in
	--release-sh=*)
		release_sh="${arg#*=}"
		continue
		;;
	--output=*)
		output_directory="${arg#*=}"
		;;
	esac

	set -- "$@" "$arg"
done
set -- --allow-unsigned "$@"

test -n "$output_directory" ||
die "Usage: $0 [--release-sh=<path>] --output=<dir> <version>"

test -d "$output_directory" ||
die "Not a directory: $output_directory"

status=0
sh "$release_sh" "$@" || status=$?

test "$status" = "$UNSIGNED_EXIT_CODE" || {
	if test "$status" = 0
	then
		die "release.sh reported success for an unsigned build; it must exit $UNSIGNED_EXIT_CODE so that a release path stops"
	fi
	die "release.sh exited $status, but an unsigned test build must exit exactly $UNSIGNED_EXIT_CODE"
}

found=0
for installer in "$output_directory"/*.exe
do
	test -f "$installer" || continue
	found=$(($found + 1))

	test -f "$installer.UNSIGNED" ||
	die "$installer has no .UNSIGNED sidecar, so nothing downstream would know it is not releasable"

	# The marker has to belong to this artifact, not merely sit beside it.
	named="$(sed -n 's/^artifact: //p' "$installer.UNSIGNED" | head -n 1)"
	recorded="$(sed -n 's/^sha256: //p' "$installer.UNSIGNED" | head -n 1)"
	actual="$(sha256sum <"$installer" | sed 's/ .*//')"

	test "$named" = "${installer##*/}" ||
	die "$installer.UNSIGNED names '$named', not '${installer##*/}'"

	test "$recorded" = "$actual" ||
	die "$installer.UNSIGNED records '$recorded' but $installer hashes to '$actual'"

	if sh "$thisdir/check-release-prerequisites.sh" promotable "$installer" >/dev/null 2>&1
	then
		die "$installer was accepted for promotion despite being unsigned"
	fi

	echo "$installer is present, bound to its unsigned marker, and refused by the promotion gate." >&2
done

test "$found" -gt 0 ||
die "No installer was produced in $output_directory"
