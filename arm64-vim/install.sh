#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

phase=Finalize
root=/
require=
test_mode=
measurement=
package_directory=
while test $# != 0
do
	case "$1" in
	--stage) phase=Stage;;
	--finalize) phase=Finalize;;
	--probe) phase=Probe;;
	--root=*) root=${1#*=};;
	--require-admission) require=t;;
	--test-mode) test_mode=t;;
	--measurement-mode) measurement=t;;
	--package-directory=*) package_directory=${1#*=};;
	*) die "Unknown option: $1";;
	esac
	shift
done

case "${GFW_ARM64_VIM_REQUIRE:-0}" in
0) ;;
1) require=t;;
*) die "GFW_ARM64_VIM_REQUIRE must be 0 or 1";;
esac
case "${GFW_ARM64_VIM_MEASURE:-0}" in
0) ;;
1) measurement=t;;
*) die "GFW_ARM64_VIM_MEASURE must be 0 or 1";;
esac

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the ARM64 Vim directory"
root_win="$(cygpath -aw "$root")" &&
script_win="$(cygpath -aw "$thisdir/install.ps1")" &&
lock_win="$(cygpath -aw "$thisdir/input-lock.json")" &&
scanner_win="$(cygpath -aw "$thisdir/../pe-imports.ps1")" ||
die "Could not resolve ARM64 Vim paths"

set -- -NoProfile -ExecutionPolicy Bypass -File "$script_win" \
	-Phase "$phase" -Root "$root_win" -Lock "$lock_win" \
	-Scanner "$scanner_win"
test -z "$require" || set -- "$@" -RequireAdmission
test -z "$test_mode" || set -- "$@" -TestMode
test -z "$measurement" || set -- "$@" -MeasurementMode
test -z "$package_directory" || {
	package_directory="$(cygpath -aw "$package_directory")" ||
	die "Could not resolve the package directory"
	set -- "$@" -PackageDirectory "$package_directory"
}
powershell.exe "$@"
