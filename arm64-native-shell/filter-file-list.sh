#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

variant=$1
case "$variant" in
installer|portable|mingit|sdk) ;;
*) die "Unknown native ARM64 shell artifact variant: $variant";;
esac

if test aarch64 != "$ARCH" ||
	{
		test 1 != "${GFW_ARM64_NATIVE_SHELL:-0}" &&
		test preview != "${GFW_ARM64_NATIVE_SHELL:-0}"
	}
then
	cat
	exit
fi

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the native ARM64 shell directory"
script="$(cygpath -aw "$thisdir/filter-file-list.ps1")" &&
lock="$(cygpath -aw "$thisdir/locks/native-shell-closure-v1.json")" ||
die "Could not resolve native ARM64 shell file-list paths"
case "$GFW_ARM64_NATIVE_SHELL" in
preview) mode=Preview;;
1) mode=Final;;
esac

pwsh.exe -NoProfile -ExecutionPolicy Bypass \
	-File "$script" -Variant "$variant" -Lock "$lock" -Mode "$mode" ||
die "Could not reconcile the native ARM64 shell file list"
