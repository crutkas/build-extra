#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

test aarch64 = "$ARCH" || exit 0

case "$1" in
--validate|"") phase=validate;;
--materialize) phase=materialize;;
*) die "Unknown native ARM64 shell phase: $1";;
esac

case "${GFW_ARM64_NATIVE_SHELL:-0}" in
0) exit 0;;
preview)
	mode=Preview
	;;
1)
	mode=Final
	;;
*)
	die "GFW_ARM64_NATIVE_SHELL must be 0, preview, or 1"
	;;
esac

sdk_root="$(cygpath -aw /)" ||
die "Could not resolve the SDK root"
case "$(printf '%s' "$sdk_root" | tr A-Z a-z)" in
c:\\msys64|c:\\msys64\\*)
	die "The shared C:\\msys64 root is a forbidden native shell input"
	;;
esac

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the native ARM64 shell directory"
script="$(cygpath -aw "$thisdir/install.ps1")" ||
die "Could not resolve the native ARM64 shell validator"
lock="$(cygpath -aw "$thisdir/locks/native-shell-closure-v1.json")" ||
die "Could not resolve the native ARM64 shell lock"

if test Preview = "$mode" && test validate = "$phase"
then
	pwsh.exe -NoProfile -ExecutionPolicy Bypass \
		-File "$script" -Mode Preview -Lock "$lock" -Quiet ||
	die "Could not validate the native ARM64 shell lock"
	exit 0
fi

if test validate = "$phase"
then
	pwsh.exe -NoProfile -ExecutionPolicy Bypass \
		-File "$script" -Mode Final -Lock "$lock" -LockOnly -Quiet ||
	die "The native ARM64 shell closure is incomplete"
	exit 0
fi

test -n "$GFW_ARM64_NATIVE_SHELL_CACHE" ||
die "GFW_ARM64_NATIVE_SHELL_CACHE is required"
test -n "$GFW_ARM64_NATIVE_SHELL_ROOT" ||
die "GFW_ARM64_NATIVE_SHELL_ROOT is required"
test -n "$GFW_ARM64_NATIVE_SHELL_WORK" ||
die "GFW_ARM64_NATIVE_SHELL_WORK is required"
test -n "$GFW_ARM64_NATIVE_SHELL_VALIDATOR" ||
die "GFW_ARM64_NATIVE_SHELL_VALIDATOR is required"
test -n "$GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT" ||
die "GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT is required"
if test -n "$GFW_ARM64_NATIVE_SHELL_ASSEMBLY_EVIDENCE" ||
	test -n "$GFW_ARM64_NATIVE_SHELL_RUNTIME_EVIDENCE"
then
	test -n "$GFW_ARM64_NATIVE_SHELL_ASSEMBLY_EVIDENCE" &&
	test -n "$GFW_ARM64_NATIVE_SHELL_RUNTIME_EVIDENCE" ||
	die "GFW_ARM64_NATIVE_SHELL_ASSEMBLY_EVIDENCE and GFW_ARM64_NATIVE_SHELL_RUNTIME_EVIDENCE must be supplied together"
fi
test -n "$GFW_ARM64_NATIVE_SHELL_PROVENANCE" ||
die "GFW_ARM64_NATIVE_SHELL_PROVENANCE is required"
test -n "$GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST" ||
die "GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST is required"
test -n "$GFW_ARM64_NATIVE_SHELL_REPORT" ||
die "GFW_ARM64_NATIVE_SHELL_REPORT is required"

root="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_ROOT")" &&
cache="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_CACHE")" &&
work="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_WORK")" &&
validator="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_VALIDATOR")" &&
provenance="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_PROVENANCE")" &&
payload="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_PAYLOAD_MANIFEST")" &&
report="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_REPORT")" ||
die "Could not resolve native ARM64 shell integration paths"

set -- pwsh.exe -NoProfile -ExecutionPolicy Bypass \
	-File "$script" \
	-Mode "$mode" \
	-Lock "$lock" \
	-Root "$root" \
	-Cache "$cache" \
	-Work "$work" \
	-Validator "$validator" \
	-AssemblerCommit "$GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT" \
	-Provenance "$provenance" \
	-PayloadManifest "$payload" \
	-Report "$report"
if test -n "$GFW_ARM64_NATIVE_SHELL_ASSEMBLY_EVIDENCE"
then
	assembly_evidence="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_ASSEMBLY_EVIDENCE")" &&
	runtime_evidence="$(cygpath -aw "$GFW_ARM64_NATIVE_SHELL_RUNTIME_EVIDENCE")" ||
	die "Could not resolve native ARM64 shell runtime evidence paths"
	set -- "$@" \
		-AssemblyEvidence "$assembly_evidence" \
		-RuntimeEvidence "$runtime_evidence"
fi

"$@" -DownloadResolved ||
die "Could not install the native ARM64 shell closure"
