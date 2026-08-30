#!/bin/sh

# Tests for the deterministic, fail-closed parts of check-for-missing-dlls.sh.
#
# Run: sh t/test-check-for-missing-dlls.sh
#
# The script under test is copied into a sandbox next to a stub file list and a
# stub PE parser, and is pointed at a stub objdump through $OBJDUMP. That makes
# it possible to drive the cases that matter -- a translated diagnostic, a
# parser that describes nothing, a parser that describes only some inputs --
# without an SDK.

here="$(cd "$(dirname "$0")" && pwd)"
top="$(dirname "$here")"

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

sandbox="$work/sandbox"
mkdir -p "$sandbox"
cp "$top/check-for-missing-dlls.sh" "$sandbox/"

cat >"$sandbox/make-file-list.sh" <<-\EOF
	#!/bin/sh
	echo usr/bin/tool.exe
	echo usr/bin/msys-2.0.dll
EOF
chmod +x "$sandbox/make-file-list.sh"

# An objdump that describes everything it is given.
cat >"$work/objdump-full" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		case "$f" in
		*tool.exe) printf '\tDLL Name: msys-2.0.dll\n';;
		*msys-2.0.dll) printf '\tDLL Name: KERNEL32.dll\n';;
		esac
	done
EOF

# An objdump that cannot read one file and says so in a language nobody is
# parsing. It still exits non-zero, as the real one does.
cat >"$work/objdump-foreign" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		case "$f" in
		*tool.exe)
			echo "objdump: $f: Dateiformat nicht erkannt" >&2
			continue
			;;
		esac
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		printf '\tDLL Name: KERNEL32.dll\n'
	done
	exit 1
EOF

# An objdump that describes nothing at all.
cat >"$work/objdump-silent" <<-\EOF
	#!/bin/sh
	echo "objdump: something went wrong" >&2
	exit 1
EOF

chmod +x "$work/objdump-full" "$work/objdump-foreign" "$work/objdump-silent"

# A PE parser that describes every path it is handed.
cat >"$work/pe-cover-all.ps1" <<-\EOF
	param([switch]$Machine, [string]$RequireMachine, [string]$AllowList, [string]$PathFile,
	      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path)
	foreach ($p in @(Get-Content -LiteralPath $PathFile)) {
	    Write-Output "${p}:"
	    if ($p -match 'tool\.exe$') {
	        Write-Output "$([char]9)DLL Name: msys-2.0.dll"
	    } else {
	        Write-Output "$([char]9)DLL Name: KERNEL32.dll"
	    }
	}
	exit 0
EOF

# A PE parser that quietly describes nothing.
cat >"$work/pe-silent.ps1" <<-\EOF
	param([switch]$Machine, [string]$RequireMachine, [string]$AllowList, [string]$PathFile,
	      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path)
	exit 0
EOF

# A PE parser that describes only the first path it is handed.
cat >"$work/pe-partial.ps1" <<-\EOF
	param([switch]$Machine, [string]$RequireMachine, [string]$AllowList, [string]$PathFile,
	      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path)
	$all = @(Get-Content -LiteralPath $PathFile)
	Write-Output "$($all[0]):"
	Write-Output "$([char]9)DLL Name: KERNEL32.dll"
	exit 0
EOF

# A PE parser that fails.
cat >"$work/pe-fail.ps1" <<-\EOF
	param([switch]$Machine, [string]$RequireMachine, [string]$AllowList, [string]$PathFile,
	      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path)
	Write-Error "cannot parse"
	exit 1
EOF

run_check () { # <objdump> <pe-imports> -> exit code, output in $work/out and $work/err
	cp "$2" "$sandbox/pe-imports.ps1"
	(
		cd "$sandbox" &&
		MSYSTEM=CLANGARM64 OBJDUMP="$1" sh ./check-for-missing-dlls.sh
	) >"$work/out" 2>"$work/err"
}

expect_exit () { # <expected> <description> <objdump> <pe-imports>
	expected="$1"
	what="$2"

	run_check "$3" "$4"
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$what"
	else
		not_ok "$what (expected exit $expected, got $actual)" "$work/err"
	fi
}

echo "# the control case"

expect_exit 0 "an objdump that describes everything passes" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

echo "# independence from the wording of objdump diagnostics"

expect_exit 0 "a translated 'file format not recognized' still reaches the PE parser" \
	"$work/objdump-foreign" "$work/pe-cover-all.ps1"

# Prove the routing rather than inferring it: with a parser that describes
# nothing, the same run has to fail.
expect_exit 1 "a binary objdump skipped is never left uninspected" \
	"$work/objdump-foreign" "$work/pe-silent.ps1"
grep -q 'Inspected 1 of 2 binaries' "$work/err" &&
ok "counts what was actually inspected" ||
not_ok "counts what was actually inspected" "$work/err"
grep -q 'objdump did not describe: /usr/bin/tool.exe' "$work/err" &&
ok "names the binary that went uninspected" ||
not_ok "names the binary that went uninspected" "$work/err"

echo "# zero inspection is never success"

expect_exit 1 "an objdump and a parser that both describe nothing fail" \
	"$work/objdump-silent" "$work/pe-silent.ps1"
grep -q 'Inspected 0 of 2 binaries' "$work/err" &&
ok "reports that nothing at all was inspected" ||
not_ok "reports that nothing at all was inspected" "$work/err"

expect_exit 0 "a parser that covers everything objdump missed passes" \
	"$work/objdump-silent" "$work/pe-cover-all.ps1"

expect_exit 1 "a parser that describes only some of its inputs fails" \
	"$work/objdump-silent" "$work/pe-partial.ps1"

echo "# tool status is never discarded"

expect_exit 1 "a parser that exits non-zero fails the check" \
	"$work/objdump-silent" "$work/pe-fail.ps1"
grep -q 'failed to parse PE imports' "$work/err" &&
ok "says which tool failed" ||
not_ok "says which tool failed" "$work/err"

expect_exit 1 "a missing objdump does not silently produce an empty report" \
	"$work/no-such-objdump" "$work/pe-silent.ps1"

echo "# the missing-DLL detection still works"

cat >"$sandbox/make-file-list.sh" <<-\EOF
	#!/bin/sh
	echo usr/bin/tool.exe
EOF
expect_exit 1 "an import with nothing to satisfy it is still reported" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"
grep -q 'is missing msys-2.0.dll' "$work/err" &&
ok "names the missing DLL" ||
not_ok "names the missing DLL" "$work/err"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
