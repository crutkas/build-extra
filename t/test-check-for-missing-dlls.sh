#!/bin/sh

# Tests for the deterministic, fail-closed parts of check-for-missing-dlls.sh.
#
# Run: sh t/test-check-for-missing-dlls.sh
#
# The script under test is copied into a sandbox next to a stub file list and a
# stub PE parser, and is pointed at a stub objdump through $OBJDUMP. That makes
# it possible to drive the cases that matter -- a translated diagnostic, a
# header printed for a file that then fails to decode, a parser that describes
# nothing -- without an SDK.

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

said () { # <pattern> <description>
	if grep -q "$1" "$work/err"
	then
		ok "$2"
	else
		not_ok "$2" "$work/err"
	fi
}

sandbox="$work/sandbox"
mkdir -p "$sandbox"
cp "$top/check-for-missing-dlls.sh" "$sandbox/"

set_file_list () { # reads the list from stdin
	{
		echo '#!/bin/sh'
		echo 'cat <<"LIST"'
		cat
		echo 'LIST'
	} >"$sandbox/make-file-list.sh"
	chmod +x "$sandbox/make-file-list.sh"
}

set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
EOF

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
		*msys-2.0.dll) printf '\tDLL Name: KERNEL32.dll\n';;
		*) printf '\tDLL Name: msys-2.0.dll\n';;
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

# The dangerous one: a normal-looking header and plausible imports for a file,
# and then a failure while decoding that same file. The import it printed names
# a DLL that is not in the payload, so if any of this output were kept the run
# would report a missing DLL.
cat >"$work/objdump-header-then-error" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		printf '\tDLL Name: ghost-truncated-decode.dll\n'
		case "$f" in
		*tool.exe)
			echo "objdump: $f: error while decoding" >&2
			exit 1
			;;
		esac
	done
EOF

# Exits zero but quietly omits one file entirely.
cat >"$work/objdump-omits-one" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		case "$f" in *tool.exe) continue;; esac
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		printf '\tDLL Name: KERNEL32.dll\n'
	done
EOF

# An objdump that describes nothing at all.
cat >"$work/objdump-silent" <<-\EOF
	#!/bin/sh
	echo "objdump: something went wrong" >&2
	exit 1
EOF

# Records the arguments it was handed, one per line, so the transport can be
# inspected.
cat >"$work/objdump-record" <<-\EOF
	#!/bin/sh
	shift
	: >"$RECORD"
	for f
	do
		printf '%s\n' "$f" >>"$RECORD"
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		case "$f" in
		*msys-2.0.dll) printf '\tDLL Name: KERNEL32.dll\n';;
		*) printf '\tDLL Name: msys-2.0.dll\n';;
		esac
	done
EOF

chmod +x "$work"/objdump-*

pe_parser_preamble='param([switch]$Machine, [string]$RequireMachine, [string]$AllowList, [string]$PathFile,
      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path)'

# A PE parser that describes every path it is handed.
{
	echo "$pe_parser_preamble"
	cat <<-\EOF
		foreach ($p in @(Get-Content -LiteralPath $PathFile)) {
		    Write-Output "${p}:"
		    if ($p -match 'msys-2\.0\.dll$') {
		        Write-Output "$([char]9)DLL Name: KERNEL32.dll"
		    } else {
		        Write-Output "$([char]9)DLL Name: msys-2.0.dll"
		    }
		}
		exit 0
	EOF
} >"$work/pe-cover-all.ps1"

# A PE parser that quietly describes nothing.
{ echo "$pe_parser_preamble"; echo 'exit 0'; } >"$work/pe-silent.ps1"

# A PE parser that describes only the first path it is handed.
{
	echo "$pe_parser_preamble"
	cat <<-\EOF
		$all = @(Get-Content -LiteralPath $PathFile)
		Write-Output "$($all[0]):"
		Write-Output "$([char]9)DLL Name: KERNEL32.dll"
		exit 0
	EOF
} >"$work/pe-partial.ps1"

# A PE parser that emits more headers than it was given inputs.
{
	echo "$pe_parser_preamble"
	cat <<-\EOF
		foreach ($p in @(Get-Content -LiteralPath $PathFile)) {
		    Write-Output "${p}:"
		    Write-Output "$([char]9)DLL Name: KERNEL32.dll"
		}
		Write-Output "C:\extra.dll:"
		exit 0
	EOF
} >"$work/pe-extra.ps1"

# A PE parser that fails.
{ echo "$pe_parser_preamble"; echo 'Write-Error "cannot parse"'; echo 'exit 1'; } >"$work/pe-fail.ps1"

run_check () { # <objdump> <pe-imports>
	cp "$2" "$sandbox/pe-imports.ps1"
	(
		cd "$sandbox" &&
		MSYSTEM=CLANGARM64 OBJDUMP="$1" RECORD="$work/record" \
		sh ./check-for-missing-dlls.sh
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

expect_exit 1 "a binary objdump skipped is never left uninspected" \
	"$work/objdump-foreign" "$work/pe-silent.ps1"
said 'Inspected 0 of 2 binaries' "counts what was actually inspected"

echo "# a header is not proof that a file was decoded"

expect_exit 1 "a header followed by an error is not counted as inspected" \
	"$work/objdump-header-then-error" "$work/pe-silent.ps1"
said 'Inspected 0 of 2 binaries' "discards the whole batch, not just the failing file"

expect_exit 0 "the same run passes once a working parser covers the batch" \
	"$work/objdump-header-then-error" "$work/pe-cover-all.ps1"
if grep -q 'ghost-truncated-decode' "$work/err"
then
	not_ok "the untrusted objdump output is discarded, not merged into the results" "$work/err"
else
	ok "the untrusted objdump output is discarded, not merged into the results"
fi

expect_exit 1 "an objdump that exits zero but omits a file is not trusted either" \
	"$work/objdump-omits-one" "$work/pe-silent.ps1"

expect_exit 0 "and that batch is reparsed natively" \
	"$work/objdump-omits-one" "$work/pe-cover-all.ps1"

echo "# zero inspection is never success"

expect_exit 1 "an objdump and a parser that both describe nothing fail" \
	"$work/objdump-silent" "$work/pe-silent.ps1"
said 'Inspected 0 of 2 binaries' "reports that nothing at all was inspected"

expect_exit 0 "a parser that covers everything objdump missed passes" \
	"$work/objdump-silent" "$work/pe-cover-all.ps1"

expect_exit 1 "a parser that describes only some of its inputs fails" \
	"$work/objdump-silent" "$work/pe-partial.ps1"

expect_exit 1 "a parser that describes more binaries than it was given fails" \
	"$work/objdump-silent" "$work/pe-extra.ps1"

echo "# tool status is never discarded"

expect_exit 1 "a parser that exits non-zero fails the check" \
	"$work/objdump-silent" "$work/pe-fail.ps1"
said 'failed to parse PE imports' "says which tool failed"

expect_exit 1 "a missing objdump is a hard failure, not something to work around" \
	"$work/no-such-objdump" "$work/pe-cover-all.ps1"
said 'objdump not found' "names the tool that is missing"

echo "# parser output has to be import evidence"

{
	echo "$pe_parser_preamble"
	cat <<-\EOF
		foreach ($p in @(Get-Content -LiteralPath $PathFile)) {
		    Write-Output "${p}:"
		    Write-Output "this is not an import line"
		}
		exit 0
	EOF
} >"$work/pe-garbage.ps1"
expect_exit 1 "a parser that emits something other than imports fails" \
	"$work/objdump-silent" "$work/pe-garbage.ps1"
said 'not import evidence' "says the output was not evidence"

echo "# awkward payload names"

set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/[.exe
	usr/bin/with space.exe
	usr/bin/-dash.exe
	usr/bin/msys-2.0.dll
EOF
expect_exit 0 "brackets, spaces and leading dashes survive the argument transport" \
	"$work/objdump-record" "$work/pe-cover-all.ps1"
for awkward in '/usr/bin/[.exe' '/usr/bin/with space.exe' '/usr/bin/-dash.exe'
do
	if grep -q -x -F "$awkward" "$work/record"
	then
		ok "objdump received $awkward intact"
	else
		not_ok "objdump received $awkward intact" "$work/record"
	fi
done

echo "# every candidate in the file list is accounted for"

# A directory name that the per-directory selection cannot match: the `*` is a
# literal here but a repetition operator in the selection's regex, so the
# directory selects none of its own members.
set_file_list <<-\EOF
	usr/li*b/orphan.dll
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
EOF
expect_exit 1 "a directory the selection cannot match is not silently skipped" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"
said 'Selected 2 of 3 binaries' "reconciles what it selected against the file list"

set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
EOF
expect_exit 0 "a duplicated path is not double-counted" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
	etc/gitconfig
EOF
expect_exit 0 "non-binaries in the file list are ignored" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

: >"$work/empty"
set_file_list <"$work/empty"
expect_exit 1 "an empty file list fails rather than reporting success" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

echo "# payload names are matched without regard to case"

# The payload file list is not case-normalised, and this script's only defence
# is that it lowercases the list before matching. Nothing exercised that, so a
# change that dropped the normalisation would leave every mixed-case binary
# silently unexamined while all the reconciliation counts still agreed -- they
# would all have been derived from the same narrowed set.

# A mixed-case library has to satisfy a lowercase binary's import.
set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/MSYS-2.0.DLL
EOF
expect_exit 0 "a mixed-case DLL satisfies an import spelled in lower case" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

# And a payload spelled entirely in upper case still gets inspected, rather
# than being reported as containing no binaries at all.
set_file_list <<-\EOF
	usr/bin/TOOL.EXE
	usr/bin/MSYS-2.0.DLL
EOF
expect_exit 0 "an all-upper-case payload is still inspected" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

set_file_list <<-\EOF
	usr/bin/Tool.Exe
	usr/bin/Msys-2.0.Dll
EOF
expect_exit 0 "a mixed-case payload is still inspected" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"

# The case-folding must not become a way to lose a real missing import: a
# mixed-case binary whose dependency is absent is still a failure.
set_file_list <<-\EOF
	usr/bin/TOOL.EXE
EOF
expect_exit 1 "a mixed-case binary with an unsatisfied import is still reported" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"
said 'is missing msys-2.0.dll' "names the missing DLL for the mixed-case binary"

echo "# the missing-DLL detection still works"

set_file_list <<-\EOF
	usr/bin/tool.exe
EOF
expect_exit 1 "an import with nothing to satisfy it is still reported" \
	"$work/objdump-full" "$work/pe-cover-all.ps1"
said 'is missing msys-2.0.dll' "names the missing DLL"
said '/usr/bin/tool.exe is missing' "attributes it to the file we asked about, not a converted path"

# A payload name containing a space must be attributed to itself, not to
# whichever file happened to be inspected before it.
cat >"$work/objdump-space" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		echo ""
		printf '%s:     file format pei-x86-64\n' "$f"
		echo ""
		case "$f" in
		*"with space.exe") printf '\tDLL Name: only-space-wants-this.dll\n';;
		*) printf '\tDLL Name: KERNEL32.dll\n';;
		esac
	done
EOF
chmod +x "$work/objdump-space"
set_file_list <<-\EOF
	usr/bin/tool.exe
	usr/bin/with space.exe
EOF
expect_exit 1 "an import of a path containing a space is still reported" \
	"$work/objdump-space" "$work/pe-cover-all.ps1"
said '/usr/bin/with space.exe is missing only-space-wants-this.dll' \
	"attributes it to the file with the space, not to the one before it"

echo "# MinGW and MSYS2 binaries are satisfied from different directories"

# MSYSTEM is CLANGARM64 above, so $MINGW_PREFIX is clangarm64.  A MinGW binary
# has to be satisfied out of clangarm64/bin, and an MSYS2 binary out of
# usr/bin; neither may borrow from the other.  Without this the branch that
# selects the satisfying set for MinGW payloads is never exercised, and a
# mutation that collapses the two goes unnoticed.
cat >"$work/objdump-mingw" <<-\EOF
	#!/bin/sh
	shift
	for f
	do
		echo ""
		printf '%s:     file format pei-aarch64-little\n' "$f"
		echo ""
		case "$f" in
		*/clangarm64/bin/git.exe) printf '\tDLL Name: libpcre2-8-0.dll\n';;
		*/usr/bin/tool.exe) printf '\tDLL Name: msys-2.0.dll\n';;
		*) printf '\tDLL Name: KERNEL32.dll\n';;
		esac
	done
EOF
chmod +x "$work/objdump-mingw"

set_file_list <<-\EOF
	clangarm64/bin/git.exe
	clangarm64/bin/libpcre2-8-0.dll
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
EOF
expect_exit 0 "a MinGW binary satisfied from the MinGW bin directory passes" \
	"$work/objdump-mingw" "$work/pe-cover-all.ps1"

# The same import with the library moved into usr/bin must fail: an MSYS2
# directory cannot satisfy a MinGW binary.
set_file_list <<-\EOF
	clangarm64/bin/git.exe
	usr/bin/libpcre2-8-0.dll
	usr/bin/tool.exe
	usr/bin/msys-2.0.dll
EOF
expect_exit 1 "a MinGW binary cannot be satisfied out of usr/bin" \
	"$work/objdump-mingw" "$work/pe-cover-all.ps1"
said '/clangarm64/bin/git.exe is missing libpcre2-8-0.dll' \
	"names the MinGW binary and the library it cannot reach"

# And the converse: an MSYS2 binary cannot borrow from the MinGW directory.
set_file_list <<-\EOF
	clangarm64/bin/msys-2.0.dll
	usr/bin/tool.exe
EOF
expect_exit 1 "an MSYS2 binary cannot be satisfied out of the MinGW bin directory" \
	"$work/objdump-mingw" "$work/pe-cover-all.ps1"
said '/usr/bin/tool.exe is missing msys-2.0.dll' \
	"names the MSYS2 binary and the library it cannot reach"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
