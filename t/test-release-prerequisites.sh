#!/bin/sh

# Tests for installer/check-release-prerequisites.sh.
#
# Run: sh t/test-release-prerequisites.sh

here="$(cd "$(dirname "$0")" && pwd)"
top="$(dirname "$here")"
checker="$top/installer/check-release-prerequisites.sh"

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

# Run a check from a given directory, with a given PATH and HOME.
run_check () { # <cwd> <args...>
	cwd="$1"
	shift
	(
		cd "$cwd" &&
		PATH="$stub_path$PATH" HOME="$work/home" GIT_CONFIG_NOSYSTEM=1 \
		sh "$checker" "$@"
	) >"$work/out" 2>"$work/err"
}

expect_exit () { # <expected> <description> <cwd> <args...>
	expected="$1"
	what="$2"
	shift 2

	run_check "$@"
	actual=$?

	if test "$actual" = "$expected"
	then
		ok "$what"
	else
		not_ok "$what (expected exit $expected, got $actual)" "$work/err"
	fi
}

mkdir -p "$work/home" "$work/plain"
stub_path=

echo "# signing"

norepo="$work/plain"
expect_exit 1 "an unconfigured signing helper fails the build" "$norepo" signing
said 'No signing helper is configured' "says what is missing"

expect_exit 3 "--allow-unsigned reports the absence instead of failing" "$norepo" signing --allow-unsigned
said 'UNSIGNED' "warns loudly that the build will be unsigned"

# The opt-out must buy exactly one thing: no other check even accepts it.
expect_exit 2 "--allow-unsigned is not accepted by any other check" "$norepo" openssh-cleanup --allow-unsigned

signed="$work/signed-repo"
mkdir -p "$signed"
(
	cd "$signed" &&
	HOME="$work/home" git init -q . &&
	HOME="$work/home" git config alias.signtool '!true'
) >/dev/null 2>&1 ||
{ echo "Could not prepare the signing fixture repository" >&2; exit 1; }

expect_exit 0 "a configured signing helper satisfies the check" "$signed" signing
expect_exit 0 "--allow-unsigned is harmless when signing is configured" "$signed" signing --allow-unsigned

blank="$work/blank-repo"
mkdir -p "$blank"
(
	cd "$blank" &&
	HOME="$work/home" git init -q . &&
	HOME="$work/home" git config alias.signtool '   '
) >/dev/null 2>&1 ||
{ echo "Could not prepare the whitespace signing fixture" >&2; exit 1; }
expect_exit 1 "a whitespace-only signing helper is treated as unset" "$blank" signing

empty="$work/empty-repo"
mkdir -p "$empty"
(
	cd "$empty" &&
	HOME="$work/home" git init -q . &&
	HOME="$work/home" git config alias.signtool ''
) >/dev/null 2>&1 ||
{ echo "Could not prepare the empty signing fixture" >&2; exit 1; }
expect_exit 1 "an empty signing helper is treated as unset" "$empty" signing

echo "# the Inno Setup compiler"

mkdir -p "$work/iscc-present/InnoSetup"
echo compiler >"$work/iscc-present/InnoSetup/ISCC.exe"
expect_exit 0 "a compiler that is present satisfies the check" "$work/iscc-present" compiler

mkdir -p "$work/iscc-missing"
expect_exit 1 "a missing compiler fails before any work is done" "$work/iscc-missing" compiler
said 'update-inno-setup.sh' "says how to install the compiler"

mkdir -p "$work/iscc-empty/InnoSetup"
: >"$work/iscc-empty/InnoSetup/ISCC.exe"
expect_exit 1 "an empty compiler binary fails" "$work/iscc-empty" compiler

echo "# the promotion gate"

mkdir -p "$work/artifacts"
echo installer >"$work/artifacts/Git-0-test-arm64.exe"
expect_exit 0 "an artifact with no unsigned marker may be promoted" \
	"$norepo" promotable "$work/artifacts/Git-0-test-arm64.exe"

printf 'built unsigned\n' >"$work/artifacts/Git-0-test-arm64.exe.UNSIGNED"
expect_exit 1 "a marker with no identity is refused" \
	"$norepo" promotable "$work/artifacts/Git-0-test-arm64.exe"
said 'does not identify' "says the marker does not identify anything"

digest="$(sha256sum <"$work/artifacts/Git-0-test-arm64.exe" | sed 's/ .*//')"
printf '# unsigned\nartifact: Git-0-test-arm64.exe\nsha256: %s\n' "$digest" \
	>"$work/artifacts/Git-0-test-arm64.exe.UNSIGNED"
expect_exit 1 "an artifact with a bound unsigned marker is refused" \
	"$norepo" promotable "$work/artifacts/Git-0-test-arm64.exe"
said 'must not be promoted' "says why it was refused"

printf '# unsigned\nartifact: Other.exe\nsha256: %s\n' "$digest" \
	>"$work/artifacts/Git-0-test-arm64.exe.UNSIGNED"
expect_exit 1 "a marker naming a different artifact is refused" \
	"$norepo" promotable "$work/artifacts/Git-0-test-arm64.exe"
said "belongs to" "says the marker belongs to something else"

printf '# unsigned\nartifact: Git-0-test-arm64.exe\nsha256: %s\n' \
	0000000000000000000000000000000000000000000000000000000000000000 \
	>"$work/artifacts/Git-0-test-arm64.exe.UNSIGNED"
expect_exit 1 "a marker whose digest does not match the artifact is refused" \
	"$norepo" promotable "$work/artifacts/Git-0-test-arm64.exe"
said 'hashes to' "says the artifact does not match the marker"

expect_exit 1 "a missing artifact is refused rather than assumed fine" \
	"$norepo" promotable "$work/artifacts/no-such.exe"

echo "# openssh cleanup data"

expect_exit 1 "a missing pacman fails rather than silently skipping the cleanup" "$norepo" openssh-cleanup
grep -q 'pacman is required' "$work/err" &&
ok "says why it failed" ||
not_ok "says why it failed" "$work/err"

make_pacman () { # <body>
	mkdir -p "$work/bin"
	{
		echo '#!/bin/sh'
		cat
	} >"$work/bin/pacman"
	chmod +x "$work/bin/pacman"
	cp "$work/bin/pacman" "$work/bin/pacman.exe"
	stub_path="$work/bin:"
}

make_pacman <<-\EOF
	echo "openssh /usr/bin/ssh.exe"
	echo "openssh /usr/bin/scp.exe"
	echo "openssh /usr/share/"
EOF
expect_exit 0 "a pacman that reports files satisfies the check" "$norepo" openssh-cleanup
printf 'usr/bin/scp.exe\nusr/bin/ssh.exe\n' >"$work/expected-openssh"
if cmp -s "$work/out" "$work/expected-openssh"
then
	ok "prints the owned files, sorted and relative"
else
	not_ok "prints the owned files, sorted and relative" "$work/out"
fi

make_pacman <<-\EOF
	echo "openssh /usr/bin/ssh.exe"
	echo "openssh /usr/bin/ssh_config"
	echo "openssh /usr/bin/ssh-add.exe"
	echo "openssh /usr/bin/sshd.exe"
EOF
(
	cd "$norepo" &&
	PATH="$stub_path$PATH" HOME="$work/home" LC_ALL=en_US.UTF-8 \
	sh "$checker" openssh-cleanup
) >"$work/out" 2>"$work/err"
printf 'usr/bin/ssh-add.exe\nusr/bin/ssh.exe\nusr/bin/ssh_config\nusr/bin/sshd.exe\n' >"$work/expected-c-order"
# installer/release.sh feeds this into `comm` against a list it sorts itself,
# so the collation has to be C regardless of the ambient locale.
if cmp -s "$work/out" "$work/expected-c-order"
then
	ok "sorts in C collation even under a locale that would order differently"
else
	not_ok "sorts in C collation even under a locale that would order differently" "$work/out"
fi

make_pacman <<-\EOF
	echo "error: package 'openssh' was not found" >&2
	exit 1
EOF
expect_exit 1 "a pacman that reports no files fails rather than producing an empty cleanup" "$norepo" openssh-cleanup
grep -q 'owns no files' "$work/err" &&
ok "says the cleanup data would have been empty" ||
not_ok "says the cleanup data would have been empty" "$work/err"

stub_path=

echo "# Inno Setup diagnostics"

known="$top/installer/iscc-known-warnings.txt"

cat >"$work/clean.log" <<-\EOF
	Inno Setup 7 Command-Line Compiler
	Successful compile (12.345 sec). Resulting Setup program filename is:
	D:\out\Git-0-test-arm64.exe
EOF
expect_exit 0 "a clean log passes" "$norepo" iscc-log "$work/clean.log" --known-warnings="$known"

cat >"$work/warn.log" <<-\EOF
	Inno Setup 7 Command-Line Compiler
	Warning: Something nobody has looked at yet.
	Successful compile (12.345 sec). Resulting Setup program filename is:
EOF
expect_exit 1 "an unreviewed warning fails the build" "$norepo" iscc-log "$work/warn.log" --known-warnings="$known"
grep -q 'Something nobody has looked at yet' "$work/err" &&
ok "prints the diagnostic instead of leaving it in the log" ||
not_ok "prints the diagnostic instead of leaving it in the log" "$work/err"

cat >"$work/error.log" <<-\EOF
	Inno Setup 7 Command-Line Compiler
	Error on line 57 in install.iss: Value of [Setup] section directive is invalid.
EOF
expect_exit 1 "an error fails the build" "$norepo" iscc-log "$work/error.log" --known-warnings="$known"

# The wording comes from ISCmplr.dll:
# `Architecture identifier "%s" is deprecated. Substituting "%s", ...`
cat >"$work/deprecated.log" <<-\EOF
	Inno Setup 7 Command-Line Compiler
	Warning: Architecture identifier "x64" is deprecated. Substituting "x64os", but note that "x64compatible" is preferred in most cases. See the "Architecture Identifiers" topic in help file for more information.
	Successful compile (12.345 sec). Resulting Setup program filename is:
EOF
expect_exit 0 "the reviewed x64 deprecation warning is accepted" "$norepo" iscc-log "$work/deprecated.log" --known-warnings="$known"
grep -q 'Architecture identifier' "$work/err" &&
ok "still shows the reviewed warning rather than hiding it" ||
not_ok "still shows the reviewed warning rather than hiding it" "$work/err"

expect_exit 1 "without a known-warnings file even a reviewed warning fails" "$norepo" iscc-log "$work/deprecated.log"

# A typo in the reviewed list must not admit everything: grep exits 2 on a bad
# pattern, which looks just like "nothing selected" if the status is ignored.
printf '# reviewed\n^Warning: \\(unclosed\n' >"$work/broken-patterns.txt"
expect_exit 1 "a malformed reviewed pattern fails instead of admitting every diagnostic" \
	"$norepo" iscc-log "$work/warn.log" --known-warnings="$work/broken-patterns.txt"
grep -q 'Could not apply the patterns' "$work/err" &&
ok "says the pattern list could not be applied" ||
not_ok "says the pattern list could not be applied" "$work/err"

expect_exit 1 "a missing log fails" "$norepo" iscc-log "$work/no-such.log" --known-warnings="$known"
expect_exit 1 "a missing known-warnings file fails" "$norepo" iscc-log "$work/clean.log" --known-warnings="$work/no-such-patterns"

echo "# the reviewed patterns against real compiler output"

# t/fixtures/iscc-diagnostics.log is not written by hand: it is the output of
# this repository's own installer/InnoSetup/ISCC.exe compiling a script that
# provokes each accepted diagnostic. If the reviewed patterns ever stop
# matching the wording the compiler actually emits, this fails.
real="$top/t/fixtures/iscc-diagnostics.log"
expect_exit 0 "every diagnostic in the captured compiler log is accounted for" \
	"$norepo" iscc-log "$real" --known-warnings="$known"

for wording in \
	'Architecture identifier' \
	'Constant "pf" has been renamed' \
	'Support function "IsX64" is deprecated' \
	"Variable 'UNUSEDLOCAL' never used" \
	"Variable 'UNUSEDGLOBAL' never used"
do
	grep -q "$wording" "$work/err" &&
	ok "reports the real diagnostic: $wording" ||
	not_ok "reports the real diagnostic: $wording" "$work/err"
done

# Each reviewed pattern has to be load-bearing. Dropping any one of them must
# fail the captured log, so the list cannot accumulate entries that match
# nothing while a real diagnostic slips through some other entry.
pattern_lines="$(grep -c -v -e '^#' -e '^$' "$known")"
test "$pattern_lines" -eq 4 &&
ok "the reviewed list has the 4 patterns these tests bind" ||
not_ok "the reviewed list has the 4 patterns these tests bind (found $pattern_lines)" /dev/null

n=0
while test "$n" -lt "$pattern_lines"
do
	n=$(($n + 1))
	grep -v -e '^#' -e '^$' "$known" |
	sed "${n}d" >"$work/minus-one.txt"
	expect_exit 1 "dropping reviewed pattern $n fails the captured log" \
		"$norepo" iscc-log "$real" --known-warnings="$work/minus-one.txt"
done

# The directive that was removed from install.iss rather than accepted must not
# be admitted if it ever comes back.
removed="$top/t/fixtures/iscc-removed-directive.log"
expect_exit 1 "the removed obsolete directive is not accepted if it returns" \
	"$norepo" iscc-log "$removed" --known-warnings="$known"
grep -q 'LZMAUseSeparateProcess' "$work/err" &&
ok "names the obsolete directive" ||
not_ok "names the obsolete directive" "$work/err"

grep -q 'LZMAUseSeparateProcess' "$top/installer/install.iss" &&
not_ok "install.iss no longer sets the obsolete directive" /dev/null ||
ok "install.iss no longer sets the obsolete directive"

# A near miss must not be accepted: the reviewed patterns are anchored and name
# an exact diagnostic, so a different variable-hint shape or a trailing
# addendum is a new diagnostic that a human has not looked at.
cat >"$work/nearmiss.log" <<-\EOF
	Warning: Line 22, Column 3: [Hint] Function 'UNUSEDFUNC' never used
EOF
expect_exit 1 "an unreviewed hint of a different shape still fails" \
	"$norepo" iscc-log "$work/nearmiss.log" --known-warnings="$known"

cat >"$work/suffixed.log" <<-\EOF
	Warning: Line 22, Column 3: [Hint] Variable 'X' never used and also something else
EOF
expect_exit 1 "a reviewed diagnostic with unreviewed text appended still fails" \
	"$norepo" iscc-log "$work/suffixed.log" --known-warnings="$known"

cat >"$work/unanchored.log" <<-\EOF
	Error: Architecture identifier "x64" is deprecated. Substituting "x64os",
EOF
expect_exit 1 "reviewed warning wording does not excuse an error line" \
	"$norepo" iscc-log "$work/unanchored.log" --known-warnings="$known"

grep -q '^\^Warning: *$' "$known" &&
not_ok "the reviewed list contains no blanket wildcard" /dev/null ||
ok "the reviewed list contains no blanket wildcard"

echo "# the signing predicate has one definition"

expect_exit 1 "--print-helper fails when no helper is configured" \
	"$norepo" signing --print-helper
test -s "$work/out" &&
not_ok "--print-helper prints nothing when there is nothing to print" "$work/out" ||
ok "--print-helper prints nothing when there is nothing to print"

expect_exit 0 "--print-helper reports the helper the release script would use" \
	"$signed" signing --print-helper
printed="$(cat "$work/out")"
test "$printed" = '!true' &&
ok "the printed helper is exactly what the signing check accepted" ||
not_ok "the printed helper is exactly what the signing check accepted ($printed)" "$work/err"

# The release script asks for the helper through this one predicate, so a
# helper the check rejects must never be printed as usable.
expect_exit 1 "--print-helper rejects a whitespace-only helper too" \
	"$blank" signing --print-helper
expect_exit 1 "--print-helper rejects an empty helper too" \
	"$empty" signing --print-helper

# --allow-unsigned relaxes the verdict, never the reported fact.
expect_exit 1 "--print-helper is not relaxed by --allow-unsigned" \
	"$norepo" signing --print-helper --allow-unsigned

# The release script must ask this one predicate rather than reading the Git
# configuration itself, otherwise the two can disagree about what counts as a
# configured helper.
grep -q 'check-release-prerequisites.sh signing --print-helper' "$top/installer/release.sh" &&
ok "installer/release.sh asks the shared predicate for the helper" ||
not_ok "installer/release.sh asks the shared predicate for the helper" /dev/null

grep -q 'git config.*signtool' "$top/installer/release.sh" &&
not_ok "installer/release.sh does not re-implement the signing predicate" /dev/null ||
ok "installer/release.sh does not re-implement the signing predicate"

echo "# usage"

expect_exit 2 "an unknown check is a usage error" "$norepo" no-such-check
expect_exit 2 "no arguments is a usage error" "$norepo"
expect_exit 2 "iscc-log without a log is a usage error" "$norepo" iscc-log --known-warnings="$known"

echo ""
if test $failures -gt 0
then
	echo "FAILED $failures of $checks checks"
	exit 1
fi
echo "passed all $checks checks"
