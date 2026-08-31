#!/bin/sh

# Verify that Git for Windows' Inno Setup script launches executables that live
# in the System directory via Inno Setup 7's native-System-directory helper.
#
# Inno Setup ships only an x86 and an x64 `Setup` binary and `SetupArchitecture`
# is left unset, therefore `Setup` is a 32-bit x86 process, also for the ARM64
# flavor. In a 32-bit process, WOW64 redirects `{sys}` (i.e. `System32`) to
# `SysWOW64`, so a plain `Exec()` of `{sys}\cmd.exe` starts the emulated x86
# `cmd.exe` on ARM64 Windows, as does an `Exec()` of a `.bat` file (for which
# Inno Setup spawns `cmd.exe` itself). `ExecNative()`, the wrapper around
# `ExecWithNativeSysDir()` in `helpers.inc.iss`, avoids that.
#
# This is a static check of the sources; that the installer really starts native
# processes still has to be observed on ARM64 Windows.

die () {
	printf '%s\n' "$*" >&2
	exit 1
}

cd "$(dirname "$0")" ||
die "Could not switch directory"

test -f install.iss ||
die "Could not find install.iss"

sources='install.iss'
for source in *.inc.iss
do
	test -f "$source" ||
	die "Could not find any *.inc.iss"
	sources="$sources $source"
done

# `Exec()`, `ExecAndCaptureOutput()` and `ExecAndLogOutput()` resolve the
# executable in the redirected System directory; only their `*WithNativeSysDir()`
# variants, wrapped as `ExecNative()`, do not.
offenders="$(grep -nE \
	"(^|[^A-Za-z0-9_])Exec(AndCaptureOutput|AndLogOutput)?\([[:space:]]*(ExpandConstant\('\{(sys|cmd|sysnative)\}|'(cmd|powershell)\.exe')" \
	$sources)" ||
test 1 = $? ||
die "Could not scan the sources"
test -z "$offenders" ||
die "Use ExecNative(), so that ARM64 does not run the emulated x86 executable:
$offenders"

# Assert that exactly one line of $1 contains $2 outside of a comment, and that
# it still passes the parameters whose semantics must be preserved.
require () {
	file=$1 &&
	fragment=$2 &&
	shift 2 &&
	line="$(grep -F -- "$fragment" "$file" | grep -v '^[[:space:]]*//')" ||
	die "$file: no line outside of a comment contains: $fragment"

	test 1 -eq "$(printf '%s\n' "$line" | wc -l)" ||
	die "$file: more than one line contains: $fragment
$line"

	for token
	do
		case "$line" in
		*"$token"*) ;;
		*) die "$file: '$token' missing from: $line";;
		esac
	done
}

require helpers.inc.iss \
	'Result:=ExecWithNativeSysDir(Filename,Params,WorkingDir,ShowCmd,Wait,ResultCode);'

require helpers.inc.iss \
	"ExecNative(ExpandConstant('{sys}\cmd.exe')" \
	SW_HIDE ewWaitUntilTerminated ',Res)'

require install.iss \
	"ExecNative('powershell.exe'" \
	aslr-manager.ps1 SW_HIDE ewWaitUntilTerminated

require install.iss \
	"ExecNative(Cmd,ExpandConstant('>\"{tmp}\post-install.log\"')" \
	AppDir SW_HIDE ewWaitUntilTerminated

# Inno Setup 7 offers no `ExecAsOriginalUserWithNativeSysDir()`, so these call
# sites necessarily still go through WOW64. Pin their number down, so that new
# ones cannot be introduced without a conscious decision.
count="$(grep -hoE "ExecAsOriginalUser\(ExpandConstant\('\{(sys|cmd)\}" $sources | wc -l)"

test 3 -eq "$count" ||
die "Expected 3 ExecAsOriginalUser() launches of System directory executables, got $count.
Inno Setup 7 offers no native-System-directory variant of ExecAsOriginalUser();
if you added such a call site, say so in the pull request and adjust this count."

# Before Inno Setup 6.3, `x64os` was called `x64`. The compiler still accepts the
# old name but warns about it, and it matches x64 Windows only, which is why the
# ARM64 installer has to list `arm64` separately.
arch="$(grep '^ArchitecturesInstallIn64BitMode=' install.iss)" ||
die "install.iss: no ArchitecturesInstallIn64BitMode directive"

case "$arch" in
*x64compatible*) ;;
*) die "install.iss: expected x64compatible in: $arch";;
esac

! printf '%s\n' "$arch" | grep -qE '(=|[[:space:]])x64([[:space:]]|$)' ||
die "install.iss: 'x64' is deprecated, use 'x64compatible': $arch"

echo "All Inno Setup launches of System directory executables are native." >&2
