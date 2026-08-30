#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

while case "$1" in
--mingit) MINIMAL_GIT=1; export MINIMAL_GIT;;
-*) die "Unknown option: $1";;
*) break;;
esac; do shift; done

test $# = 0 || die "$0 does not take arguments"

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine script directory"

sys_dlls="$(ls "$SYSTEMROOT/system32"/*.dll "$SYSTEMROOT/system32"/*.DLL "$SYSTEMROOT/system32"/*.drv | tr A-Z a-z)" ||
die "Could not enumerate system .dll files"

LF='
'

ARCH="$(uname -m)" ||
die "Could not determine architecture"

case "$MSYSTEM" in
MINGW64) MINGW_PREFIX=mingw64;;
UCRT64)
	MINGW_PREFIX=ucrt64
	ARCH=ucrt64
	;;
CLANGARM64)
	MINGW_PREFIX=clangarm64
	ARCH=aarch64
	;;
MINGW32) MINGW_PREFIX=mingw32;;
*)
	case "$ARCH" in
	i686) MINGW_PREFIX=mingw32;;
	x86_64)
		case $(uname -s) in
			*-ARM64)
				MINGW_PREFIX=clangarm64
				ARCH=aarch64
				;;
			*) MINGW_PREFIX=mingw64;;
		esac
		;;
	*) die "Unhandled architecture: $ARCH";;
	esac
	;;
esac

if test -t 2
then
	print_dir=t
else
	print_dir=
fi

# Overridable so that the test suite can drive this script with a stub, and so
# that a native `objdump` can be pointed at later. The default is unchanged.
OBJDUMP="${OBJDUMP-/usr/bin/objdump}"

# A missing inspection tool is a hard failure, not something to work around.
# Rerouting silently to the fallback parser would mean the run no longer
# inspects what it says it does.
{ test -x "$OBJDUMP" || command -v "$OBJDUMP" >/dev/null 2>&1; } ||
die "objdump not found at '$OBJDUMP'; refusing to inspect the payload without it"

used_dlls_file=/tmp/used-dlls.$$.txt
>"$used_dlls_file"
missing_dlls_file=/tmp/missing-dlls.$$.txt
>"$missing_dlls_file"
unused_dlls_file=/tmp/unused-dlls.$$.txt
tmp_file=/tmp/tmp.$$.txt
trap "rm -f \"$used_dlls_file\" \"$missing_dlls_file\" \"$unused_dlls_file\" \
	\"$tmp_file\" \"$tmp_file.raw\" \"$tmp_file.all\" \"$tmp_file.ldd\" \
	\"$tmp_file.pe\" \"$tmp_file.pe.fixed\" \"$tmp_file.pe.raw\" \
	\"$tmp_file.expected\" \"$tmp_file.seen\" \"$tmp_file.todo\" \
	\"$tmp_file.win\" \"$tmp_file.candidates\" \"$tmp_file.dirs\"" EXIT

# Report the binaries a parser described, by extracting the file names we asked
# about from its own output. `objdump` writes "<path>:<TAB>file format <fmt>"
# and pe-imports.ps1 writes "<path>:"; both are keyed on the path we supplied.
# Never key on a parser's diagnostics: those are translated at run time and
# their wording is not a stable interface.
parsed_files () {
	tr -d '\r' <"$1" |
	sed -n -e 's|^\(/[^:]*\):$|\1|p' -e 's|^\(/[^:]*\):[ 	].*$|\1|p'
}

# Run `objdump -p` over a list of paths. The list is carried in the positional
# parameters rather than a word-split string, so a path containing a space, a
# tab or a bracket is passed through intact.
run_objdump () { # <list-file> <stdout> <stderr>
	objdump_list="$1"
	objdump_out="$2"
	objdump_err="$3"

	# `set --` below overwrites these, so read them out first.
	set --
	while IFS= read -r objdump_path
	do
		set -- "$@" "$objdump_path"
	done <"$objdump_list"

	: >"$objdump_out"
	: >"$objdump_err"
	test $# -gt 0 || return 0
	"$OBJDUMP" -p "$@" >"$objdump_out" 2>"$objdump_err"
}

# Replace each header pe-imports.ps1 emitted with the path we asked about, in
# order. Its own echoed path has been through MSYS conversion and is not
# comparable to ours, so pairing them by position is the only sound way to
# attribute an import to a file.
#
# Every line is also checked against the parser's own output schema: a header,
# or an import indented below one. Counting headers is not enough on its own --
# evidence that is not the shape we expect is not evidence. Sets
# $pe_header_count, and returns non-zero on any schema or arity violation.
rewrite_pe_headers () { # <inputs> <parser-output> <out> <scratch>
	tr -d '\r' <"$2" >"$4"
	: >"$3"
	pe_header_count=0

	exec 5<"$1" 6<"$4"
	while IFS= read -r pe_line <&6
	do
		case "$pe_line" in
		"	DLL Name: "?*)
			printf '%s\n' "$pe_line" >>"$3"
			;;
		*:)
			if IFS= read -r pe_original <&5
			then
				printf '%s:\n' "$pe_original" >>"$3"
				pe_header_count=$(($pe_header_count + 1))
			else
				exec 5<&- 6<&-
				return 1
			fi
			;;
		*)
			exec 5<&- 6<&-
			return 2
			;;
		esac
	done
	exec 5<&- 6<&-
	return 0
}

ARCH=$ARCH "$thisdir"/make-file-list.sh >"$tmp_file.raw" ||
die "Could not generate the file list"

tr A-Z a-z <"$tmp_file.raw" | grep -v '/getprocaddr64.exe$' | LC_ALL=C sort -u >"$tmp_file.all"
test -s "$tmp_file.all" ||
die "The file list is empty; refusing to report success"

# These two may legitimately match nothing, which used to abort the whole scan
# through the `&&` chain below and still exit successfully.
usr_bin_dlls="$(grep '^usr/bin/[^/]*\.dll$' "$tmp_file.all")" || usr_bin_dlls=
mingw_bin_dlls="$(grep '^'$MINGW_PREFIX'/bin/[^/]*\.dll$' "$tmp_file.all")" || mingw_bin_dlls=

# Every binary in the payload, and the directories they live in. The totals are
# reconciled at the end so that a directory whose name defeats the per-directory
# selection below cannot be skipped while the rest of the run still looks busy.
grep '\.\(dll\|exe\)$' "$tmp_file.all" >"$tmp_file.candidates"
candidate_total=$(($(wc -l <"$tmp_file.candidates")))
sed -n 's/[^/]*\.\(dll\|exe\)$//p' "$tmp_file.all" | LC_ALL=C sort -u >"$tmp_file.dirs"

total_expected=0
total_inspected=0

exec 7<"$tmp_file.dirs"
while IFS= read -r dir <&7
do
	test -z "$print_dir" ||
	printf "dir: $dir\\033[K\\r" >&2

	case "$dir" in
	usr/*) dlls="$usr_bin_dlls$LF";;
	$MINGW_PREFIX/*) dlls="$mingw_bin_dlls$LF";;
	*) dlls="";;
	esac

	sed -ne "s,^$dir[^/]*\.\(dll\|exe\)$,/&,p" "$tmp_file.all" |
	LC_ALL=C sort -u >"$tmp_file.expected"
	expected_count=$(($(wc -l <"$tmp_file.expected")))
	test "$expected_count" -gt 0 || continue

	objdump_status=0
	run_objdump "$tmp_file.expected" "$tmp_file.ldd" "$tmp_file" ||
	objdump_status=$?

	# `objdump` prints a header, and can print imports, for a file and then
	# fail while decoding that same file. A header is therefore not proof
	# that anything was decoded, and a batch that exited non-zero tells us
	# nothing about which of its members were finished. Trust the batch only
	# when it exited cleanly and described every member; otherwise discard
	# all of its output and reparse the whole batch natively.
	objdump_trusted=
	if test "$objdump_status" = 0
	then
		parsed_files "$tmp_file.ldd" | LC_ALL=C sort -u >"$tmp_file.seen"
		LC_ALL=C comm -23 "$tmp_file.expected" "$tmp_file.seen" >"$tmp_file.todo"
		test -s "$tmp_file.todo" ||
		objdump_trusted=t
	fi

	if test -n "$objdump_trusted"
	then
		objdump_count=$expected_count
		: >"$tmp_file.todo"
	else
		objdump_count=0
		: >"$tmp_file.ldd"
		cat "$tmp_file.expected" >"$tmp_file.todo"
	fi

	# Whatever `objdump` did not prove it decoded goes to the native PE
	# parser. On ARM64 that is every binary, because the MSYS2 Binutils
	# build cannot decode pei-aarch64. Hand the paths over in a file: MSYS
	# silently refuses to convert an argument containing a bracket, and the
	# payload really does contain `usr/bin/[.exe`.
	pe_count=0
	if test -s "$tmp_file.todo"
	then
		type cygpath >/dev/null 2>&1 ||
		die "cygpath is required to hand payload paths to pe-imports.ps1"

		cygpath -w -f "$tmp_file.todo" >"$tmp_file.win" ||
		die "Could not convert payload paths to Windows form"

		powershell.exe -NoProfile -ExecutionPolicy Bypass \
			-File "$thisdir/pe-imports.ps1" \
			-PathFile "$(cygpath -w "$tmp_file.win")" >"$tmp_file.pe" || {
			cat "$tmp_file" >&2
			die "pe-imports.ps1 failed to parse PE imports in /$dir (objdump exit code $objdump_status)"
		}

		rewrite_status=0
		rewrite_pe_headers "$tmp_file.todo" "$tmp_file.pe" \
			"$tmp_file.pe.fixed" "$tmp_file.pe.raw" ||
		rewrite_status=$?

		case $rewrite_status in
		0) ;;
		1) die "pe-imports.ps1 described more binaries than it was given in /$dir";;
		*) die "pe-imports.ps1 produced output that is not import evidence in /$dir";;
		esac

		pe_count=$pe_header_count
		cat "$tmp_file.pe.fixed" >>"$tmp_file.ldd"
	fi

	# Fail closed. A parser that quietly describes nothing must never be
	# mistaken for a clean result, so account for every binary we expected.
	inspected_count=$(($objdump_count + $pe_count))
	if test $inspected_count -ne $expected_count
	then
		if test -n "$objdump_trusted"
		then
			trust=trusted
		else
			trust="not trusted"
		fi
		cat "$tmp_file" >&2
		echo "Inspected $inspected_count of $expected_count binaries in /$dir" >&2
		echo "objdump exited with $objdump_status and was $trust;" \
			"pe-imports.ps1 described $pe_count of" \
			"$(($(wc -l <"$tmp_file.todo")))" >&2
		sed 's|^|  not proven decoded: |' <"$tmp_file.todo" >&2
		die "Could not determine the DLL dependencies of every binary in /$dir"
	fi

	total_expected=$(($total_expected + $expected_count))
	total_inspected=$(($total_inspected + $inspected_count))

	tr A-Z\\r a-z\ <"$tmp_file.ldd" |
	grep -e '^.dll name:' -e '^[^ ]*\.\(dll\|exe\):' |
	while read a b c d
	do
		case "$c" in api-ms-*) continue;; esac # API set, always provided by Windows
		case "$a,$b" in
		*.exe:,*|*.dll:,*) current="${a%:}";;
		dll,name:) # `objdump -p` / pe-imports.ps1 output
			echo "$c" >>"$used_dlls_file"
			case "$sys_dlls$LF$dlls" in
			*"/$c$LF"*) ;; # okay, it's included
			*)
				echo "$current is missing $c" >&2
				echo "$c" >>"$missing_dlls_file"
				;;
			esac
			;;
		esac
	done
done
exec 7<&-
printf "$next_line" >&2

test "$candidate_total" -gt 0 ||
die "The file list contains no .dll or .exe files; refusing to report success"
test "$total_expected" -eq "$candidate_total" ||
die "Selected $total_expected of $candidate_total binaries in the file list; refusing to report success"
test "$total_inspected" -eq "$total_expected" ||
die "Inspected $total_inspected of $total_expected binaries; refusing to report success"

used_dlls_regex="/\\($(test -n "$MINIMAL_GIT" || printf 'p11-kit-trust\\|';
	sort <"$used_dlls_file" |
	uniq |
	sed -e 's/+x/\\+/g' -e 's/\.dll$/\\|/' -e '$s/\\|//' |
	tr -d '\n')\\)\\.dll\$"
grep '\.dll$' "$tmp_file.all" |
	grep -v \
		-e "$used_dlls_regex" \
		-e '^usr/lib/perl5/' \
		-e '^usr/lib/gawk/' \
		-e '^usr/lib/openssl/engines' \
		-e '^usr/lib/sasl2/' \
		-e '^usr/lib/coreutils/libstdbuf.dll' \
		-e "^$MINGW_PREFIX/bin/libcurl\(\|-openssl\)-4.dll" \
		-e "^$MINGW_PREFIX/bin/\(atlassian\|azuredevops\|bitbucket\|gcmcore.*\|github\|gitlab\|microsoft\|newtonsoft\|system\..*\|webview2loader\|avalonia\|.*harfbuzzsharp\|microcom\|.*skiasharp\|av_libglesv2\|msalruntime\(\|_x86\|_arm64\)\)\." \
		-e "^$MINGW_PREFIX/lib/ossl-modules/" \
		-e "^$MINGW_PREFIX/lib/\(engines\|reg\|thread\)" |
	sed 's/^/unused dll: /' |
	tee "$unused_dlls_file" >&2

test ! -s "$missing_dlls_file" && test ! -s "$unused_dlls_file"
