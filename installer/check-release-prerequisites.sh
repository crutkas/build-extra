#!/bin/sh

# Prerequisites that installer/release.sh must not get wrong quietly.
#
# Each of these guarded a behaviour that used to be switched off by the state
# of the build machine, with no message and a zero exit code: an installer
# could be built unsigned, or without the data needed to clean up a previous
# OpenSSH installation, and nothing said so. They live here rather than inline
# so they can be tested on their own.
#
# Exit codes: 0 satisfied, 1 not satisfied, 2 usage error,
#             3 signing not configured but explicitly opted out of.

die () {
	echo "$*" >&2
	exit 1
}

usage () {
	cat >&2 <<-EOF
	Usage: $0 <check> [options]

	  signing [--allow-unsigned] [--print-helper]
	      Verify that a signing helper is configured. With --allow-unsigned,
	      report the absence via exit code 3 instead of failing. With
	      --print-helper, print the helper and exit 0 only if one is set;
	      this is the single predicate every caller must use.

	  compiler [--iscc=<file>]
	      Verify that the Inno Setup compiler is present and executable.

	  openssh-cleanup
	      Print the files owned by the OpenSSH package, one relative path per
	      line, sorted. Fails when that list cannot be determined.

	  iscc-log <file> [--known-warnings=<file>]
	      Fail on warnings and errors in an Inno Setup compiler log, except
	      those matched by a reviewed pattern in <file>.

	  promotable <artifact>
	      Fail when <artifact> is accompanied by an .UNSIGNED sidecar, or is
	      missing. This is the mechanical gate a promotion step must run
	      before publishing anything this repository produced.
	EOF
	exit 2
}

# The one place that decides whether signing is configured. An alias set to
# whitespace is as useless as an unset one, and would otherwise pass a `test -n`
# and then expand to nothing. Callers must ask here rather than re-deriving it:
# two views of this question disagreeing is how an installer gets told to sign
# and marked unsigned at the same time.
signing_helper () {
	printf '%s' "$(git config alias.signtool)" | tr -d ' 	'
}

check_signing () {
	allow_unsigned=
	print_only=

	while test $# -gt 0
	do
		case "$1" in
		--allow-unsigned) allow_unsigned=t;;
		--print-helper) print_only=t;;
		*) echo "Unknown option: $1" >&2; usage;;
		esac
		shift
	done

	helper="$(signing_helper)"

	test -z "$print_only" || {
		test -n "$helper" || return 1
		printf '%s\n' "$helper"
		return 0
	}

	if test -n "$helper"
	then
		return 0
	fi

	test -n "$allow_unsigned" || {
		echo "No signing helper is configured." >&2
		echo "Set the 'signtool' Git alias, e.g." >&2
		echo "  git config --global alias.signtool '!sh $(dirname "$0")/../signtool.sh'" >&2
		echo "or pass --allow-unsigned to build an installer that must not be released." >&2
		exit 1
	}

	echo "Building an UNSIGNED installer because --allow-unsigned was given." >&2
	exit 3
}

check_compiler () {
	iscc=./InnoSetup/ISCC.exe

	while test $# -gt 0
	do
		case "$1" in
		--iscc=*) iscc="${1#*=}";;
		*) echo "Unknown option: $1" >&2; usage;;
		esac
		shift
	done

	test -f "$iscc" ||
	die "Not found: $iscc; run installer/update-inno-setup.sh to install the compiler"

	test -s "$iscc" ||
	die "$iscc is empty"
}

check_promotable () {
	test $# = 1 || usage

	artifact="$1"

	test -f "$artifact" ||
	die "Not found: $artifact; nothing to promote"

	marker="$artifact.UNSIGNED"
	test -f "$marker" || {
		echo "$artifact carries no unsigned marker."
		return 0
	}

	echo "$marker says:" >&2
	sed 's/^/  /' <"$marker" >&2

	# The marker binds to the artifact by name and by content. A marker that
	# does not match the file beside it is worse than one that does: it means
	# either the artifact or the marker has been swapped, and neither can be
	# promoted on that basis.
	named="$(sed -n 's/^artifact: //p' "$marker" | head -n 1)"
	recorded="$(sed -n 's/^sha256: //p' "$marker" | head -n 1)"

	case "$named,$recorded" in
	,* | *,) die "$marker does not identify the artifact it belongs to; refusing to promote $artifact";;
	esac

	test "$named" = "${artifact##*/}" ||
	die "$marker belongs to '$named', not to '${artifact##*/}'; refusing to promote either"

	type sha256sum >/dev/null 2>&1 ||
	die "sha256sum is required to verify $marker"

	actual="$(sha256sum <"$artifact" | sed 's/ .*//')"
	test "$actual" = "$recorded" ||
	die "$marker records $recorded but $artifact hashes to $actual; refusing to promote"

	die "$artifact was built unsigned and must not be promoted"
}

check_openssh_cleanup () {
	test $# = 0 || usage

	type -p pacman.exe >/dev/null 2>&1 ||
	die "pacman is required to determine which files the OpenSSH package owns"

	errors="$(mktemp)" && files="$(mktemp)" ||
	die "Could not create a temporary file"

	pacman -Ql openssh 2>"$errors" |
	sed -n 's|^openssh /\(.*[^/]\)$|\1|p' |
	LC_ALL=C sort >"$files"
	# `pacman -Ql` mentions a missing files database on a stripped SDK; that
	# is noise, but anything else is worth seeing.
	grep -v 'database file for .* does not exist' <"$errors" >&2

	if test ! -s "$files"
	then
		rm -f "$errors" "$files"
		die "The OpenSSH package owns no files; refusing to build an installer that cannot clean up a previous OpenSSH"
	fi

	cat "$files"
	rm -f "$errors" "$files"
}

check_iscc_log () {
	known_warnings=
	log=

	while test $# -gt 0
	do
		case "$1" in
		--known-warnings=*) known_warnings="${1#*=}";;
		-*) echo "Unknown option: $1" >&2; usage;;
		*)
			test -z "$log" || usage
			log="$1"
			;;
		esac
		shift
	done

	test -n "$log" || usage
	test -f "$log" ||
	die "Not found: $log"

	diagnostics="$(mktemp)" && unexpected="$(mktemp)" ||
	die "Could not create a temporary file"

	# Inno Setup reports both on stdout, which release.sh captures into the
	# log. They used to end up there and be read by nobody.
	grep '^\(Warning\|Error\)' "$log" >"$diagnostics"
	case $? in
	0 | 1) ;;
	*)
		rm -f "$diagnostics" "$unexpected"
		die "Could not scan $log for diagnostics"
		;;
	esac

	if test -n "$known_warnings"
	then
		test -f "$known_warnings" || {
			rm -f "$diagnostics" "$unexpected"
			die "Not found: $known_warnings"
		}

		known="$(mktemp)" ||
		die "Could not create a temporary file"
		sed -e '/^[ 	]*#/d' -e '/^[ 	]*$/d' "$known_warnings" >"$known"
		if test -s "$known"
		then
			# grep exits 1 when it selects nothing, which is the
			# normal all-reviewed case, but 2 when a pattern is
			# malformed. Treating those alike would let a typo in
			# the reviewed list admit every diagnostic.
			grep -v -f "$known" "$diagnostics" >"$unexpected"
			case $? in
			0 | 1) ;;
			*)
				rm -f "$diagnostics" "$unexpected" "$known"
				die "Could not apply the patterns in $known_warnings"
				;;
			esac
		else
			cat "$diagnostics" >"$unexpected"
		fi
		rm -f "$known"
	else
		cat "$diagnostics" >"$unexpected"
	fi

	if test -s "$diagnostics"
	then
		echo "Inno Setup reported:" >&2
		sed 's/^/  /' <"$diagnostics" >&2
	fi

	if test -s "$unexpected"
	then
		rm -f "$diagnostics" "$unexpected"
		die "Unreviewed Inno Setup diagnostics; fix them, or add a reviewed pattern to ${known_warnings:-a known-warnings file}"
	fi

	rm -f "$diagnostics" "$unexpected"
}

test $# -gt 0 || usage

check="$1"
shift

case "$check" in
signing) check_signing "$@";;
compiler) check_compiler "$@";;
openssh-cleanup) check_openssh_cleanup "$@";;
iscc-log) check_iscc_log "$@";;
promotable) check_promotable "$@";;
*) echo "Unknown check: $check" >&2; usage;;
esac
