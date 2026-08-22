#!/bin/sh

die () {
	echo "$*" >&2
	exit 1
}

thisdir="$(cd "$(dirname "$0")" && pwd)" ||
die "Could not determine the test directory"
bindir=${ARM64_BUSYBOX_TEST_BIN:-/usr/bin}
selection_only=
case "$1" in
--selection-only) selection_only=t;;
"") ;;
*) die "Unknown option: $1";;
esac

replacement_file=/etc/arm64-busybox-replacements.tsv
test -n "$ARM64_BUSYBOX_TEST_BIN" ||
test -f "$replacement_file" ||
die "Missing $replacement_file"

if test -z "$ARM64_BUSYBOX_TEST_BIN"
then
	count=$(sed 1d "$replacement_file" | wc -l) ||
	die "Could not count ARM64 BusyBox replacements"
	test 59 = "$count" ||
	die "Expected 59 default replacements, found $count"

	while IFS= read -r path
	do
		test -x "/$path" ||
		die "Missing ARM64 BusyBox replacement /$path"
		tr -d '\r' <"$replacement_file" |
		awk -F '	' -v path="$path" \
			'$1 == path && $3 == "default" { found = 1 } END { exit !found }' ||
		die "$path is not recorded as a default replacement"
	done <"$thisdir/../arm64-busybox/default-replacements.txt"
fi

tool () {
	name=$1
	shift
	"$bindir/$name.exe" "$@"
}

machine=$(tool uname -m) ||
die "BusyBox uname failed"
case "$machine" in
aarch64|x86_64) ;;
*) die "Unexpected BusyBox machine: $machine";;
esac
test "$machine" = "$(tool arch)" ||
die "BusyBox arch and uname disagree"

test -z "$selection_only" || exit 0

tmp=${TMPDIR:-/tmp}/arm64-busybox-compat.$$
trap 'cd / && "$bindir/rm.exe" -rf "$tmp"' EXIT
tool mkdir -p "$tmp" ||
die "Could not create $tmp"
cd "$tmp" ||
die "Could not enter $tmp"

printf 'payload' >"space name"
test payload = "$(tool cat "$tmp/space name")" ||
die "cat path conversion or quoting failed"

printf 'abc' | tool base32 >actual &&
printf 'MFRGG===\n' >expect &&
tool cmp expect actual ||
die "base32 failed"
printf 'abc' | tool base64 >actual &&
printf 'YWJj\n' >expect &&
tool cmp expect actual ||
die "base64 failed"
test file = "$(tool basename dir/file)" &&
test dir = "$(tool dirname dir/file)" ||
die "basename or dirname failed"
printf 'abc' | tool cksum >actual &&
grep -q '^1219131554 3$' actual ||
die "cksum failed"
printf 'a\nb\nc\n' >left &&
printf 'b\nc\nd\n' >right &&
tool comm left right >actual &&
printf 'a\n\t\tb\n\t\tc\n\td\n' >expect &&
tool cmp expect actual ||
die "comm failed"
printf 'one:two\n' | tool cut -d: -f2 >actual &&
test two = "$(tool cat actual)" ||
die "cut failed"
test text = "$(tool echo -n text)" ||
die "echo failed"
ARM64_BUSYBOX_ENV=visible tool env >actual &&
grep -q '^ARM64_BUSYBOX_ENV=visible$' actual ||
die "env failed"
printf 'a\tb\n' | tool expand -t 4 >actual &&
printf 'a   b\n' >expect &&
tool cmp expect actual ||
die "expand failed"
test 5 = "$(tool expr 2 + 3)" ||
die "expr failed"
tool false && die "false returned success"
printf 'abcdef\n' | tool fold -w 3 >actual &&
printf 'abc\ndef\n' >expect &&
tool cmp expect actual ||
die "fold failed"
printf '1\n2\n3\n' | tool head -n 2 >actual &&
printf '1\n2\n' >expect &&
tool cmp expect actual ||
die "head failed"
printf '1 a\n2 b\n' >left &&
printf '1 x\n2 y\n' >right &&
tool join left right >actual &&
printf '1 a x\n2 b y\n' >expect &&
tool cmp expect actual ||
die "join failed"
printf 'abc' | tool md5sum >actual &&
grep -q '^900150983cd24fb0d6963f7d28e17f72  -$' actual ||
die "md5sum failed"

tool mkdir -p tree/dir &&
printf 'source' >tree/source &&
tool cp tree/source tree/copy &&
tool mv tree/copy tree/moved &&
test source = "$(tool cat tree/moved)" &&
tool ln tree/source tree/hardlink &&
test source = "$(tool cat tree/hardlink)" &&
tool rmdir tree/dir ||
die "basic file operations failed"

target_win=$(cygpath -aw tree/source) &&
link_win=$(cygpath -aw tree/symlink) &&
if BB_LINK="$link_win" BB_TARGET="$target_win" \
	powershell.exe -NoProfile -Command \
	'$null = New-Item -ItemType SymbolicLink -Path $env:BB_LINK -Target $env:BB_TARGET -Force' \
	2>/dev/null
then
	tool cp -a tree/symlink tree/symlink-copy &&
	test -L tree/symlink-copy &&
	test source = "$(tool cat tree/symlink-copy)" ||
	die "cp did not preserve a native Windows symlink"
else
	/usr/bin/ln -s source tree/symlink &&
	tool cp -a tree/symlink tree/symlink-copy &&
	test source = "$(tool cat tree/symlink-copy)" ||
	die "cp did not preserve an MSYS symlink"
fi

temp=$(tool mktemp "$tmp/template.XXXXXX") &&
test -f "$temp" ||
die "mktemp failed"
printf 'a\n\nb\n' | tool nl -ba >actual &&
test 3 = "$(grep -c '[0-9]' actual)" ||
die "nl failed"
nproc=$(tool nproc) &&
test "$nproc" -gt 0 ||
die "nproc failed"
printf 'A' | tool od -An -tx1 >actual &&
grep -q '41' actual ||
die "od failed"
printf 'a\nb\n' >left &&
printf '1\n2\n' >right &&
tool paste left right >actual &&
printf 'a\t1\nb\t2\n' >expect &&
tool cmp expect actual ||
die "paste failed"
test value = "$(tool printf %s value)" ||
die "printf failed"
printf '1\n2\n3\n' >expect &&
tool seq 1 3 >actual &&
tool cmp expect actual ||
die "seq failed"

printf 'abc' | tool sha1sum >actual &&
grep -q '^a9993e364706816aba3e25717850c26c9cd0d89d  -$' actual ||
die "sha1sum failed"
printf 'abc' | tool sha256sum >actual &&
grep -q '^ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -$' actual ||
die "sha256sum failed"
printf 'abc' | tool sha384sum >actual &&
grep -q '^cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7  -$' actual ||
die "sha384sum failed"
printf 'abc' | tool sha512sum >actual &&
grep -q '^ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f  -$' actual ||
die "sha512sum failed"

printf 'beta\nalpha\nalpha\n' | tool sort | tool uniq >actual &&
printf 'alpha\nbeta\n' >expect &&
tool cmp expect actual ||
die "sort or uniq failed"
printf 'abcdef' >split-input &&
tool split -b 3 split-input split- &&
test abc = "$(tool cat split-aa)" &&
test def = "$(tool cat split-ab)" ||
die "split failed"
printf 'abc' | tool sum >actual &&
grep -Eq '^[0-9]+ +1 *$' actual ||
die "sum failed"
printf 'a\nb\n' | tool tac >actual &&
printf 'b\na\n' >expect &&
tool cmp expect actual ||
die "tac failed"
printf '1\n2\n3\n' | tool tail -n 2 >actual &&
printf '2\n3\n' >expect &&
tool cmp expect actual ||
die "tail failed"
printf 'tee\n' | tool tee tee-output >actual &&
tool cmp actual tee-output ||
die "tee failed"
tool test -f tee-output &&
tool '[' -f tee-output ] ||
die "test or [ failed"
tool touch -t 202001020304 tee-output ||
die "touch failed"
test ABC = "$(printf abc | tool tr a-z A-Z)" ||
die "tr failed"
tool true ||
die "true failed"
tool truncate -s 2 tee-output &&
test 2 = "$(tool wc -c <tee-output | tr -d ' ')" ||
die "truncate or wc failed"
printf 'a b\nb c\n' | tool tsort >actual &&
test 3 = "$(tool wc -l <actual | tr -d ' ')" ||
die "tsort failed"
printf 'a   b\n' | tool unexpand -a -t 4 >actual &&
printf 'a\tb\n' >expect &&
tool cmp expect actual ||
die "unexpand failed"
printf remove >unlink-me &&
tool unlink unlink-me &&
test ! -e unlink-me ||
die "unlink failed"
tool yes yes | tool head -n 2 >actual
printf 'yes\nyes\n' >expect
tool cmp expect actual ||
die "yes failed"

printf 'same' >left &&
tool cp left right &&
tool cmp -s left right &&
tool diff -u left right >actual &&
printf 'changed' >right &&
tool cmp -s left right && die "cmp did not report a difference"
tool diff left right >/dev/null
test 1 = $? ||
die "diff returned an unexpected status"

tool mkdir -p find &&
printf 'one\n' >find/1.txt &&
printf 'two\n' >find/2.txt &&
tool find find -name '*.txt' -print0 |
tool xargs -0 "$bindir/cat.exe" >actual &&
printf 'one\ntwo\n' >expect &&
tool cmp expect actual ||
die "find or xargs failed"

utf8="caf$(printf '\303\251').txt"
printf 'unicode' >"$utf8" &&
tool cp "$utf8" utf8-copy &&
tool mv utf8-copy utf8-moved &&
test unicode = "$(tool cat utf8-moved)" ||
die "UTF-8 filename handling failed"

signal_seen=
trap 'signal_seen=t' TERM
kill -TERM $$ ||
die "Could not deliver SIGTERM to Git Bash"
trap - TERM
test t = "$signal_seen" ||
die "Git Bash did not run the SIGTERM trap"

export PATH="$bindir:$PATH"
export GIT_CONFIG_NOSYSTEM=1
export HOME="$tmp/home"
export XDG_CONFIG_HOME="$HOME"
tool mkdir -p "$HOME"
git config --global user.name "BusyBox test"
git config --global user.email busybox@example.invalid

git init -q --bare remote.git &&
git init -q source &&
(
	cd source &&
	printf 'initial\n' >tracked &&
	git add tracked &&
	git commit -qm initial &&
	git branch -M main &&
	git remote add origin ../remote.git &&
	git push -q -u origin main
) &&
git --git-dir=remote.git symbolic-ref HEAD refs/heads/main &&
git clone -q remote.git clone ||
die "clone workflow failed"

(
	cd source &&
	printf 'fetched\n' >>tracked &&
	git commit -qam fetched &&
	git push -q
) &&
(
	cd clone &&
	git fetch -q &&
	git checkout -q origin/main &&
	grep -q fetched tracked
) ||
die "fetch or checkout workflow failed"

(
	cd clone &&
	git checkout -qb topic main &&
	printf 'topic\n' >topic &&
	git add topic &&
	git commit -qm topic &&
	git checkout -q main &&
	printf 'main\n' >main &&
	git add main &&
	git commit -qm main &&
	git checkout -q topic &&
	git rebase -q main &&
	printf 'pick\n' >picked &&
	git add picked &&
	git commit -qm picked &&
	pick=$(git rev-parse HEAD) &&
	git checkout -qb consumer HEAD^ &&
	git cherry-pick "$pick" >/dev/null &&
	test -f picked
) ||
die "rebase or cherry-pick workflow failed"

(
	cd clone &&
	git checkout -q main &&
	printf '#!/bin/sh\nprintf hook-ran >../hook-ran\n' >.git/hooks/pre-commit &&
	/usr/bin/chmod +x .git/hooks/pre-commit &&
	printf 'hook\n' >hooked &&
	git add hooked &&
	git commit -qm hook &&
	test hook-ran = "$(cat ../hook-ran)"
) ||
die "hook workflow failed"

git init -q submodule-source &&
(
	cd submodule-source &&
	printf 'submodule\n' >content &&
	git add content &&
	git commit -qm submodule
) &&
(
	cd clone &&
	git checkout -q main &&
	git -c protocol.file.allow=always submodule add -q ../submodule-source deps/sub &&
	git commit -qm submodule
) &&
git -c protocol.file.allow=always clone -q --recurse-submodules clone submodule-clone &&
test -f submodule-clone/deps/sub/content ||
die "submodule workflow failed"

git init -q lfs &&
(
	cd lfs &&
	git lfs install --local >/dev/null &&
	git lfs track '*.bin' >/dev/null &&
	printf 'large-object\n' >object.bin &&
	git add .gitattributes object.bin &&
	git commit -qm lfs &&
	git show :object.bin | grep -q 'oid sha256:'
) ||
die "Git LFS workflow failed"

(
	cd clone &&
	git checkout -q main &&
	git archive --format=zip -o ../archive.zip HEAD &&
	git archive --format=tar HEAD >../archive.tar &&
	git diff HEAD^ HEAD >../change.patch
) &&
tool mkdir archive-output &&
(
	cd archive-output &&
	tool unzip -q ../archive.zip &&
	test -f tracked
) &&
tool mkdir tar-output &&
tar -xf archive.tar -C tar-output &&
test -f tar-output/tracked &&
(
	cd clone &&
	git checkout -qb apply-test HEAD^ &&
	git apply ../change.patch &&
	test -f hooked
) ||
die "archive or patch/apply workflow failed"

git config --global credential.helper \
	'!f() { test "$1" = get && printf "%s\n" username=test-user password=test-password; }; f' &&
printf 'protocol=https\nhost=example.invalid\n\n' |
git credential fill >credential-output &&
grep -q '^username=test-user$' credential-output &&
grep -q '^password=test-password$' credential-output ||
die "credential workflow failed"

echo "ARM64 BusyBox compatibility checks passed"
