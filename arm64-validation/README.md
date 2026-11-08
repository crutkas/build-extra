# ARM64 bundle validation contract

`validate-arm64-bundle.ps1` is the final, immutable integration boundary
after an assembler has downloaded, verified, extracted, and overlaid an ARM64
bundle. It requires PowerShell 7.5 or newer and has no external module
dependencies.

## Invocation

Static Preview validation:

```powershell
pwsh -NoProfile -File validate-arm64-bundle.ps1 `
  -Mode Preview -Root <staged-root> -Lock <bundle-lock.json> `
  -Provenance <bundle-provenance.json> `
  -PayloadManifest <payload-manifest.json> `
  -ToolRoot <validation-tools> -Report <validation-report.json>
```

Static Final validation uses the same command with `-Mode Final`.
`-ToolRoot` is needed only when detected ARM64 MSYS payload PEs require
pseudo-reloc scanning.

Runtime evidence is read only in Runtime mode:

```powershell
pwsh -NoProfile -File validate-arm64-bundle.ps1 `
  -Mode Runtime -Root <staged-root> -Lock <bundle-lock.json> `
  -Provenance <bundle-provenance.json> `
  -PayloadManifest <payload-manifest.json> `
  -AssemblyEvidence <assembly-run-evidence.json> `
  -RuntimeEvidence <runtime-evidence.json> `
  -StaticReport <prior-preview-or-final-report.json> `
  -ToolRoot <validation-tools> -Report <validation-report.json>
```

The runtime document declares `admissionMode` as `Preview` or `Final`.
The validator applies that static admission policy before validating runtime
evidence. Preview and Final never read or execute assembly-run or runtime
evidence. Runtime requires both evidence documents plus the static report from
a prior successful Preview or Final run over the same inputs. `-StaticReport`
is rejected in Preview and Final.

Assembler-facing aliases are `-PortableRoot`, `-LockPath`,
`-ProvenancePath`, `-PayloadManifestPath`, `-AssemblyEvidencePath`,
`-RuntimeEvidencePath`, `-StaticReportPath`, and `-OutputPath`. The canonical
names above remain the contract.

## Classification ownership

The payload manifest is producer-owned but carries no architecture data. Each
entry is exactly `path`, `type`, `bytes`, `sha256`, `linkTarget`. The
validator alone derives `architecture`, `machine`, `personality`, `imports`
and `clrFlags` by parsing each materialized PE, and emits them in the
`classifications` array of its own report. A payload manifest that declares
any classification property is rejected as a schema violation.

## Digest graph

The graph is strictly acyclic:

1. Provenance binds the raw lock-file SHA-256.
2. The payload manifest binds raw lock and provenance SHA-256 values.
3. Assembly-run evidence and runtime evidence independently bind raw lock,
   provenance, and payload-manifest SHA-256 values, the root inventory
   SHA-256, and the static report SHA-256, and repeat the rich source-lock
   SHA-256.
4. The static report binds lock, provenance, payload manifest and root
   inventory. Runtime reads it; nothing static reads runtime output.

The root inventory digest is SHA-256 over ordinally sorted UTF-8 lines:
`type<TAB>path<TAB>bytes<TAB>sha256<LF>`. Directories use byte count `0`
and hash `-`. No upstream document may bind a downstream digest.

## Documents

The v1 schemas are in `arm64-validation/schemas/`. All object properties are
closed. Paths use relative forward-slash form, ordinal order, and
case-insensitive uniqueness.

The canonical adapter lock is exactly
`preview-evidence/bundle-lock.v1.json`, serialized as UTF-8 without BOM,
LF-only, with final LF. Its required property order is `schemaVersion`,
`sourceLock`, `sourceDateEpoch`, `nativeShellClosure`, `inputs`.
`sourceLock` is exactly
`{path:"preview-evidence/source-lock.json",sha256:<rich-lock SHA-256>}` and is
verified against that excluded evidence file. Inputs are ordinally sorted by
ID. This lets a richer product lock derive a stable validator projection
without adding a reverse digest edge.

The lock contains deterministic `sourceDateEpoch`, ordered
`nativeShellClosure`, and resolved/unresolved inputs. Allowed immutable
repositories are `crutkas/*`, `git-for-windows/git`, and `ip7z/7zip`; the
validator never fetches them. `github-release` identities bind repository,
tag, commit, and exact release URL. `github-raw-commit` identities bind
repository, full commit, source path, and exact `raw.githubusercontent.com`
URL. A `base-bundle` may instead use `derived-tree` when the root is built by
this repository rather than downloaded: `release`, `asset` and `package` are
then null, and the resolution binds `build:{repository:"crutkas/build-extra",
commit}`, an optional exact `sdkSource` identity that is never guessed, and
`manifest:{path:"preview-evidence/base-tree-manifest.v1.json",sha256}`. The
validator reads that manifest, verifies its exact bytes and serialization, and
requires the provenance base archive members to match it entry for entry.
A `derived-tree` base overlays the destination root using identity mappings;
later overlays replace ownership explicitly. `derived-tree` is additive: a
base materialized from an official release asset keeps `github-release`.
Exactly one resolved input has role `base-bundle`.
`provenance.overlayOrder` is the authoritative application order: it starts
with that base input and then lists every resolved payload overlay exactly
once. Canonical lock inputs and provenance inputs remain ordinally sorted by
ID only for serialization; that sorting never determines overlay precedence.
Roles include `base-bundle`, `payload`, and `validation-tool`. Package
metadata is null when none exists rather than fabricated. Package `provides`
are concrete payload-relative normalized paths, not `.PKGINFO` virtual
provide tokens. Every unresolved input has null resolution, release, asset,
package, and overlay fields. Validation tools use a disabled overlay and
never enter the payload.

Deterministic provenance binds only the lock. It repeats `sourceDateEpoch`,
`nativeShellClosure`, and each resolved immutable identity; enumerates the
complete ordered archive member set; marks every include/exclude selection;
records the exact destination; names every replacement loser and final winner;
and enumerates all final members. It contains no host, current time, shared
observation, payload path, or payload digest. The validator derives selection
from `overlay.destination` and the include/exclude rules rather than trusting a
selected flag. Explicit overlay `mappings` bind archive-member renames;
unmapped selections use `destination/sourceMember`.

The payload manifest covers every materialized file and directory below `.`
except exactly `preview-evidence/`. Every file is rebound to its winning
archive member by source member, byte count, and SHA-256. The validator scans
every file for MZ/PE content regardless of extension and validates the full
DOS, COFF, optional-header, section, import, and CLR structure before
classifying architecture or personality.

Archive members may be files, directories, symlinks, or hardlinks. Link
targets are normalized in-archive paths, must resolve to another exhaustively
enumerated selected member, must preserve target bytes/hash, and may not form
cycles. Scoped payload symlinks are allowed only when manifest and provenance
declare the same contained file target. Directory links, junctions, mount
points, broken/escaping/cyclic links, and undeclared reparse points fail.
Declared hardlinks must share the target's NTFS file identity and bytes/hash.
Because Windows reports every name of a multiply linked file as a hard link
with an empty target, identity is enumerated with `fsutil hardlink list`:
every name must lie under Root, and a multiply linked file is accepted only
when provenance declares it as a hardlink or as the canonical target of a
declared hardlink alias. Undeclared multiply linked files are rejected. Member
paths may not have a component ending in a dot or space, because Win32 would
open a different file than the one enumerated, and no member of any type may
carry an NTFS alternate data stream.

Runtime evidence records exactly Git Bash, Git, SSH, GPG, hook, submodule,
rebase, and git-svn. A passing scenario has an exact command vector, complete
ETW kernel process and image-load coverage, `lostEvents=0`, a complete process
tree, one role process, unique process instances/times, explicit parent links,
strictly enclosing trace times, and complete module lists. Snapshot sampling
is not admissible. Preview admission may use a reason-only unresolved scenario
with null trace. Final admission may not.
Runtime evidence repeats the assembly-run `previewId` and identifies the
validator as repository `crutkas/build-extra`, this checkout's full commit,
and mode `Runtime`. `previewId` is run identity only; immutable lock,
provenance, and payload documents do not accept `closureId` or `previewId`.
The validator commit must equal the attached checked-out `crutkas*` branch
HEAD, the checkout's `origin` must identify `crutkas/build-extra`, and that
HEAD must be reachable from the matching `refs/remotes/origin/<branch>` ref.
A dangling commit or a commit from another branch is not accepted merely
because it carries the same validator blob. Likewise, a `derived-tree` build
commit, or a `github-raw-commit` input whose repository is
`crutkas/build-extra`, must resolve to a commit object in this checkout and be
reachable from that authoritative remote-tracking ref. Other allowlisted
repositories remain immutable recorded identities and are never fetched.

The closed command vectors are the staged absolute executable followed by
exactly these suffixes:

| Scenario | Executable | Required argv suffix |
| --- | --- | --- |
| Git Bash | `usr/bin/bash.exe` | `--noprofile --norc -lc "exit 0"` |
| Git | `bin/git.exe` | `--version` |
| SSH | `usr/bin/ssh.exe` | `-V` |
| GPG | `usr/bin/gpg.exe` | `--version` |
| hook | `usr/bin/bash.exe` | `--noprofile --norc -lc "exit 0"` |
| submodule | `bin/git.exe` | `submodule status --recursive` |
| rebase | `usr/bin/bash.exe` | `--noprofile --norc -lc "git rebase --show-current-patch"` |
| git-svn | `usr/bin/bash.exe` | `--noprofile --norc -lc "git svn --version"` |

`collector` is not a self-attested identity. Its exact fields are `inputId`,
`repository`, `commit`, `sourcePath`, `url`, `bytes`, `sha256`, and `method`.
`inputId` must resolve to a canonical lock input with role `validation-tool`,
status `resolved`, and resolution `github-raw-commit`. Repository, commit, and
sourcePath equal that input's raw-commit release; URL, bytes, and SHA-256 equal
its asset; and the provenance archive member at sourcePath repeats the bytes
and SHA-256 while remaining unselected. `method` is exactly
`ETW-Kernel-Process-ImageLoad`.

## Policy and pins

Preview allows only x64 paths already present in
`arm64-x64-payload-baseline.txt`, reports all remaining x64 paths, and sets
`readyForFinal=false`. Final allows no x64 path and no unresolved input.
Every native-shell closure path must exist as a file. Final requires every
closure file to classify as ARM64.
Native x86, unknown PE machines, mixed MSYS/Cygwin imports, unsafe roots,
traversal, case collisions, reparse points, and use of `C:\msys64` fail
closed.
Runtime modules outside the staged root are accepted only below canonical
`C:\Windows\System32`, `C:\Windows\SysArm32` (where present), or
`C:\Windows\WinSxS`. Other Windows subtrees, including `Temp` and `Tasks`,
are not trusted.

Pseudo-reloc candidates are detected ARM64 PEs importing `msys-2.0.dll`;
declared package personality is not used for target selection. The committed
scanner is the exact 10,569-byte source at
`crutkas/MSYS2-packages@3356eec1411983cc252b04afac32bca5f3b8d824` with
SHA-256
`888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`.
Objdump and nm must match their archive-member records from immutable package
`mingw-w64-cross-cygwinarm64-binutils` version `2.44.50-2`, package SHA-256
`3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b`.
The canonical objdump member is 2,887,699 bytes with SHA-256
`bb0d53db4128aff7f6b20c46be4e3625b1d82134476d7b03e58ed22015136e6e`;
the canonical nm member is 1,257,877 bytes with SHA-256
`80b4716108b362ba05f48cd9228d20a4193897b4a5eeb8eb19e80f4c83e3e90a`.
The canonical linker member SHA-256 is
`075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`
for 1,887,140 bytes.
The scanner must exit 0 with `result=pass`, but that alone is not proof.
Admissible output is only an explicitly parsed `empty` table, or a `v2` table
whose record count equals its flags count and whose every flag is 64.
`absent`, unknown, v1, and malformed results fail closed, including stripped
native MSYS PEs for which symbol lookup reports no table.

The shared `C:\msys64` observation is accepted only as a live,
non-authoritative before/after record in downstream assembly-run evidence.
The assembly host may be Windows AMD64 or ARM64 and records both OS and
PowerShell process architecture. Any before/after difference or mutation-risk
command, including `pacman -Sw`, is rejected. The shared root is never an
input, deterministic provenance, payload, or runtime source.

The package-database canonical manifest covers regular files below
`C:\msys64\var\lib\pacman\local`. It is generated by PowerShell 7 with this
exact pipeline:

```powershell
Get-ChildItem $db -Recurse -File |
  Sort-Object FullName |
  ForEach-Object {
    [pscustomobject]@{
      path = $_.FullName.Substring($db.Length + 1)
      length = $_.Length
      lastWriteUtc = $_.LastWriteTimeUtc.ToString("o")
      sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  } |
  Export-Csv $out -NoTypeInformation -Encoding utf8
```

The external observation is a closed read-only vocabulary rather than free
text. `commands` is exactly this ordered four-item array, with no duplicates:
`enumerate-database-manifest`, `hash-database-manifest`, `hash-package-log`,
`stat-package-log`. Missing, extra, reordered, duplicate, or other values,
including every `pacman` invocation and `pacman -Sw`, are rejected as a
mutation risk.

The exact columns are `path,length,lastWriteUtc,sha256`; paths are relative
Windows backslash paths. `Export-Csv` supplies standard CSV quoting, UTF-8
without BOM, and Windows CRLF. The database snapshot records the data-row
count as `files`, manifest byte length as `bytes`, and full lowercase hash as
`canonicalManifestSha256`. The historical observation was 1,178 rows,
170,275 bytes, and SHA-256
`93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34`;
those are observations, not schema constants.

## Exit and report contract

| Code | Meaning |
| ---: | --- |
| 0 | Validation passed |
| 10 | Validator, committed scanner, or scanner-tool execution failure |
| 20 | Schema, provenance, digest, archive, member, overlay, or ownership failure |
| 30 | Static architecture, import personality, or pseudo-reloc policy failure |
| 40 | Runtime evidence, ETW completeness, runtime identity, or runtime policy failure |

The validator writes a deterministic report whenever the report destination
can be created. Reports contain no validation-time timestamp or temporary
path. The report destination must be a local drive-qualified path outside
Root, ToolRoot, `C:\msys64`, every validator input, and the entire validator
checkout.
The checkout restriction includes its worktree and common Git metadata plus
the validator's scanner, baseline, PowerShell, Git, and filesystem-inspection
dependencies. Existing report hardlink identities are checked as well. If an
otherwise successful validation cannot atomically write its report, the
process exits nonzero.

Per-mode success predicates, all of which must hold for exit code 0:

- **Preview**: `mode="Preview"`, `result="pass"`, `exitCode=0`, `errors` empty,
  every contract/provenance/payload check passes, and every remaining x64
  classification is a subset of the historical baseline. `readyForFinal` is
  true only when there are additionally no unresolved inputs and no remaining
  x64 members, so Preview can pass while `readyForFinal` is false.
- **Final**: as Preview plus `admissionMode="Final"`, zero unresolved inputs
  and an empty `remainingX64`; a passing Final always reports
  `readyForFinal=true`.
- **Runtime**: `mode="Runtime"`, `result="pass"`, `exitCode=0`, the supplied
  static report records a passing Preview or Final over the identical lock,
  provenance, payload manifest and root inventory digests, and assembly-run
  and runtime evidence bind all five digests including the static report.
  The recomputed static state must set `readyForFinal=true`.
  `admissionMode` is taken from the runtime document and its static policy is
  applied before evidence is validated.

In every mode, `digests.rootInventorySha256` is populated from the validator's
own exhaustive enumeration, and `classifications` carries the validator-derived
per-path architecture data.
