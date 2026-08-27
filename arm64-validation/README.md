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
  -ToolRoot <validation-tools> -Report <validation-report.json>
```

The runtime document declares `admissionMode` as `Preview` or `Final`.
The validator applies that static admission policy before validating runtime
evidence. Preview and Final never read or execute assembly-run or runtime
evidence. Runtime requires both evidence documents.

Assembler-facing aliases are `-PortableRoot`, `-LockPath`,
`-ProvenancePath`, `-PayloadManifestPath`, `-AssemblyEvidencePath`,
`-RuntimeEvidencePath`, and `-OutputPath`. The canonical names above remain
the contract.

## Digest graph

The graph is strictly acyclic:

1. Provenance binds the raw lock-file SHA-256.
2. The payload manifest binds raw lock and provenance SHA-256 values.
3. Assembly-run evidence and runtime evidence independently bind raw lock,
   provenance, and payload-manifest SHA-256 values plus the root inventory
   SHA-256, and repeat the rich source-lock SHA-256.

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
URL. Roles include `base-bundle`, `payload`, and `validation-tool`. Package
metadata is null when none exists rather than fabricated. Every unresolved
input has null resolution, release, asset, package, and overlay fields.
Validation tools use a disabled overlay and never enter the payload.

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

## Policy and pins

Preview allows only x64 paths already present in
`arm64-x64-payload-baseline.txt`, reports all remaining x64 paths, and sets
`readyForFinal=false`. Final allows no x64 path and no unresolved input.
Every native-shell closure path must exist as a file. Final requires every
closure file to classify as ARM64.
Native x86, unknown PE machines, mixed MSYS/Cygwin imports, unsafe roots,
traversal, case collisions, reparse points, and use of `C:\msys64` fail
closed.

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
The scanner must exit 0 with `result=pass`; nonempty v1 tables fail, and every
v2 record in this lane must use flag 64.

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
path.
