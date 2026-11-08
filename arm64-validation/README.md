# ARM64 payload validation

`validate-arm64-bundle.ps1` is the final integration boundary between a
bundle assembler and Git for Windows ARM64 admission. The assembler owns
download, extraction, overlay ordering, and runtime trace collection. The
validator independently verifies those records, scans the materialized
payload, and applies architecture policy.

The validator never uses `C:\msys64` as an input or evidence source. A
read-only shared installation may be recorded only as a non-authoritative
external observation with identical before/after snapshots.

## Invocation

Run the validator after materialization and runtime trace collection, before
atomically admitting the staged root:

```powershell
pwsh -NoProfile -File validate-arm64-bundle.ps1 `
  -Mode Preview `
  -Root C:\staging\PortableGit `
  -Lock C:\evidence\bundle-lock.json `
  -Provenance C:\evidence\bundle-provenance.json `
  -PayloadManifest C:\evidence\payload-manifest.json `
  -RuntimeEvidence C:\evidence\runtime-evidence.json `
  -ToolRoot C:\evidence\validation-tools `
  -Report C:\evidence\validation-report.json
```

`-PortableRoot`, `-LockPath`, `-ProvenancePath`,
`-PayloadManifestPath`, `-RuntimeEvidencePath`, and `-OutputPath` are
aliases for the corresponding parameters above.

Use `-Mode Final` only for final admission. `-ToolRoot` is required when
resolved native MSYS inputs need pseudo-relocation validation.

| Exit | Meaning |
| ---: | --- |
| 0 | Contract and selected mode passed |
| 1 | Scanner, tool, or payload enumeration failed closed |
| 2 | Lock, provenance, ownership, overlay, archive, or digest contract failed |
| 3 | Static payload architecture or pseudo-relocation policy failed |
| 4 | Runtime process/module evidence failed |

The report is always written when validation reaches policy evaluation.

## Modes

Preview mode:

- allows lock inputs and runtime scenarios explicitly marked `unresolved`;
- requires all immutable fields of an unresolved lock input to be `null`;
- reports remaining baseline x64 payloads and sets `readyForFinal=false`;
- rejects placeholders, new x64 paths, malformed or incomplete scans,
  foreign runtime processes/modules, and wrong runtime personalities.

Final mode adds these requirements:

- every input is resolved and immutable;
- every required runtime scenario passed;
- the materialized payload contains zero x64 PE files;
- every resolved native MSYS PE passed fixed-linker pseudo-relocation checks.

Both modes fail on any observed x64 process or loaded module. Runtime
processes must be ARM64. Payload modules may be ARM64 or CLR AnyCPU.
Cygwin personality is not an MSYS substitute and is rejected.

## Schema v1

The machine-readable contracts are:

- `bundle-lock-v1.schema.json`
- `bundle-provenance-v1.schema.json`
- `payload-manifest-v1.schema.json`
- `runtime-evidence-v1.schema.json`

All paths use `/`, are relative, and may not contain traversal, drive
prefixes, empty components, or case-insensitive collisions.

### Lock

The lock has `schemaVersion=1` and an `inputs` array. Resolved inputs require
full fork-only release, asset, package, and overlay identities. Package
`provides` entries are exact final destination paths and are used to detect
missing replacements and overlap between packages.

Tool inputs use `role=tool` and `overlay.enabled=false`; they are verified
under `-ToolRoot` and must never enter the payload. Other resolved inputs
use `overlay.enabled=true`. Unresolved inputs set `resolution`, `release`,
`asset`, `package`, and `overlay` to `null`.

Package `personality` is one of:

- `mingw`: native Win32/MinGW PE without MSYS/Cygwin runtime imports;
- `msys`: imports `msys-2.0.dll`;
- `managed`: CLR AnyCPU;
- `windows`: Windows-owned executable or module;
- `mixed`: base bundle containing multiple personalities.

### Provenance

Provenance binds to the exact lock SHA-256 and records:

- the full assembler commit;
- Windows/ARM64 host and UTC creation time;
- exact release, asset, and package verification for every resolved input;
- ordered archive members with source/destination/type/size/hash;
- explicit `replacesSourceInput` for every overlay collision;
- validator and candidate tool identities;
- fixed-linker pseudo-relocation inputs when native MSYS packages are present.

Every include pattern must select at least one recorded archive member. Every
selected member must appear exactly once in the final overlay map. Case-only
collisions and undeclared replacement collisions fail.

Shared `C:\msys64` observations remain non-authoritative. For the current
observation at `2026-08-27T15:55:35Z`, the full values are:

- log: 155150 bytes,
  SHA-256 `925ce045782b49e6454956eae9ee0a5b700b17c805843d18329509f4e2a492c8`;
- database: 1178 files, canonical manifest SHA-256
  `93a39fb4e4105489b733275fa94e8cc718f25c239f0064cd64c4a68832a68c34`.

The validator requires full hashes and exact before/after equality. A
recorded `pacman -Sw` command is rejected as mutation-risk.

### Payload manifest

The payload manifest binds to the lock and provenance SHA-256 values. Its
ordinally sorted `entries` array covers every materialized file, directory,
and symlink. Each entry records final path, type, source input/package/member,
and immutable file size/hash. PE entries add:

```json
{
  "architecture": {
    "kind": "arm64",
    "machine": "0xAA64",
    "personality": "msys"
  }
}
```

The validator enumerates the root and verifies that no manifest or disk
member is missing. It scans every file regardless of extension, distinguishes
CLR AnyCPU from native x86, parses imports without loading the image, and
rejects scanner errors. Non-PE files set `architecture` to `null`.

The authoritative historical baseline remains:

- `arm64-payload-architecture-v2.55.0.4.tsv`
- 732 PE rows: 209 ARM64, 432 x64, 90 AnyCPU, one x86
- normalized manifest SHA-256
  `ae1e311fd81258150c2300d02c58655f30b190a15bcbe3ea8bbaccc1ce8c1c9a`

### Fixed-linker pseudo-relocations

For each ARM64 PE sourced from a resolved `package.personality=msys` input,
provenance lists an ordinally sorted pseudo-relocation target. The validator
uses only candidate-owned tools under `-ToolRoot` and invokes:

```powershell
pwsh -NoProfile -File <scanner> `
  -PePath <payload-pe> `
  -OutputPath <temporary-json> `
  -Objdump <tool-root>\opt\bin\aarch64-pc-cygwin-objdump.exe `
  -Nm <tool-root>\opt\bin\aarch64-pc-cygwin-nm.exe
```

Pinned scanner:

- `crutkas/MSYS2-packages@3356eec1411983cc252b04afac32bca5f3b8d824`
- `.ci/check-aarch64-pseudo-relocs.ps1`
- 10569 bytes
- SHA-256
  `888939b57d1bce2e3c119e7c4824703e893bd449d49a5142f040dd935741ddb9`

Pinned tool package:

- `mingw-w64-cross-cygwinarm64-binutils 2.44.50-2`
- package SHA-256
  `3c7b47529181dab726d22cf6ed045184260af915eea583488c13c07e478ac02b`
- canonical linker SHA-256
  `075ed377a430eb120a994dfdc7c3187e937331239204578d696f08ee1c72fb1f`

The scanner must exit 0 and report `result=pass`. An absent or empty table
passes. A nonempty v1 table, malformed report, or policy violation fails.
For this fixed-linker contract, every emitted v2 flag must be scalar64
(`64`), which is stricter than the scanner's general 8/16/32/64 policy.
Objdump, nm, and the linker are verified against their full hashes and must
not appear in the payload.

### Runtime evidence

Runtime evidence binds to the lock, provenance, and payload manifest hashes
and declares a native Windows/ARM64 host. Required scenario IDs are:

- `git-bash`
- `git`
- `ssh`
- `gpg`
- `hook`
- `submodule`
- `rebase`
- `git-svn`

A passed scenario records command exit 0, `traceComplete=true`, and every
observed process. Each process records its payload path/hash/architecture,
role, `modulesComplete=true`, and every loaded module. Payload module records
bind to payload entries; external modules must be full-hash Windows modules
under `C:\Windows`.

Required role/personality pairs include MSYS `shell`, `hook`, `rebase`, and
`git-svn`, and MinGW `git`, `ssh`, `gpg`, and `submodule`. Any x64/x86/unknown
process or module, Cygwin personality, incomplete trace, missing role, or
digest mismatch fails.

## Ownership backlog

`generate-arm64-x64-backlog.ps1` reproduces:

- `arm64-x64-ownership-v2.55.0.4.tsv`
- `arm64-x64-backlog-v2.55.0.4.json`

The generator accepts only the package database from
`crutkas/git-sdk-arm64@7a77c0c5ff81d1c979302c9cc49a62f26f68d17c`
at `var/lib/pacman/local`; it rejects shared `C:\msys64`. It fails on
unowned/ambiguous baseline paths and overlapping replacement claims.

The current model applies 114 paths from green or green-source candidate
BusyBox/OpenSSH/dos2unix/gawk/Vim work, then models 46 paths owned by the
unresolved runtime/ncurses/readline/Bash stack. It does not contain or
consume immutable pins for those unresolved packages. The resulting
machine-readable remaining backlog has 272 paths grouped by package,
dependency-removal opportunity, and required action.
