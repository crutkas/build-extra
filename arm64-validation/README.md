# Authoritative ARM64 preview admission

`validate-arm64-preview.ps1` is the fail-closed post-materialization boundary.
It does not download, extract, prepare, overlay, or assemble content. The
assembler must materialize the portable root and produce all four v1 input
documents before invoking it.

## Exact invocation and paths

```powershell
pwsh -NoProfile -File <pinned-build-extra>\validate-arm64-preview.ps1 `
  -Mode preview `
  -PortableRoot C:\staging\PortableGit `
  -LockPath C:\staging\PortableGit\preview-evidence\bundle-lock.v1.json `
  -ProvenancePath C:\staging\PortableGit\preview-evidence\deterministic-provenance.v1.json `
  -PayloadManifestPath C:\staging\PortableGit\preview-evidence\payload-manifest.v1.json `
  -RuntimeEvidencePath C:\staging\PortableGit\preview-evidence\runtime-evidence.v1.json `
  -OutputPath C:\staging\PortableGit\preview-evidence\validation-evidence.v1.json
```

All five JSON paths are required below `<PortableRoot>\preview-evidence` with
the exact filenames shown. Replace `preview` with `final` for final admission.
`preview` inventories and reports broader payload x64 while requiring every
`nativeShellClosure` PE and every observed native process/module to be ARM64.
`final` additionally rejects all non-ARM64 native payload PE, ARM64EC, x86,
x64, unknown PE/CLR, and unresolved package slots. CLR AnyCPU is permitted
outside the native closure.

Runtime evidence is event-complete, not sampled: `collection.complete=true`,
`droppedEvents=0`, method `etw-image-load`, per-process
`modulesComplete=true`, and successful `shell` and `git` smokes are mandatory.
Any x64/x86/unknown process or module is red. Missing input, mismatched digest,
incomplete collection, missing evidence, or missing/nonpassing output fails
closed.

## Contracts

The strict JSON Schema 2020-12 contracts are:

- `preview-lock-v1.schema.json`
- `payload-manifest-v1.schema.json`
- `deterministic-provenance-v1.schema.json`
- `runtime-evidence-v1.schema.json`
- `validation-evidence-v1.schema.json`

The payload manifest requires exactly:

```json
"scope":{"root":".","excludedPrefixes":["preview-evidence/"]}
```

Its sorted `files` array covers every non-directory path outside that prefix
and records exact bytes/SHA-256 for files. Archive declarations contain the
complete member inventory, hashes, and logical package owner. The validator
compares both inventories with disk/archive content and independently obtains
PE/CLR architecture through the repository's `pe-imports.ps1` inventory
helper.

Deterministic provenance contains no timestamp, host, shared installation, or
other mutable observation. It requires the exact payload reference
`{"path":"payload-manifest.v1.json","sha256":"<64 lowercase hex>"}`, the lock
digest, assembler revision, immutable source inputs, and validator revision.
The validator file set is exactly:

- `validate-arm64-preview.ps1`
- `pe-imports.ps1`

Both byte counts and SHA-256 values are verified before admission. No
extractor, binutils, or preparation executable is part of that set or allowed
anywhere in the preview, including the excluded evidence prefix.

The main evidence binds `previewId`, `mode`, validator repository/commit and
the exact byte counts/SHA-256 values of lock, deterministic provenance,
payload manifest, and runtime evidence. It includes full root PE/CLR
inventory, root file inventory, archive/member checks, runtime summary,
unresolved slots, and every violation. A no-op `{"result":"pass"}` does not
conform to the schema.

## Exit semantics

| Code | Meaning |
| ---: | --- |
| 0 | `result=pass`; selected mode admitted |
| 2 | preview only: `result=not-ready`; contract valid but slots unresolved |
| 3 | `result=fail`; content, architecture, archive, or runtime policy failed |
| 64 | CLI usage or required-path error; output is absent |
| 65 | missing/malformed input or binding failure; output is absent |
| 70 | internal/scanner/write failure; output is absent |

Codes 0, 2, and 3 write complete evidence atomically. Consumers must require
code 0, a present evidence file conforming to the evidence schema, and
`result=pass`; every other state is failure.
