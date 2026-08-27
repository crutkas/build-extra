# Native ARM64 MSYS shell payload

This directory owns the final-product integration of the native ARM64 MSYS
runtime and shell closure. It does not build packages and does not assemble
the separate portable preview bundle.

`locks/native-shell-closure-v1.json` is the rich immutable product contract.
The five a527 runtime packages, compiler evidence, and fixed binutils validator
are pinned to public release assets. The final ncurses, readline, and Bash
packages remain unresolved because fixed-linker release assets do not exist
yet. Their known package and ownership admission constraints are recorded
separately while identity, asset, package, and overlay fields remain null.
Final mode rejects that state before downloading or changing a payload.

The integration never uses the shared MSYS2 installation or its Pacman
client. Archives are downloaded directly into a private cache, verified
before extraction, and extracted into fresh private directories. Only
explicit overlay mappings can enter the product. Cross-host GCC and binutils
executables are validation inputs and are forbidden from the payload.

Use `install.ps1 -Mode Preview` to validate the lock and report unresolved
inputs. Product materialization copies its exact bytes to
`<Root>/preview-evidence/source-lock.json` and derives the canonical validator
adapter at `<Root>/preview-evidence/bundle-lock.v1.json`. Before applying any
overlay, it inventories the complete staged tree into
`<Root>/preview-evidence/base-tree-manifest.v1.json`. The adapter binds that
manifest as derived input `stack-base` at build commit
`be0217cb572704f27ea04c9abde8bb992b8ef0c0`, without claiming an SDK identity.
Provenance and the complete payload manifest bind the adapter, not the rich
source lock.

Product materialization also requires `-AssemblerCommit`. The file-list
wrapper derives it from `HEAD` only after verifying that `install.ps1` and
`NativeShell.psm1` match the committed blobs, then exports it as
`GFW_ARM64_NATIVE_SHELL_ASSEMBLER_COMMIT`.

`install.ps1 -Mode Final` additionally requires a payload root, private
cache/work directories, and the authoritative payload validator owned by the
ARM64 payload-gate lane. It first runs static Final validation without reading
runtime evidence. `-AssemblyEvidence` and `-RuntimeEvidence` are optional, but
must be supplied together; when present, a successful Final check is followed
by a separate Runtime check and report. The Runtime invocation receives the
successful static report through `-StaticReport`; both runtime evidence
documents bind that report's exact SHA-256. Static product builds omit runtime
evidence.
Preview products use static Preview admission while shell inputs remain
unresolved; Final admission remains fail-closed until all inputs resolve and
the validator reports no remaining x64 payload.

Installer, PortableGit, and MinGit builds copy their baseline file lists into
fresh per-invocation staging roots. Final overlay and gate checks run there,
never against the live SDK. Provenance, payload, report, and work paths gain
an artifact-and-process suffix so repeated products cannot reuse transaction
state.
