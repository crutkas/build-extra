# ARM64 vNext ownership foundation

This directory defines construction-time checks for ARM64 vNext payloads. It
does not grant admission or release authority.

`provenance.py` consumes the canonical, sealed
`arm64-vnext-input-provenance-v1` document and verifies a payload-input
manifest against the checked-in JSON schema. Every payload file must identify:

* its source repository, ref, commit, and tree;
* an admitted package or archive URL, size, SHA-256, and signature record;
* the build recipe path and canonical committed Git-blob SHA-256;
* the admitted Windows image; and
* the canonical SHA-256 of every provenance record on which it depends.

Diagnostics emitted by the tool are deliberately marked
`admission_authority: false`. A manifest cannot carry admission status or
authorization fields.

Payload paths are resolved under `--payload-root`; build recipe paths are
resolved independently under `--source-root`. Both are containment checked,
and payload uniqueness is enforced after case-normalized path resolution.
The manifest candidate must be the exact repository HEAD/ref/tree, and every
payload source identity must match it.

The process attestor under `process-attestor/` is an epoch-specific Windows
ARM64 utility. It creates the target suspended, measures the exact target
image through a stable handle that denies write/delete sharing, resumes it,
samples loaded modules through similarly held handles, and records file IDs,
mapped paths, hashes, PE identities, and the relevant live machine APIs.
Pre/post identity and hash mismatches are fatal. It accepts a process as
native ARM64 only when both the PE Machine and `ProcessMachineTypeInfo` are
`0xAA64`.

Run the focused tests with:

```
python -m unittest discover -s arm64-vnext/tests -v
```
