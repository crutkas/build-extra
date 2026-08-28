# Native ARM64 Vim input

`input-lock.json` is package-local candidate evidence. It freezes the audited
package and evidence hashes, package metadata, source commit, workflow run,
public release identity, replacement inventory, and expected payload deltas.

ARM64 SDK assembly runs `install.sh` in two phases. Staging admits only an
independently audited public prerelease whose pull request, workflow run,
annotated tag, release body, and exact three assets match the completed lock.
It downloads every asset by API asset ID and verifies its byte length and
SHA-256 before inspecting either package. Finalization replaces the seven
declared Vim PEs, copies the verified native dependency closure beside them,
retains the base `usr/bin/vimtutor` script, and writes the payload provenance
manifest. The authoritative payload assembler transforms these records into
its resolved bundle input and overlay; this candidate file is not itself a
bundle lock.

The `measuring` state permits asset consumption only when
`GFW_ARM64_VIM_MEASURE=1`; normal builds skip it and
`GFW_ARM64_VIM_REQUIRE=1` fails. After CI records exact installer and Portable
Git byte deltas, the lock advances atomically to `admitted`.
The shipped provenance binds the immutable source, release, package, and payload
identity, but excludes lifecycle state and compressed-product size assertions.
This avoids making those output measurements depend on their own lock values.
`-TestMode` is reserved for synthetic temporary fixtures in
`t/check-arm64-vim-integration.ps1`; it must not be used with release bytes.

The admitted lock records an installer delta of 1,680,591 bytes and a Portable
Git delta of 1,086,961 bytes. MinGit and BusyBox MinGit remain unchanged.
