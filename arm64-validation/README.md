# ARM64 x64-path ownership ledger

This directory derives a scheduling ledger for every x64 PE path in the
official Git for Windows v2.55.0(4) ARM64 release. It does not claim that any
released path has been removed or replaced. Candidate and modeled groups
remain unresolved until downstream native bytes receive separate immutable
admission.

`generate-arm64-x64-ledger.ps1` downloads release asset `510402464` twice by
its GitHub asset API URL and checks both copies against the API digest, size,
and SHA-256. It scans each decompressed TAR as a byte stream and never extracts
or follows links. The five reviewed POSIX absolute symlinks are recorded as
installed-link metadata; their targets are not extraction destinations. All
hardlinks are resolved within the in-memory archive model.

Package attribution comes from two independent private bare Git clones of
`git-for-windows/git-sdk-arm64` at commit
`7a77c0c5ff81d1c979302c9cc49a62f26f68d17c`. The generator reads only Git
objects under the pinned `var/lib/pacman/local` tree and does not use an SDK
worktree or SDK `main`.

Run the complete local validation with:

```powershell
$token = gh auth token
.\arm64-validation\generate-arm64-x64-ledger.ps1 `
  -PrivateRoot "$env:TEMP\arm64-ledger-$([guid]::NewGuid().ToString('N'))" `
  -GitHubToken $token
.\arm64-validation\check-arm64-x64-ledger.ps1
.\arm64-validation\test-arm64-x64-ledger.ps1
```

The generator must produce byte-identical UTF-8/no-BOM, LF-only artifacts
under both Windows PowerShell 5.1 and PowerShell 7. The dedicated workflow
runs both runtimes, binds checkout to the exact pull-request head, and retains
each runtime's canonical artifacts and exact-run evidence.
