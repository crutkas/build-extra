# Native ARM64 BusyBox payload

The package in this directory is the exact fork-local artifact built from
`crutkas/busybox-w32@e7299058b4074a19cfae0f446ec45ab87e804a27` by
`crutkas/MINGW-packages#4`.

Package:
`mingw-w64-clang-aarch64-busybox-1.38.0.git.e7299058-1-any.pkg.tar.zst`

SHA-256:
`93c5bc40010b58db0de29bd4eac3b87fa48d6c0e140c620208b1cd3d6722b499`

`install.sh` installs that package only for `ARCH=aarch64` and replaces the
paths in `default-replacements.txt` with hardlinks to the packaged BusyBox
executable. The default list is covered by the compatibility tests in `t/`.
`retained-paths.tsv` records every direct candidate and architecture gap that
remains on GNU/MSYS by default.

Set `GFW_EXPERIMENTAL_ARM64_BUSYBOX=1` at build time to include the additional
direct candidates in `experimental-replacements.txt`. Those replacements are
fork-only and do not claim GNU semantic parity. Set `GFW_ARM64_BUSYBOX=0` to
produce an unmodified comparison payload for validation.
