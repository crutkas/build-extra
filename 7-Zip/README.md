# 7-Zip self-extractor (SFX) stubs

Git for Windows builds its self-extracting archives -- `PortableGit-*.7z.exe`
(see `../portable/release.sh`) and `git-sdk-installer-*.7z.exe` (see
`../sdk-installer/release.sh`) -- by concatenating a 7-Zip SFX stub, an
`;!@Install@!UTF-8!` configuration block, and the compressed `.7z` payload into
a single `.exe`. The SFX stub is the small native program that shows the
extraction dialog and unpacks the payload to the chosen directory.

This directory holds the checked-in stubs and the tooling that guards them.

## Files

| File                    | PE Machine        | Used by                                   |
|-------------------------|-------------------|-------------------------------------------|
| `7zS.sfx`               | `0x014C` (x86)    | x86, x64 and UCRT64 self-extractors       |
| `7zS-arm64.sfx`         | `0xAA64` (ARM64)  | ARM64 self-extractors (native, see below) |
| `7zSD.sfx`              | `0x014C` (x86)    | not consumed by build-extra (see note)    |
| `verify-sfx-machine.sh` | --                | architecture gate run by both `release.sh`|
| `t/`                    | --                | tests for the architecture gate           |

`7zS.sfx` is statically linked, so it is the stub that ships. `7zSD.sfx` is the
dynamically linked variant produced by the same upstream build; it is tracked
for parity with the upstream artifacts but is not referenced by any
`release.sh`, so it needs no ARM64 counterpart.

## Why ARM64 needs its own stub

The x86 `7zS.sfx` runs on ARM64 Windows only through the x86 emulation layer.
Shipping it inside `PortableGit-*-arm64.7z.exe` and
`git-sdk-installer-*-arm64.7z.exe` means the very first thing an ARM64 user runs
is an emulated x86 process on the supported extraction path. The ARM64 artifacts
therefore use `7zS-arm64.sfx`, a stub compiled for `IMAGE_FILE_MACHINE_ARM64`
(`0xAA64`), so extraction runs as a native ARM64 process.

x64 continues to reuse the x86 stub (`0x014C`); that is the pre-existing,
deliberate behavior and is out of scope for the ARM64 work.

## Architecture gate (no silent fallback)

Both `release.sh` scripts select the stub by architecture and then run
`verify-sfx-machine.sh <arch> <stub>` before assembling the `.exe`. The gate
reads the stub's PE `Machine` field and requires an exact match:

* `aarch64` requires exactly `0xAA64`, and rejects `0x014C` (x86), `0x8664`
  (x64), `0xA641` (ARM64EC) and `0xA64E` (ARM64X).
* every other architecture requires the shared x86 stub (`0x014C`).

If the ARM64 stub is missing or is not a native ARM64 binary, the build fails
loudly instead of falling back to the x86 stub. Run the tests with:

```sh
sh 7-Zip/t/test-verify-sfx-machine.sh
```

## Signing

The stub is a normal PE image; the payload is appended as overlay data after it.
Swapping the x86 stub for the ARM64 stub does not change how the finished `.exe`
is code-signed (`../signtool.sh` / `osslsigncode` sign the concatenated `.exe`
as a whole), so the signing hook is unaffected.

## Provenance

The stubs are not built in this repository. They are produced from source by the
Git for Windows fork of 7-Zip and copied in verbatim, mirroring how the official
7-Zip project ships its SFX modules.

* Source: <https://github.com/git-for-windows/7-Zip>, branch
  `v26.01-VS2022-sfx`.
* Pinned commit: `7e46321cf82b45aeb0cbcedb39e256879ffe7374`
  ("Merge pull request #42 from git-for-windows/sfxsetup-cfg").
* x86 stubs (`7zS.sfx`, `7zSD.sfx`) copied from workflow run
  <https://github.com/git-for-windows/7-Zip/actions/runs/26519712551>.
* Toolchain: Visual Studio 2022 (MSBuild), solution
  `CPP/7zip/Bundles/SFXSetup/SFXSetup.sln`. Configuration `Release` yields
  `7zS.sfx` (static), `ReleaseD` yields `7zSD.sfx` (dynamic).

### Reproducing `7zS-arm64.sfx`

`SFXSetup.sln` currently defines only the `Win32` (x86) platform, which is why
`7zS.sfx` is x86. Producing a native ARM64 stub requires, in the
`git-for-windows/7-Zip` fork on the pinned branch:

1. Add an `ARM64` platform to `SFXSetup.sln` and the `SFXSetup.vcxproj` (and the
   projects it depends on).
2. Build on a `windows-11-arm` runner (or cross-compile) with Visual Studio
   2022:

   ```
   msbuild /m /p:Configuration=Release /p:Platform=ARM64 \
     CPP/7zip/Bundles/SFXSetup/SFXSetup.sln
   ```

3. Confirm the result reports PE Machine `0xAA64` and copy it here as
   `7zS-arm64.sfx`.

Record the producing commit, workflow run and SHA-256 below when the ARM64 stub
is added, exactly as the x86 stubs are documented above.

### SHA-256

```
81b23536c11d2b069f2c9e7b49fc1700c93a41edaaf8985a240877a96a9d612e  7zS.sfx
48d292108d82b6b268876e24f083761b0469aa7453821f46eb44529355e1d5f8  7zSD.sfx
```
