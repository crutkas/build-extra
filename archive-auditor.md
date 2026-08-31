# Recursive archive auditor

`archive-auditor.py` emits a deterministic manifest by reading archive
headers and member byte ranges directly. It never invokes an archive tool,
extracts to the file system, or resolves a member through a name-based
lookup. Nested members are read from their physical record and audited in
memory.

This is a source-only audit primitive. It is not wired into packaging,
release, or consumption workflows. It remains non-consumable until the
predecessor policy and ledger pull requests, and a separate independent
audit of this implementation, have landed.

## Runtime and commands

Python 3.14 or newer is required to cover every supported format. In
particular, zstd support uses the standard-library `compression.zstd`
module. No third-party module or network installation is used.

```console
python archive-auditor.py audit [limits] archive
python archive-auditor.py compare [limits] archive-a archive-b
```

Both commands write sorted, ASCII JSON. `audit` exits 0 for an accepted
archive and 2 for a structured rejection or I/O error. `compare` exits 0
when the physical manifests match, 1 when they differ, and 2 when either
input is rejected.

Run the repository-local synthetic suite with:

```console
python -B t/test_archive_auditor.py
```

The configurable limits and defaults are:

| Option | Default |
|--------|---------|
| `--max-depth` | 8 nested archive levels |
| `--max-total-expanded-bytes` | 4 GiB across the recursive audit |
| `--max-members-per-archive` | 100,000 physical members |
| `--max-members-total` | 200,000 physical members |
| `--max-compression-ratio` | 1000 |
| `--max-path-length` | 4096 UTF-8 bytes |

The decompression paths apply output bounds before materializing the full
stream. A limit violation is therefore a rejection boundary, not only an
after-the-fact report.

## Supported physical formats

| Format | Accepted subset |
|--------|-----------------|
| ZIP, NuGet, MSIX | Single-volume ZIP with stored or raw-deflate members, classic 32-bit sizes, local and central headers that agree, and CP437 or declared UTF-8 names |
| TAR | v7/ustar headers; regular files, directories, symlinks, hardlinks, GNU long names/links, and a strict PAX key subset |
| gzip | One RFC 1952 deflate member with validated header, footer, CRC, and size |
| bzip2 | One bzip2 stream |
| xz | One xz stream |
| zstd | One dictionary-free zstd frame |
| 7z | Version 0.x, inline metadata, plain or encoded headers, solid streams, and one Copy, LZMA, or LZMA2 coder per folder |
| 7z SFX | The same 7z subset after one inert MZ prefix in a `.7z.exe` file |

The suffixes used by Git for Windows package and payload flows are mapped
to these formats, including `.pkg.tar.xz`, `.pkg.tar.zst`,
`.src.tar.gz`, `.tar.bz2`, `.zip`, `.nupkg`, `.7z`, and `.7z.exe`.
Both a suffix claim and physical magic must agree for nested archives.

The following variants reject rather than fall back to an extractor:
ZIP64, split or encrypted ZIP, ZIP Unicode shadow-name fields, ZIP
comments, concatenated compression streams, zstd dictionaries, sparse or
extended-attribute TAR records, TAR device nodes, 7z encryption,
multi-coder/filter graphs, external or additional 7z streams, anti-items,
start positions, comments, and reparse-point or link representations that
the parser cannot prove safe.

The accepted PAX keys are `path`, `linkpath`, `size`, `uid`, `gid`,
`uname`, `gname`, `mode`, `mtime`, `atime`, `ctime`, and `comment`.
Vendor keys, including `LIBARCHIVE.creationtime`, reject unless they are
added to this explicit allowlist.

## Manifest

The top-level schema identifier is
`git-for-windows.archive-audit/v1`. It contains the source length and
SHA-256, the effective limits, recursive totals, and one archive node.

Every archive node contains:

| Field | Meaning |
|-------|---------|
| `identity` | SHA-256 identity of the exact containing bytes |
| `parent` | Parent archive identity, member ordinal, and logical path |
| `archiveChain` | Ordered identities from the root through this node |
| `format` | Detected physical archive or compression format |
| `headerOffset`, `dataOffset` | Byte offsets in this node's physical coordinate space |
| `storedLength`, `expandedLength` | Exact containing and expanded lengths |
| `members` | Physical records in original order |
| `ownerDisposition` | Format-specific catalog, footer, SFX, or terminal-block ownership |

Every member records its physical ordinal, exact header and data offsets,
header/stored/expanded lengths, raw path bytes and declared encoding,
logical Windows path, type, resolved link target, content SHA-256,
format-specific ownership/disposition, and nested archive identity.
Nested archive nodes are embedded under the owning member.

An empty 7z file or directory has no physical data range, so its
`dataOffset` is `null`, its stored length is zero, and its
`storageDisposition` is `none`. LZMA/LZMA2 records include both their
declared dictionary and the bounded effective dictionary needed to decode
the declared output.

Offsets are relative to the bytes identified by the owning archive node.
An inner TAR expanded from gzip therefore has its own coordinate space and
identity. A solid 7z member reports the exact shared packed range plus its
`expandedOffset`; its `storageDisposition` is
`shared-solid-folder` rather than pretending that a per-file compressed
range exists.

`compare` audits both inputs and recursively compares these physical
manifests while ignoring only the input file names. Source bytes, member
order, header layout, offsets, lengths, compression disposition, metadata,
and nested identities all participate. It therefore reports a difference
when two archives extract to the same tree but differ physically.

## Fail-closed rejection matrix

| Class | Rejection examples |
|-------|--------------------|
| Names and encoding | Duplicate raw names, case-insensitive logical collisions, invalid UTF-8/UTF-16, non-NFC text |
| Paths | Absolute, drive-qualified, traversal, control-character, reserved Windows, or over-limit paths |
| Links | Absolute or escaping targets, undeclared targets, forward/invalid hardlinks, reparse points, and link cycles |
| Structure | Overlap, gaps, out-of-range records, undeclared members or pack streams, header/catalog disagreement |
| Integrity | ZIP/TAR/gzip/7z checksum failures, malformed lengths, nonzero TAR padding |
| Compression | Unsupported methods, invalid streams, dictionaries, ratio excess, or expanded-byte excess |
| Recursion | Depth excess, global member excess, and repeated ancestor archive identity |
| Trailing data | ZIP data after EOCD, nonzero TAR data after terminators, concatenated streams, and bytes after the 7z next header |
| Nested typing | Archive suffix and physical-magic disagreement |

`t/test_archive_auditor.py` creates all fixtures in repository-local test
code. It commits no payload or package binaries. The suite covers valid
records and each rejection class, including duplicate ZIP/TAR names with
different content, nested duplicates, traversal, safe and unsafe links,
link cycles, bombs and every ceiling, malformed offsets/lengths/checksums,
unsupported compression, appended bytes, solid/encoded 7z headers, and
physical A/B order and layout differences.
