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
python -B -m unittest discover -s t -p 'test_archive_auditor.py'
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
| `--max-sfx-prefix-bytes` | 16 MiB ceiling on the embedded 7z signature offset |
| `--max-sfx-overlay-scan-bytes` | 16 MiB searched past the PE image for a signature |
| `--max-sfx-signature-occurrences` | 4096 signature byte matches examined |
| `--max-sfx-signature-candidates` | 64 overlay candidates parsed |
| `--max-envelope-work-bytes` | 256 MiB of 7z next-header CRC across the audit |
| `--max-certificate-entries` | 64 `WIN_CERTIFICATE` entries |

Every limit is validated as a positive integer of the correct type,
`--max-depth` additionally as 0 to 128, and `--max-compression-ratio` as a
positive finite number. A limit of the wrong type, including a `bool`, is an
`INVALID_LIMIT` rejection rather than a coerced value. The effective limits
are echoed in the manifest so a decision can be replayed.

The decompression paths apply output bounds before materializing the full
stream. A limit violation is therefore a rejection boundary, not only an
after-the-fact report.

### Bounded MZ/PE signature discovery

A 7z signature is six bytes, so an attacker who controls an MZ/PE input can
place many cheap 32-byte start headers that each declare a next header
covering nearly the whole file. Validating them naively costs a copy and a
CRC per decoy, which is quadratic in the input.

Discovery is therefore explicitly budgeted, and every budget is charged
*before* the work it pays for:

1. The PE layout is parsed exactly once, before any candidate is considered.
2. The search for a signature starts at the end of the PE image and is
   bounded by `--max-sfx-overlay-scan-bytes`, so the cost is proportional to
   the overlay rather than to a potentially huge executable. The image is
   never rescanned on the accepting path.
3. Each signature byte match is charged against
   `--max-sfx-signature-occurrences`, and each candidate against
   `--max-sfx-signature-candidates`.
4. A candidate is parsed with the fixed 32-byte start-header check only,
   which reads at most 20 bytes of CRC.
5. The declared next-header length is charged against
   `--max-envelope-work-bytes` before the next-header CRC runs. The CRC is
   computed incrementally over bounded `memoryview` chunks, so no candidate
   ever materializes a copy of its next header.

A candidate that reaches validation and proves malformed fails the whole
input closed. A later valid candidate can never erase an earlier malformed
one, so malformed signature-bearing bytes in the overlay cannot masquerade
as inert gap. Two valid candidates remain an `AMBIGUOUS_7Z_SIGNATURE`
rejection. Signatures inside the PE image or inside the declared certificate
table are outside the overlay window, so they are never candidates and
cannot contribute to ambiguity; they are still reported specifically on the
rejection path.

Because a stray six-byte signature sequence inside already-classified
archive bytes is also treated as a malformed candidate, an archive that
happens to contain that sequence is rejected rather than accepted. This is
the deliberate stricter reading: the probability is about one in a few
million for a 100 MB archive, and a false rejection is recoverable whereas a
missed embedded archive is not.

Candidate storage is bounded: only the first two valid envelopes are
retained for reporting. Budgets are held on the shared audit state, so
nested archives draw on the same ceilings as their container, and the totals
are reported in the manifest. `--max-envelope-work-bytes` is charged for
every 7z next header, including bare non-SFX archives, so the aggregate CRC
work of a recursive audit is bounded regardless of how the archives are
nested. The envelope accepted by discovery is carried into parsing, so an
accepted next header is CRC-checked and charged exactly once.

Exhausting a budget is a deliberate, stable rejection
(`SFX_SIGNATURE_OCCURRENCE_LIMIT`, `SFX_SIGNATURE_CANDIDATE_LIMIT`,
`SFX_OVERLAY_SCAN_LIMIT`, `SFX_PREFIX_LIMIT`, or `ENVELOPE_WORK_LIMIT`). A
candidate is never silently skipped so that an earlier or later candidate can
be accepted in its place.

## Supported physical formats

| Format | Accepted subset |
|--------|-----------------|
| ZIP, NuGet, MSIX | Single-volume ZIP with stored or raw-deflate members, classic 32-bit sizes, local and central headers that agree, and CP437 or declared UTF-8 names |
| TAR | v7/ustar headers; regular files, directories, symlinks, hardlinks, GNU long names/links, and a strict PAX key subset |
| gzip | One RFC 1952 deflate member with validated header, optional byte-derived original name, footer, CRC, and size |
| bzip2 | One bzip2 stream |
| xz | One xz stream |
| zstd | One dictionary-free zstd frame |
| 7z | Version 0.x, inline metadata, plain or encoded headers, solid streams, and one Copy, LZMA, or LZMA2 coder per folder |
| 7z SFX | The same 7z subset after one structurally bounded, inert MZ/PE prefix, optionally followed by a validated terminal `WIN_CERTIFICATE` table |

Physical bytes alone identify ZIP, compression streams, 7z, and 7z SFX;
caller path, basename, case, and suffix never affect classification,
acceptance, nested descent, or rejection. TAR recognition performs a full
pass, bounded by the active member ceilings, over checksums, record tiling,
padding, PAX size overrides, and terminal zero records. This recognizes strict
v7 TARs that have no magic. ustar and GNU magic classify malformed input as
TAR so that strict parsing rejects it rather than treating it as an opaque
leaf. Opaque decompressed content remains a leaf.

A nested member that begins with `MZ` is recorded as an opaque leaf only
when every one of its bytes is provably accounted for as PE image plus an
optional validated terminal certificate table, leaving no unclassified
overlay. Packages that ship ordinary `.exe` members, including large ones
and signed ones, are therefore auditable. If an overlay exists it must be
classified: a 7z archive is audited, and anything else is a rejection
(`UNCLASSIFIED_PE_OVERLAY`, or `SFX_OVERLAY_SCAN_LIMIT` when the overlay is
larger than the configured search allowance). A nested member is never
silently opaque because a signature sits beyond a scan threshold, and the
nested and root paths apply the same ceilings to the same bytes. A root
input that is an ordinary PE with no embedded archive is still rejected,
because it is not an archive.

### Unix file types

ZIP and 7z members can carry a Unix mode. `S_IFMT` is decoded explicitly and
the allowlist is small: a regular file, a directory where that is
structurally consistent, and a truly unspecified type. Symlinks and every
special type (`S_IFCHR`, `S_IFBLK`, `S_IFIFO`, `S_IFSOCK`) and every unknown
nonzero type are rejected with a format-specific structured error carrying
the octal mode and decoded type name, so a device node or socket can never
be recorded, hashed, or descended into as if it were a regular file.

A ZIP mode is interpreted only when the central-directory creator system is
Unix-like; otherwise the high sixteen bits are not a Unix mode and the type
is classified from the DOS attributes and the trailing slash. A 7z mode is
interpreted only when the member sets the Unix extension attribute; mode
bits present without it are an `AMBIGUOUS_MEMBER_TYPE` rejection rather than
a silently trusted type. TAR keeps its own explicit typeflag handling, which
already distinguishes and validates each record type.

An MZ prefix must contain bounded DOS, PE, optional-header, data-directory,
and section-table structures. Both PE32 (`0x10b`) and PE32+ (`0x20b`)
optional headers are parsed, including `NumberOfRvaAndSizes`, which may not
exceed 16 and whose declared directory bytes must fit inside the declared
optional header. Section raw ranges must start at or after `SizeOfHeaders`,
end inside the file, and must not overlap each other. The embedded 7z
signature must occur at or after the end of the PE image and no later than
the configured prefix ceiling. Candidate envelopes must have valid 7z
start-header and next-header CRCs and exact boundaries; multiple valid
envelopes reject as ambiguous. The SFX bytes are only parsed and hashed,
never executed, and certificate bytes are never decoded or trusted.

### Signed and unsigned SFX

`IMAGE_DIRECTORY_ENTRY_SECURITY` (index 4) is the attribute-certificate
directory. Unlike every other directory its `VirtualAddress` is a physical
file offset, not an RVA, and it is read as such.

For an **unsigned** SFX the security directory is absent or zero, and the 7z
envelope must end at physical end of file.

For a **signed** SFX the physically common layout is
`PE image | 7z overlay | terminal WIN_CERTIFICATE table`. The 7z envelope is
permitted to end at the certificate-table offset instead of end of file,
but only when the declared table is valid and consumes the terminal suffix
exactly. The table must be 8-byte aligned, have an 8-byte-multiple length,
begin at or after the end of the PE image, and end exactly at end of file.
It is then walked as a bounded `WIN_CERTIFICATE` sequence: each entry's
`dwLength` must be at least the 8-byte header, must fit in the table, must
carry a known revision and certificate type, and is followed by 8-byte
alignment padding that must be present, in range, and zero. The entries must
consume the table exactly, and at least one entry must exist.

The certificate offset, length, SHA-256, and per-entry framing are recorded
as physical provenance, so a comparison binds the certificate bytes. The
source SHA-256 continues to bind every byte of the input, and the input is
fully classified as PE image, optional alignment gap, 7z archive, and
optional certificate table, each of which is separately hash-bound.

These reject rather than fall back: a candidate inside the certificate
table, a certificate table before or overlapping the image or the archive, a
nonterminal table, undeclared or trailing bytes between the archive and the
table, a half-declared directory, misaligned offsets or lengths, malformed
entries or padding, and any range overlap.

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

A canonical 32-byte empty 7z archive has `nextHeaderSize == 0`, no members,
and no packed or next-header ranges. Its archive `dataOffset` and
`nextHeaderOffset` are 32. The valid 40-byte form with an explicit zero-file
FilesInfo next header is also accepted and records that eight-byte header as
an owned range.

Offsets are relative to the bytes identified by the owning archive node.
An inner TAR expanded from gzip therefore has its own coordinate space and
identity. A solid 7z member reports the exact shared packed range plus its
`expandedOffset`; its `storageDisposition` is
`shared-solid-folder` rather than pretending that a per-file compressed
range exists.

`compare` audits both inputs and recursively compares these physical
manifests while ignoring only the caller-supplied display input names. Source
bytes, member
order, header layout, offsets, lengths, compression disposition, metadata,
and nested identities all participate. It therefore reports a difference
when two archives extract to the same tree but differ physically.

gzip original-name (`FNAME`) bytes are validated and recorded as header
provenance. They are never derived from or compared with the outer filename.
Renaming identical gzip bytes therefore does not change acceptance or
comparison, while changing `FNAME` changes both source identity and recorded
metadata.

For 7z SFX input the exact PE prefix, alignment gap, archive, and
certificate bytes are all recorded as physical provenance, so a changed
prefix byte changes comparison even when the embedded 7z members are
unchanged. The `archiveStart` and `archiveEnd` fields record where the 7z
envelope is required to begin and end.

### Physical provenance partition

Every 7z node records an exact-once ownership partition under
`ownerDisposition.provenance`. The partitions are ordered, non-overlapping,
and contiguous, and their lengths sum exactly to the containing length,
which is asserted at build time and is a `PROVENANCE_PARTITION_INVALID`
rejection if it ever fails. Each partition records its role, offset, length,
and its own SHA-256, so a comparison binds each region independently.

| Role | Range |
|------|-------|
| `pe-image` | `[0, peImageEnd)` |
| `overlay-gap` | `[peImageEnd, archiveStart)` |
| `archive` | `[archiveStart, archiveEnd)` |
| `certificate` | `[certificateOffset, sourceLength)` when signed |

A bare 7z archive has the single `archive` partition covering all its bytes.
An unsigned SFX omits the `certificate` partition. A zero-length
`overlay-gap` is still recorded so the schema is stable.

The whole-bytes digest recorded as the node `identity`, and the top-level
`source.sha256`, remain available as an independent envelope checksum. They
overlap every partition by construction and are therefore corroboration, not
ownership: the partition is the ownership record. Changing one region
changes exactly that region's partition digest plus the whole-bytes digest.

The legacy `sfxPrefixLength`, `sfxPrefixSha256`, `overlayGapLength`, and
`overlayGapSha256` fields are removed. They overlapped one another and could
be misread as an exact partition.

`peLayout` records the parsed PE geometry: optional-header magic and length,
`NumberOfRvaAndSizes`, section count, `SizeOfHeaders`, the image end, the
overlay window, the signed/unsigned disposition, and the certificate offset,
length, SHA-256, and per-entry offsets, lengths, revisions, and types. A
changed certificate therefore changes comparison even when the PE image and
the embedded 7z members are identical.

The recursive `totals` report the members and expanded bytes as before, plus
`sfxSignatureOccurrences`, `sfxSignatureCandidates`, and
`envelopeWorkBytes`, so the discovery work an accepted input actually
cost is visible and comparable.

## Fail-closed rejection matrix

| Class | Rejection examples |
|-------|--------------------|
| Names and encoding | Duplicate raw names, case-insensitive logical collisions, invalid UTF-8/UTF-16, non-NFC text, or any Unicode `Cc` control (including C0 and C1) in names, links, or metadata |
| Paths | Absolute, drive-qualified, traversal, control-character, reserved Windows, or over-limit paths |
| Links | Absolute or escaping targets, undeclared targets, forward/invalid hardlinks, reparse points, and link cycles |
| Member types | ZIP or 7z symlinks, character and block devices, FIFOs, sockets, unknown Unix types, and Unix mode bits declared without the metadata that gives them meaning |
| Structure | Overlap, gaps, out-of-range records, undeclared members or pack streams, header/catalog disagreement, malformed PE prefixes, or ambiguous SFX signatures |
| Integrity | ZIP/TAR/gzip/7z checksum failures, malformed lengths, nonzero TAR padding |
| Compression | Unsupported methods, invalid streams, dictionaries, ratio excess, or expanded-byte excess |
| Recursion | Depth excess, global member excess, and repeated ancestor archive identity |
| Trailing data | ZIP data after EOCD, nonzero TAR data after terminators, a second valid gzip member/bzip2 stream/xz stream/zstd frame, and bytes after the 7z next header |
| SFX bounds | Missing or out-of-ceiling embedded signatures, signatures overlapping declared PE image ranges, signatures inside a declared certificate table, and unclassified PE overlay bytes |
| SFX candidates | Any overlay signature that reaches validation and is malformed, regardless of whether a later candidate would have been valid |
| SFX work budgets | More signature occurrences, overlay candidates, overlay scan bytes, prefix bytes, or aggregate next-header CRC bytes than the configured ceilings |
| PE certificates | Malformed, misaligned, half-declared, nonterminal, overlapping, over-count, or inexactly consumed `WIN_CERTIFICATE` tables |
| Provenance | Ownership partitions that are unordered, overlapping, or do not cover the containing stream exactly |

`t/test_archive_auditor.py` creates all fixtures in repository-local test
code. It commits no payload or package binaries. The suite covers valid
records and each rejection class, including duplicate ZIP/TAR names with
different content, nested duplicates, traversal, safe and unsafe links,
link cycles, controls on independently generated text surfaces, bombs and
every ceiling, malformed offsets/lengths/checksums, unsupported compression,
appended bytes and valid concatenated streams, GNU long-name/link records,
empty and solid/encoded 7z headers, filename-independent nested wrapper
recognition, canonical and explicit-header empty 7z archives, filename-
independent 7z SFX audit/compare pairs, bounded and ambiguous SFX scans, and
physical A/B order and layout differences.

The PE fixtures are built from a parameterized image builder covering PE32
and PE32+, nonzero section content, multiple sections, section gaps,
overlapping sections, sections inside the headers, short optional headers,
differing `NumberOfRvaAndSizes`, and valid and malformed security
directories and `WIN_CERTIFICATE` chains. Signed SFX coverage includes
acceptance, comparison equality, changed-certificate inequality, a candidate
inside the certificate table, a genuine overlay alongside in-image and
in-certificate decoys, malformed and trailing certificate cases, and the
exact prefix-ceiling and overlay-allowance boundaries.

Nested PE coverage proves that a large image-only executable and a signed
executable with no overlay stay opaque, that a nested SFX whose overlay
starts past an alignment gap is audited, and that an unclassified overlay,
an over-allowance overlay, and an over-ceiling signature are rejected with
the same codes at root and when nested. Member-type coverage builds an
independent byte fixture for every `S_IFMT` value in both ZIP and 7z,
including unknown types, DOS and unspecified controls, creator-system edge
cases, and mode bits declared without their enabling metadata. Provenance
coverage asserts exact sums, ordering, per-partition digests, mutation
isolation, and compare-mode behaviour for signed, unsigned, zero-gap, and
bare archives.

The adversarial coverage is deterministic rather than timing-based: a
fixture with thousands of valid-looking cheap decoys asserts a stable
rejection code and asserts measured CRC and hash bytes against a hard bound
derived from the configured limits, which is orders of magnitude below the
unbounded cost. A generous wall-clock assertion is included only as an
additional smoke check.
