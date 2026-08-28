#!/usr/bin/env python3

import ast
import bz2
import gzip
import importlib.util
import io
import json
import lzma
from pathlib import Path
import random
import re
import struct
import sys
import time
import tempfile
import unittest
from unittest import mock
import zlib

try:
    from compression import zstd
except ImportError:
    zstd = None


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("archive_auditor", ROOT / "archive-auditor.py")
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)

# Code-shaped Markdown spans that are structure names, not rejection codes.
# Their exact occurrence counts independently anchor this narrow exclusion set.
STRUCTURAL_IDENTIFIERS = frozenset({
    "FNAME",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "S_IFBLK",
    "S_IFCHR",
    "S_IFIFO",
    "S_IFMT",
    "S_IFSOCK",
    "WIN_CERTIFICATE",
})
STRUCTURAL_IDENTIFIER_COUNTS = {
    "FNAME": 2,
    "IMAGE_DIRECTORY_ENTRY_SECURITY": 1,
    "S_IFBLK": 1,
    "S_IFCHR": 1,
    "S_IFIFO": 1,
    "S_IFMT": 2,
    "S_IFSOCK": 1,
    "WIN_CERTIFICATE": 5,
}
EXPECTED_BUDGET_REJECTION_CODES = frozenset({
    "ENVELOPE_WORK_LIMIT",
    "SFX_OVERLAY_SCAN_LIMIT",
    "SFX_SIGNATURE_CANDIDATE_LIMIT",
    "SFX_SIGNATURE_OCCURRENCE_LIMIT",
})
EXPECTED_FORWARDING_SITE_COUNTS = {
    ("_bounded_range", "reject", "code"): 1,
    ("_reject_compressed_tail", "reject", "code"): 1,
    ("checked_slice", "reject", "code"): 1,
    ("classify_unix_file_type", "reject", "code"): 2,
    ("reject", "AuditError", "code"): 1,
    ("require_end", "reject", "code"): 1,
    ("strict_decode", "reject", "code"): 1,
}
EXPECTED_CONDITIONAL_REJECTION_CODES = frozenset({
    "AMBIGUOUS_ZIP_EOCD",
    "INVALID_ZIP_EOCD",
})
RESOLVED_REJECTION_CODES = frozenset({
    "AMBIGUOUS_ZIP_EOCD",
    "CONCATENATED_BZIP2_STREAM",
    "CONCATENATED_XZ_STREAM",
    "CONCATENATED_ZSTD_FRAME",
    "INVALID_GZIP_COMMENT",
    "INVALID_GZIP_NAME",
    "INVALID_PATH_ENCODING",
    "INVALID_PAX_KEY",
    "INVALID_PAX_VALUE",
    "INVALID_ZIP_EOCD",
    "OUT_OF_RANGE_RECORD",
    "TRAILING_HEADER_PAYLOAD",
    "UNSUPPORTED_7Z_MEMBER_TYPE",
    "UNSUPPORTED_ZIP_MEMBER_TYPE",
})
CLASSIFIED_NON_CODE_LITERALS = frozenset({"NFC"})


def raw_deflate(data):
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def make_zip(entries):
    local = bytearray()
    central = bytearray()
    local_offsets = []
    for entry in entries:
        name = entry["name"]
        name = name.encode("utf-8") if isinstance(name, str) else name
        content = entry.get("content", b"")
        method = entry.get("method", 0)
        flags = entry.get("flags", 0x0800)
        external = entry.get("external", 0)
        extra = entry.get("extra", b"")
        compressed = raw_deflate(content) if method == 8 else entry.get("compressed", content)
        crc = zlib.crc32(content) & 0xffffffff
        local_offset = len(local)
        local_offsets.append(local_offset)
        local += struct.pack(
            "<I5H3I2H",
            0x04034B50,
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(compressed),
            len(content),
            len(name),
            len(extra),
        )
        local += name + extra + compressed
        central += struct.pack(
            "<I6H3I5H2I",
            0x02014B50,
            entry.get("version_made", 0x0314),
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(compressed),
            len(content),
            len(name),
            len(extra),
            0,
            0,
            0,
            external,
            local_offset,
        )
        central += name + extra
    central_offset = len(local)
    result = local + central
    result += struct.pack(
        "<I4H2IH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        central_offset,
        0,
    )
    return bytes(result)


def tar_octal(value, width):
    return f"{value:0{width - 1}o}\0".encode("ascii")


def make_tar_entry(name, content=b"", typeflag=b"0", link="", raw_name=None):
    name_raw = raw_name if raw_name is not None else name.encode("utf-8")
    link_raw = link.encode("utf-8")
    if len(name_raw) > 100 or len(link_raw) > 100:
        raise ValueError("test TAR helper only supports short header names")
    header = bytearray(512)
    header[0:len(name_raw)] = name_raw
    header[100:108] = tar_octal(0o755 if typeflag == b"5" else 0o644, 8)
    header[108:116] = tar_octal(0, 8)
    header[116:124] = tar_octal(0, 8)
    header[124:136] = tar_octal(len(content), 12)
    header[136:148] = tar_octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[157:157 + len(link_raw)] = link_raw
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265:269] = b"root"
    header[297:301] = b"root"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    padding = b"\0" * ((-len(content)) % 512)
    return bytes(header) + content + padding


def make_tar(entries, trailing_zero_blocks=2):
    return b"".join(
        make_tar_entry(
            entry["name"],
            entry.get("content", b""),
            entry.get("typeflag", b"0"),
            entry.get("link", ""),
            entry.get("raw_name"),
        )
        for entry in entries
    ) + b"\0" * (512 * trailing_zero_blocks)


def make_v7_tar(entries):
    archive = bytearray(make_tar(entries))
    cursor = 0
    for entry in entries:
        archive[cursor + 257:cursor + 265] = b"\0" * 8
        archive[cursor + 148:cursor + 156] = b"        "
        archive[cursor + 148:cursor + 156] = (
            f"{sum(archive[cursor:cursor + 512]):06o}\0 ".encode("ascii")
        )
        size = len(entry.get("content", b""))
        cursor += 512 + ((size + 511) & ~511)
    return bytes(archive)


def pax_record(key, value):
    suffix = f" {key}={value}\n".encode("utf-8")
    length = len(suffix) + 1
    while True:
        encoded = str(length).encode("ascii") + suffix
        if len(encoded) == length:
            return encoded
        length = len(encoded)


def make_gzip(data, embedded_name=None):
    flags = 0x08 if embedded_name is not None else 0
    header = b"\x1f\x8b\x08" + bytes([flags]) + b"\0\0\0\0\0\xff"
    if embedded_name is not None:
        header += embedded_name.encode("latin-1") + b"\0"
    return (
        header
        + raw_deflate(data)
        + struct.pack("<II", zlib.crc32(data) & 0xffffffff, len(data) & 0xffffffff)
    )


def seven_uint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError("7z encoded integer is outside uint64")
    for extra in range(8):
        if value < 1 << (7 + 7 * extra):
            prefix = ((1 << extra) - 1) << (8 - extra)
            high = value >> (8 * extra)
            low_mask = (1 << (8 * extra)) - 1
            return bytes([prefix | high]) + (value & low_mask).to_bytes(extra, "little")
    return b"\xff" + value.to_bytes(8, "little")


def seven_digests(values):
    return b"\x01" + b"".join(struct.pack("<I", value) for value in values)


def seven_folder(method, properties=b""):
    flags = len(method) | (0x20 if properties else 0)
    result = seven_uint(1) + bytes([flags]) + method
    if properties:
        result += seven_uint(len(properties)) + properties
    return result


def seven_streams(packed, expanded, sizes, method=b"\0", properties=b"", pack_position=0):
    pack = (
        b"\x06"
        + seven_uint(pack_position)
        + seven_uint(1)
        + b"\x09"
        + seven_uint(len(packed))
        + b"\x0a"
        + seven_digests([zlib.crc32(packed) & 0xffffffff])
        + b"\0"
    )
    unpack = (
        b"\x07\x0b"
        + seven_uint(1)
        + b"\0"
        + seven_folder(method, properties)
        + b"\x0c"
        + seven_uint(len(expanded))
        + b"\x0a"
        + seven_digests([zlib.crc32(expanded) & 0xffffffff])
        + b"\0"
    )
    substreams = b""
    if len(sizes) > 1:
        substreams = (
            b"\x08\x0d"
            + seven_uint(len(sizes))
            + b"\x09"
            + b"".join(seven_uint(size) for size in sizes[:-1])
            + b"\x0a"
            + seven_digests([
                zlib.crc32(expanded[sum(sizes[:index]):sum(sizes[:index + 1])]) & 0xffffffff
                for index in range(len(sizes))
            ])
            + b"\0"
        )
    return pack + unpack + substreams + b"\0"


def seven_bits(values):
    result = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            result[index // 8] |= 0x80 >> (index % 8)
    return bytes(result)


def seven_files(entries, attributes=None, attributes_payload=None, extra_properties=b""):
    names = [entry["name"] for entry in entries]
    names_payload = b"\0" + b"".join(
        name.encode("utf-16-le") + b"\0\0" for name in names
    )
    result = (
        b"\x05"
        + seven_uint(len(names))
        + b"\x11"
        + seven_uint(len(names_payload))
        + names_payload
    )
    empty_streams = [
        entry.get("type") == "directory" or not entry.get("content", b"")
        for entry in entries
    ]
    if any(empty_streams):
        bits = seven_bits(empty_streams)
        result += b"\x0e" + seven_uint(len(bits)) + bits
        empty_files = [
            entry.get("type") != "directory"
            for entry, empty in zip(entries, empty_streams)
            if empty
        ]
        bits = seven_bits(empty_files)
        result += b"\x0f" + seven_uint(len(bits)) + bits
    if attributes_payload is not None:
        result += b"\x15" + seven_uint(len(attributes_payload)) + attributes_payload
    elif attributes is not None:
        payload = b"\x01\x00" + b"".join(struct.pack("<I", value) for value in attributes)
        result += b"\x15" + seven_uint(len(payload)) + payload
    return result + extra_properties + b"\0"


def wrap_7z(packed_region, next_header, sfx=b""):
    start_header = struct.pack(
        "<QQI",
        len(packed_region),
        len(next_header),
        zlib.crc32(next_header) & 0xffffffff,
    )
    signature = (
        AUDITOR.SEVEN_ZIP_SIGNATURE
        + b"\0\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xffffffff)
        + start_header
    )
    return sfx + signature + packed_region + next_header


def make_sfx_prefix(length=512, section_raw_size=0):
    if length < 512:
        raise ValueError("SFX test prefix must be at least 512 bytes")
    prefix = bytearray(length)
    prefix[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", prefix, 0x3c, pe_offset)
    prefix[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        prefix,
        pe_offset + 4,
        0xaa64,
        1,
        0,
        0,
        0,
        0xf0,
        0x0002,
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", prefix, optional_offset, 0x20b)
    struct.pack_into("<I", prefix, optional_offset + 60, 512)
    section = optional_offset + 0xf0
    prefix[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<I", prefix, section + 16, section_raw_size)
    struct.pack_into("<I", prefix, section + 20, 512 if section_raw_size else 0)
    return bytes(prefix)


def make_7z(
    entries,
    method="copy",
    encoded_header=False,
    sfx=b"",
    huge_dictionary=False,
    attributes=None,
    attributes_payload=None,
    extra_properties=b"",
):
    contents = [
        entry.get("content", b"")
        for entry in entries
        if entry.get("type") != "directory" and entry.get("content", b"")
    ]
    expanded = b"".join(contents)
    if method == "copy":
        packed = expanded
        method_id = b"\0"
        properties = b""
    elif method == "lzma":
        dictionary = 1 << 20
        declared_dictionary = 0xffffffff if huge_dictionary else dictionary
        properties = bytes([3 + 9 * (0 + 5 * 2)]) + struct.pack("<I", declared_dictionary)
        filters = [{
            "id": lzma.FILTER_LZMA1,
            "dict_size": dictionary,
            "lc": 3,
            "lp": 0,
            "pb": 2,
        }]
        packed = lzma.compress(expanded, format=lzma.FORMAT_RAW, filters=filters)
        method_id = b"\x03\x01\x01"
    elif method == "lzma2":
        properties = b"\x28" if huge_dictionary else b"\x10"
        dictionary = 4096 if huge_dictionary else (2 | (properties[0] & 1)) << (properties[0] // 2 + 11)
        packed = lzma.compress(
            expanded,
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dictionary}],
        )
        method_id = b"\x21"
    else:
        packed = expanded
        method_id = bytes.fromhex(method)
        properties = b""

    streams = (
        seven_streams(
            packed,
            expanded,
            [len(content) for content in contents],
            method_id,
            properties,
        )
        if contents
        else b""
    )
    main_header = (
        b"\x01"
        + (b"\x04" + streams if streams else b"")
        + seven_files(entries, attributes, attributes_payload, extra_properties)
        + b"\0"
    )
    if encoded_header:
        encoded_streams = seven_streams(
            main_header,
            main_header,
            [len(main_header)],
            pack_position=len(packed),
        )
        packed_region = packed + main_header
        next_header = b"\x17" + encoded_streams
    else:
        packed_region = packed
        next_header = main_header
    return wrap_7z(packed_region, next_header, sfx)


def make_7z_multiple_folders(entries):
    contents = [entry["content"] for entry in entries]
    packed = b"".join(contents)
    pack = (
        b"\x06\0"
        + seven_uint(len(contents))
        + b"\x09"
        + b"".join(seven_uint(len(content)) for content in contents)
        + b"\x0a"
        + seven_digests([zlib.crc32(content) & 0xffffffff for content in contents])
        + b"\0"
    )
    unpack = (
        b"\x07\x0b"
        + seven_uint(len(contents))
        + b"\0"
        + b"".join(seven_folder(b"\0") for _ in contents)
        + b"\x0c"
        + b"".join(seven_uint(len(content)) for content in contents)
        + b"\x0a"
        + seven_digests([zlib.crc32(content) & 0xffffffff for content in contents])
        + b"\0"
    )
    streams = pack + unpack + b"\0"
    header = b"\x01\x04" + streams + seven_files(entries) + b"\0"
    return wrap_7z(packed, header)


PE_DIRECTORY_RELATIVE = {0x10b: 96, 0x20b: 112}
PE_DIRECTORY_COUNT_RELATIVE = {0x10b: 92, 0x20b: 108}


def build_pe(
    magic=0x20b,
    sections=((".text", 0x200, 0x200),),
    number_of_rva_and_sizes=16,
    optional_size=None,
    size_of_headers=None,
    pe_offset=0x80,
    security=None,
    image_length=None,
    section_fill=0x90,
):
    """Build a realistic PE image with nonzero section content.

    Sections are (name, raw_offset, raw_size) triples so that gaps, overlaps,
    and empty sections can all be expressed directly.
    """
    directory_relative = PE_DIRECTORY_RELATIVE[magic]
    if optional_size is None:
        optional_size = directory_relative + 8 * number_of_rva_and_sizes
    optional_offset = pe_offset + 24
    section_table = optional_offset + optional_size
    section_table_end = section_table + 40 * len(sections)
    if size_of_headers is None:
        size_of_headers = (section_table_end + 511) // 512 * 512
    end = size_of_headers
    for _, raw_offset, raw_size in sections:
        if raw_size:
            end = max(end, raw_offset + raw_size)
    if image_length is not None:
        end = max(end, image_length)

    image = bytearray(end)
    for _, raw_offset, raw_size in sections:
        for position in range(raw_offset, min(raw_offset + raw_size, len(image))):
            image[position] = section_fill
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3c, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        0xaa64,
        len(sections),
        0,
        0,
        0,
        optional_size,
        0x0002,
    )
    struct.pack_into("<H", image, optional_offset, magic)
    struct.pack_into("<I", image, optional_offset + 60, size_of_headers)
    struct.pack_into(
        "<I",
        image,
        optional_offset + PE_DIRECTORY_COUNT_RELATIVE[magic],
        number_of_rva_and_sizes,
    )
    if security is not None:
        struct.pack_into(
            "<II",
            image,
            optional_offset + directory_relative + 8 * 4,
            security[0],
            security[1],
        )
    for index, (name, raw_offset, raw_size) in enumerate(sections):
        entry = section_table + 40 * index
        image[entry:entry + 8] = name.encode("ascii").ljust(8, b"\0")
        struct.pack_into("<I", image, entry + 16, raw_size)
        struct.pack_into("<I", image, entry + 20, raw_offset if raw_size else 0)
    return bytes(image)


def security_directory_offset(data):
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    return optional_offset + PE_DIRECTORY_RELATIVE[magic] + 8 * 4


def win_certificate(payload, revision=0x0200, certificate_type=0x0002):
    entry = struct.pack("<IHH", len(payload) + 8, revision, certificate_type) + payload
    return entry + b"\0" * (-len(entry) % 8)


def sign(body, certificates, offset=None, length=None):
    """Append a declared WIN_CERTIFICATE table and patch the security directory."""
    signed = bytearray(body)
    table = b"".join(certificates)
    struct.pack_into(
        "<II",
        signed,
        security_directory_offset(signed),
        len(signed) if offset is None else offset,
        len(table) if length is None else length,
    )
    return bytes(signed) + table


def align_image(archive, **kwargs):
    """Pad the PE image so the certificate table lands on an 8-byte boundary
    immediately after the 7z overlay, with no gap between them."""
    image = build_pe(security=(0, 0), **kwargs)
    gap = -(len(image) + len(archive)) % 8
    if gap:
        image = build_pe(security=(0, 0), **dict(kwargs, image_length=len(image) + gap))
    return image


def signed_sfx(archive, certificates, **kwargs):
    """The physically common layout: PE image | 7z overlay | certificate table."""
    image = align_image(archive, **kwargs)
    return image, sign(image + archive, certificates)


def build_pe_raw(section_count=None, magic=None, number_of_rva_and_sizes=None, **kwargs):
    """Build a PE and then patch a single header field to an invalid value.

    Used to reach malformed-header branches that the structural builder
    cannot express directly.
    """
    image = bytearray(build_pe(**kwargs))
    pe_offset = struct.unpack_from("<I", image, 0x3c)[0]
    optional_offset = pe_offset + 24
    if section_count is not None:
        struct.pack_into("<H", image, pe_offset + 6, section_count)
    if magic is not None:
        struct.pack_into("<H", image, optional_offset, magic)
    if number_of_rva_and_sizes is not None:
        current_magic = struct.unpack_from("<H", image, optional_offset)[0]
        relative = PE_DIRECTORY_COUNT_RELATIVE.get(current_magic, PE_DIRECTORY_COUNT_RELATIVE[0x20b])
        struct.pack_into("<I", image, optional_offset + relative, number_of_rva_and_sizes)
    return bytes(image)


def partition(node, role):
    """Look up one exact-once physical provenance partition by role."""
    for item in node["ownerDisposition"]["provenance"]["partitions"]:
        if item["role"] == role:
            return item
    raise AssertionError(f"no {role} partition in {node['ownerDisposition']['provenance']}")


def seven_zip_decoy(total_length, offset):
    """A 32-byte start header that survives every cheap check.

    Without a work budget each one forces a next-header copy and CRC over
    nearly the whole input, which is the quadratic blowup being bounded.
    """
    start_header = struct.pack("<QQI", 0, total_length - (offset + 32), 0)
    return (
        AUDITOR.SEVEN_ZIP_SIGNATURE
        + b"\0\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xffffffff)
        + start_header
    )


def make_decoy_sfx(decoys, total_length=1 << 20, prefix=None, tail=b""):
    prefix = build_pe() if prefix is None else prefix
    body = bytearray(prefix.ljust(total_length - len(tail), b"\0"))
    for index in range(decoys):
        offset = len(prefix) + index * 32
        body[offset:offset + 32] = seven_zip_decoy(total_length, offset)
    return bytes(body) + tail


class ArchiveAuditorTests(unittest.TestCase):
    def audit(self, data, name, limits=None):
        return AUDITOR.ArchiveAuditor(limits).audit_bytes(data, name)

    def assert_rejected(self, code, data, name, limits=None):
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(data, name, limits)
        self.assertEqual(code, context.exception.code)

    def assert_control_rejected(self, data, name):
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(data, name)
        self.assertEqual("CONTROL_CHARACTER", context.exception.code)
        self.assertEqual(
            "Archive text contains a Unicode control character",
            context.exception.message,
        )
        self.assertEqual("U+0085", context.exception.details["codePoint"])

    def test_valid_zip_records_exact_offsets_and_content(self):
        archive = make_zip([{"name": "dir/file.txt", "content": b"hello"}])
        manifest = self.audit(archive, "MinGit.zip")
        member = manifest["archive"]["members"][0]
        self.assertEqual("zip", manifest["archive"]["format"])
        self.assertEqual(0, member["ordinal"])
        self.assertEqual(0, member["headerOffset"])
        self.assertEqual(42, member["dataOffset"])
        self.assertEqual(5, member["storedLength"])
        self.assertEqual(5, member["expandedLength"])
        self.assertEqual(AUDITOR.sha256(b"hello"), member["contentSha256"])
        self.assertEqual("dir/file.txt", member["logicalPath"])
        self.assertIn("centralDirectoryOffset", member["ownerDisposition"])

    def test_valid_deflated_zip_and_rejected_symlink(self):
        archive = make_zip([{"name": "target", "content": b"x", "method": 8}])
        manifest = self.audit(archive, "payload.zip")
        self.assertEqual(["file"], [item["type"] for item in manifest["archive"]["members"]])

        symlink = make_zip([
            {"name": "target", "content": b"x", "method": 8},
            {"name": "link", "content": b"target", "external": 0o120777 << 16},
        ])
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(symlink, "payload.zip")
        self.assertEqual("UNSUPPORTED_ZIP_MEMBER_TYPE", context.exception.code)
        self.assertEqual("symlink", context.exception.details["unixFileType"])
        self.assertEqual("120777", context.exception.details["unixMode"])

    def test_zip_duplicate_physical_name_with_different_content_rejected(self):
        archive = make_zip([
            {"name": "same", "content": b"a"},
            {"name": "same", "content": b"b"},
        ])
        self.assert_rejected("DUPLICATE_PHYSICAL_NAME", archive, "duplicate.zip")

    def test_zip_duplicate_logical_windows_name_rejected(self):
        archive = make_zip([
            {"name": "Readme", "content": b"a"},
            {"name": "README", "content": b"b"},
        ])
        self.assert_rejected("DUPLICATE_LOGICAL_NAME", archive, "duplicate.zip")

    def test_zip_slip_and_absolute_paths_rejected(self):
        for path, code in (("../escape", "TRAVERSAL_PATH"), ("/absolute", "ABSOLUTE_PATH"), ("C:/drive", "ABSOLUTE_PATH")):
            with self.subTest(path=path):
                self.assert_rejected(code, make_zip([{"name": path}]), "unsafe.zip")

    def test_ambiguous_and_windows_reserved_paths_rejected(self):
        self.assert_rejected(
            "AMBIGUOUS_PATH_NORMALIZATION",
            make_zip([{"name": "e\u0301"}]),
            "normalization.zip",
        )
        self.assert_rejected(
            "UNSAFE_WINDOWS_PATH",
            make_zip([{"name": "con"}]),
            "reserved.zip",
        )

    def test_windows_alias_and_namespace_paths_rejected(self):
        unsafe = (
            ("\\\\server\\share", "UNSAFE_PATH"),
            ("\\\\?\\C:\\device", "UNSAFE_PATH"),
            ("file:stream", "UNSAFE_WINDOWS_PATH"),
            ("file.", "UNSAFE_WINDOWS_PATH"),
            ("file ", "UNSAFE_WINDOWS_PATH"),
            ("CONIN$", "UNSAFE_WINDOWS_PATH"),
            ("COM\u00b9", "UNSAFE_WINDOWS_PATH"),
        )
        for path, code in unsafe:
            with self.subTest(path=path):
                self.assert_rejected(code, make_zip([{"name": path}]), "unsafe.zip")

    def test_zip_invalid_utf8_name_rejected(self):
        archive = make_zip([{"name": b"\xff", "flags": 0x0800}])
        self.assert_rejected("INVALID_PATH_ENCODING", archive, "encoding.zip")

    def test_zip_utf8_c1_control_name_rejected(self):
        archive = make_zip([{"name": "unsafe\u0085name"}])
        self.assert_control_rejected(archive, "control.zip")

    def test_zip_unsafe_reparse_target_rejected(self):
        archive = make_zip([{"name": "point", "external": 0x0400}])
        self.assert_rejected("UNSAFE_REPARSE_POINT", archive, "reparse.zip")

    def test_zip_unsupported_method_rejected(self):
        archive = make_zip([{"name": "file", "content": b"x", "method": 99}])
        self.assert_rejected("UNSUPPORTED_ZIP_COMPRESSION", archive, "method.zip")

    def test_zip_unsupported_variants_rejected(self):
        valid = make_zip([{"name": "file", "content": b"x"}])
        central = valid.rfind(b"PK\x01\x02")
        eocd = valid.rfind(b"PK\x05\x06")

        zip64 = bytearray(valid)
        struct.pack_into("<H", zip64, eocd + 8, 0xffff)
        struct.pack_into("<H", zip64, eocd + 10, 0xffff)
        self.assert_rejected("UNSUPPORTED_ZIP64", bytes(zip64), "zip64.zip")

        split = bytearray(valid)
        struct.pack_into("<H", split, eocd + 4, 1)
        self.assert_rejected("UNSUPPORTED_MULTIVOLUME_ZIP", bytes(split), "split.zip")

        encrypted = bytearray(valid)
        struct.pack_into("<H", encrypted, 6, 0x0801)
        struct.pack_into("<H", encrypted, central + 8, 0x0801)
        self.assert_rejected("UNSUPPORTED_ZIP_ENCRYPTION", bytes(encrypted), "encrypted.zip")

        commented = bytearray(valid)
        struct.pack_into("<H", commented, eocd + 20, 1)
        commented += b"x"
        self.assert_rejected("UNSUPPORTED_ZIP_COMMENT", bytes(commented), "comment.zip")

        unicode_shadow = make_zip([
            {"name": "file", "content": b"x", "extra": b"\x75\x70\0\0"},
        ])
        self.assert_rejected("AMBIGUOUS_ZIP_ENCODING", unicode_shadow, "unicode.zip")

    def test_zip_checksum_length_and_offset_errors_rejected(self):
        valid = make_zip([{"name": "file", "content": b"abc"}])
        central = valid.rfind(b"PK\x01\x02")
        bad_crc = bytearray(valid)
        struct.pack_into("<I", bad_crc, 14, 0)
        struct.pack_into("<I", bad_crc, central + 16, 0)
        self.assert_rejected("ZIP_CRC_MISMATCH", bytes(bad_crc), "crc.zip")

        bad_length = bytearray(valid)
        struct.pack_into("<I", bad_length, 18, len(valid))
        struct.pack_into("<I", bad_length, central + 20, len(valid))
        self.assert_rejected("OUT_OF_RANGE_RECORD", bytes(bad_length), "length.zip")

        bad_offset = bytearray(valid)
        struct.pack_into("<I", bad_offset, central + 42, len(valid))
        self.assert_rejected("UNDECLARED_ZIP_PREFIX", bytes(bad_offset), "offset.zip")

    def test_zip_overlapping_records_rejected(self):
        archive = bytearray(make_zip([
            {"name": "a", "content": b"a"},
            {"name": "b", "content": b"b"},
        ]))
        first = archive.find(b"PK\x01\x02")
        second = archive.find(b"PK\x01\x02", first + 1)
        struct.pack_into("<I", archive, second + 42, 0)
        self.assert_rejected("OVERLAPPING_ZIP_RECORDS", bytes(archive), "overlap.zip")

    def test_zip_appended_payload_rejected(self):
        archive = make_zip([{"name": "file"}]) + b"appended"
        self.assert_rejected("INVALID_ZIP_EOCD", archive, "trailing.zip")

    def test_truncated_zip_central_header_is_structured_rejection(self):
        archive = b"PK\x01\x02" + struct.pack(
            "<I4H2IH",
            0x06054B50,
            0,
            0,
            1,
            1,
            4,
            0,
            0,
        )
        self.assert_rejected("OUT_OF_RANGE_RECORD", archive, "truncated.zip")

    def test_valid_tar_records_exact_offsets_and_links(self):
        archive = make_tar([
            {"name": "file", "content": b"hello"},
            {"name": "dir/", "typeflag": b"5"},
            {"name": "dir/link", "typeflag": b"2", "link": "../file"},
            {"name": "hard", "typeflag": b"1", "link": "file"},
        ])
        manifest = self.audit(archive, "payload.tar")
        members = manifest["archive"]["members"]
        self.assertEqual(0, members[0]["headerOffset"])
        self.assertEqual(512, members[0]["dataOffset"])
        self.assertEqual("file", members[0]["type"])
        self.assertEqual("file", members[2]["linkTarget"])
        self.assertEqual("file", members[3]["linkTarget"])
        self.assertIn("mode", members[0]["ownerDisposition"])

    def test_valid_tar_pax_path_preserves_metadata_record(self):
        pax = pax_record("path", "long/path.txt")
        archive = (
            make_tar_entry("PaxHeaders/file", pax, b"x")
            + make_tar_entry("short", b"data")
            + b"\0" * 1024
        )
        manifest = self.audit(archive, "pax.tar")
        self.assertEqual("metadata", manifest["archive"]["members"][0]["type"])
        self.assertEqual("long/path.txt", manifest["archive"]["members"][1]["logicalPath"])
        self.assertEqual("pax", manifest["archive"]["members"][1]["rawPath"]["source"])

    def test_pax_c1_control_metadata_rejected(self):
        pax = pax_record("comment", "unsafe\u0085metadata")
        archive = (
            make_tar_entry("PaxHeaders/file", pax, b"x")
            + make_tar_entry("file")
            + b"\0" * 1024
        )
        self.assert_control_rejected(archive, "control-pax.tar")

    def test_tar_c1_control_link_target_rejected(self):
        archive = make_tar([
            {"name": "target"},
            {"name": "link", "typeflag": b"2", "link": "target\u0085"},
        ])
        self.assert_control_rejected(archive, "control-link.tar")

    def test_valid_gnu_long_name_and_link_records(self):
        long_target = "target-" + "a" * 110
        archive = (
            make_tar_entry("././@LongLink", long_target.encode() + b"\0", b"L")
            + make_tar_entry("short-target", b"payload")
            + make_tar_entry("././@LongLink", long_target.encode() + b"\0", b"K")
            + make_tar_entry("link", b"", b"2")
            + b"\0" * 1024
        )
        members = self.audit(archive, "gnu.tar")["archive"]["members"]
        self.assertEqual("gnu-long-name", members[0]["ownerDisposition"]["metadataType"])
        self.assertEqual(long_target, members[1]["logicalPath"])
        self.assertEqual("gnu-long-name", members[1]["rawPath"]["source"])
        self.assertEqual("gnu-long-link", members[2]["ownerDisposition"]["metadataType"])
        self.assertEqual(long_target, members[3]["linkTarget"])

    def test_local_pax_metadata_cannot_retarget_gnu_metadata_size(self):
        pax = pax_record("size", "3")
        archive = (
            make_tar_entry("PaxHeaders/file", pax, b"x")
            + make_tar_entry("././@LongLink", b"name\0", b"L")
            + make_tar_entry("file", b"abc")
            + b"\0" * 1024
        )
        self.assert_rejected("AMBIGUOUS_TAR_METADATA", archive, "ambiguous.tar")

    def test_tar_duplicate_name_with_different_content_rejected(self):
        archive = make_tar([
            {"name": "same", "content": b"a"},
            {"name": "same", "content": b"b"},
        ])
        self.assert_rejected("DUPLICATE_PHYSICAL_NAME", archive, "duplicate.tar")

    def test_tar_traversal_absolute_and_invalid_encoding_rejected(self):
        for entry, code in (
            ({"name": "../escape"}, "TRAVERSAL_PATH"),
            ({"name": "/absolute"}, "ABSOLUTE_PATH"),
            ({"name": "ignored", "raw_name": b"\xff"}, "INVALID_PATH_ENCODING"),
        ):
            with self.subTest(entry=entry):
                self.assert_rejected(code, make_tar([entry]), "unsafe.tar")

    def test_tar_unsafe_links_and_cycles_rejected(self):
        absolute = make_tar([
            {"name": "file"},
            {"name": "link", "typeflag": b"2", "link": "/file"},
        ])
        self.assert_rejected("UNSAFE_LINK_TARGET", absolute, "links.tar")

        forward_hardlink = make_tar([
            {"name": "hard", "typeflag": b"1", "link": "later"},
            {"name": "later"},
        ])
        self.assert_rejected("UNSAFE_HARDLINK_TARGET", forward_hardlink, "links.tar")

        cycle = make_tar([
            {"name": "a", "typeflag": b"2", "link": "b"},
            {"name": "b", "typeflag": b"2", "link": "a"},
        ])
        self.assert_rejected("LINK_CYCLE", cycle, "links.tar")

        undeclared = make_tar([
            {"name": "link", "typeflag": b"2", "link": "missing"},
        ])
        self.assert_rejected("UNDECLARED_LINK_TARGET", undeclared, "links.tar")

    def test_long_tar_link_chain_does_not_recurse_in_python(self):
        entries = [{"name": "file"}]
        entries.extend(
            {
                "name": f"s{index}",
                "typeflag": b"2",
                "link": f"s{index + 1}" if index < 1499 else "file",
            }
            for index in range(1500)
        )
        manifest = self.audit(make_tar(entries), "chain.tar")
        self.assertEqual(1501, len(manifest["archive"]["members"]))

    def test_tar_checksum_length_padding_and_trailing_payload_rejected(self):
        valid = make_tar([{"name": "file", "content": b"x"}])
        checksum = bytearray(valid)
        checksum[0] ^= 1
        self.assert_rejected("TAR_CHECKSUM_MISMATCH", bytes(checksum), "checksum.tar")

        length = bytearray(valid)
        length[124:136] = tar_octal(len(valid), 12)
        length[148:156] = b"        "
        length[148:156] = f"{sum(length[:512]):06o}\0 ".encode("ascii")
        self.assert_rejected("OUT_OF_RANGE_RECORD", bytes(length), "length.tar")

        padding = bytearray(valid)
        padding[513] = 1
        self.assert_rejected("NONZERO_TAR_PADDING", bytes(padding), "padding.tar")

        self.assert_rejected("TRAILING_TAR_PAYLOAD", valid + b"x", "trailing.tar")

    def test_tar_unsupported_member_and_extension_rejected(self):
        device = make_tar([{"name": "device", "typeflag": b"3"}])
        self.assert_rejected("UNSUPPORTED_TAR_MEMBER_TYPE", device, "device.tar")

        pax = pax_record("GNU.sparse.map", "0,1")
        sparse = make_tar_entry("PaxHeaders/file", pax, b"x") + make_tar_entry("file") + b"\0" * 1024
        self.assert_rejected("UNSUPPORTED_TAR_EXTENSION", sparse, "sparse.tar")

    def test_oversized_pax_numbers_are_structured_rejections(self):
        oversized_length = b"9" * 4301 + b" key=value\n"
        archive = make_tar_entry("PaxHeaders/file", oversized_length, b"x") + b"\0" * 1024
        self.assert_rejected("INVALID_PAX_RECORD", archive, "length.tar")

        oversized_size = pax_record("size", "9" * 4301)
        archive = (
            make_tar_entry("PaxHeaders/file", oversized_size, b"x")
            + make_tar_entry("file")
            + b"\0" * 1024
        )
        self.assert_rejected("INVALID_TAR_NUMBER", archive, "size.tar")

    def test_compressed_tar_wrappers_recurse(self):
        inner = make_tar([{"name": "file", "content": b"payload"}])
        wrappers = [
            ("payload.tar.gz", gzip.compress(inner, mtime=0), "gzip"),
            ("payload.tar.bz2", bz2.compress(inner), "bzip2"),
            ("payload.tar.xz", lzma.compress(inner, format=lzma.FORMAT_XZ), "xz"),
        ]
        if zstd is not None:
            wrappers.append(("payload.tar.zst", zstd.compress(inner), "zstd"))
        for name, archive, archive_format in wrappers:
            with self.subTest(format=archive_format):
                manifest = self.audit(archive, name)
                root = manifest["archive"]
                self.assertEqual(archive_format, root["format"])
                self.assertEqual("tar", root["members"][0]["nestedArchive"]["format"])
                self.assertEqual(root["identity"], root["members"][0]["nestedArchive"]["parent"]["archiveIdentity"])

    def test_wrapped_v7_tar_recognition_is_filename_independent(self):
        inner = make_v7_tar([{"name": "file", "content": b"payload"}])
        wrappers = [
            (
                gzip.compress(inner, mtime=0),
                ("payload.tar.gz", "payload.tgz", "payload.gz", "arbitrary-gzip"),
                "gzip",
            ),
            (
                bz2.compress(inner),
                ("payload.tar.bz2", "payload.tbz2", "payload.bz2", "arbitrary-bzip2"),
                "bzip2",
            ),
            (
                lzma.compress(inner, format=lzma.FORMAT_XZ),
                ("payload.tar.xz", "payload.txz", "payload.xz", "arbitrary-xz"),
                "xz",
            ),
        ]
        if zstd is not None:
            wrappers.append((
                zstd.compress(inner),
                ("payload.tar.zst", "payload.tzst", "payload.zst", "payload.zstd", "arbitrary-zstd"),
                "zstd",
            ))
        for archive, names, archive_format in wrappers:
            baseline = self.audit(archive, names[0])
            with self.subTest(format=archive_format, name=names[0]):
                self.assertEqual("tar", baseline["archive"]["members"][0]["nestedArchive"]["format"])
            for name in names[1:]:
                with self.subTest(format=archive_format, name=name):
                    candidate = self.audit(archive, name)
                    self.assertEqual("tar", candidate["archive"]["members"][0]["nestedArchive"]["format"])
                    self.assertTrue(AUDITOR.compare_manifests(baseline, candidate)["equal"])

    def test_wrapped_opaque_content_remains_a_leaf(self):
        wrappers = [
            (gzip.compress(b"opaque", mtime=0), "opaque-gzip"),
            (bz2.compress(b"opaque"), "opaque-bzip2"),
            (lzma.compress(b"opaque"), "opaque-xz"),
        ]
        if zstd is not None:
            wrappers.append((zstd.compress(b"opaque"), "opaque-zstd"))
        for archive, name in wrappers:
            with self.subTest(name=name):
                member = self.audit(archive, name)["archive"]["members"][0]
                self.assertNotIn("nestedArchive", member)
                self.assertIsNone(member["nestedArchiveIdentity"])

    def test_arbitrary_named_wrapper_rejects_corrupt_ustar_checksum(self):
        inner = bytearray(make_tar([{"name": "file", "content": b"payload"}]))
        inner[0] ^= 1
        wrapped = gzip.compress(bytes(inner), mtime=0)
        self.assert_rejected(
            "TAR_CHECKSUM_MISMATCH",
            wrapped,
            "arbitrary-wrapper-name",
        )

    def test_wrapped_v7_tar_member_bound_reaches_strict_parser(self):
        inner = make_v7_tar([
            {"name": "first"},
            {"name": "second"},
        ])
        wrapped = bz2.compress(inner)
        self.assert_rejected(
            "MEMBERS_PER_ARCHIVE_LIMIT",
            wrapped,
            "arbitrary-wrapper-name",
            AUDITOR.Limits(max_members_per_archive=1),
        )

    def test_compressed_wrapper_appended_payload_rejected(self):
        inner = make_tar([{"name": "file"}])
        wrappers = [
            ("payload.tar.gz", gzip.compress(inner, mtime=0)),
            ("payload.tar.bz2", bz2.compress(inner)),
            ("payload.tar.xz", lzma.compress(inner)),
        ]
        if zstd is not None:
            wrappers.append(("payload.tar.zst", zstd.compress(inner)))
        for name, archive in wrappers:
            with self.subTest(name=name):
                self.assert_rejected("TRAILING_COMPRESSED_PAYLOAD", archive + b"x", name)

    def test_valid_concatenated_compression_streams_rejected_precisely(self):
        first_gzip = make_gzip(b"first")
        second_gzip = make_gzip(b"second")
        first_bzip2 = bz2.compress(b"first")
        second_bzip2 = bz2.compress(b"second")
        first_xz = lzma.compress(b"first")
        second_xz = lzma.compress(b"second")
        fixtures = [
            (
                first_gzip,
                second_gzip,
                "payload.gz",
                "CONCATENATED_GZIP_MEMBER",
                "Only one gzip member is accepted",
            ),
            (
                first_bzip2,
                second_bzip2,
                "payload.bz2",
                "CONCATENATED_BZIP2_STREAM",
                "Only one bzip2 stream is accepted",
            ),
            (
                first_xz,
                second_xz,
                "payload.xz",
                "CONCATENATED_XZ_STREAM",
                "Only one xz stream is accepted",
            ),
        ]
        if zstd is not None:
            first_zstd = zstd.compress(b"first")
            second_zstd = zstd.compress(b"second")
            fixtures.append((
                first_zstd,
                second_zstd,
                "payload.zst",
                "CONCATENATED_ZSTD_FRAME",
                "Only one zstd frame is accepted",
            ))
        for first, second, name, code, message in fixtures:
            with self.subTest(name=name):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(first + second, name)
                self.assertEqual(code, context.exception.code)
                self.assertEqual(message, context.exception.message)
                self.assertEqual(
                    {"offset": len(first)},
                    context.exception.details,
                )

    def test_wrapper_comparison_ignores_input_file_name(self):
        payload = b"plain payload"
        wrappers = [
            ("gz", gzip.compress(payload, mtime=0)),
            ("bz2", bz2.compress(payload)),
            ("xz", lzma.compress(payload)),
        ]
        if zstd is not None:
            wrappers.append(("zst", zstd.compress(payload)))
        for suffix, archive in wrappers:
            with self.subTest(suffix=suffix):
                left = self.audit(archive, f"left.{suffix}")
                right = self.audit(archive, f"right.{suffix}")
                self.assertTrue(AUDITOR.compare_manifests(left, right)["equal"])

    def test_stream_wrapper_compression_ratio_is_bounded(self):
        payload = b"\0" * 10000
        for name, archive in (
            ("payload.gz", gzip.compress(payload, mtime=0)),
            ("payload.bz2", bz2.compress(payload)),
            ("payload.xz", lzma.compress(payload)),
        ):
            with self.subTest(name=name):
                self.assert_rejected(
                    "COMPRESSION_RATIO_LIMIT",
                    archive,
                    name,
                    AUDITOR.Limits(max_compression_ratio=2),
                )

    def test_gzip_embedded_directory_name_rejected(self):
        archive = make_gzip(b"payload", "../payload")
        self.assert_rejected("UNSAFE_PATH", archive, "payload.gz")

    def test_gzip_c1_control_original_name_rejected(self):
        self.assert_control_rejected(
            make_gzip(b"payload", "unsafe\u0085name"),
            "control.gz",
        )

    def test_gzip_embedded_name_is_outer_filename_independent(self):
        inner = make_tar([{"name": "file", "content": b"x"}])
        compressed = make_gzip(inner, "data")
        manifests = [
            self.audit(compressed, name)
            for name in ("data.gz", "backup.gz", "arbitrary-name")
        ]
        member = manifests[0]["archive"]["members"][0]
        self.assertEqual("data", member["logicalPath"])
        self.assertEqual("gzip-header", member["rawPath"]["source"])
        self.assertEqual("64617461", member["rawPath"]["hex"])
        self.assertEqual("data", member["rawPath"]["text"])
        self.assertEqual("data", manifests[0]["archive"]["ownerDisposition"]["embeddedName"])
        self.assertEqual("64617461", manifests[0]["archive"]["ownerDisposition"]["embeddedNameHex"])
        self.assertEqual("tar", member["nestedArchive"]["format"])
        for candidate in manifests[1:]:
            self.assertTrue(AUDITOR.compare_manifests(manifests[0], candidate)["equal"])

    def test_gzip_changed_embedded_name_changes_comparison(self):
        first = self.audit(make_gzip(b"payload", "first.bin"), "data.gz")
        second = self.audit(make_gzip(b"payload", "second.bin"), "backup.gz")
        comparison = AUDITOR.compare_manifests(first, second)
        self.assertFalse(comparison["equal"])
        paths = {difference["path"] for difference in comparison["differences"]}
        self.assertIn("$.source.sha256", paths)
        self.assertIn("$.archive.ownerDisposition.embeddedName", paths)
        self.assertIn("$.archive.members[0].rawPath.text", paths)

    @unittest.skipIf(zstd is None, "compression.zstd is unavailable")
    def test_zstd_dictionary_frame_rejected(self):
        archive = bytearray(zstd.compress(b"payload"))
        descriptor = archive[4]
        dictionary_offset = 5 + (0 if descriptor & 0x20 else 1)
        archive[4] = descriptor | 0x01
        archive[dictionary_offset:dictionary_offset] = b"\x01"
        self.assert_rejected("UNSUPPORTED_ZSTD_DICTIONARY", bytes(archive), "payload.zst")

    def test_deflate_paths_never_call_unbounded_flush(self):
        class FlushGuard:
            def __init__(self, decoder):
                self.decoder = decoder

            def decompress(self, *args, **kwargs):
                return self.decoder.decompress(*args, **kwargs)

            @property
            def eof(self):
                return self.decoder.eof

            @property
            def unused_data(self):
                return self.decoder.unused_data

            @property
            def unconsumed_tail(self):
                return self.decoder.unconsumed_tail

            def flush(self):
                raise AssertionError("unbounded zlib flush must not be called")

        zipped = make_zip([{"name": "file", "content": b"x" * 100, "method": 8}])
        gzipped = gzip.compress(b"x" * 100, mtime=0)
        real_decompressobj = zlib.decompressobj
        with mock.patch.object(
            AUDITOR.zlib,
            "decompressobj",
            side_effect=lambda *args, **kwargs: FlushGuard(real_decompressobj(*args, **kwargs)),
        ):
            self.audit(zipped, "payload.zip")
            self.audit(gzipped, "payload.gz")

    def test_nested_valid_archives_and_duplicate_rejection(self):
        inner_tar = make_tar([{"name": "file", "content": b"x"}])
        outer = make_zip([{"name": "inner.tar", "content": inner_tar}])
        manifest = self.audit(outer, "outer.zip")
        nested = manifest["archive"]["members"][0]["nestedArchive"]
        self.assertEqual("tar", nested["format"])
        self.assertEqual(1, nested["parent"]["memberOrdinal"] + 1)

        inner_duplicate = make_zip([
            {"name": "same", "content": b"a"},
            {"name": "same", "content": b"b"},
        ])
        self.assert_rejected(
            "DUPLICATE_PHYSICAL_NAME",
            make_zip([{"name": "inner.zip", "content": inner_duplicate}]),
            "outer.zip",
        )

    def test_nested_format_is_derived_from_bytes_not_member_name(self):
        inner_tar = make_tar([{"name": "file"}])
        outer = make_zip([{"name": "claims.zip", "content": inner_tar}])
        nested = self.audit(outer, "outer.bin")["archive"]["members"][0]["nestedArchive"]
        self.assertEqual("tar", nested["format"])

    def test_valid_7z_copy_solid_and_encoded_headers(self):
        for encoded in (False, True):
            with self.subTest(encoded=encoded):
                archive = make_7z([
                    {"name": "a", "content": b"alpha"},
                    {"name": "b", "content": b"beta"},
                ], encoded_header=encoded)
                manifest = self.audit(archive, "payload.7z")
                members = manifest["archive"]["members"]
                self.assertEqual(["a", "b"], [item["logicalPath"] for item in members])
                self.assertEqual([32, 32], [item["dataOffset"] for item in members])
                self.assertEqual(
                    ["shared-solid-folder", "shared-solid-folder"],
                    [item["ownerDisposition"]["storageDisposition"] for item in members],
                )
                self.assertEqual(
                    "encoded-shared" if encoded else "plain-shared",
                    members[0]["ownerDisposition"]["headerDisposition"],
                )

    def test_valid_7z_multiple_folders_keep_distinct_physical_ranges(self):
        archive = make_7z_multiple_folders([
            {"name": "a", "content": b"alpha"},
            {"name": "b", "content": b"beta"},
        ])
        members = self.audit(archive, "payload.7z")["archive"]["members"]
        self.assertEqual([32, 37], [member["dataOffset"] for member in members])
        self.assertEqual([5, 4], [member["storedLength"] for member in members])
        self.assertEqual(["00", "00"], [
            member["ownerDisposition"]["coderMethod"] for member in members
        ])

    def test_valid_7z_lzma_and_lzma2(self):
        for method in ("lzma", "lzma2"):
            with self.subTest(method=method):
                archive = make_7z([{"name": "file", "content": b"compress me" * 20}], method=method)
                manifest = self.audit(archive, "payload.7z")
                self.assertEqual(
                    AUDITOR.sha256(b"compress me" * 20),
                    manifest["archive"]["members"][0]["contentSha256"],
                )

    def test_7z_large_declared_dictionary_is_memory_bounded(self):
        content = b"compress me" * 20
        for method in ("lzma", "lzma2"):
            with self.subTest(method=method):
                archive = make_7z(
                    [{"name": "file", "content": content}],
                    method=method,
                    huge_dictionary=True,
                )
                member = self.audit(archive, "payload.7z")["archive"]["members"][0]
                self.assertEqual(0xffffffff, member["ownerDisposition"]["declaredDictionarySize"])
                self.assertEqual(4096, member["ownerDisposition"]["effectiveDictionarySize"])

    def test_valid_7z_empty_file_and_directory_have_no_data_offset(self):
        archive = make_7z([
            {"name": "directory", "type": "directory"},
            {"name": "empty"},
            {"name": "file", "content": b"x"},
        ])
        members = self.audit(archive, "payload.7z")["archive"]["members"]
        self.assertEqual(["directory", "file", "file"], [member["type"] for member in members])
        self.assertEqual([None, None, 32], [member["dataOffset"] for member in members])
        self.assertEqual(["none", "none", "exclusive"], [
            member["ownerDisposition"]["storageDisposition"] for member in members
        ])

    def test_explicit_empty_files_info_7z_has_no_members_or_packed_ranges(self):
        archive = make_7z([])
        node = self.audit(archive, "empty.7z")["archive"]
        self.assertEqual("7z", node["format"])
        self.assertEqual([], node["members"])
        self.assertEqual(32, node["dataOffset"])
        self.assertEqual(32, node["ownerDisposition"]["nextHeaderOffset"])
        self.assertEqual(
            len(archive) - 32,
            node["ownerDisposition"]["nextHeaderLength"],
        )

    def test_canonical_32_byte_empty_7z_and_near_empty_rejections(self):
        archive = wrap_7z(b"", b"")
        self.assertEqual(32, len(archive))
        node = self.audit(archive, "empty.bin")["archive"]
        self.assertEqual("7z", node["format"])
        self.assertEqual([], node["members"])
        self.assertEqual(32, node["dataOffset"])
        self.assertEqual(32, node["ownerDisposition"]["nextHeaderOffset"])
        self.assertEqual(0, node["ownerDisposition"]["nextHeaderLength"])
        self.assertEqual(
            "canonical-empty",
            node["ownerDisposition"]["nextHeaderDisposition"],
        )

        bad_start_crc = bytearray(archive)
        bad_start_crc[8] ^= 1
        self.assert_rejected(
            "SEVEN_ZIP_START_HEADER_CRC_MISMATCH",
            bytes(bad_start_crc),
            "empty",
        )

        bad_next_crc = bytearray(archive)
        bad_next_crc[28] ^= 1
        struct.pack_into("<I", bad_next_crc, 8, zlib.crc32(bad_next_crc[12:32]) & 0xffffffff)
        self.assert_rejected(
            "SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH",
            bytes(bad_next_crc),
            "empty",
        )

        bad_offset = bytearray(archive)
        struct.pack_into("<Q", bad_offset, 12, 1)
        struct.pack_into("<I", bad_offset, 8, zlib.crc32(bad_offset[12:32]) & 0xffffffff)
        self.assert_rejected(
            "SEVEN_ZIP_NEXT_HEADER_OUT_OF_RANGE",
            bytes(bad_offset),
            "empty",
        )
        self.assert_rejected(
            "UNDECLARED_7Z_EMPTY_PAYLOAD",
            wrap_7z(b"x", b""),
            "empty",
        )
        self.assert_rejected("TRAILING_7Z_PAYLOAD", archive + b"x", "empty")
        self.assert_rejected("INVALID_7Z_HEADER", wrap_7z(b"", b"\xff"), "empty")

    def test_7z_c1_control_name_rejected(self):
        archive = make_7z([{"name": "unsafe\u0085name", "content": b"x"}])
        self.assert_control_rejected(archive, "control.7z")

    def test_valid_7z_sfx_is_filename_independent_and_never_executed(self):
        prefix = make_sfx_prefix()
        inner = make_zip([{"name": "nested", "content": b"x"}])
        archive = make_7z([{"name": "opaque.member", "content": inner}], sfx=prefix)
        names = [
            "PortableGit.7z.exe",
            "PortableGit.exe",
            "PortableGit.7z",
            "blob.bin",
            "Arbitrary/Nested/MiXeD.Name",
        ]
        manifests = [self.audit(archive, name) for name in names]
        baseline = manifests[0]
        for name, manifest in zip(names, manifests):
            with self.subTest(name=name):
                node = manifest["archive"]
                self.assertEqual("7z-sfx", node["format"])
                self.assertEqual(len(prefix), node["headerOffset"])
                self.assertEqual(len(prefix) + 32, node["dataOffset"])
                self.assertEqual(
                    len(prefix),
                    partition(node, "pe-image")["length"] + partition(node, "overlay-gap")["length"],
                )
                self.assertEqual(AUDITOR.sha256(prefix), partition(node, "pe-image")["sha256"])
                self.assertEqual("zip", node["members"][0]["nestedArchive"]["format"])
                self.assertEqual(
                    {"length", "sha256"},
                    set(AUDITOR.manifest_for_comparison(manifest)["source"]),
                )
                self.assertTrue(AUDITOR.compare_manifests(baseline, manifest)["equal"])

        changed_prefix = bytearray(prefix)
        changed_prefix[0x40] = 1
        changed = self.audit(
            make_7z(
                [{"name": "opaque.member", "content": inner}],
                sfx=bytes(changed_prefix),
            ),
            "PortableGit.exe",
        )
        self.assertFalse(AUDITOR.compare_manifests(baseline, changed)["equal"])
        self.assertNotEqual(
            partition(baseline["archive"], "pe-image")["sha256"],
            partition(changed["archive"], "pe-image")["sha256"],
        )

    def test_7z_sfx_rejects_malformed_missing_invalid_and_overlapping_prefixes(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        self.assert_rejected("MALFORMED_SFX_PE_PREFIX", b"MZshort" + archive, "blob")

        bad_pe = bytearray(make_sfx_prefix())
        bad_pe[0x80:0x84] = b"PX\0\0"
        self.assert_rejected(
            "MALFORMED_SFX_PE_PREFIX",
            bytes(bad_pe) + archive,
            "PortableGit.7z.exe",
        )
        self.assert_rejected(
            "MISSING_7Z_SFX_SIGNATURE",
            make_sfx_prefix(),
            "PortableGit.7z.exe",
        )

        bad_7z = bytearray(archive)
        bad_7z[8] ^= 1
        self.assert_rejected(
            "SEVEN_ZIP_START_HEADER_CRC_MISMATCH",
            make_sfx_prefix() + bytes(bad_7z),
            "blob.bin",
        )

        overlapping_prefix = make_sfx_prefix(600, section_raw_size=256)
        large_archive = make_7z([{"name": "file", "content": b"x" * 256}])
        self.assert_rejected(
            "SFX_SIGNATURE_OVERLAPS_PE_IMAGE",
            overlapping_prefix + large_archive,
            "blob.bin",
        )

    def test_7z_sfx_signature_ambiguity_reports_only_valid_offsets(self):
        explicit_empty_header = make_7z([])[32:]
        later_archive = wrap_7z(b"", explicit_empty_header)
        earlier_signature = wrap_7z(b"\0" * 32, explicit_empty_header)[:32]
        archive = make_sfx_prefix() + earlier_signature + later_archive
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(archive, "blob.bin")
        self.assertEqual("AMBIGUOUS_7Z_SIGNATURE", context.exception.code)
        self.assertEqual(
            {"firstOffset", "secondOffset"},
            set(context.exception.details),
        )

    def test_7z_sfx_scan_ceiling_rejects_out_of_range_signature(self):
        archive = wrap_7z(b"", b"")
        image_end = len(build_pe())
        allowance = AUDITOR.MAX_SFX_OVERLAY_SCAN_BYTES

        at_limit = build_pe(image_length=image_end + allowance) + archive
        node = self.audit(at_limit, "PortableGit.7z.exe")["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(allowance, partition(node, "overlay-gap")["length"])

        past_limit = build_pe(image_length=image_end + allowance + 1) + archive
        self.assert_rejected("SFX_OVERLAY_SCAN_LIMIT", past_limit, "PortableGit.7z.exe")

    def test_7z_checksums_offsets_methods_and_trailing_payload_rejected(self):
        valid = make_7z([{"name": "file", "content": b"x"}])
        start_crc = bytearray(valid)
        start_crc[8] ^= 1
        self.assert_rejected("SEVEN_ZIP_START_HEADER_CRC_MISMATCH", bytes(start_crc), "bad.7z")

        next_crc = bytearray(valid)
        next_crc[-1] ^= 1
        self.assert_rejected("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", bytes(next_crc), "bad.7z")

        offset = bytearray(valid)
        struct.pack_into("<Q", offset, 12, len(valid))
        struct.pack_into("<I", offset, 8, zlib.crc32(offset[12:32]) & 0xffffffff)
        self.assert_rejected(
            "SEVEN_ZIP_NEXT_HEADER_OUT_OF_RANGE",
            bytes(offset),
            "bad.7z",
        )

        unsupported = make_7z([{"name": "file", "content": b"x"}], method="04")
        self.assert_rejected("UNSUPPORTED_7Z_COMPRESSION", unsupported, "bad.7z")

        self.assert_rejected("TRAILING_7Z_PAYLOAD", valid + b"x", "bad.7z")

    def test_7z_invalid_complex_coder_rejects_without_crashing(self):
        pack = b"\x06\0\x01\x09\0\0"
        zero_output_folder = b"\x01\x11\0\x01\0"
        unpack = b"\x07\x0b\x01\0" + zero_output_folder + b"\x0c\0"
        streams = pack + unpack + b"\0"
        header = b"\x01\x04" + streams + seven_files([]) + b"\0"
        archive = wrap_7z(b"", header)
        self.assert_rejected("UNSUPPORTED_7Z_CODER_GRAPH", archive, "bad.7z")

    def test_7z_additional_streams_rejected(self):
        archive = wrap_7z(b"", b"\x01\x03")
        self.assert_rejected("UNSUPPORTED_7Z_ADDITIONAL_STREAMS", archive, "bad.7z")

    def test_7z_path_reparse_and_outer_filename_independence(self):
        traversal = make_7z([{"name": "../escape", "content": b"x"}])
        self.assert_rejected("TRAVERSAL_PATH", traversal, "bad.7z")

        archive = make_7z([{"name": "file", "content": b"x"}])
        left = self.audit(archive, "claims.zip")
        right = self.audit(archive, "payload.7z")
        self.assertEqual("7z", left["archive"]["format"])
        self.assertTrue(AUDITOR.compare_manifests(left, right)["equal"])

    def test_recursion_member_byte_ratio_and_path_ceilings(self):
        leaf = make_zip([{"name": "leaf", "content": b"x"}])
        middle = make_zip([{"name": "leaf.zip", "content": leaf}])
        outer = make_zip([{"name": "middle.zip", "content": middle}])
        self.assert_rejected(
            "RECURSION_DEPTH_LIMIT",
            outer,
            "outer.zip",
            AUDITOR.Limits(max_depth=1),
        )

        two = make_zip([{"name": "a"}, {"name": "b"}])
        self.assert_rejected(
            "MEMBERS_PER_ARCHIVE_LIMIT",
            two,
            "two.zip",
            AUDITOR.Limits(max_members_per_archive=1),
        )
        self.assert_rejected(
            "GLOBAL_MEMBER_LIMIT",
            middle,
            "middle.zip",
            AUDITOR.Limits(max_members_total=1),
        )
        self.assert_rejected(
            "TOTAL_EXPANDED_BYTES_LIMIT",
            make_zip([{"name": "file", "content": b"12345"}]),
            "bytes.zip",
            AUDITOR.Limits(max_total_expanded_bytes=4),
        )
        self.assert_rejected(
            "COMPRESSION_RATIO_LIMIT",
            make_zip([{"name": "file", "content": b"\0" * 1000, "method": 8}]),
            "ratio.zip",
            AUDITOR.Limits(max_compression_ratio=2),
        )
        self.assert_rejected(
            "PATH_LENGTH_LIMIT",
            make_zip([{"name": "12345"}]),
            "path.zip",
            AUDITOR.Limits(max_path_length=4),
        )

    def test_repeated_ancestor_identity_and_invalid_limits_rejected(self):
        archive = make_zip([{"name": "file"}])
        identity = "sha256:" + AUDITOR.sha256(archive)
        auditor = AUDITOR.ArchiveAuditor()
        with self.assertRaises(AUDITOR.AuditError) as context:
            auditor._audit_bytes(archive, "nested.zip", {}, 1, [identity])
        self.assertEqual("ARCHIVE_CYCLE", context.exception.code)

        with self.assertRaises(AUDITOR.AuditError) as context:
            AUDITOR.ArchiveAuditor(AUDITOR.Limits(max_depth=129))
        self.assertEqual("INVALID_LIMIT", context.exception.code)

    def test_physical_manifest_comparison_detects_order_layout_and_bytes(self):
        first = make_zip([
            {"name": "a", "content": b"one"},
            {"name": "b", "content": b"two"},
        ])
        reordered = make_zip([
            {"name": "b", "content": b"two"},
            {"name": "a", "content": b"one"},
        ])
        relaid = make_zip([
            {"name": "a", "content": b"one", "method": 8},
            {"name": "b", "content": b"two", "method": 8},
        ])
        left = self.audit(first, "a.zip")
        same = self.audit(first, "different-name.zip")
        order = self.audit(reordered, "b.zip")
        layout = self.audit(relaid, "c.zip")
        self.assertTrue(AUDITOR.compare_manifests(left, same)["equal"])
        self.assertFalse(AUDITOR.compare_manifests(left, order)["equal"])
        self.assertFalse(AUDITOR.compare_manifests(left, layout)["equal"])
        self.assertTrue(AUDITOR.compare_manifests(left, order)["differences"])

    def test_manifest_json_is_deterministic_ascii(self):
        archive = make_zip([{"name": "file", "content": b"x"}])
        first = self.audit(archive, "payload.zip")
        second = self.audit(archive, "payload.zip")
        encoded_a = json.dumps(first, sort_keys=True, ensure_ascii=True)
        encoded_b = json.dumps(second, sort_keys=True, ensure_ascii=True)
        self.assertEqual(encoded_a, encoded_b)
        self.assertTrue(encoded_a.isascii())

    def test_cli_audit_compare_and_structured_failure(self):
        first = make_zip([{"name": "a", "content": b"x"}])
        second = make_zip([{"name": "a", "content": b"y"}])
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            a = Path(directory) / "a.zip"
            b = Path(directory) / "b.zip"
            bad = Path(directory) / "bad.zip"
            a.write_bytes(first)
            b.write_bytes(second)
            bad.write_bytes(b"not a zip")

            stdout = io.StringIO()
            old_stdout = AUDITOR.sys.stdout
            try:
                AUDITOR.sys.stdout = stdout
                self.assertEqual(0, AUDITOR.main(["audit", str(a)]))
            finally:
                AUDITOR.sys.stdout = old_stdout
            self.assertEqual(AUDITOR.SCHEMA, json.loads(stdout.getvalue())["schema"])

            stdout = io.StringIO()
            old_stdout = AUDITOR.sys.stdout
            try:
                AUDITOR.sys.stdout = stdout
                self.assertEqual(1, AUDITOR.main(["compare", str(a), str(b)]))
            finally:
                AUDITOR.sys.stdout = old_stdout
            self.assertFalse(json.loads(stdout.getvalue())["equal"])

            stderr = io.StringIO()
            old_stderr = AUDITOR.sys.stderr
            try:
                AUDITOR.sys.stderr = stderr
                self.assertEqual(2, AUDITOR.main(["audit", str(bad)]))
            finally:
                AUDITOR.sys.stderr = old_stderr
            self.assertEqual("UNRECOGNIZED_ARCHIVE", json.loads(stderr.getvalue())["error"]["code"])

    def test_cli_7z_sfx_audit_and_compare_are_filename_independent(self):
        archive = make_7z(
            [{"name": "nested.data", "content": make_zip([{"name": "file"}])}],
            sfx=make_sfx_prefix(),
        )
        names = [
            "PortableGit.7z.exe",
            "PortableGit.exe",
            "PortableGit.7z",
            "blob.bin",
            str(Path("nested") / "MiXeD.Extension"),
        ]
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            paths = []
            for index, name in enumerate(names):
                path = root / str(index) / name
                path.parent.mkdir(parents=True)
                path.write_bytes(archive)
                paths.append(path)

                stdout = io.StringIO()
                old_stdout = AUDITOR.sys.stdout
                try:
                    AUDITOR.sys.stdout = stdout
                    self.assertEqual(0, AUDITOR.main(["audit", str(path)]))
                finally:
                    AUDITOR.sys.stdout = old_stdout
                self.assertEqual("7z-sfx", json.loads(stdout.getvalue())["archive"]["format"])

            for left, right in zip(paths, paths[1:]):
                stdout = io.StringIO()
                old_stdout = AUDITOR.sys.stdout
                try:
                    AUDITOR.sys.stdout = stdout
                    self.assertEqual(
                        0,
                        AUDITOR.main(["compare", str(left), str(right)]),
                    )
                finally:
                    AUDITOR.sys.stdout = old_stdout
                self.assertTrue(json.loads(stdout.getvalue())["equal"])

    def measure_crc(self, data, limits=None, name="hostile.bin"):
        """Run an audit while counting every byte fed to zlib.crc32 and sha256."""
        crc_bytes = []
        hash_bytes = []
        starts = []
        real_crc32 = AUDITOR.zlib.crc32
        real_start = AUDITOR.seven_zip_start_header
        real_sha256 = AUDITOR.hashlib.sha256

        def counting_crc32(payload, value=0):
            crc_bytes.append(len(payload))
            return real_crc32(payload, value)

        def counting_start(data_, offset, archive_end=None):
            starts.append(offset)
            return real_start(data_, offset, archive_end)

        class CountingSha256:
            def __init__(self, payload=b""):
                hash_bytes.append(len(payload))
                self._digest = real_sha256(payload)

            def update(self, payload):
                hash_bytes.append(len(payload))
                self._digest.update(payload)

            def hexdigest(self):
                return self._digest.hexdigest()

            def digest(self):
                return self._digest.digest()

        with mock.patch.object(AUDITOR.zlib, "crc32", counting_crc32):
            with mock.patch.object(AUDITOR, "seven_zip_start_header", counting_start):
                with mock.patch.object(AUDITOR.hashlib, "sha256", CountingSha256):
                    try:
                        AUDITOR.ArchiveAuditor(limits).audit_bytes(data, name)
                        code = None
                    except AUDITOR.AuditError as exc:
                        code = exc.code
        return {
            "code": code,
            "crcBytes": sum(crc_bytes),
            "hashBytes": sum(hash_bytes),
            "startHeaders": len(starts),
        }

    def limits_with(self, **overrides):
        defaults = AUDITOR.Limits()
        values = {
            "max_depth": defaults.max_depth,
            "max_total_expanded_bytes": defaults.max_total_expanded_bytes,
            "max_members_per_archive": defaults.max_members_per_archive,
            "max_members_total": defaults.max_members_total,
            "max_compression_ratio": defaults.max_compression_ratio,
            "max_path_length": defaults.max_path_length,
            "max_sfx_prefix_bytes": defaults.max_sfx_prefix_bytes,
            "max_sfx_overlay_scan_bytes": defaults.max_sfx_overlay_scan_bytes,
            "max_sfx_signature_occurrences": defaults.max_sfx_signature_occurrences,
            "max_sfx_signature_candidates": defaults.max_sfx_signature_candidates,
            "max_envelope_work_bytes": defaults.max_envelope_work_bytes,
            "max_certificate_entries": defaults.max_certificate_entries,
        }
        values.update(overrides)
        return values

    def test_sfx_decoy_signatures_cannot_buy_unbounded_crc_work(self):
        total = 1 << 20
        decoys = 4000
        hostile = make_decoy_sfx(decoys, total)
        unbounded = decoys * total
        defaults = AUDITOR.Limits()

        measured = self.measure_crc(hostile)
        self.assertEqual("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", measured["code"])
        self.assertLessEqual(measured["startHeaders"], defaults.max_sfx_signature_candidates)
        self.assertLessEqual(measured["crcBytes"], 2 * total)
        self.assertLess(measured["crcBytes"] * 100, unbounded)
        self.assertLessEqual(measured["hashBytes"], 2 * total)

        measured = self.measure_crc(
            hostile,
            AUDITOR.Limits(max_envelope_work_bytes=4 << 20, max_sfx_signature_candidates=4096),
        )
        self.assertEqual("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", measured["code"])
        self.assertLessEqual(measured["crcBytes"], (4 << 20) + total)

        tight = self.measure_crc(hostile, AUDITOR.Limits(max_envelope_work_bytes=1024))
        self.assertEqual("ENVELOPE_WORK_LIMIT", tight["code"])
        self.assertLess(tight["crcBytes"], total)

        started = time.perf_counter()
        self.assert_rejected("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", hostile, "hostile.bin")
        self.assertLess(time.perf_counter() - started, 30.0)

    def test_malformed_overlay_candidate_fails_closed_despite_a_valid_tail(self):
        genuine = make_7z([{"name": "file", "content": b"payload"}])
        image = build_pe()

        corrupt_start = bytearray(genuine)
        corrupt_start[8] ^= 1
        leading = image + bytes(corrupt_start) + genuine
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(leading, "sfx.bin")
        self.assertEqual("SEVEN_ZIP_START_HEADER_CRC_MISMATCH", context.exception.code)
        self.assertEqual(len(image), context.exception.details["offset"])

        total = len(image) + 32 + len(genuine)
        decoyed = image + seven_zip_decoy(total, len(image)) + genuine
        self.assertEqual(total, len(decoyed))
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(decoyed, "sfx.bin")
        self.assertEqual("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", context.exception.code)
        self.assertEqual(len(image), context.exception.details["offset"])

        truncated = image + bytes(genuine[:32]) + genuine
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(truncated, "sfx.bin")
        self.assertEqual("TRAILING_7Z_PAYLOAD", context.exception.code)

        self.assertEqual(
            "7z-sfx",
            self.audit(image + genuine, "sfx.bin")["archive"]["format"],
        )

    def test_budget_limits_take_precedence_over_candidate_validation(self):
        genuine = make_7z([{"name": "file", "content": b"payload"}])
        image = build_pe()
        total = len(image) + 32 + len(genuine)
        decoyed = image + seven_zip_decoy(total, len(image)) + genuine

        self.assert_rejected("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", decoyed, "sfx.bin")
        self.assert_rejected(
            "ENVELOPE_WORK_LIMIT",
            decoyed,
            "sfx.bin",
            AUDITOR.Limits(max_envelope_work_bytes=8),
        )

        explicit_empty_header = make_7z([])[32:]
        later = wrap_7z(b"", explicit_empty_header)
        earlier = wrap_7z(b"\0" * 32, explicit_empty_header)[:32]
        ambiguous = build_pe() + earlier + later
        self.assert_rejected("AMBIGUOUS_7Z_SIGNATURE", ambiguous, "sfx.bin")
        self.assert_rejected(
            "SFX_SIGNATURE_OCCURRENCE_LIMIT",
            ambiguous,
            "sfx.bin",
            AUDITOR.Limits(max_sfx_signature_occurrences=1),
        )
        self.assert_rejected(
            "SFX_SIGNATURE_CANDIDATE_LIMIT",
            ambiguous,
            "sfx.bin",
            AUDITOR.Limits(max_sfx_signature_candidates=1),
        )

    def test_pe_image_size_never_bounds_a_valid_sfx(self):
        """Discovery is overlay-relative: a large valid image is not a reason to reject."""
        archive = make_7z([{"name": "file", "content": b"x"}])
        image_end = len(build_pe())

        small = AUDITOR.Limits(max_sfx_prefix_bytes=1024)
        flush = build_pe(image_length=2048) + archive
        node = self.audit(flush, "big.exe", small)["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(2048, node["headerOffset"])
        self.assertEqual(
            "7z-sfx",
            self.audit(
                make_zip([{"name": "inner.exe", "content": flush}]),
                "package.zip",
                small,
            )["archive"]["members"][0]["nestedArchive"]["format"],
        )

        for image_length, expectation in (
            (AUDITOR.MAX_SFX_PREFIX_LENGTH, "7z-sfx"),
            (AUDITOR.MAX_SFX_PREFIX_LENGTH + 1, "7z-sfx"),
        ):
            with self.subTest(imageLength=image_length):
                data = build_pe(
                    sections=((".text", 0x400, image_length - 0x400),),
                ) + archive
                node = self.audit(data, "big.exe")["archive"]
                self.assertEqual(expectation, node["format"])
                self.assertEqual(image_length, node["headerOffset"])
                self.assertEqual(0, partition(node, "overlay-gap")["length"])

    def test_overlay_scan_allowance_bounds_the_gap_before_the_signature(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        image_end = len(build_pe())
        for gap, allowance, expectation in (
            (4096, 4096, "7z-sfx"),
            (4096, 4095, "SFX_OVERLAY_SCAN_LIMIT"),
            (0, 1, "7z-sfx"),
        ):
            with self.subTest(gap=gap, allowance=allowance):
                data = build_pe(image_length=image_end + gap) + archive
                limits = AUDITOR.Limits(max_sfx_overlay_scan_bytes=allowance)
                if expectation == "7z-sfx":
                    node = self.audit(data, "sfx.bin", limits)["archive"]
                    self.assertEqual("7z-sfx", node["format"])
                    self.assertEqual(gap, partition(node, "overlay-gap")["length"])
                    self.assertLessEqual(
                        self.audit(data, "sfx.bin", limits)["totals"]["sfxOverlayScanBytes"],
                        allowance,
                    )
                else:
                    self.assert_rejected(expectation, data, "sfx.bin", limits)

    def test_sfx_signature_candidate_and_occurrence_limits_reject(self):
        hostile = make_decoy_sfx(64)
        self.assert_rejected(
            "SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH",
            hostile,
            "hostile.bin",
            AUDITOR.Limits(max_sfx_signature_candidates=8),
        )
        self.assert_rejected(
            "ENVELOPE_WORK_LIMIT",
            hostile,
            "hostile.bin",
            AUDITOR.Limits(max_envelope_work_bytes=16),
        )

    def test_exhausted_budget_never_falls_through_to_a_later_valid_overlay(self):
        genuine = make_7z([{"name": "file", "content": b"payload"}])
        total = (1 << 20) + len(genuine)
        hostile = make_decoy_sfx(8, total, tail=genuine)

        relaxed = AUDITOR.Limits(
            max_envelope_work_bytes=1 << 30,
            max_sfx_signature_candidates=64,
        )
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(hostile, "hostile.bin", relaxed)
        self.assertEqual("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", context.exception.code)

        for limits, expected in (
            (AUDITOR.Limits(max_envelope_work_bytes=8), "ENVELOPE_WORK_LIMIT"),
        ):
            with self.subTest(expected=expected):
                self.assert_rejected(expected, hostile, "hostile.bin", limits)

    def test_signature_work_budget_is_shared_across_nested_archives(self):
        inner = make_7z([{"name": "leaf", "content": b"x" * 64}], sfx=build_pe())
        outer = make_zip([{"name": "inner.bin", "content": inner}])
        totals = self.audit(outer, "outer.zip")["totals"]
        self.assertEqual(1, totals["sfxSignatureCandidates"])
        self.assertGreaterEqual(totals["sfxSignatureOccurrences"], 1)
        self.assertGreater(totals["envelopeWorkBytes"], 0)

        auditor = AUDITOR.ArchiveAuditor()
        auditor.state.envelope_work = auditor.limits.max_envelope_work_bytes
        with self.assertRaises(AUDITOR.AuditError) as context:
            auditor.audit_bytes(outer, "outer.zip")
        self.assertEqual("ENVELOPE_WORK_LIMIT", context.exception.code)

    def test_cli_bounded_sfx_limits_match_in_memory_behaviour(self):
        hostile = make_decoy_sfx(4000)
        cases = (
            (
                ["--max-envelope-work-bytes", "16"],
                {"max_envelope_work_bytes": 16},
                "ENVELOPE_WORK_LIMIT",
            ),
            (
                ["--max-compression-ratio", "1e308"],
                {"max_compression_ratio": 1e308},
                "INVALID_LIMIT",
            ),
            (
                ["--max-sfx-signature-candidates", "8"],
                {"max_sfx_signature_candidates": 8},
                "SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH",
            ),
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "hostile.bin"
            path.write_bytes(hostile)
            for arguments, overrides, expected in cases:
                with self.subTest(arguments=arguments):
                    stderr = io.StringIO()
                    old_stderr = AUDITOR.sys.stderr
                    try:
                        AUDITOR.sys.stderr = stderr
                        self.assertEqual(2, AUDITOR.main(["audit"] + arguments + [str(path)]))
                    finally:
                        AUDITOR.sys.stderr = old_stderr
                    self.assertEqual(expected, json.loads(stderr.getvalue())["error"]["code"])

                    measured = self.measure_crc(
                        hostile,
                        AUDITOR.Limits(**self.limits_with(**overrides)),
                    )
                    self.assertEqual(expected, measured["code"])

    def test_limits_manifest_reports_every_decision_relevant_ceiling(self):
        manifest = self.audit(make_zip([{"name": "file"}]), "a.zip")
        self.assertEqual(
            {
                "maxDepth",
                "maxTotalExpandedBytes",
                "maxMembersPerArchive",
                "maxMembersTotal",
                "maxCompressionRatio",
                "maxPathLength",
                "maxSfxPrefixBytes",
                "maxSfxOverlayScanBytes",
                "maxSfxSignatureOccurrences",
                "maxSfxSignatureCandidates",
                "maxEnvelopeWorkBytes",
                "maxCertificateEntries",
            },
            set(manifest["limits"]),
        )
        self.assertEqual(
            {
                "members",
                "expandedBytes",
                "sfxSignatureOccurrences",
                "sfxSignatureCandidates",
                "sfxOverlayScanBytes",
                "envelopeWorkBytes",
            },
            set(manifest["totals"]),
        )
        for name in (
            "max_sfx_prefix_bytes",
            "max_sfx_overlay_scan_bytes",
            "max_sfx_signature_occurrences",
            "max_sfx_signature_candidates",
            "max_envelope_work_bytes",
            "max_certificate_entries",
        ):
            for value in (0, -1, True, 1.5, "8"):
                with self.subTest(limit=name, value=value):
                    with self.assertRaises(AUDITOR.AuditError) as context:
                        AUDITOR.ArchiveAuditor(AUDITOR.Limits(**{name: value}))
                    self.assertEqual("INVALID_LIMIT", context.exception.code)
        for limits in (
            AUDITOR.Limits(max_sfx_prefix_bytes=64),
            AUDITOR.Limits(max_depth=True),
            AUDITOR.Limits(max_compression_ratio=True),
        ):
            with self.subTest(limits=limits):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.ArchiveAuditor(limits)
                self.assertEqual("INVALID_LIMIT", context.exception.code)

    def test_sfx_prefix_ceiling_boundary_uses_candidate_offset_logic(self):
        ceiling = 4096
        archive = make_7z([{"name": "file", "content": b"x"}])
        image_end = len(build_pe())
        for gap, expectation in (
            (ceiling - 1, "7z-sfx"),
            (ceiling, "7z-sfx"),
            (ceiling + 1, "SFX_OVERLAY_SCAN_LIMIT"),
        ):
            with self.subTest(gap=gap):
                data = build_pe(image_length=image_end + gap) + archive
                limits = AUDITOR.Limits(max_sfx_overlay_scan_bytes=ceiling)
                if expectation == "7z-sfx":
                    node = self.audit(data, "sfx.bin", limits)["archive"]
                    self.assertEqual("7z-sfx", node["format"])
                    self.assertEqual(image_end + gap, node["headerOffset"])
                    self.assertEqual(gap, partition(node, "overlay-gap")["length"])
                else:
                    self.assert_rejected(expectation, data, "sfx.bin", limits)

    def test_pe32_and_pe32plus_sections_gaps_and_overlaps(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        for magic in (0x10b, 0x20b):
            with self.subTest(magic=magic):
                image = build_pe(
                    magic=magic,
                    sections=(
                        (".text", 0x400, 0x200),
                        (".rdata", 0x800, 0x200),
                        (".data", 0xc00, 0x200),
                    ),
                )
                node = self.audit(image + archive, "sfx.bin")["archive"]
                self.assertEqual("7z-sfx", node["format"])
                layout = node["ownerDisposition"]["peLayout"]
                self.assertEqual(f"{magic:04x}", layout["optionalHeaderMagic"])
                self.assertEqual(3, layout["sectionCount"])
                self.assertEqual(0xe00, layout["peImageEnd"])
                self.assertEqual(0xe00, layout["overlayStart"])
                self.assertEqual(len(image) + len(archive), layout["overlayEnd"])
                self.assertEqual("unsigned", layout["signatureDisposition"])

        overlapping = build_pe(sections=((".text", 0x400, 0x300), (".data", 0x600, 0x200)))
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(overlapping + archive, "sfx.bin")
        self.assertEqual("MALFORMED_SFX_PE_PREFIX", context.exception.code)
        self.assertEqual({"firstSection", "secondSection"}, set(context.exception.details))
        self.assertEqual(0, context.exception.details["firstSection"])
        self.assertEqual(1, context.exception.details["secondSection"])

        empty_section = build_pe(sections=((".text", 0x400, 0x200), (".bss", 0, 0)))
        self.assertEqual(
            "7z-sfx",
            self.audit(empty_section + archive, "sfx.bin")["archive"]["format"],
        )

        inside_headers = build_pe(sections=((".text", 0x100, 0x200),))
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(inside_headers + archive, "sfx.bin")
        self.assertEqual("MALFORMED_SFX_PE_PREFIX", context.exception.code)
        self.assertEqual(0x100, context.exception.details["rawOffset"])

    def test_pe_optional_header_and_directory_counts_validated(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        for magic, optional_size in ((0x10b, 64), (0x20b, 96)):
            with self.subTest(magic=magic, optionalSize=optional_size):
                short = build_pe(magic=magic, optional_size=optional_size, number_of_rva_and_sizes=0)
                self.assert_rejected("MALFORMED_SFX_PE_PREFIX", short + archive, "sfx.bin")

        for count in (0, 4):
            with self.subTest(numberOfRvaAndSizes=count):
                image = build_pe(number_of_rva_and_sizes=count)
                layout = self.audit(image + archive, "sfx.bin")["archive"]["ownerDisposition"]["peLayout"]
                self.assertEqual(count, layout["numberOfRvaAndSizes"])
                self.assertEqual("unsigned", layout["signatureDisposition"])

        overlong = bytearray(build_pe(number_of_rva_and_sizes=16))
        struct.pack_into("<I", overlong, 0x80 + 24 + PE_DIRECTORY_COUNT_RELATIVE[0x20b], 17)
        self.assert_rejected("MALFORMED_SFX_PE_PREFIX", bytes(overlong) + archive, "sfx.bin")

        undersized = build_pe(number_of_rva_and_sizes=16, optional_size=112 + 8 * 15)
        self.assert_rejected("MALFORMED_SFX_PE_PREFIX", undersized + archive, "sfx.bin")

    def test_signed_sfx_overlay_ends_at_the_validated_certificate_table(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        certificate = win_certificate(b"pkcs7-placeholder-bytes")
        image, data = signed_sfx(archive, [certificate])

        node = self.audit(data, "PortableGit.exe")["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(len(image), node["headerOffset"])
        self.assertEqual(len(image) + len(archive), node["ownerDisposition"]["archiveEnd"])
        self.assertEqual(["file"], [member["logicalPath"] for member in node["members"]])
        layout = node["ownerDisposition"]["peLayout"]
        self.assertEqual("signed", layout["signatureDisposition"])
        self.assertEqual(len(image) + len(archive), layout["certificateOffset"])
        self.assertEqual(len(certificate), layout["certificateLength"])
        self.assertEqual(AUDITOR.sha256(certificate), partition(node, "certificate")["sha256"])
        self.assertEqual(1, len(layout["certificateEntries"]))
        self.assertEqual("0200", layout["certificateEntries"][0]["revision"])

        unsigned = self.audit(image + archive, "PortableGit.exe")["archive"]
        self.assertEqual(len(image) + len(archive), unsigned["ownerDisposition"]["archiveEnd"])
        self.assertIsNone(unsigned["ownerDisposition"]["peLayout"]["certificateOffset"])

    def test_signed_sfx_comparison_binds_certificate_bytes(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        baseline = self.audit(signed_sfx(archive, [win_certificate(b"signature-a")])[1], "a.exe")
        same = self.audit(signed_sfx(archive, [win_certificate(b"signature-a")])[1], "b.exe")
        changed = self.audit(signed_sfx(archive, [win_certificate(b"signature-b")])[1], "c.exe")

        self.assertTrue(AUDITOR.compare_manifests(baseline, same)["equal"])
        self.assertFalse(AUDITOR.compare_manifests(baseline, changed)["equal"])
        self.assertNotEqual(baseline["source"]["sha256"], changed["source"]["sha256"])
        self.assertNotEqual(
            partition(baseline["archive"], "certificate")["sha256"],
            partition(changed["archive"], "certificate")["sha256"],
        )

    def test_unsigned_sfx_and_certificate_gaps_must_not_leave_trailing_bytes(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        self.assert_rejected("TRAILING_7Z_PAYLOAD", build_pe() + archive + b"x", "sfx.bin")

        padded = align_image(archive) + archive + b"\0" * 8
        self.assert_rejected(
            "TRAILING_7Z_PAYLOAD",
            sign(padded, [win_certificate(b"signature")]),
            "sfx.bin",
        )

    def test_seven_zip_signature_inside_certificate_is_not_a_candidate(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        decoy = win_certificate(AUDITOR.SEVEN_ZIP_SIGNATURE + b"\0" * 26)

        self.assert_rejected(
            "SFX_SIGNATURE_INSIDE_CERTIFICATE",
            sign(build_pe(security=(0, 0)), [decoy]),
            "sfx.bin",
        )

        image, data = signed_sfx(archive, [decoy])
        node = self.audit(data, "sfx.bin")["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(len(image), node["headerOffset"])

    def test_in_image_decoy_never_contributes_to_candidate_ambiguity(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        sections = ((".text", 0x400, 0x200),)
        image = bytearray(align_image(archive, sections=sections))
        image[0x400:0x420] = seven_zip_decoy(0x420, 0x400)
        image = bytes(image)

        node = self.audit(image + archive, "sfx.bin")["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(len(image), node["headerOffset"])

        certificate = win_certificate(AUDITOR.SEVEN_ZIP_SIGNATURE + b"\0" * 26)
        node = self.audit(sign(image + archive, [certificate]), "sfx.bin")["archive"]
        self.assertEqual(len(image), node["headerOffset"])
        self.assertEqual("signed", node["ownerDisposition"]["peLayout"]["signatureDisposition"])

        self.assert_rejected("SFX_SIGNATURE_OVERLAPS_PE_IMAGE", image, "sfx.bin")

    def test_two_genuine_overlay_candidates_remain_ambiguous(self):
        explicit_empty_header = make_7z([])[32:]
        later = wrap_7z(b"", explicit_empty_header)
        earlier = wrap_7z(b"\0" * 32, explicit_empty_header)[:32]
        data = build_pe() + earlier + later
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(data, "sfx.bin")
        self.assertEqual("AMBIGUOUS_7Z_SIGNATURE", context.exception.code)
        self.assertEqual({"firstOffset", "secondOffset"}, set(context.exception.details))

    def test_malformed_certificate_tables_reject_fail_closed(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        body = align_image(archive) + archive
        certificate = win_certificate(b"signature")

        cases = {
            "trailing": sign(body, [certificate]) + b"x",
            "misaligned-offset": sign(body, [certificate], offset=len(body) + 1),
            "unaligned-length": sign(body, [certificate], length=len(certificate) - 1),
            "half-empty-length": sign(body, [certificate], length=0),
            "half-empty-offset": sign(body, [certificate], offset=0),
            "before-image": sign(body, [certificate], offset=8),
            "nonterminal": sign(body, [certificate], length=len(certificate) - 8),
            "overlong": sign(body, [certificate], length=len(certificate) + 8),
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(data, "sfx.bin")
                self.assertIn(
                    context.exception.code,
                    ("MALFORMED_SFX_PE_PREFIX", "MALFORMED_PE_CERTIFICATE"),
                )

        for label, offset, layout, value in (
            ("short-dwlength", 0, "<I", 4),
            ("overlong-dwlength", 0, "<I", len(certificate) + 8),
            ("bad-revision", 4, "<H", 0x0300),
            ("bad-type", 6, "<H", 0x00ff),
        ):
            with self.subTest(case=label):
                mutated = bytearray(sign(body, [certificate]))
                struct.pack_into(layout, mutated, len(body) + offset, value)
                self.assert_rejected("MALFORMED_PE_CERTIFICATE", bytes(mutated), "sfx.bin")

        nonzero_padding = bytearray(sign(body, [win_certificate(b"abc")]))
        nonzero_padding[-1] = 1
        self.assert_rejected("MALFORMED_PE_CERTIFICATE", bytes(nonzero_padding), "sfx.bin")

    def test_bounded_crc_and_hash_helpers_match_the_naive_form(self):
        chunk = AUDITOR.STREAM_CHUNK_LENGTH
        length = 3 * chunk + 12345
        data = (bytes(range(256)) * (length // 256 + 1))[:length]
        ranges = (
            (0, 0),
            (0, 1),
            (5, 5),
            (1, chunk),
            (0, chunk),
            (0, chunk + 1),
            (chunk, chunk),
            (chunk - 1, 2 * chunk + 1),
            (7, 3 * chunk),
            (length - 1, length),
            (0, length - 1),
            (0, length),
        )
        for start, end in ranges:
            with self.subTest(start=start, end=end):
                self.assertEqual(
                    zlib.crc32(data[start:end]) & 0xffffffff,
                    AUDITOR.crc32_range(data, start, end),
                )
                self.assertEqual(
                    AUDITOR.sha256(data[start:end]),
                    AUDITOR.sha256_range(data, start, end),
                )
        for start, end in ((-1, 5), (0, length + 1), (5, 4)):
            with self.subTest(start=start, end=end):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.crc32_range(data, start, end)
                self.assertEqual("OUT_OF_RANGE_RECORD", context.exception.code)

    def extract_rejection_evidence(self, source):
        pattern = re.compile(r"[A-Z][A-Z0-9_]{2,}")
        tree = ast.parse(source)
        rejection_callees = frozenset({"reject", "AuditError"})
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def containing_function(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node
            return None

        def static_strings(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return {node.value}
            if isinstance(node, ast.IfExp):
                body = static_strings(node.body)
                orelse = static_strings(node.orelse)
                if body is not None and orelse is not None:
                    return body | orelse
            return None

        def static_codes(node):
            values = static_strings(node)
            if values is not None and all(pattern.fullmatch(value) for value in values):
                return values
            return None

        direct_calls = []
        non_name_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in rejection_callees:
                direct_calls.append(node)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in rejection_callees:
                non_name_calls.append(node.lineno)

        self.assertEqual(
            [],
            non_name_calls,
            f"structured-error callees must be direct ast.Name nodes: {non_name_calls}",
        )
        self.assertEqual(
            258,
            len(direct_calls),
            "physical direct structured-error call-site count drifted",
        )

        missing_arguments = [node.lineno for node in direct_calls if not node.args]
        self.assertEqual(
            [],
            missing_arguments,
            f"structured-error calls lack a code argument: {missing_arguments}",
        )

        static_sites = []
        forwarding_sites = []
        unextractable = []
        declarative_forms = set()
        static_raised = set()
        for node in direct_calls:
            first = node.args[0]
            codes = static_codes(first)
            if codes is not None:
                static_sites.append(node)
                static_raised.update(codes)
                declarative_forms.add(ast.dump(first, include_attributes=False))
            elif isinstance(first, ast.Name):
                forwarding_sites.append(node)
            else:
                unextractable.append(
                    (node.lineno, ast.dump(first, include_attributes=False))
                )

        self.assertEqual(
            [],
            unextractable,
            f"unextractable structured-error code expressions: {unextractable}",
        )
        self.assertEqual(8, len(forwarding_sites), "forwarding site count drifted")
        self.assertEqual(
            158,
            len(declarative_forms),
            "unique declarative rejection-code form count drifted",
        )
        constant_raised = {
            node.args[0].value
            for node in static_sites
            if isinstance(node.args[0], ast.Constant)
        }

        forwarding_counts = {}
        for node in forwarding_sites:
            owner = containing_function(node)
            key = (
                owner.name if owner is not None else "<module>",
                node.func.id,
                node.args[0].id,
            )
            forwarding_counts[key] = forwarding_counts.get(key, 0) + 1
        self.assertEqual(
            EXPECTED_FORWARDING_SITE_COUNTS,
            forwarding_counts,
            "forwarding structured-error sites must stay explicitly enumerated",
        )

        self.assertEqual(
            len(direct_calls),
            len(static_sites) + len(forwarding_sites),
            "every physical structured-error call must resolve",
        )
        conditional_raised = static_raised - constant_raised
        self.assertEqual(
            EXPECTED_CONDITIONAL_REJECTION_CODES,
            conditional_raised,
            "conditional rejection-code extraction drifted",
        )

        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and pattern.fullmatch(node.value)
        }
        expected_residue = RESOLVED_REJECTION_CODES | CLASSIFIED_NON_CODE_LITERALS
        residue = literals - constant_raised
        self.assertEqual(
            expected_residue,
            residue,
            "every code-shaped literal outside direct constant raises must be classified",
        )
        self.assertFalse(
            constant_raised & expected_residue,
            "directly raised literals and the explicit residue must be disjoint",
        )
        self.assertFalse(
            RESOLVED_REJECTION_CODES & CLASSIFIED_NON_CODE_LITERALS,
            "resolved rejection codes and classified non-codes must be disjoint",
        )
        raised = constant_raised | RESOLVED_REJECTION_CODES
        self.assertEqual(
            literals,
            raised | CLASSIFIED_NON_CODE_LITERALS,
            "raised, resolved, and classified non-code literals must cover the outer bound",
        )
        return {
            "literals": literals,
            "raised": raised,
            "constantRaised": constant_raised,
            "resolved": RESOLVED_REJECTION_CODES,
            "physicalCallSites": len(direct_calls),
            "declarativeForms": len(declarative_forms),
        }

    def assert_documented_rejection_contract(
        self,
        source,
        text,
        structural_identifiers=STRUCTURAL_IDENTIFIERS,
    ):
        evidence = self.extract_rejection_evidence(source)
        literals = evidence["literals"]
        raised = evidence["raised"]

        code_spans = re.findall(r"`([A-Z][A-Z0-9_]{2,})`", text)
        structural_identifiers = frozenset(structural_identifiers)
        documented = set(code_spans) - structural_identifiers

        # A silently empty documentation extraction must fail loudly.
        self.assertGreater(len(documented), 8, "documentation extraction found too few codes")
        overlap = structural_identifiers & raised
        self.assertFalse(
            overlap,
            f"structural identifiers cannot suppress raised codes: {sorted(overlap)}",
        )
        self.assertEqual(
            STRUCTURAL_IDENTIFIERS,
            frozenset(STRUCTURAL_IDENTIFIER_COUNTS),
            "structural vocabulary and occurrence anchors must remain exact",
        )
        self.assertEqual(
            STRUCTURAL_IDENTIFIERS,
            structural_identifiers,
            "structural identifier exclusions must match the anchored vocabulary",
        )
        for identifier, count in STRUCTURAL_IDENTIFIER_COUNTS.items():
            self.assertEqual(
                count,
                code_spans.count(identifier),
                f"structural identifier occurrence drifted: {identifier}",
            )
        self.assertTrue(raised <= literals)
        self.assertIn("UNRECOGNIZED_ARCHIVE", raised)
        self.assertIn("AMBIGUOUS_7Z_SIGNATURE", documented)

        undocumentable = sorted(documented - raised)
        self.assertEqual(
            [],
            undocumentable,
            f"documentation advertises codes that production cannot raise: {undocumentable}",
        )
        self.assertTrue(
            documented < raised,
            "documented rejection codes must remain a proper production subset",
        )
        self.assertGreater(
            len(raised - documented),
            len(documented),
            "most production rejection codes must remain intentionally unpublished",
        )
        self.assertIn(
            "intentionally a stable subset, not an exhaustive catalog",
            text,
            "the specification must state the one-sided rejection-code contract",
        )

        budget = re.compile(r"^(?:SFX_|ENVELOPE_).*_LIMIT$")
        marker = "Exhausting a budget is a deliberate, stable rejection"
        self.assertIn(marker, text)
        start = text.index(marker)
        paragraph = text[start:text.index("\n\n", start)]
        documented_budget = set(re.findall(r"`([A-Z][A-Z0-9_]{2,})`", paragraph))
        production_budget = {code for code in raised if budget.match(code)}

        self.assertEqual(
            EXPECTED_BUDGET_REJECTION_CODES,
            production_budget,
            "the production budget family must remain the stable contract",
        )
        self.assertEqual(
            EXPECTED_BUDGET_REJECTION_CODES,
            documented_budget,
            "the normative budget family must remain the stable contract",
        )
        self.assertNotIn("SFX_PREFIX_LIMIT", literals)
        self.assertNotIn("SFX_PREFIX_LIMIT", documented)
        return evidence

    def test_documented_rejection_codes_match_production(self):
        """The normative documented rejection contract must track production."""
        auditor_path = Path(AUDITOR.__file__).resolve()
        self.assertEqual((ROOT / "archive-auditor.py").resolve(), auditor_path)
        source = auditor_path.read_text(encoding="utf-8")
        text = (ROOT / "archive-auditor.md").read_text(encoding="utf-8")
        self.assert_documented_rejection_contract(source, text)

    def test_nonliteral_rejection_codes_are_classified_and_representative_codes_raise(self):
        source = (ROOT / "archive-auditor.py").read_text(encoding="utf-8")
        evidence = self.extract_rejection_evidence(source)
        raised = evidence["raised"]

        late_eocd = bytearray(22)
        late_eocd[:4] = b"PK\x05\x06"
        early_eocd = bytearray(late_eocd)
        struct.pack_into("<H", early_eocd, 20, len(late_eocd))

        def raw_pax_record(key, value):
            body = key + b"=" + value + b"\n"
            length = len(body) + 2
            while True:
                record = str(length).encode("ascii") + b" " + body
                if len(record) == length:
                    return record
                length = len(record)

        runtime_cases = (
            (
                lambda: AUDITOR.ArchiveAuditor().audit_bytes(
                    make_zip([{"name": "file"}]) + b"x",
                    "missing-eocd.zip",
                ),
                "INVALID_ZIP_EOCD",
            ),
            (
                lambda: AUDITOR.ArchiveAuditor().audit_bytes(
                    bytes(early_eocd + late_eocd),
                    "ambiguous-eocd.zip",
                ),
                "AMBIGUOUS_ZIP_EOCD",
            ),
            (
                lambda: AUDITOR.crc32_range(b"abcdef", 0, 99),
                "OUT_OF_RANGE_RECORD",
            ),
            (
                lambda: AUDITOR.checked_slice(b"abc", 0, 99),
                "OUT_OF_RANGE_RECORD",
            ),
            (
                lambda: AUDITOR.strict_decode(b"\xff\xfe", "utf-8"),
                "INVALID_PATH_ENCODING",
            ),
            (
                lambda: AUDITOR.strict_decode(
                    b"\xff",
                    "ascii",
                    "INVALID_GZIP_NAME",
                ),
                "INVALID_GZIP_NAME",
            ),
            (
                lambda: AUDITOR.strict_decode(
                    b"\xff",
                    "ascii",
                    "INVALID_GZIP_COMMENT",
                ),
                "INVALID_GZIP_COMMENT",
            ),
            (
                lambda: AUDITOR.BinaryReader(b"\x01\x02\x03").require_end(),
                "TRAILING_HEADER_PAYLOAD",
            ),
            (
                lambda: AUDITOR.parse_pax(raw_pax_record(b"\xff", b"value")),
                "INVALID_PAX_KEY",
            ),
            (
                lambda: AUDITOR.parse_pax(raw_pax_record(b"comment", b"\xff")),
                "INVALID_PAX_VALUE",
            ),
        )
        for operation, expected in runtime_cases:
            with self.subTest(code=expected):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    operation()
                self.assertEqual(expected, context.exception.code)
                self.assertIn(expected, raised)

    def test_documented_rejection_contract_mutation_controls(self):
        """Dormant strings, exclusions, and budget drift cannot bless documentation."""
        source = (ROOT / "archive-auditor.py").read_text(encoding="utf-8")
        text = (ROOT / "archive-auditor.md").read_text(encoding="utf-8")
        baseline_evidence = self.extract_rejection_evidence(source)

        def replace_once(value, old, new):
            self.assertEqual(1, value.count(old), f"mutation anchor drifted: {old!r}")
            return value.replace(old, new, 1)

        def must_fail(
            label,
            mutated_source,
            mutated_text,
            expected,
            exclusions=STRUCTURAL_IDENTIFIERS,
        ):
            with self.subTest(mutation=label):
                with self.assertRaises(AssertionError) as context:
                    self.assert_documented_rejection_contract(
                        mutated_source,
                        mutated_text,
                        exclusions,
                    )
                self.assertIn(expected, str(context.exception))

        parent_text = replace_once(
            text,
            "`SFX_OVERLAY_SCAN_LIMIT`, or `ENVELOPE_WORK_LIMIT`). A candidate is never\n"
            "silently skipped so that an earlier or later candidate can be accepted in\n"
            "its place.",
            "`SFX_OVERLAY_SCAN_LIMIT`, `SFX_PREFIX_LIMIT`, or "
            "`ENVELOPE_WORK_LIMIT`). A\n"
            "candidate is never silently skipped so that an earlier or later candidate can\n"
            "be accepted in its place.",
        )
        must_fail("parent documentation", source, parent_text, "SFX_PREFIX_LIMIT")

        fake_code = "BOGUS_DOCUMENTED_CODE"
        must_fail(
            "unbacked documented code",
            source,
            text + f"\n`{fake_code}`\n",
            fake_code,
        )
        must_fail(
            "documented dormant literal",
            source + '\n_DORMANT_CODE = "DORMANT_REJECTION_CODE"\n',
            text + "\n`DORMANT_REJECTION_CODE`\n",
            "outside direct constant raises",
        )

        renamed_source = replace_once(
            source,
            '"UNCLASSIFIED_PE_OVERLAY"',
            '"RENAMED_PE_OVERLAY"',
        )
        renamed_source += '\n_DORMANT_OLD_CODE = "UNCLASSIFIED_PE_OVERLAY"\n'
        must_fail(
            "renamed raise with dormant old code",
            renamed_source,
            text,
            "outside direct constant raises",
        )
        renamed_conditional = replace_once(
            source,
            '"AMBIGUOUS_ZIP_EOCD" if candidates else "INVALID_ZIP_EOCD"',
            '"RENAMED_ZIP_EOCD" if candidates else "INVALID_ZIP_EOCD"',
        )
        renamed_conditional += '\n_DORMANT_OLD_CODE = "AMBIGUOUS_ZIP_EOCD"\n'
        must_fail(
            "renamed conditional raise with dormant old code",
            renamed_conditional,
            text,
            "conditional rejection-code extraction drifted",
        )

        must_fail(
            "bogus structural exclusion",
            source,
            text + f"\n`{fake_code}`\n",
            "anchored vocabulary",
            STRUCTURAL_IDENTIFIERS | {fake_code},
        )
        must_fail(
            "raised structural exclusion",
            source,
            text,
            "cannot suppress raised codes",
            STRUCTURAL_IDENTIFIERS | {"UNCLASSIFIED_PE_OVERLAY"},
        )
        for code in sorted(RESOLVED_REJECTION_CODES):
            must_fail(
                f"newly resolved structural exclusion {code}",
                source,
                text,
                "cannot suppress raised codes",
                STRUCTURAL_IDENTIFIERS | {code},
            )

        no_raised_source = source.replace("reject(", "mutated_reject(")
        no_raised_source = no_raised_source.replace("AuditError(", "MutatedAuditError(")
        must_fail(
            "empty raised extraction",
            no_raised_source,
            text,
            "physical direct structured-error call-site count",
        )
        must_fail(
            "empty documented extraction",
            source,
            text.replace("`", ""),
            "documentation extraction found too few codes",
        )
        must_fail(
            "missing one-sided contract statement",
            source,
            text.replace(
                "intentionally a stable subset, not an exhaustive catalog",
                "a selected catalog",
            ),
            "specification must state the one-sided rejection-code contract",
        )
        all_raised = baseline_evidence["raised"]
        exhaustive_text = text + "\n" + " ".join(
            f"`{code}`" for code in sorted(all_raised)
        )
        must_fail(
            "exhaustive general contract",
            source,
            exhaustive_text,
            "proper production subset",
        )

        direct_code = '"DUPLICATE_PHYSICAL_NAME"'
        for label, expression in (
            ("format call", '"{}".format("DUPLICATE_PHYSICAL_NAME")'),
            ("lookup", '{"code": "DUPLICATE_PHYSICAL_NAME"}["code"]'),
            ("concatenation", '"DUPLICATE_" + "PHYSICAL_NAME"'),
            ("f-string", 'f"DUPLICATE_PHYSICAL_NAME"'),
        ):
            must_fail(
                f"unextractable direct {label}",
                replace_once(source, direct_code, expression),
                text,
                "unextractable structured-error code expressions",
            )

        must_fail(
            "unclassified forwarding literal",
            replace_once(
                source,
                'strict_decode(entry["nameRaw"], encoding)',
                'strict_decode(entry["nameRaw"], encoding, "NEW_FORWARD_CODE")',
            ),
            text,
            "outside direct constant raises",
        )
        must_fail(
            "unclassified table-bound literal",
            replace_once(
                source,
                '"CONCATENATED_BZIP2_STREAM"',
                '"NEW_TABLE_BOUND_CODE"',
            ),
            text,
            "outside direct constant raises",
        )
        must_fail(
            "attribute rejection callee",
            replace_once(
                source,
                'reject(\n                "DUPLICATE_PHYSICAL_NAME"',
                'self.reject(\n                "DUPLICATE_PHYSICAL_NAME"',
            ),
            text,
            "structured-error callees must be direct ast.Name nodes",
        )

        addition_victim = '"DUPLICATE_PHYSICAL_NAME"'
        for added in ("SFX_ADDED_LIMIT", "ENVELOPE_ADDED_LIMIT"):
            added_source = replace_once(source, addition_victim, f'"{added}"')
            added_text = replace_once(
                text,
                "`ENVELOPE_WORK_LIMIT`). A candidate",
                f"`{added}`, or `ENVELOPE_WORK_LIMIT`). A candidate",
            )
            must_fail(
                f"added budget {added}",
                added_source,
                added_text,
                "production budget family",
            )

        for code in sorted(EXPECTED_BUDGET_REJECTION_CODES):
            removed = f"RETIRED_{code}"
            removed_source = source.replace(f'"{code}"', f'"{removed}"')
            self.assertNotEqual(source, removed_source)
            removed_text = text.replace(f"`{code}`", code)
            self.assertNotEqual(text, removed_text)
            must_fail(
                f"removed budget with dormant literal {code}",
                removed_source + f'\n_DORMANT_OLD_BUDGET = "{code}"\n',
                removed_text,
                "outside direct constant raises",
            )
            must_fail(
                f"removed budget {code}",
                removed_source,
                removed_text,
                "production budget family",
            )

            prefix = "SFX" if code.startswith("SFX_") else "ENVELOPE"
            renamed = f"{prefix}_RENAMED_LIMIT"
            budget_source = source.replace(f'"{code}"', f'"{renamed}"')
            self.assertNotEqual(source, budget_source)
            budget_text = text.replace(f"`{code}`", f"`{renamed}`")
            self.assertNotEqual(text, budget_text)
            must_fail(
                f"renamed budget {code}",
                budget_source,
                budget_text,
                "production budget family",
            )

    def test_mutations_always_produce_a_structured_outcome(self):
        """Mutation control covering all eight third-audit findings.

        Sweeps seed families that reach every remediated path and limit
        configurations including extreme and overflowing values, so a
        traceback anywhere in configuration, PE parsing, overlay scanning,
        member classification, or provenance surfaces as a failure here.
        """
        archive = make_7z([{"name": "payload.dat", "content": b"content-bytes"}])
        image, signed = signed_sfx(archive, [win_certificate(b"pkcs7-placeholder")])
        image_end = len(build_pe())
        unix = AUDITOR.SEVEN_ZIP_UNIX_EXTENSION
        seeds = {
            "signed-sfx": signed,
            "unsigned-sfx": image + archive,
            "bare-7z": archive,
            "decoy-sfx": make_decoy_sfx(16, 1 << 14),
            "plain-pe": build_pe(sections=((".text", 0x400, 0x400),)),
            "gapped-sfx": build_pe(image_length=image_end + 512) + archive,
            "zip-modes": make_zip([
                {"name": "a", "content": b"x", "external": 0o100644 << 16},
                {"name": "b/", "external": (0o040755 << 16) | 0x10},
            ]),
            "7z-modes": make_7z(
                [{"name": "m", "content": b"x"}],
                attributes=[(0o100644 << 16) | unix],
            ),
        }
        limit_sets = [
            AUDITOR.Limits(max_envelope_work_bytes=8 << 20, max_sfx_signature_candidates=32),
            AUDITOR.Limits(max_compression_ratio=1),
            AUDITOR.Limits(max_compression_ratio=AUDITOR.MAX_COMPRESSION_RATIO),
            AUDITOR.Limits(max_sfx_overlay_scan_bytes=16),
            AUDITOR.Limits(max_sfx_overlay_scan_bytes=AUDITOR.MAX_LIMIT_VALUE),
            AUDITOR.Limits(max_total_expanded_bytes=1),
        ]
        generator = random.Random(20260828)
        codes = set()
        for label, seed in seeds.items():
            for iteration in range(40):
                data = bytearray(seed)
                for _ in range(generator.randint(1, 6)):
                    data[generator.randrange(len(data))] = generator.randrange(256)
                if not generator.randrange(10):
                    data = data[:generator.randrange(1, len(data) + 1)]
                limits = limit_sets[iteration % len(limit_sets)]
                with self.subTest(seed=label, iteration=iteration):
                    try:
                        AUDITOR.ArchiveAuditor(limits).audit_bytes(bytes(data), "fuzz.bin")
                    except AUDITOR.AuditError as exc:
                        self.assertIsInstance(exc.code, str)
                        self.assertTrue(exc.code)
                        codes.add(exc.code)
        self.assertGreater(len(codes), 6)

        extreme = (1e308, float("inf"), float("nan"), 10 ** 400, "8", True, 0, -1)
        for label, seed in seeds.items():
            for value in extreme:
                with self.subTest(seed=label, ratio=repr(value)):
                    with self.assertRaises(AUDITOR.AuditError) as context:
                        AUDITOR.ArchiveAuditor(
                            AUDITOR.Limits(max_compression_ratio=value)
                        ).audit_bytes(seed, "fuzz.bin")
                    self.assertEqual("INVALID_LIMIT", context.exception.code)

    def test_overlay_work_does_not_scale_with_overlay_length(self):
        """Discovery cost follows the configured bound, not the overlay size."""
        image_end = len(build_pe())
        allowance = AUDITOR.Limits(max_sfx_overlay_scan_bytes=64)

        charged = {}
        for payload in (128, 1 << 12, 1 << 16, 1 << 20):
            archive = make_7z([{"name": "clean", "content": b"x" * payload}])
            data = build_pe() + archive
            manifest = self.audit(data, "sfx.bin", allowance)
            self.assertEqual("7z-sfx", manifest["archive"]["format"])
            charged[len(data)] = manifest["totals"]["sfxOverlayScanBytes"]

        self.assertGreater(max(charged) // min(charged), 100)
        self.assertEqual(
            1,
            len(set(charged.values())),
            f"overlay scan work must not vary with overlay length: {charged}",
        )
        self.assertLessEqual(max(charged.values()), 64)

        # A gap wider than the allowance is rejected rather than fully scanned.
        for gap in (1 << 12, 1 << 20):
            with self.subTest(gap=gap):
                wide = build_pe(image_length=image_end + gap) + make_7z(
                    [{"name": "clean", "content": b"x" * 128}]
                )
                self.assert_rejected("SFX_OVERLAY_SCAN_LIMIT", wide, "sfx.bin", allowance)

        default_totals = self.audit(
            build_pe(image_length=image_end + (1 << 20))
            + make_7z([{"name": "clean", "content": b"x" * 128}]),
            "sfx.bin",
        )["totals"]
        self.assertLessEqual(
            default_totals["sfxOverlayScanBytes"],
            AUDITOR.Limits().max_sfx_overlay_scan_bytes,
        )

    def test_nested_ordinary_pe_members_are_opaque_leaves(self):
        executable = build_pe(sections=((".text", 0x400, 0x200),))
        self.assertNotIn(AUDITOR.SEVEN_ZIP_SIGNATURE, executable)
        container = make_zip([
            {"name": "tools/git.exe", "content": executable},
            {"name": "notes.txt", "content": b"plain"},
        ])
        node = self.audit(container, "package.zip")["archive"]
        self.assertEqual(["tools/git.exe", "notes.txt"], [m["logicalPath"] for m in node["members"]])
        for member in node["members"]:
            with self.subTest(path=member["logicalPath"]):
                self.assertIsNone(member["nestedArchiveIdentity"])
                self.assertNotIn("nestedArchive", member)

        for label, blob, code in (
            ("mz-text", b"MZ this is not a portable executable at all", "MALFORMED_SFX_PE_PREFIX"),
            ("mz-truncated", executable[:96], "MALFORMED_SFX_PE_PREFIX"),
            (
                "mz-bad-signature",
                executable[:0x80] + b"PX\0\0" + executable[0x84:],
                "MALFORMED_SFX_PE_PREFIX",
            ),
        ):
            with self.subTest(case=label):
                nested = make_zip([{"name": "blob.bin", "content": blob}])
                self.assert_rejected(code, nested, "package.zip")
                self.assert_rejected(code, blob, "blob.bin")

        sfx = make_7z([{"name": "leaf", "content": b"x"}], sfx=build_pe())
        member = self.audit(
            make_zip([{"name": "inner.bin", "content": sfx}]),
            "package.zip",
        )["archive"]["members"][0]
        self.assertEqual("7z-sfx", member["nestedArchive"]["format"])

        broken = bytearray(sfx)
        broken[0x80:0x84] = b"PX\0\0"
        self.assert_rejected(
            "MALFORMED_SFX_PE_PREFIX",
            make_zip([{"name": "inner.bin", "content": bytes(broken)}]),
            "package.zip",
        )

        self.assert_rejected("MISSING_7Z_SFX_SIGNATURE", executable, "git.exe")

    def test_malformed_nested_pe_never_becomes_an_opaque_leaf(self):
        """Root and nested malformed PE shapes must agree exactly."""
        valid = build_pe(sections=((".text", 0x400, 0x200),))
        cases = {
            "truncated-dos": b"MZ" + b"\0" * 40,
            "dos-only": valid[:64],
            "truncated-pe-header": valid[:0x84],
            "truncated-coff": valid[:0x90],
            "bad-pe-signature": valid[:0x80] + b"PX\0\0" + valid[0x84:],
            "zero-sections": build_pe_raw(section_count=0),
            "too-many-sections": build_pe_raw(section_count=97),
            "bad-optional-magic": build_pe_raw(magic=0x999),
            "short-optional-header": build_pe(optional_size=64, number_of_rva_and_sizes=0),
            "overlapping-sections": build_pe(
                sections=((".a", 0x400, 0x300), (".b", 0x600, 0x200)),
            ),
            "section-inside-headers": build_pe(sections=((".a", 0x100, 0x200),)),
            "too-many-directories": build_pe_raw(number_of_rva_and_sizes=17),
            "directories-past-optional": build_pe(
                number_of_rva_and_sizes=16, optional_size=112 + 8 * 15,
            ),
        }
        for label, blob in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(AUDITOR.AuditError) as root:
                    self.audit(blob, "root.exe")
                with self.assertRaises(AUDITOR.AuditError) as nested:
                    self.audit(make_zip([{"name": "m.exe", "content": blob}]), "p.zip")
                self.assertEqual(root.exception.code, nested.exception.code)
                self.assertEqual("MALFORMED_SFX_PE_PREFIX", root.exception.code)

        body = align_image(b"")
        certificates = {
            "bad-revision": sign(body, [win_certificate(b"sig", revision=0x0300)]),
            "bad-type": sign(body, [win_certificate(b"sig", certificate_type=0x00ff)]),
            "nonterminal": sign(body, [win_certificate(b"sig")], length=8),
            "misaligned": sign(body, [win_certificate(b"sig")], offset=len(body) + 1),
        }
        for label, blob in certificates.items():
            with self.subTest(certificate=label):
                with self.assertRaises(AUDITOR.AuditError) as root:
                    self.audit(blob, "root.exe")
                with self.assertRaises(AUDITOR.AuditError) as nested:
                    self.audit(make_zip([{"name": "m.exe", "content": blob}]), "p.zip")
                self.assertEqual(root.exception.code, nested.exception.code)
                self.assertIn(
                    root.exception.code,
                    ("MALFORMED_PE_CERTIFICATE", "MALFORMED_SFX_PE_PREFIX"),
                )

        signed_valid = sign(align_image(b""), [win_certificate(b"pkcs7")])
        member = self.audit(
            make_zip([{"name": "signed.exe", "content": signed_valid}]),
            "p.zip",
        )["archive"]["members"][0]
        self.assertIsNone(member["nestedArchiveIdentity"])
        self.assert_rejected("MISSING_7Z_SFX_SIGNATURE", signed_valid, "signed.exe")

    def test_accepted_envelope_is_validated_and_charged_exactly_once(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        _, signed = signed_sfx(archive, [win_certificate(b"signature")])
        for label, data in (
            ("bare-7z", archive),
            ("unsigned-sfx", build_pe() + archive),
            ("signed-sfx", signed),
        ):
            with self.subTest(case=label):
                manifest = self.audit(data, "input.bin")
                node = manifest["archive"]
                self.assertEqual(
                    node["ownerDisposition"]["nextHeaderLength"],
                    manifest["totals"]["envelopeWorkBytes"],
                )
                self.assertEqual(
                    1 if label != "bare-7z" else 0,
                    manifest["totals"]["sfxSignatureCandidates"],
                )

    def test_overlay_gap_and_provenance_partition_are_exact(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        image = build_pe(sections=((".text", 0x400, 0x200),), image_length=0x800)
        data = image + archive
        node = self.audit(data, "sfx.bin")["archive"]
        provenance = node["ownerDisposition"]["provenance"]

        self.assertEqual(len(data), provenance["containerLength"])
        self.assertEqual(len(data), provenance["coveredLength"])
        self.assertEqual(
            ["pe-image", "overlay-gap", "archive"],
            [item["role"] for item in provenance["partitions"]],
        )
        self.assertEqual(0x600, partition(node, "pe-image")["length"])
        self.assertEqual(0x800 - 0x600, partition(node, "overlay-gap")["length"])
        self.assertEqual(
            AUDITOR.sha256(image[0x600:0x800]),
            partition(node, "overlay-gap")["sha256"],
        )

        cursor = 0
        for item in provenance["partitions"]:
            self.assertEqual(cursor, item["offset"])
            self.assertEqual(AUDITOR.sha256(data[item["offset"]:item["offset"] + item["length"]]), item["sha256"])
            cursor += item["length"]
        self.assertEqual(len(data), cursor)

        flush = build_pe(sections=((".text", 0x400, 0x200),))
        self.assertEqual(
            0,
            partition(self.audit(flush + archive, "sfx.bin")["archive"], "overlay-gap")["length"],
        )

    def test_certificate_chain_and_entry_ceiling(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        chain = [win_certificate(b"a" * 9), win_certificate(b"bb"), win_certificate(b"c" * 17)]
        image, data = signed_sfx(archive, chain)
        table_start = len(image) + len(archive)

        entries = self.audit(data, "sfx.bin")["archive"]["ownerDisposition"]["peLayout"]["certificateEntries"]
        self.assertEqual(3, len(entries))
        self.assertEqual([17, 10, 25], [entry["length"] for entry in entries])
        self.assertEqual(
            [table_start, table_start + 24, table_start + 40],
            [entry["offset"] for entry in entries],
        )

        self.assert_rejected(
            "CERTIFICATE_ENTRY_LIMIT",
            data,
            "sfx.bin",
            AUDITOR.Limits(max_certificate_entries=2),
        )

    def test_nested_pe_is_opaque_only_when_every_byte_is_accounted_for(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])

        large = build_pe(sections=((".text", 0x400, 0x40000),))
        self.assertNotIn(AUDITOR.SEVEN_ZIP_SIGNATURE, large)
        member = self.audit(
            make_zip([{"name": "tools/git.exe", "content": large}]),
            "package.zip",
        )["archive"]["members"][0]
        self.assertIsNone(member["nestedArchiveIdentity"])

        signed_plain = sign(align_image(b""), [win_certificate(b"pkcs7")])
        member = self.audit(
            make_zip([{"name": "signed.exe", "content": signed_plain}]),
            "package.zip",
        )["archive"]["members"][0]
        self.assertIsNone(member["nestedArchiveIdentity"])

        trailing = large + b"\x00" * 64
        self.assert_rejected(
            "UNCLASSIFIED_PE_OVERLAY",
            make_zip([{"name": "blob.exe", "content": trailing}]),
            "package.zip",
        )
        self.assert_rejected("UNCLASSIFIED_PE_OVERLAY", trailing, "blob.exe")

        nested_sfx = build_pe(image_length=len(build_pe()) + 4096) + archive
        member = self.audit(
            make_zip([{"name": "inner.exe", "content": nested_sfx}]),
            "package.zip",
        )["archive"]["members"][0]
        self.assertEqual("7z-sfx", member["nestedArchive"]["format"])

        self.assert_rejected(
            "SFX_OVERLAY_SCAN_LIMIT",
            make_zip([{"name": "inner.exe", "content": nested_sfx}]),
            "package.zip",
            AUDITOR.Limits(max_sfx_overlay_scan_bytes=64),
        )

    def test_nested_and_root_pe_prefix_ceiling_agree(self):
        archive = make_7z([{"name": "file", "content": b"x"}])
        image_end = len(build_pe())
        blob = build_pe(image_length=image_end + 1024) + archive

        def nested_of(data, limits=None):
            return self.audit(
                make_zip([{"name": "inner.exe", "content": data}]),
                "package.zip",
                limits,
            )["archive"]["members"][0]

        node = self.audit(blob, "blob.exe")["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual("7z-sfx", nested_of(blob)["nestedArchive"]["format"])

        tight = AUDITOR.Limits(max_sfx_overlay_scan_bytes=512)
        with self.assertRaises(AUDITOR.AuditError) as root:
            self.audit(blob, "blob.exe", tight)
        with self.assertRaises(AUDITOR.AuditError) as nested:
            nested_of(blob, tight)
        self.assertEqual("SFX_OVERLAY_SCAN_LIMIT", root.exception.code)
        self.assertEqual(root.exception.code, nested.exception.code)

        trailing = build_pe(sections=((".text", 0x400, 0x200),)) + b"\0" * 64
        with self.assertRaises(AUDITOR.AuditError) as root:
            self.audit(trailing, "blob.exe")
        with self.assertRaises(AUDITOR.AuditError) as nested:
            nested_of(trailing)
        self.assertEqual("UNCLASSIFIED_PE_OVERLAY", root.exception.code)
        self.assertEqual(root.exception.code, nested.exception.code)

    def test_zip_unix_file_types_are_decoded_explicitly(self):
        accepted = {
            "regular": 0o100644,
            "unspecified": 0o000644,
        }
        for name, mode in accepted.items():
            with self.subTest(accepted=name):
                node = self.audit(
                    make_zip([{"name": "member", "content": b"x", "external": mode << 16}]),
                    "modes.zip",
                )["archive"]
                self.assertEqual("file", node["members"][0]["type"])
                self.assertEqual(name, node["members"][0]["ownerDisposition"]["unixFileType"])

        rejected = {
            "symlink": 0o120777,
            "character-device": 0o020644,
            "block-device": 0o060644,
            "fifo": 0o010644,
            "socket": 0o140644,
        }
        for name, mode in rejected.items():
            with self.subTest(rejected=name):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(
                        make_zip([{"name": "member", "content": b"x", "external": mode << 16}]),
                        "modes.zip",
                    )
                self.assertEqual("UNSUPPORTED_ZIP_MEMBER_TYPE", context.exception.code)
                self.assertEqual(name, context.exception.details["unixFileType"])
                self.assertEqual(f"{mode:06o}", context.exception.details["unixMode"])

        for unknown in (0o030000, 0o050000, 0o070000, 0o110000, 0o130000, 0o150000, 0o160000, 0o170000):
            with self.subTest(unknown=f"{unknown:06o}"):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(
                        make_zip([{"name": "member", "content": b"x", "external": unknown << 16}]),
                        "modes.zip",
                    )
                self.assertEqual("UNSUPPORTED_ZIP_MEMBER_TYPE", context.exception.code)

        node = self.audit(
            make_zip([{"name": "dir/", "external": (0o040755 << 16) | 0x10}]),
            "modes.zip",
        )["archive"]
        self.assertEqual("directory", node["members"][0]["type"])
        self.assertEqual("directory", node["members"][0]["ownerDisposition"]["unixFileType"])

        self.assert_rejected(
            "AMBIGUOUS_MEMBER_TYPE",
            make_zip([{"name": "dir/", "external": 0o100644 << 16}]),
            "modes.zip",
        )

    def test_zip_non_unix_creator_never_yields_a_unix_type(self):
        for creator, version_made in (("dos", 0x0014), ("ntfs", 0x0A14)):
            with self.subTest(creator=creator):
                node = self.audit(
                    make_zip([{
                        "name": "member",
                        "content": b"x",
                        "external": 0o120777 << 16,
                        "version_made": version_made,
                    }]),
                    "modes.zip",
                )["archive"]
                member = node["members"][0]
                self.assertEqual("file", member["type"])
                self.assertEqual("unspecified", member["ownerDisposition"]["unixFileType"])
                self.assertFalse(member["ownerDisposition"]["unixModeDeclared"])
                self.assertEqual(version_made >> 8, member["ownerDisposition"]["creatorSystem"])
                self.assertEqual(AUDITOR.sha256(b"x"), member["contentSha256"])

        node = self.audit(
            make_zip([{"name": "member", "content": b"x", "version_made": 0x1314}]),
            "modes.zip",
        )["archive"]
        self.assertTrue(node["members"][0]["ownerDisposition"]["unixModeDeclared"])

    def test_seven_zip_unix_file_types_are_decoded_explicitly(self):
        unix = AUDITOR.SEVEN_ZIP_UNIX_EXTENSION
        for name, mode in (("regular", 0o100644), ("unspecified", 0o000644)):
            with self.subTest(accepted=name):
                archive = make_7z(
                    [{"name": "member", "content": b"x"}],
                    attributes=[(mode << 16) | unix],
                )
                member = self.audit(archive, "modes.7z")["archive"]["members"][0]
                self.assertEqual("file", member["type"])
                self.assertEqual(name, member["ownerDisposition"]["unixFileType"])

        for name, mode in (
            ("symlink", 0o120777),
            ("character-device", 0o020644),
            ("block-device", 0o060644),
            ("fifo", 0o010644),
            ("socket", 0o140644),
        ):
            with self.subTest(rejected=name):
                archive = make_7z(
                    [{"name": "member", "content": b"x"}],
                    attributes=[(mode << 16) | unix],
                )
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(archive, "modes.7z")
                self.assertEqual("UNSUPPORTED_7Z_MEMBER_TYPE", context.exception.code)
                self.assertEqual(name, context.exception.details["unixFileType"])

        for unknown in (0o030000, 0o050000, 0o070000, 0o110000, 0o130000, 0o150000, 0o160000, 0o170000):
            with self.subTest(unknown=f"{unknown:06o}"):
                archive = make_7z(
                    [{"name": "member", "content": b"x"}],
                    attributes=[(unknown << 16) | unix],
                )
                self.assert_rejected("UNSUPPORTED_7Z_MEMBER_TYPE", archive, "modes.7z")

        smuggled = make_7z(
            [{"name": "member", "content": b"x"}],
            attributes=[0o120777 << 16],
        )
        self.assert_rejected("AMBIGUOUS_MEMBER_TYPE", smuggled, "modes.7z")

        reparse = make_7z([{"name": "member", "content": b"x"}], attributes=[0x0400])
        self.assert_rejected("UNSAFE_REPARSE_POINT", reparse, "modes.7z")

        directory = make_7z(
            [{"name": "dir", "type": "directory"}],
            attributes=[(0o040755 << 16) | unix | 0x10],
        )
        member = self.audit(directory, "modes.7z")["archive"]["members"][0]
        self.assertEqual("directory", member["type"])
        self.assertEqual("directory", member["ownerDisposition"]["unixFileType"])

        with_data = make_7z(
            [{"name": "dir", "content": b"x"}],
            attributes=[(0o040755 << 16) | unix],
        )
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(with_data, "modes.7z")
        self.assertEqual("INCONSISTENT_7Z_MEMBER_TYPE", context.exception.code)
        self.assertEqual("file", context.exception.details["structuralType"])
        self.assertEqual("directory", context.exception.details["unixFileType"])

    def test_provenance_partition_is_disjoint_and_exact(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        certificate = win_certificate(b"pkcs7-placeholder")
        image, signed = signed_sfx(archive, [certificate])
        unsigned = align_image(archive) + archive

        signed_node = self.audit(signed, "signed.exe")["archive"]
        self.assertEqual(
            ["pe-image", "overlay-gap", "archive", "certificate"],
            [item["role"] for item in signed_node["ownerDisposition"]["provenance"]["partitions"]],
        )
        unsigned_node = self.audit(unsigned, "unsigned.exe")["archive"]
        self.assertEqual(
            ["pe-image", "overlay-gap", "archive"],
            [item["role"] for item in unsigned_node["ownerDisposition"]["provenance"]["partitions"]],
        )
        bare_node = self.audit(archive, "bare.7z")["archive"]
        self.assertEqual(
            ["archive"],
            [item["role"] for item in bare_node["ownerDisposition"]["provenance"]["partitions"]],
        )

        for label, data, node in (
            ("signed", signed, signed_node),
            ("unsigned", unsigned, unsigned_node),
            ("bare", archive, bare_node),
        ):
            with self.subTest(case=label):
                provenance = node["ownerDisposition"]["provenance"]
                self.assertEqual(len(data), provenance["containerLength"])
                self.assertEqual(
                    len(data),
                    sum(item["length"] for item in provenance["partitions"]),
                )
                cursor = 0
                for item in provenance["partitions"]:
                    self.assertEqual(cursor, item["offset"])
                    self.assertEqual(
                        AUDITOR.sha256(data[item["offset"]:item["offset"] + item["length"]]),
                        item["sha256"],
                    )
                    cursor += item["length"]
                self.assertEqual(len(data), cursor)

        self.assertNotIn("sfxPrefixSha256", signed_node["ownerDisposition"])
        self.assertNotIn("sfxPrefixLength", signed_node["ownerDisposition"])
        self.assertNotIn("overlayGapSha256", signed_node["ownerDisposition"])
        self.assertNotIn("overlayGapLength", signed_node["ownerDisposition"])

    def test_provenance_mutation_is_isolated_to_one_partition(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        image, signed = signed_sfx(archive, [win_certificate(b"pkcs7-placeholder")])
        baseline = self.audit(signed, "a.exe")
        base_hashes = {
            item["role"]: item["sha256"]
            for item in baseline["archive"]["ownerDisposition"]["provenance"]["partitions"]
        }

        gap_start = partition(baseline["archive"], "overlay-gap")["offset"]
        gap_length = partition(baseline["archive"], "overlay-gap")["length"]
        mutations = {"pe-image": 0x40, "certificate": len(signed) - 1}
        if gap_length:
            mutations["overlay-gap"] = gap_start

        for role, offset in mutations.items():
            with self.subTest(role=role):
                mutated = bytearray(signed)
                mutated[offset] ^= 1
                try:
                    changed = self.audit(bytes(mutated), "b.exe")
                except AUDITOR.AuditError as exc:
                    self.assertIn(exc.code, ("MALFORMED_PE_CERTIFICATE", "MALFORMED_SFX_PE_PREFIX"))
                    continue
                hashes = {
                    item["role"]: item["sha256"]
                    for item in changed["archive"]["ownerDisposition"]["provenance"]["partitions"]
                }
                self.assertNotEqual(base_hashes[role], hashes[role])
                for other in base_hashes:
                    if other != role:
                        self.assertEqual(base_hashes[other], hashes[other])
                self.assertNotEqual(baseline["source"]["sha256"], changed["source"]["sha256"])
                self.assertFalse(AUDITOR.compare_manifests(baseline, changed)["equal"])

    def payload_probe(self, data, limits=None, name="probe.bin"):
        """Audit while counting every payload decoder, CRC, and hash call."""
        counters = {"inflate": 0, "decompressobj": 0, "lzma": 0, "crc32": 0, "sha256": 0}
        real_decompressobj = AUDITOR.zlib.decompressobj
        real_crc32 = AUDITOR.zlib.crc32
        real_sha256 = AUDITOR.hashlib.sha256
        real_lzma = AUDITOR.lzma.LZMADecompressor
        real_inflate = AUDITOR.ArchiveAuditor._inflate_zip
        real_decode = AUDITOR.ArchiveAuditor._seven_decode_streams

        def counting_decompressobj(*a, **k):
            counters["decompressobj"] += 1
            return real_decompressobj(*a, **k)

        def counting_crc32(payload, value=0):
            counters["crc32"] += 1
            return real_crc32(payload, value)

        def counting_sha256(payload=b""):
            counters["sha256"] += 1
            return real_sha256(payload)

        def counting_lzma(*a, **k):
            counters["lzma"] += 1
            return real_lzma(*a, **k)

        def counting_inflate(self_, *a, **k):
            counters["inflate"] += 1
            return real_inflate(self_, *a, **k)

        def counting_decode(self_, *a, **k):
            counters["inflate"] += 1
            return real_decode(self_, *a, **k)

        patches = [
            mock.patch.object(AUDITOR.zlib, "decompressobj", counting_decompressobj),
            mock.patch.object(AUDITOR.zlib, "crc32", counting_crc32),
            mock.patch.object(AUDITOR.hashlib, "sha256", counting_sha256),
            mock.patch.object(AUDITOR.lzma, "LZMADecompressor", counting_lzma),
            mock.patch.object(AUDITOR.ArchiveAuditor, "_inflate_zip", counting_inflate),
            mock.patch.object(AUDITOR.ArchiveAuditor, "_seven_decode_streams", counting_decode),
        ]
        for patch in patches:
            patch.start()
        try:
            try:
                AUDITOR.ArchiveAuditor(limits).audit_bytes(data, name)
                code = None
            except AUDITOR.AuditError as exc:
                code = exc.code
        finally:
            for patch in reversed(patches):
                patch.stop()
        return code, counters

    def test_zip_special_types_reject_before_any_payload_work(self):
        for label, entry in (
            ("corrupt-deflate", {
                "name": "dev",
                "method": 8,
                "compressed": b"\xff\xff\xff\xff\xff\xff",
                "external": 0o020644 << 16,
            }),
            ("tight-ratio", {
                "name": "dev",
                "content": b"\0" * 8192,
                "method": 8,
                "external": 0o060644 << 16,
            }),
            ("symlink-corrupt", {
                "name": "link",
                "method": 8,
                "compressed": b"\x00\x01\x02",
                "external": 0o120777 << 16,
            }),
        ):
            with self.subTest(case=label):
                archive = make_zip([entry])
                code, counters = self.payload_probe(
                    archive,
                    AUDITOR.Limits(max_compression_ratio=2),
                )
                self.assertEqual("UNSUPPORTED_ZIP_MEMBER_TYPE", code)
                self.assertEqual(0, counters["inflate"])
                self.assertEqual(0, counters["decompressobj"])

    def test_seven_zip_special_types_reject_before_any_payload_work(self):
        unix = AUDITOR.SEVEN_ZIP_UNIX_EXTENSION
        for label, method, content in (
            ("invalid-coder", "0301010101", b"x" * 64),
            ("copy-stream", "copy", b"x" * 4096),
        ):
            with self.subTest(case=label):
                archive = make_7z(
                    [{"name": "dev", "content": content}],
                    method=method,
                    attributes=[(0o020644 << 16) | unix],
                )
                code, counters = self.payload_probe(
                    archive,
                    AUDITOR.Limits(max_compression_ratio=2),
                )
                self.assertEqual("UNSUPPORTED_7Z_MEMBER_TYPE", code)
                self.assertEqual(0, counters["inflate"])
                self.assertEqual(0, counters["lzma"])

    def test_seven_zip_structural_and_attribute_types_must_agree(self):
        unix = AUDITOR.SEVEN_ZIP_UNIX_EXTENSION
        coherent = (
            ("regular-with-data", {"name": "m", "content": b"x"}, (0o100644 << 16) | unix, False),
            ("empty-regular", {"name": "m", "content": b""}, (0o100644 << 16) | unix, False),
            ("directory", {"name": "m", "type": "directory"}, (0o040755 << 16) | unix | 0x10, True),
            ("unspecified-file", {"name": "m", "content": b"x"}, 0, False),
        )
        for label, entry, attribute, expect_directory in coherent:
            with self.subTest(coherent=label):
                node = self.audit(make_7z([entry], attributes=[attribute]), "c.7z")["archive"]
                member = node["members"][0]
                self.assertEqual("directory" if expect_directory else "file", member["type"])

        contradictions = (
            ("dir-bit-with-data", {"name": "m", "content": b"x"}, 0x10),
            ("dir-bit-empty-file", {"name": "m", "content": b""}, 0x10),
            ("structural-dir-without-bit", {"name": "m", "type": "directory"}, unix | (0o040755 << 16)),
            ("unix-dir-with-data", {"name": "m", "content": b"x"}, unix | (0o040755 << 16)),
            ("unix-regular-on-directory", {"name": "m", "type": "directory"}, unix | (0o100644 << 16) | 0x10),
        )
        for label, entry, attribute in contradictions:
            with self.subTest(contradiction=label):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    self.audit(make_7z([entry], attributes=[attribute]), "c.7z")
                self.assertEqual("INCONSISTENT_7Z_MEMBER_TYPE", context.exception.code)
                for field in ("path", "structuralType", "emptyStream", "emptyFile"):
                    self.assertIn(field, context.exception.details)

        self.assert_rejected(
            "OUT_OF_RANGE_RECORD",
            make_7z(
                [{"name": "a", "content": b"x"}, {"name": "b", "content": b"y"}],
                attributes_payload=b"\x01\x00" + struct.pack("<I", 0),
            ),
            "c.7z",
        )
        auditor = AUDITOR.ArchiveAuditor()
        with self.assertRaises(AUDITOR.AuditError) as context:
            auditor._seven_classify_members(
                {"attributes": [0]},
                [(b"a", "a"), (b"b", "b")],
                [False, False],
                [],
            )
        self.assertEqual("SEVEN_ZIP_PROPERTY_COUNT_MISMATCH", context.exception.code)
        with self.assertRaises(AUDITOR.AuditError) as context:
            auditor._seven_classify_members({}, [(b"a", "a")], [True], [])
        self.assertEqual("SEVEN_ZIP_PROPERTY_COUNT_MISMATCH", context.exception.code)

    def test_seven_zip_optional_values_must_be_canonical(self):
        entries = [{"name": "m", "content": b"x"}]
        canonical = b"\x01\x00" + struct.pack("<I", 0)
        self.assertEqual(
            "file",
            self.audit(make_7z(entries, attributes_payload=canonical), "c.7z")["archive"]["members"][0]["type"],
        )

        cases = {
            "all-defined-2": b"\x02\x00" + struct.pack("<I", 0),
            "all-defined-255": b"\xff\x00" + struct.pack("<I", 0),
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                self.assert_rejected(
                    "NONCANONICAL_7Z_PROPERTY",
                    make_7z(entries, attributes_payload=payload),
                    "c.7z",
                )
                self.assert_rejected(
                    "NONCANONICAL_7Z_PROPERTY",
                    make_7z(entries, attributes_payload=payload, encoded_header=True),
                    "c.7z",
                )

        defined_vector = b"\x00\x80\x00" + struct.pack("<I", 0)
        self.assertEqual(
            "file",
            self.audit(
                make_7z(entries, attributes_payload=defined_vector), "c.7z",
            )["archive"]["members"][0]["type"],
        )

        self.assert_rejected(
            "NONCANONICAL_7Z_BIT_VECTOR",
            make_7z(entries, attributes_payload=b"\x00\x81\x00" + struct.pack("<I", 0)),
            "c.7z",
        )
        self.assert_rejected(
            "NONCANONICAL_7Z_BIT_VECTOR",
            make_7z(entries, attributes_payload=b"\x00\x01\x00"),
            "c.7z",
        )
        self.assert_rejected(
            "NONCANONICAL_7Z_PROPERTY",
            make_7z(entries, attributes_payload=b"\x01\x00" + struct.pack("<I", 0) + b"\x00"),
            "c.7z",
        )
        self.assert_rejected(
            "OUT_OF_RANGE_RECORD",
            make_7z(entries, attributes_payload=b"\x01\x00" + b"\x00\x00\x00"),
            "c.7z",
        )
        self.assert_rejected(
            "UNSUPPORTED_7Z_EXTERNAL_PROPERTY",
            make_7z(entries, attributes_payload=b"\x01\x01" + struct.pack("<I", 0)),
            "c.7z",
        )
        self.assert_rejected(
            "DUPLICATE_7Z_FILE_PROPERTY",
            make_7z(
                entries,
                attributes_payload=b"\x01\x00" + struct.pack("<I", 0),
                extra_properties=b"\x15\x06\x01\x00" + struct.pack("<I", 0),
            ),
            "c.7z",
        )

    def test_numeric_limits_never_escape_as_unstructured_errors(self):
        from decimal import Decimal

        probes = (
            ("bool", True),
            ("string", "8"),
            ("decimal", Decimal("2")),
            ("huge-int", 10 ** 400),
            ("float-max", sys.float_info.max),
            ("nan", float("nan")),
            ("inf", float("inf")),
            ("negative-inf", float("-inf")),
            ("zero", 0),
            ("negative", -1),
            ("subnormal-negative", -5e-324),
        )
        for label, value in probes:
            with self.subTest(ratio=label):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.ArchiveAuditor(AUDITOR.Limits(max_compression_ratio=value))
                self.assertEqual("INVALID_LIMIT", context.exception.code)

        for label, value in (("subnormal", 5e-324), ("one", 1), ("max", AUDITOR.MAX_COMPRESSION_RATIO)):
            with self.subTest(accepted=label):
                AUDITOR.ArchiveAuditor(AUDITOR.Limits(max_compression_ratio=value))

        for name in (
            "max_depth",
            "max_total_expanded_bytes",
            "max_members_per_archive",
            "max_members_total",
            "max_path_length",
            "max_sfx_prefix_bytes",
            "max_sfx_overlay_scan_bytes",
            "max_sfx_signature_occurrences",
            "max_sfx_signature_candidates",
            "max_envelope_work_bytes",
            "max_certificate_entries",
        ):
            for value in (10 ** 400, float("inf"), float("nan"), "8", Decimal("2"), 1.5, True):
                with self.subTest(limit=name, value=repr(value)):
                    with self.assertRaises(AUDITOR.AuditError) as context:
                        AUDITOR.ArchiveAuditor(AUDITOR.Limits(**{name: value}))
                    self.assertEqual("INVALID_LIMIT", context.exception.code)

        payloads = {
            "gzip": make_gzip(b"x" * 4096),
            "bzip2": bz2.compress(make_tar([{"name": "f", "content": b"x"}])),
            "xz": lzma.compress(make_tar([{"name": "f", "content": b"x"}])),
            "zip": make_zip([{"name": "f", "content": b"x" * 4096, "method": 8}]),
            "7z": make_7z([{"name": "f", "content": b"x" * 64}]),
        }
        for label, payload in payloads.items():
            with self.subTest(format=label):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.ArchiveAuditor(
                        AUDITOR.Limits(max_compression_ratio=1e308)
                    ).audit_bytes(payload, "x.bin")
                self.assertEqual("INVALID_LIMIT", context.exception.code)

    def test_cli_extreme_limits_return_structured_json(self):
        payloads = {
            "gzip": make_gzip(b"x" * 4096),
            "zip": make_zip([{"name": "f", "content": b"x" * 4096, "method": 8}]),
            "7z": make_7z([{"name": "f", "content": b"x" * 64}]),
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            for label, payload in payloads.items():
                path = Path(directory) / f"{label}.bin"
                path.write_bytes(payload)
                for argument in ("1e308", "inf", "nan", "-1", "0"):
                    with self.subTest(format=label, ratio=argument):
                        stderr = io.StringIO()
                        old_stderr = AUDITOR.sys.stderr
                        try:
                            AUDITOR.sys.stderr = stderr
                            status = AUDITOR.main(
                                ["audit", "--max-compression-ratio", argument, str(path)]
                            )
                        finally:
                            AUDITOR.sys.stderr = old_stderr
                        self.assertEqual(2, status)
                        document = json.loads(stderr.getvalue())
                        self.assertEqual("INVALID_LIMIT", document["error"]["code"])
                        self.assertFalse(document["ok"])

    def test_overlay_search_is_bounded_by_the_configured_window(self):
        image_end = len(build_pe())
        deep = b"\0" * 4096 + AUDITOR.SEVEN_ZIP_SIGNATURE + b"\0" * 4096
        archive = make_7z([{"name": "payload", "content": deep}])
        data = build_pe() + archive

        limits = AUDITOR.Limits(max_sfx_overlay_scan_bytes=64)
        node = self.audit(data, "sfx.bin", limits)["archive"]
        self.assertEqual("7z-sfx", node["format"])
        self.assertEqual(image_end, node["headerOffset"])
        totals = self.audit(data, "sfx.bin", limits)["totals"]
        self.assertLessEqual(totals["sfxOverlayScanBytes"], 64)

        big_gap = build_pe(image_length=image_end + (1 << 20)) + make_7z(
            [{"name": "clean", "content": b"x" * 128}]
        )
        measured = self.audit(big_gap, "sfx.bin")["totals"]
        self.assertLessEqual(
            measured["sfxOverlayScanBytes"],
            AUDITOR.Limits().max_sfx_overlay_scan_bytes,
        )

        self.assert_rejected(
            "SFX_OVERLAY_SCAN_LIMIT",
            build_pe(image_length=image_end + 4096) + b"\0" * 64,
            "sfx.bin",
            AUDITOR.Limits(max_sfx_overlay_scan_bytes=64),
        )

        many = build_pe() + b"".join(
            seven_zip_decoy(image_end + 32 * (index + 1), image_end + 32 * index)
            for index in range(64)
        )
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(many, "sfx.bin")
        self.assertIn(
            context.exception.code,
            ("TRAILING_7Z_PAYLOAD", "SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH"),
        )

        self.assertEqual(
            "7z-sfx",
            self.audit(
                build_pe() + make_7z([{"name": "clean", "content": b"x" * 128}]),
                "sfx.bin",
                AUDITOR.Limits(max_sfx_overlay_scan_bytes=AUDITOR.MAX_LIMIT_VALUE),
            )["archive"]["format"],
        )
        # With an unbounded window the stray signature inside the archive body
        # is itself scanned, and a malformed candidate is fail-closed.
        self.assert_rejected(
            "SEVEN_ZIP_START_HEADER_CRC_MISMATCH",
            data,
            "sfx.bin",
            AUDITOR.Limits(max_sfx_overlay_scan_bytes=AUDITOR.MAX_LIMIT_VALUE),
        )

        signed_archive = make_7z([{"name": "payload", "content": deep}])
        _, signed = signed_sfx(signed_archive, [win_certificate(b"pkcs7")])
        node = self.audit(signed, "signed.exe", AUDITOR.Limits(max_sfx_overlay_scan_bytes=64))["archive"]
        self.assertEqual("signed", node["ownerDisposition"]["peLayout"]["signatureDisposition"])

    def test_manifest_schema_is_versioned_and_not_interchangeable(self):
        archive = make_zip([{"name": "f", "content": b"x"}])
        manifest = self.audit(archive, "a.zip")
        self.assertEqual("git-for-windows.archive-audit/v2", manifest["schema"])
        self.assertEqual(
            "git-for-windows.archive-comparison/v2",
            AUDITOR.compare_manifests(manifest, manifest)["schema"],
        )

        legacy = json.loads(json.dumps(manifest))
        legacy["schema"] = "git-for-windows.archive-audit/v1"
        for left, right in ((legacy, manifest), (manifest, legacy)):
            with self.subTest(side="a" if left is legacy else "b"):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.compare_manifests(left, right)
                self.assertEqual("UNSUPPORTED_MANIFEST_SCHEMA", context.exception.code)

        missing = json.loads(json.dumps(manifest))
        del missing["schema"]
        with self.assertRaises(AUDITOR.AuditError) as context:
            AUDITOR.compare_manifests(missing, manifest)
        self.assertEqual("UNSUPPORTED_MANIFEST_SCHEMA", context.exception.code)

    def test_provenance_has_no_duplicate_ownership_hashes(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        _, signed = signed_sfx(archive, [win_certificate(b"pkcs7-placeholder")])
        node = self.audit(signed, "signed.exe")["archive"]
        layout = node["ownerDisposition"]["peLayout"]

        self.assertNotIn("certificateSha256", layout)
        self.assertIn("certificateEntries", layout)
        for entry in layout["certificateEntries"]:
            self.assertEqual({"offset", "length", "revision", "certificateType"}, set(entry))

        digests = [item["sha256"] for item in node["ownerDisposition"]["provenance"]["partitions"]]
        serialized = json.dumps(node, sort_keys=True)
        for digest in digests:
            self.assertEqual(1, serialized.count(digest), digest)

    def test_same_length_partition_mutation_is_isolated(self):
        archive = make_7z([{"name": "file", "content": b"payload"}])
        image, signed = signed_sfx(archive, [win_certificate(b"pkcs7-placeholder")])
        baseline = self.audit(signed, "a.exe")
        base = {
            item["role"]: item["sha256"]
            for item in baseline["archive"]["ownerDisposition"]["provenance"]["partitions"]
        }

        mutated = bytearray(signed)
        mutated[0x40] ^= 0xff
        changed = self.audit(bytes(mutated), "b.exe")
        after = {
            item["role"]: item["sha256"]
            for item in changed["archive"]["ownerDisposition"]["provenance"]["partitions"]
        }
        self.assertEqual(len(signed), len(mutated))
        self.assertNotEqual(base["pe-image"], after["pe-image"])
        for role in ("archive", "certificate"):
            self.assertEqual(base[role], after[role])
        self.assertEqual(
            [item["length"] for item in baseline["archive"]["ownerDisposition"]["provenance"]["partitions"]],
            [item["length"] for item in changed["archive"]["ownerDisposition"]["provenance"]["partitions"]],
        )
        self.assertFalse(AUDITOR.compare_manifests(baseline, changed)["equal"])

    def test_tampered_partition_records_are_rejected(self):
        data = make_7z([{"name": "file", "content": b"payload"}])
        for label, ranges in (
            ("reordered", [("archive", 32, len(data)), ("pe-image", 0, 32)]),
            ("overlapping", [("pe-image", 0, 64), ("archive", 32, len(data))]),
            ("gapped", [("pe-image", 0, 16), ("archive", 32, len(data))]),
            ("short", [("archive", 0, len(data) - 1)]),
            ("long", [("archive", 0, len(data) + 1)]),
        ):
            with self.subTest(case=label):
                with self.assertRaises(AUDITOR.AuditError) as context:
                    AUDITOR.physical_partition(data, ranges, "probe")
                self.assertEqual("PROVENANCE_PARTITION_INVALID", context.exception.code)


if __name__ == "__main__":
    unittest.main()
