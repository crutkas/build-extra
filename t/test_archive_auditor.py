#!/usr/bin/env python3

import bz2
import gzip
import importlib.util
import io
import json
import lzma
from pathlib import Path
import struct
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


def seven_files(entries):
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
    return result + b"\0"


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


def make_7z(entries, method="copy", encoded_header=False, sfx=b"", huge_dictionary=False):
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
    main_header = b"\x01" + (b"\x04" + streams if streams else b"") + seven_files(entries) + b"\0"
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


class ArchiveAuditorTests(unittest.TestCase):
    def audit(self, data, name, limits=None):
        return AUDITOR.ArchiveAuditor(limits).audit_bytes(data, name)

    def assert_rejected(self, code, data, name, limits=None):
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(data, name, limits)
        self.assertEqual(code, context.exception.code)

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

    def test_valid_deflated_zip_and_safe_symlink(self):
        symlink_mode = 0o120777 << 16
        archive = make_zip([
            {"name": "target", "content": b"x", "method": 8},
            {"name": "link", "content": b"target", "external": symlink_mode},
        ])
        manifest = self.audit(archive, "payload.zip")
        self.assertEqual(["file", "symlink"], [item["type"] for item in manifest["archive"]["members"]])
        self.assertEqual("target", manifest["archive"]["members"][1]["linkTarget"])

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

    def test_zip_invalid_utf8_name_rejected(self):
        archive = make_zip([{"name": b"\xff", "flags": 0x0800}])
        self.assert_rejected("INVALID_PATH_ENCODING", archive, "encoding.zip")

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

    def test_nested_gzip_fname_compares_with_containing_basename(self):
        inner = make_tar([{"name": "file", "content": b"x"}])
        compressed = make_gzip(inner, "pkg.tar")
        outer = make_zip([{"name": "sub/pkg.tar.gz", "content": compressed}])
        manifest = self.audit(outer, "outer.zip")
        wrapper = manifest["archive"]["members"][0]["nestedArchive"]
        self.assertEqual("gzip", wrapper["format"])
        self.assertEqual("tar", wrapper["members"][0]["nestedArchive"]["format"])

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

    def test_nested_format_disagreement_rejected(self):
        inner_tar = make_tar([{"name": "file"}])
        outer = make_zip([{"name": "claims.zip", "content": inner_tar}])
        self.assert_rejected("NESTED_FORMAT_DISAGREEMENT", outer, "outer.zip")

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

    def test_valid_7z_sfx_is_never_executed(self):
        prefix = b"MZ" + b"synthetic inert prefix"
        archive = make_7z([{"name": "file", "content": b"x"}], sfx=prefix)
        manifest = self.audit(archive, "PortableGit.7z.exe")
        self.assertEqual("7z-sfx", manifest["archive"]["format"])
        self.assertEqual(len(prefix), manifest["archive"]["ownerDisposition"]["sfxPrefixLength"])

    def test_7z_sfx_signature_ambiguity_reports_only_two_offsets(self):
        archive = b"MZ" + AUDITOR.SEVEN_ZIP_SIGNATURE * 10000
        with self.assertRaises(AUDITOR.AuditError) as context:
            self.audit(archive, "ambiguous.7z.exe")
        self.assertEqual("AMBIGUOUS_7Z_SIGNATURE", context.exception.code)
        self.assertEqual(
            {"firstOffset", "secondOffset"},
            set(context.exception.details),
        )

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
        self.assert_rejected("OUT_OF_RANGE_RECORD", bytes(offset), "bad.7z")

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

    def test_7z_path_reparse_and_format_disagreement_rejected(self):
        traversal = make_7z([{"name": "../escape", "content": b"x"}])
        self.assert_rejected("TRAVERSAL_PATH", traversal, "bad.7z")

        archive = make_7z([{"name": "file", "content": b"x"}])
        self.assert_rejected("FORMAT_DISAGREEMENT", archive, "claims.zip")

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
        with tempfile.TemporaryDirectory() as directory:
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
            self.assertEqual("INVALID_ZIP_EOCD", json.loads(stderr.getvalue())["error"]["code"])


if __name__ == "__main__":
    unittest.main()
