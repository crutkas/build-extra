#!/usr/bin/env python3

import argparse
import bz2
import hashlib
import json
import lzma
import math
import os
import re
import struct
import sys
import unicodedata
import zlib
from dataclasses import asdict, dataclass

try:
    from compression import zstd
except ImportError:
    zstd = None


SCHEMA = "git-for-windows.archive-audit/v1"
COMPARISON_SCHEMA = "git-for-windows.archive-comparison/v1"
SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf'\x1c"
MAX_SFX_PREFIX_LENGTH = 16 * 1024 * 1024
XZ_SIGNATURE = b"\xfd7zXZ\x00"
ZSTD_SIGNATURE = b"\x28\xb5\x2f\xfd"
WINDOWS_RESERVED = re.compile(
    r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|"
    r"com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\..*)?$",
    re.IGNORECASE,
)


class AuditError(Exception):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def document(self):
        result = {
            "schema": SCHEMA,
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }
        if self.details:
            result["error"]["details"] = self.details
        return result


def reject(code, message, **details):
    raise AuditError(code, message, **details)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_slice(data, offset, length, code="OUT_OF_RANGE_RECORD"):
    if offset < 0 or length < 0 or offset + length > len(data):
        reject(
            code,
            "Archive record extends outside its containing byte stream",
            offset=offset,
            length=length,
            containerLength=len(data),
        )
    return data[offset:offset + length]


def u16(data, offset):
    return struct.unpack_from("<H", checked_slice(data, offset, 2), 0)[0]


def u32(data, offset):
    return struct.unpack_from("<I", checked_slice(data, offset, 4), 0)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", checked_slice(data, offset, 8), 0)[0]


def validate_archive_text(text, surface="archive text"):
    for char in text:
        if unicodedata.category(char) == "Cc":
            reject(
                "CONTROL_CHARACTER",
                "Archive text contains a Unicode control character",
                surface=surface,
                codePoint=f"U+{ord(char):04X}",
            )
    return text


def strict_decode(raw, encoding, code="INVALID_PATH_ENCODING", surface="archive text"):
    try:
        text = raw.decode(encoding, errors="strict")
    except UnicodeError as exc:
        reject(code, "Archive text is not valid in its declared encoding", encoding=encoding, reason=str(exc))
    return validate_archive_text(text, surface)


def terminated_field(raw, encoding="utf-8"):
    nul = raw.find(b"\0")
    if nul < 0:
        value = raw
    else:
        if any(raw[nul + 1:]):
            reject("AMBIGUOUS_HEADER_ENCODING", "A NUL-terminated header field has nonzero trailing bytes")
        value = raw[:nul]
    return value, strict_decode(value, encoding)


def raw_path(raw, text, encoding, source="header", **extra):
    result = {
        "encoding": encoding,
        "hex": raw.hex(),
        "text": text,
        "source": source,
    }
    result.update(extra)
    return result


def normalize_path(text, is_directory, max_length):
    validate_archive_text(text, "member name")
    if text != unicodedata.normalize("NFC", text):
        reject("AMBIGUOUS_PATH_NORMALIZATION", "Archive path is not Unicode NFC", path=text)
    if "\\" in text:
        reject("UNSAFE_PATH", "Archive path uses a Windows path separator", path=text)
    if text.startswith("/") or text.startswith("//") or re.match(r"^[A-Za-z]:", text):
        reject("ABSOLUTE_PATH", "Archive path is absolute", path=text)

    had_trailing_slash = text.endswith("/")
    candidate = text[:-1] if had_trailing_slash else text
    if not candidate:
        reject("UNSAFE_PATH", "Archive member has an empty path")
    if len(candidate.encode("utf-8")) > max_length:
        reject(
            "PATH_LENGTH_LIMIT",
            "Archive path exceeds the configured byte limit",
            path=candidate,
            limit=max_length,
        )

    components = candidate.split("/")
    for component in components:
        if component in ("", "."):
            reject("AMBIGUOUS_PATH", "Archive path contains an empty or dot component", path=text)
        if component == "..":
            reject("TRAVERSAL_PATH", "Archive path contains a parent traversal", path=text)
        if component.endswith((" ", ".")):
            reject("UNSAFE_WINDOWS_PATH", "Archive path component has a trailing space or dot", path=text)
        if any(char in '<>:"|?*' for char in component):
            reject("UNSAFE_WINDOWS_PATH", "Archive path contains a Windows-reserved character", path=text)
        if WINDOWS_RESERVED.match(component):
            reject("UNSAFE_WINDOWS_PATH", "Archive path uses a Windows-reserved name", path=text)

    if had_trailing_slash and not is_directory:
        reject("AMBIGUOUS_MEMBER_TYPE", "Only directory members may have a trailing slash", path=text)
    return "/".join(components)


def normalize_link_target(member_path, target, max_length, root_relative=False):
    validate_archive_text(target, "link target")
    if target != unicodedata.normalize("NFC", target):
        reject("AMBIGUOUS_LINK_TARGET", "Link target is not Unicode NFC", path=member_path, target=target)
    if "\\" in target or target.startswith("/") or target.startswith("//") or re.match(r"^[A-Za-z]:", target):
        reject("UNSAFE_LINK_TARGET", "Link target is absolute or uses a Windows separator", path=member_path, target=target)
    if len(target.encode("utf-8")) > max_length:
        reject("PATH_LENGTH_LIMIT", "Link target exceeds the configured byte limit", path=member_path, target=target)

    base = [] if root_relative else member_path.split("/")[:-1]
    for component in target.split("/"):
        if component in ("", "."):
            if component == "":
                reject("AMBIGUOUS_LINK_TARGET", "Link target contains an empty component", path=member_path, target=target)
            continue
        if component == "..":
            if not base:
                reject("UNSAFE_LINK_TARGET", "Link target escapes the archive root", path=member_path, target=target)
            base.pop()
            continue
        if component.endswith((" ", ".")) or any(char in '<>:"|?*' for char in component) or WINDOWS_RESERVED.match(component):
            reject("UNSAFE_LINK_TARGET", "Link target is unsafe on Windows", path=member_path, target=target)
        base.append(component)
    if not base:
        reject("UNSAFE_LINK_TARGET", "Link target resolves to the archive root", path=member_path, target=target)
    return "/".join(base)


class PathRegistry:
    def __init__(self):
        self.raw = {}
        self.logical = {}

    def add(self, raw_name, logical_name, ordinal):
        if raw_name in self.raw:
            reject(
                "DUPLICATE_PHYSICAL_NAME",
                "Two physical archive members carry the same raw name",
                firstOrdinal=self.raw[raw_name],
                secondOrdinal=ordinal,
                rawPathHex=raw_name.hex(),
            )
        key = logical_name.casefold()
        if key in self.logical:
            reject(
                "DUPLICATE_LOGICAL_NAME",
                "Two archive members resolve to the same Windows path",
                firstOrdinal=self.logical[key],
                secondOrdinal=ordinal,
                logicalPath=logical_name,
            )
        self.raw[raw_name] = ordinal
        self.logical[key] = ordinal


@dataclass(frozen=True)
class Limits:
    max_depth: int = 8
    max_total_expanded_bytes: int = 4 * 1024 * 1024 * 1024
    max_members_per_archive: int = 100000
    max_members_total: int = 200000
    max_compression_ratio: float = 1000.0
    max_path_length: int = 4096

    def manifest(self):
        values = asdict(self)
        return {
            "maxDepth": values["max_depth"],
            "maxTotalExpandedBytes": values["max_total_expanded_bytes"],
            "maxMembersPerArchive": values["max_members_per_archive"],
            "maxMembersTotal": values["max_members_total"],
            "maxCompressionRatio": values["max_compression_ratio"],
            "maxPathLength": values["max_path_length"],
        }


class AuditState:
    def __init__(self, limits):
        self.limits = limits
        self.total_expanded = 0
        self.total_members = 0

    def add_member(self, archive_count):
        archive_count += 1
        if archive_count > self.limits.max_members_per_archive:
            reject(
                "MEMBERS_PER_ARCHIVE_LIMIT",
                "Archive exceeds the configured member count",
                count=archive_count,
                limit=self.limits.max_members_per_archive,
            )
        self.total_members += 1
        if self.total_members > self.limits.max_members_total:
            reject(
                "GLOBAL_MEMBER_LIMIT",
                "Recursive audit exceeds the configured global member count",
                count=self.total_members,
                limit=self.limits.max_members_total,
            )
        return archive_count

    def check_expansion(self, expanded, stored, owner):
        if expanded < 0 or stored < 0:
            reject("INVALID_LENGTH", "Archive record declares a negative length", owner=owner)
        if expanded and expanded / max(1, stored) > self.limits.max_compression_ratio:
            reject(
                "COMPRESSION_RATIO_LIMIT",
                "Archive record exceeds the configured compression ratio",
                owner=owner,
                storedLength=stored,
                expandedLength=expanded,
                limit=self.limits.max_compression_ratio,
            )
        if self.total_expanded + expanded > self.limits.max_total_expanded_bytes:
            reject(
                "TOTAL_EXPANDED_BYTES_LIMIT",
                "Recursive audit exceeds the configured expanded-byte budget",
                total=self.total_expanded + expanded,
                limit=self.limits.max_total_expanded_bytes,
            )

    def charge_expansion(self, expanded, stored, owner):
        self.check_expansion(expanded, stored, owner)
        self.total_expanded += expanded

    def remaining_expansion(self):
        return self.limits.max_total_expanded_bytes - self.total_expanded


def member_record(
    ordinal,
    header_offset,
    header_length,
    data_offset,
    stored_length,
    expanded_length,
    raw_name,
    logical_path,
    member_type,
    content,
    owner,
    link_target=None,
):
    return {
        "ordinal": ordinal,
        "headerOffset": header_offset,
        "headerLength": header_length,
        "dataOffset": data_offset,
        "storedLength": stored_length,
        "expandedLength": expanded_length,
        "rawPath": raw_name,
        "logicalPath": logical_path,
        "type": member_type,
        "linkTarget": link_target,
        "contentSha256": sha256(content),
        "ownerDisposition": owner,
        "nestedArchiveIdentity": None,
        "_content": content,
    }


class BinaryReader:
    def __init__(self, data, absolute_base=0):
        self.data = data
        self.pos = 0
        self.absolute_base = absolute_base

    def remaining(self):
        return len(self.data) - self.pos

    def absolute(self):
        return self.absolute_base + self.pos

    def read(self, length):
        value = checked_slice(self.data, self.pos, length)
        self.pos += length
        return value

    def byte(self):
        return self.read(1)[0]

    def uint32(self):
        return struct.unpack("<I", self.read(4))[0]

    def uint64_real(self):
        return struct.unpack("<Q", self.read(8))[0]

    def uint64(self):
        first = self.byte()
        mask = 0x80
        value = 0
        for extra in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * extra))
            value |= self.byte() << (8 * extra)
            mask >>= 1
        return value

    def require_end(self, code="TRAILING_HEADER_PAYLOAD"):
        if self.remaining():
            reject(code, "Structured archive header has undeclared trailing bytes", offset=self.absolute(), length=self.remaining())


def read_bit_vector(reader, count):
    result = []
    mask = 0
    current = 0
    for _ in range(count):
        if not mask:
            current = reader.byte()
            mask = 0x80
        result.append(bool(current & mask))
        mask >>= 1
    return result


class ArchiveAuditor:
    def __init__(self, limits=None):
        self.limits = limits or Limits()
        self._validate_limits()
        self.state = AuditState(self.limits)

    def _validate_limits(self):
        integer_limits = {
            "maxTotalExpandedBytes": self.limits.max_total_expanded_bytes,
            "maxMembersPerArchive": self.limits.max_members_per_archive,
            "maxMembersTotal": self.limits.max_members_total,
            "maxPathLength": self.limits.max_path_length,
        }
        if not isinstance(self.limits.max_depth, int) or not 0 <= self.limits.max_depth <= 128:
            reject("INVALID_LIMIT", "maxDepth must be an integer between 0 and 128")
        for name, value in integer_limits.items():
            if not isinstance(value, int) or value <= 0:
                reject("INVALID_LIMIT", f"{name} must be a positive integer")
        if (
            not isinstance(self.limits.max_compression_ratio, (int, float))
            or not math.isfinite(self.limits.max_compression_ratio)
            or self.limits.max_compression_ratio <= 0
        ):
            reject("INVALID_LIMIT", "maxCompressionRatio must be a positive finite number")

    def audit_path(self, path):
        size = os.path.getsize(path)
        if size > self.limits.max_total_expanded_bytes:
            reject(
                "TOTAL_EXPANDED_BYTES_LIMIT",
                "Input archive alone exceeds the configured byte budget",
                length=size,
                limit=self.limits.max_total_expanded_bytes,
            )
        with open(path, "rb") as handle:
            data = handle.read()
        if len(data) > self.limits.max_total_expanded_bytes:
            reject(
                "TOTAL_EXPANDED_BYTES_LIMIT",
                "Input archive changed while being read and exceeds the configured byte budget",
                length=len(data),
                limit=self.limits.max_total_expanded_bytes,
            )
        archive = self._audit_bytes(data, os.path.basename(path), None, 0, [])
        return {
            "schema": SCHEMA,
            "source": {
                "name": os.path.basename(path),
                "length": len(data),
                "sha256": sha256(data),
            },
            "limits": self.limits.manifest(),
            "totals": {
                "members": self.state.total_members,
                "expandedBytes": self.state.total_expanded,
            },
            "archive": archive,
        }

    def audit_bytes(self, data, name="archive"):
        if len(data) > self.limits.max_total_expanded_bytes:
            reject(
                "TOTAL_EXPANDED_BYTES_LIMIT",
                "Input archive alone exceeds the configured byte budget",
                length=len(data),
                limit=self.limits.max_total_expanded_bytes,
            )
        archive = self._audit_bytes(data, name, None, 0, [])
        return {
            "schema": SCHEMA,
            "source": {
                "name": name,
                "length": len(data),
                "sha256": sha256(data),
            },
            "limits": self.limits.manifest(),
            "totals": {
                "members": self.state.total_members,
                "expandedBytes": self.state.total_expanded,
            },
            "archive": archive,
        }

    def _audit_bytes(self, data, name, parent, depth, chain):
        if depth > self.limits.max_depth:
            reject(
                "RECURSION_DEPTH_LIMIT",
                "Nested archive exceeds the configured recursion depth",
                depth=depth,
                limit=self.limits.max_depth,
                name=name,
            )
        identity = "sha256:" + sha256(data)
        if identity in chain:
            reject("ARCHIVE_CYCLE", "Nested archive repeats an ancestor byte identity", identity=identity)

        detected, signature_offset = detect_format(
            data,
            self._tar_recognition_member_limit(),
        )
        archive_format = detected
        if not archive_format:
            reject("UNRECOGNIZED_ARCHIVE", "Input is not a supported archive format")

        node = {
            "identity": identity,
            "parent": parent,
            "archiveChain": chain + [identity],
            "format": archive_format,
            "headerOffset": signature_offset,
            "dataOffset": signature_offset,
            "storedLength": len(data),
            "expandedLength": len(data),
            "members": [],
        }
        if archive_format == "zip":
            self._parse_zip(data, node)
        elif archive_format == "tar":
            self._parse_tar(data, node)
        elif archive_format in ("gzip", "bzip2", "xz", "zstd"):
            self._parse_wrapper(data, node, archive_format)
        elif archive_format == "7z":
            self._parse_7z(data, node, signature_offset)
        else:
            reject("UNSUPPORTED_ARCHIVE_FORMAT", "Archive format is recognized but unsupported", format=archive_format)

        self._attach_nested(node, depth, chain + [identity])
        return node

    def _attach_nested(self, node, depth, chain):
        for member in node["members"]:
            content = member.pop("_content", b"")
            nested_name = member.pop("_nestedName", member["logicalPath"] or "")
            if member["type"] != "file":
                continue
            nested_detected, _ = detect_format(
                content,
                self._tar_recognition_member_limit(),
            )
            if not nested_detected:
                continue
            parent = {
                "archiveIdentity": node["identity"],
                "memberOrdinal": member["ordinal"],
                "logicalPath": member["logicalPath"],
            }
            nested = self._audit_bytes(content, nested_name, parent, depth + 1, chain)
            member["nestedArchiveIdentity"] = nested["identity"]
            member["nestedArchive"] = nested

    def _tar_recognition_member_limit(self):
        return max(
            0,
            min(
                self.limits.max_members_per_archive,
                self.limits.max_members_total - self.state.total_members,
            ),
        )

    def _check_links(self, members):
        by_path = {
            member["logicalPath"]: member
            for member in members
            if member["logicalPath"] is not None and member["type"] not in ("metadata",)
        }
        for member in members:
            target = member["linkTarget"]
            if target is not None and target not in by_path:
                reject(
                    "UNDECLARED_LINK_TARGET",
                    "Link target is not a declared archive member",
                    path=member["logicalPath"],
                    target=target,
                )

        graph = {
            member["logicalPath"]: member["linkTarget"]
            for member in members
            if member["linkTarget"] is not None
        }
        visited = set()
        for start in graph:
            if start in visited:
                continue
            path = start
            chain = []
            chain_positions = {}
            while path in graph and path not in visited:
                if path in chain_positions:
                    reject("LINK_CYCLE", "Archive links form a cycle", path=path)
                chain_positions[path] = len(chain)
                chain.append(path)
                path = graph[path]
            visited.update(chain)

    def _parse_zip(self, data, node):
        candidates = []
        start = max(0, len(data) - 65557)
        cursor = start
        while True:
            cursor = data.find(b"PK\x05\x06", cursor)
            if cursor < 0:
                break
            if cursor + 22 <= len(data):
                comment_length = u16(data, cursor + 20)
                if cursor + 22 + comment_length == len(data):
                    candidates.append(cursor)
            cursor += 1
        if len(candidates) != 1:
            reject(
                "AMBIGUOUS_ZIP_EOCD" if candidates else "INVALID_ZIP_EOCD",
                "ZIP must contain exactly one terminal end-of-central-directory record",
                candidates=len(candidates),
            )
        eocd = candidates[0]
        disk, central_disk, disk_entries, total_entries = struct.unpack_from("<4H", data, eocd + 4)
        central_size, central_offset = struct.unpack_from("<2I", data, eocd + 12)
        comment_length = u16(data, eocd + 20)
        if any((disk, central_disk)) or disk_entries != total_entries:
            reject("UNSUPPORTED_MULTIVOLUME_ZIP", "Multi-volume ZIP archives are unsupported")
        if total_entries == 0xffff or central_size == 0xffffffff or central_offset == 0xffffffff:
            reject("UNSUPPORTED_ZIP64", "ZIP64 archives are unsupported")
        if total_entries > self.limits.max_members_per_archive:
            reject(
                "MEMBERS_PER_ARCHIVE_LIMIT",
                "ZIP entry count exceeds the configured member limit",
                count=total_entries,
                limit=self.limits.max_members_per_archive,
            )
        if self.state.total_members + total_entries > self.limits.max_members_total:
            reject(
                "GLOBAL_MEMBER_LIMIT",
                "ZIP entry count exceeds the remaining global member limit",
                count=self.state.total_members + total_entries,
                limit=self.limits.max_members_total,
            )
        if comment_length:
            reject("UNSUPPORTED_ZIP_COMMENT", "ZIP archive comments are rejected as ambiguous metadata")
        if central_offset + central_size != eocd:
            reject(
                "UNDECLARED_ZIP_PAYLOAD",
                "ZIP central directory does not end exactly at EOCD",
                centralOffset=central_offset,
                centralSize=central_size,
                eocdOffset=eocd,
            )

        entries = []
        cursor = central_offset
        central_end = central_offset + central_size
        for central_ordinal in range(total_entries):
            if checked_slice(data, cursor, 4) != b"PK\x01\x02":
                reject("INVALID_ZIP_CENTRAL_HEADER", "ZIP central-directory signature is invalid", offset=cursor)
            fixed_header = checked_slice(data, cursor, 46)
            fields = struct.unpack_from("<6H3I5H2I", fixed_header, 4)
            (
                version_made,
                version_needed,
                flags,
                method,
                mod_time,
                mod_date,
                crc,
                compressed_size,
                expanded_size,
                name_length,
                extra_length,
                entry_comment_length,
                start_disk,
                internal_attributes,
                external_attributes,
                local_offset,
            ) = fields
            length = 46 + name_length + extra_length + entry_comment_length
            block = checked_slice(data, cursor, length)
            name_raw = block[46:46 + name_length]
            extra = block[46 + name_length:46 + name_length + extra_length]
            comment = block[46 + name_length + extra_length:]
            self._validate_zip_entry(flags, method, version_needed, extra, comment, start_disk)
            entries.append({
                "centralOrdinal": central_ordinal,
                "centralOffset": cursor,
                "centralLength": length,
                "versionMade": version_made,
                "versionNeeded": version_needed,
                "flags": flags,
                "method": method,
                "modTime": mod_time,
                "modDate": mod_date,
                "crc": crc,
                "compressedSize": compressed_size,
                "expandedSize": expanded_size,
                "nameRaw": name_raw,
                "externalAttributes": external_attributes,
                "internalAttributes": internal_attributes,
                "localOffset": local_offset,
                "extraIds": self._zip_extra_ids(extra),
            })
            cursor += length
        if cursor != central_end:
            reject(
                "CENTRAL_DIRECTORY_LENGTH_MISMATCH",
                "ZIP central-directory size does not match its physical records",
                declaredEnd=central_end,
                parsedEnd=cursor,
            )

        local_offsets = [entry["localOffset"] for entry in entries]
        if len(set(local_offsets)) != len(local_offsets):
            reject("OVERLAPPING_ZIP_RECORDS", "Multiple central entries point at the same local record")
        entries.sort(key=lambda entry: entry["localOffset"])
        if entries and entries[0]["localOffset"] != 0:
            reject("UNDECLARED_ZIP_PREFIX", "ZIP has undeclared bytes before its first local record")
        if not entries and central_offset != 0:
            reject("UNDECLARED_ZIP_PREFIX", "Empty ZIP has undeclared bytes before its central directory")

        registry = PathRegistry()
        members = []
        expected_offset = 0
        archive_count = 0
        for ordinal, entry in enumerate(entries):
            offset = entry["localOffset"]
            if offset != expected_offset:
                reject(
                    "OVERLAPPING_OR_GAPPED_ZIP_RECORDS",
                    "ZIP local records are overlapping or separated by undeclared bytes",
                    expectedOffset=expected_offset,
                    actualOffset=offset,
                )
            if checked_slice(data, offset, 4) != b"PK\x03\x04":
                reject("INVALID_ZIP_LOCAL_HEADER", "ZIP local-header signature is invalid", offset=offset)
            (
                version_needed,
                flags,
                method,
                mod_time,
                mod_date,
                local_crc,
                local_compressed,
                local_expanded,
                name_length,
                extra_length,
            ) = struct.unpack_from("<5H3I2H", data, offset + 4)
            header_length = 30 + name_length + extra_length
            header = checked_slice(data, offset, header_length)
            local_name = header[30:30 + name_length]
            local_extra = header[30 + name_length:]
            self._validate_zip_entry(flags, method, version_needed, local_extra, b"", 0)
            if (
                local_name != entry["nameRaw"]
                or flags != entry["flags"]
                or method != entry["method"]
                or version_needed != entry["versionNeeded"]
                or mod_time != entry["modTime"]
                or mod_date != entry["modDate"]
            ):
                reject("ZIP_HEADER_DISAGREEMENT", "ZIP local and central headers disagree", offset=offset)
            descriptor = bool(flags & 0x0008)
            if not descriptor and (
                local_crc != entry["crc"]
                or local_compressed != entry["compressedSize"]
                or local_expanded != entry["expandedSize"]
            ):
                reject("ZIP_HEADER_DISAGREEMENT", "ZIP local sizes or checksum disagree with central metadata", offset=offset)
            if descriptor and any((local_crc, local_compressed, local_expanded)):
                reject("AMBIGUOUS_ZIP_DESCRIPTOR", "Streaming ZIP local sizes must be zero", offset=offset)

            data_offset = offset + header_length
            compressed = checked_slice(data, data_offset, entry["compressedSize"])
            expanded = self._inflate_zip(compressed, method, entry["expandedSize"], entry["nameRaw"])
            if zlib.crc32(expanded) & 0xffffffff != entry["crc"]:
                reject("ZIP_CRC_MISMATCH", "ZIP member checksum is invalid", ordinal=ordinal)
            descriptor_length = 0
            end = data_offset + entry["compressedSize"]
            if descriptor:
                if checked_slice(data, end, 4) == b"PK\x07\x08":
                    descriptor_length = 16
                    values = struct.unpack_from("<3I", checked_slice(data, end + 4, 12))
                else:
                    descriptor_length = 12
                    values = struct.unpack_from("<3I", checked_slice(data, end, 12))
                if values != (entry["crc"], entry["compressedSize"], entry["expandedSize"]):
                    reject("ZIP_DESCRIPTOR_MISMATCH", "ZIP data descriptor disagrees with central metadata", offset=end)
                end += descriptor_length
            expected_offset = end

            encoding = "utf-8" if flags & 0x0800 else "cp437"
            text = strict_decode(entry["nameRaw"], encoding)
            unix_mode = (entry["externalAttributes"] >> 16) & 0xffff
            dos_attributes = entry["externalAttributes"] & 0xffff
            if dos_attributes & 0x0400:
                reject("UNSAFE_REPARSE_POINT", "ZIP member carries the Windows reparse-point attribute", path=text)
            file_type = unix_mode & 0o170000
            is_directory = text.endswith("/") or file_type == 0o040000 or bool(dos_attributes & 0x10)
            is_symlink = file_type == 0o120000
            if is_symlink and is_directory:
                reject("AMBIGUOUS_MEMBER_TYPE", "ZIP member is both a directory and symlink", path=text)
            logical = normalize_path(text, is_directory, self.limits.max_path_length)
            registry.add(entry["nameRaw"], logical, ordinal)
            link_target = None
            member_type = "directory" if is_directory else "symlink" if is_symlink else "file"
            content = expanded
            if is_directory and expanded:
                reject("DIRECTORY_WITH_DATA", "ZIP directory carries file data", path=logical)
            if is_symlink:
                target_text = strict_decode(expanded, "utf-8", "INVALID_LINK_ENCODING")
                link_target = normalize_link_target(logical, target_text, self.limits.max_path_length)
                content = expanded

            self.state.charge_expansion(len(expanded), len(compressed), f"zip:{logical}")
            archive_count = self.state.add_member(archive_count)
            members.append(member_record(
                ordinal,
                offset,
                header_length,
                data_offset,
                len(compressed),
                len(expanded),
                raw_path(entry["nameRaw"], text, encoding),
                logical,
                member_type,
                content,
                {
                    "centralDirectoryOffset": entry["centralOffset"],
                    "centralDirectoryLength": entry["centralLength"],
                    "centralDirectoryOrdinal": entry["centralOrdinal"],
                    "compressionMethod": method,
                    "crc32": f"{entry['crc']:08x}",
                    "dataDescriptorLength": descriptor_length,
                    "versionMadeBy": entry["versionMade"],
                    "versionNeeded": entry["versionNeeded"],
                    "externalAttributes": f"{entry['externalAttributes']:08x}",
                    "internalAttributes": f"{entry['internalAttributes']:04x}",
                    "unixMode": f"{unix_mode:06o}",
                    "dosAttributes": f"{dos_attributes:04x}",
                    "extraFieldIds": entry["extraIds"],
                },
                link_target,
            ))
        if expected_offset != central_offset:
            reject(
                "UNDECLARED_ZIP_PAYLOAD",
                "ZIP local record area does not end at its central directory",
                localEnd=expected_offset,
                centralOffset=central_offset,
            )
        self._check_links(members)
        node["dataOffset"] = 0
        node["members"] = members
        node["ownerDisposition"] = {
            "centralDirectoryOffset": central_offset,
            "centralDirectoryLength": central_size,
            "endOfCentralDirectoryOffset": eocd,
        }

    def _zip_extra_ids(self, extra):
        ids = []
        cursor = 0
        while cursor < len(extra):
            if cursor + 4 > len(extra):
                reject("INVALID_ZIP_EXTRA_FIELD", "ZIP extra-field header is truncated")
            field_id, length = struct.unpack_from("<2H", extra, cursor)
            cursor += 4
            checked_slice(extra, cursor, length)
            if field_id == 0x0001:
                reject("UNSUPPORTED_ZIP64", "ZIP64 extra fields are unsupported")
            if field_id in (0x7075, 0x6375):
                reject("AMBIGUOUS_ZIP_ENCODING", "Unicode ZIP shadow-name extra fields are rejected")
            if field_id == 0x9901:
                reject("UNSUPPORTED_ZIP_ENCRYPTION", "AES-encrypted ZIP entries are unsupported")
            ids.append(f"{field_id:04x}")
            cursor += length
        return ids

    def _validate_zip_entry(self, flags, method, version_needed, extra, comment, start_disk):
        if flags & 0x0001 or flags & 0x0040 or flags & 0x2000:
            reject("UNSUPPORTED_ZIP_ENCRYPTION", "Encrypted ZIP entries are unsupported")
        allowed = 0x0808
        if method == 8:
            allowed |= 0x0006
        if flags & ~allowed:
            reject("UNSUPPORTED_ZIP_FLAGS", "ZIP entry uses unsupported general-purpose flags", flags=f"{flags:04x}")
        if method not in (0, 8):
            reject("UNSUPPORTED_ZIP_COMPRESSION", "ZIP compression method is unsupported", method=method)
        if version_needed > 63:
            reject("UNSUPPORTED_ZIP_VERSION", "ZIP entry requires an unsupported extractor version", version=version_needed)
        if start_disk:
            reject("UNSUPPORTED_MULTIVOLUME_ZIP", "ZIP entry starts on another volume")
        if comment:
            reject("UNSUPPORTED_ZIP_COMMENT", "ZIP per-entry comments are rejected as ambiguous metadata")
        self._zip_extra_ids(extra)

    def _inflate_zip(self, compressed, method, expected_size, name):
        self.state.check_expansion(expected_size, len(compressed), f"zip:{name.hex()}")
        if method == 0:
            if len(compressed) != expected_size:
                reject("ZIP_LENGTH_MISMATCH", "Stored ZIP member length disagrees with expanded length", rawPathHex=name.hex())
            return compressed
        maximum = min(expected_size, self.state.remaining_expansion()) + 1
        try:
            decoder = zlib.decompressobj(-15)
            expanded = decoder.decompress(compressed, maximum)
        except zlib.error as exc:
            reject("INVALID_ZIP_DEFLATE", "ZIP deflate stream is invalid", reason=str(exc))
        if len(expanded) != expected_size:
            reject(
                "ZIP_LENGTH_MISMATCH",
                "ZIP expanded length disagrees with central metadata",
                expected=expected_size,
                actual=len(expanded),
            )
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            reject("TRAILING_COMPRESSED_PAYLOAD", "ZIP deflate stream has trailing or unconsumed bytes")
        return expanded

    def _parse_tar(self, data, node):
        cursor = 0
        ordinal = 0
        archive_count = 0
        members = []
        registry = PathRegistry()
        global_pax = {}
        pending_pax = None
        pending_long_name = None
        pending_long_link = None
        prior_by_path = {}
        zero_start = None

        while cursor < len(data):
            header = checked_slice(data, cursor, 512)
            if not any(header):
                if cursor + 1024 > len(data) or any(checked_slice(data, cursor + 512, 512)):
                    reject("INVALID_TAR_TERMINATOR", "TAR must end with at least two zero blocks", offset=cursor)
                zero_start = cursor
                if any(data[cursor:]):
                    reject("TRAILING_TAR_PAYLOAD", "TAR has nonzero bytes after its terminator", offset=cursor)
                if (len(data) - cursor) % 512:
                    reject("TRAILING_TAR_PAYLOAD", "TAR trailing zero padding is not block-aligned", offset=cursor)
                break

            validate_tar_flavor(header, cursor)

            stored_checksum = parse_tar_number(header[148:156], "checksum")
            checksum_header = bytearray(header)
            checksum_header[148:156] = b"        "
            unsigned_checksum = sum(checksum_header)
            signed_checksum = sum(byte if byte < 128 else byte - 256 for byte in checksum_header)
            if stored_checksum not in (unsigned_checksum, signed_checksum):
                reject(
                    "TAR_CHECKSUM_MISMATCH",
                    "TAR header checksum is invalid",
                    offset=cursor,
                    expected=stored_checksum,
                    unsigned=unsigned_checksum,
                    signed=signed_checksum,
                )

            name_bytes, name_text = terminated_field(header[0:100])
            prefix_bytes, prefix_text = terminated_field(header[345:500])
            header_name_bytes = (prefix_bytes + (b"/" if prefix_bytes and name_bytes else b"") + name_bytes)
            header_name_text = prefix_text + ("/" if prefix_text and name_text else "") + name_text
            typeflag = header[156:157]
            header_size = parse_tar_number(header[124:136], "size")
            metadata_type = typeflag in (b"x", b"g", b"L", b"K")
            if metadata_type and pending_pax is not None:
                reject(
                    "AMBIGUOUS_TAR_METADATA",
                    "A local PAX header cannot describe another metadata record",
                    offset=cursor,
                )
            effective_size = header_size
            if not metadata_type and pending_pax and "size" in pending_pax:
                effective_size = parse_decimal(pending_pax["size"], "pax size")
            data_offset = cursor + 512
            self.state.check_expansion(
                effective_size,
                effective_size,
                f"tar-record:{ordinal}",
            )
            content = checked_slice(data, data_offset, effective_size)
            padded = (effective_size + 511) & ~511
            padding = checked_slice(data, data_offset + effective_size, padded - effective_size)
            if any(padding):
                reject("NONZERO_TAR_PADDING", "TAR member data padding contains nonzero bytes", offset=data_offset + effective_size)
            next_offset = data_offset + padded

            if metadata_type:
                archive_count = self.state.add_member(archive_count)
                self.state.charge_expansion(len(content), len(content), f"tar-metadata:{ordinal}")
                kind = {
                    b"x": "pax-local",
                    b"g": "pax-global",
                    b"L": "gnu-long-name",
                    b"K": "gnu-long-link",
                }[typeflag]
                members.append(member_record(
                    ordinal,
                    cursor,
                    512,
                    data_offset,
                    len(content),
                    len(content),
                    raw_path(header_name_bytes, header_name_text, "utf-8"),
                    None,
                    "metadata",
                    content,
                    {
                        "metadataType": kind,
                        "headerTypeFlag": typeflag.hex(),
                        "headerSize": header_size,
                    },
                ))
                if typeflag in (b"x", b"g"):
                    parsed = parse_pax(content)
                    if typeflag == b"g":
                        if pending_pax is not None:
                            reject("AMBIGUOUS_TAR_METADATA", "Global PAX header appears while local metadata is pending")
                        structural = sorted(set(parsed) & {"path", "linkpath", "size"})
                        if structural:
                            reject(
                                "UNSUPPORTED_TAR_EXTENSION",
                                "Global PAX header contains a structural key",
                                keys=structural,
                            )
                        global_pax.update(parsed)
                    else:
                        if pending_pax is not None:
                            reject("AMBIGUOUS_TAR_METADATA", "Multiple local PAX headers precede one member")
                        pending_pax = parsed
                else:
                    value = content[:-1] if content.endswith(b"\0") else content
                    if b"\0" in value:
                        reject("AMBIGUOUS_HEADER_ENCODING", "GNU TAR long-name record contains an embedded NUL")
                    text = strict_decode(value, "utf-8")
                    if typeflag == b"L":
                        if pending_long_name is not None:
                            reject("AMBIGUOUS_TAR_METADATA", "Multiple GNU long-name records precede one member")
                        pending_long_name = (value, text)
                    else:
                        if pending_long_link is not None:
                            reject("AMBIGUOUS_TAR_METADATA", "Multiple GNU long-link records precede one member")
                        pending_long_link = (value, text)
                cursor = next_offset
                ordinal += 1
                continue

            pax = dict(global_pax)
            if pending_pax:
                pax.update(pending_pax)
            if pending_long_name and "path" in pax:
                reject("AMBIGUOUS_TAR_METADATA", "GNU long name and PAX path both override one member")
            if pending_long_link and "linkpath" in pax:
                reject("AMBIGUOUS_TAR_METADATA", "GNU long link and PAX linkpath both override one member")

            effective_name_bytes = header_name_bytes
            effective_name_text = header_name_text
            path_source = "header"
            if pending_long_name:
                effective_name_bytes, effective_name_text = pending_long_name
                path_source = "gnu-long-name"
            if "path" in pax:
                effective_name_text = pax["path"]
                effective_name_bytes = effective_name_text.encode("utf-8")
                path_source = "pax"

            link_bytes, link_text = terminated_field(header[157:257])
            if pending_long_link:
                link_bytes, link_text = pending_long_link
            if "linkpath" in pax:
                link_text = pax["linkpath"]
                link_bytes = link_text.encode("utf-8")

            if typeflag in (b"\0", b"0", b"7"):
                member_type = "file"
                is_directory = False
            elif typeflag == b"5":
                member_type = "directory"
                is_directory = True
            elif typeflag == b"2":
                member_type = "symlink"
                is_directory = False
            elif typeflag == b"1":
                member_type = "hardlink"
                is_directory = False
            else:
                reject(
                    "UNSUPPORTED_TAR_MEMBER_TYPE",
                    "TAR member type is unsupported",
                    offset=cursor,
                    typeFlag=typeflag.hex(),
                )
            logical = normalize_path(effective_name_text, is_directory, self.limits.max_path_length)
            registry.add(effective_name_bytes, logical, ordinal)
            link_target = None
            if member_type in ("directory", "symlink", "hardlink") and effective_size:
                reject("LINK_OR_DIRECTORY_WITH_DATA", "TAR link or directory carries file data", path=logical)
            if member_type == "symlink":
                link_target = normalize_link_target(logical, link_text, self.limits.max_path_length)
            elif member_type == "hardlink":
                link_target = normalize_link_target(
                    logical,
                    link_text,
                    self.limits.max_path_length,
                    root_relative=True,
                )
                prior = prior_by_path.get(link_target)
                if prior is None or prior["type"] not in ("file", "hardlink"):
                    reject(
                        "UNSAFE_HARDLINK_TARGET",
                        "TAR hardlink must target a preceding regular file",
                        path=logical,
                        target=link_target,
                    )

            mode = pax.get("mode", str(parse_tar_number(header[100:108], "mode")))
            uid = pax.get("uid", str(parse_tar_number(header[108:116], "uid")))
            gid = pax.get("gid", str(parse_tar_number(header[116:124], "gid")))
            uname_bytes, uname = terminated_field(header[265:297])
            gname_bytes, gname = terminated_field(header[297:329])
            del uname_bytes, gname_bytes
            uname = pax.get("uname", uname)
            gname = pax.get("gname", gname)
            self.state.charge_expansion(len(content), len(content), f"tar:{logical}")
            archive_count = self.state.add_member(archive_count)
            members.append(member_record(
                ordinal,
                cursor,
                512,
                data_offset,
                len(content),
                len(content),
                raw_path(
                    effective_name_bytes,
                    effective_name_text,
                    "utf-8",
                    source=path_source,
                    headerHex=header_name_bytes.hex(),
                ),
                logical,
                member_type,
                content,
                {
                    "headerTypeFlag": typeflag.hex(),
                    "headerSize": header_size,
                    "mode": mode,
                    "uid": uid,
                    "gid": gid,
                    "userName": uname,
                    "groupName": gname,
                    "pax": {key: pax[key] for key in sorted(pax)},
                },
                link_target,
            ))
            prior_by_path[logical] = members[-1]
            pending_pax = None
            pending_long_name = None
            pending_long_link = None
            cursor = next_offset
            ordinal += 1

        if zero_start is None:
            reject("MISSING_TAR_TERMINATOR", "TAR has no terminal zero blocks")
        if any((pending_pax, pending_long_name, pending_long_link)):
            reject("ORPHAN_TAR_METADATA", "TAR ends with metadata that does not describe a member")
        self._check_links(members)
        node["members"] = members
        node["ownerDisposition"] = {
            "terminalZeroOffset": zero_start,
            "terminalZeroLength": len(data) - zero_start,
        }

    def _parse_wrapper(self, data, node, archive_format):
        if archive_format == "gzip":
            (
                expanded,
                data_offset,
                stored_length,
                owner,
                embedded_name,
                embedded_name_raw,
            ) = self._decode_gzip(data)
        elif archive_format == "bzip2":
            if len(data) < 4 or data[:3] != b"BZh" or data[3:4] not in b"123456789":
                reject("INVALID_BZIP2_HEADER", "bzip2 stream header is invalid")
            expanded, consumed = self._bounded_decompress(bz2.BZ2Decompressor(), data, "bzip2")
            if consumed != len(data):
                self._reject_compressed_tail("bzip2", data[consumed:], consumed)
            data_offset = 4
            stored_length = len(data) - 4
            owner = {"blockSizeDigit": chr(data[3]), "streamEndOffset": consumed}
            embedded_name = None
            embedded_name_raw = None
        elif archive_format == "xz":
            if not data.startswith(XZ_SIGNATURE):
                reject("INVALID_XZ_HEADER", "xz stream header is invalid")
            expanded, consumed = self._bounded_decompress(lzma.LZMADecompressor(format=lzma.FORMAT_XZ), data, "xz")
            if consumed != len(data):
                self._reject_compressed_tail("xz", data[consumed:], consumed)
            if len(data) < 24:
                reject("INVALID_XZ_STREAM", "xz stream is too short")
            data_offset = 12
            stored_length = len(data) - 24
            owner = {
                "streamFlags": data[6:8].hex(),
                "footerOffset": len(data) - 12,
                "streamEndOffset": consumed,
            }
            embedded_name = None
            embedded_name_raw = None
        else:
            if zstd is None:
                reject("UNSUPPORTED_ZSTD_RUNTIME", "Python runtime does not provide compression.zstd")
            data_offset, zstd_owner = parse_zstd_header(data)
            expanded, consumed = self._bounded_decompress(zstd.ZstdDecompressor(), data, "zstd")
            if consumed != len(data):
                self._reject_compressed_tail("zstd", data[consumed:], consumed)
            stored_length = len(data) - data_offset
            owner = dict(zstd_owner, streamEndOffset=consumed)
            embedded_name = None
            embedded_name_raw = None

        payload_name = "payload"
        path_source = "synthetic-wrapper-payload"
        if embedded_name is not None:
            if "/" in embedded_name or "\\" in embedded_name:
                reject(
                    "UNSAFE_PATH",
                    "gzip original-name field contains a directory component",
                    embeddedName=embedded_name,
                )
            payload_name = embedded_name
            path_source = "gzip-header"
        payload_raw = embedded_name_raw if embedded_name_raw is not None else payload_name.encode("utf-8")
        payload_encoding = "latin-1" if embedded_name_raw is not None else "utf-8"
        logical = normalize_path(payload_name, False, self.limits.max_path_length)
        self.state.charge_expansion(len(expanded), max(1, stored_length), f"{archive_format}:{logical}")
        archive_count = self.state.add_member(0)
        del archive_count
        member = member_record(
            0,
            0,
            data_offset,
            data_offset,
            stored_length,
            len(expanded),
            raw_path(payload_raw, payload_name, payload_encoding, source=path_source),
            logical,
            "file",
            expanded,
            dict(owner, compression=archive_format),
        )
        member["_nestedName"] = "payload"
        node["dataOffset"] = data_offset
        node["expandedLength"] = len(expanded)
        node["members"] = [member]
        node["ownerDisposition"] = owner

    def _reject_compressed_tail(self, archive_format, tail, offset):
        signatures = {
            "bzip2": (b"BZh", "CONCATENATED_BZIP2_STREAM", "bzip2 stream"),
            "xz": (XZ_SIGNATURE, "CONCATENATED_XZ_STREAM", "xz stream"),
            "zstd": (ZSTD_SIGNATURE, "CONCATENATED_ZSTD_FRAME", "zstd frame"),
        }
        signature, code, description = signatures[archive_format]
        if tail.startswith(signature):
            reject(
                code,
                f"Only one {description} is accepted",
                offset=offset,
            )
        reject(
            "TRAILING_COMPRESSED_PAYLOAD",
            f"{description} has trailing bytes",
            offset=offset,
        )

    def _bounded_decompress(self, decoder, data, owner):
        remaining = self.state.remaining_expansion()
        ratio_ceiling = int(max(1, len(data)) * self.limits.max_compression_ratio)
        maximum = min(remaining, ratio_ceiling) + 1
        try:
            expanded = decoder.decompress(data, max_length=maximum)
        except (OSError, EOFError, lzma.LZMAError, zstd.ZstdError if zstd else OSError) as exc:
            reject("INVALID_COMPRESSED_STREAM", "Compressed stream is invalid", compression=owner, reason=str(exc))
        if len(expanded) > remaining:
            reject(
                "TOTAL_EXPANDED_BYTES_LIMIT",
                "Compressed stream exceeds the configured expanded-byte budget",
                compression=owner,
                limit=self.limits.max_total_expanded_bytes,
            )
        if len(expanded) > ratio_ceiling:
            reject(
                "COMPRESSION_RATIO_LIMIT",
                "Compressed stream exceeds the configured compression ratio",
                compression=owner,
                storedLength=len(data),
                expandedLengthAtLeast=len(expanded),
                limit=self.limits.max_compression_ratio,
            )
        if not decoder.eof:
            reject("INVALID_COMPRESSED_STREAM", "Compressed stream is truncated", compression=owner)
        unused = decoder.unused_data
        return expanded, len(data) - len(unused)

    def _decode_gzip(self, data):
        if len(data) < 18 or data[:2] != b"\x1f\x8b" or data[2] != 8:
            reject("INVALID_GZIP_HEADER", "gzip header is invalid")
        flags = data[3]
        if flags & 0xe0:
            reject("INVALID_GZIP_FLAGS", "gzip reserved header flags are set", flags=f"{flags:02x}")
        cursor = 10
        if flags & 0x04:
            extra_length = u16(data, cursor)
            cursor += 2
            checked_slice(data, cursor, extra_length)
            cursor += extra_length
        embedded_name = None
        embedded_name_raw = None
        if flags & 0x08:
            end = data.find(b"\0", cursor)
            if end < 0:
                reject("INVALID_GZIP_HEADER", "gzip original-name field is unterminated")
            embedded_name_raw = data[cursor:end]
            embedded_name = strict_decode(
                embedded_name_raw,
                "latin-1",
                "INVALID_GZIP_NAME",
                "gzip original name",
            )
            cursor = end + 1
        comment_raw = None
        if flags & 0x10:
            end = data.find(b"\0", cursor)
            if end < 0:
                reject("INVALID_GZIP_HEADER", "gzip comment field is unterminated")
            comment_raw = data[cursor:end]
            strict_decode(comment_raw, "latin-1", "INVALID_GZIP_COMMENT", "gzip comment")
            cursor = end + 1
        if flags & 0x02:
            expected_header_crc = u16(data, cursor)
            actual_header_crc = zlib.crc32(data[:cursor]) & 0xffff
            if expected_header_crc != actual_header_crc:
                reject("GZIP_HEADER_CRC_MISMATCH", "gzip header checksum is invalid")
            cursor += 2

        decoder = zlib.decompressobj(-15)
        remaining = self.state.remaining_expansion()
        ratio_ceiling = int(max(1, len(data) - cursor - 8) * self.limits.max_compression_ratio)
        maximum = min(remaining, ratio_ceiling) + 1
        try:
            expanded = decoder.decompress(data[cursor:], maximum)
        except zlib.error as exc:
            reject("INVALID_GZIP_DEFLATE", "gzip deflate stream is invalid", reason=str(exc))
        if len(expanded) > remaining:
            reject("TOTAL_EXPANDED_BYTES_LIMIT", "gzip stream exceeds the configured expanded-byte budget")
        if len(expanded) > ratio_ceiling:
            reject(
                "COMPRESSION_RATIO_LIMIT",
                "gzip stream exceeds the configured compression ratio",
                storedLength=max(1, len(data) - cursor - 8),
                expandedLengthAtLeast=len(expanded),
                limit=self.limits.max_compression_ratio,
            )
        if not decoder.eof:
            reject("INVALID_GZIP_DEFLATE", "gzip deflate stream is truncated")
        consumed_deflate = len(data[cursor:]) - len(decoder.unused_data)
        footer_offset = cursor + consumed_deflate
        footer = checked_slice(data, footer_offset, 8)
        if footer_offset + 8 != len(data):
            tail_offset = footer_offset + 8
            if data[tail_offset:].startswith(b"\x1f\x8b"):
                reject(
                    "CONCATENATED_GZIP_MEMBER",
                    "Only one gzip member is accepted",
                    offset=tail_offset,
                )
            reject(
                "TRAILING_COMPRESSED_PAYLOAD",
                "gzip stream has trailing bytes",
                offset=tail_offset,
            )
        expected_crc, expected_size = struct.unpack("<2I", footer)
        if zlib.crc32(expanded) & 0xffffffff != expected_crc:
            reject("GZIP_CRC_MISMATCH", "gzip payload checksum is invalid")
        if len(expanded) & 0xffffffff != expected_size:
            reject("GZIP_LENGTH_MISMATCH", "gzip payload length is invalid", expected=expected_size, actual=len(expanded))
        return (
            expanded,
            cursor,
            consumed_deflate,
            {
                "flags": f"{flags:02x}",
                "mtime": u32(data, 4),
                "extraFlags": data[8],
                "operatingSystem": data[9],
                "embeddedName": embedded_name,
                "embeddedNameHex": embedded_name_raw.hex() if embedded_name_raw is not None else None,
                "commentHex": comment_raw.hex() if comment_raw is not None else None,
                "footerOffset": footer_offset,
                "crc32": f"{expected_crc:08x}",
            },
            embedded_name,
            embedded_name_raw,
        )

    def _parse_7z(self, data, node, signature_offset):
        if signature_offset:
            validate_sfx_pe_prefix(data, signature_offset)
        major, minor, next_start, next_size, next_header = seven_zip_envelope(
            data,
            signature_offset,
        )

        physical_ranges = []
        if next_size == 0:
            streams = None
            files = {"names": []}
            shared_header_offset = next_start
            shared_header_length = 0
            header_disposition = "canonical-empty"
        else:
            header_reader = BinaryReader(next_header, next_start)
            nid = header_reader.byte()
            if nid == 0x17:
                encoded_streams = self._seven_parse_streams(header_reader)
                header_reader.require_end()
                decoded, ranges = self._seven_decode_streams(data, signature_offset, encoded_streams, "encoded-header")
                physical_ranges.extend(ranges)
                if len(decoded) != 1:
                    reject("UNSUPPORTED_7Z_ENCODED_HEADER", "Encoded 7z header must contain exactly one substream")
                decoded_header = decoded[0]["content"]
                main_reader = BinaryReader(decoded_header)
                if main_reader.byte() != 0x01:
                    reject("INVALID_7Z_HEADER", "Decoded 7z header does not begin with kHeader")
                streams, files = self._seven_parse_header(main_reader)
                main_reader.require_end()
                shared_header_offset = ranges[0]["offset"]
                shared_header_length = sum(item["length"] for item in ranges)
                header_disposition = "encoded-shared"
            elif nid == 0x01:
                streams, files = self._seven_parse_header(header_reader)
                header_reader.require_end()
                shared_header_offset = next_start
                shared_header_length = next_size
                header_disposition = "plain-shared"
            else:
                reject("INVALID_7Z_HEADER", "7z next header has an unsupported top-level identifier", nid=nid)

        decoded_streams = []
        if streams is not None:
            decoded_streams, ranges = self._seven_decode_streams(data, signature_offset, streams, "main")
            physical_ranges.extend(ranges)
        if next_size:
            physical_ranges.append({"offset": next_start, "length": next_size, "owner": "next-header"})
        self._validate_physical_ranges(
            physical_ranges,
            signature_offset + 32,
            len(data),
            "7z",
        )

        names = files["names"]
        empty_streams = files.get("emptyStreams", [False] * len(names))
        empty_files = files.get("emptyFiles", [False] * sum(empty_streams))
        anti = files.get("anti", [False] * sum(empty_streams))
        if any(anti):
            reject("UNSUPPORTED_7Z_ANTI_ITEM", "7z anti-items are unsupported")
        stream_iter = iter(decoded_streams)
        empty_index = 0
        members = []
        registry = PathRegistry()
        archive_count = 0
        for ordinal, (name_raw, name_text) in enumerate(names):
            attributes = files.get("attributes", [None] * len(names))[ordinal]
            windows_attributes = attributes or 0
            if windows_attributes & 0x0400:
                reject("UNSAFE_REPARSE_POINT", "7z member carries the Windows reparse-point attribute", path=name_text)
            unix_mode = (windows_attributes >> 16) & 0xffff
            unix_type = unix_mode & 0o170000
            if unix_type in (0o120000, 0o060000):
                reject("UNSUPPORTED_7Z_LINK", "7z symlink or block-device member is unsupported", path=name_text)

            if empty_streams[ordinal]:
                is_empty_file = empty_files[empty_index]
                empty_index += 1
                is_directory = not is_empty_file
                stream = {
                    "content": b"",
                    "offset": None,
                    "length": 0,
                    "expandedOffset": 0,
                    "folder": None,
                    "substream": None,
                    "shared": False,
                    "crc32": "00000000",
                    "coderMethod": None,
                    "coderProperties": None,
                    "declaredDictionarySize": None,
                    "effectiveDictionarySize": None,
                }
            else:
                try:
                    stream = next(stream_iter)
                except StopIteration:
                    reject("SEVEN_ZIP_STREAM_COUNT_MISMATCH", "7z has fewer data streams than files")
                is_directory = bool(windows_attributes & 0x10) or unix_type == 0o040000
                if is_directory:
                    reject("DIRECTORY_WITH_DATA", "7z directory carries file data", path=name_text)
            logical = normalize_path(name_text, is_directory, self.limits.max_path_length)
            registry.add(name_raw, logical, ordinal)
            content = stream["content"]
            archive_count = self.state.add_member(archive_count)
            members.append(member_record(
                ordinal,
                shared_header_offset,
                shared_header_length,
                stream["offset"],
                stream["length"],
                len(content),
                raw_path(name_raw, name_text, "utf-16-le"),
                logical,
                "directory" if is_directory else "file",
                content,
                {
                    "headerDisposition": header_disposition,
                    "storageDisposition": (
                        "none"
                        if stream["offset"] is None
                        else "shared-solid-folder"
                        if stream["shared"]
                        else "exclusive"
                    ),
                    "folderOrdinal": stream["folder"],
                    "substreamOrdinal": stream["substream"],
                    "expandedOffset": stream["expandedOffset"],
                    "crc32": stream["crc32"],
                    "coderMethod": stream["coderMethod"],
                    "coderProperties": stream["coderProperties"],
                    "declaredDictionarySize": stream["declaredDictionarySize"],
                    "effectiveDictionarySize": stream["effectiveDictionarySize"],
                    "windowsAttributes": f"{windows_attributes:08x}",
                    "unixMode": f"{unix_mode:06o}",
                    "creationTime": files.get("creationTimes", [None] * len(names))[ordinal],
                    "accessTime": files.get("accessTimes", [None] * len(names))[ordinal],
                    "modificationTime": files.get("modificationTimes", [None] * len(names))[ordinal],
                },
            ))
        try:
            next(stream_iter)
            reject("SEVEN_ZIP_STREAM_COUNT_MISMATCH", "7z has more data streams than files")
        except StopIteration:
            pass

        node["format"] = "7z-sfx" if signature_offset else "7z"
        node["headerOffset"] = signature_offset
        node["dataOffset"] = signature_offset + 32
        node["members"] = members
        node["ownerDisposition"] = {
            "archiveVersion": f"{major}.{minor}",
            "signatureOffset": signature_offset,
            "sfxPrefixLength": signature_offset,
            "sfxPrefixSha256": sha256(data[:signature_offset]) if signature_offset else None,
            "nextHeaderOffset": next_start,
            "nextHeaderLength": next_size,
            "nextHeaderDisposition": header_disposition,
        }

    def _seven_parse_header(self, reader):
        streams = None
        files = None
        seen = set()
        while True:
            nid = reader.byte()
            if nid == 0x00:
                break
            if nid in seen:
                reject("DUPLICATE_7Z_HEADER_SECTION", "7z header section is repeated", nid=nid)
            seen.add(nid)
            if nid == 0x02:
                self._seven_archive_properties(reader)
            elif nid == 0x03:
                reject("UNSUPPORTED_7Z_ADDITIONAL_STREAMS", "7z additional streams are unsupported")
            elif nid == 0x04:
                streams = self._seven_parse_streams(reader)
            elif nid == 0x05:
                files = self._seven_parse_files(reader)
            else:
                reject("UNSUPPORTED_7Z_HEADER_SECTION", "7z header section is unsupported", nid=nid)
        if files is None:
            reject("MISSING_7Z_FILES_INFO", "7z header does not declare its files")
        return streams, files

    def _seven_archive_properties(self, reader):
        while True:
            prop = reader.byte()
            if prop == 0:
                return
            size = reader.uint64()
            payload = reader.read(size)
            if prop != 0x19 or any(payload):
                reject("UNSUPPORTED_7Z_ARCHIVE_PROPERTY", "7z archive property is unsupported", property=prop)

    def _seven_parse_streams(self, reader):
        pack = None
        folders = None
        substreams = None
        while True:
            nid = reader.byte()
            if nid == 0:
                break
            if nid == 0x06:
                if pack is not None:
                    reject("DUPLICATE_7Z_STREAM_SECTION", "7z PackInfo section is repeated")
                pack = self._seven_pack_info(reader)
            elif nid == 0x07:
                if folders is not None:
                    reject("DUPLICATE_7Z_STREAM_SECTION", "7z UnPackInfo section is repeated")
                folders = self._seven_unpack_info(reader)
            elif nid == 0x08:
                if folders is None:
                    reject("INVALID_7Z_STREAM_ORDER", "7z SubStreamsInfo precedes UnPackInfo")
                if substreams is not None:
                    reject("DUPLICATE_7Z_STREAM_SECTION", "7z SubStreamsInfo section is repeated")
                substreams = self._seven_substreams_info(reader, folders)
            else:
                reject("UNSUPPORTED_7Z_STREAM_SECTION", "7z stream section is unsupported", nid=nid)
        if pack is None or folders is None:
            reject("INCOMPLETE_7Z_STREAMS_INFO", "7z streams info lacks PackInfo or UnPackInfo")
        if substreams is None:
            substreams = self._seven_default_substreams(folders)
        return {"pack": pack, "folders": folders, "substreams": substreams}

    def _seven_pack_info(self, reader):
        pack_pos = reader.uint64()
        count = reader.uint64()
        if count > self.limits.max_members_per_archive:
            reject("MEMBERS_PER_ARCHIVE_LIMIT", "7z pack-stream count exceeds the configured limit", count=count)
        sizes = None
        crcs = [None] * count
        while True:
            nid = reader.byte()
            if nid == 0:
                break
            if nid == 0x09:
                if sizes is not None:
                    reject("DUPLICATE_7Z_PROPERTY", "7z pack sizes are repeated")
                sizes = [reader.uint64() for _ in range(count)]
            elif nid == 0x0a:
                crcs = self._seven_digests(reader, count)
            else:
                reject("UNSUPPORTED_7Z_PACK_PROPERTY", "7z PackInfo property is unsupported", nid=nid)
        if sizes is None:
            reject("MISSING_7Z_PACK_SIZES", "7z PackInfo omits packed sizes")
        return {"position": pack_pos, "sizes": sizes, "crcs": crcs}

    def _seven_unpack_info(self, reader):
        if reader.byte() != 0x0b:
            reject("INVALID_7Z_UNPACK_INFO", "7z UnPackInfo omits Folder records")
        count = reader.uint64()
        if count > self.limits.max_members_per_archive:
            reject("MEMBERS_PER_ARCHIVE_LIMIT", "7z folder count exceeds the configured limit", count=count)
        if reader.byte() != 0:
            reject("UNSUPPORTED_7Z_EXTERNAL_PROPERTY", "Externally stored 7z folders are unsupported")
        folders = [self._seven_folder(reader) for _ in range(count)]
        if reader.byte() != 0x0c:
            reject("INVALID_7Z_UNPACK_INFO", "7z UnPackInfo omits coder output sizes")
        for folder in folders:
            folder["unpackSizes"] = [reader.uint64() for _ in range(folder["totalOut"])]
        nid = reader.byte()
        if nid == 0x0a:
            digests = self._seven_digests(reader, count)
            for folder, digest in zip(folders, digests):
                folder["crc"] = digest
            nid = reader.byte()
        if nid != 0:
            reject("INVALID_7Z_UNPACK_INFO", "7z UnPackInfo has an unsupported trailing property", nid=nid)
        return folders

    def _seven_folder(self, reader):
        count = reader.uint64()
        if count == 0 or count > 64:
            reject("UNSUPPORTED_7Z_CODER_GRAPH", "7z folder coder count is unsupported", count=count)
        coders = []
        total_in = 0
        total_out = 0
        for _ in range(count):
            flags = reader.byte()
            if flags & 0xc0:
                reject("UNSUPPORTED_7Z_CODER_FLAGS", "7z coder uses reserved or alternative-method flags", flags=flags)
            method_size = flags & 0x0f
            if not method_size:
                reject("INVALID_7Z_CODER", "7z coder has an empty method identifier")
            method = reader.read(method_size)
            if flags & 0x10:
                num_in = reader.uint64()
                num_out = reader.uint64()
                if not 1 <= num_in <= 64 or not 1 <= num_out <= 64:
                    reject(
                        "UNSUPPORTED_7Z_CODER_GRAPH",
                        "7z complex coder stream counts must be between 1 and 64",
                        inputStreams=num_in,
                        outputStreams=num_out,
                    )
            else:
                num_in = num_out = 1
            properties = reader.read(reader.uint64()) if flags & 0x20 else b""
            coders.append({"method": method, "in": num_in, "out": num_out, "properties": properties})
            total_in += num_in
            total_out += num_out
            if total_in > 64 or total_out > 64:
                reject(
                    "UNSUPPORTED_7Z_CODER_GRAPH",
                    "7z folder stream graph exceeds the supported bound",
                    inputStreams=total_in,
                    outputStreams=total_out,
                )
        bind_count = total_out - 1
        binds = [(reader.uint64(), reader.uint64()) for _ in range(bind_count)]
        packed_count = total_in - bind_count
        if not 1 <= packed_count <= 64:
            reject(
                "UNSUPPORTED_7Z_CODER_GRAPH",
                "7z folder has an invalid packed-stream count",
                packedStreams=packed_count,
            )
        packed_indices = [reader.uint64() for _ in range(packed_count)] if packed_count > 1 else [0]
        return {
            "coders": coders,
            "binds": binds,
            "packedIndices": packed_indices,
            "totalIn": total_in,
            "totalOut": total_out,
            "crc": None,
        }

    def _seven_substreams_info(self, reader, folders):
        counts = [1] * len(folders)
        sizes = None
        digests = None
        nid = reader.byte()
        if nid == 0x0d:
            counts = [reader.uint64() for _ in folders]
            if (
                any(count > self.limits.max_members_per_archive for count in counts)
                or sum(counts) > self.limits.max_members_per_archive
            ):
                reject(
                    "MEMBERS_PER_ARCHIVE_LIMIT",
                    "7z substream count exceeds the configured member limit",
                    count=sum(counts),
                    limit=self.limits.max_members_per_archive,
                )
            nid = reader.byte()
        if nid == 0x09:
            sizes = []
            for folder, count in zip(folders, counts):
                subtotal = 0
                for _ in range(max(0, count - 1)):
                    value = reader.uint64()
                    sizes.append(value)
                    subtotal += value
                if count:
                    final_size = folder["unpackSizes"][-1] - subtotal
                    if final_size < 0:
                        reject("INVALID_7Z_SUBSTREAM_SIZE", "7z substream sizes exceed the folder output")
                    sizes.append(final_size)
            nid = reader.byte()
        if sizes is None:
            sizes = []
            for folder, count in zip(folders, counts):
                if count == 1:
                    sizes.append(folder["unpackSizes"][-1])
                elif count:
                    reject("MISSING_7Z_SUBSTREAM_SIZES", "Solid 7z folder omits substream sizes")
        digest_slots = sum(
            count if count != 1 or folder["crc"] is None else 0
            for folder, count in zip(folders, counts)
        )
        if nid == 0x0a:
            digests = self._seven_digests(reader, digest_slots)
            nid = reader.byte()
        if nid != 0:
            reject("INVALID_7Z_SUBSTREAM_INFO", "7z SubStreamsInfo has an unsupported trailing property", nid=nid)
        if digests is None:
            digests = [None] * digest_slots

        result = []
        size_index = 0
        digest_index = 0
        for folder_index, (folder, count) in enumerate(zip(folders, counts)):
            for substream in range(count):
                if count == 1 and folder["crc"] is not None:
                    crc = folder["crc"]
                else:
                    crc = digests[digest_index]
                    digest_index += 1
                result.append({
                    "folder": folder_index,
                    "substream": substream,
                    "size": sizes[size_index],
                    "crc": crc,
                })
                size_index += 1
        return result

    def _seven_default_substreams(self, folders):
        return [
            {
                "folder": index,
                "substream": 0,
                "size": folder["unpackSizes"][-1],
                "crc": folder["crc"],
            }
            for index, folder in enumerate(folders)
        ]

    def _seven_digests(self, reader, count):
        all_defined = reader.byte()
        defined = [True] * count if all_defined else read_bit_vector(reader, count)
        return [reader.uint32() if present else None for present in defined]

    def _seven_decode_streams(self, archive, signature_offset, streams, owner):
        pack = streams["pack"]
        pack_offsets = []
        cursor = signature_offset + 32 + pack["position"]
        for index, size in enumerate(pack["sizes"]):
            packed = checked_slice(archive, cursor, size)
            expected_crc = pack["crcs"][index]
            if expected_crc is not None and zlib.crc32(packed) & 0xffffffff != expected_crc:
                reject("SEVEN_ZIP_PACK_CRC_MISMATCH", "7z packed-stream checksum is invalid", stream=index)
            pack_offsets.append((cursor, size))
            cursor += size

        folders = streams["folders"]
        pack_index = 0
        folder_outputs = []
        folder_coders = []
        ranges = []
        for folder_index, folder in enumerate(folders):
            if (
                len(folder["coders"]) != 1
                or folder["totalIn"] != 1
                or folder["totalOut"] != 1
                or folder["binds"]
                or len(folder["packedIndices"]) != 1
            ):
                reject(
                    "UNSUPPORTED_7Z_CODER_GRAPH",
                    "Only one-coder, one-input, one-output 7z folders are supported",
                    folder=folder_index,
                )
            if pack_index >= len(pack_offsets):
                reject("SEVEN_ZIP_PACK_STREAM_MISMATCH", "7z folder has no corresponding packed stream")
            offset, length = pack_offsets[pack_index]
            packed = checked_slice(archive, offset, length)
            expected_size = folder["unpackSizes"][0]
            self.state.check_expansion(expected_size, len(packed), f"7z:{owner}:{folder_index}")
            expanded, coder_disposition = self._seven_decode_coder(
                folder["coders"][0],
                packed,
                expected_size,
            )
            if folder["crc"] is not None and zlib.crc32(expanded) & 0xffffffff != folder["crc"]:
                reject("SEVEN_ZIP_FOLDER_CRC_MISMATCH", "7z folder checksum is invalid", folder=folder_index)
            self.state.charge_expansion(len(expanded), len(packed), f"7z:{owner}:{folder_index}")
            folder_outputs.append(expanded)
            folder_coders.append(coder_disposition)
            ranges.append({"offset": offset, "length": length, "owner": f"{owner}-folder-{folder_index}"})
            pack_index += 1
        if pack_index != len(pack_offsets):
            reject("SEVEN_ZIP_PACK_STREAM_MISMATCH", "7z has undeclared packed streams")

        decoded = []
        folder_substreams = {}
        for substream in streams["substreams"]:
            folder_substreams.setdefault(substream["folder"], []).append(substream)
        for folder_index, output in enumerate(folder_outputs):
            coder_disposition = folder_coders[folder_index]
            expanded_offset = 0
            substreams = folder_substreams.get(folder_index, [])
            for item in substreams:
                content = checked_slice(output, expanded_offset, item["size"])
                if item["crc"] is not None and zlib.crc32(content) & 0xffffffff != item["crc"]:
                    reject(
                        "SEVEN_ZIP_SUBSTREAM_CRC_MISMATCH",
                        "7z substream checksum is invalid",
                        folder=folder_index,
                        substream=item["substream"],
                    )
                packed_offset, packed_length = pack_offsets[folder_index]
                decoded.append({
                    "content": content,
                    "offset": packed_offset,
                    "length": packed_length,
                    "expandedOffset": expanded_offset,
                    "folder": folder_index,
                    "substream": item["substream"],
                    "shared": len(substreams) > 1,
                    "crc32": f"{zlib.crc32(content) & 0xffffffff:08x}",
                    **coder_disposition,
                })
                expanded_offset += item["size"]
            if expanded_offset != len(output):
                reject("SEVEN_ZIP_SUBSTREAM_SIZE_MISMATCH", "7z substreams do not consume their folder output")
        return decoded, ranges

    def _seven_decode_coder(self, coder, packed, expected_size):
        method = coder["method"]
        properties = coder["properties"]
        if method == b"\x00":
            if properties or len(packed) != expected_size:
                reject("INVALID_7Z_COPY_STREAM", "7z Copy coder metadata or length is invalid")
            return packed, {
                "coderMethod": method.hex(),
                "coderProperties": properties.hex(),
                "declaredDictionarySize": None,
                "effectiveDictionarySize": None,
            }
        if method == b"\x03\x01\x01":
            if len(properties) != 5:
                reject("INVALID_7Z_LZMA_PROPERTIES", "7z LZMA coder properties are invalid")
            first = properties[0]
            if first >= 9 * 5 * 5:
                reject("INVALID_7Z_LZMA_PROPERTIES", "7z LZMA lc/lp/pb property is invalid")
            lc = first % 9
            remainder = first // 9
            lp = remainder % 5
            pb = remainder // 5
            declared_dictionary = struct.unpack_from("<I", properties, 1)[0]
            if declared_dictionary < 4096:
                reject("INVALID_7Z_LZMA_PROPERTIES", "7z LZMA dictionary is smaller than 4096 bytes")
            effective_dictionary = min(declared_dictionary, max(4096, expected_size))
            filters = [{
                "id": lzma.FILTER_LZMA1,
                "dict_size": effective_dictionary,
                "lc": lc,
                "lp": lp,
                "pb": pb,
            }]
        elif method == b"\x21":
            if len(properties) != 1 or properties[0] > 40:
                reject("INVALID_7Z_LZMA2_PROPERTIES", "7z LZMA2 coder properties are invalid")
            prop = properties[0]
            declared_dictionary = 0xffffffff if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)
            effective_dictionary = min(declared_dictionary, max(4096, expected_size))
            filters = [{"id": lzma.FILTER_LZMA2, "dict_size": effective_dictionary}]
        else:
            reject("UNSUPPORTED_7Z_COMPRESSION", "7z coder method is unsupported", method=method.hex())
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            expanded = decoder.decompress(packed, max_length=min(expected_size, self.state.remaining_expansion()) + 1)
        except (lzma.LZMAError, ValueError) as exc:
            reject("INVALID_7Z_COMPRESSED_STREAM", "7z compressed stream is invalid", reason=str(exc))
        if len(expanded) != expected_size or not decoder.eof or decoder.unused_data:
            reject(
                "SEVEN_ZIP_LENGTH_MISMATCH",
                "7z coder output length is invalid",
                expected=expected_size,
                actual=len(expanded),
            )
        return expanded, {
            "coderMethod": method.hex(),
            "coderProperties": properties.hex(),
            "declaredDictionarySize": declared_dictionary,
            "effectiveDictionarySize": effective_dictionary,
        }

    def _seven_parse_files(self, reader):
        count = reader.uint64()
        if count > self.limits.max_members_per_archive:
            reject("MEMBERS_PER_ARCHIVE_LIMIT", "7z file count exceeds the configured limit", count=count)
        if self.state.total_members + count > self.limits.max_members_total:
            reject(
                "GLOBAL_MEMBER_LIMIT",
                "7z file count exceeds the remaining global member limit",
                count=self.state.total_members + count,
                limit=self.limits.max_members_total,
            )
        properties = {}
        while True:
            nid = reader.byte()
            if nid == 0:
                break
            if nid in properties:
                reject("DUPLICATE_7Z_FILE_PROPERTY", "7z FilesInfo property is repeated", nid=nid)
            size = reader.uint64()
            properties[nid] = reader.read(size)

        if 0x11 not in properties:
            reject("MISSING_7Z_NAMES", "7z FilesInfo omits member names")
        result = {"names": self._seven_names(properties.pop(0x11), count)}
        if 0x0e in properties:
            result["emptyStreams"] = self._seven_exact_bits(properties.pop(0x0e), count)
        empty_count = sum(result.get("emptyStreams", []))
        if 0x0f in properties:
            result["emptyFiles"] = self._seven_exact_bits(properties.pop(0x0f), empty_count)
        if 0x10 in properties:
            result["anti"] = self._seven_exact_bits(properties.pop(0x10), empty_count)
        for nid, key in ((0x12, "creationTimes"), (0x13, "accessTimes"), (0x14, "modificationTimes")):
            if nid in properties:
                result[key] = self._seven_optional_values(properties.pop(nid), count, 8)
        if 0x15 in properties:
            result["attributes"] = self._seven_optional_values(properties.pop(0x15), count, 4)
        if 0x18 in properties:
            reject("UNSUPPORTED_7Z_START_POSITIONS", "7z start-position file properties are unsupported")
        if 0x16 in properties:
            reject("UNSUPPORTED_7Z_COMMENTS", "7z comments are rejected as ambiguous metadata")
        if 0x19 in properties:
            dummy = properties.pop(0x19)
            if any(dummy):
                reject("INVALID_7Z_DUMMY_PROPERTY", "7z dummy property contains nonzero bytes")
        if properties:
            reject("UNSUPPORTED_7Z_FILE_PROPERTY", "7z FilesInfo property is unsupported", nid=min(properties))
        return result

    def _seven_names(self, payload, count):
        reader = BinaryReader(payload)
        if reader.byte() != 0:
            reject("UNSUPPORTED_7Z_EXTERNAL_PROPERTY", "Externally stored 7z names are unsupported")
        raw = reader.read(reader.remaining())
        if len(raw) % 2:
            reject("INVALID_7Z_NAME", "7z UTF-16 name data has odd length")
        names = []
        cursor = 0
        for _ in range(count):
            end = cursor
            while end + 1 < len(raw) and raw[end:end + 2] != b"\0\0":
                end += 2
            if end + 1 >= len(raw):
                reject("INVALID_7Z_NAME", "7z name is not NUL-terminated")
            value = raw[cursor:end]
            names.append((value, strict_decode(value, "utf-16-le", "INVALID_7Z_NAME")))
            cursor = end + 2
        if cursor != len(raw):
            reject("TRAILING_7Z_NAME_DATA", "7z name property has undeclared trailing bytes")
        return names

    def _seven_exact_bits(self, payload, count):
        reader = BinaryReader(payload)
        result = read_bit_vector(reader, count)
        if reader.remaining():
            reject("TRAILING_7Z_BIT_VECTOR", "7z bit vector has undeclared trailing bytes")
        if count % 8 and payload and payload[-1] & ((1 << (8 - count % 8)) - 1):
            reject("NONZERO_7Z_BIT_PADDING", "7z bit vector has nonzero padding bits")
        return result

    def _seven_optional_values(self, payload, count, width):
        reader = BinaryReader(payload)
        all_defined = reader.byte()
        defined = [True] * count if all_defined else read_bit_vector(reader, count)
        if reader.byte() != 0:
            reject("UNSUPPORTED_7Z_EXTERNAL_PROPERTY", "Externally stored 7z file properties are unsupported")
        values = []
        for present in defined:
            values.append(int.from_bytes(reader.read(width), "little") if present else None)
        reader.require_end()
        return values

    def _validate_physical_ranges(self, ranges, start, end, owner):
        ranges = sorted((item for item in ranges if item["length"]), key=lambda item: item["offset"])
        cursor = start
        for item in ranges:
            if item["offset"] != cursor:
                reject(
                    "OVERLAPPING_OR_GAPPED_RECORDS",
                    "Archive physical records overlap or leave undeclared payload",
                    owner=owner,
                    expectedOffset=cursor,
                    actualOffset=item["offset"],
                )
            cursor += item["length"]
        if cursor != end:
            reject(
                "UNDECLARED_ARCHIVE_PAYLOAD",
                "Archive physical records do not cover the containing stream",
                owner=owner,
                declaredEnd=cursor,
                containerEnd=end,
            )


def validate_tar_flavor(header, offset):
    magic = header[257:263]
    version = header[263:265]
    if magic == b"\0" * 6 and version == b"\0" * 2:
        return "v7"
    if magic == b"ustar\0" and version == b"00":
        return "ustar"
    if magic == b"ustar " and version == b" \0":
        return "gnu"
    reject(
        "INVALID_TAR_FORMAT",
        "TAR header is not strict v7, ustar, or GNU ustar",
        offset=offset,
        magicHex=magic.hex(),
        versionHex=version.hex(),
    )


def parse_tar_number(raw, field):
    if not raw:
        reject("INVALID_TAR_NUMBER", "TAR numeric field is empty", field=field)
    if raw[0] & 0x80:
        value = int.from_bytes(bytes([raw[0] & 0x7f]) + raw[1:], "big", signed=False)
        return value
    stripped = raw.strip(b" \0")
    if not stripped:
        return 0
    if any(byte not in b"01234567" for byte in stripped):
        reject("INVALID_TAR_NUMBER", "TAR numeric field is not octal", field=field, valueHex=raw.hex())
    return int(stripped, 8)


def parse_decimal(text, field):
    if not re.fullmatch(r"[0-9]{1,20}", text):
        reject("INVALID_TAR_NUMBER", "PAX numeric value is not an unsigned decimal", field=field, value=text)
    value = int(text, 10)
    if value > 0xffffffffffffffff:
        reject("INVALID_TAR_NUMBER", "PAX numeric value exceeds uint64", field=field, value=text)
    return value


def parse_pax(data):
    cursor = 0
    result = {}
    while cursor < len(data):
        space = data.find(b" ", cursor)
        if space < 0:
            reject("INVALID_PAX_RECORD", "PAX record has no length delimiter", offset=cursor)
        length_raw = data[cursor:space]
        if (
            not length_raw.isdigit()
            or length_raw.startswith(b"0")
            or len(length_raw) > 20
        ):
            reject("INVALID_PAX_RECORD", "PAX record length is invalid", offset=cursor)
        length = int(length_raw)
        record = checked_slice(data, cursor, length, "INVALID_PAX_RECORD")
        if not record.endswith(b"\n") or space >= cursor + length:
            reject("INVALID_PAX_RECORD", "PAX record boundary is invalid", offset=cursor)
        body = record[space - cursor + 1:-1]
        equals = body.find(b"=")
        if equals <= 0:
            reject("INVALID_PAX_RECORD", "PAX record lacks a key/value separator", offset=cursor)
        key = strict_decode(body[:equals], "ascii", "INVALID_PAX_KEY")
        value = strict_decode(body[equals + 1:], "utf-8", "INVALID_PAX_VALUE")
        if key in result:
            reject("DUPLICATE_PAX_KEY", "PAX metadata key is repeated", key=key)
        if key.startswith("GNU.sparse") or key.startswith("SCHILY.xattr"):
            reject("UNSUPPORTED_TAR_EXTENSION", "Sparse or extended-attribute TAR metadata is unsupported", key=key)
        allowed = {
            "path", "linkpath", "size", "uid", "gid", "uname", "gname",
            "mode", "mtime", "atime", "ctime", "comment",
        }
        if key not in allowed:
            reject("UNSUPPORTED_TAR_EXTENSION", "PAX metadata key is unsupported", key=key)
        result[key] = value
        cursor += length
    return result


def is_structural_tar(data, member_limit):
    if len(data) < 1024 or len(data) % 512:
        return False
    cursor = 0
    members = 0
    pending_pax = None
    try:
        while cursor < len(data):
            header = checked_slice(data, cursor, 512)
            if not any(header):
                if cursor + 1024 > len(data):
                    return False
                if any(checked_slice(data, cursor + 512, 512)):
                    return False
                return not any(data[cursor:]) and pending_pax is None

            validate_tar_flavor(header, cursor)
            stored_checksum = parse_tar_number(header[148:156], "checksum")
            checksum_header = bytearray(header)
            checksum_header[148:156] = b"        "
            unsigned = sum(checksum_header)
            signed = sum(byte if byte < 128 else byte - 256 for byte in checksum_header)
            if stored_checksum not in (unsigned, signed):
                return False

            typeflag = header[156:157]
            metadata = typeflag in (b"x", b"g", b"L", b"K")
            header_size = parse_tar_number(header[124:136], "size")
            effective_size = header_size
            if not metadata and pending_pax and "size" in pending_pax:
                effective_size = parse_decimal(pending_pax["size"], "pax size")
            data_offset = cursor + 512
            padded = (effective_size + 511) & ~511
            data_end = data_offset + effective_size
            padded_end = data_offset + padded
            if data_end > len(data) or padded_end > len(data):
                return False
            if any(data[data_end:padded_end]):
                return False

            members += 1
            if members > member_limit:
                return True

            if typeflag == b"x":
                if pending_pax is not None:
                    return False
                pending_pax = parse_pax(data[data_offset:data_end])
            elif typeflag == b"g":
                parse_pax(data[data_offset:data_end])
            elif metadata:
                if pending_pax is not None:
                    return False
            else:
                pending_pax = None
            cursor = data_offset + padded
    except (AuditError, UnicodeError, ValueError, OverflowError):
        return False
    return False


def parse_zstd_header(data):
    if len(data) < 6 or not data.startswith(ZSTD_SIGNATURE):
        reject("INVALID_ZSTD_HEADER", "zstd frame header is invalid")
    descriptor = data[4]
    if descriptor & 0x18:
        reject("INVALID_ZSTD_HEADER", "zstd frame descriptor has a reserved bit set")
    size_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    checksum = bool(descriptor & 0x04)
    dictionary_flag = descriptor & 0x03
    cursor = 5
    window_descriptor = None
    if not single_segment:
        window_descriptor = checked_slice(data, cursor, 1)[0]
        cursor += 1
    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    dictionary_id = int.from_bytes(checked_slice(data, cursor, dictionary_size), "little") if dictionary_size else 0
    cursor += dictionary_size
    content_size_width = (1 if single_segment else 0, 2, 4, 8)[size_flag]
    frame_content_size = None
    if content_size_width:
        frame_content_size = int.from_bytes(checked_slice(data, cursor, content_size_width), "little")
        if content_size_width == 2:
            frame_content_size += 256
        cursor += content_size_width
    if dictionary_id:
        reject("UNSUPPORTED_ZSTD_DICTIONARY", "Dictionary-compressed zstd frames are unsupported", dictionaryId=dictionary_id)
    return cursor, {
        "frameDescriptor": f"{descriptor:02x}",
        "singleSegment": single_segment,
        "contentChecksum": checksum,
        "windowDescriptor": f"{window_descriptor:02x}" if window_descriptor is not None else None,
        "dictionaryId": dictionary_id,
        "frameContentSize": frame_content_size,
    }


def seven_zip_envelope(data, signature_offset):
    if signature_offset < 0 or signature_offset > len(data):
        reject(
            "SEVEN_ZIP_SIGNATURE_OUT_OF_RANGE",
            "7z signature offset is outside the containing byte stream",
            offset=signature_offset,
            containerLength=len(data),
        )
    if len(data) - signature_offset < 32:
        reject(
            "TRUNCATED_7Z_START_HEADER",
            "7z start header is shorter than 32 bytes",
            offset=signature_offset,
            availableLength=len(data) - signature_offset,
        )
    signature = data[signature_offset:signature_offset + 32]
    if signature[:6] != SEVEN_ZIP_SIGNATURE:
        reject("INVALID_7Z_SIGNATURE", "7z signature is invalid", offset=signature_offset)
    major, minor = signature[6], signature[7]
    if major != 0 or minor > 4:
        reject("UNSUPPORTED_7Z_VERSION", "7z archive version is unsupported", major=major, minor=minor)
    if zlib.crc32(signature[12:32]) & 0xffffffff != struct.unpack_from("<I", signature, 8)[0]:
        reject("SEVEN_ZIP_START_HEADER_CRC_MISMATCH", "7z start-header checksum is invalid")

    next_offset, next_size, next_crc = struct.unpack_from("<QQI", signature, 12)
    payload_start = signature_offset + 32
    if next_offset > len(data) - payload_start:
        reject(
            "SEVEN_ZIP_NEXT_HEADER_OUT_OF_RANGE",
            "7z next-header offset is outside the containing byte stream",
            nextHeaderOffset=next_offset,
            availableLength=len(data) - payload_start,
        )
    next_start = payload_start + next_offset
    if next_size > len(data) - next_start:
        reject(
            "SEVEN_ZIP_NEXT_HEADER_OUT_OF_RANGE",
            "7z next header extends outside the containing byte stream",
            nextHeaderOffset=next_offset,
            nextHeaderLength=next_size,
            availableLength=len(data) - next_start,
        )
    next_end = next_start + next_size
    if next_end != len(data):
        reject(
            "TRAILING_7Z_PAYLOAD",
            "7z next header does not end at the archive boundary",
            nextHeaderEnd=next_end,
            archiveLength=len(data),
        )
    next_header = data[next_start:next_end]
    if zlib.crc32(next_header) & 0xffffffff != next_crc:
        reject("SEVEN_ZIP_NEXT_HEADER_CRC_MISMATCH", "7z next-header checksum is invalid")
    if next_size == 0 and next_offset != 0:
        reject(
            "UNDECLARED_7Z_EMPTY_PAYLOAD",
            "A 7z archive with no next header cannot declare preceding payload bytes",
            payloadLength=next_offset,
        )
    return major, minor, next_start, next_size, next_header


def validate_sfx_pe_prefix(data, signature_offset=None):
    if len(data) < 64:
        reject("MALFORMED_SFX_PE_PREFIX", "MZ-prefixed input is shorter than a DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    if pe_offset < 64 or pe_offset > MAX_SFX_PREFIX_LENGTH - 24:
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "MZ-prefixed input has an invalid PE header offset",
            peHeaderOffset=pe_offset,
        )
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "MZ-prefixed input does not contain a bounded PE signature",
            peHeaderOffset=pe_offset,
        )

    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if not 1 <= section_count <= 96:
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "PE section count is outside the supported structural bound",
            sectionCount=section_count,
        )
    optional_offset = pe_offset + 24
    section_table = optional_offset + optional_size
    section_table_end = section_table + 40 * section_count
    if section_table_end > len(data) or section_table_end > MAX_SFX_PREFIX_LENGTH:
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "PE headers extend outside the bounded SFX prefix",
            headerEnd=section_table_end,
        )
    if optional_size < 64:
        reject("MALFORMED_SFX_PE_PREFIX", "PE optional header is too short")
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    minimum_optional_size = {0x10b: 96, 0x20b: 112}.get(optional_magic)
    if minimum_optional_size is None or optional_size < minimum_optional_size:
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "PE optional header has an unsupported shape",
            optionalHeaderMagic=f"{optional_magic:04x}",
            optionalHeaderLength=optional_size,
        )
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    if size_of_headers < section_table_end or size_of_headers > len(data):
        reject(
            "MALFORMED_SFX_PE_PREFIX",
            "PE SizeOfHeaders does not contain the section table",
            sizeOfHeaders=size_of_headers,
            sectionTableEnd=section_table_end,
        )

    raw_ranges = []
    image_end = size_of_headers
    for index in range(section_count):
        section = section_table + 40 * index
        raw_size = struct.unpack_from("<I", data, section + 16)[0]
        raw_offset = struct.unpack_from("<I", data, section + 20)[0]
        if not raw_size:
            continue
        raw_end = raw_offset + raw_size
        if raw_offset < size_of_headers or raw_end > len(data):
            reject(
                "MALFORMED_SFX_PE_PREFIX",
                "PE section data extends outside the executable image",
                section=index,
                rawOffset=raw_offset,
                rawLength=raw_size,
            )
        raw_ranges.append((raw_offset, raw_end, index))
        image_end = max(image_end, raw_end)
    raw_ranges.sort()
    for previous, current in zip(raw_ranges, raw_ranges[1:]):
        if previous[1] > current[0]:
            reject(
                "MALFORMED_SFX_PE_PREFIX",
                "PE section data ranges overlap",
                firstSection=previous[2],
                secondSection=current[2],
            )

    if signature_offset is not None:
        if signature_offset > MAX_SFX_PREFIX_LENGTH:
            reject(
                "SFX_PREFIX_LIMIT",
                "7z SFX prefix exceeds the fixed physical scan ceiling",
                prefixLength=signature_offset,
                limit=MAX_SFX_PREFIX_LENGTH,
            )
        if signature_offset < image_end:
            reject(
                "SFX_SIGNATURE_OVERLAPS_PE_IMAGE",
                "Embedded 7z signature overlaps PE headers or section data",
                signatureOffset=signature_offset,
                peImageEnd=image_end,
            )


def detect_format(data, tar_member_limit=Limits.max_members_per_archive):
    if data.startswith((b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06")):
        return "zip", 0
    if data.startswith(SEVEN_ZIP_SIGNATURE):
        return "7z", 0
    if data.startswith(b"\x1f\x8b"):
        return "gzip", 0
    if data.startswith(b"BZh"):
        return "bzip2", 0
    if data.startswith(XZ_SIGNATURE):
        return "xz", 0
    if data.startswith(ZSTD_SIGNATURE):
        return "zstd", 0
    if data.startswith(b"MZ"):
        validate_sfx_pe_prefix(data)
        scan_end = min(len(data), MAX_SFX_PREFIX_LENGTH + len(SEVEN_ZIP_SIGNATURE))
        cursor = 0
        first_candidate = None
        second_candidate = None
        first_error = None
        valid_candidates = []
        while True:
            candidate = data.find(SEVEN_ZIP_SIGNATURE, cursor, scan_end)
            if candidate < 0 or candidate > MAX_SFX_PREFIX_LENGTH:
                break
            if first_candidate is None:
                first_candidate = candidate
            elif second_candidate is None:
                second_candidate = candidate
            try:
                seven_zip_envelope(data, candidate)
            except AuditError as exc:
                if first_error is None:
                    first_error = exc
            else:
                valid_candidates.append(candidate)
                if len(valid_candidates) == 2:
                    reject(
                        "AMBIGUOUS_7Z_SIGNATURE",
                        "SFX contains multiple valid 7z signature envelopes",
                        firstOffset=valid_candidates[0],
                        secondOffset=valid_candidates[1],
                    )
            cursor = candidate + 1
        if valid_candidates:
            validate_sfx_pe_prefix(data, valid_candidates[0])
            return "7z", valid_candidates[0]
        if first_candidate is not None:
            validate_sfx_pe_prefix(data, first_candidate)
            if second_candidate is not None:
                reject(
                    "INVALID_7Z_SFX_CANDIDATES",
                    "SFX contains multiple 7z signatures but none has a valid envelope",
                    firstOffset=first_candidate,
                    secondOffset=second_candidate,
                )
            raise first_error
        if len(data) > MAX_SFX_PREFIX_LENGTH:
            reject(
                "SFX_PREFIX_LIMIT",
                "No 7z signature occurs within the fixed physical scan ceiling",
                limit=MAX_SFX_PREFIX_LENGTH,
            )
        reject("MISSING_7Z_SFX_SIGNATURE", "MZ/PE input contains no embedded 7z signature")
    if len(data) >= 512 and data[257:263] in (b"ustar\0", b"ustar "):
        return "tar", 0
    if is_structural_tar(data, tar_member_limit):
        return "tar", 0
    return None, 0


def manifest_for_comparison(manifest):
    result = dict(manifest)
    result["source"] = {
        key: value
        for key, value in manifest["source"].items()
        if key != "name"
    }
    return result


def compare_values(left, right, path="$", differences=None):
    if differences is None:
        differences = []
    if type(left) is not type(right):
        differences.append({"path": path, "a": left, "b": right})
        return differences
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}"
            if key not in left:
                differences.append({"path": child, "a": None, "b": right[key]})
            elif key not in right:
                differences.append({"path": child, "a": left[key], "b": None})
            else:
                compare_values(left[key], right[key], child, differences)
    elif isinstance(left, list):
        length = max(len(left), len(right))
        for index in range(length):
            child = f"{path}[{index}]"
            if index >= len(left):
                differences.append({"path": child, "a": None, "b": right[index]})
            elif index >= len(right):
                differences.append({"path": child, "a": left[index], "b": None})
            else:
                compare_values(left[index], right[index], child, differences)
    elif left != right:
        differences.append({"path": path, "a": left, "b": right})
    return differences


def compare_manifests(left, right):
    differences = compare_values(manifest_for_comparison(left), manifest_for_comparison(right))
    return {
        "schema": COMPARISON_SCHEMA,
        "equal": not differences,
        "a": {
            "identity": left["archive"]["identity"],
            "length": left["source"]["length"],
        },
        "b": {
            "identity": right["archive"]["identity"],
            "length": right["source"]["length"],
        },
        "differences": differences,
    }


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value):
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def positive_float(value):
    parsed = float(value)
    if not math.isfinite(parsed) or not parsed > 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def add_limit_arguments(parser):
    parser.add_argument("--max-depth", type=nonnegative_int, default=Limits.max_depth)
    parser.add_argument("--max-total-expanded-bytes", type=positive_int, default=Limits.max_total_expanded_bytes)
    parser.add_argument("--max-members-per-archive", type=positive_int, default=Limits.max_members_per_archive)
    parser.add_argument("--max-members-total", type=positive_int, default=Limits.max_members_total)
    parser.add_argument("--max-compression-ratio", type=positive_float, default=Limits.max_compression_ratio)
    parser.add_argument("--max-path-length", type=positive_int, default=Limits.max_path_length)


def limits_from_args(args):
    return Limits(
        max_depth=args.max_depth,
        max_total_expanded_bytes=args.max_total_expanded_bytes,
        max_members_per_archive=args.max_members_per_archive,
        max_members_total=args.max_members_total,
        max_compression_ratio=args.max_compression_ratio,
        max_path_length=args.max_path_length,
    )


def write_json(value, stream):
    json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
    stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fail-closed recursive physical archive auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_parser = subparsers.add_parser("audit", help="emit a deterministic recursive physical manifest")
    add_limit_arguments(audit_parser)
    audit_parser.add_argument("archive")
    compare_parser = subparsers.add_parser("compare", help="audit and compare two physical archive manifests")
    add_limit_arguments(compare_parser)
    compare_parser.add_argument("archive_a")
    compare_parser.add_argument("archive_b")
    args = parser.parse_args(argv)

    try:
        limits = limits_from_args(args)
        if args.command == "audit":
            write_json(ArchiveAuditor(limits).audit_path(args.archive), sys.stdout)
            return 0
        left = ArchiveAuditor(limits).audit_path(args.archive_a)
        right = ArchiveAuditor(limits).audit_path(args.archive_b)
        result = compare_manifests(left, right)
        write_json(result, sys.stdout)
        return 0 if result["equal"] else 1
    except (AuditError, OSError, struct.error, MemoryError) as exc:
        if isinstance(exc, AuditError):
            error = exc
        elif isinstance(exc, struct.error):
            error = AuditError("MALFORMED_BINARY_HEADER", str(exc))
        elif isinstance(exc, MemoryError):
            error = AuditError("RESOURCE_EXHAUSTED", "The configured limits exceed available memory")
        else:
            error = AuditError("IO_ERROR", str(exc))
        write_json(error.document(), sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
