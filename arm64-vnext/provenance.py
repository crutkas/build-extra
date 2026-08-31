#!/usr/bin/env python3

import argparse
import hashlib
import json
import subprocess
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


EPOCH = "2026-08-31-v1"
LEDGER_SCHEMA = "arm64-vnext-input-provenance-v1"
MANIFEST_SCHEMA = "arm64-vnext-payload-input-manifest-v1"
DIAGNOSTIC_SCHEMA = "arm64-vnext-payload-input-diagnostic-v1"
SCHEMA_PATH = Path(__file__).parent / "schemas" / "payload-input-manifest-v1.schema.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]*$")
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
PROTECTED_FIELDS = {
    "admission",
    "admission_authority",
    "admitted",
    "authorization",
    "authorized",
    "status",
}


class ValidationError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{path}: invalid JSON: {error}") from error


def resolve_schema_reference(schema_root, reference):
    if not reference.startswith("#/"):
        raise ValidationError(f"schema: unsupported reference: {reference}")
    value = schema_root
    for part in reference[2:].split("/"):
        value = value[part.replace("~1", "/").replace("~0", "~")]
    return value


def matches_json_type(value, expected):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def validate_schema_instance(value, schema, schema_root, context="$"):
    if "$ref" in schema:
        return validate_schema_instance(
            value,
            resolve_schema_reference(schema_root, schema["$ref"]),
            schema_root,
            context,
        )
    expected_types = schema.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    if expected_types and not any(
        matches_json_type(value, expected) for expected in expected_types
    ):
        raise ValidationError(
            f"{context}: schema type must be {' or '.join(expected_types)}"
        )
    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{context}: schema const mismatch")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = sorted(set(required) - set(value))
        if missing:
            raise ValidationError(
                f"{context}: schema missing fields: {', '.join(missing)}"
            )
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise ValidationError(
                    f"{context}: schema unknown fields: {', '.join(unknown)}"
                )
        for key, child in value.items():
            if key in properties:
                validate_schema_instance(
                    child, properties[key], schema_root, f"{context}.{key}"
                )
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValidationError(f"{context}: schema array is too short")
        item_schema = schema.get("items")
        if item_schema:
            for index, child in enumerate(value):
                validate_schema_instance(
                    child, item_schema, schema_root, f"{context}[{index}]"
                )
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValidationError(f"{context}: schema string is too short")
        pattern = schema.get("pattern")
        if pattern and not re.fullmatch(pattern, value):
            raise ValidationError(f"{context}: schema pattern mismatch")
        if schema.get("format") == "uri":
            uri = urlparse(value)
            if (
                not URI.fullmatch(value)
                or INVALID_PERCENT_ESCAPE.search(value)
                or (uri.scheme in {"http", "https"} and not uri.netloc)
            ):
                raise ValidationError(f"{context}: schema URI format mismatch")
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and "minimum" in schema
        and value < schema["minimum"]
    ):
        raise ValidationError(f"{context}: schema value below minimum")


def enforce_manifest_schema(manifest):
    schema = read_json(SCHEMA_PATH)
    validate_schema_instance(manifest, schema, schema)


def require_keys(value, required, allowed, context):
    if not isinstance(value, dict):
        raise ValidationError(f"{context}: expected object")
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        raise ValidationError(f"{context}: missing fields: {', '.join(missing)}")
    if unknown:
        raise ValidationError(f"{context}: unknown fields: {', '.join(unknown)}")


def require_sha256(value, context):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValidationError(f"{context}: expected lowercase SHA-256")


def reject_protected_fields(value, context="manifest"):
    if isinstance(value, dict):
        found = sorted(PROTECTED_FIELDS & set(value))
        if context.endswith(".archive.signature"):
            found = [field for field in found if field != "status"]
        if found:
            raise ValidationError(
                f"{context}: protected authority fields: {', '.join(found)}"
            )
        for key, child in value.items():
            reject_protected_fields(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_protected_fields(child, f"{context}[{index}]")


def load_ledger(path, expected_file_sha256):
    require_sha256(expected_file_sha256, "expected ledger file hash")
    raw = path.read_bytes()
    actual_file_sha256 = sha256_bytes(raw)
    if actual_file_sha256 != expected_file_sha256:
        raise ValidationError("canonical provenance ledger file hash mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{path}: invalid JSON: {error}") from error
    require_keys(document, {"payload", "seal"}, {"payload", "seal"}, "ledger")
    payload = document["payload"]
    seal = document["seal"]
    canonical = canonical_json(payload)
    payload_sha256 = sha256_bytes(canonical)
    if seal.get("payload_sha256") != payload_sha256:
        raise ValidationError("canonical provenance ledger payload seal mismatch")
    if seal.get("payload_utf8_bytes") not in (None, len(canonical)):
        raise ValidationError("canonical provenance ledger payload size mismatch")
    if payload.get("schema") != LEDGER_SCHEMA:
        raise ValidationError("canonical provenance ledger schema mismatch")
    if payload.get("epoch") != EPOCH:
        raise ValidationError("canonical provenance ledger epoch mismatch")
    records = {}
    for index, record in enumerate(payload.get("inputs", [])):
        record_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(record_id, str) or not record_id:
            raise ValidationError(f"ledger input {index}: missing id")
        if record_id in records:
            raise ValidationError(f"ledger: duplicate input id: {record_id}")
        records[record_id] = record
    return records, payload_sha256


def admitted_record(records, record_id, context):
    record = records.get(record_id)
    if record is None:
        raise ValidationError(f"{context}: input not found: {record_id}")
    if record.get("epoch") != EPOCH:
        raise ValidationError(f"{context}: input has wrong epoch: {record_id}")
    if record.get("status") != "ADMITTED":
        raise ValidationError(f"{context}: input is not currently admitted: {record_id}")
    require_sha256(record.get("sha256"), f"{context}: ledger record hash")
    return record


def validate_source(source, context):
    require_keys(
        source,
        {"repository", "ref", "commit", "tree"},
        {"repository", "ref", "commit", "tree"},
        context,
    )
    if (
        not isinstance(source["repository"], str)
        or source["repository"].count("/") != 1
    ):
        raise ValidationError(f"{context}: repository must be owner/name")
    if not isinstance(source["ref"], str) or not source["ref"]:
        raise ValidationError(f"{context}: ref must be non-empty")
    if not GIT_OBJECT.fullmatch(str(source["commit"])):
        raise ValidationError(f"{context}: commit must be a full lowercase object id")
    if not GIT_OBJECT.fullmatch(str(source["tree"])):
        raise ValidationError(f"{context}: tree must be a full lowercase object id")


def git_output(root, arguments, context, text=True):
    process = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=text,
        check=False,
    )
    if process.returncode:
        error = process.stderr.strip() if text else process.stderr.decode().strip()
        raise ValidationError(f"{context}: git failed: {error}")
    return process.stdout.strip() if text else process.stdout


def repository_name(root):
    remote = git_output(root, ["remote", "get-url", "origin"], "repository remote")
    normalized = remote.rstrip("/").removesuffix(".git").replace("\\", "/")
    if normalized.startswith("git@") and ":" in normalized:
        normalized = normalized.split(":", 1)[1]
    elif "://" in normalized:
        normalized = urlparse(normalized).path.strip("/")
    parts = normalized.split("/")
    if len(parts) < 2:
        raise ValidationError("repository remote: cannot derive owner/name")
    return "/".join(parts[-2:])


def verify_candidate(candidate, source_root):
    validate_source(candidate, "manifest.candidate")
    actual_head = git_output(source_root, ["rev-parse", "HEAD"], "candidate HEAD")
    actual_tree = git_output(
        source_root, ["rev-parse", "HEAD^{tree}"], "candidate tree"
    )
    actual_branch = git_output(
        source_root, ["branch", "--show-current"], "candidate branch"
    )
    if not actual_branch:
        raise ValidationError("manifest candidate: detached HEAD is not allowed")
    actual_ref = f"refs/heads/{actual_branch}"
    actual_repository = repository_name(source_root)
    expected = {
        "repository": actual_repository,
        "ref": actual_ref,
        "commit": actual_head,
        "tree": actual_tree,
    }
    if candidate != expected:
        raise ValidationError("manifest candidate does not match source repository HEAD")


def validate_record_reference(reference, records, context):
    require_keys(
        reference,
        {"id", "record_sha256"},
        {"id", "record_sha256"},
        context,
    )
    record = admitted_record(records, reference["id"], context)
    require_sha256(reference["record_sha256"], f"{context}.record_sha256")
    if reference["record_sha256"] != sha256_bytes(canonical_json(record)):
        raise ValidationError(f"{context}: stale provenance record hash")


def validate_payload(
    payload,
    payload_root,
    source_root,
    candidate,
    records,
    context,
):
    require_keys(
        payload,
        {
            "path",
            "size",
            "sha256",
            "source",
            "archive",
            "build_recipe",
            "windows_image",
            "provenance_records",
        },
        {
            "path",
            "size",
            "sha256",
            "source",
            "archive",
            "build_recipe",
            "windows_image",
            "provenance_records",
        },
        context,
    )
    payload_path = (payload_root / payload["path"]).resolve()
    if payload_root != payload_path and payload_root not in payload_path.parents:
        raise ValidationError(f"{context}: payload path escapes root")
    if not payload_path.is_file():
        raise ValidationError(f"{context}: payload file is missing")
    raw = payload_path.read_bytes()
    if payload["size"] != len(raw):
        raise ValidationError(f"{context}: payload size mismatch")
    require_sha256(payload["sha256"], f"{context}.sha256")
    if payload["sha256"] != sha256_bytes(raw):
        raise ValidationError(f"{context}: payload hash mismatch")
    validate_source(payload["source"], f"{context}.source")
    if payload["source"] != candidate:
        raise ValidationError(f"{context}: source does not match manifest candidate")

    archive = payload["archive"]
    require_keys(
        archive,
        {"provenance_id", "url", "size", "sha256", "signature"},
        {"provenance_id", "url", "size", "sha256", "signature"},
        f"{context}.archive",
    )
    archive_record = admitted_record(
        records, archive["provenance_id"], f"{context}.archive"
    )
    for field in ("url", "size", "sha256", "signature"):
        if archive.get(field) != archive_record.get(field):
            raise ValidationError(f"{context}.archive: {field} differs from ledger")

    recipe = payload["build_recipe"]
    require_keys(
        recipe, {"path", "sha256"}, {"path", "sha256"}, f"{context}.build_recipe"
    )
    recipe_path = (source_root / recipe["path"]).resolve()
    if (
        source_root != recipe_path
        and source_root not in recipe_path.parents
    ) or not recipe_path.is_file():
        raise ValidationError(f"{context}.build_recipe: recipe file is missing")
    require_sha256(recipe["sha256"], f"{context}.build_recipe.sha256")
    recipe_blob = git_output(
        source_root,
        ["show", f"{candidate['commit']}:{recipe['path']}"],
        f"{context}.build_recipe",
        text=False,
    )
    if recipe["sha256"] != sha256_bytes(recipe_blob):
        raise ValidationError(f"{context}.build_recipe: Git blob hash mismatch")

    image = payload["windows_image"]
    require_keys(
        image,
        {"provenance_id", "sha256"},
        {"provenance_id", "sha256"},
        f"{context}.windows_image",
    )
    image_record = admitted_record(
        records, image["provenance_id"], f"{context}.windows_image"
    )
    if image["sha256"] != image_record["sha256"]:
        raise ValidationError(f"{context}.windows_image: hash differs from ledger")

    references = payload["provenance_records"]
    if not isinstance(references, list) or not references:
        raise ValidationError(f"{context}: provenance_records must be non-empty")
    ids = [reference.get("id") for reference in references if isinstance(reference, dict)]
    if len(ids) != len(set(ids)):
        raise ValidationError(f"{context}: duplicate provenance record reference")
    for index, reference in enumerate(references):
        validate_record_reference(
            reference, records, f"{context}.provenance_records[{index}]"
        )
    required_ids = {archive["provenance_id"], image["provenance_id"]}
    if not required_ids.issubset(ids):
        raise ValidationError(f"{context}: archive/image provenance references missing")


def validate_manifest(
    manifest_path,
    ledger_path,
    ledger_sha256,
    payload_root,
    source_root,
):
    manifest = read_json(manifest_path)
    reject_protected_fields(manifest)
    enforce_manifest_schema(manifest)
    require_keys(
        manifest,
        {"schema", "epoch", "candidate", "authority", "payload_files"},
        {"schema", "epoch", "candidate", "authority", "payload_files"},
        "manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ValidationError("manifest schema mismatch")
    if manifest["epoch"] != EPOCH:
        raise ValidationError("manifest epoch mismatch")
    source_root = source_root.resolve()
    verify_candidate(manifest["candidate"], source_root)
    records, payload_sha256 = load_ledger(ledger_path, ledger_sha256)
    authority = manifest["authority"]
    require_keys(
        authority,
        {"input_provenance"},
        {"input_provenance"},
        "manifest.authority",
    )
    provenance = authority["input_provenance"]
    require_keys(
        provenance,
        {"file_sha256", "payload_sha256"},
        {"file_sha256", "payload_sha256"},
        "manifest.authority.input_provenance",
    )
    if provenance["file_sha256"] != ledger_sha256:
        raise ValidationError("manifest ledger file identity mismatch")
    if provenance["payload_sha256"] != payload_sha256:
        raise ValidationError("manifest ledger payload identity mismatch")
    payloads = manifest["payload_files"]
    if not isinstance(payloads, list) or not payloads:
        raise ValidationError("manifest payload_files must be non-empty")
    resolved_paths = [
        str((payload_root / payload["path"]).resolve()).casefold()
        for payload in payloads
    ]
    if len(resolved_paths) != len(set(resolved_paths)):
        raise ValidationError("manifest contains duplicate payload paths")
    payload_root = payload_root.resolve()
    for index, payload in enumerate(payloads):
        validate_payload(
            payload,
            payload_root,
            source_root,
            manifest["candidate"],
            records,
            f"manifest.payload_files[{index}]",
        )
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "epoch": EPOCH,
        "valid": True,
        "admission_authority": False,
        "manifest": str(manifest_path.resolve()),
        "canonical_input_provenance": {
            "path": str(ledger_path.resolve()),
            "file_sha256": ledger_sha256,
            "payload_sha256": payload_sha256,
        },
        "payload_count": len(payloads),
        "message": "Construction inputs verified; no admission authority granted.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--input-provenance", required=True, type=Path)
    parser.add_argument("--input-provenance-sha256", required=True)
    parser.add_argument("--payload-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate_manifest(
            args.manifest,
            args.input_provenance,
            args.input_provenance_sha256.lower(),
            args.payload_root,
            args.source_root,
        )
    except (OSError, ValidationError) as error:
        result = {
            "schema": DIAGNOSTIC_SCHEMA,
            "epoch": EPOCH,
            "valid": False,
            "admission_authority": False,
            "error": str(error),
        }
        print(json.dumps(result, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
