import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1]))
import provenance


def digest(value):
    return hashlib.sha256(value).hexdigest()


def record_digest(value):
    return digest(provenance.canonical_json(value))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "payload.bin").write_bytes(b"payload")
        (self.root / "recipe.sh").write_bytes(b"recipe\n")
        self.git("init", "-q")
        self.git("config", "user.name", "Test User")
        self.git("config", "user.email", "test@example.invalid")
        self.git("remote", "add", "origin", "https://github.com/owner/repo.git")
        self.git("add", "recipe.sh")
        self.git("commit", "-qm", "Add recipe")
        self.candidate = {
            "repository": "owner/repo",
            "ref": f"refs/heads/{self.git('branch', '--show-current')}",
            "commit": self.git("rev-parse", "HEAD"),
            "tree": self.git("rev-parse", "HEAD^{tree}"),
        }
        self.archive = {
            "id": "package:archive",
            "epoch": provenance.EPOCH,
            "status": "ADMITTED",
            "url": "https://example.invalid/archive.zip",
            "size": 123,
            "sha256": digest(b"archive"),
            "signature": {
                "kind": "detached",
                "sha256": digest(b"signature"),
                "status": "Valid",
            },
        }
        self.image = {
            "id": "windows:selected-image",
            "epoch": provenance.EPOCH,
            "status": "ADMITTED",
            "sha256": digest(b"windows-image"),
        }
        self.write_ledger([self.archive, self.image])
        self.manifest = {
            "schema": provenance.MANIFEST_SCHEMA,
            "epoch": provenance.EPOCH,
            "candidate": self.candidate,
            "authority": {
                "input_provenance": {
                    "file_sha256": self.ledger_sha256,
                    "payload_sha256": self.payload_sha256,
                }
            },
            "payload_files": [
                {
                    "path": "payload.bin",
                    "size": 7,
                    "sha256": digest(b"payload"),
                    "source": self.candidate,
                    "archive": {
                        "provenance_id": self.archive["id"],
                        "url": self.archive["url"],
                        "size": self.archive["size"],
                        "sha256": self.archive["sha256"],
                        "signature": self.archive["signature"],
                    },
                    "build_recipe": {
                        "path": "recipe.sh",
                        "sha256": digest(
                            self.git_bytes("show", "HEAD:recipe.sh")
                        ),
                    },
                    "windows_image": {
                        "provenance_id": self.image["id"],
                        "sha256": self.image["sha256"],
                    },
                    "provenance_records": [
                        {
                            "id": self.archive["id"],
                            "record_sha256": record_digest(self.archive),
                        },
                        {
                            "id": self.image["id"],
                            "record_sha256": record_digest(self.image),
                        },
                    ],
                }
            ],
        }

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", *arguments], cwd=self.root, text=True
        ).strip()

    def git_bytes(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.root)

    def write_ledger(self, records):
        payload = {
            "schema": provenance.LEDGER_SCHEMA,
            "epoch": provenance.EPOCH,
            "inputs": records,
        }
        canonical = provenance.canonical_json(payload)
        self.payload_sha256 = digest(canonical)
        document = {
            "payload": payload,
            "seal": {
                "payload_utf8_bytes": len(canonical),
                "payload_sha256": self.payload_sha256,
            },
        }
        self.ledger_path = self.root / "ledger.json"
        self.ledger_path.write_text(json.dumps(document), encoding="utf-8")
        self.ledger_sha256 = digest(self.ledger_path.read_bytes())

    def verify(self, manifest=None):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest or self.manifest), encoding="utf-8")
        return provenance.validate_manifest(
            path,
            self.ledger_path,
            self.ledger_sha256,
            self.root,
            self.root,
        )

    def assert_rejected(self, manifest, message):
        with self.assertRaisesRegex(provenance.ValidationError, message):
            self.verify(manifest)

    def test_valid_manifest_is_diagnostic_only(self):
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertFalse(result["admission_authority"])

    def test_missing_input_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"]["provenance_id"] = "missing"
        self.assert_rejected(changed, "input not found")

    def test_duplicate_input_records_are_rejected(self):
        self.write_ledger([self.archive, self.archive, self.image])
        self.manifest["authority"]["input_provenance"].update(
            file_sha256=self.ledger_sha256,
            payload_sha256=self.payload_sha256,
        )
        self.assert_rejected(self.manifest, "duplicate input id")

    def test_stale_input_record_is_rejected(self):
        changed_record = copy.deepcopy(self.archive)
        changed_record["verification"] = "new verification metadata"
        self.write_ledger([changed_record, self.image])
        self.manifest["authority"]["input_provenance"].update(
            file_sha256=self.ledger_sha256,
            payload_sha256=self.payload_sha256,
        )
        self.assert_rejected(self.manifest, "stale provenance record hash")

    def test_wrong_epoch_is_rejected(self):
        changed_record = copy.deepcopy(self.archive)
        changed_record["epoch"] = "2026-08-30-v1"
        self.write_ledger([changed_record, self.image])
        self.manifest["authority"]["input_provenance"].update(
            file_sha256=self.ledger_sha256,
            payload_sha256=self.payload_sha256,
        )
        self.assert_rejected(self.manifest, "input has wrong epoch")

    def test_wrong_hash_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["sha256"] = "0" * 64
        self.assert_rejected(changed, "payload hash mismatch")

    def test_self_authorizing_record_is_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["authorization"] = "granted"
        self.assert_rejected(changed, "protected authority fields")

    def test_numeric_git_object_is_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["candidate"]["commit"] = 123
        changed["payload_files"][0]["source"]["commit"] = 123
        self.assert_rejected(changed, "schema type must be string")

    def test_empty_repository_components_are_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["candidate"]["repository"] = "/"
        changed["payload_files"][0]["source"]["repository"] = "/"
        self.assert_rejected(changed, "schema pattern mismatch")

    def test_integer_url_is_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"]["url"] = 123
        self.assert_rejected(changed, "schema type must be string")

    def test_malformed_url_is_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"][
            "url"
        ] = "https://example.invalid/path with spaces"
        self.assert_rejected(changed, "schema URI format mismatch")

    def test_boolean_size_is_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"]["size"] = True
        self.assert_rejected(changed, "schema type must be integer")

    def test_null_signature_is_rejected_by_schema(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"]["signature"] = None
        self.assert_rejected(changed, "schema type must be object or string")

    def test_signature_status_must_match_sealed_ledger(self):
        changed = copy.deepcopy(self.manifest)
        changed["payload_files"][0]["archive"]["signature"]["status"] = "Invalid"
        self.assert_rejected(changed, "signature differs from ledger")

    def test_resolved_alias_payload_paths_are_rejected(self):
        changed = copy.deepcopy(self.manifest)
        alias = copy.deepcopy(changed["payload_files"][0])
        alias["path"] = ".\\payload.bin"
        changed["payload_files"].append(alias)
        self.assert_rejected(changed, "duplicate payload paths")

    def test_recipe_uses_canonical_git_blob_bytes(self):
        (self.root / "recipe.sh").write_bytes(b"recipe\r\n")
        result = self.verify()
        self.assertTrue(result["valid"])

    def test_candidate_must_match_repository_head(self):
        changed = copy.deepcopy(self.manifest)
        changed["candidate"]["commit"] = "0" * 40
        changed["payload_files"][0]["source"]["commit"] = "0" * 40
        self.assert_rejected(changed, "does not match source repository HEAD")


if __name__ == "__main__":
    unittest.main()
